#!/usr/bin/env python3
"""Controlled NGINX SRV fan-out experiment. Loopback only, bounded workloads.

Run on a Linux GitHub Actions runner after building ./objs/nginx.
This is a measurement harness, NOT a proof of a security vulnerability.
"""

import collections
import http.server
import json
import os
import pathlib
import re
import socket
import socketserver
import statistics
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
NGINX = ROOT / "objs" / "nginx"
OUT = ROOT / "research" / "srv-fanout-output"
# The 64-target/10-CNAME maximum is deliberately modest, to avoid a DoS test.
CASES = ((1, 0), (8, 0), (8, 5), (32, 5), (64, 10))


def encode_name(name):
    return b"".join(bytes([len(s)]) + s.encode("ascii") for s in name.split(".")) + b"\x00"


def decode_question(packet):
    if len(packet) < 17:
        raise ValueError("short DNS query")
    pos = 12
    parts = []
    while True:
        if pos >= len(packet):
            raise ValueError("incomplete DNS name")
        size = packet[pos]
        pos += 1
        if size == 0:
            break
        if size > 63 or pos + size > len(packet):
            raise ValueError("invalid DNS label")
        parts.append(packet[pos:pos + size].decode("ascii").lower())
        pos += size
    if pos + 4 > len(packet):
        raise ValueError("incomplete DNS question")
    qtype, qclass = struct.unpack_from("!HH", packet, pos)
    return ".".join(parts), qtype, qclass, pos + 4


def answer_rr(rtype, rdata):
    return b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 1, len(rdata)) + rdata


class ControlledDNS(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address):
        super().__init__(address, DNSRequest)
        self.lock = threading.Lock()
        self.counts = collections.Counter()
        self.failures = []
        self.max_response_size = 0

    def record(self, key, response_length):
        with self.lock:
            self.counts[key] += 1
            self.max_response_size = max(self.max_response_size, response_length)

    def snapshot(self, case_id):
        with self.lock:
            return {
                name: self.counts[(case_id, name)]
                for name in ("SRV", "A", "AAAA", "other")
            }

    def response(self, packet):
        qname, qtype, qclass, qend = decode_question(packet)
        match = re.search(r"(?:^|\.)s([0-4])\.lab\.invalid$", qname)
        case_id = int(match.group(1)) if match else -1
        header = packet[:2]
        question = packet[12:qend]
        rrs = []
        if qclass == 1 and 0 <= case_id < len(CASES):
            targets, depth = CASES[case_id]
            base = f"s{case_id}.lab.invalid"
            if qtype == 33 and qname == f"_http._tcp.{base}":
                for i in range(targets):
                    host = f"t{i:03d}.{base}"
                    data = struct.pack("!HHH", 0, 1, 19081) + encode_name(host)
                    rrs.append(answer_rr(33, data))
                label = "SRV"
            elif qtype == 1 and qname.endswith("." + base):
                labels = qname.split(".")
                if re.fullmatch(r"t\d{3}", labels[0]):
                    stage = 0
                    host_label = labels[0]
                elif (len(labels) >= 5 and re.fullmatch(r"c\d+", labels[0])
                      and re.fullmatch(r"t\d{3}", labels[1])):
                    stage = int(labels[0][1:])
                    host_label = labels[1]
                else:
                    stage = -1
                    host_label = ""
                if 0 <= stage <= depth:
                    if stage == depth:
                        rrs.append(answer_rr(1, socket.inet_aton("127.0.0.1")))
                    else:
                        next_name = f"c{stage + 1}.{host_label}.{base}"
                        rrs.append(answer_rr(5, encode_name(next_name)))
                label = "A"
            else:
                label = "AAAA" if qtype == 28 else "other"
        else:
            label = "other"

        reply = header + struct.pack("!HHHHH", 0x8180, 1, len(rrs), 0, 0)
        reply += question + b"".join(rrs)
        if len(reply) > 4096:
            raise ValueError(f"DNS response unexpectedly exceeds 4096 bytes: {len(reply)}")
        self.record((case_id, label), len(reply))
        return reply


class DNSRequest(socketserver.BaseRequestHandler):
    def handle(self):
        packet, transport = self.request
        try:
            response = self.server.response(packet)
            transport.sendto(response, self.client_address)
        except Exception as exc:
            with self.server.lock:
                self.server.failures.append(str(exc))


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"backend-ok")

    def log_message(self, *args):
        return


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_rss_kb(pid):
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        pass
    return 0


def family_rss_kb(pid):
    pids = [pid]
    found = set()
    rss = 0
    while pids:
        current = pids.pop()
        if current in found:
            continue
        found.add(current)
        rss += read_rss_kb(current)
        try:
            children = pathlib.Path(
                f"/proc/{current}/task/{current}/children"
            ).read_text().split()
            pids.extend(int(child) for child in children)
        except (FileNotFoundError, ProcessLookupError):
            pass
    return rss


def http_get(port, path, timeout=2):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{port}{path}", timeout=timeout
    ) as response:
        return response.status, response.read().decode("ascii")


def nginx_config(prefix, dns_port, listen_port, case_id):
    return f"""worker_processes 1;
error_log {prefix}/error.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 4096; }}
http {{
    access_log off;
    upstream backend_pool {{
        zone backend_pool 128k;
        resolver 127.0.0.1:{dns_port} ipv6=off valid=1s;
        resolver_timeout 5s;
        server s{case_id}.lab.invalid service=http resolve;
    }}
    server {{
        listen 127.0.0.1:{listen_port};
        location = /health {{ return 200 'ok'; }}
        location = /proxy {{ proxy_pass http://backend_pool; }}
    }}
}}
"""


def run_case(dns, case_id, targets, depth):
    prefix = OUT / f"case-{case_id}"
    prefix.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    listen_port = free_port()
    conf.write_text(nginx_config(prefix, dns.server_address[1], listen_port, case_id))
    validate = subprocess.run(
        [str(NGINX), "-p", str(prefix) + "/", "-c", str(conf), "-t"],
        capture_output=True, text=True, timeout=10
    )
    if validate.returncode:
        raise RuntimeError(f"nginx -t failed: {validate.stderr}")

    error_log = (prefix / "process.log").open("w")
    proc = subprocess.Popen(
        [str(NGINX), "-p", str(prefix) + "/", "-c", str(conf), "-g", "daemon off;"],
        stdout=error_log, stderr=subprocess.STDOUT
    )
    try:
        ready_by = time.monotonic() + 8
        while time.monotonic() < ready_by:
            if proc.poll() is not None:
                raise RuntimeError(f"nginx exited with {proc.returncode}")
            try:
                status, _ = http_get(listen_port, "/health", timeout=0.4)
                if status == 200:
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        else:
            raise RuntimeError("nginx did not start listening")

        # Verify all child chains have actually reached the authoritative DNS server.
        expected = targets * (depth + 1)
        deadline = time.monotonic() + 16
        while time.monotonic() < deadline:
            counts = dns.snapshot(case_id)
            if counts["A"] >= expected and counts["SRV"] >= 1:
                break
            if proc.poll() is not None:
                raise RuntimeError("nginx exited during DNS resolution")
            time.sleep(0.04)

        # Capture non-invasive measurements after the bounded resolution run.
        counts = dns.snapshot(case_id)
        latencies = []
        for _ in range(25):
            start = time.perf_counter()
            status, _ = http_get(listen_port, "/health")
            assert status == 200
            latencies.append((time.perf_counter() - start) * 1000)
        status, body = http_get(listen_port, "/proxy", timeout=5)
        rss_kb = family_rss_kb(proc.pid)
        result = {
            "case": case_id, "srv_targets": targets, "cname_depth": depth,
            "expected_a_queries": expected, "dns": counts,
            "dns_response_max_bytes": dns.max_response_size,
            "nginx_family_rss_kb": rss_kb,
            "health_ms_median": round(statistics.median(latencies), 3),
            "health_ms_max": round(max(latencies), 3),
            "proxy_status": status, "proxy_body": body,
        }
        if counts["SRV"] < 1 or counts["A"] < expected:
            raise AssertionError(f"DNS fan-out incomplete: {result}")
        if status != 200 or body != "backend-ok":
            raise AssertionError(f"proxy did not resolve: {result}")
        return result
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        error_log.close()


def main():
    if not NGINX.is_file():
        raise RuntimeError(f"missing compiled nginx: {NGINX}")
    OUT.mkdir(parents=True, exist_ok=True)
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 19081), Backend)
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
    backend_thread.start()
    dns = ControlledDNS(("127.0.0.1", 0))
    dns_thread = threading.Thread(target=dns.serve_forever, daemon=True)
    dns_thread.start()
    results = []
    errors = []
    try:
        for idx, (targets, depth) in enumerate(CASES):
            try:
                result = run_case(dns, idx, targets, depth)
                results.append(result)
                print(json.dumps(result, sort_keys=True), flush=True)
            except Exception as exc:
                errors.append({"case": idx, "error": str(exc)})
                print(f"FAILED case={idx} {exc}", flush=True)
                break
    finally:
        dns.shutdown()
        dns.server_close()
        backend.shutdown()
        backend.server_close()
    payload = {"results": results, "errors": errors, "dns_errors": dns.failures,
               "bounds": {"max_targets": 64, "max_cname_depth": 10},
               "interpretation": "Functional fan-out evidence; not a DoS demonstration"}
    (OUT / "results.json").write_text(json.dumps(payload, indent=2) + "\n")
    if errors or dns.failures or len(results) != len(CASES):
        raise SystemExit(1)
    print(f"PASS: {len(results)} bounded NGINX SRV/CNAME scenarios", flush=True)


if __name__ == "__main__":
    main()
