#!/usr/bin/env python3
"""Bounded live-impact probe for nginx DNS SRV resolution.

This intentionally tests a loopback-only controlled DNS zone. It does not
create network traffic outside the runner or demonstrate a public DoS.
"""

import collections
import json
import pathlib
import re
import signal
import socketserver
import statistics
import subprocess
import threading
import time
import urllib.error

from resolver_srv_fanout import (
    Backend,
    CASES,
    NGINX,
    OUT,
    ControlledDNS,
    decode_question,
    family_rss_kb,
    free_port,
    http_get,
    nginx_config,
    http,
)

LIVE_OUT = OUT / "live-impact"
LIVE_OUT.mkdir(parents=True, exist_ok=True)
TICKS = 100  # overridden at runtime with os.sysconf


def quantile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))], 3)


def family_cpu_ticks(master_pid):
    """Aggregate Linux /proc stat utime+stime for master and children."""
    pids, seen, total = [master_pid], set(), 0
    while pids:
        pid = pids.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            line = pathlib.Path(f"/proc/{pid}/stat").read_text()
            fields = line[line.rfind(")") + 2:].split()
            # fields[0] is proc field 3; 14 and 15 become [11], [12].
            total += int(fields[11]) + int(fields[12])
            children = pathlib.Path(f"/proc/{pid}/task/{pid}/children").read_text()
            pids.extend(map(int, children.split()))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return total


class StudyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, udp = self.request
        try:
            answer = self.server.response(packet)
            if answer is not None:
                udp.sendto(answer, self.client_address)
        except Exception as exc:
            with self.server.lock:
                self.server.failures.append(str(exc))


class StudyDNS(ControlledDNS):
    """Extend the existing controlled DNS with deterministic delays/drops."""

    def __init__(self, mode):
        super().__init__(("127.0.0.1", 0))
        self.RequestHandlerClass = StudyHandler
        self.mode = mode
        self.first_a = threading.Event()
        self.seen_a = 0
        self.inflight_a = 0
        self.peak_inflight_a = 0

    def response(self, packet):
        qname, qtype, _qclass, _end = decode_question(packet)
        case = re.search(r"(?:^|\.)s([0-4])\.lab\.invalid$", qname)
        if qtype == 1 and case is not None:
            with self.lock:
                self.seen_a += 1
                self.inflight_a += 1
                self.peak_inflight_a = max(self.peak_inflight_a, self.inflight_a)
                self.first_a.set()
            try:
                if self.mode == "drop":
                    return None
                if self.mode == "delay":
                    # Every chain remains in-flight long enough for live /health
                    # and /proc polling; final A lookup is deliberately slower.
                    is_terminal = (qname.startswith("c10.") or
                                   (not qname.startswith("c") and
                                    int(case.group(1)) == 0))
                    time.sleep(0.55 if is_terminal else 0.030)
                return super().response(packet)
            finally:
                with self.lock:
                    self.inflight_a -= 1
        return super().response(packet)


def launch_nginx(dns_port, case_id, label, timeout=5):
    prefix = LIVE_OUT / label
    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / "logs").mkdir(exist_ok=True)
    listen_port = free_port()
    conf = prefix / "nginx.conf"
    conf.write_text(nginx_config(prefix, dns_port, listen_port, case_id).replace(
        "resolver_timeout 5s;", f"resolver_timeout {timeout}s;"
    ))
    checked = subprocess.run(
        [str(NGINX), "-p", str(prefix) + "/", "-c", str(conf), "-t"],
        capture_output=True, text=True, timeout=10
    )
    if checked.returncode:
        raise AssertionError(f"nginx -t failed: {checked.stderr}")
    output = (prefix / "process.log").open("w")
    proc = subprocess.Popen(
        [str(NGINX), "-p", str(prefix) + "/", "-c", str(conf), "-g", "daemon off;"],
        stdout=output, stderr=subprocess.STDOUT
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"NGINX terminated on startup: {proc.returncode}")
            try:
                if http_get(listen_port, "/health", timeout=0.25)[0] == 200:
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.015)
        else:
            raise TimeoutError("NGINX did not become healthy")
        return proc, output, prefix, listen_port
    except BaseException:
        proc.terminate()
        proc.wait(timeout=3)
        output.close()
        raise


def clean_stop(proc, output):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    output.close()


def probe(label, case_id, mode, max_seconds, cancel=False):
    dns = StudyDNS(mode)
    thread = threading.Thread(target=dns.serve_forever, daemon=True)
    thread.start()
    p = None
    output = None
    observations = []
    rss_samples = []
    cpu_samples = []
    errors = []
    first_time = None
    last_time = None
    pending_samples = 0
    try:
        p, output, prefix, port = launch_nginx(
            dns.server_address[1], case_id, label, 1 if mode == "drop" else 5
        )
        assert dns.first_a.wait(timeout=4), "NGINX never queried target A records"
        # The first DNS request is known to be in-flight here.
        start = time.monotonic()
        first_time = start
        ticks_at_start = family_cpu_ticks(p.pid)
        done = False
        while time.monotonic() - start < max_seconds:
            if p.poll() is not None:
                errors.append(f"NGINX unexpectedly exited rc={p.returncode}")
                break
            if cancel and (time.monotonic() - start) >= 0.08:
                pending = dns.inflight_a
                # A response is still outstanding when the master is stopped.
                if pending:
                    pending_samples += 1
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
                    errors.append("NGINX required SIGKILL on cancellation")
                done = True
                break
            now = time.monotonic()
            rss_samples.append(family_rss_kb(p.pid))
            cpu_samples.append(family_cpu_ticks(p.pid))
            try:
                before = time.perf_counter()
                status, body = http_get(port, "/health", timeout=0.75)
                elapsed = (time.perf_counter() - before) * 1000
                if status != 200 or body != "ok":
                    errors.append(f"bad health response {status}: {body!r}")
                observations.append(elapsed)
            except Exception as exc:
                errors.append(f"health request failed: {exc}")
            with dns.lock:
                inflight = dns.inflight_a
                responded = dns.counts[(case_id, "A")]
            if inflight:
                pending_samples += 1
            targets, depth = CASES[case_id]
            if mode == "delay" and responded >= targets * (depth + 1):
                done = True
                break
            time.sleep(0.006)
        last_time = time.monotonic()
        if not cancel and mode == "delay" and not done:
            errors.append("bounded DNS resolution did not complete by deadline")
        if mode == "drop" and dns.seen_a < 1:
            errors.append("no A queries were dropped")
        if cancel and not done:
            errors.append("NGINX cancellation did not occur")
        if cancel and pending_samples < 1:
            errors.append("no in-flight DNS query observed at termination")
        if mode == "delay":
            counts = dns.snapshot(case_id)
            targets, depth = CASES[case_id]
            if counts["A"] < targets * (depth + 1):
                errors.append(f"resolution incomplete: {counts['A']} A queries")
        duration = max(0.001, last_time - first_time)
        # CPU ticks are a process-family approximation, not a calibrated CPU %.
        result = {
            "label": label,
            "mode": mode,
            "case": case_id,
            "srv_targets": CASES[case_id][0],
            "cname_depth": CASES[case_id][1],
            "duration_seconds": round(duration, 3),
            "health_sample_count": len(observations),
            "health_median_ms": quantile(observations, .5),
            "health_p95_ms": quantile(observations, .95),
            "health_max_ms": round(max(observations), 3) if observations else None,
            "family_rss_peak_sampled_kib": max(rss_samples, default=0),
            "family_cpu_ticks_delta": (
                max(cpu_samples, default=ticks_at_start) - ticks_at_start
            ),
            "dns_A_queries_seen": dns.seen_a,
            "dns_A_answers_sent": dns.snapshot(case_id)["A"],
            "dns_max_simultaneous_A_requests": dns.peak_inflight_a,
            "health_checks_during_pending_dns": pending_samples,
            "nginx_still_running_at_measurement_end": p.poll() is None,
            "nginx_exit_code": p.poll(),
            "errors": errors + dns.failures,
        }
        (LIVE_OUT / f"{label}.json").write_text(json.dumps(result, indent=2) + "\n")
        print("LIVE " + json.dumps(result, sort_keys=True), flush=True)
        return result
    finally:
        if p is not None:
            clean_stop(p, output)
        dns.shutdown()
        dns.server_close()


def main():
    if not NGINX.exists():
        raise FileNotFoundError(NGINX)
    # All traffic stays within 127.0.0.1; no remote resolvers.
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 19081), Backend)
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
    backend_thread.start()
    results = []
    try:
        # Small baseline and 64-target test with DNS work intentionally pending.
        results.append(probe("baseline-live", 0, "delay", 4.0))
        results.append(probe("fanout-live", 4, "delay", 5.0))
        # No A responses: capture bounded health/CPU/RSS during timeouts.
        results.append(probe("dns-timeout", 3, "drop", 2.5))
        # Stop the NGINX master while child A queries are outstanding.
        results.append(probe("cancel-pending", 4, "delay", 1.5, cancel=True))
    finally:
        backend.shutdown()
        backend.server_close()
    failed = [r for r in results if r["errors"]]
    summary = {
        "results": results,
        "failed": len(failed),
        "limitations": [
            "One run only; no statistical confidence interval.",
            "Health responses sample a shared worker, but DNS reply delays are artificial.",
            "CPU ticks and RSS are sampled, not exact peaks or isolated CPU utilization.",
            "No network attacker trigger, resource exhaustion, or CVE claimed.",
        ],
    }
    (LIVE_OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"LIVE PROBE: {len(results)} cases; {len(failed)} errors", flush=True)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
