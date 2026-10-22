#!/usr/bin/env python3
"""GitHub-runner-only HTTP 103 edge-case validation for nginx #1732."""
import os, pathlib, socket, subprocess, tempfile, threading, time, urllib.error, urllib.request

BINARY = os.path.abspath(os.getenv("NGINX_BINARY", "./objs/nginx"))
HINT = b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload; as=style\r\n\r\n"

def case(count, *, truncated=False, retries=False):
    with tempfile.TemporaryDirectory(prefix="nginx-1732-edge-") as tmp:
        root=pathlib.Path(tmp)
        (root/"logs").mkdir()
        listener=socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        upstream_port=listener.getsockname()[1]
        probe=socket.socket()
        probe.bind(("127.0.0.1",0))
        frontend_port=probe.getsockname()[1]
        probe.close()
        # Configured proxy_buffer_size 4k is supported; the exact boundary is
        # discovered on CI rather than assuming parser bookkeeping.
        (root/"nginx.conf").write_text(f"""daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 128; }}
http {{
 access_log off;
 server {{
  listen 127.0.0.1:{frontend_port};
  location / {{
   proxy_buffer_size 4k;
   proxy_connect_timeout 2s;
   proxy_read_timeout 5s;
   proxy_pass http://127.0.0.1:{upstream_port};
  }}
 }}
}}
""")
        def serve():
            try:
                listener.settimeout(12)
                with listener.accept()[0] as conn:
                    conn.settimeout(12)
                    conn.recv(65536)
                    try:
                        for _ in range(count):
                            conn.sendall(HINT)
                        if not truncated:
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    except (BrokenPipeError, ConnectionResetError):
                        pass
            except socket.timeout:
                pass
            finally:
                listener.close()
        thread=threading.Thread(target=serve, daemon=True)
        thread.start()
        proc=subprocess.Popen([BINARY,"-p",tmp,"-c",str(root/"nginx.conf")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if proc.poll() is not None:
                    raise RuntimeError("nginx exited before readiness")
                try:
                    with socket.create_connection(("127.0.0.1", frontend_port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.04)
            else:
                raise RuntimeError("nginx not ready")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{frontend_port}/", timeout=15) as reply:
                    status=reply.status
                    reply.read()
            except urllib.error.HTTPError as exc:
                status=exc.code
            return status
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            thread.join(timeout=3)

# Baseline positive controls: normal upstream behavior must stay intact.
for n in (0, 1, 3):
    status=case(n)
    print(f"baseline count={n} status={status}",flush=True)
    assert status == 200, f"baseline changed at {n}"

# Find the actual first rejected hint block and test both sides.
low, high=3, 256
while case(high)==200 and high < 4096:
    high*=2
assert high < 4096, "no enforced limit found"
while low + 1 < high:
    mid=(low+high)//2
    if case(mid)==200:
        low=mid
    else:
        high=mid
assert case(low)==200
assert case(high)==502, f"first above-limit response should fail ({high})"
print(f"boundary last_accepted={low} first_rejected={high}",flush=True)

for n in (high+1, 1000, 10000, 100000):
    status=case(n)
    print(f"oversized count={n} status={status}",flush=True)
    assert status==502

status=case(1,truncated=True)
print(f"truncated early hints status={status}",flush=True)
assert status==502

print("EDGE TESTS PASS",flush=True)
