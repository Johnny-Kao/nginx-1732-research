#!/usr/bin/env python3
"""End-to-end bounded Early Hints check. Run with a freshly built ./objs/nginx."""
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

nginx = os.path.abspath(os.environ.get("NGINX_BINARY", "./objs/nginx"))
count = int(os.environ.get("HINT_COUNT", "10000"))
with tempfile.TemporaryDirectory(prefix="ngx1732-") as tmp:
    root = pathlib.Path(tmp)
    (root / "logs").mkdir()
    upstream = socket.socket()
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    upstream_port = upstream.getsockname()[1]
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    proxy_port = probe.getsockname()[1]
    probe.close()
    config = root / "nginx.conf"
    config.write_text(f"""daemon off;
master_process off;
error_log {root}/logs/error.log info;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
  access_log off;
  server {{
    listen 127.0.0.1:{proxy_port};
    location / {{ proxy_pass http://127.0.0.1:{upstream_port}; }}
  }}
}}
""")
    def serve():
        conn, _ = upstream.accept()
        with conn:
            conn.settimeout(10)
            conn.recv(65536)
            hint = b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload; as=style\r\n\r\n"
            try:
                for i in range(count):
                    conn.sendall(hint)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            except (BrokenPipeError, ConnectionResetError):
                pass
        upstream.close()
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    proc = subprocess.Popen([nginx, "-c", str(config), "-p", tmp])
    try:
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError(f"nginx exited unexpectedly: {proc.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("nginx not listening")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{proxy_port}/", timeout=30) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        # Oversized early hints should fail the upstream response rather than continue
        # accumulating unbounded request-pool allocations.
        print(f"hints={count} status={status}")
        if status != 502:
            raise AssertionError(f"expected 502 for oversized hints, got {status}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        worker.join(timeout=5)
