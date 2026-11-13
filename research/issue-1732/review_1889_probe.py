#!/usr/bin/env python3
"""Isolated #1889 A/B behavior probes; nginx executable provided via NGINX_BINARY."""
import os, pathlib, socket, subprocess, tempfile, threading, time

BIN = os.path.abspath(os.environ.get("NGINX_BINARY", "./objs/nginx"))
HINT = b"HTTP/1.1 103 Early Hints\r\nLink: </x>; rel=preload\r\n\r\n"
FINAL = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

def freeport():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def probe(n, forward, retry=False):
    with tempfile.TemporaryDirectory(prefix="nginx1889-") as d:
        root=pathlib.Path(d); (root/"logs").mkdir()
        p1,p2,front=freeport(),freeport(),freeport()
        hits=[0,0]
        def backend(port, idx):
            with socket.socket() as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("127.0.0.1",port));srv.listen(2);srv.settimeout(8)
                try:
                    with srv.accept()[0] as c:
                        hits[idx]+=1;c.settimeout(8);c.recv(8192)
                        if idx==0:
                            for _ in range(n):
                                try: c.sendall(HINT)
                                except OSError: break
                        try:c.sendall(FINAL)
                        except OSError:pass
                except (socket.timeout, OSError):pass
        threads=[threading.Thread(target=backend,args=(p1,0),daemon=True)]
        if retry:threads.append(threading.Thread(target=backend,args=(p2,1),daemon=True))
        for t in threads:t.start()
        backend_conf=f"server 127.0.0.1:{p1};"
        if retry:backend_conf+=f" server 127.0.0.1:{p2};"
        (root/"nginx.conf").write_text(f"""daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 256; }}
http {{
  upstream backend {{ {backend_conf} }}
  server {{ listen 127.0.0.1:{front};
    location / {{ proxy_buffer_size 4k;
      proxy_next_upstream error timeout{' invalid_header' if retry else ''};
      proxy_next_upstream_tries 2;
      proxy_read_timeout 5s;
      proxy_pass http://backend; }}
  }}
}}
""")
        # Optionally override the upstream HTTP/1.1 early-hints forwarding by
        # testing a client that does not advertise 103 support.
        p=subprocess.Popen([BIN,"-p",d,"-c",str(root/"nginx.conf")],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if p.poll() is not None:raise RuntimeError("nginx startup failed")
                try:
                    with socket.create_connection(("127.0.0.1",front),timeout=.1):break
                except OSError:time.sleep(.025)
            with socket.create_connection(("127.0.0.1",front),timeout=10) as c:
                c.settimeout(10)
                # Explicit HTTP/1.0 client disables 103 forwarding in default config.
                version="HTTP/1.1" if forward else "HTTP/1.0"
                c.sendall(f"GET / {version}\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
                raw=bytearray()
                try:
                    while True:
                        b=c.recv(65536)
                        if not b:break
                        raw.extend(b)
                        if len(raw)>2000000:break
                except (socket.timeout, ConnectionResetError):pass
            log=(root/"logs/error.log").read_text(errors="replace")
            status=[line.decode(errors="replace") for line in bytes(raw).split(b"\r\n") if line.startswith(b"HTTP/")]
            return {"statuses":status,"hits":hits,"too_big_logs":log.count("upstream sent too big early hints"),
                    "error_log_present":"[error]" in log and "upstream sent too big early hints" in log}
        finally:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            for t in threads:t.join(timeout=.2)

if __name__=="__main__":
    for forward in (False,True):
        for n in (0,1,50,65,66,80,200):
            print("CASE",{"forward":forward,"blocks":n,**probe(n,forward)},flush=True)
    print("RETRY",probe(100,True,retry=True),flush=True)
