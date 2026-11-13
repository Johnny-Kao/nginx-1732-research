#!/usr/bin/env python3
"""Isolated C prototype: compare RSS and final status with short and wide 103s."""
import os, socket, subprocess, tempfile, pathlib, threading, time, json

BINARY=os.path.abspath(os.getenv("NGINX_BINARY","./objs/nginx"))
N=int(os.getenv("N_HINTS","30000"))

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        return s.getsockname()[1]

def rss(pid):
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"): return int(line.split()[1])
    except OSError: pass
    return None

def run(fields):
    with tempfile.TemporaryDirectory(prefix="reuse1732-") as d:
        root=pathlib.Path(d);(root/"logs").mkdir()
        back,front=port(),port()
        srv=socket.socket();srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        srv.bind(("127.0.0.1",back));srv.listen(2)
        hint=b"HTTP/1.1 103 Early Hints\r\n"+b"".join(
            f"X-Hint-{i}: v\r\n".encode() for i in range(fields))+b"\r\n"
        final=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        stats={"sent":0,"disconnected":False};responses=[]
        (root/"nginx.conf").write_text(f"""daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/logs/error.log error;
events {{ worker_connections 128; }}
http {{ access_log off; server {{ listen 127.0.0.1:{front}; location / {{
  proxy_buffer_size 4k; proxy_read_timeout 25s;
  proxy_pass http://127.0.0.1:{back};
}} }} }}
""")
        def feed():
            try:
                c,_=srv.accept()
                with c:
                    c.settimeout(18);c.recv(4096)
                    for i in range(N):
                        try:c.sendall(hint);stats["sent"]+=1
                        except OSError:stats["disconnected"]=True;break
                        if i%200==0:time.sleep(.0006)
                    try:c.sendall(final)
                    except OSError:stats["disconnected"]=True
            except OSError:stats["disconnected"]=True
            finally:srv.close()
        proc=subprocess.Popen([BINARY,"-p",d,"-c",str(root/"nginx.conf")],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if proc.poll() is not None:raise RuntimeError("nginx failed to start")
                try:
                    with socket.create_connection(("127.0.0.1",front),timeout=.1):break
                except OSError:time.sleep(.025)
            else:raise RuntimeError("no readiness")
            before=rss(proc.pid)
            t=threading.Thread(target=feed,daemon=True);t.start()
            def client():
                try:
                    with socket.create_connection(("127.0.0.1",front),timeout=10) as c:
                        c.settimeout(25)
                        c.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        data=bytearray()
                        while True:
                            chunk=c.recv(65536)
                            if not chunk:break
                            if len(data)<2048:data.extend(chunk[:2048-len(data)])
                        responses.append(bytes(data))
                except OSError as e:responses.append(str(type(e).__name__).encode())
            ct=threading.Thread(target=client,daemon=True);ct.start()
            samples=[]
            deadline=time.monotonic()+28
            while time.monotonic()<deadline:
                x=rss(proc.pid)
                if x is not None:samples.append(x)
                if not ct.is_alive():break
                time.sleep(.002)
            ct.join(timeout=3);t.join(timeout=3)
            output={"headers_per_103":fields,"blocks_sent":stats["sent"],
                    "disconnected":stats["disconnected"],"rss_start_kib":before,
                    "rss_peak_kib":max(samples) if samples else None,
                    "rss_delta_kib":max(samples)-before if samples and before is not None else None,
                    "response_status":responses[0].split(b"\r\n",1)[0].decode(errors="replace") if responses else "missing"}
            print("REUSE_RESULT "+json.dumps(output),flush=True)
            assert stats["sent"]>=N//2, "incomplete stream"
            assert output["response_status"].startswith("HTTP/1.1 200"), "valid final 200 lost"
            return output
        finally:
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()

results=[run(0),run(1),run(12)]
if results[2]["rss_delta_kib"] > results[0]["rss_delta_kib"]+4096:
    print("REUSE_ONLY_NOT_BOUNDED: expanded list parts still allocate per 103",flush=True)
else:
    print("REUSE_ONLY_NO_WIDE_GROWTH_OBSERVED: inspect parser allocations before concluding",flush=True)
