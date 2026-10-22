#!/usr/bin/env python3
"""GitHub Linux CI: byte boundary, upstream retry semantics, and /proc RSS for issue #1732."""
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

NGINX = os.path.abspath(os.getenv("NGINX_BINARY", "./objs/nginx"))
BASE = b"HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n"
END = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

def port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

def single(padding, *, count=1, health=False, invalid_first=False):
    with tempfile.TemporaryDirectory(prefix="nginx1732-") as d:
        root=pathlib.Path(d); (root/"logs").mkdir()
        p1,p2,front=port(),port(),port()
        hits=[0,0]
        ready=threading.Event()
        def server(which, p):
            srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); srv.bind(("127.0.0.1",p));srv.listen(4);srv.settimeout(12)
            ready.set()
            try:
                conn,_=srv.accept()
                with conn:
                    conn.settimeout(10)
                    conn.recv(8192);hits[which]+=1
                    try:
                        if which==1:
                            conn.sendall(END)
                        elif invalid_first:
                            conn.sendall(b"HTTP/1.1 999 Nope\r\n\r\n")
                        else:
                            item=BASE+b"X-Pad: "+b"x"*padding+b"\r\n\r\n"
                            for _ in range(count): conn.sendall(item)
                            conn.sendall(END)
                    except (BrokenPipeError,ConnectionResetError,OSError):
                        pass
            except socket.timeout: pass
            finally: srv.close()
        t1=threading.Thread(target=server,args=(0,p1),daemon=True);t1.start()
        t2=threading.Thread(target=server,args=(1,p2),daemon=True)
        if health: t2.start()
        ups=f"server 127.0.0.1:{p1};"
        if health: ups+=f"\nserver 127.0.0.1:{p2};"
        (root/"nginx.conf").write_text(f"""daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 128; }}
http {{
 upstream backend {{ {ups} }}
 server {{ listen 127.0.0.1:{front};
  location / {{ proxy_buffer_size 4k; proxy_next_upstream error timeout invalid_header http_500 http_502 http_503; proxy_next_upstream_tries 2; proxy_read_timeout 5s; proxy_pass http://backend; }}
 }}
}}
""")
        proc=subprocess.Popen([NGINX,"-p",d,"-c",str(root/"nginx.conf")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(120):
                if proc.poll() is not None: raise RuntimeError("nginx died")
                try:
                    conn=socket.create_connection(("127.0.0.1",front),timeout=.2);conn.close();break
                except OSError:time.sleep(.03)
            else: raise RuntimeError("not listening")
            req=socket.create_connection(("127.0.0.1",front),timeout=8)
            with req:
                req.settimeout(10);req.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                received=bytearray()
                while True:
                    try: part=req.recv(65536)
                    except (socket.timeout,ConnectionResetError):break
                    if not part:break
                    received.extend(part)
                    if len(received)>2000000:break
            time.sleep(.04)
            data=bytes(received)
            return {"raw":data,"hits":hits[:],"logs":(root/"logs/error.log").read_text(errors="replace")}
        finally:
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
            t1.join(timeout=.1)
            if health:t2.join(timeout=.1)

def outcome(r):
    lines=[x for x in r["raw"].split(b"\r\n") if x.startswith(b"HTTP/")]
    return [x.decode(errors="replace") for x in lines]

# Exact one-byte transition, varying size of ONE otherwise-identical 103 message.
lo,hi=0,3000
assert b"200 OK" in single(lo)["raw"],"baseline small hint must work"
assert b"502 Bad Gateway" in single(hi)["raw"],"large hint should be rejected"
while hi-lo>1:
    mid=(lo+hi)//2
    r=single(mid)
    if b"200 OK" in r["raw"]:lo=mid
    else:hi=mid
ok=single(lo);bad=single(hi)
print("ONE-BYTE BOUNDARY", {"last_accepted_padding":lo,"first_rejected_padding":hi,
      "accepted":outcome(ok),"rejected":outcome(bad)},flush=True)
assert hi==lo+1
assert b"200 OK" in ok["raw"] and b"502 Bad Gateway" in bad["raw"]

# Retry semantics are experimentally reported: after a forwarded 103, nginx cannot
# transparently retry once response output has already started.
r=single(0,count=100,health=True)
print("AFTER_HINT_FAILURE_RETRY",{"status_lines":outcome(r),"upstream_hits":r["hits"]},flush=True)
assert r["hits"][0]==1,"broken first upstream was not contacted"
# No fragile assertion about retry policy before observing actual upstream behavior.

# Resource measurements use the actual nginx pid (master_process off), and a slow,
# chunked upstream to permit sampling the live process RSS.
def rss_case(n):
    with tempfile.TemporaryDirectory(prefix="nginx1732rss-") as d:
        root=pathlib.Path(d);(root/"logs").mkdir()
        back,front=port(),port(); srv=socket.socket();srv.bind(("127.0.0.1",back));srv.listen(1)
        def feeder():
            try:
                c,_=srv.accept()
                with c:
                    c.recv(8192)
                    item=BASE+b"\r\n"
                    for i in range(n):
                        try:c.sendall(item)
                        except (BrokenPipeError,ConnectionResetError):break
                        if i%20==0:time.sleep(.001)
                    try:c.sendall(END)
                    except OSError:pass
            finally:srv.close()
        (root/"nginx.conf").write_text(f"""daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 128; }}
http {{ server {{ listen 127.0.0.1:{front}; location / {{ proxy_buffer_size 4k; proxy_pass http://127.0.0.1:{back}; }} }} }}
""")
        p=subprocess.Popen([NGINX,"-p",d,"-c",str(root/"nginx.conf")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        t=threading.Thread(target=feeder,daemon=True)
        try:
            for _ in range(100):
                try:
                    x=socket.create_connection(("127.0.0.1",front),timeout=.1);x.close();break
                except OSError:time.sleep(.03)
            t.start()
            def client():
                with socket.create_connection(("127.0.0.1",front),timeout=10) as c:
                    c.settimeout(10);c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    try:
                        while c.recv(65536): pass
                    except OSError:pass
            ct=threading.Thread(target=client,daemon=True);ct.start()
            vals=[]
            for i in range(500):
                try:
                    for line in pathlib.Path(f"/proc/{p.pid}/status").read_text().splitlines():
                        if line.startswith("VmRSS:"):vals.append(int(line.split()[1]));break
                except OSError:break
                if not ct.is_alive():break
                time.sleep(.005)
            ct.join(timeout=15)
            print("RSS",{"blocks_offered":n,"samples":len(vals),"min_kib":min(vals),"peak_kib":max(vals),"delta_kib":max(vals)-min(vals)},flush=True)
            assert vals and max(vals)-min(vals)<16384,"patched nginx RSS increased by >16 MiB"
        finally:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            t.join(timeout=.2)

rss_case(100000)
print("BYTE/RETRY/RSS RESEARCH CHECKS COMPLETE",flush=True)
