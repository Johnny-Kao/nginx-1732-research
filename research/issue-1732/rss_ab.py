#!/usr/bin/env python3
"""A/B: identical upstream stream, same Linux runner; measure /proc RSS."""
import os, socket, subprocess, tempfile, pathlib, threading, time, json, sys

HINT=b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload; as=style\r\n\r\n"
FINAL=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
N=int(os.environ.get("AB_HINTS","300000"))
def free_port():
 s=socket.socket();s.bind(("127.0.0.1",0));p=s.getsockname()[1];s.close();return p
def rss(pid):
 try:
  for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
   if line.startswith("VmRSS:"):return int(line.split()[1])
 except OSError:pass
 return None
def execute(binary, label):
 with tempfile.TemporaryDirectory(prefix="nginx-ab-") as d:
  root=pathlib.Path(d);(root/"logs").mkdir()
  up,front=free_port(),free_port()
  srv=socket.socket();srv.bind(("127.0.0.1",up));srv.listen(2)
  stats={"sent":0,"broken":False}
  started=threading.Event()
  def feeder():
   try:
    c,_=srv.accept()
    with c:
     c.settimeout(15);c.recv(4096);started.set()
     # Stream slowly enough for RSS polling to capture actual growth.
     for i in range(N):
      try:c.sendall(HINT);stats["sent"]+=1
      except (OSError,BrokenPipeError):
       stats["broken"]=True;break
      if i%200==0:time.sleep(.0005)
     if not stats["broken"]:
      try:c.sendall(FINAL)
      except OSError:pass
   finally:srv.close()
  (root/"nginx.conf").write_text(f"""daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 128; }}
http {{ access_log off; server {{ listen 127.0.0.1:{front}; location / {{ proxy_buffer_size 4k; proxy_read_timeout 20s; proxy_pass http://127.0.0.1:{up}; }} }} }}
""")
  p=subprocess.Popen([binary,"-p",d,"-c",str(root/"nginx.conf")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   for _ in range(120):
    try:
     with socket.create_connection(("127.0.0.1",front),timeout=.1):break
    except OSError:time.sleep(.025)
   before=rss(p.pid)
   t=threading.Thread(target=feeder,daemon=True);t.start()
   outcome=[]
   def client():
    try:
     with socket.create_connection(("127.0.0.1",front),timeout=20) as c:
      c.settimeout(20);c.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
      buf=b""
      while True:
       chunk=c.recv(65536)
       if not chunk:break
       if len(buf)<2048:buf+=chunk[:2048-len(buf)]
      outcome.append(buf.split(b"\r\n",1)[0].decode(errors="replace"))
    except OSError as e:outcome.append(type(e).__name__)
   ct=threading.Thread(target=client,daemon=True);ct.start()
   samples=[]
   deadline=time.monotonic()+28
   while time.monotonic()<deadline:
    val=rss(p.pid)
    if val is not None:samples.append(val)
    if not ct.is_alive():break
    time.sleep(.002)
   ct.join(timeout=1);t.join(timeout=1)
   after=rss(p.pid)
   result={"variant":label,"rss_before_kib":before,"rss_peak_kib":max(samples) if samples else None,"rss_after_kib":after,"rss_growth_kib":max(samples)-before if samples and before is not None else None,"samples":len(samples),"hints_sent":stats["sent"],"upstream_broken":stats["broken"],"response":outcome[:1]}
   print("AB_RESULT "+json.dumps(result),flush=True)
   return result
  finally:
   p.terminate()
   try:p.wait(timeout=3)
   except subprocess.TimeoutExpired:p.kill();p.wait()
a=execute(os.path.abspath(sys.argv[1]),"unpatched")
b=execute(os.path.abspath(sys.argv[2]),"patched")
assert a["rss_growth_kib"] is not None and b["rss_growth_kib"] is not None
assert a["hints_sent"]>=100000, "unpatched exposure too short"
assert b["rss_growth_kib"]<16384, "patched RSS growth exceeded bound"
assert a["rss_growth_kib"]>b["rss_growth_kib"]+16384, "no material A/B difference"
print("AB_VERDICT PASS",flush=True)
