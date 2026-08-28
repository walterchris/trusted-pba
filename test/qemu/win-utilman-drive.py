#!/usr/bin/env python3
"""At the PBA-booted Windows logon screen, open an elevated SYSTEM shell via the
Utilman trick (Utilman.exe has been replaced by cmd.exe offline; the Ease-of-Access
button launches it as SYSTEM), and run a PowerShell script from C:. Drives QEMU over
QMP (send-key + input-send-event); screenshots at each step. No login needed (the
demo image's autologon is intentionally broken).

  win-utilman-drive.py <qmp.sock> <shotdir> <shotprefix> <ps1-path-on-C e.g. C:\\bitlocker-enable.ps1>
"""
import socket, sys, json, time, os
SOCK, SHOT, PFX, PS1 = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def conn():
    for _ in range(120):
        if os.path.exists(SOCK): break
        time.sleep(0.5)
    s = socket.socket(socket.AF_UNIX); s.settimeout(20); s.connect(SOCK)
    f = s.makefile("rw"); f.readline()
    f.write('{"execute":"qmp_capabilities"}\n'); f.flush(); f.readline()
    return s, f
S, F = conn()
def cmd(c):
    F.write(json.dumps(c)+"\n"); F.flush()
    for _ in range(30):
        l = F.readline()
        if '"return"' in l or '"error"' in l: return l
    return ""
def shot(n):
    p=f"{SHOT}/{PFX}-{n}.png"; cmd({"execute":"screendump","arguments":{"filename":p,"format":"png"}})
    print(f"[shot] {n} -> {os.path.getsize(p) if os.path.exists(p) else 'MISS'}", flush=True)
def keys(*ks):
    cmd({"execute":"send-key","arguments":{"keys":[{"type":"qcode","data":k} for k in ks]}}); time.sleep(0.08)
def click(px,py):  # pixel coords in a 1280x800 frame -> absolute tablet coords
    x=int(px/1280*32767); y=int(py/800*32767)
    cmd({"execute":"input-send-event","arguments":{"events":[
        {"type":"abs","data":{"axis":"x","value":x}},{"type":"abs","data":{"axis":"y","value":y}}]}}); time.sleep(0.2)
    cmd({"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"button":"left","down":True}}]}}); time.sleep(0.1)
    cmd({"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"button":"left","down":False}}]}}); time.sleep(0.3)
PLAIN={' ':'spc','-':'minus','.':'dot','\\':'backslash','/':'slash'}
def typ(s):
    for ch in s:
        if ch.isalpha(): keys('shift',ch.lower()) if ch.isupper() else keys(ch)
        elif ch.isdigit(): keys(ch)
        elif ch==':': keys('shift','semicolon')
        elif ch in PLAIN: keys(PLAIN[ch])
        else: keys(ch)
def wait(sec,label): print(f"[wait] {sec}s {label}",flush=True); time.sleep(sec)

wait(85,"boot to logon"); shot("logon")
keys("ret"); wait(2,"dismiss autologon domain error"); shot("afterOK")
click(1188,757); wait(5,"Ease-of-Access -> Utilman=cmd (SYSTEM)"); shot("cmd")
typ(f"powershell -ExecutionPolicy Bypass -File {PS1}"); keys("ret")
print("[run] launched",PS1,flush=True)
wait(25,"enabling BitLocker"); shot("running")
for i in range(10):
    wait(20,f"encrypt poll {i}"); shot(f"enc{i}")
print("[done]",flush=True); S.close()
