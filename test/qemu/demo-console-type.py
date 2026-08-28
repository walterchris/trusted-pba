#!/usr/bin/env python3
"""Demo helper: wait for the PBA's "SED passphrase:" prompt in the serial log,
then type the passphrase over QMP send-key (PS/2 -> ConIn, the console credential
source, headless-safe). Unlike test/qemu/console-qmp.py this asserts nothing and
leaves QEMU running so the demo boots on to Linux — it just supplies the keystrokes
a human would type when INTERACTIVE is not set.

Env: QMP_SOCK, SERIAL_LOG, PASSPHRASE (default "correct horse"),
     PROMPT_TIMEOUT (default 180)."""
import json
import os
import socket
import time

QMP_SOCK = os.environ["QMP_SOCK"]
SERIAL_LOG = os.environ["SERIAL_LOG"]
PASSPHRASE = os.environ.get("PASSPHRASE", "correct horse")
PROMPT_TIMEOUT = float(os.environ.get("PROMPT_TIMEOUT", "180"))
PROMPT = "SED passphrase:"

# PS/2 qcode per character (the demo passphrase is lowercase + space).
KEY = {" ": "spc"}
for c in "abcdefghijklmnopqrstuvwxyz0123456789":
    KEY[c] = c


def qmp_connect():
    for _ in range(int(PROMPT_TIMEOUT)):
        try:
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(10)
            s.connect(QMP_SOCK)
            f = s.makefile("rw")
            f.readline()  # greeting
            f.write('{"execute":"qmp_capabilities"}\n')
            f.flush()
            f.readline()
            return s, f
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(1)
    raise SystemExit("demo-console-type: QMP socket never appeared")


def send_key(f, qcode):
    f.write(json.dumps({"execute": "send-key",
                        "arguments": {"keys": [{"type": "qcode", "data": qcode}]}}) + "\n")
    f.flush()
    for _ in range(20):
        if '"return"' in f.readline():
            break


def wait_for_prompt():
    deadline = time.time() + PROMPT_TIMEOUT
    while time.time() < deadline:
        try:
            with open(SERIAL_LOG, "r", errors="ignore") as fh:
                if PROMPT in fh.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    return False


def main():
    s, f = qmp_connect()
    if not wait_for_prompt():
        print("demo-console-type: prompt never appeared; not typing")
        return
    time.sleep(0.5)
    for ch in PASSPHRASE:
        send_key(f, KEY.get(ch, ch))
        time.sleep(0.06)
    send_key(f, "ret")
    print(f"demo-console-type: typed {len(PASSPHRASE)} chars + Enter")


if __name__ == "__main__":
    main()
