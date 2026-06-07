#!/usr/bin/env python3
"""Boot a Trusted PBA .efi via run-qemu.sh and assert the Phase-0 serial markers.

Spawns run-qemu.sh (which builds the ESP and launches QEMU/OVMF with serial on
stdout), scans the serial stream for the start and success markers within a
timeout, then tears QEMU down. Exit 0 only if both markers are observed.

    expect-serial.py <app.efi>

Env: QEMU_TIMEOUT (seconds, default 120).
"""
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "run-qemu.sh")

START = re.compile(rb"TRUSTED-PBA: start")
SUCCESS = re.compile(rb"TRUSTED-PBA: phase-0 skeleton ok")
TIMEOUT = float(os.environ.get("QEMU_TIMEOUT", "120"))


class _HardTimeout(Exception):
    pass


def _on_alarm(_signum, _frame):
    # Raised in the main thread, interrupting a blocking readline() so a silent
    # QEMU hang (no newline ever emitted) cannot wedge the harness forever.
    raise _HardTimeout()


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: expect-serial.py <app.efi>")
    app = sys.argv[1]
    if not os.path.isfile(app):
        sys.exit(f"not found: {app}")

    proc = subprocess.Popen(
        [RUN, app],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,  # own process group so we can kill QEMU's tree
    )
    deadline = time.monotonic() + TIMEOUT
    seen_start = seen_ok = False
    buf = b""
    # Hard wall-clock guard: fires even if QEMU emits no further bytes (blocking
    # readline). A couple of seconds of slack over the soft deadline below.
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(int(TIMEOUT) + 2)
    try:
        for line in iter(proc.stdout.readline, b""):
            sys.stdout.buffer.write(line)
            sys.stdout.flush()
            buf += line
            if START.search(buf):
                seen_start = True
            if SUCCESS.search(buf):
                seen_ok = True
            if seen_start and seen_ok:
                break
            if time.monotonic() > deadline:
                print("\n[expect-serial] FAIL: timeout", flush=True)
                break
    except _HardTimeout:
        print("\n[expect-serial] FAIL: hard timeout (no output)", flush=True)
    finally:
        signal.alarm(0)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

    if seen_start and seen_ok:
        print("[expect-serial] PASS: start + phase-0 markers observed")
        return 0
    print(f"[expect-serial] FAIL: start={seen_start} ok={seen_ok}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
