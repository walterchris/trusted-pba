#!/usr/bin/env python3
"""Boot the Trusted PBA via run-qemu.sh and assert the expected serial markers.

Spawns run-qemu.sh (which builds the ESP — including the chainload test app when
TESTAPP is set — and launches QEMU/OVMF with serial on stdout), scans the serial
stream for every REQUIRED marker within a timeout, then tears QEMU down. Exits 0
only if all required markers are observed.

    expect-serial.py <pba.efi>

Env: QEMU_TIMEOUT (seconds, default 120); TESTAPP (path, forwarded to run-qemu.sh).
"""
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "run-qemu.sh")

# Markers that must all appear on serial for the run to pass. Phase 1 proves the
# full chainload path: the PBA starts, the chainloaded test app runs, and control
# returns to the PBA.
REQUIRED = (
    re.compile(rb"TRUSTED-PBA: start"),
    re.compile(rb"TEST-APP: ok"),
    re.compile(rb"TRUSTED-PBA: chainload returned"),
)
TIMEOUT = float(os.environ.get("QEMU_TIMEOUT", "120"))


class _HardTimeout(Exception):
    pass


def _on_alarm(_signum, _frame):
    # Raised in the main thread, interrupting a blocking readline() so a silent
    # QEMU hang (no newline ever emitted) cannot wedge the harness forever.
    raise _HardTimeout()


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: expect-serial.py <pba.efi>")
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
    seen = set()
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
            seen = {m.pattern for m in REQUIRED if m.search(buf)}
            if len(seen) == len(REQUIRED):
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

    missing = [m.pattern.decode() for m in REQUIRED if m.pattern not in seen]
    if not missing:
        print("[expect-serial] PASS: all markers observed")
        return 0
    print(f"[expect-serial] FAIL: missing markers: {missing}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
