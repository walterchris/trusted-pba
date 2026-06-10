#!/usr/bin/env python3
"""Boot the Trusted PBA via run-qemu.sh and assert serial markers.

Spawns run-qemu.sh (which builds the ESP — including the chainload test app when
TESTAPP is set — and launches QEMU/OVMF with serial on stdout), scans the serial
stream within a timeout, then tears QEMU down.

Pass requires that every REQUIRE marker appears and no FORBID marker appears. This
supports both the happy path and fail-closed (negative) tests.

FORBID stays live after the last REQUIRE: once every REQUIRE has matched, the
harness keeps draining serial output for a bounded grace window (EXPECT_GRACE)
— or until QEMU exits — and only then declares PASS. A PBA that logs the final
required failure marker and then boots anyway (forbidden marker after the last
REQUIRE) therefore still FAILs. A FORBID hit at any point is an immediate FAIL.
The window ends by timer, not EOF, so a guest that dead-stops (on_error "halt")
adds at most the grace window to the runtime.

    expect-serial.py <pba.efi>

Env:
  QEMU_TIMEOUT  seconds (default 120)
  EXPECT_GRACE  seconds to keep draining for FORBID markers after the last
                REQUIRE matched (default 8)
  TESTAPP       path, forwarded to run-qemu.sh to stage the chainload target
  REQUIRE       comma-separated markers that must all appear
                (default: the happy chainload path with the loud SED-unlock
                skip the default sed_unlock="none" policy must announce)
  FORBID        comma-separated markers that must NOT appear (default: both
                SED-unlock outcome markers — a "none" run must never unlock,
                so a policy-variant mixup can never silently pass)
  EXPECT_STUB   self-test only: a shell command used as the serial source
                instead of run-qemu.sh (see harness-selftest.sh); the
                <pba.efi> argument is then ignored and may be omitted
"""
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "run-qemu.sh")

DEFAULT_REQUIRE = (
    "TRUSTED-PBA: start,TRUSTED-PBA: sed unlock not required by policy,"
    "TEST-APP: ok,TRUSTED-PBA: chainload returned"
)
DEFAULT_FORBID = "TRUSTED-PBA: sed unlock ok,TRUSTED-PBA: sed unlock failed"
TIMEOUT = float(os.environ.get("QEMU_TIMEOUT", "120"))
GRACE = float(os.environ.get("EXPECT_GRACE", "8"))


def _markers(env, default):
    return tuple(
        re.compile(p.strip().encode())
        for p in os.environ.get(env, default).split(",")
        if p.strip()
    )


REQUIRE = _markers("REQUIRE", DEFAULT_REQUIRE)
FORBID = _markers("FORBID", DEFAULT_FORBID)


class _HardTimeout(Exception):
    pass


def _on_alarm(_signum, _frame):
    # Raised in the main thread, interrupting a blocking readline() so a silent
    # QEMU hang (no newline ever emitted) cannot wedge the harness forever.
    raise _HardTimeout()


def main() -> int:
    stub = os.environ.get("EXPECT_STUB")
    if stub:
        argv = ["/bin/sh", "-c", stub]  # self-test: scripted serial source
    else:
        if len(sys.argv) != 2:
            sys.exit("usage: expect-serial.py <pba.efi>")
        app = sys.argv[1]
        if not os.path.isfile(app):
            sys.exit(f"not found: {app}")
        argv = [RUN, app]

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,  # own process group so we can kill QEMU's tree
    )
    deadline = time.monotonic() + TIMEOUT
    seen = set()
    forbidden = None
    grace_end = None  # set once every REQUIRE has matched; FORBID stays live
    buf = b""
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT + 2)
    try:
        for line in iter(proc.stdout.readline, b""):
            sys.stdout.buffer.write(line)
            sys.stdout.flush()
            buf += line
            forbidden = next((m.pattern for m in FORBID if m.search(buf)), None)
            if forbidden:
                break
            if grace_end is None:
                seen = {m.pattern for m in REQUIRE if m.search(buf)}
                if len(seen) == len(REQUIRE):
                    # All REQUIREs matched — do NOT pass yet. Keep draining for
                    # a bounded grace window so a forbidden marker emitted after
                    # the last REQUIRE (e.g. a chainload following a logged
                    # unlock failure) still fails the run. A halted guest never
                    # EOFs, so the window must end by timer, not EOF: re-arm
                    # the alarm to break a blocked readline() at the window end.
                    grace_end = time.monotonic() + GRACE
                    signal.setitimer(signal.ITIMER_REAL, GRACE + 1)
                elif time.monotonic() > deadline:
                    print("\n[expect-serial] FAIL: timeout", flush=True)
                    break
            elif time.monotonic() > grace_end:
                break
    except _HardTimeout:
        if grace_end is None:
            print("\n[expect-serial] FAIL: hard timeout (no output)", flush=True)
        # else: guest went silent during the grace window — the expected end of
        # a fail-closed/halt scenario; judge everything read so far below.
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
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

    if forbidden:
        print(f"[expect-serial] FAIL: forbidden marker observed: {forbidden.decode()}")
        return 1
    missing = [m.pattern.decode() for m in REQUIRE if m.pattern not in seen]
    if missing:
        print(f"[expect-serial] FAIL: missing markers: {missing}")
        return 1
    print("[expect-serial] PASS: all required markers observed; no forbidden markers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
