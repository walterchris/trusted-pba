#!/usr/bin/env python3
"""QMP-driven keyboard injection + serial-expect driver for the console-matrix.

Boots a consoletest PBA in an already-running QEMU instance (serial log at
SERIAL_LOG, QMP socket at QMP_SOCK), waits for the "SED passphrase:" prompt,
injects the passphrase character-by-character via QMP send-key (PS/2 qcode
events that reach OVMF's EFI_SIMPLE_TEXT_INPUT / ConIn cleanly), then asserts
REQUIRE/FORBID markers in the serial log.

Why QMP send-key instead of serial stdin:
  OVMF's TerminalDxe connects the UART as a secondary ConIn device and runs a
  VT100/PC-ANSI decoder on the incoming bytes. Under non-interactive (headless)
  use the bytes arrive as a burst rather than one per keystroke, and the decoder
  mangles them into garbled or missing characters. QMP send-key injects PS/2
  keyboard events that bypass TerminalDxe entirely and reach EFI_SIMPLE_TEXT_INPUT
  directly — exactly what the console credential source reads (ADR-0011 §4).
  Verified under -display none: OVMF's q35 machine wires a PS/2 controller to
  ConIn regardless of display presence (confirmed empirically on QEMU 9.2.4 +
  Fedora OVMF 202402).

Key mapping:
  a-z     -> qcode is the character itself
  space   -> "spc"
  Enter   -> "ret"
  The test passphrase ("correct horse") uses only lowercase letters and a space,
  so no Shift injection is needed.

Environment variables (all required — set by console-matrix.sh):
  QMP_SOCK      path to the UNIX-domain QMP control socket
  SERIAL_LOG    path to the file QEMU writes serial output to (-serial file:...)
  PASSPHRASE    passphrase to type (e.g. "correct horse" or "wrong pass")
  REQUIRE       comma-separated marker strings that MUST appear in serial output
  FORBID        comma-separated marker strings that MUST NOT appear
  PROMPT_TIMEOUT  seconds to wait for "SED passphrase:" (default 180)
  DRAIN_TIMEOUT   seconds to wait for all REQUIRE markers after key injection
                  (default 60)
  GRACE_TIMEOUT   seconds to keep draining for FORBID markers after the last
                  REQUIRE matched (default 8)
"""

import json
import os
import re
import socket
import sys
import time

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

QMP_SOCK = os.environ["QMP_SOCK"]
SERIAL_LOG = os.environ["SERIAL_LOG"]
PASSPHRASE = os.environ["PASSPHRASE"]

REQUIRE_RAW = os.environ.get("REQUIRE", "")
FORBID_RAW = os.environ.get("FORBID", "")
PROMPT_TIMEOUT = float(os.environ.get("PROMPT_TIMEOUT", "180"))
DRAIN_TIMEOUT = float(os.environ.get("DRAIN_TIMEOUT", "60"))
GRACE_TIMEOUT = float(os.environ.get("GRACE_TIMEOUT", "8"))

# Compile marker patterns (same semantics as expect-serial.py).
_REQUIRE = [re.compile(p.strip().encode()) for p in REQUIRE_RAW.split(",") if p.strip()]
_FORBID = [re.compile(p.strip().encode()) for p in FORBID_RAW.split(",") if p.strip()]


# ---------------------------------------------------------------------------
# QMP helpers
# ---------------------------------------------------------------------------

class QMP:
    """Minimal synchronous QMP client over a UNIX socket."""

    def __init__(self, path: str) -> None:
        self._s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._s.connect(path)
        self._s.settimeout(10)
        self._buf = b""
        # Consume the greeting
        greeting = self._recv()
        qver = greeting.get("QMP", {}).get("version", {}).get("qemu", {})
        print(f"[qmp] connected — QEMU {qver.get('major')}.{qver.get('minor')}.{qver.get('micro')}")
        # Negotiate capabilities
        self._send({"execute": "qmp_capabilities"})
        self._recv()  # {"return": {}}

    def _send(self, obj: dict) -> None:
        self._s.sendall(json.dumps(obj).encode())

    def _recv(self) -> dict:
        while True:
            chunk = self._s.recv(4096)
            if not chunk:
                raise EOFError("QMP socket closed")
            self._buf += chunk
            try:
                obj = json.loads(self._buf.decode())
                self._buf = b""
                return obj
            except json.JSONDecodeError:
                continue

    def send_key(self, qcode: str) -> None:
        self._send({
            "execute": "send-key",
            "arguments": {"keys": [{"type": "qcode", "data": qcode}]},
        })
        try:
            self._recv()
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._s.close()
        except OSError:
            pass


def _char_to_qcode(ch: str) -> str:
    if ch == " ":
        return "spc"
    if ch.islower() or ch.isdigit():
        return ch
    raise ValueError(f"unsupported character for qcode injection: {ch!r} "
                     "(only lowercase letters, digits, and space are supported)")


def inject_passphrase(qmp: QMP, passphrase: str, inter_key_delay: float = 0.05) -> None:
    """Inject each character of passphrase, then press Enter."""
    for ch in passphrase:
        qmp.send_key(_char_to_qcode(ch))
        time.sleep(inter_key_delay)
    qmp.send_key("ret")
    time.sleep(inter_key_delay)


# ---------------------------------------------------------------------------
# Serial-log polling
# ---------------------------------------------------------------------------

def _read_serial() -> bytes:
    try:
        with open(SERIAL_LOG, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return b""


def wait_for_prompt(prompt: bytes, deadline: float) -> bool:
    while time.monotonic() < deadline:
        if prompt in _read_serial():
            return True
        time.sleep(0.25)
    return False


def wait_for_markers(require: list, forbid: list, deadline: float, grace: float) -> tuple[bool, str]:
    """Poll serial log for REQUIRE/FORBID markers.

    Returns (passed: bool, reason: str).
    FORBID hit → immediate fail.
    All REQUIRE matched → drain for `grace` more seconds watching for FORBID.
    Timeout → fail if any REQUIRE not yet matched.
    """
    seen: set[bytes] = set()
    grace_deadline: float | None = None

    while True:
        now = time.monotonic()
        data = _read_serial()

        for pat in forbid:
            if pat.search(data):
                return False, f"FORBID marker hit: {pat.pattern.decode()!r}"

        if grace_deadline is None:
            for pat in require:
                if pat.search(data):
                    seen.add(pat.pattern)
            if len(seen) == len(require):
                grace_deadline = time.monotonic() + grace

            if now > deadline:
                missing = [p.pattern.decode() for p in require if p.pattern not in seen]
                return False, f"timeout — missing REQUIRE markers: {missing}"
        else:
            if time.monotonic() > grace_deadline:
                return True, "all REQUIRE matched; no FORBID in grace window"

        time.sleep(0.25)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print(f"[console-qmp] passphrase='{PASSPHRASE}'")
    print(f"[console-qmp] REQUIRE={REQUIRE_RAW!r}")
    print(f"[console-qmp] FORBID={FORBID_RAW!r}")

    # Wait for QMP socket (QEMU may still be starting).
    qmp_deadline = time.monotonic() + 30
    while not os.path.exists(QMP_SOCK):
        if time.monotonic() > qmp_deadline:
            print("[console-qmp] FAIL: QMP socket did not appear within 30s")
            return 1
        time.sleep(0.25)

    qmp = QMP(QMP_SOCK)

    # Phase 1: wait for the passphrase prompt.
    prompt_deadline = time.monotonic() + PROMPT_TIMEOUT
    print(f"[console-qmp] waiting for 'SED passphrase:' (timeout {PROMPT_TIMEOUT}s)...")
    if not wait_for_prompt(b"SED passphrase:", prompt_deadline):
        print(f"[console-qmp] FAIL: 'SED passphrase:' prompt not seen within {PROMPT_TIMEOUT}s")
        print("[console-qmp] --- serial log tail ---")
        data = _read_serial()
        sys.stdout.buffer.write(data[-4096:] if len(data) > 4096 else data)
        sys.stdout.flush()
        qmp.close()
        return 1
    print("[console-qmp] prompt found; injecting passphrase...")

    # Small settle delay — give OVMF time to fully arm ConIn after printing the prompt.
    time.sleep(0.5)

    # Phase 2: inject keystrokes.
    inject_passphrase(qmp, PASSPHRASE)
    qmp.close()

    # Phase 3: wait for REQUIRE/FORBID markers.
    marker_deadline = time.monotonic() + DRAIN_TIMEOUT
    passed, reason = wait_for_markers(_REQUIRE, _FORBID, marker_deadline, GRACE_TIMEOUT)

    # Print the serial log for CI artifact / debugging.  QEMU may flush its
    # file buffer only on exit; if the file is empty here (QEMU still running
    # and hasn't flushed yet) the caller's tee/stdout capture already has the
    # serial output from QEMU's own stdout, so this is informational only.
    log_data = _read_serial()
    print(f"\n[console-qmp] --- serial log ({len(log_data)} bytes) ---")
    if log_data:
        sys.stdout.buffer.write(log_data)
        sys.stdout.flush()
    print("\n[console-qmp] --- end serial log ---")

    if passed:
        print(f"[console-qmp] PASS: {reason}")
        return 0
    else:
        print(f"[console-qmp] FAIL: {reason}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
