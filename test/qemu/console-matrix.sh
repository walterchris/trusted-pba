#!/usr/bin/env bash
#
# Automated console-credential-source matrix (ADR-0011 A2, #99).
#
# Tests the interactive passphrase path end-to-end in QEMU/OVMF with
# MockOpalDxe as the virtual SED, completely headlessly — no human
# keystrokes required in CI.
#
# KEY INJECTION MECHANISM — why QMP send-key, not serial stdin
# ============================================================
# OVMF's TerminalDxe decodes incoming UART bytes as VT100/PC-ANSI escape
# sequences.  Under -nographic/-display none the bytes arrive as a burst
# rather than one-per-keystroke, and the decoder mangles them into garbled
# or missing characters (confirmed empirically: passphrase arrives corrupted,
# auth fails spuriously).
#
# QMP send-key injects PS/2 keyboard scan-code events that reach OVMF's
# EFI_SIMPLE_TEXT_INPUT (ConIn) directly — bypassing TerminalDxe entirely.
# This is exactly what the console credential source reads (ADR-0011 §4).
# Verified under -display none on QEMU 9.2.4 + Fedora OVMF 202402: OVMF's
# q35 machine wires a PS/2 i8042 controller to ConIn regardless of whether a
# display device is present, so send-key reaches ConIn reliably headless.
#
# Serial output is routed to a FILE (not stdio) so the expect driver can poll
# it without consuming QEMU's stdin. QMP runs on a UNIX-domain socket.
#
# Scenarios
# =========
#   POS: type "correct horse" → REQUIRE MOCKOPAL auth ok + sed unlock ok +
#        TEST-APP: ok; FORBID sed unlock failed.
#        Proves the console source delivers the right credential.
#
#   NEG: type "wrong pass"   → REQUIRE TRUSTED-PBA: sed unlock failed;
#        FORBID MOCKOPAL: auth ok + sed unlock ok + TEST-APP: ok.
#        Proves fail-closed on a wrong interactive passphrase (mutation-proof:
#        the FORBIDs are live for the full grace window after the last REQUIRE,
#        so a PBA that logs the failure then boots anyway still FAILs).
#
#   console-matrix.sh <pba-consoletest.efi> <testapp.efi>
#
# Prerequisites: QEMU, OVMF, mtools, python3, virt-firmware (pip),
#   MockOpalDxe.efi (test/edk2-mock-opal/build.sh).
set -euo pipefail

PBA="${1:?usage: console-matrix.sh <pba-consoletest.efi> <testapp.efi>}"
TESTAPP="${2:?usage: console-matrix.sh <pba-consoletest.efi> <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
DRIVER="$HERE/../edk2-mock-opal/MockOpalDxe.efi"
QMP_DRIVER="$HERE/console-qmp.py"

. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"

[ -f "$DRIVER" ] || {
    echo "MockOpalDxe.efi not found; run test/edk2-mock-opal/build.sh" >&2
    exit 2
}
[ -f "$PBA" ] || { echo "PBA not found: $PBA" >&2; exit 2; }
[ -f "$TESTAPP" ] || { echo "TESTAPP not found: $TESTAPP" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Inject Driver0000 so OVMF dispatches MockOpalDxe before the PBA.
python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.fd" '\EFI\MOCK\MOCKOPALDXE.EFI'

# run_console_scenario <label> <passphrase> <REQUIRE> <FORBID>
#
# Builds a per-run ESP, launches QEMU headless with:
#   -serial file:$WORK/$label/serial.log
#   -qmp    unix:$WORK/$label/qmp.sock,server,nowait
#   -display none
# then delegates to console-qmp.py which waits for the prompt,
# injects the passphrase via QMP, and asserts the markers.
run_console_scenario() {
    local label="$1" passphrase="$2" require="$3" forbid="$4"
    local sdir="$WORK/$label"
    mkdir -p "$sdir"

    local img="$sdir/esp.img"
    local vars="$sdir/vars.fd"
    local serial_log="$sdir/serial.log"
    local qmp_sock="$sdir/qmp.sock"

    # Build the ESP for this scenario.
    truncate -s 64M "$img"
    mformat -i "$img" -F ::
    mmd -i "$img" ::/EFI ::/EFI/BOOT ::/EFI/TEST ::/EFI/MOCK
    mcopy -i "$img" "$PBA" ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i "$img" "$TESTAPP" ::/EFI/TEST/TESTAPP.EFI
    mcopy -i "$img" "$DRIVER" ::/EFI/MOCK/MOCKOPALDXE.EFI

    cp "$WORK/vars.fd" "$vars"
    chmod u+w "$vars"

    # Launch QEMU: serial → file, QMP → UNIX socket, no display.
    # -no-reboot: OVMF reboots on EFI_SUCCESS from the last boot option; the PBA
    # exits after chainload returns, so -no-reboot stops the cycle after one run.
    qemu-system-x86_64 \
        -machine q35 -accel tcg -cpu max -m 2G \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_SECBOOT_CODE" \
        -drive if=pflash,format=raw,unit=1,file="$vars" \
        -drive "format=raw,file=$img,if=none,id=esp" \
        -device virtio-blk-pci,drive=esp \
        -serial "file:$serial_log" \
        -qmp "unix:$qmp_sock,server,nowait" \
        -display none \
        -no-reboot \
        -net none &
    local qpid=$!

    # Run the QMP/expect driver; capture its exit code.
    local rc=0
    QMP_SOCK="$qmp_sock" \
    SERIAL_LOG="$serial_log" \
    PASSPHRASE="$passphrase" \
    REQUIRE="$require" \
    FORBID="$forbid" \
    PROMPT_TIMEOUT=180 \
    DRAIN_TIMEOUT=60 \
    GRACE_TIMEOUT=8 \
        python3 "$QMP_DRIVER" || rc=$?

    # Always clean up QEMU.
    kill "$qpid" 2>/dev/null || true
    wait "$qpid" 2>/dev/null || true

    return "$rc"
}

fail=0

# --------------------------------------------------------------------------
# Scenario POS: correct passphrase → full unlock + chainload
# --------------------------------------------------------------------------
scenario "POS: correct horse → auth ok + sed unlock ok + chainload" \
    run_console_scenario "pos" \
        "correct horse" \
        "MOCKOPAL: auth ok,TRUSTED-PBA: sed unlock ok,TEST-APP: ok" \
        "TRUSTED-PBA: sed unlock failed"

# --------------------------------------------------------------------------
# Scenario NEG: wrong passphrase → fail closed, never boots
# --------------------------------------------------------------------------
scenario "NEG: wrong pass → sed unlock failed (fail closed)" \
    run_console_scenario "neg" \
        "wrong pass" \
        "TRUSTED-PBA: sed unlock failed" \
        "MOCKOPAL: auth ok,TRUSTED-PBA: sed unlock ok,TEST-APP: ok"

echo
if [ "$fail" -eq 0 ]; then
    echo "CONSOLE MATRIX: PASS"
else
    echo "CONSOLE MATRIX: FAIL"
    exit 1
fi
