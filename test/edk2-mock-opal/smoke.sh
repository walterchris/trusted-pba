#!/usr/bin/env bash
#
# Dispatch smoke test: boot OVMF with MockOpalDxe.efi staged on the ESP and a
# Driver0000 entry pointing at it, then assert via serial markers that the
# driver was dispatched, installed its protocol, and did not break the boot
# (the boot app still runs). Full PBA-unlock integration is a later task.
#
#   smoke.sh <bootapp.efi>     e.g. bin/testapp.efi (task build:testapp)
#
# Requires MockOpalDxe.efi (run ./build.sh first) and the test/qemu harness
# prerequisites (qemu, OVMF, mtools, python3 + virt-firmware).

set -euo pipefail

HERE="$(dirname "$(readlink -f "$0")")"
QEMU_DIR="$HERE/../qemu"
APP="${1:?usage: smoke.sh <bootapp.efi>}"
DRIVER="$HERE/MockOpalDxe.efi"

[ -f "$DRIVER" ] || { echo "MockOpalDxe.efi not found; run $HERE/build.sh" >&2; exit 2; }

# Driver0000 -> \EFI\MOCK\MOCKOPALDXE.EFI in a copy of the stock (Setup Mode)
# VARS template; run-qemu.sh stages the driver at that path when DRIVER is set.
. "$QEMU_DIR/ovmf-pair.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 "$QEMU_DIR/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.fd" \
	'\EFI\MOCK\MOCKOPALDXE.EFI'

DRIVER="$DRIVER" OVMF_VARS="$WORK/vars.fd" \
REQUIRE='MOCKOPAL: dispatched,MOCKOPAL: protocol installed,TEST-APP: ok' \
FORBID='MOCKOPAL: install failed,MOCKOPAL: fault' \
	python3 "$QEMU_DIR/expect-serial.py" "$APP"
