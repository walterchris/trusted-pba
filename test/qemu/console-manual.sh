#!/usr/bin/env bash
#
# Manual / interactive test of the `console` credential source (ADR-0011, A2).
# Boots a `-tags consoletest` PBA in QEMU/OVMF with the MockOpalDxe virtual SED
# and prompts for the SED passphrase — YOU type it. Unlike the expect-driven
# matrices, QEMU runs attached to your terminal so the guest's SimpleTextInput
# receives your keystrokes.
#
#   test/qemu/console-manual.sh <pba-consoletest.efi> <testapp.efi>
#
# At the "SED passphrase:" prompt type the MockOpalDxe Admin1 PIN — `correct horse`
# — to unlock (expect: sed unlock ok -> TEST-APP: ok). A wrong PIN fails closed.
# Quit QEMU with Ctrl-A then X.
set -euo pipefail

PBA="${1:?usage: console-manual.sh <pba-consoletest.efi> <testapp.efi>}"
TESTAPP="${2:?usage: console-manual.sh <pba-consoletest.efi> <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
DRIVER="$HERE/../edk2-mock-opal/MockOpalDxe.efi"
. "$HERE/ovmf-pair.sh"

[ -f "$DRIVER" ] || { echo "MockOpalDxe.efi not found; run test/edk2-mock-opal/build.sh" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Inject a Driver0000 entry so OVMF dispatches MockOpalDxe (the virtual SED).
python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.fd" '\EFI\MOCK\MOCKOPALDXE.EFI'

echo "############################################################"
echo "## Interactive console-source test."
echo "## At 'SED passphrase:' type the mock Admin1 PIN:  correct horse"
echo "##   right PIN  -> TRUSTED-PBA: sed unlock ok -> TEST-APP: ok"
echo "##   wrong PIN  -> sed unlock failed (fail closed)"
echo "## Quit QEMU: Ctrl-A X"
echo "############################################################"

# virtio-blk ESP so the QEMU disk adds no competing Storage Security instance;
# MockOpalDxe stays the sole SED. Run run-qemu.sh in the foreground (interactive).
exec env OVMF_VARS="$WORK/vars.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" QEMU_DISK_IF=virtio \
	"$HERE/run-qemu.sh" "$PBA"
