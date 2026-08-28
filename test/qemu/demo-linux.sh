#!/usr/bin/env bash
#
# demo:linux — one watchable, flag-driven full-boot showcase of Trusted PBA:
#
#   PBA banner -> Secure Boot state -> mock Opal SED unlock (MockOpalDxe) ->
#   the PBA validates + chainloads a signed Alpine UKI -> a REAL Alpine Linux
#   boots to a login prompt.
#
#   demo-linux.sh <pba.efi>
#
# Flags (task demo:linux VAR=value, or VAR=value in the environment):
#   SECUREBOOT=1  (default) firmware Secure Boot ENFORCING, db = the PBA's key A
#                 ONLY; the Key-B-signed UKI is admitted by the PBA's trust broker
#                 via the Security2 override (validation "pba-override"). This is
#                 the single-hop broker: firmware trusts only the PBA, the PBA
#                 vouches for the OS against its own trust store.
#   SECUREBOOT=0  no Secure Boot; the PBA verifies the UKI ("pba") and chainloads
#                 it directly (no firmware gate to bypass, no override).
#   INTERACTIVE=1 you type the SED passphrase yourself ("correct horse"); default
#                 (0) auto-types it over QMP so the demo runs unattended.
#   SERIAL=1      headless serial run (no QEMU window); composes with the above.
#   NOKVM=1       force TCG.  OVMF_CODE/OVMF_VARS override the firmware pair.
#
# Prerequisites: demo-secureboot-setup.sh has run (keys P/B + Key-B-signed UKI in
# bin/demosb/), MockOpalDxe built (task build:mock-opal), and the PBA built with
# the matching variant (demolinuxsb,pbatest,trustbroker for SECUREBOOT=1;
# demolinuxplain,pbatest for SECUREBOOT=0) — the Taskfile wires all three.
#
# All keys are throwaway (bin/demosb/), never committed (baseline §13).
set -euo pipefail

PBA="${1:?usage: demo-linux.sh <pba.efi>}"
SECUREBOOT="${SECUREBOOT:-1}"
INTERACTIVE="${INTERACTIVE:-0}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/bin/demosb"
DRIVER="$HERE/../edk2-mock-opal/MockOpalDxe.efi"

[ -f "$OUT/alpine-signed.efi" ] || { echo "run demo-secureboot-setup.sh first (bin/demosb missing)" >&2; exit 2; }
[ -f "$DRIVER" ] || { echo "MockOpalDxe.efi not found; run: task build:mock-opal" >&2; exit 2; }
ISO="$(cat "$OUT/iso.path")"

. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"

WORK="$(mktemp -d)"
QEMU_PID=""; TAIL_PID=""; TYPER_PID=""
cleanup() {
	for p in "$QEMU_PID" "$TYPER_PID" "$TAIL_PID"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 143' TERM INT

# ---- Firmware variables + PBA image -------------------------------------------
VARS0="$WORK/vars0.fd"
if [ "$SECUREBOOT" = 1 ]; then
	resolve_vfv
	GUID="$(uuidgen)"
	echo "## Signing the PBA with the platform key (key A)"
	sbsign --key "$OUT/P.key" --cert "$OUT/P.crt" --output "$WORK/pba-run.efi" "$PBA" >/dev/null
	echo "## Enrolling Secure Boot (enforcing): PK/KEK + db = { key A only } — the UKI (key B) is NOT in db"
	"$VFV" --input "$OVMF_VARS_TEMPLATE" --output "$VARS0" \
		--set-pk  "$GUID" "$OUT/PK.crt" \
		--add-kek "$GUID" "$OUT/KEK.crt" \
		--add-db  "$GUID" "$OUT/P.crt" \
		--no-microsoft --secure-boot >/dev/null
	echo "## Signing the MockOpalDxe driver with key A (firmware must validate it before dispatch)"
	sbsign --key "$OUT/P.key" --cert "$OUT/P.crt" --output "$WORK/driver.efi" "$DRIVER" >/dev/null
	DRIVER_STAGE="$WORK/driver.efi"
	CODE="$OVMF_SECBOOT_CODE"
else
	echo "## Secure Boot OFF (Setup Mode); the PBA verifies the UKI itself (validation pba)"
	cp "$OVMF_VARS_TEMPLATE" "$VARS0"; chmod u+w "$VARS0"
	cp "$PBA" "$WORK/pba-run.efi"
	DRIVER_STAGE="$DRIVER"
	CODE="${OVMF_CODE:-$OVMF_SECBOOT_CODE}"
fi

# Driver0000 -> MockOpalDxe so the mock SED's Storage Security protocol exists first.
python3 "$HERE/add-driver-entry.py" "$VARS0" "$WORK/vars.fd" '\EFI\MOCK\MOCKOPALDXE.EFI' >/dev/null

# ---- GPT ESP: PBA (default loader) + Key-B-signed UKI + MockOpalDxe ------------
DISK="$WORK/disk.img"
truncate -s 96M "$DISK"
parted -s "$DISK" mklabel gpt mkpart ESP fat32 1MiB 100% set 1 esp on >/dev/null 2>&1
mformat -i "$DISK@@1M" -F ::
mmd -i "$DISK@@1M" ::/EFI ::/EFI/BOOT ::/EFI/LINUX ::/EFI/MOCK
mcopy -i "$DISK@@1M" "$WORK/pba-run.efi"      ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$DISK@@1M" "$OUT/alpine-signed.efi" ::/EFI/LINUX/ALPINE.EFI
mcopy -i "$DISK@@1M" "$DRIVER_STAGE"          ::/EFI/MOCK/MOCKOPALDXE.EFI

# ---- QEMU --------------------------------------------------------------------
ACCEL="tcg"; CPU="max"
if [ -z "${NOKVM:-}" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL="kvm"; CPU="host"; fi

SERIAL_LOG="$WORK/serial.log"; : > "$SERIAL_LOG"
QMP_SOCK="$WORK/qmp.sock"
QEMU_ARGS=(
	-machine q35 -accel "$ACCEL" -cpu "$CPU" -m 2G
	-drive if=pflash,format=raw,unit=0,readonly=on,file="$CODE"
	-drive if=pflash,format=raw,unit=1,file="$WORK/vars.fd"
	-drive "format=raw,file=$DISK,if=none,id=esp" -device virtio-blk-pci,drive=esp,bootindex=0
	-drive "format=raw,file=$ISO,if=none,id=media,readonly=on" -device virtio-blk-pci,drive=media
	-qmp "unix:$QMP_SOCK,server,nowait"
	-net none -no-reboot
)
[ -n "${SERIAL:-}" ] && QEMU_ARGS+=(-display none)

sbmsg="Secure Boot ENFORCING (db = key A) -> pba-override"; [ "$SECUREBOOT" = 1 ] || sbmsg="Secure Boot off -> pba-verify"
intmsg="auto-typed passphrase"; [ "$INTERACTIVE" = 1 ] && intmsg="type the passphrase yourself"
echo "## demo:linux — $sbmsg, $intmsg (accel=$ACCEL)"

if [ "$INTERACTIVE" = 1 ]; then
	# Human types the SED passphrase — via the QEMU window (SERIAL unset) or the
	# serial console (SERIAL=1). Serial on stdio so keystrokes reach ConIn.
	echo "## When you see 'SED passphrase:', type:  correct horse"
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -serial mon:stdio &
	QEMU_PID=$!; wait "$QEMU_PID"
else
	# Auto-typed: serial to a file (so the typer can watch for the prompt and we can
	# mirror it to this terminal), passphrase injected over QMP send-key.
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -serial "file:$SERIAL_LOG" &
	QEMU_PID=$!
	tail -n +1 -F "$SERIAL_LOG" 2>/dev/null & TAIL_PID=$!
	QMP_SOCK="$QMP_SOCK" SERIAL_LOG="$SERIAL_LOG" PASSPHRASE="correct horse" \
		python3 "$HERE/demo-console-type.py" & TYPER_PID=$!
	wait "$QEMU_PID"
fi
