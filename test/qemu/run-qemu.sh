#!/usr/bin/env bash
#
# Build a FAT EFI System Partition containing the given .efi at
# /EFI/BOOT/BOOTX64.EFI (the UEFI removable-media default loader, so OVMF boots it
# with no NVRAM entry or startup.nsh) and boot it under QEMU + OVMF.
#
# Pure launcher: serial is routed to stdout (-nographic) and the process is
# replaced by QEMU. Marker assertion / lifecycle is owned by expect-serial.py.
# Runs headless under TCG (no KVM) so it works in CI containers.
#
#   run-qemu.sh <app.efi>
#
# OVMF firmware paths can be overridden via OVMF_CODE / OVMF_VARS.

set -euo pipefail

APP="${1:?usage: run-qemu.sh <app.efi>}"

# Locate OVMF firmware across common distro layouts (Fedora, Debian/Ubuntu).
find_fw() {
	local override="$1"; shift
	local c
	for c in "$override" "$@"; do
		[ -n "$c" ] && [ -f "$c" ] && { echo "$c"; return 0; }
	done
	return 1
}
OVMF_CODE="$(find_fw "${OVMF_CODE:-}" \
	/usr/share/OVMF/OVMF_CODE.fd \
	/usr/share/edk2/ovmf/OVMF_CODE.fd \
	/usr/share/OVMF/OVMF_CODE_4M.fd \
	/usr/share/qemu/OVMF_CODE.fd)" || { echo "OVMF_CODE.fd not found; set OVMF_CODE" >&2; exit 2; }
OVMF_VARS="$(find_fw "${OVMF_VARS:-}" \
	/usr/share/OVMF/OVMF_VARS.fd \
	/usr/share/edk2/ovmf/OVMF_VARS.fd \
	/usr/share/OVMF/OVMF_VARS_4M.fd \
	/usr/share/qemu/OVMF_VARS.fd)" || { echo "OVMF_VARS.fd not found; set OVMF_VARS" >&2; exit 2; }

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
IMG="$WORK/esp.img"
VARS="$WORK/vars.fd"

# FAT32 ESP (64 MiB is comfortably above mformat's -F minimum).
truncate -s 64M "$IMG"
mformat -i "$IMG" -F ::
mmd -i "$IMG" ::/EFI ::/EFI/BOOT
mcopy -i "$IMG" "$APP" ::/EFI/BOOT/BOOTX64.EFI

# Per-run writable copy of the NVRAM variable store.
cp "$OVMF_VARS" "$VARS"
chmod u+w "$VARS"

# CPU/memory notes (verified empirically):
#  -cpu max : the default TCG "qemu64" model lacks CPU features the TamaGo amd64
#             runtime touches during bring-up, causing a firmware #GP. "max"
#             exposes the needed features and runs under pure TCG (no KVM).
#  -m 2G    : the TamaGo amd64 UEFI runtime needs ~1 GiB of RAM (512M faults);
#             2 GiB gives headroom and is fine on CI runners.
QEMU_CPU="${QEMU_CPU:-max}"
QEMU_MEM="${QEMU_MEM:-2G}"

# Note: exec replaces this shell with QEMU so the caller's process-group kill
# reaches QEMU directly. The temp dir is reclaimed by the OS on CI runners; the
# orchestrator (expect-serial.py) owns teardown.
exec qemu-system-x86_64 \
	-machine q35 -accel tcg -cpu "$QEMU_CPU" -m "$QEMU_MEM" \
	-nographic \
	-drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
	-drive if=pflash,format=raw,unit=1,file="$VARS" \
	-drive format=raw,file="$IMG" \
	-net none -no-reboot
