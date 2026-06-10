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
# If TESTAPP=<path> is set, that image is staged at /EFI/TEST/TESTAPP.EFI so the
# booted app can chainload it.
# If DRIVER=<path> is set, that image is staged at /EFI/MOCK/MOCKOPALDXE.EFI; it
# is only dispatched if OVMF_VARS carries a matching Driver0000 entry (see
# test/qemu/add-driver-entry.py and test/edk2-mock-opal/).

set -euo pipefail

APP="${1:?usage: run-qemu.sh <app.efi>}"

# Resolve OVMF firmware. Default to the secure-boot-capable build (its enforcement
# is inert in Setup Mode, so unsigned images still boot, and the SecureBoot UEFI
# variable then exists for the PBA to read). Override OVMF_CODE/OVMF_VARS to pick a
# specific pair — the Secure Boot matrix does this (enrolled VARS + signed images).
HERE_RQ="$(dirname "$(readlink -f "$0")")"
. "$HERE_RQ/ovmf-pair.sh"
OVMF_CODE="${OVMF_CODE:-$OVMF_SECBOOT_CODE}"
OVMF_VARS="${OVMF_VARS:-$OVMF_VARS_TEMPLATE}"
[ -f "$OVMF_CODE" ] || { echo "OVMF_CODE not found: $OVMF_CODE" >&2; exit 2; }
[ -f "$OVMF_VARS" ] || { echo "OVMF_VARS not found: $OVMF_VARS" >&2; exit 2; }

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

# Optional second-stage image the booted app chainloads (Phase 1: the test app).
if [ -n "${TESTAPP:-}" ]; then
	mmd -i "$IMG" ::/EFI/TEST
	mcopy -i "$IMG" "$TESTAPP" ::/EFI/TEST/TESTAPP.EFI
fi

# Optional DXE driver (Phase 6: MockOpalDxe), loaded via Driver0000 in OVMF_VARS.
if [ -n "${DRIVER:-}" ]; then
	mmd -i "$IMG" ::/EFI/MOCK
	mcopy -i "$IMG" "$DRIVER" ::/EFI/MOCK/MOCKOPALDXE.EFI
fi

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
