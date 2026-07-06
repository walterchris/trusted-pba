#!/usr/bin/env bash
#
# Build a FAT EFI System Partition containing the given .efi at
# /EFI/BOOT/BOOTX64.EFI (the UEFI removable-media default loader, so OVMF boots it
# with no NVRAM entry or startup.nsh) and boot it under QEMU + OVMF.
#
# Pure launcher: serial is routed to stdout (-nographic); QEMU runs as a child so
# the temp ESP/VARS are cleaned up on exit. Marker assertion / lifecycle is owned
# by expect-serial.py.
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
# If QEMU_DISK_IF=virtio, the ESP is attached as a virtio-blk device instead of
# the default IDE/SATA disk. QEMU's IDE/SATA disks advertise IDENTIFY word 48
# (Trusted Computing supported), which makes OVMF's AtaBus install a competing
# real EFI_STORAGE_SECURITY_COMMAND_PROTOCOL instance on the QEMU disk; the
# mock-Opal matrix uses virtio so MockOpalDxe stays the sole instance the PBA
# transport locates (multi-instance selection is a Phase 8 refinement).

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
cleanup() {
	[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT
# Turn a process-group kill (expect-serial.py's teardown) into a normal exit so
# the EXIT trap runs; QEMU, sharing the group, gets the signal directly too.
trap 'exit 143' TERM INT
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

# ESP attachment (see header note on QEMU_DISK_IF).
if [ "${QEMU_DISK_IF:-}" = "virtio" ]; then
	DISK_ARGS=(-drive "format=raw,file=$IMG,if=none,id=esp" -device virtio-blk-pci,drive=esp)
else
	DISK_ARGS=(-drive "format=raw,file=$IMG")
fi

# Optional vTPM for measured-boot tests: if QEMU_TPM_SOCK points at a running swtpm
# control socket, attach a TPM 2.0 (tpm-tis) so firmware measures the boot. It MUST
# be a UNIX socket and swtpm must run with only `--ctrl type=unixio` (no --server):
# QEMU's tpm-emulator hands the TPM data channel to swtpm via CMD_SET_DATAFD (an fd
# passed over the ctrl socket, SCM_RIGHTS), which needs a UNIX socket and no
# competing --server channel. Keep the socket path short (sockaddr_un ~108 chars).
TPM_ARGS=()
if [ -n "${QEMU_TPM_SOCK:-}" ]; then
	TPM_ARGS=(-chardev "socket,id=chrtpm,path=$QEMU_TPM_SOCK"
		-tpmdev emulator,id=tpm0,chardev=chrtpm
		-device tpm-tis,tpmdev=tpm0)
fi

QEMU_ARGS=(
	-machine q35 -accel tcg -cpu "$QEMU_CPU" -m "$QEMU_MEM"
	-nographic
	-drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE"
	-drive if=pflash,format=raw,unit=1,file="$VARS"
	"${DISK_ARGS[@]}"
	"${TPM_ARGS[@]}"
	-net none -no-reboot
)

if [ -n "${QEMU_INTERACTIVE:-}" ]; then
	# Foreground (no &): QEMU must own the controlling TTY to switch it to raw
	# mode — per-keystroke delivery with no local line-buffering/echo — which the
	# interactive console passphrase prompt needs. Backgrounding leaves the TTY in
	# cooked mode, so the host echoes locally and only ships the whole line on
	# Enter as one burst, which OVMF's serial input decoder mangles. The EXIT trap
	# still reclaims $WORK after QEMU returns (Ctrl-A X to quit).
	qemu-system-x86_64 "${QEMU_ARGS[@]}"
else
	# Run QEMU as a child (not exec) so the cleanup trap reclaims $WORK on exit —
	# under exec the EXIT trap never fired and the per-run ESP/VARS images leaked
	# locally. QEMU shares this script's process group, so expect-serial.py's
	# process-group kill still reaches it; serial stays on the inherited stdout.
	qemu-system-x86_64 "${QEMU_ARGS[@]}" &
	QEMU_PID=$!
	wait "$QEMU_PID"
fi
