#!/usr/bin/env bash
#
# demo:linux — a watchable, full-boot-flow showcase of Trusted PBA:
#
#   PBA banner -> Secure Boot state -> mock Opal SED unlock (MockOpalDxe:
#   StartSession -> range unlock -> MBRDone) -> chainload -> a REAL Alpine
#   Linux kernel boots to a login prompt.
#
# Unlike the test: matrices (headless, assertion-driven), this is meant to be
# run interactively and watched. It boots graphically by default (QEMU window);
# set SERIAL=1 for a headless serial run (what CI / a quick check uses).
#
#   demo-linux.sh <pba-demolinux.efi>
#
# The mock SED unlock is real code: the -tags demolinux PBA drives its UEFI
# Storage Security transport against the MockOpalDxe driver, unlocking with the
# shared-spec Admin1 test PIN, then firmware-chainloads the Alpine UKI. Nothing
# here is signed (Secure Boot stays off) — the demo shows the unlock+handoff, not
# Secure Boot; `task test:sb` / `task test:opal-mock` cover the enforcing paths.
#
# Architecture (why it is built this way):
#   - The OS is a UKI (Alpine's kernel + initramfs + our cmdline) staged on a GPT
#     ESP next to the PBA, so the PBA chainloads it from its own boot volume — no
#     second-volume chainload, no distro grub.cfg to wrangle. (Alpine's boot image
#     is a 1.4 MB FAT that cannot hold the 5 MB PBA, so injecting into the ISO is
#     out.)
#   - The pristine Alpine ISO is attached as a plain virtio data disk (NOT optical),
#     so firmware creates no boot entry for it (the ESP wins deterministically via
#     a GPT/ESP boot entry + bootindex=0), while Alpine's initramfs still finds its
#     modloop/rootfs on it by scanning block devices.
#
# Env overrides:
#   SERIAL=1               headless serial run (-nographic), for CI / quick checks
#   NOKVM=1                force TCG (no /dev/kvm)
#   ALPINE_VERSION=x.y.z   pin a different alpine-virt release (default below)
#   DEMO_CACHE=<dir>       ISO/UKI cache location (default: repo .demo-cache/)
#   OVMF_CODE / OVMF_VARS  override the firmware pair
set -euo pipefail

PBA="${1:?usage: demo-linux.sh <pba-demolinux.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
DRIVER="$HERE/../edk2-mock-opal/MockOpalDxe.efi"

[ -f "$DRIVER" ] || { echo "MockOpalDxe.efi not found; run: task build:mock-opal" >&2; exit 2; }

# Download the Alpine ISO + build its UKI (cached in .demo-cache/); sets ISO, UKI.
eval "$(env DEMO_CACHE="${DEMO_CACHE:-$ROOT/.demo-cache}" "$HERE/alpine-uki.sh")"

# Firmware pair (secure-boot-capable CODE is fine — it is inert in Setup Mode, so
# the unsigned PBA/UKI still boot and the SecureBoot variable exists to report).
. "$HERE/ovmf-pair.sh"
OVMF_CODE="${OVMF_CODE:-$OVMF_SECBOOT_CODE}"
OVMF_VARS="${OVMF_VARS:-$OVMF_VARS_TEMPLATE}"

WORK="$(mktemp -d)"
QEMU_PID=""
cleanup() { [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 143' TERM INT

# GPT disk with one EFI System Partition (a bare-FAT whole-disk is not a resolvable
# boot entry when another bootable volume is present; a real ESP + bootindex=0 is).
DISK="$WORK/disk.img"
truncate -s 96M "$DISK"
parted -s "$DISK" mklabel gpt mkpart ESP fat32 1MiB 100% set 1 esp on >/dev/null 2>&1
mformat -i "$DISK@@1M" -F ::
mmd -i "$DISK@@1M" ::/EFI ::/EFI/BOOT ::/EFI/LINUX ::/EFI/MOCK
mcopy -i "$DISK@@1M" "$PBA"    ::/EFI/BOOT/BOOTX64.EFI       # PBA = the removable-media default loader
mcopy -i "$DISK@@1M" "$UKI"    ::/EFI/LINUX/ALPINE.EFI       # chainload target (policy_demolinux.json)
mcopy -i "$DISK@@1M" "$DRIVER" ::/EFI/MOCK/MOCKOPALDXE.EFI   # dispatched via Driver0000 below

# NVRAM: Driver0000 -> MockOpalDxe (short-form path; BDS finds it on the ESP) so the
# mock SED's Storage Security protocol exists before the PBA runs.
cp "$OVMF_VARS" "$WORK/vars0.fd"; chmod u+w "$WORK/vars0.fd"
python3 "$HERE/add-driver-entry.py" "$WORK/vars0.fd" "$WORK/vars.fd" '\EFI\MOCK\MOCKOPALDXE.EFI' >/dev/null

# Accel: KVM by default (fast for a live demo); TCG fallback / NOKVM=1.
ACCEL="tcg"
if [ -z "${NOKVM:-}" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL="kvm"; fi
[ "$ACCEL" = "kvm" ] && CPU="host" || CPU="max"

QEMU_ARGS=(
	-machine q35 -accel "$ACCEL" -cpu "$CPU" -m 2G
	-drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE"
	-drive if=pflash,format=raw,unit=1,file="$WORK/vars.fd"
	# ESP first (bootindex=0); the ISO is a plain data disk (no boot entry) that
	# Alpine's initramfs mounts for its modloop/rootfs.
	-drive "format=raw,file=$DISK,if=none,id=esp" -device virtio-blk-pci,drive=esp,bootindex=0
	-drive "format=raw,file=$ISO,if=none,id=media,readonly=on" -device virtio-blk-pci,drive=media
	-net none -no-reboot
)

if [ -n "${SERIAL:-}" ]; then
	# Headless: everything on stdout (PBA ConOut + serial merge). CI / quick check.
	echo "## Booting (serial/headless, accel=$ACCEL) — Ctrl-A X to quit"
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -nographic &
	QEMU_PID=$!; wait "$QEMU_PID"
else
	# Graphical: the PBA banner + boot flow show in the QEMU window; a serial
	# console is also mirrored to this terminal so the flow is visible either way.
	echo "## Booting Trusted PBA demo in a QEMU window (accel=$ACCEL)."
	echo "## Watch: PBA banner -> Secure Boot -> mock SED unlock -> Alpine Linux login."
	echo "## (serial mirrored below; close the QEMU window or Ctrl-C to stop)"
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -serial mon:stdio &
	QEMU_PID=$!; wait "$QEMU_PID"
fi
