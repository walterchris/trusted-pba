#!/usr/bin/env bash
#
# Build a minimal Linux UKI (Unified Kernel Image) for the linux-boot matrix:
# a real distro kernel + a one-binary initramfs (the static Go init from
# test/fixtures/linuxinit, which prints "TEST-LINUX: userspace ok" on serial and
# powers off) + an embedded "console=ttyS0" cmdline, assembled with systemd's
# ukify into a single PE the PBA can chainload like any EFI application.
#
# A UKI (not a bare EFISTUB kernel) because the PBA's chainloader passes no
# LoadOptions: the kernel gets its cmdline and initramfs only if they are
# embedded in the image itself.
#
#   build-linux-uki.sh <out.efi>
#
# Kernel: $TPBA_LINUX_KERNEL if set, else the running kernel
# (/boot/vmlinuz-$(uname -r); on hosts where that is root-only, copy it
# somewhere readable and point TPBA_LINUX_KERNEL at it).
# Needs: host go, GNU cpio, ukify + the systemd-boot stub
# (Fedora: systemd-ukify + systemd-boot-unsigned; Ubuntu: systemd-ukify +
# systemd-boot-efi).
set -euo pipefail

OUT="${1:?usage: build-linux-uki.sh <out.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"

KERNEL="${TPBA_LINUX_KERNEL:-/boot/vmlinuz-$(uname -r)}"
[ -r "$KERNEL" ] || {
	echo "kernel not readable: $KERNEL — set TPBA_LINUX_KERNEL to a readable vmlinuz" >&2
	exit 2
}

# ukify lives at /usr/bin/ukify or (Fedora) /usr/lib/systemd/ukify.
if command -v ukify >/dev/null 2>&1; then
	UKIFY=ukify
elif [ -x /usr/lib/systemd/ukify ]; then
	UKIFY=/usr/lib/systemd/ukify
else
	echo "ukify not found — install systemd-ukify (+ systemd-boot-unsigned/-efi for the stub)" >&2
	exit 2
fi
STUB=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
[ -f "$STUB" ] || {
	echo "systemd-boot stub not found: $STUB — install systemd-boot-unsigned (Fedora) / systemd-boot-efi (Ubuntu)" >&2
	exit 2
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Initramfs: /init (static Go binary) + an empty /dev for the devtmpfs mount.
mkdir -p "$WORK/root/dev"
CGO_ENABLED=0 go build -C "$ROOT" -trimpath -ldflags '-s -w' \
	-o "$WORK/root/init" ./test/fixtures/linuxinit
(cd "$WORK/root" && find . | cpio -o -H newc --owner=+0:+0 --quiet) | gzip > "$WORK/initrd.img"

# panic=-1: an early kernel panic reboots immediately; under run-qemu.sh's
# -no-reboot that exits QEMU, so a broken boot fails fast instead of hanging
# the harness until its timeout.
"$UKIFY" build \
	--stub "$STUB" \
	--linux "$KERNEL" \
	--initrd "$WORK/initrd.img" \
	--cmdline "console=ttyS0,115200 panic=-1" \
	--output "$OUT" >/dev/null

echo "built $OUT (kernel $KERNEL)"
