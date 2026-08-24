#!/usr/bin/env bash
#
# Shared demo helper: ensure a cached Alpine ISO and a matching UKI exist, and
# print their paths as shell assignments for the caller to eval:
#
#   eval "$(alpine-uki.sh)"     # sets ISO=<…> and UKI=<…>
#
# The UKI is Alpine's own kernel + initramfs (extracted from the ISO) assembled
# with ukify + the systemd-boot stub, with a serial-console cmdline so the boot is
# visible headless. Both demo launchers (demo-linux.sh, demo-secureboot.sh) use it
# so the download/build logic lives in one place.
#
# Env: ALPINE_VERSION (default below), DEMO_CACHE (default: repo .demo-cache/).
set -euo pipefail

HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"

ALPINE_VERSION="${ALPINE_VERSION:-3.21.7}"
ALPINE_BRANCH="v${ALPINE_VERSION%.*}"   # 3.21.7 -> v3.21
ISO_NAME="alpine-virt-${ALPINE_VERSION}-x86_64.iso"
ISO_URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/x86_64/${ISO_NAME}"
CACHE="${DEMO_CACHE:-$ROOT/.demo-cache}"

if command -v ukify >/dev/null 2>&1; then UKIFY=ukify
elif [ -x /usr/lib/systemd/ukify ]; then UKIFY=/usr/lib/systemd/ukify
else echo "ukify not found — install systemd-ukify (+ systemd-boot-unsigned/-efi for the stub)" >&2; exit 2; fi
STUB=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
[ -f "$STUB" ] || { echo "systemd-boot stub not found: $STUB — install systemd-boot-unsigned (Fedora) / systemd-boot-efi (Ubuntu)" >&2; exit 2; }

mkdir -p "$CACHE"
ISO="$CACHE/$ISO_NAME"
if [ ! -f "$ISO" ]; then
	echo "## Downloading $ISO_NAME (~64 MB, cached in $CACHE) …" >&2
	curl -fL --progress-bar -o "$ISO.part" "$ISO_URL" >&2
	mv "$ISO.part" "$ISO"
fi

UKI="$CACHE/alpine-uki-${ALPINE_VERSION}.efi"
if [ ! -f "$UKI" ] || [ "$ISO" -nt "$UKI" ]; then
	echo "## Building Alpine UKI (kernel + initramfs + serial console) …" >&2
	TMPX="$(mktemp -d)"
	xorriso -osirrox on -indev "$ISO" \
		-extract /boot/vmlinuz-virt "$TMPX/vmlinuz" \
		-extract /boot/initramfs-virt "$TMPX/initrd" 2>/dev/null
	# Alpine's mkinitfs scans block devices for its media, so no alpine_dev= is
	# needed; console=ttyS0 + no "quiet" make the whole boot visible on serial too.
	"$UKIFY" build --stub "$STUB" --linux "$TMPX/vmlinuz" --initrd "$TMPX/initrd" \
		--cmdline "modules=loop,squashfs,sd-mod,usb-storage console=ttyS0,115200 console=tty0" \
		--output "$UKI" >/dev/null
	rm -rf "$TMPX"
fi

printf 'ISO=%q\nUKI=%q\n' "$ISO" "$UKI"
