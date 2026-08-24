#!/usr/bin/env bash
#
# demo:secureboot — run stage. A watchable Secure Boot + trust-broker showcase:
#
#   firmware (SB ENFORCING) validates the PBA via our platform key (hop 1)
#     -> the PBA TRUST-BROKERS the OS: `pba` validation verifies the Alpine UKI's
#        Authenticode against the broker CA embedded in its trust store (hop 2)
#     -> firmware re-validates the OS on load via db (hop 3)
#     -> a REAL Alpine Linux boots — proving the OS was correctly signed by the
#        key we added to the trust broker.
#
#   demo-secureboot.sh <pba-demosb.efi>
#
# Expects demo-secureboot-setup.sh to have run (keys + signed UKI in bin/demosb/,
# broker CA embedded, PBA built -tags pbatest,demosb). Boots graphically by
# default; SERIAL=1 for a headless serial run. Env: NOKVM=1, OVMF_CODE/OVMF_VARS.
#
# NOTE: all keys are throwaway, generated in bin/demosb/ and never committed
# (baseline §13). Secure Boot is REAL here (enforcing), enrolled with our keys.
set -euo pipefail

PBA="${1:?usage: demo-secureboot.sh <pba-demosb.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/bin/demosb"

[ -f "$OUT/iso.path" ] || { echo "run demo-secureboot-setup.sh first (bin/demosb missing)" >&2; exit 2; }
ISO="$(cat "$OUT/iso.path")"
[ -f "$OUT/alpine-signed.efi" ] || { echo "signed OS missing; re-run demo-secureboot-setup.sh" >&2; exit 2; }

. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"
resolve_vfv
GUID="$(uuidgen)"

WORK="$(mktemp -d)"
QEMU_PID=""
cleanup() { [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 143' TERM INT

# Sign the PBA with the platform key P (firmware validates it via db, hop 1).
echo "## Signing the PBA with the platform key"
sbsign --key "$OUT/P.key" --cert "$OUT/P.crt" --output "$WORK/pba-signed.efi" "$PBA"

# Enroll PK/KEK + db = {P (validates the PBA), B (validates the OS on load)},
# Secure Boot ENFORCING, our keys only (--no-microsoft). Both hops resolve in db.
echo "## Enrolling Secure Boot keys (enforcing): PK/KEK + db{platform, broker}"
"$VFV" --input "$OVMF_VARS_TEMPLATE" --output "$WORK/vars.fd" \
	--set-pk  "$GUID" "$OUT/PK.crt" \
	--add-kek "$GUID" "$OUT/KEK.crt" \
	--add-db  "$GUID" "$OUT/P.crt" \
	--add-db  "$GUID" "$OUT/B.crt" \
	--no-microsoft --secure-boot >/dev/null

# GPT ESP: signed PBA as the default loader + signed Alpine UKI as the chainload
# target (policy_demosb.json -> EFI/LINUX/ALPINE.EFI, validation "pba").
DISK="$WORK/disk.img"
truncate -s 96M "$DISK"
parted -s "$DISK" mklabel gpt mkpart ESP fat32 1MiB 100% set 1 esp on >/dev/null 2>&1
mformat -i "$DISK@@1M" -F ::
mmd -i "$DISK@@1M" ::/EFI ::/EFI/BOOT ::/EFI/LINUX
mcopy -i "$DISK@@1M" "$WORK/pba-signed.efi"   ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$DISK@@1M" "$OUT/alpine-signed.efi" ::/EFI/LINUX/ALPINE.EFI

# Accel: KVM by default; TCG fallback / NOKVM=1.
ACCEL="tcg"; CPU="max"
if [ -z "${NOKVM:-}" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL="kvm"; CPU="host"; fi

QEMU_ARGS=(
	-machine q35 -accel "$ACCEL" -cpu "$CPU" -m 2G
	-drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_SECBOOT_CODE"
	-drive if=pflash,format=raw,unit=1,file="$WORK/vars.fd"
	-drive "format=raw,file=$DISK,if=none,id=esp" -device virtio-blk-pci,drive=esp,bootindex=0
	-drive "format=raw,file=$ISO,if=none,id=media,readonly=on" -device virtio-blk-pci,drive=media
	-net none -no-reboot
)

if [ -n "${SERIAL:-}" ]; then
	echo "## Booting (serial/headless, SB enforcing, accel=$ACCEL) — Ctrl-A X to quit"
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -nographic &
	QEMU_PID=$!; wait "$QEMU_PID"
else
	echo "## Booting the Secure Boot + trust-broker demo in a QEMU window (accel=$ACCEL)."
	echo "## Watch: firmware validates the PBA -> PBA trust-brokers the signed OS -> Alpine boots."
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -serial mon:stdio &
	QEMU_PID=$!; wait "$QEMU_PID"
fi
