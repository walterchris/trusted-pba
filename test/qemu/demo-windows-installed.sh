#!/usr/bin/env bash
#
# demo:windows WIN_OSDISK=<disk> — boot a FULL, pre-installed Windows through the
# Key-A-only override model, all the way to the Windows logon screen:
#
#   firmware (SB ENFORCING, db = OUR KEY A ONLY — no Microsoft) validates the signed
#   PBA  ->  the PBA trust-brokers Windows Boot Manager against the Microsoft Windows
#   CAs in its OWN store and admits it via the shim-style Security2 override  ->
#   bootmgfw -> winload -> the Windows kernel -> the real Windows logon screen.
#
#   demo-windows-installed.sh <pba-demowinnosed.efi>
#
# Unlike the self-contained WinPE demo (demo-windows.sh), this needs a Windows disk
# you have already installed (a GPT disk with an ESP + an installed Windows NTFS
# volume). Point WIN_OSDISK at it. Runtime writes are discarded (-snapshot); only the
# signed PBA is staged into the disk's ESP as the fallback loader.
#
# IMPORTANT — the disk must be booted on a controller Windows has an inbox driver for.
# We attach it as SATA/AHCI (inbox storahci); virtio-blk needs the virtio driver
# injected or Windows bugchecks INACCESSIBLE_BOOT_DEVICE. There is NO mock SED here
# (its Storage-Security protocol confuses the installed OS's boot-device enumeration);
# use the self-contained WinPE demo to show the mock Opal unlock.
#
# Env: SERIAL=1 headless; SCREENSHOT=<png> headless capture (SCREENSHOT_DELAY, default
# 150); NOKVM=1 force TCG; NOTPM=1 disable the emulated TPM 2.0.
# All Secure Boot keys are throwaway (bin/demowin/), never committed (baseline §13).
set -euo pipefail

PBA="${1:?usage: demo-windows-installed.sh <pba-demowinnosed.efi>}"
DISK="${WIN_OSDISK:?set WIN_OSDISK=<installed Windows disk image>}"
[ -f "$DISK" ] || { echo "WIN_OSDISK not found: $DISK" >&2; exit 2; }
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/bin/demowin"
. "$HERE/ovmf-pair.sh"

W="$(mktemp -d)"
QEMU_PID=""; SWTPM_PID=""
cleanup() { for p in "$QEMU_PID" "$SWTPM_PID"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT
trap 'exit 143' TERM INT

# ---- Throwaway platform keys (key A only) + sign the PBA -----------------------
[ -f "$OUT/P.key" ] || {
	mkdir -p "$OUT"
	for role in PK KEK P; do
		openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
			-subj "/CN=TrustedPBA Demo $role/" -keyout "$OUT/$role.key" -out "$OUT/$role.crt" 2>/dev/null
	done
}
echo "## Signing the PBA with the platform key (key A) and staging it into the disk's ESP"
sbsign --key "$OUT/P.key" --cert "$OUT/P.crt" --output "$W/pba-signed.efi" "$PBA" >/dev/null
# Stage the override PBA as the ESP fallback loader (small write to the FAT ESP; the
# installed Windows volume is untouched, and runtime writes are discarded via -snapshot).
mcopy -i "$DISK@@1M" -o "$W/pba-signed.efi" ::/EFI/BOOT/BOOTX64.EFI

# ---- Secure Boot: db = key A ONLY (no Microsoft) — the override does the work ----
echo "## Enrolling Secure Boot (enforcing): db = { key A only }; Windows Boot Manager is admitted by the PBA override, not firmware db"
GUID="$(uuidgen)"
virt-fw-vars --input "$OVMF_VARS_TEMPLATE" --output "$W/vars.fd" \
	--set-pk  "$GUID" "$OUT/PK.crt" \
	--add-kek "$GUID" "$OUT/KEK.crt" \
	--add-db  "$GUID" "$OUT/P.crt" \
	--no-microsoft --secure-boot >/dev/null

# ---- Emulated TPM 2.0 (Windows 11) --------------------------------------------
TPM_ARGS=()
if [ -z "${NOTPM:-}" ] && command -v swtpm >/dev/null 2>&1; then
	mkdir -p "$W/tpm"
	swtpm socket --tpm2 --tpmstate dir="$W/tpm" --ctrl type=unixio,path="$W/swtpm.sock" --flags startup-clear &
	SWTPM_PID=$!
	TPM_ARGS=(-chardev "socket,id=chrtpm,path=$W/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0)
fi

# ---- Boot: the installed disk on SATA/AHCI (inbox storahci) --------------------
ACCEL="tcg"; CPU="max"
if [ -z "${NOKVM:-}" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL="kvm"; CPU="host"; fi
QEMU_ARGS=(
	-machine q35 -accel "$ACCEL" -cpu "$CPU" -m 6G -smp 4
	-drive if=pflash,unit=0,readonly=on,format=raw,file="$OVMF_SECBOOT_CODE"
	-drive if=pflash,unit=1,format=raw,file="$W/vars.fd"
	-drive "file=$DISK,if=none,id=osd,format=raw,snapshot=on" -device ide-hd,drive=osd,bus=ide.0,bootindex=0
	"${TPM_ARGS[@]}"
	-device qemu-xhci -device usb-tablet -net none
)

if [ -n "${SCREENSHOT:-}" ]; then
	echo "## Booting headless; will screenshot to $SCREENSHOT after ${SCREENSHOT_DELAY:-150}s"
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -display none -vga std -qmp "unix:$W/qmp.sock,server,nowait" &
	QEMU_PID=$!
	python3 - "$W/qmp.sock" "$SCREENSHOT" "${SCREENSHOT_DELAY:-150}" <<'PY'
import socket, json, sys, time, os
sock, out, delay = sys.argv[1], sys.argv[2], int(sys.argv[3])
base = out[:-4] if out.endswith(".png") else out
def shot(p):
    try:
        s=socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(sock); f=s.makefile("rw")
        f.readline(); f.write('{"execute":"qmp_capabilities"}\n'); f.flush(); f.readline()
        f.write(json.dumps({"execute":"screendump","arguments":{"filename":p,"format":"png"}})+"\n"); f.flush()
        r=f.readline().strip(); s.close(); return "error" not in r
    except Exception as e: print("qmp gone:", e); return False
for _ in range(120):
    if os.path.exists(sock): break
    time.sleep(0.5)
t, step = 0, 30
while t < delay:
    time.sleep(step); t += step
    print(f"t={t}s ok={shot(f'{base}.{t}s.png')}")
shot(out)
PY
	echo "## Screenshots saved: ${SCREENSHOT%.png}.<t>s.png (+ $SCREENSHOT)"
elif [ -n "${SERIAL:-}" ]; then
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -nographic &
	QEMU_PID=$!; wait "$QEMU_PID"
else
	echo "## Booting the installed Windows through the Key-A-only override (accel=$ACCEL)."
	echo "## Watch: firmware (key A only) validates the PBA → PBA admits Windows Boot Manager via the Security2 override → Windows boots to the logon screen."
	qemu-system-x86_64 "${QEMU_ARGS[@]}" &
	QEMU_PID=$!; wait "$QEMU_PID"
fi
