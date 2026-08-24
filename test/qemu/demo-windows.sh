#!/usr/bin/env bash
#
# demo:windows — a watchable Secure Boot showcase that hands off to REAL Windows:
#
#   firmware (SB ENFORCING, Microsoft db/dbx + our key enrolled) validates the
#   signed PBA (our key)  ->  the PBA chainloads the Windows Boot Manager, which
#   the FIRMWARE validates against the Microsoft db (the canonical, BitLocker-safe
#   Windows path — the PBA does not pre-verify it)  ->  Windows boots and you see
#   the Windows screen.
#
#   demo-windows.sh <pba-demowin.efi>
#
# The Windows media is a Windows 11 Enterprise Evaluation ISO (no product key,
# fetched from Microsoft's eval center on first run, cached in .demo-cache/). Set
# WIN_ISO=/path/to/Windows.iso to use your own instead. It boots the Windows Setup
# environment (real Windows / WinPE) — enough to "land in Windows and see the
# screen"; install.wim is omitted from the boot volume (it exceeds FAT32's 4 GB
# limit and is only needed to actually install).
#
# Boots graphically by default. Env:
#   SERIAL=1                  headless (no Windows serial output, mostly for smoke)
#   SCREENSHOT=<file.png>     headless; capture the screen via QMP after a delay and exit
#   SCREENSHOT_DELAY=<sec>    when to grab the screenshot (default 120)
#   NOKVM=1 / NOTPM=1         force TCG / disable the emulated TPM 2.0
#   WIN_ISO=<path>            use a local Windows ISO instead of fetching
#
# All Secure Boot keys are throwaway (bin/demowin/), never committed (baseline §13).
set -euo pipefail

PBA="${1:?usage: demo-windows.sh <pba-demowin.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/bin/demowin"
CACHE="${DEMO_CACHE:-$ROOT/.demo-cache}"
MAT="$ROOT/internal/truststore/materials"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

mkdir -p "$OUT" "$CACHE"

# ---- 1. Resolve the Windows ISO (user-supplied or Microsoft eval-center) --------
ISO="${WIN_ISO:-$CACHE/win11-ent-eval.iso}"
if [ ! -f "$ISO" ]; then
	echo "## Fetching the official Windows 11 Enterprise Evaluation ISO (en-US, ~7 GB) …"
	page="$(curl -fsSL --user-agent "$UA" "https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise")"
	# The anchor labelled "64-bit edition: … (en-US)" carries the x64 English ISO fwlink.
	linkid="$(printf '%s' "$page" | grep -oE "linkid=[0-9]+&(amp;)?clcid=0x409&(amp;)?culture=en-us&(amp;)?country=us\" aria-label=\"64-bit edition: Download Windows 11 Enterprise ISO 64-bit \(en-US\)" | grep -oE "linkid=[0-9]+" | head -1 | cut -d= -f2)"
	[ -n "$linkid" ] || { echo "could not find the en-US x64 ISO link on the eval page; pass WIN_ISO=<path>" >&2; exit 2; }
	echo "## eval-center fwlink linkid=$linkid"
	curl -fL -C - --retry 3 --user-agent "$UA" -o "$ISO.part" \
		"https://go.microsoft.com/fwlink/?linkid=$linkid&clcid=0x409&culture=en-us&country=us"
	mv "$ISO.part" "$ISO"
fi
echo "## Windows ISO: $ISO"

# ---- 2. Extract the UEFI boot tree (cached; install.wim omitted) ----------------
TREE="$CACHE/win-boot-tree"
if [ ! -d "$TREE" ] || [ "$ISO" -nt "$TREE" ]; then
	echo "## Extracting Windows boot files (efi, boot, sources\\boot.wim) — one-time, cached …"
	rm -rf "$TREE.tmp"; mkdir -p "$TREE.tmp"
	# Windows ISOs are UDF (needed for the >4 GB install.wim), which xorriso does not
	# read; 7z does. Extract EFI + boot managers + fonts (small) and ONLY
	# sources/boot.wim (the WinPE/Setup ramdisk). install.wim is skipped — it exceeds
	# FAT32's 4 GB limit and is only needed to actually install; booting to the
	# Windows Setup screen needs just boot.wim.
	7z x -y -o"$TREE.tmp" "$ISO" efi boot 'sources/boot.wim' >/dev/null
	# Ensure the chainload target exists: the policy points at
	# \EFI\MICROSOFT\BOOT\BOOTMGFW.EFI; if the media only ships the loader at
	# \EFI\BOOT\BOOTX64.EFI, mirror it there before the PBA takes that slot.
	if [ ! -f "$TREE.tmp/efi/microsoft/boot/bootmgfw.efi" ] && [ -f "$TREE.tmp/efi/boot/bootx64.efi" ]; then
		cp "$TREE.tmp/efi/boot/bootx64.efi" "$TREE.tmp/efi/microsoft/boot/bootmgfw.efi"
	fi
	mv "$TREE.tmp" "$TREE"
fi

# ---- 3. Firmware pair + throwaway keys ------------------------------------------
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"
resolve_vfv
GUID="$(uuidgen)"

WORK="$(mktemp -d)"
QEMU_PID=""; SWTPM_PID=""
cleanup() {
	[ -n "$QEMU_PID" ]  && kill "$QEMU_PID"  2>/dev/null || true
	[ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 143' TERM INT

echo "## Generating platform keys (PK/KEK/db=P) and signing the PBA"
for role in PK KEK P; do
	openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
		-subj "/CN=TrustedPBA Demo $role/" \
		-keyout "$OUT/$role.key" -out "$OUT/$role.crt" 2>/dev/null
done
sbsign --key "$OUT/P.key" --cert "$OUT/P.crt" --output "$WORK/pba-signed.efi" "$PBA"

# ---- 4. Enroll Secure Boot: our key (PBA) + Microsoft db/dbx (Windows loader) ---
echo "## Enrolling Secure Boot (enforcing): PK/KEK + db{our key + Microsoft Windows CAs} + Microsoft dbx"
# Enroll the Microsoft Windows db CAs explicitly from our pinned materials (the
# tool's --microsoft-db flag is a no-op in this virt-firmware build). Windows Boot
# Manager (25H2) is signed by "Microsoft Windows Production PCA 2011"; the 2023 CA
# is added too so newer/older loaders validate. dbx is the real Microsoft dbx.
"$VFV" --input "$OVMF_VARS_TEMPLATE" --output "$WORK/vars.fd" \
	--set-pk  "$GUID" "$OUT/PK.crt" \
	--add-kek "$GUID" "$OUT/KEK.crt" \
	--add-db  "$GUID" "$OUT/P.crt" \
	--add-db  "$GUID" "$MAT/db/win-production-pca-2011.der" \
	--add-db  "$GUID" "$MAT/db/windows-uefi-ca-2023.der" \
	--set-dbx "$MAT/dbx/dbx-amd64.bin" \
	--secure-boot >/dev/null

# ---- 5. Build the GPT/ESP boot disk: PBA in front of the real Windows loader ----
echo "## Building the boot disk (PBA + Windows boot files on a FAT32 ESP)"
DISK="$WORK/disk.img"
truncate -s 3G "$DISK"
parted -s "$DISK" mklabel gpt mkpart ESP fat32 1MiB 100% set 1 esp on >/dev/null 2>&1
mformat -i "$DISK@@1M" -F ::
# Copy the whole Windows boot tree, then place the PBA as the default loader and
# keep the real Windows Boot Manager at the policy's target path.
mcopy -i "$DISK@@1M" -s -Q "$TREE"/* ::/
# Place the SIGNED PBA as the default loader (firmware validates it via our db key);
# the real Windows Boot Manager stays at \EFI\MICROSOFT\BOOT\BOOTMGFW.EFI (the target).
mcopy -i "$DISK@@1M" -o "$WORK/pba-signed.efi" ::/EFI/BOOT/BOOTX64.EFI

# ---- 6. Optional emulated TPM 2.0 (Windows 11) ----------------------------------
TPM_ARGS=()
if [ -z "${NOTPM:-}" ] && command -v swtpm >/dev/null 2>&1; then
	mkdir -p "$WORK/tpm"
	swtpm socket --tpm2 --tpmstate dir="$WORK/tpm" \
		--ctrl type=unixio,path="$WORK/swtpm.sock" --flags startup-clear &
	SWTPM_PID=$!
	TPM_ARGS=(-chardev "socket,id=chrtpm,path=$WORK/swtpm.sock"
		-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0)
fi

# ---- 7. Boot -------------------------------------------------------------------
ACCEL="tcg"; CPU="max"
if [ -z "${NOKVM:-}" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL="kvm"; CPU="host"; fi

QEMU_ARGS=(
	-machine q35 -accel "$ACCEL" -cpu "$CPU" -m 4G -smp 2
	-drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_SECBOOT_CODE"
	-drive if=pflash,format=raw,unit=1,file="$WORK/vars.fd"
	-drive "format=raw,file=$DISK,if=none,id=esp" -device virtio-blk-pci,drive=esp,bootindex=0
	-device qemu-xhci -device usb-tablet
	"${TPM_ARGS[@]}"
	-net none
)

if [ -n "${SCREENSHOT:-}" ]; then
	# Headless capture: boot, wait, grab the framebuffer via QMP, exit. Lets a
	# maintainer (or CI) verify the demo lands in Windows without a display.
	echo "## Booting headless; will screenshot to $SCREENSHOT after ${SCREENSHOT_DELAY:-120}s"
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -display none -vga std \
		-qmp "unix:$WORK/qmp.sock,server,nowait" &
	QEMU_PID=$!
	# Poll: open a FRESH QMP connection every interval and screendump, so a guest
	# reboot / QEMU exit can't break a long-lived session. Writes out.<t>s.png at
	# each step plus the final out; stops when QEMU is gone or the delay elapses.
	python3 - "$WORK/qmp.sock" "$SCREENSHOT" "${SCREENSHOT_DELAY:-120}" <<'PY'
import socket, json, sys, time, os
sockpath, out, delay = sys.argv[1], sys.argv[2], int(sys.argv[3])
base = out[:-4] if out.endswith(".png") else out
def shot(path):
    try:
        s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(sockpath)
        f = s.makefile("rw")
        f.readline()
        f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n"); f.flush(); f.readline()
        f.write(json.dumps({"execute": "screendump",
                            "arguments": {"filename": path, "format": "png"}}) + "\n"); f.flush()
        r = f.readline().strip(); s.close()
        return "error" not in r
    except Exception as e:
        print("qmp gone:", e); return False
for _ in range(60):                       # wait for the socket to appear
    if os.path.exists(sockpath): break
    time.sleep(0.5)
t, step = 0, 30
while t < delay:
    time.sleep(step); t += step
    ok = shot(f"{base}.{t}s.png")
    print(f"t={t}s screendump ok={ok}")
    if not ok: break
shot(out)                                 # final
PY
	wait "$QEMU_PID" 2>/dev/null || true
	echo "## Screenshots saved: ${SCREENSHOT%.png}.<t>s.png (+ $SCREENSHOT)"
elif [ -n "${SERIAL:-}" ]; then
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -nographic &
	QEMU_PID=$!; wait "$QEMU_PID"
else
	echo "## Booting the Windows demo in a QEMU window (accel=$ACCEL, TPM=${TPM_ARGS:+on})."
	echo "## Watch: firmware validates the PBA → PBA hands off → firmware validates Windows Boot Manager → Windows boots."
	qemu-system-x86_64 "${QEMU_ARGS[@]}" &
	QEMU_PID=$!; wait "$QEMU_PID"
fi
