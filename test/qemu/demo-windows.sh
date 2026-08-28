#!/usr/bin/env bash
#
# demo:windows — a watchable Secure Boot showcase that hands off to REAL Windows via
# the Key-A-only override model (ADR-0013):
#
#   firmware (SB ENFORCING, db = OUR KEY A ONLY — no Microsoft) validates the signed
#   PBA  ->  a mock Opal SED unlocks on the console credential ("correct horse")  ->
#   the PBA TRUST-BROKERS the Windows Boot Manager against the Microsoft Windows CAs
#   in its OWN embedded trust store, then admits it via the shim-style Security2
#   override (validation "pba-override") — firmware db never sees Microsoft  ->
#   Windows boots and you see the Windows screen.
#
#   NB: the override authorizes bootmgfw without a firmware db authority, so PCR 7
#   diverges from a native Windows boot — BitLocker must be (re)sealed with the PBA
#   already in the chain, or it drops to recovery (ADR-0013 / ADR-0012). The eval
#   media used here has no BitLocker enrolled, so the demo itself boots cleanly.
#
#   demo-windows.sh <pba-demowin.efi>
#
# Secure Boot and the trust broker are ALWAYS on here (that is the demo). Flags:
#   INTERACTIVE=1             you type the SED passphrase ("correct horse") in the
#                             QEMU window; default (0) auto-types it over QMP.
#   SERIAL=1                  headless (no window; PBA console on serial, mostly smoke)
#   SCREENSHOT=<file.png>     headless; capture the screen via QMP after a delay and exit
#   SCREENSHOT_DELAY=<sec>    when to grab the screenshot (default 120)
#   NOKVM=1 / NOTPM=1         force TCG / disable the emulated TPM 2.0
#   WIN_ISO=<path>            use a local Windows ISO instead of fetching
#
# The Windows media is a Windows 11 Enterprise Evaluation ISO (no product key,
# fetched from Microsoft's eval center on first run, cached in .demo-cache/). It
# boots the Windows Setup environment (real Windows / WinPE) — enough to "land in
# Windows and see the screen"; install.wim is omitted from the boot volume (it
# exceeds FAT32's 4 GB limit and is only needed to actually install).
#
# Prerequisite: MockOpalDxe built (task build:mock-opal). All Secure Boot keys are
# throwaway (bin/demowin/), never committed (baseline §13).
set -euo pipefail

PBA="${1:?usage: demo-windows.sh <pba-demowin.efi>}"
INTERACTIVE="${INTERACTIVE:-0}"
HERE="$(dirname "$(readlink -f "$0")")"

# WIN_OSDISK set -> boot a FULL, pre-installed Windows through the override (on AHCI,
# to the logon screen) instead of the self-contained WinPE Setup path. Different PBA
# variant (no mock SED — it confuses the installed OS's boot-device enumeration).
if [ -n "${WIN_OSDISK:-}" ]; then
	exec "$HERE/demo-windows-installed.sh" "$PBA"
fi

ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/bin/demowin"
CACHE="${DEMO_CACHE:-$ROOT/.demo-cache}"
MAT="$ROOT/internal/truststore/materials"
DRIVER="$HERE/../edk2-mock-opal/MockOpalDxe.efi"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

[ -f "$DRIVER" ] || { echo "MockOpalDxe.efi not found; run: task build:mock-opal" >&2; exit 2; }
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
QEMU_PID=""; SWTPM_PID=""; TAIL_PID=""; TYPER_PID=""
cleanup() {
	for p in "$QEMU_PID" "$TYPER_PID" "$TAIL_PID" "$SWTPM_PID"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 143' TERM INT

echo "## Generating platform keys (PK/KEK/db=P) and signing the PBA + mock SED driver"
for role in PK KEK P; do
	openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
		-subj "/CN=TrustedPBA Demo $role/" \
		-keyout "$OUT/$role.key" -out "$OUT/$role.crt" 2>/dev/null
done
sbsign --key "$OUT/P.key" --cert "$OUT/P.crt" --output "$WORK/pba-signed.efi" "$PBA"
# The MockOpalDxe driver is dispatched under enforcing Secure Boot, so firmware must
# validate it first — sign it with our db key (P), same as the PBA.
sbsign --key "$OUT/P.key" --cert "$OUT/P.crt" --output "$WORK/driver.efi" "$DRIVER"

# ---- 4. Enroll Secure Boot: our key (PBA) ONLY — no Microsoft in firmware ---------
echo "## Enrolling Secure Boot (enforcing): PK/KEK + db = { our key A only } — NO Microsoft CAs in db"
# The override model (ADR-0013): firmware trusts only our key A, so it validates the
# PBA and nothing else. Windows Boot Manager (Microsoft-signed) is NOT in db — firmware
# would reject it (EFI_SECURITY_VIOLATION) on its own. The PBA's trust broker verifies
# it against the Microsoft Windows CAs in the PBA's OWN embedded trust store, then admits
# it via the Security2 override (validation "pba-override"). --no-microsoft keeps the
# Microsoft KEK/db out of firmware; the broker (not firmware) owns the Windows db/dbx.
"$VFV" --input "$OVMF_VARS_TEMPLATE" --output "$WORK/vars0.fd" \
	--set-pk  "$GUID" "$OUT/PK.crt" \
	--add-kek "$GUID" "$OUT/KEK.crt" \
	--add-db  "$GUID" "$OUT/P.crt" \
	--no-microsoft --secure-boot >/dev/null
# Driver0000 -> MockOpalDxe so the mock SED's Storage Security protocol exists before
# the PBA runs and looks for a locked drive to unlock.
python3 "$HERE/add-driver-entry.py" "$WORK/vars0.fd" "$WORK/vars.fd" '\EFI\MOCK\MOCKOPALDXE.EFI' >/dev/null

# ---- 5. Build the GPT/ESP boot disk: PBA + mock SED in front of the Windows loader
echo "## Building the boot disk (PBA + MockOpalDxe + Windows boot files on a FAT32 ESP)"
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
# Stage the signed mock SED driver where Driver0000 expects it.
mmd   -i "$DISK@@1M" ::/EFI/MOCK 2>/dev/null || true
mcopy -i "$DISK@@1M" -o "$WORK/driver.efi" ::/EFI/MOCK/MOCKOPALDXE.EFI

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

SERIAL_LOG="$WORK/serial.log"; : > "$SERIAL_LOG"
QMP_SOCK="$WORK/qmp.sock"
QEMU_ARGS=(
	-machine q35 -accel "$ACCEL" -cpu "$CPU" -m 4G -smp 2
	-drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_SECBOOT_CODE"
	-drive if=pflash,format=raw,unit=1,file="$WORK/vars.fd"
	-drive "format=raw,file=$DISK,if=none,id=esp" -device virtio-blk-pci,drive=esp,bootindex=0
	-device qemu-xhci -device usb-tablet
	"${TPM_ARGS[@]}"
	-serial "file:$SERIAL_LOG"
	-qmp "unix:$QMP_SOCK,server,nowait"
	-net none
)

# Auto-type the SED passphrase over QMP unless the operator wants to type it. The
# typer watches the serial log for the PBA's "SED passphrase:" prompt (headless-safe;
# keystrokes reach ConIn over PS/2, so it works with or without a display).
start_typer() {
	[ "$INTERACTIVE" = 1 ] && return
	QMP_SOCK="$QMP_SOCK" SERIAL_LOG="$SERIAL_LOG" PASSPHRASE="correct horse" \
		python3 "$HERE/demo-console-type.py" & TYPER_PID=$!
}

if [ -n "${SCREENSHOT:-}" ]; then
	# Headless capture: boot, auto-unlock, wait, grab the framebuffer via QMP, exit.
	# Lets a maintainer (or CI) verify the demo lands in Windows without a display.
	echo "## Booting headless; auto-typing the SED passphrase; will screenshot to $SCREENSHOT after ${SCREENSHOT_DELAY:-120}s"
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -display none -vga std &
	QEMU_PID=$!
	start_typer
	# Poll: open a FRESH QMP connection every interval and screendump, so a guest
	# reboot / QEMU exit can't break a long-lived session. Writes out.<t>s.png at
	# each step plus the final out; stops when QEMU is gone or the delay elapses.
	python3 - "$QMP_SOCK" "$SCREENSHOT" "${SCREENSHOT_DELAY:-120}" <<'PY'
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
	echo "## Booting headless (serial); auto-typing the SED passphrase (accel=$ACCEL)."
	qemu-system-x86_64 "${QEMU_ARGS[@]}" -display none &
	QEMU_PID=$!
	tail -n +1 -F "$SERIAL_LOG" 2>/dev/null & TAIL_PID=$!
	start_typer
	wait "$QEMU_PID"
else
	intmsg="auto-typing the SED passphrase"; [ "$INTERACTIVE" = 1 ] && intmsg="type 'correct horse' at the SED prompt in the window"
	echo "## Booting the Windows demo in a QEMU window (accel=$ACCEL, TPM=${TPM_ARGS:+on}); $intmsg."
	echo "## Watch: firmware (Key A only) validates the PBA → mock SED unlock → PBA trust-brokers Windows Boot Manager + admits it via the Security2 override → Windows boots."
	qemu-system-x86_64 "${QEMU_ARGS[@]}" &
	QEMU_PID=$!
	start_typer
	wait "$QEMU_PID"
fi
