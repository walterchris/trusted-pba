#!/usr/bin/env bash
#
# demo:windows BITLOCKER=1 WIN_OSDISK=<disk> — boot a real, BitLocker-encrypted Windows
# through the PBA and watch it AUTO-UNLOCK via the TPM (no recovery prompt):
#
#   firmware (SB ENFORCING, db = key A + Microsoft CAs) validates the signed PBA -> the
#   PBA trust-brokers Windows Boot Manager (validation "pba") and firmware re-validates
#   it against the Microsoft db -> a NORMAL, reproducible PCR 7 -> BitLocker's TPM
#   protector releases the VMK -> Windows decrypts C: and boots to the logon screen.
#
# This is the firmware-db model (ADR-0013): BitLocker works because bootmgfw/winload are
# authorized by the Microsoft db, so PCR 7 is reproducible across boots. The Key-A-only
# override model (ADR-0014) does NOT work with BitLocker — it makes the OS-loader
# authority in PCR 7 non-reproducible, so BitLocker drops to recovery on every boot.
#
#   demo-windows-bitlocker.sh <pba-demowinbl.efi>
#
# On first run (or SETUP=1) it enables BitLocker on a working COPY of WIN_OSDISK: it
# plants the offline Utilman->cmd trick (ntfsprogs, no mount/root), provisions the TPM
# (swtpm_setup), boots through the PBA, opens a SYSTEM shell at the logon screen and runs
# bitlocker-enable.ps1, and waits for full encryption. The BitLocker disk + sealed TPM +
# Secure-Boot vars are cached in .demo-cache/wininstall/bl-*. Every later run just boots
# them (snapshot) and shows the auto-unlock. All keys are throwaway (bin/demowin/).
#
# Env: SETUP=1 force re-enable; SCREENSHOT=<png> headless capture; SERIAL=1 headless;
#      NOKVM=1 force TCG; WIN_OSDISK=<disk> the source Windows disk (required for setup).
set -euo pipefail

PBA="${1:?usage: demo-windows-bitlocker.sh <pba-demowinbl.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/bin/demowin"
MAT="$ROOT/internal/truststore/materials"
CACHE="${DEMO_CACHE:-$ROOT/.demo-cache}/wininstall"
BLQCOW="$CACHE/bl-demo.qcow2"; BLTPM="$CACHE/bl-demo-tpm"; BLVARS="$CACHE/bl-demo-vars.fd"
mkdir -p "$CACHE"
for t in ntfscat ntfscp ntfsfix swtpm_setup virt-fw-vars sbsign; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 2; }; done

# ---- Throwaway platform keys (persist across setup/demo) -----------------------
[ -f "$OUT/P.key" ] || { mkdir -p "$OUT"; for r in PK KEK P; do
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -subj "/CN=TrustedPBA Demo $r/" -keyout "$OUT/$r.key" -out "$OUT/$r.crt" 2>/dev/null; done; }

# ---- A Windows-compatible TPM-enabled OVMF (Fedora 4M, converted to raw) --------
CODE="$CACHE/ovmf4m-code.fd"; VTPL="$CACHE/ovmf4m-vars-tpl.fd"
if [ ! -f "$CODE" ]; then
  SRC=""; for c in /usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2 /usr/share/OVMF/OVMF_CODE_4M.secboot.qcow2; do [ -f "$c" ] && SRC="$c" && break; done
  [ -n "$SRC" ] || { echo "no 4M secboot OVMF found (need edk2 4M build with TPM2)" >&2; exit 2; }
  qemu-img convert -O raw "$SRC" "$CODE"
  qemu-img convert -O raw "${SRC/OVMF_CODE_4M/OVMF_VARS_4M}" "$VTPL"
fi

fwvars() {  # enroll db = key A + Microsoft Windows CAs + MS dbx into $1
  local guid; guid="$(uuidgen)"
  virt-fw-vars --input "$VTPL" --output "$1" \
    --set-pk "$guid" "$OUT/PK.crt" --add-kek "$guid" "$OUT/KEK.crt" --add-db "$guid" "$OUT/P.crt" \
    --add-db "$guid" "$MAT/db/win-production-pca-2011.der" --add-db "$guid" "$MAT/db/windows-uefi-ca-2023.der" \
    --set-dbx "$MAT/dbx/dbx-amd64.bin" --secure-boot >/dev/null
}

# ================= SETUP: enable BitLocker on a copy of WIN_OSDISK ===============
if [ "${SETUP:-0}" = 1 ] || [ ! -f "$BLQCOW" ]; then
  DISK="${WIN_OSDISK:?SETUP needs WIN_OSDISK=<installed Windows disk> (GPT + ESP + NTFS Windows)}"
  [ -f "$DISK" ] || { echo "WIN_OSDISK not found: $DISK" >&2; exit 2; }
  echo "## SETUP: enabling BitLocker on a working copy of $DISK (one-time, ~10 min)"
  W="$(mktemp -d)"; QP=""; SW=""
  cleanup(){ for p in "$QP" "$SW"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
  trap cleanup EXIT

  # NTFS partition offset from the GPT (part 3 = the Windows volume).
  OFF="$(python3 - "$DISK" <<'PY'
import sys,struct
f=open(sys.argv[1],'rb'); f.seek(512); h=f.read(92)
pl=struct.unpack('<Q',h[72:80])[0]; n=struct.unpack('<I',h[80:84])[0]; sz=struct.unpack('<I',h[84:88])[0]
f.seek(pl*512)
for i in range(n):
    e=f.read(sz)
    if e[:16]==b'\x00'*16: continue
    first=struct.unpack('<Q',e[32:40])[0]
    o=first*512; g=open(sys.argv[1],'rb'); g.seek(o); sig=g.read(11)[3:11]; g.close()
    if sig==b'NTFS    ': print(o); break
PY
)"
  [ -n "$OFF" ] || { echo "no NTFS partition found in $DISK" >&2; exit 2; }
  SIZE=$(( $(stat -c%s "$DISK") - OFF ))
  echo "## planting the Utilman->cmd trick + bitlocker-enable.ps1 offline (ntfsprogs)"
  dd if="$DISK" of="$W/p3.img" bs=1M iflag=skip_bytes,count_bytes skip="$OFF" count="$SIZE" conv=sparse status=none
  ntfsfix -d "$W/p3.img" >/dev/null 2>&1
  ntfscat "$W/p3.img" /Windows/System32/cmd.exe > "$W/cmd.exe" 2>/dev/null
  [ -f "$W/p3.img.Utilman.bak" ] || ntfscat "$W/p3.img" /Windows/System32/Utilman.exe > "$CACHE/Utilman.orig.exe" 2>/dev/null || true
  ntfscp "$W/p3.img" "$W/cmd.exe" /Windows/System32/Utilman.exe
  ntfscp "$W/p3.img" "$HERE/bitlocker-enable.ps1" /bitlocker-enable.ps1
  # working raw copy of the whole disk with the modified partition + the signed PBA in the ESP
  cp --sparse=always "$DISK" "$W/work.img"
  dd if="$W/p3.img" of="$W/work.img" bs=1M iflag=skip_bytes,count_bytes oflag=seek_bytes seek="$OFF" count="$SIZE" conv=notrunc,sparse status=none
  sbsign --key "$OUT/P.key" --cert "$OUT/P.crt" --output "$W/pba.efi" "$PBA" >/dev/null 2>&1
  mcopy -i "$W/work.img@@1M" -o "$W/pba.efi" ::/EFI/BOOT/BOOTX64.EFI
  rm -f "$BLQCOW"; qemu-img convert -O qcow2 "$W/work.img" "$BLQCOW"

  rm -rf "$BLTPM"; mkdir -p "$BLTPM"; swtpm_setup --tpm2 --tpmstate "$BLTPM" --overwrite --logfile "$W/prov.log" >/dev/null 2>&1 || true
  fwvars "$BLVARS"
  swtpm socket --tpm2 --tpmstate dir="$BLTPM" --ctrl type=unixio,path="$W/tpm.sock" --flags startup-clear >/dev/null 2>&1 & SW=$!
  sleep 1; : > /tmp/bl-demo-setup-serial.log
  ACCEL=tcg; CPU=max; [ -z "${NOKVM:-}" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] && { ACCEL=kvm; CPU=host; }
  qemu-system-x86_64 -machine q35 -accel "$ACCEL" -cpu "$CPU" -m 6G -smp 4 \
    -drive if=pflash,unit=0,readonly=on,format=raw,file="$CODE" \
    -drive if=pflash,unit=1,format=raw,file="$BLVARS" \
    -drive "file=$BLQCOW,if=none,id=osd,format=qcow2" -device ide-hd,drive=osd,bus=ide.0,bootindex=0 \
    -chardev socket,id=chrtpm,path="$W/tpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0 \
    -device qemu-xhci -device usb-tablet -net none -display none -vga std \
    -serial file:/tmp/bl-demo-setup-serial.log -qmp "unix:$W/qmp.sock,server,nowait" & QP=$!
  echo "## booting through the PBA; a SYSTEM shell will enable BitLocker (watch /tmp/bl-demo-setup-serial.log)"
  python3 "$HERE/win-utilman-drive.py" "$W/qmp.sock" "$W" setup 'C:\bitlocker-enable.ps1' || true
  for i in $(seq 1 110); do kill -0 "$QP" 2>/dev/null || break; sleep 5; done
  kill "$QP" "$SW" 2>/dev/null || true; QP=""; SW=""
  sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\r//g' /tmp/bl-demo-setup-serial.log | grep -aE "^BL: (FINAL|protector:)" || true
  # sanity: the volume must now be BitLocker (-FVE-FS-)
  qemu-img convert -O raw "$BLQCOW" "$W/chk.raw"
  sig="$(python3 -c "f=open('$W/chk.raw','rb');f.seek($OFF);import sys;sys.stdout.write(repr(f.read(11)[3:11]))")"
  [ "$sig" = "b'-FVE-FS-'" ] || { echo "## SETUP FAILED: volume is not BitLocker-encrypted ($sig). Re-run with SETUP=1." >&2; exit 1; }
  echo "## SETUP done: BitLocker enabled + TPM-sealed. Cached: $(basename "$BLQCOW"), sealed TPM, SB vars."
  trap - EXIT; rm -rf "$W"
fi

# ================= DEMO: boot the BitLocker disk -> TPM auto-unlock ==============
[ -f "$BLQCOW" ] && [ -f "$BLVARS" ] && [ -d "$BLTPM" ] || { echo "no cached BitLocker demo; run once with SETUP=1 WIN_OSDISK=<disk>" >&2; exit 2; }
echo "## DEMO: booting the BitLocker-encrypted Windows through the PBA — the TPM auto-unlocks it (no recovery prompt)"
W="$(mktemp -d)"; QP=""; SW=""
cleanup2(){ for p in "$QP" "$SW"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup2 EXIT
swtpm socket --tpm2 --tpmstate dir="$BLTPM" --ctrl type=unixio,path="$W/tpm.sock" --flags startup-clear >/dev/null 2>&1 & SW=$!
sleep 1
# Same SB vars as the seal boot (a different PK/KEK/db enrollment would change PCR 7 and
# force BitLocker recovery), and snapshot=on so the demo is repeatable and read-only.
ACCEL=tcg; CPU=max; [ -z "${NOKVM:-}" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] && { ACCEL=kvm; CPU=host; }
QEMU_ARGS=(
  -machine q35 -accel "$ACCEL" -cpu "$CPU" -m 6G -smp 4
  -drive if=pflash,unit=0,readonly=on,format=raw,file="$CODE"
  -drive if=pflash,unit=1,format=raw,file="$BLVARS"
  -drive "file=$BLQCOW,if=none,id=osd,format=qcow2,snapshot=on" -device ide-hd,drive=osd,bus=ide.0,bootindex=0
  -chardev "socket,id=chrtpm,path=$W/tpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0
  -device qemu-xhci -device usb-tablet -net none
)
if [ -n "${SCREENSHOT:-}" ]; then
  qemu-system-x86_64 "${QEMU_ARGS[@]}" -display none -vga std -qmp "unix:$W/qmp.sock,server,nowait" & QP=$!
  python3 - "$W/qmp.sock" "$SCREENSHOT" "${SCREENSHOT_DELAY:-150}" <<'PY'
import socket,json,sys,time,os
sock,out,delay=sys.argv[1],sys.argv[2],int(sys.argv[3]); base=out[:-4] if out.endswith(".png") else out
def shot(p):
    try:
        s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(sock);f=s.makefile("rw")
        f.readline();f.write('{"execute":"qmp_capabilities"}\n');f.flush();f.readline()
        f.write(json.dumps({"execute":"screendump","arguments":{"filename":p,"format":"png"}})+"\n");f.flush()
        r=f.readline().strip();s.close();return "error" not in r
    except Exception as e: print("qmp gone:",e); return False
for _ in range(120):
    if os.path.exists(sock): break
    time.sleep(0.5)
t=0
while t<delay:
    time.sleep(30); t+=30; print(f"t={t}s ok={shot(f'{base}.{t}s.png')}")
shot(out)
PY
  echo "## screenshots: ${SCREENSHOT%.png}.<t>s.png (+ $SCREENSHOT)"
elif [ -n "${SERIAL:-}" ]; then
  qemu-system-x86_64 "${QEMU_ARGS[@]}" -nographic & QP=$!; wait "$QP"
else
  echo "## Watch: firmware validates the PBA -> PBA + firmware validate Windows Boot Manager -> TPM auto-unlocks BitLocker -> Windows logon."
  qemu-system-x86_64 "${QEMU_ARGS[@]}" & QP=$!; wait "$QP"
fi
