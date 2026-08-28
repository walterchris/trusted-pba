#!/usr/bin/env bash
#
# ADR-0014 validation: the pba-override PCR-7 REPRODUCIBILITY theory — the claim
# BitLocker actually depends on. override-pcr.sh already proved the override *diverges*
# PCR 7 from a firmware-db boot; this proves the two properties that decide whether a
# BitLocker seal to that (diverged) PCR 7 would keep releasing:
#
#   1. REPRODUCIBLE : boot the SAME override config twice → PCR 7 must be IDENTICAL.
#                     (If it is, a TPM seal to it re-releases on every boot.)
#   2. AUTHORITY-STABLE, NOT HASH-STABLE : boot the override with a DIFFERENT PBA
#      binary signed by the SAME key A (a content update) → PCR 7 must be IDENTICAL
#      (PCR 7 measures the Secure Boot *authority* = key A, not the image hash),
#      while PCR 4 (the image hash) DIFFERS (proving the content really changed).
#      This refines ADR-0014: a same-key PBA update is NOT a BitLocker reseal event;
#      only a signing-key / db / Secure-Boot-config change is.
#
#   pcr7-reproducibility.sh <override-pba-v1.efi> <override-pba-v2.efi> <tpmread.efi>
#
# Firmware db = OUR KEY A ONLY (--no-microsoft), exactly as demo:windows enrolls it, so
# the tpmread fixture (standing in for bootmgfw, signed by the pbatest test CA, NOT in
# db) can only load via the Security2 override. Needs a TPM-enabled OVMF
# (build-ovmf-tpm.sh), swtpm, sbsign, virt-firmware, and the pbatest test CA
# (bin/pbatest/test.{key,crt}, from pba-setup.sh). Throwaway keys only.
set -euo pipefail

V1="${1:?usage: pcr7-reproducibility.sh <override-v1> <override-v2> <tpmread.efi>}"
V2="${2:?}"
TPMREAD="${3:?}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"
EXPECT="$HERE/expect-serial.py"
TESTCA_KEY="$ROOT/bin/pbatest/test.key"
TESTCA_CRT="$ROOT/bin/pbatest/test.crt"

[ -f "$TESTCA_KEY" ] || { echo "missing $TESTCA_KEY (run test/qemu/pba-setup.sh first)" >&2; exit 2; }
command -v swtpm >/dev/null || { echo "swtpm not found" >&2; exit 2; }
resolve_vfv

echo "## Building/locating TPM-enabled OVMF (Fedora's has no TPM2)"
eval "$("$HERE/build-ovmf-tpm.sh" | tail -2)"   # sets OVMF_TPM_CODE / OVMF_TPM_VARS
[ -f "${OVMF_TPM_CODE:-}" ] || { echo "no TPM-enabled OVMF" >&2; exit 1; }

WORK="$(mktemp -d)"   # short path for swtpm UNIX sockets
trap 'rm -rf "$WORK"; pkill -f "swtpm socket.*$WORK" 2>/dev/null || true' EXIT
GUID="$(uuidgen)"

gen_test_keys "$WORK" "TrustedPBA Test"
# Firmware db = key A ONLY (no Microsoft) — identical to the demo:windows override model.
"$VFV" --input "$OVMF_TPM_VARS" --output "$WORK/vars.fd" \
	--set-pk "$GUID" "$WORK/PK.crt" --add-kek "$GUID" "$WORK/KEK.crt" \
	--add-db "$GUID" "$WORK/db.crt" \
	--no-microsoft --secure-boot >/dev/null

# Both PBA versions signed by the SAME key A; the fixture by the pbatest test CA (out
# of db → only the override can load it).
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/v1.efi" "$V1"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/v2.efi" "$V2"
sbsign --key "$TESTCA_KEY"  --cert "$TESTCA_CRT"  --output "$WORK/tpmread.efi" "$TPMREAD"

# boot <pba> <tag> -> echoes "PCR7:<hex> PCR4:<hex>" the guest printed over serial.
boot() {
	local pba="$1" tag="$2" s="$WORK/tpm.$2"
	mkdir -p "$s/st"; cp "$WORK/vars.fd" "$s/vars.fd"
	setsid swtpm socket --tpm2 --tpmstate dir="$s/st" --ctrl type=unixio,path="$s/c" \
		--flags startup-clear </dev/null >"$s/swtpm.log" 2>&1 &
	local sp=$!; sleep 1
	local outp
	outp="$(env OVMF_CODE="$OVMF_TPM_CODE" OVMF_VARS="$s/vars.fd" TESTAPP="$WORK/tpmread.efi" \
		QEMU_TPM_SOCK="$s/c" QEMU_TIMEOUT=90 REQUIRE='PCR4:' FORBID='__none__' \
		python3 "$EXPECT" "$pba" 2>&1)"
	kill "$sp" 2>/dev/null || true
	local p7 p4
	p7="$(printf '%s' "$outp" | grep -aoE 'PCR7: [0-9a-f]{64}' | head -1 | awk '{print $2}')"
	p4="$(printf '%s' "$outp" | grep -aoE 'PCR4: [0-9a-f]{64}' | head -1 | awk '{print $2}')"
	echo "PCR7:$p7 PCR4:$p4"
}

echo "## Boot 1/3 — override, PBA v1 (first boot)"
R_A="$(boot "$WORK/v1.efi" a)"
echo "## Boot 2/3 — override, PBA v1 (repeat, fresh TPM)"
R_B="$(boot "$WORK/v1.efi" b)"
echo "## Boot 3/3 — override, PBA v2 (different content, SAME key A)"
R_C="$(boot "$WORK/v2.efi" c)"

A7="${R_A#PCR7:}"; A7="${A7%% *}"; A4="${R_A##*PCR4:}"
B7="${R_B#PCR7:}"; B7="${B7%% *}"; B4="${R_B##*PCR4:}"
C7="${R_C#PCR7:}"; C7="${C7%% *}"; C4="${R_C##*PCR4:}"

echo
printf 'v1 boot #1 : PCR7=%s  PCR4=%s\n' "$A7" "$A4"
printf 'v1 boot #2 : PCR7=%s  PCR4=%s\n' "$B7" "$B4"
printf 'v2 (diff)  : PCR7=%s  PCR4=%s\n' "$C7" "$C4"
echo

fail=0
[ -n "$A7" ] && [ -n "$B7" ] && [ -n "$C7" ] || { echo "FAIL — a boot did not report PCR 7/4"; exit 1; }

# 1. Reproducible across identical boots.
if [ "$A7" = "$B7" ]; then
	echo "REPRODUCIBLE           : PASS — PCR 7 identical across two identical override boots"
else
	echo "REPRODUCIBLE           : FAIL — PCR 7 changed between identical boots"; fail=1
fi
# 2a. Same-key content update does NOT move PCR 7 (authority-stable).
if [ "$A7" = "$C7" ]; then
	echo "AUTHORITY-STABLE       : PASS — PCR 7 unchanged by a same-key PBA content update (NOT a reseal event)"
else
	echo "AUTHORITY-STABLE       : FAIL — PCR 7 changed on a same-key content update"; fail=1
fi
# 2b. ...but the content really did change (PCR 4 differs), so 2a is meaningful.
if [ "$A4" != "$C4" ]; then
	echo "CONTENT-DID-CHANGE     : PASS — PCR 4 differs for v1 vs v2 (image hash changed, as expected)"
else
	echo "CONTENT-DID-CHANGE     : WARN — PCR 4 identical; v1/v2 may not differ in measured content"
fi

echo
if [ "$fail" = 0 ]; then
	echo "PCR-7 REPRODUCIBILITY: PASS — a BitLocker seal to the override PCR 7 is reproducible across boots"
	echo "  and survives same-key PBA content updates; only a signing-key/db/SB-config change reseals."
else
	echo "PCR-7 REPRODUCIBILITY: FAIL"; exit 1
fi
