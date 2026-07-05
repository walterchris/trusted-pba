#!/usr/bin/env bash
#
# ADR-0012 task 5: EMPIRICALLY confirm the pba-override path diverges PCR 7 (the PCR
# BitLocker seals to). Boots a guest EFI_TCG2 PCR reader (tpmread) two ways under a
# TPM-enabled OVMF + swtpm and compares the PCR 7 it prints over serial:
#
#   OVERRIDE : override PBA + fixture signed by the pbatest test CA (NOT in db).
#              The Security2 override authorizes it -> firmware records NO
#              EV_EFI_VARIABLE_AUTHORITY(db) event for the fixture in PCR 7.
#   FIRMWARE : firmware-validation PBA + fixture signed by a DISTINCT db authority
#              (dbB). Firmware validates it -> measures dbB into PCR 7.
#
# PCR 7 must DIFFER. Note: the fixture's authority must be DISTINCT from the PBA's,
# or PCR 7's per-authority dedup hides the difference (this is why the real Windows
# case — PBA=our key, bootmgfw=Microsoft's — diverges).
#
#   override-pcr.sh <override-pba.efi> <firmware-pba.efi> <tpmread.efi>
#
# Needs a TPM-enabled OVMF (build-ovmf-tpm.sh), swtpm, sbsign, virt-firmware, and the
# pbatest test CA key (bin/pbatest/test.key, from pba-setup.sh). Throwaway keys only.
set -euo pipefail

OVERRIDE_PBA="${1:?usage: override-pcr.sh <override-pba> <firmware-pba> <tpmread.efi>}"
FW_PBA="${2:?}"
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

echo "## Building TPM-enabled OVMF (Fedora's has no TPM2)"
eval "$("$HERE/build-ovmf-tpm.sh" | tail -2)"   # sets OVMF_TPM_CODE / OVMF_TPM_VARS
[ -f "${OVMF_TPM_CODE:-}" ] || { echo "no TPM-enabled OVMF" >&2; exit 1; }

WORK="$(mktemp -d)"   # short path for swtpm UNIX sockets
trap 'rm -rf "$WORK"; pkill -f "swtpm socket.*$WORK" 2>/dev/null || true' EXIT
GUID="$(uuidgen)"

gen_test_keys "$WORK" "TrustedPBA Test"
# A second, DISTINCT db authority for the firmware-validated fixture (so its PCR 7
# authority event is not deduped against the PBA's).
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -subj "/CN=TrustedPBA dbB" \
	-keyout "$WORK/dbB.key" -out "$WORK/dbB.crt" 2>/dev/null
"$VFV" --input "$OVMF_TPM_VARS" --output "$WORK/vars.fd" \
	--set-pk "$GUID" "$WORK/PK.crt" --add-kek "$GUID" "$WORK/KEK.crt" \
	--add-db "$GUID" "$WORK/db.crt" --add-db "$GUID" "$WORK/dbB.crt" \
	--no-microsoft --secure-boot >/dev/null

sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.override.efi" "$OVERRIDE_PBA"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.fw.efi" "$FW_PBA"
sbsign --key "$TESTCA_KEY" --cert "$TESTCA_CRT" --output "$WORK/tpmread.testca.efi" "$TPMREAD"
sbsign --key "$WORK/dbB.key" --cert "$WORK/dbB.crt" --output "$WORK/tpmread.dbB.efi" "$TPMREAD"

# boot <pba> <fixture> <tag> -> echoes the "PCR7: <hex>" line the guest printed.
boot() {
	local pba="$1" fix="$2" tag="$3" s="$WORK/tpm.$3"
	mkdir -p "$s/st"; cp "$WORK/vars.fd" "$s/vars.fd"
	setsid swtpm socket --tpm2 --tpmstate dir="$s/st" --ctrl type=unixio,path="$s/c" \
		--flags startup-clear </dev/null >"$s/swtpm.log" 2>&1 &
	local sp=$!; sleep 1
	env OVMF_CODE="$OVMF_TPM_CODE" OVMF_VARS="$s/vars.fd" TESTAPP="$fix" QEMU_TPM_SOCK="$s/c" \
		QEMU_TIMEOUT=90 REQUIRE='PCR7:' FORBID='__none__' \
		python3 "$EXPECT" "$pba" 2>&1 | grep -aoE 'PCR7: [0-9a-f]{64}' | head -1
	kill "$sp" 2>/dev/null || true
}

A="$(boot "$WORK/pba.override.efi" "$WORK/tpmread.testca.efi" override)"
B="$(boot "$WORK/pba.fw.efi" "$WORK/tpmread.dbB.efi" firmware)"

echo
echo "override PCR7 : ${A#PCR7: }"
echo "firmware PCR7 : ${B#PCR7: }"
if [ -n "$A" ] && [ -n "$B" ] && [ "$A" != "$B" ]; then
	echo "PCR-7 CHARACTERIZATION: PASS — override diverges PCR 7 (BitLocker seal to PCR 7 would break)"
elif [ -n "$A" ] && [ "$A" = "$B" ]; then
	echo "PCR-7 CHARACTERIZATION: FAIL — PCR 7 identical (authority deduped? check distinct db certs)"; exit 1
else
	echo "PCR-7 CHARACTERIZATION: FAIL — a boot did not report PCR 7"; exit 1
fi
