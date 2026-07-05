#!/usr/bin/env bash
#
# ADR-0012 / #82 task-1 GO-NO-GO spike: does firmware call an installed asm stub as
# EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication and honor its verdict, so an image
# NOT in firmware `db` boots under enforcing Secure Boot?
#
# OVMF is enrolled with OUR test keys ONLY (--no-microsoft, enforcing). Both PBA
# variants are db-signed (so firmware loads the PBA). The chainload target is the
# UNSIGNED testapp — out-of-`db`, so firmware rejects it normally.
#
#   NEG (default PBA, no override): firmware rejects the target -> "chainload failed".
#   POS (`-tags overridespike` PBA): the PBA overwrites Security2.FileAuthentication
#        with a runtime-free asm stub returning EFI_SUCCESS; firmware then calls it on
#        LoadImage and the out-of-`db` target BOOTS ("TEST-APP: ok").
#
#   override-spike.sh <pba-default.efi> <pba-overridespike.efi> <testapp.efi>
#
# SPIKE ONLY — the stub authorizes unconditionally (a Secure Boot bypass). Throwaway
# TEST keys, never committed (baseline §13).
set -euo pipefail

PBA_DEFAULT="${1:?usage: override-spike.sh <pba-default.efi> <pba-overridespike.efi> <testapp.efi>}"
PBA_SPIKE="${2:?usage: override-spike.sh <pba-default.efi> <pba-overridespike.efi> <testapp.efi>}"
TESTAPP="${3:?usage: override-spike.sh <pba-default.efi> <pba-overridespike.efi> <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"
EXPECT="$HERE/expect-serial.py"

resolve_vfv
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
GUID="$(uuidgen)"

echo "## Generating test PK/KEK/db (throwaway, $WORK) + enrolling our keys only (enforcing)"
gen_test_keys "$WORK" "TrustedPBA Test"
enroll_keys "$OVMF_VARS_TEMPLATE" "$WORK/vars.secboot.fd" "$GUID" "$WORK"

echo "## Signing both PBA variants with the db key (target stays unsigned = out-of-db)"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.default.efi" "$PBA_DEFAULT"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.spike.efi" "$PBA_SPIKE"

fail=0

# NEG (control): no override -> firmware rejects the unsigned/out-of-db target at
# LoadImage; the PBA surfaces it as "chainload failed". The target must NOT run.
scenario "NEG: no override, enforcing SB -> firmware rejects the out-of-db target" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" TESTAPP="$TESTAPP" \
		REQUIRE='TRUSTED-PBA: chainload failed' \
		FORBID='TEST-APP: ok' \
		python3 "$EXPECT" "$WORK/pba.default.efi"

# POS: the spike installs the Security2 stub; firmware calls it on LoadImage and the
# out-of-db target BOOTS. REQUIRE the install marker + the target's own marker;
# FORBID the fail-closed marker (its absence proves LoadImage succeeded).
scenario "POS: Security2 override installed -> out-of-db target boots under enforcing SB" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" TESTAPP="$TESTAPP" \
		REQUIRE='OVERRIDE-SPIKE: Security2,TEST-APP: ok' \
		FORBID='TRUSTED-PBA: chainload failed' \
		python3 "$EXPECT" "$WORK/pba.spike.efi"

echo
if [ "$fail" -eq 0 ]; then
	echo "OVERRIDE-SPIKE: GO — firmware honored the installed stub (mechanism viable)"
else
	echo "OVERRIDE-SPIKE: NO-GO — see failed scenario above"
	exit 1
fi
