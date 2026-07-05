#!/usr/bin/env bash
#
# ADR-0012 trust-broker override matrix (pba-override validation). Self-contained:
# the pbatest test CA (embedded in both PBA builds) signs the fixture, and OVMF is
# enrolled with OUR keys ONLY — so the fixture is PBA-trusted but NOT in firmware db.
#
#   CONTROL (pba build, no override): PBA verifies the fixture, then firmware rejects
#           it at LoadImageBuffer (not in db) -> "chainload failed". Proves the PBA
#           verdict alone cannot make firmware accept an out-of-db image.
#   POS     (overridetest,trustbroker build): PBA verifies -> arms the Security2
#           override for exactly that buffer -> firmware honors it -> fixture BOOTS.
#   TAMPER  (override build, UNSIGNED fixture): imageverify rejects before arming ->
#           fail-closed, override never installed.
#
#   override-trustbroker.sh <control-pba.efi> <override-pba.efi> <signed-fixture.efi> <unsigned-fixture.efi>
#
# SPIKE/pre-acceptance: the override diverges PCR 7 (ADR-0012). Throwaway TEST keys,
# never committed (baseline §13).
set -euo pipefail

CONTROL="${1:?usage: override-trustbroker.sh <control-pba> <override-pba> <signed-fixture> <unsigned-fixture>}"
OVERRIDE="${2:?}"
SIGNED="${3:?}"
UNSIGNED="${4:?}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"
EXPECT="$HERE/expect-serial.py"

resolve_vfv
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
GUID="$(uuidgen)"

echo "## Generating test PK/KEK/db (throwaway) + enrolling our keys only (enforcing)"
gen_test_keys "$WORK" "TrustedPBA Test"
enroll_keys "$OVMF_VARS_TEMPLATE" "$WORK/vars.secboot.fd" "$GUID" "$WORK"

echo "## Signing both PBA builds with the db key (fixture stays test-CA-signed = out-of-db)"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.control.efi" "$CONTROL"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.override.efi" "$OVERRIDE"

fail=0

# CONTROL: pba (no override) -> firmware re-validates the buffer at LoadImageBuffer
# and rejects it (the test CA is not in db). The PBA surfaces "chainload failed".
scenario "CONTROL: pba mode, enforcing SB -> firmware rejects the out-of-db (but PBA-verified) fixture" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" TESTAPP="$SIGNED" \
		REQUIRE='TRUSTED-PBA: pba-verified,TRUSTED-PBA: chainload failed' \
		FORBID='TEST-APP: ok' \
		python3 "$EXPECT" "$WORK/pba.control.efi"

# POS: pba-override -> PBA verifies, arms the override for that buffer, firmware
# honors it, fixture boots. REQUIRE verify + arm + the fixture marker; FORBID fail.
scenario "POS: pba-override -> verified out-of-db fixture BOOTS under enforcing SB" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" TESTAPP="$SIGNED" \
		REQUIRE='TRUSTED-PBA: pba-verified,TRUSTED-PBA: override armed,TEST-APP: ok' \
		FORBID='TRUSTED-PBA: chainload failed' \
		python3 "$EXPECT" "$WORK/pba.override.efi"

# TAMPER: pba-override with an UNSIGNED fixture -> imageverify rejects before the
# override is armed; fail-closed, nothing installed, nothing boots.
scenario "TAMPER: pba-override, unsigned fixture -> verify fails closed, override never armed" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" TESTAPP="$UNSIGNED" \
		REQUIRE='TRUSTED-PBA: chainload failed' \
		FORBID='TEST-APP: ok,TRUSTED-PBA: override armed' \
		python3 "$EXPECT" "$WORK/pba.override.efi"

echo
if [ "$fail" -eq 0 ]; then
	echo "TRUST-BROKER OVERRIDE MATRIX: PASS"
else
	echo "TRUST-BROKER OVERRIDE MATRIX: FAIL"
	exit 1
fi
