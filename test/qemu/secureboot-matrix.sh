#!/usr/bin/env bash
#
# Secure Boot test matrix for Trusted PBA (Phase 2 foundation slice, #36).
#
# Generates throwaway TEST PK/KEK/db keys, enrolls them into an OVMF variable
# store (enforcing), signs the PBA + chainload fixture, and runs three scenarios:
#   A. SB off (Setup Mode), unsigned PBA      -> boots; PBA reports "secure-boot: off"
#   B. SB on  (enforcing),  signed PBA        -> boots; PBA reports "enforcing"
#   C. SB on  (enforcing),  UNSIGNED PBA      -> firmware REJECTS it (fail closed)
#
#   secureboot-matrix.sh <pba.efi> <testapp.efi>
#
# TEST keys are generated in an ephemeral workdir and never written to the repo
# (baseline §13: never commit private keys).
set -euo pipefail

PBA="${1:?usage: secureboot-matrix.sh <pba.efi> <testapp.efi>}"
TESTAPP="${2:?usage: secureboot-matrix.sh <pba.efi> <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
. "$HERE/ovmf-pair.sh"
EXPECT="$HERE/expect-serial.py"

VFV="${VIRT_FW_VARS:-$HOME/.local/bin/virt-fw-vars}"
command -v "$VFV" >/dev/null 2>&1 || VFV="virt-fw-vars"
command -v "$VFV" >/dev/null 2>&1 || {
	echo "virt-fw-vars not found (set VIRT_FW_VARS or: pip install virt-firmware)" >&2
	exit 2
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
GUID="$(uuidgen)"

echo "## Generating test PK/KEK/db (throwaway, $WORK)"
for role in PK KEK db; do
	openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
		-subj "/CN=TrustedPBA Test $role/" \
		-keyout "$WORK/$role.key" -out "$WORK/$role.crt" 2>/dev/null
done

echo "## Enrolling keys into OVMF VARS (enforcing) from $OVMF_VARS_TEMPLATE"
"$VFV" --input "$OVMF_VARS_TEMPLATE" --output "$WORK/vars.secboot.fd" \
	--set-pk "$GUID" "$WORK/PK.crt" \
	--add-kek "$GUID" "$WORK/KEK.crt" \
	--add-db "$GUID" "$WORK/db.crt" \
	--no-microsoft --secure-boot >/dev/null

echo "## Signing PBA + fixture with the db key"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.signed.efi" "$PBA"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/testapp.signed.efi" "$TESTAPP"
sbverify --cert "$WORK/db.crt" "$WORK/pba.signed.efi" >/dev/null

fail=0
scenario() {
	echo; echo "===== $1 ====="; shift
	if "$@"; then echo "----- ok"; else echo "----- FAILED"; fail=1; fi
}

# A: Secure Boot off (Setup Mode) — unsigned PBA boots, reports "off".
scenario "A: SB off, unsigned PBA -> boots" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$OVMF_VARS_TEMPLATE" TESTAPP="$TESTAPP" \
		REQUIRE='TRUSTED-PBA: secure-boot: off,TEST-APP: ok,TRUSTED-PBA: chainload returned' \
		python3 "$EXPECT" "$PBA"

# B: Secure Boot enforcing — signed PBA boots, reports "enforcing", chainloads signed fixture.
scenario "B: SB enforcing, signed PBA -> boots" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" TESTAPP="$WORK/testapp.signed.efi" \
		REQUIRE='TRUSTED-PBA: secure-boot: enforcing,TEST-APP: ok,TRUSTED-PBA: chainload returned' \
		python3 "$EXPECT" "$WORK/pba.signed.efi"

# C: Secure Boot enforcing — UNSIGNED PBA is rejected by firmware (fail closed).
# The firmware emits e.g. "failed to load Boot0002 ...: Access Denied -- rejected
# probably by Secure Boot". We REQUIRE the stable "Access Denied" status substring
# (resilient to edk2 message-wording changes across distros) and — the actual
# security invariant — FORBID any sign the PBA executed.
scenario "C: SB enforcing, unsigned PBA -> firmware rejects" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" \
		REQUIRE='Access Denied' \
		FORBID='TRUSTED-PBA: start' \
		python3 "$EXPECT" "$PBA"

echo
if [ "$fail" -eq 0 ]; then
	echo "SECURE BOOT MATRIX: PASS"
else
	echo "SECURE BOOT MATRIX: FAIL"
	exit 1
fi
