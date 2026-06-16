#!/usr/bin/env bash
#
# Secure Boot test matrix for Trusted PBA (Phase 2 foundation slice, #36).
#
# Generates throwaway TEST PK/KEK/db keys, enrolls them into an OVMF variable
# store (enforcing), signs the PBA + chainload fixture, and runs five scenarios:
#   A. SB off (Setup Mode), unsigned PBA      -> boots; PBA reports "secure-boot: off"
#   B. SB on  (enforcing),  db-signed PBA     -> boots; PBA reports "enforcing"
#   C. SB on  (enforcing),  UNSIGNED PBA      -> firmware REJECTS it (fail closed)
#   D. SB on  (enforcing),  WRONG-key PBA     -> firmware REJECTS it (signature != trust)
#   E. SB on  (enforcing),  db-signed PBA whose Authenticode hash is in dbx
#                                             -> firmware REJECTS it (revocation > trust)
#
#   secureboot-matrix.sh <pba.efi> <testapp.efi>
#
# TEST keys are generated in an ephemeral workdir and never written to the repo
# (baseline §13: never commit private keys).
set -euo pipefail

PBA="${1:?usage: secureboot-matrix.sh <pba.efi> <testapp.efi>}"
TESTAPP="${2:?usage: secureboot-matrix.sh <pba.efi> <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"
EXPECT="$HERE/expect-serial.py"
GO="${GO:-go}"

resolve_vfv

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
GUID="$(uuidgen)"

echo "## Generating test PK/KEK/db (throwaway, $WORK)"
gen_test_keys "$WORK" "TrustedPBA Test"

# An extra keypair that is NOT enrolled anywhere — proves that a validly-signed but
# UNTRUSTED image is still rejected (a signature alone is not trust).
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
	-subj "/CN=TrustedPBA UNTRUSTED key/" \
	-keyout "$WORK/bad.key" -out "$WORK/bad.crt" 2>/dev/null

echo "## Enrolling keys into OVMF VARS (enforcing) from $OVMF_VARS_TEMPLATE"
enroll_keys "$OVMF_VARS_TEMPLATE" "$WORK/vars.secboot.fd" "$GUID" "$WORK"

echo "## Signing PBA + fixture with the db key"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.signed.efi" "$PBA"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/testapp.signed.efi" "$TESTAPP"
sbverify --cert "$WORK/db.crt" "$WORK/pba.signed.efi" >/dev/null
# PBA signed by the untrusted key (cert not in db) — for the wrong-key scenario.
sbsign --key "$WORK/bad.key" --cert "$WORK/bad.crt" --output "$WORK/pba.badsigned.efi" "$PBA"

# A second enforcing store, identical trust to vars.secboot.fd but with the
# db-signed PBA's Authenticode hash added to dbx. The Authenticode digest excludes
# the signature, so it is the same whether computed here or by firmware; we compute
# it with go-uefi (the library imageverify itself uses) so the revoked hash and the
# product's notion of the image hash come from one source. (#18: dbx > db.)
echo "## Computing the db-signed PBA's Authenticode hash + enrolling a dbx-by-hash store"
PBA_HASH="$(cd "$ROOT" && "$GO" run ./test/qemu/authenticode-hash "$WORK/pba.signed.efi")"
enroll_keys "$OVMF_VARS_TEMPLATE" "$WORK/vars.dbxhash.fd" "$GUID" "$WORK" "$PBA_HASH"

fail=0

# A and B run the default sed_unlock="none" PBA: REQUIRE the loud skip marker
# and FORBID both unlock outcomes (same guard as the other suites), so a
# policy-variant mixup — a build that actually drives an unlock — can never
# silently pass.

# A: Secure Boot off (Setup Mode) — unsigned PBA boots, reports "off".
scenario "A: SB off, unsigned PBA -> boots" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$OVMF_VARS_TEMPLATE" TESTAPP="$TESTAPP" \
		REQUIRE='TRUSTED-PBA: secure-boot: off,TRUSTED-PBA: sed unlock not required by policy,TEST-APP: ok,TRUSTED-PBA: chainload returned' \
		FORBID='TRUSTED-PBA: sed unlock ok,TRUSTED-PBA: sed unlock failed' \
		python3 "$EXPECT" "$PBA"

# B: Secure Boot enforcing — signed PBA boots, reports "enforcing", chainloads signed fixture.
scenario "B: SB enforcing, signed PBA -> boots" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" TESTAPP="$WORK/testapp.signed.efi" \
		REQUIRE='TRUSTED-PBA: secure-boot: enforcing,TRUSTED-PBA: sed unlock not required by policy,TEST-APP: ok,TRUSTED-PBA: chainload returned' \
		FORBID='TRUSTED-PBA: sed unlock ok,TRUSTED-PBA: sed unlock failed' \
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

# D: Secure Boot enforcing — PBA signed by an UNTRUSTED key (not in db) is rejected.
# Proves a signature alone is not enough: the firmware rejects it just like the
# unsigned case ("Access Denied" / "Security Violation"). FORBID is the invariant.
scenario "D: SB enforcing, PBA signed by UNTRUSTED key -> firmware rejects" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.secboot.fd" \
		REQUIRE='Access Denied|Security Violation' \
		FORBID='TRUSTED-PBA: start' \
		python3 "$EXPECT" "$WORK/pba.badsigned.efi"

# E: Secure Boot enforcing — the SAME db-signed PBA that boots in B, but its
# Authenticode hash is now in dbx. Firmware must reject it: revocation overrides
# trust (dbx > db). Only the dbx entry differs from B, so a pass here can only mean
# the hash revocation took effect. FORBID any sign the PBA executed (the invariant).
scenario "E: SB enforcing, db-signed PBA revoked by dbx hash -> firmware rejects" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.dbxhash.fd" \
		REQUIRE='Access Denied|Security Violation' \
		FORBID='TRUSTED-PBA: start' \
		python3 "$EXPECT" "$WORK/pba.signed.efi"

echo
if [ "$fail" -eq 0 ]; then
	echo "SECURE BOOT MATRIX: PASS"
else
	echo "SECURE BOOT MATRIX: FAIL"
	exit 1
fi
