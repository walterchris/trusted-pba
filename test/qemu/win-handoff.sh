#!/usr/bin/env bash
#
# Windows-handoff (A') test for Trusted PBA — the firmware-db path for a real
# Microsoft-signed second stage (e.g. Windows Boot Manager). See ADR-0012 / ADR-0007.
#
# The PBA is built `-tags winhandoff,trustfull`: a pba-validation policy targeting
# the staged loader (EFI/TEST/TESTAPP.EFI) + the real full trust set (Microsoft CAs).
# We enroll OUR test keys AND the Microsoft KEK/db into OVMF, so the two-hop chain is:
#   1. firmware validates the PBA via OUR db key (first hop);
#   2. the PBA pba-verifies the real Microsoft-signed loader against the MS CA in its
#      embedded trust store (the trust-broker check);
#   3. firmware re-validates the SourceBuffer against the Microsoft CA in db on load.
# All three must pass for the loader to launch — and because firmware db (not a
# Security-protocol override) authorizes it, PCR 7 / BitLocker stay intact (ADR-0012).
#
# Scenarios:
#   POS: our keys + Microsoft in db          -> PBA verifies AND firmware loads it
#   NEG: our keys ONLY in db (--no-microsoft) -> PBA still verifies, but firmware
#        rejects the MS-signed buffer on load (proves the PBA's verdict alone is not
#        sufficient under enforcing Secure Boot — the mechanism ADR-0012 documents).
#
#   win-handoff.sh <pba-winhandoff.efi>
#
# The Microsoft-signed loader is operator/CI-provided (not committed): set
# TPBA_REAL_WINLOADER (or TPBA_REAL_SHIM — CI installs shim-signed, which chains to
# the third-party Microsoft UEFI CA and is redistributable). Skips when absent so
# normal runs stay deterministic — same gating as TestRealMicrosoftSignedImage.
#
# TEST keys are ephemeral and never written to the repo (baseline §13).
set -euo pipefail

PBA="${1:?usage: win-handoff.sh <pba-winhandoff.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
EXPECT="$HERE/expect-serial.py"

# Gate BEFORE sourcing ovmf-pair.sh (which fails when no OVMF pair is present), so a
# machine without the loader skips cleanly regardless of OVMF availability.
LOADER="${TPBA_REAL_WINLOADER:-${TPBA_REAL_SHIM:-}}"
if [ -z "$LOADER" ] || [ ! -f "$LOADER" ]; then
	echo "SKIP: set TPBA_REAL_WINLOADER (or TPBA_REAL_SHIM) to a Microsoft-signed loader to run the Windows-handoff test"
	exit 0
fi
echo "## Windows-handoff loader: $LOADER"

. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"
resolve_vfv
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
GUID="$(uuidgen)"

echo "## Generating test PK/KEK/db (throwaway, $WORK)"
gen_test_keys "$WORK" "TrustedPBA Test"

echo "## Signing the PBA with the db key"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.signed.efi" "$PBA"

echo "## Enrolling OVMF stores: (POS) our keys + Microsoft, (NEG) our keys only"
enroll_keys_ms "$OVMF_VARS_TEMPLATE" "$WORK/vars.ms.fd"    "$GUID" "$WORK"
enroll_keys    "$OVMF_VARS_TEMPLATE" "$WORK/vars.nomsfd"   "$GUID" "$WORK"

fail=0

# POS: our db key validates the PBA; the MS CA in db validates the loader on load;
# the PBA independently pba-verifies it against the full trust set. REQUIRE the
# PBA's verify marker and FORBID the fail-closed marker — its absence after
# "pba-verified" means LoadImageBuffer succeeded (firmware accepted the MS-signed
# buffer) and StartImage was reached, i.e. the loader launched.
scenario "POS: our keys + Microsoft in db -> PBA verifies + firmware loads real MS loader" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.ms.fd" TESTAPP="$LOADER" \
		REQUIRE='TRUSTED-PBA: start,TRUSTED-PBA: pba-verified EFI/TEST/TESTAPP.EFI (trust set full)' \
		FORBID='chainload failed' \
		python3 "$EXPECT" "$WORK/pba.signed.efi"

# NEG: same PBA + loader, but only our keys in db. The PBA still verifies the loader
# (its trust store has the MS CA), then firmware REJECTS the MS-signed buffer on load
# (no MS CA in db) -> "chainload failed". Proves firmware re-validation is the gate
# and that MS-CA-in-db (not the PBA's verdict) is what authorizes the load.
scenario "NEG: our keys only in db -> PBA verifies but firmware rejects the load" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.nomsfd" TESTAPP="$LOADER" \
		REQUIRE='TRUSTED-PBA: pba-verified EFI/TEST/TESTAPP.EFI (trust set full),chainload failed' \
		FORBID='TRUSTED-PBA: chainload returned' \
		python3 "$EXPECT" "$WORK/pba.signed.efi"

echo
if [ "$fail" -eq 0 ]; then
	echo "WINDOWS-HANDOFF: PASS"
else
	echo "WINDOWS-HANDOFF: FAIL"
	exit 1
fi
