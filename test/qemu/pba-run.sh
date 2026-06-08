#!/usr/bin/env bash
#
# PBA verify-then-load matrix in QEMU/OVMF. Boots the `-tags pbatest` PBA (whose
# embedded policy uses validation "pba" and whose only trusted db cert is the test
# CA from pba-setup.sh) against two staged fixtures:
#
#   accept : fixture signed by the test CA  -> imageverify accepts -> chainload runs
#   reject : unsigned fixture               -> fail closed, image never started
#
# Removes the generated test-db.der on exit so it never lingers in a checkout.
#
#   pba-run.sh <pba-pbatest.efi> <unsigned-testapp.efi>
#
# Needs: the materials prepared by pba-setup.sh (bin/pbatest/testapp-signed.efi).

set -euo pipefail

PBA="${1:?usage: pba-run.sh <pba.efi> <testapp.efi>}"
FIX_UNSIGNED="${2:?usage: pba-run.sh <pba.efi> <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
SIGNED="$ROOT/bin/pbatest/testapp-signed.efi"
DER="$ROOT/internal/truststore/testdata/test-db.der"

cleanup() { rm -f "$DER"; }
trap cleanup EXIT

[ -f "$SIGNED" ] || { echo "missing $SIGNED (run pba-setup.sh first)" >&2; exit 2; }

echo "== pba-accept: fixture signed by embedded test CA must verify and chainload =="
REQUIRE='TRUSTED-PBA: pba-verified,TEST-APP: ok,TRUSTED-PBA: chainload returned' \
FORBID='TRUSTED-PBA: chainload failed' \
TESTAPP="$SIGNED" \
	python3 "$HERE/expect-serial.py" "$PBA"

echo "== pba-reject: unsigned fixture must fail closed (no chainload) =="
REQUIRE='TRUSTED-PBA: chainload failed' \
FORBID='TEST-APP: ok,TRUSTED-PBA: chainload returned' \
TESTAPP="$FIX_UNSIGNED" \
	python3 "$HERE/expect-serial.py" "$PBA"

echo "pba-matrix: PASS"
