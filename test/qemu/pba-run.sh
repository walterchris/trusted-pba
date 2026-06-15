#!/usr/bin/env bash
#
# PBA verify-then-load matrix in QEMU/OVMF. Boots the `-tags pbatest` PBA (whose
# embedded policy uses validation "pba" and whose only trusted db cert is the test
# CA from pba-setup.sh) against two staged fixtures:
#
#   accept  : fixture signed by the test CA  -> imageverify accepts -> chainload runs
#   reject  : unsigned fixture               -> fail closed, image never started
#   revoked : fixture signed by a leaf that chains to db but is dbx-revoked
#             -> fail closed (dbx by certificate), image never started
#
# Removes the generated test-db.der / test-dbx.bin on exit so they never linger in
# a checkout.
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
REVOKED="$ROOT/bin/pbatest/testapp-revoked.efi"
DER="$ROOT/internal/truststore/testdata/test-db.der"
DBX="$ROOT/internal/truststore/testdata/test-dbx.bin"

cleanup() { rm -f "$DER" "$DBX"; }
trap cleanup EXIT

[ -f "$SIGNED" ] || { echo "missing $SIGNED (run pba-setup.sh first)" >&2; exit 2; }
[ -f "$REVOKED" ] || { echo "missing $REVOKED (run pba-setup.sh first)" >&2; exit 2; }

# Both scenarios run the sed_unlock="none" pbatest policy: REQUIRE the loud
# skip marker and FORBID both unlock outcomes, so a policy-variant mixup
# (a build that actually drives an unlock) can never silently pass.
echo "== pba-accept: fixture signed by embedded test CA must verify and chainload =="
REQUIRE='TRUSTED-PBA: sed unlock not required by policy,TRUSTED-PBA: pba-verified,TEST-APP: ok,TRUSTED-PBA: chainload returned' \
FORBID='TRUSTED-PBA: chainload failed,TRUSTED-PBA: sed unlock ok,TRUSTED-PBA: sed unlock failed' \
TESTAPP="$SIGNED" \
	python3 "$HERE/expect-serial.py" "$PBA"

echo "== pba-reject: unsigned fixture must fail closed (no chainload) =="
REQUIRE='TRUSTED-PBA: sed unlock not required by policy,TRUSTED-PBA: chainload failed' \
FORBID='TEST-APP: ok,TRUSTED-PBA: chainload returned,TRUSTED-PBA: sed unlock ok,TRUSTED-PBA: sed unlock failed' \
TESTAPP="$FIX_UNSIGNED" \
	python3 "$HERE/expect-serial.py" "$PBA"

# The revoked fixture IS validly signed and DOES chain to db (via R) — it must be
# rejected specifically by dbx (ErrRevokedCert), never reaching pba-verified. FORBID
# pba-verified so a regression that stops enforcing dbx cannot silently pass here.
echo "== pba-revoked: dbx-revoked (but db-chaining) fixture must fail closed (no chainload) =="
REQUIRE='TRUSTED-PBA: sed unlock not required by policy,TRUSTED-PBA: chainload failed' \
FORBID='TEST-APP: ok,TRUSTED-PBA: pba-verified,TRUSTED-PBA: chainload returned,TRUSTED-PBA: sed unlock ok,TRUSTED-PBA: sed unlock failed' \
TESTAPP="$REVOKED" \
	python3 "$HERE/expect-serial.py" "$PBA"

echo "pba-matrix: PASS"
