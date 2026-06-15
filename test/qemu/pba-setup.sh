#!/usr/bin/env bash
#
# Prepare materials for the PBA verify-then-load matrix (pba-run.sh):
#
#   - generate a throwaway self-signed code-signing CA `R` — the ONLY db
#     certificate the `-tags pbatest` build trusts — and write it (DER) to
#     internal/truststore/testdata/test-db.der so the next build embeds it;
#   - Authenticode-sign the chainload fixture with `R` into
#     bin/pbatest/testapp-signed.efi (the accept case);
#   - issue a code-signing leaf `L` from `R`, Authenticode-sign the fixture with
#     `L` into bin/pbatest/testapp-revoked.efi (chains to db via R, but L is
#     revoked), and craft internal/truststore/testdata/test-dbx.bin — a dbx update
#     revoking L by certificate — so the next build embeds it (the revoked case).
#
# The unsigned fixture (bin/testapp.efi) drives the fail-closed reject case.
#
# The CA's NotBefore is "now"; the pbatest build that follows takes several
# seconds, so the guest RTC at boot is always at/after it (same host clock). The
# build-time floor (internal/boottime) is earlier still, so boottime.Now() yields
# the RTC reading, which satisfies the cert validity window.
#
#   pba-setup.sh <testapp.efi>
#
# Needs: openssl, sbsign. Generates no committed artifacts (test-db.der and
# test-dbx.bin are git-ignored and removed by pba-run.sh; bin/ is wiped by
# `task clean`).

set -euo pipefail

FIX="${1:?usage: pba-setup.sh <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
DER="$ROOT/internal/truststore/testdata/test-db.der"
DBX="$ROOT/internal/truststore/testdata/test-dbx.bin"
OUT="$ROOT/bin/pbatest"

mkdir -p "$OUT" "$(dirname "$DER")"

# Root code-signing CA `R` — the only trusted db cert in the pbatest build.
openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "$OUT/test.key" -out "$OUT/test.crt" \
	-subj "/CN=Trusted PBA Test DB CA" -days 3650 \
	-addext "extendedKeyUsage=codeSigning" 2>/dev/null

openssl x509 -in "$OUT/test.crt" -outform DER -out "$DER"

# Accept case: fixture signed directly by R (chains to db, not revoked).
sbsign --key "$OUT/test.key" --cert "$OUT/test.crt" \
	--output "$OUT/testapp-signed.efi" "$FIX"

# Leaf `L` issued by R, code-signing EKU. The fixture signed by L still chains to
# db (via R) and carries a valid code-signing EKU, so only dbx — not "untrusted"
# or "no signature" — can reject it.
openssl req -newkey rsa:2048 -nodes \
	-keyout "$OUT/leaf.key" -out "$OUT/leaf.csr" \
	-subj "/CN=Trusted PBA Test Revoked Leaf" 2>/dev/null

openssl x509 -req -in "$OUT/leaf.csr" \
	-CA "$OUT/test.crt" -CAkey "$OUT/test.key" -CAcreateserial \
	-out "$OUT/leaf.crt" -days 3650 \
	-extfile <(printf 'extendedKeyUsage=codeSigning\n') 2>/dev/null

# Revoked case: fixture signed by L. sbsign embeds the full chain (leaf + R), so
# imageverify can build the chain to db; the embedded dbx then revokes L.
sbsign --key "$OUT/leaf.key" --cert "$OUT/leaf.crt" \
	--addcert "$OUT/test.crt" \
	--output "$OUT/testapp-revoked.efi" "$FIX"

# dbx revoking L by certificate. imageverify.revoked() compares raw DER via
# c.Equal, so feed make-test-dbx.py L's exact DER.
openssl x509 -in "$OUT/leaf.crt" -outform DER -out "$OUT/leaf.der"
python3 "$HERE/make-test-dbx.py" "$OUT/leaf.der" "$DBX"

echo "pba-setup: embedded test db -> $DER; test dbx -> $DBX"
echo "pba-setup: signed fixture -> $OUT/testapp-signed.efi; revoked fixture -> $OUT/testapp-revoked.efi"
