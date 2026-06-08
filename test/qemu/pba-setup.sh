#!/usr/bin/env bash
#
# Prepare materials for the PBA verify-then-load matrix (pba-run.sh):
#
#   - generate a throwaway self-signed code-signing CA — the ONLY db certificate
#     the `-tags pbatest` build trusts — and write it (DER) to
#     internal/truststore/testdata/test-db.der so the next build embeds it;
#   - Authenticode-sign the chainload fixture with that CA into
#     bin/pbatest/testapp-signed.efi (the accept case).
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
# Needs: openssl, sbsign. Generates no committed artifacts (test-db.der is
# git-ignored and removed by pba-run.sh; bin/ is wiped by `task clean`).

set -euo pipefail

FIX="${1:?usage: pba-setup.sh <testapp.efi>}"
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"
DER="$ROOT/internal/truststore/testdata/test-db.der"
OUT="$ROOT/bin/pbatest"

mkdir -p "$OUT" "$(dirname "$DER")"

openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "$OUT/test.key" -out "$OUT/test.crt" \
	-subj "/CN=Trusted PBA Test DB CA" -days 3650 \
	-addext "extendedKeyUsage=codeSigning" 2>/dev/null

openssl x509 -in "$OUT/test.crt" -outform DER -out "$DER"

sbsign --key "$OUT/test.key" --cert "$OUT/test.crt" \
	--output "$OUT/testapp-signed.efi" "$FIX"

echo "pba-setup: embedded test db -> $DER; signed fixture -> $OUT/testapp-signed.efi"
