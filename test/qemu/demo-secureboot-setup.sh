#!/usr/bin/env bash
#
# demo:secureboot — setup stage (runs BEFORE the -tags pbatest,demosb build).
#
# Prepares the Secure Boot + trust-broker demo materials:
#   - platform key `P`  : signs the PBA; firmware validates the PBA via db (hop 1).
#   - broker/OS key `B` : signs the Alpine UKI; its cert is embedded in the PBA's
#                         trust store (the trust broker) so `pba` validation accepts
#                         the OS (hop 2), and is also enrolled in firmware db so the
#                         firmware permits the load (hop 3).
#
# This is exactly "sign the OS with a second key and add that key to the trust
# broker": B is the second key. It writes B's cert to the pbatest trust-store slot
# (internal/truststore/testdata/test-db.der) so the following build embeds it, and
# a small dbx (revoking a throwaway cert) to satisfy the fail-closed "dbx must carry
# revocations" check. It signs the Alpine UKI with B. The PBA itself is signed with
# P in the run stage (after it is built).
#
#   demo-secureboot-setup.sh
#
# Outputs into bin/demosb/ (keys + signed UKI + iso path). Needs openssl, sbsign,
# python3 + virt-firmware. Generates no committed artifacts (git-ignored).
set -euo pipefail

HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/bin/demosb"
DER="$ROOT/internal/truststore/testdata/test-db.der"
DBX="$ROOT/internal/truststore/testdata/test-dbx.bin"

mkdir -p "$OUT" "$(dirname "$DER")"

# Alpine ISO + UKI (cached); sets ISO, UKI.
eval "$(env DEMO_CACHE="${DEMO_CACHE:-$ROOT/.demo-cache}" "$HERE/alpine-uki.sh")"

# Platform key P (signs the PBA) + PK/KEK for enrollment.
echo "## Generating platform keys (PK/KEK/db=P) and broker CA (B) …"
for role in PK KEK P; do
	openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
		-subj "/CN=TrustedPBA Demo $role/" \
		-keyout "$OUT/$role.key" -out "$OUT/$role.crt" 2>/dev/null
done

# Broker/OS CA B — the "second key": signs the OS, trusted by the broker.
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
	-subj "/CN=TrustedPBA Demo OS Broker CA/" \
	-addext "extendedKeyUsage=codeSigning" \
	-keyout "$OUT/B.key" -out "$OUT/B.crt" 2>/dev/null

# Embed B into the trust broker (the only db CA the -tags pbatest build trusts).
openssl x509 -in "$OUT/B.crt" -outform DER -out "$DER"

# A dbx is required (Load fails closed on an empty revocation set). Revoke a
# throwaway leaf that is used nowhere, so nothing real is revoked.
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
	-subj "/CN=TrustedPBA Demo Unused Revoked/" \
	-keyout "$OUT/unused.key" -out "$OUT/unused.crt" 2>/dev/null
openssl x509 -in "$OUT/unused.crt" -outform DER -out "$OUT/unused.der"
python3 "$HERE/make-test-dbx.py" "$OUT/unused.der" "$DBX"

# Sign the Alpine UKI with B — the OS the trust broker will validate.
sbsign --key "$OUT/B.key" --cert "$OUT/B.crt" --output "$OUT/alpine-signed.efi" "$UKI"

# Hand the ISO path to the run stage.
printf '%s\n' "$ISO" > "$OUT/iso.path"

echo "## Setup done: broker CA -> $DER ; signed OS -> $OUT/alpine-signed.efi"
