#!/usr/bin/env bash
#
# Keyfile credential-source matrix (ADR-0011 A3, #100).
#
# Tests the file-backed unlock seed path end-to-end in QEMU/OVMF with
# MockOpalDxe as the virtual SED. The `-tags keyfiletest` PBA (sed_unlock
# "required", credential source "keyfile", path EFI/KEY/sed.key, on_error
# "halt") reads its unlock seed from a file staged on the ESP and drives the
# full unlock -> MBRDone -> chainload flow. No human interaction — the key is
# a file, not a prompt, so this runs headlessly like the mock-opal matrix
# (expect-serial.py, not the QMP send-key driver the console source needs).
#
# The key is staged into the ESP via run-qemu.sh's KEYFILE env, which mcopies
# it to ::/EFI/KEY/sed.key.
#
# Scenarios
# =========
#   POS: keyfile contains "correct horse" (the MockOpalDxe PIN) ->
#        REQUIRE MOCKOPAL auth ok + sed unlock ok + TEST-APP: ok;
#        FORBID sed unlock failed. Proves the keyfile delivers the credential.
#
#   NEG: keyfile contains wrong bytes ->
#        REQUIRE TRUSTED-PBA: sed unlock failed;
#        FORBID MOCKOPAL: auth ok + sed unlock ok + TEST-APP: ok.
#        Proves fail-closed on a wrong-content keyfile (the FORBIDs stay live
#        for the full grace window after the last REQUIRE, so a PBA that logs
#        the failure then boots anyway still FAILs — mutation-proof).
#
#   keyfile-matrix.sh <pba-keyfiletest.efi> <testapp.efi>
#
# Requires MockOpalDxe.efi (test/edk2-mock-opal/build.sh) and the harness
# prerequisites (qemu, OVMF, mtools, python3 + virt-firmware).
set -euo pipefail

PBA="${1:?usage: keyfile-matrix.sh <pba-keyfiletest.efi> <testapp.efi>}"
TESTAPP="${2:?usage: keyfile-matrix.sh <pba-keyfiletest.efi> <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
DRIVER="$HERE/../edk2-mock-opal/MockOpalDxe.efi"
EXPECT="$HERE/expect-serial.py"
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"

[ -f "$DRIVER" ] || { echo "MockOpalDxe.efi not found; run test/edk2-mock-opal/build.sh" >&2; exit 2; }
[ -f "$PBA" ] || { echo "PBA not found: $PBA" >&2; exit 2; }
[ -f "$TESTAPP" ] || { echo "TESTAPP not found: $TESTAPP" >&2; exit 2; }

# Re-prove the FORBID/grace property every negative scenario relies on (a
# fail-open PBA can never false-PASS) before trusting any verdict. Cheap; no QEMU.
echo "## harness self-test (expect-serial.py FORBID/grace semantics)"
"$HERE/harness-selftest.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DRVPATH='\EFI\MOCK\MOCKOPALDXE.EFI'
export QEMU_DISK_IF=virtio

# Driver0000 entry so OVMF dispatches MockOpalDxe as the (sole) Storage Security
# device before the PBA runs.
python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.fd" "$DRVPATH"

# Stage the correct- and wrong-content keyfiles. "correct horse" is the shared-spec
# Admin1 test PIN (test/fixtures/opal / the MockOpalDxe secret).
printf '%s' 'correct horse' > "$WORK/key.correct"
printf '%s' 'wrong key'     > "$WORK/key.wrong"

HAPPY='MOCKOPAL: auth ok,TRUSTED-PBA: sed unlock ok,TEST-APP: ok,TRUSTED-PBA: chainload returned'
NOBOOT='TRUSTED-PBA: sed unlock ok,TEST-APP: ok,TRUSTED-PBA: chainload returned'

fail=0

# --------------------------------------------------------------------------
# Scenario POS: correct keyfile -> full unlock + chainload
# --------------------------------------------------------------------------
scenario "POS: correct keyfile -> auth ok + sed unlock ok + chainload" \
	env OVMF_VARS="$WORK/vars.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" \
		KEYFILE="$WORK/key.correct" \
		REQUIRE="$HAPPY" \
		FORBID='TRUSTED-PBA: sed unlock failed' \
		python3 "$EXPECT" "$PBA"

# --------------------------------------------------------------------------
# Scenario NEG: wrong-content keyfile -> fail closed, never boots
# --------------------------------------------------------------------------
scenario "NEG: wrong keyfile -> sed unlock failed (fail closed)" \
	env OVMF_VARS="$WORK/vars.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" \
		KEYFILE="$WORK/key.wrong" \
		REQUIRE='TRUSTED-PBA: sed unlock failed' \
		FORBID="$NOBOOT,MOCKOPAL: auth ok" \
		python3 "$EXPECT" "$PBA"

echo
if [ "$fail" -eq 0 ]; then
	echo "KEYFILE MATRIX: PASS"
else
	echo "KEYFILE MATRIX: FAIL"
	exit 1
fi
