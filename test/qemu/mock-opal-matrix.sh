#!/usr/bin/env bash
#
# Mock-Opal integration matrix for Trusted PBA (Phase 6, #22) — the MVP's
# primary virtual integration test: the `-tags sedtest` PBA (sed_unlock
# "required", shared-spec Admin1 PIN, on_error "halt") drives its REAL UEFI
# Storage Security transport against the MockOpalDxe DXE driver in QEMU/OVMF,
# end to end: Discovery0 -> StartSession -> range unlock -> MBRDone ->
# chainload.
#
# Scenarios:
#   unlock-chainload : driver dispatched, no fault   -> full unlock + chainload
#   auth-fail        : StartSession always rejected  -> fail closed, no boot
#   fail-mbrdone     : MBRControl Set refused        -> fail closed, no boot
#   fail-after-unlock: IF-SEND dies after the range  -> partial unlock, no boot
#                      unlock (negative asserted via FORBID on chainload
#                      markers, NOT mock-marker absence: the documented mock
#                      behavior keeps a stale staged response readable)
#   no-driver        : required policy, NO driver    -> no transport, no boot
#   secure-boot      : SB enforcing, db-signed driver+PBA+fixture -> full
#                      unlock + chainload (BDS silently skips an unsigned
#                      Driver#### image, so the MOCKOPAL REQUIREs are the
#                      proof the driver actually ran under enforcement)
#
# Fault injection: the MockOpalFault variable is written offline into the
# per-scenario VARS copy by add-driver-entry.py (4th argument).
#
# Every run attaches the ESP as virtio-blk (QEMU_DISK_IF): QEMU's IDE/SATA
# disks advertise IDENTIFY word 48, so OVMF's AtaBus would install a second,
# real Storage Security instance on the QEMU disk and the PBA transport (which
# takes the first instance; selection is Phase 8) could talk to the wrong
# device. virtio-blk carries no Storage Security, keeping MockOpalDxe the sole
# instance — and making no-driver a true zero-instance scenario.
#
#   mock-opal-matrix.sh <pba-sedtest.efi> <testapp.efi>
#
# Requires MockOpalDxe.efi (test/edk2-mock-opal/build.sh) and the harness
# prerequisites (qemu, OVMF, mtools, sbsign, openssl, python3 + virt-firmware).
set -euo pipefail

PBA="${1:?usage: mock-opal-matrix.sh <pba-sedtest.efi> <testapp.efi>}"
TESTAPP="${2:?usage: mock-opal-matrix.sh <pba-sedtest.efi> <testapp.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
DRIVER="$HERE/../edk2-mock-opal/MockOpalDxe.efi"
EXPECT="$HERE/expect-serial.py"
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"

[ -f "$DRIVER" ] || { echo "MockOpalDxe.efi not found; run test/edk2-mock-opal/build.sh" >&2; exit 2; }

# Re-prove the harness property every negative scenario depends on (FORBID
# stays live after the last REQUIRE — a fail-open PBA can never false-PASS)
# before trusting any verdict below. Cheap: no QEMU involved.
echo "## harness self-test (expect-serial.py FORBID/grace semantics)"
"$HERE/harness-selftest.sh"

resolve_vfv

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DRVPATH='\EFI\MOCK\MOCKOPALDXE.EFI'
export QEMU_DISK_IF=virtio

# Per-scenario VARS stores: Driver0000 entry + (optionally) the MockOpalFault
# fault variable, all written offline into copies of the stock template.
python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.fd" "$DRVPATH"
for fault in auth-fail fail-mbrdone fail-after-unlock; do
	python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.$fault.fd" \
		"$DRVPATH" "$fault"
done

# Common marker sets. The full happy path REQUIREs every stage of the scripted
# unlock plus the chainloaded fixture; every negative FORBIDs both "sed unlock
# ok" and the chainload/test-app markers (fail closed: locked drive never boots).
HAPPY='MOCKOPAL: dispatched,MOCKOPAL: auth ok,MOCKOPAL: unlocked,MOCKOPAL: mbr-done set,TRUSTED-PBA: sed unlock ok,TEST-APP: ok,TRUSTED-PBA: chainload returned'
NOBOOT='TRUSTED-PBA: sed unlock ok,TEST-APP: ok,TRUSTED-PBA: chainload returned'

fail=0

scenario "unlock-chainload: no fault -> full unlock + MBRDone + chainload" \
	env OVMF_VARS="$WORK/vars.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" \
		REQUIRE="$HAPPY" \
		FORBID='TRUSTED-PBA: sed unlock failed' \
		python3 "$EXPECT" "$PBA"

scenario "auth-fail: StartSession rejected -> fail closed, device stays locked" \
	env OVMF_VARS="$WORK/vars.auth-fail.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" \
		REQUIRE='MOCKOPAL: fault auth-fail active,MOCKOPAL: auth fail,TRUSTED-PBA: sed unlock failed' \
		FORBID="$NOBOOT,MOCKOPAL: unlocked" \
		python3 "$EXPECT" "$PBA"

scenario "fail-mbrdone: MBRControl refused -> fail closed, shadow MBR stays" \
	env OVMF_VARS="$WORK/vars.fail-mbrdone.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" \
		REQUIRE='MOCKOPAL: fault fail-mbrdone active,MOCKOPAL: mbr-refused fault,TRUSTED-PBA: sed unlock failed' \
		FORBID="$NOBOOT,MOCKOPAL: mbr-done set" \
		python3 "$EXPECT" "$PBA"

scenario "fail-after-unlock: transport dies after range unlock -> partial unlock never boots" \
	env OVMF_VARS="$WORK/vars.fail-after-unlock.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" \
		REQUIRE='MOCKOPAL: fault fail-after-unlock active,MOCKOPAL: unlocked,TRUSTED-PBA: sed unlock failed' \
		FORBID="$NOBOOT" \
		python3 "$EXPECT" "$PBA"

scenario "no-driver: required policy, no Storage Security device -> fail closed" \
	env TESTAPP="$TESTAPP" \
		REQUIRE='TRUSTED-PBA: sed unlock failed' \
		FORBID="$NOBOOT,MOCKOPAL: dispatched" \
		python3 "$EXPECT" "$PBA"

# Secure Boot scenario: throwaway PK/KEK/db (same pattern as
# secureboot-matrix.sh; keys never touch the repo, baseline §13), enrolled
# enforcing, driver + PBA + fixture all db-signed. Same REQUIREs as the happy
# path — under enforcement an unsigned Driver#### is skipped with no error
# anywhere, so only the MOCKOPAL markers prove the driver was dispatched.
echo; echo "## secure-boot: generating + enrolling throwaway test keys"
GUID="$(uuidgen)"
gen_test_keys "$WORK" "TrustedPBA MockOpal Test"
enroll_keys "$OVMF_VARS_TEMPLATE" "$WORK/vars.sb-enrolled.fd" "$GUID" "$WORK"
python3 "$HERE/add-driver-entry.py" "$WORK/vars.sb-enrolled.fd" "$WORK/vars.sb.fd" "$DRVPATH"
for img in driver:"$DRIVER" pba:"$PBA" testapp:"$TESTAPP"; do
	sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" \
		--output "$WORK/${img%%:*}.signed.efi" "${img#*:}"
done

scenario "secure-boot: SB enforcing, db-signed driver+PBA+fixture -> full unlock + chainload" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.sb.fd" \
		DRIVER="$WORK/driver.signed.efi" TESTAPP="$WORK/testapp.signed.efi" \
		REQUIRE="$HAPPY,TRUSTED-PBA: secure-boot: enforcing" \
		FORBID='TRUSTED-PBA: sed unlock failed' \
		python3 "$EXPECT" "$WORK/pba.signed.efi"

echo
if [ "$fail" -eq 0 ]; then
	echo "MOCK OPAL MATRIX: PASS"
else
	echo "MOCK OPAL MATRIX: FAIL"
	exit 1
fi
