#!/usr/bin/env bash
#
# NVMe-passthru Opal matrix (#110) — the sedutil-pbkdf2-over-NVMe unlock,
# end-to-end in QEMU/OVMF.
#
# The `-tags sednvmetest,hwdebug` PBA (sed_unlock "required", policy-pin
# "correct horse", derive sedutil-pbkdf2, iterations "auto", on_error "halt")
# selects the NVMe-passthru carrier (the only transport exposing the drive
# serial the PBKDF2 salt needs) and drives MockOpalDxe's
# EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL surface: Identify Controller for the salt,
# Security Send/Receive for the Opal session — the same TPer the Storage
# Security matrix exercises, over the other carrier.
#
# The mock drive is provisioned at 75000 PBKDF2 iterations (the upstream-sedutil
# default, e.g. the lab's 1.20.0), so the POS scenario proves the FULL #112 auto
# path: candidate 500000 derives + is rejected NOT_AUTHORIZED, the loop advances,
# candidate 75000 authenticates — the exact real-world hash-provisioned shape
# that blocked the A4b hardware test.
#
# Scenarios
# =========
#   POS auto-unlock : no fault -> Identify (salt) + attempt 1 rejected +
#                     attempt 2 auth ok + unlock + MBRDone + chainload.
#                     The hwdbg "authenticated at 75000 iterations" marker pins
#                     the winning candidate.
#
#   NEG auth-lockout: every StartSession -> AUTHORITY_LOCKED_OUT (0x12).
#                     The auto loop must STOP after attempt 1 (try-limit
#                     safety): FORBID "startsession 2" plus the boot markers.
#
#   NEG no-driver   : no MockOpalDxe -> zero NVMe pass-thru handles ->
#                     NewAllNVMe hard-fails -> fail closed, no boot. A true
#                     zero-instance scenario: QEMU exposes no pass-thru without
#                     a real -device nvme, and the ESP is virtio-blk.
#
#   nvme-opal-matrix.sh <pba-sednvmetest.efi> <testapp.efi>
#
# Requires MockOpalDxe.efi (test/edk2-mock-opal/build.sh) and the harness
# prerequisites (qemu, OVMF, mtools, python3 + virt-firmware).
set -euo pipefail

PBA="${1:?usage: nvme-opal-matrix.sh <pba-sednvmetest.efi> <testapp.efi>}"
TESTAPP="${2:?usage: nvme-opal-matrix.sh <pba-sednvmetest.efi> <testapp.efi>}"
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

# PBKDF2-HMAC-SHA512 at 500000 (+75000 for auto) iterations runs on the
# TCG-emulated CPU — give the derive stages generous headroom over the 120s
# default.
export QEMU_TIMEOUT=300

# Per-scenario VARS stores: Driver0000 entry + (optionally) the auth-lockout
# fault variable, written offline into copies of the stock template.
python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.fd" "$DRVPATH"
python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.auth-lockout.fd" \
	"$DRVPATH" "auth-lockout"

# The POS REQUIREs pin every stage that distinguishes this path from the
# Storage-Security matrix: the pass-thru install, the Identify salt read, the
# rejected first candidate ("auth fail" + a second attempt), the winning 75000
# marker (hwdbg; matched WITHOUT its "[hwdbg]" prefix — expect-serial compiles
# markers as regexes, and the brackets would be a character class), and the
# boot. Every negative FORBIDs the boot markers (fail closed: locked drive
# never boots).
HAPPY='MOCKOPAL: nvme passthru installed,MOCKOPAL: nvme identify,MOCKOPAL: auth fail,MOCKOPAL: startsession 2,MOCKOPAL: auth ok,MOCKOPAL: unlocked,MOCKOPAL: mbr-done set,sedutil-pbkdf2 auto: authenticated at 75000 iterations,TRUSTED-PBA: sed unlock ok,TEST-APP: ok,TRUSTED-PBA: chainload returned'
NOBOOT='TRUSTED-PBA: sed unlock ok,TEST-APP: ok,TRUSTED-PBA: chainload returned'

fail=0

# --------------------------------------------------------------------------
# Scenario POS: auto advances 500000 -> 75000 over the NVMe carrier -> boot
# --------------------------------------------------------------------------
scenario "POS: sedutil-pbkdf2 auto over NVMe -> reject@500000, auth@75000, unlock + chainload" \
	env OVMF_VARS="$WORK/vars.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" \
		REQUIRE="$HAPPY" \
		FORBID='TRUSTED-PBA: sed unlock failed' \
		python3 "$EXPECT" "$PBA"

# --------------------------------------------------------------------------
# Scenario NEG: AUTHORITY_LOCKED_OUT stops the auto loop after one attempt
# --------------------------------------------------------------------------
scenario "NEG: auth-lockout -> auto stops after attempt 1, fail closed" \
	env OVMF_VARS="$WORK/vars.auth-lockout.fd" DRIVER="$DRIVER" TESTAPP="$TESTAPP" \
		REQUIRE='MOCKOPAL: fault auth-lockout active,MOCKOPAL: startsession 1,MOCKOPAL: auth lockout,TRUSTED-PBA: sed unlock failed' \
		FORBID="$NOBOOT,MOCKOPAL: startsession 2" \
		python3 "$EXPECT" "$PBA"

# --------------------------------------------------------------------------
# Scenario NEG: no driver -> zero NVMe pass-thru handles -> hard fail, no boot
# --------------------------------------------------------------------------
scenario "NEG: no driver -> no NVMe pass-thru handle -> fail closed" \
	env TESTAPP="$TESTAPP" \
		REQUIRE='TRUSTED-PBA: sed unlock failed' \
		FORBID="$NOBOOT,MOCKOPAL: dispatched" \
		python3 "$EXPECT" "$PBA"

echo
if [ "$fail" -eq 0 ]; then
	echo "NVME OPAL MATRIX: PASS"
else
	echo "NVME OPAL MATRIX: FAIL"
	exit 1
fi
