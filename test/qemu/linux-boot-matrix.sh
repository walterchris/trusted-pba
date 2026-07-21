#!/usr/bin/env bash
#
# Linux-boot matrix — the PBA boots a REAL Linux kernel to userspace after the
# SED unlock, in QEMU/OVMF.
#
# Where the other matrices chainload a gnu-efi fixture that just prints a
# marker, this one stages a real UKI (distro kernel + initramfs, built by
# build-linux-uki.sh) at the sedtest policy's target path (EFI/TEST/TESTAPP.EFI)
# and asserts that the kernel actually reaches userspace ("TEST-LINUX:
# userspace ok" from the initramfs init). The PBA build, policy, and unlock
# flow are exactly the mock-opal matrix's (`-tags sedtest` + MockOpalDxe); only
# the chainload target changes — so this proves the full product claim:
# unlock the SED, then boot an operating system.
#
# Scenarios
# =========
#   POS          : unlock -> chainload UKI -> kernel -> userspace marker.
#                  (No "chainload returned" REQUIRE: a kernel never returns
#                  to the firmware; the guest powers itself off.)
#   NEG auth-fail: StartSession rejected -> fail closed -> the OS must never
#                  boot (FORBID the userspace marker). The locked-drive-never-
#                  boots-an-OS claim with a real OS behind the gate; the full
#                  fail-closed fault matrix lives in mock-opal-matrix.sh (same
#                  PBA build).
#   POS-SB       : Secure Boot enforcing, db-signed driver+PBA+UKI -> unlock ->
#                  kernel to userspace under enforcement.
#
#   linux-boot-matrix.sh <pba-sedtest.efi> <linux-uki.efi>
#
# Requires MockOpalDxe.efi (test/edk2-mock-opal/build.sh) and the harness
# prerequisites (qemu, OVMF, mtools, sbsign, openssl, python3 + virt-firmware).
set -euo pipefail

PBA="${1:?usage: linux-boot-matrix.sh <pba-sedtest.efi> <linux-uki.efi>}"
UKI="${2:?usage: linux-boot-matrix.sh <pba-sedtest.efi> <linux-uki.efi>}"
HERE="$(dirname "$(readlink -f "$0")")"
DRIVER="$HERE/../edk2-mock-opal/MockOpalDxe.efi"
EXPECT="$HERE/expect-serial.py"
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"

[ -f "$DRIVER" ] || { echo "MockOpalDxe.efi not found; run test/edk2-mock-opal/build.sh" >&2; exit 2; }
[ -f "$PBA" ] || { echo "PBA not found: $PBA" >&2; exit 2; }
[ -f "$UKI" ] || { echo "UKI not found: $UKI (run test/qemu/build-linux-uki.sh)" >&2; exit 2; }

# Re-prove the harness FORBID/grace property before trusting any verdict.
# NOTE the property's precondition: FORBID stays live only for the grace window
# (EXPECT_GRACE, default 8s) after the last REQUIRE — it catches forbidden
# markers whose latency fits that window. A TCG kernel takes minutes to reach
# userspace, so the NEG below must NOT rely on the slow "TEST-LINUX: userspace
# ok" marker alone: it FORBIDs the PBA's own chainload-side markers
# ("TRUSTED-PBA: starting"/"ESP opened"), which a fail-open PBA emits within
# milliseconds of logging the unlock failure — comfortably inside the window.
# The userspace marker stays FORBIDden as defense-in-depth only.
echo "## harness self-test (expect-serial.py FORBID/grace semantics)"
"$HERE/harness-selftest.sh"

resolve_vfv

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DRVPATH='\EFI\MOCK\MOCKOPALDXE.EFI'
export QEMU_DISK_IF=virtio

# A distro kernel decompresses and boots on the TCG-emulated CPU — well beyond
# the 120s default budget.
export QEMU_TIMEOUT=420

python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.fd" "$DRVPATH"
python3 "$HERE/add-driver-entry.py" "$OVMF_VARS_TEMPLATE" "$WORK/vars.auth-fail.fd" \
	"$DRVPATH" "auth-fail"

HAPPY='MOCKOPAL: auth ok,MOCKOPAL: unlocked,MOCKOPAL: mbr-done set,TRUSTED-PBA: sed unlock ok,TEST-LINUX: userspace ok'
# NOBOOT: the fast chainload-side markers are the enforcing FORBIDs (see the
# grace-window note above); the userspace marker is defense-in-depth.
NOBOOT='TRUSTED-PBA: sed unlock ok,TRUSTED-PBA: starting,TRUSTED-PBA: ESP opened,TEST-LINUX: userspace ok'

fail=0

# --------------------------------------------------------------------------
# Scenario POS: unlock -> real kernel to userspace
# --------------------------------------------------------------------------
scenario "POS: unlock -> chainload UKI -> Linux userspace" \
	env OVMF_VARS="$WORK/vars.fd" DRIVER="$DRIVER" TESTAPP="$UKI" \
		REQUIRE="$HAPPY" \
		FORBID='TRUSTED-PBA: sed unlock failed' \
		python3 "$EXPECT" "$PBA"

# --------------------------------------------------------------------------
# Scenario NEG: auth-fail -> fail closed, the OS never boots
# --------------------------------------------------------------------------
scenario "NEG: auth-fail -> sed unlock failed, Linux never boots" \
	env OVMF_VARS="$WORK/vars.auth-fail.fd" DRIVER="$DRIVER" TESTAPP="$UKI" \
		REQUIRE='MOCKOPAL: fault auth-fail active,MOCKOPAL: auth fail,TRUSTED-PBA: sed unlock failed' \
		FORBID="$NOBOOT" \
		python3 "$EXPECT" "$PBA"

# --------------------------------------------------------------------------
# Scenario POS-SB: enforcing Secure Boot, db-signed driver + PBA + UKI
# --------------------------------------------------------------------------
echo; echo "## secure-boot: generating + enrolling throwaway test keys"
GUID="$(uuidgen)"
gen_test_keys "$WORK" "TrustedPBA LinuxBoot Test"
enroll_keys "$OVMF_VARS_TEMPLATE" "$WORK/vars.sb-enrolled.fd" "$GUID" "$WORK"
python3 "$HERE/add-driver-entry.py" "$WORK/vars.sb-enrolled.fd" "$WORK/vars.sb.fd" "$DRVPATH"
for img in driver:"$DRIVER" pba:"$PBA" uki:"$UKI"; do
	sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" \
		--output "$WORK/${img%%:*}.signed.efi" "${img#*:}"
done

scenario "POS-SB: SB enforcing, db-signed driver+PBA+UKI -> unlock -> Linux userspace" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.sb.fd" \
		DRIVER="$WORK/driver.signed.efi" TESTAPP="$WORK/uki.signed.efi" \
		REQUIRE="$HAPPY,TRUSTED-PBA: secure-boot: enforcing" \
		FORBID='TRUSTED-PBA: sed unlock failed' \
		python3 "$EXPECT" "$WORK/pba.signed.efi"

echo
if [ "$fail" -eq 0 ]; then
	echo "LINUX BOOT MATRIX: PASS"
else
	echo "LINUX BOOT MATRIX: FAIL"
	exit 1
fi
