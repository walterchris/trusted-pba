#!/usr/bin/env bash
#
# ADR-0012 task 5 (measured boot): boot the pba-override path with a virtual TPM
# (swtpm) attached, proving the Security2 override works with measured boot ACTIVE
# — i.e. the override does not break booting on a TPM platform. OVMF measures the
# boot into the vTPM as usual.
#
#   override-vtpm.sh <override-pba.efi> <testCA-signed-fixture.efi>
#
# NOTE on PCR read-back: we do NOT read PCR digits here. QEMU's tpm-emulator hands
# the TPM data channel to swtpm via CMD_SET_DATAFD (an fd over the UNIX ctrl socket),
# which precludes a concurrent swtpm --server channel for tpm2-tools; and PCRs are
# volatile (lost when swtpm exits with QEMU). Empirical PCR-7 digits therefore need
# a guest-side EFI_TCG2_PROTOCOL event-log dumper (tracked as a follow-up). The
# PCR-7 DIVERGENCE itself is characterized from the TCG/SHIM mechanism in ADR-0012.
#
# Throwaway TEST keys, never committed (baseline §13).
set -euo pipefail

OVERRIDE_PBA="${1:?usage: override-vtpm.sh <override-pba.efi> <testCA-signed-fixture.efi>}"
FIXTURE="${2:?}"
HERE="$(dirname "$(readlink -f "$0")")"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/ovmf-pair.sh"
. "$HERE/sb-lib.sh"
EXPECT="$HERE/expect-serial.py"

resolve_vfv
WORK="$(mktemp -d)"                 # short path: swtpm/QEMU UNIX socket (sockaddr_un ~108)
trap 'rm -rf "$WORK"; [ -n "${SWTPM_PID:-}" ] && kill "$SWTPM_PID" 2>/dev/null; pkill -f "swtpm socket.*$WORK" 2>/dev/null || true' EXIT
GUID="$(uuidgen)"
mkdir -p "$WORK/state"

gen_test_keys "$WORK" "TrustedPBA Test"
enroll_keys "$OVMF_VARS_TEMPLATE" "$WORK/vars.fd" "$GUID" "$WORK"
sbsign --key "$WORK/db.key" --cert "$WORK/db.crt" --output "$WORK/pba.efi" "$OVERRIDE_PBA"

# swtpm with ONLY a UNIX ctrl socket (QEMU establishes the data channel via
# CMD_SET_DATAFD over it). setsid so expect-serial's process-group kill of QEMU
# does not also stop swtpm.
setsid swtpm socket --tpm2 --tpmstate dir="$WORK/state" \
	--ctrl type=unixio,path="$WORK/tpm.sock" \
	--flags startup-clear </dev/null >"$WORK/swtpm.log" 2>&1 &
SWTPM_PID=$!
sleep 1

fail=0
scenario "pba-override boots with a vTPM present (measured boot active)" \
	env OVMF_CODE="$OVMF_SECBOOT_CODE" OVMF_VARS="$WORK/vars.fd" TESTAPP="$FIXTURE" \
		QEMU_TPM_SOCK="$WORK/tpm.sock" \
		REQUIRE='TRUSTED-PBA: override armed,TEST-APP: ok' \
		FORBID='TRUSTED-PBA: chainload failed' \
		python3 "$EXPECT" "$WORK/pba.efi"

echo
if [ "$fail" -eq 0 ]; then
	echo "OVERRIDE vTPM: PASS — override works under measured boot (PCR-7 divergence: see ADR-0012)"
else
	echo "OVERRIDE vTPM: FAIL"
	exit 1
fi
