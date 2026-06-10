#!/usr/bin/env bash
#
# Harness self-test for expect-serial.py — no QEMU needed. Re-proves on every
# run the property the negative suites depend on: FORBID stays live after the
# last REQUIRE has matched (a fail-open PBA that logs "sed unlock failed" and
# then chainloads anyway must FAIL, not false-PASS).
#
# EXPECT_STUB replaces run-qemu.sh with a scripted serial source, so the real
# harness code path (readline loop, grace window, alarm, process-group
# teardown) is exercised, only the guest is faked. Marker sets mirror the
# mock-opal negative scenarios.
#
# Scenarios:
#   fail-open-then-halt : requires, then forbidden boot markers, then silence
#                         (guest halts)        -> must FAIL on the FORBID
#   fail-open-then-exit : requires, then forbidden boot markers, then EOF
#                         (guest/QEMU exits)   -> must FAIL on the FORBID
#   clean-negative-halt : requires only, then silence -> must PASS after the
#                         grace window, bounded by the timer (never EOFs)
#   forbid-early        : forbidden marker before requires complete -> FAIL
#   missing-require     : EOF before all requires appeared          -> FAIL
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
EXPECT="$HERE/expect-serial.py"

REQ='TRUSTED-PBA: start,TRUSTED-PBA: sed unlock failed'
FOR='TEST-APP: ok,TRUSTED-PBA: chainload returned'
GRACE=2

neg='printf "TRUSTED-PBA: start\nTRUSTED-PBA: sed unlock failed\n"'
boot='printf "TEST-APP: ok\nTRUSTED-PBA: chainload returned\n"'

fail=0
check() { # check <name> <want-exit> <must-grep> <stub> [max-seconds]
	local name="$1" want="$2" must="$3" stub="$4" max="${5:-}" out rc=0 t0 t1
	t0=$(date +%s)
	out="$(env EXPECT_STUB="$stub" QEMU_TIMEOUT=15 EXPECT_GRACE="$GRACE" \
		REQUIRE="$REQ" FORBID="$FOR" python3 "$EXPECT" 2>&1)" || rc=$?
	t1=$(date +%s)
	if [ "$rc" -ne "$want" ]; then
		echo "[selftest] $name: FAIL (exit $rc, want $want)"; echo "$out"; fail=1; return
	fi
	if ! grep -qF "$must" <<<"$out"; then
		echo "[selftest] $name: FAIL (output lacks '$must')"; echo "$out"; fail=1; return
	fi
	if [ -n "$max" ] && [ $((t1 - t0)) -gt "$max" ]; then
		echo "[selftest] $name: FAIL (took $((t1 - t0))s, max ${max}s)"; fail=1; return
	fi
	echo "[selftest] $name: ok (exit $rc, $((t1 - t0))s)"
}

check fail-open-then-halt 1 "forbidden marker observed" "$neg; $boot; sleep 60"
check fail-open-then-exit 1 "forbidden marker observed" "$neg; $boot"
check clean-negative-halt 0 "PASS: all required markers" "$neg; sleep 60" 10
check forbid-early 1 "forbidden marker observed" \
	'printf "TRUSTED-PBA: start\n"'"; $boot; sleep 60"
check missing-require 1 "missing markers" 'printf "TRUSTED-PBA: start\n"'

if [ "$fail" -ne 0 ]; then
	echo "HARNESS SELF-TEST: FAIL"
	exit 1
fi
echo "HARNESS SELF-TEST: PASS"
