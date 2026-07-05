# Security review — `pba-override` Secure Boot trust broker (#82, ADR-0012/0013)

- **Date:** 2026-07-05
- **Change:** branch `feat/trust-broker-override` (SHIM-style `EFI_SECURITY2_ARCH_PROTOCOL`
  override so the PBA can boot an image it verified but firmware `db` does not trust —
  gated behind `-tags trustbroker` + explicit `pba-override` policy opt-in).
- **Reviewer:** independent security-review-agent (adversarial, did not implement the change).
- **Method:** two rounds against the threat model + non-negotiable security rules; read the
  asm stub, the Go install/verify path, the policy/gating, both ADRs, the threat-model delta,
  and the go-boot `LocateProtocol`/`LoadImageBuffer` at the pinned `v1.6.2-tpba.5`; ran the
  host `internal/tbstub` test and independently mutation-tested the stub.

## Round 1 (commit `4a36163`): BLOCK
- **F1 (blocking):** override armed unconditionally — ADR-0012/0013 require *enforcing* Secure
  Boot; the `enforcing` state was not threaded past `run()`.
- **F2 (blocking):** the stub's `mismatch→chain` and `one-shot-disarm` branches had no test
  (TAMPER fails at verify, before the stub runs).
- F3 (high): no host-testable path for the state machine. F4 (medium, non-blocking): no
  structural guard against `pba-override` on a measured-boot target. F6 (low): score R-014.
- Confirmed **sound**: single-buffer pointer+size authorization, one-shot disarm, MS-ABI
  tail-call (args + shadow space preserved, no Go-runtime entry), `-tags trustbroker` gating
  out of default/release builds, fail-closed without the tag, `unsafe` slot offset, restore-on-defer.

## Round 2 (commit `30cf210`): APPROVE — no unresolved merge-blockers
- **F1 resolved:** `chainload(entry, enforcing)` → `verifyAndLoadOverride(target, enforcing)`
  refuses (`pba-override requires enforcing Secure Boot`) before ESP open / LocateProtocol /
  arm; QEMU `SB-OFF` scenario confirms; matrix 4/4.
- **F2/F3 resolved:** stub + arm-state extracted to `internal/tbstub` (host + tamago);
  `stub_test.go` drives the real asm stub via an MS-ABI trampoline covering all five branches;
  reviewer re-ran it (PASS) and mutation-proved it (dropping the disarm / inverting a branch
  fails the test).
- **F4 addressed:** loud `WARNING: pba-override diverges PCR 7 …` before arming.

## Outstanding (non-blocking, tracked)
- **F6:** R-014 scored in `risk-assessment.md` (done in this change).
- **CI:** `internal/tbstub` test needs Go ≥1.26.4 — CI uses `go-version-file: go.mod` (1.26.4), so it executes.

## Disposition
ADR-0013's acceptance precondition (independent review, no unresolved blockers) is met from the
reviewer's side. Merge to `main` is the §5.3 human gate (Security/Release Owner). Capability is
inert in shipped builds until a policy opts in on a `-tags trustbroker` build.
