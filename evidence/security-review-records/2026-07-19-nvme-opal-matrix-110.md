# Security review — QEMU NVMe-passthru Opal matrix + mock fidelity fix (#110)

- **Date:** 2026-07-19
- **Change:** branch `feat/nvme-opal-matrix-110` (issue #110). Test tooling only —
  **no product code changed** (verified by the reviewer against the full diff):
  1. `test/edk2-mock-opal/MockOpalDxe.c` (+`.inf`, README) — the mock SED now also
     PRODUCES `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` on the same handle: Identify
     Controller (scripted 20-byte serial, the sedutil-pbkdf2 salt) and Security
     Send/Receive (0x81/0x82) dispatch into the shared scripted TPer with the ComID
     in native order (no swap — the product NVMe carrier's contract), while the
     Storage Security surface keeps its swap. New `auth-lockout` fault
     (`AUTHORITY_LOCKED_OUT` 0x12) and `startsession N` attempt markers. A second
     accepted Admin1 credential: the PBKDF2-derived key at 75000 iterations
     (hash-provisioned drive shape), drift-guarded by `TestMockDerivedKeySync`.
  2. **Mock fidelity fix (R-010):** both mocks (`internal/opal/mocktper.go` + the C
     driver) returned 0x12 for a wrong credential; real drives return
     `NOT_AUTHORIZED` (0x01 — observed on lab hardware, and the status the #112
     auto mode advances on). Both mocks + the shared spec now use 0x01; 0x12 is an
     explicit fault shape.
  3. `internal/policy` — tag-gated `sednvmetest` embedded test policy (policy-pin,
     `derive: sedutil-pbkdf2`, `iterations: "auto"`).
  4. `test/qemu/nvme-opal-matrix.sh` + Taskfile `nvme-opal-matrix` + CI
     `qemu-nvme-matrix` — POS (auto advances 500000→75000 → unlock → MBRDone →
     chainload over NVMe), NEG auth-lockout (stop after attempt 1), NEG no-driver
     (zero pass-thru handles → hard fail). All PASS locally; `mock-opal-matrix`
     (6/6) and `keyfile-matrix` (2/2) regression-clean.
- **Reviewers:** two independent reviews — **go-reviewer** (idiomatic-Go; APPROVE,
  no changes; independently recomputed the PBKDF2 vector and cross-checked the C
  constants byte-for-byte) and the adversarial **security-review-agent** (APPROVE);
  neither implemented the change.
- **Method (security reviewer):** verified the no-product-code claim file-by-file
  (`MockTPer` has zero non-test references, so the linker dead-strips it from the
  product binary; the Taskfile default `build` carries no test tags); attacked the
  mock-fidelity change against every consumer of the wrong-credential shape;
  attacked the dual-credential mock for its ability to mask a raw-path PBA bug;
  verified the `startsession 2` FORBID liveness in the C control flow; checked
  release-gate containment of the test policy and `hwdebug`; recomputed the
  derived-key vector independently.

## Verdict: APPROVE

- **Mock-fidelity change weakens no negative test** — every consumer checked:
  the SSC matrices' auth scenarios are raw single-attempt and status-agnostic; every
  test pinning the 0x12-stop behavior uses synthetic transports/fakes, which still
  exercise 0x12 directly. The change converts a recorded R-010 residual (mock
  conflating wrong-PIN with lockout) into tested, hardware-faithful behavior.
- **Dual-credential mock cannot mask a derive bypass** — a raw-PIN send over NVMe
  would authenticate on attempt 1 and FAIL the POS on three missing REQUIREs
  (`auth fail`, `startsession 2`, the hwdbg 75000 marker); a derive-parameter bug
  fails attempt 2. The 32-byte constant pins passphrase, exact 20-byte salt,
  iteration count, PRF, and key length simultaneously.
- **FORBID `startsession 2` is live** — the attempt marker is emitted first in
  `HandleStartSession`, before validation and the fault check, so a second attempt
  necessarily prints it; the harness FORBID/grace property is re-proven by
  `harness-selftest.sh` each run.
- **Test policy / hwdebug contained** — `policy_sednvme.json` is rejected by
  `CheckReleaseReady` on three independent grounds; the embed is tag-gated with a
  compile-error (duplicate symbol) on tag misuse; `hwdebug` leaks no key material
  (the candidate iteration list is public source).
- **Secrets clean** — the derived-key constant is a public test vector (PBKDF2 of
  the canonical committed test passphrase over a fictitious mock serial).

## Findings (non-blocking)

- **F-1 (Low, pre-existing, track against #90):** the release policy gate validates
  the *file* `internal/policy/policy.json`, not the build tags of the released
  artifact — a release built with a test tag (`sednvmetest`, `sedtest`, `hwdebug`,
  …) would not be caught by the gate alone. Shared with all existing test tags; the
  release pipeline (still a placeholder) must assert the artifact's tag set.
- **F-2 (Info):** the C driver's `auth-fail` fault now returns 0x01, so under an
  auto-mode policy that fault burns two attempts; no current matrix asserts attempt
  count under `auth-fail`, so nothing regresses.

## Threat-model / risk-assessment impact

- **R-010** improved (mock/real wrong-credential divergence closed; the
  sedutil-pbkdf2-over-NVMe path — previously provable only on hardware — now has
  deterministic CI coverage of the real carrier code); residual stays **Medium**
  pending the Phase-8 hardware rerun.
- **R-002** gains end-to-end negative evidence (try-limit stop on lockout;
  zero-handles hard fail — both FORBIDding boot markers).
- No new trust boundary, no product behavior change ⇒ **no ADR** (within ADR-0005's
  test strategy and the Accepted ADR-0011 §3).
