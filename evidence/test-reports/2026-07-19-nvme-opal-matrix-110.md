# Test evidence — QEMU NVMe-passthru Opal matrix (`nvme-opal-matrix`, #110)

- **Date:** 2026-07-19 (local runs; CI job added in the same change).
- **Issue:** #110. **Branch:** `feat/nvme-opal-matrix-110`.
- **Scope:** test tooling + one mock-fidelity fix — **no product code change**.
- **What it proves:** the `sedutil-pbkdf2`-over-NVMe unlock — previously provable
  only on hardware (A4b, #104) — now has a deterministic virtual test path that
  exercises the **real product NVMe-passthru carrier code** end-to-end: locate
  `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` handles, command-packet marshalling via
  go-boot, Identify-Controller serial as the PBKDF2 salt, and the no-ComID-swap
  Opal session. Also proves the #112 `auto` iteration mode's try-limit safety
  end-to-end in QEMU (advance only on `NOT_AUTHORIZED`, stop on lockout).
- **Risks:** **R-010** (QEMU/mock vs real SED divergence — coverage strengthened
  + one actual divergence fixed), **R-002** (unlock before auth — the `auto`
  loop's fail-closed semantics proven e2e). No rating change (both stay Medium).
- **ADR status:** **no new ADR** — within ADR-0005 (virtual-first test strategy)
  and the already-Accepted ADR-0011 §3 (`auto` semantics unchanged); the QEMU
  device model (test-tooling-plan §3.7) stays deferred — the existing MockOpalDxe
  driver was extended instead of building a separate `MockNvmePassThru`.

## Test setup

- **Mock (test tooling):** `test/edk2-mock-opal/MockOpalDxe.c` now also produces
  `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` on the same handle as the Storage
  Security protocol:
  - **Identify Controller** (`0x06`, CNS=1) → scripted 20-byte serial
    `"TPBA-MOCK-0001      "` at bytes 4..23 — the sedutil-pbkdf2 salt.
  - **Security Send/Receive** (`0x81`/`0x82`) → the **shared** scripted TPer,
    ComID in **native TCG order** (no swap — the product NVMe carrier's
    contract); the Storage Security surface keeps its swap, mirroring the real
    firmware marshalling difference between the two carriers.
  - **Second accepted Admin1 credential:** the PBKDF2 derivation of the
    shared-spec passphrase at **75000** iterations over the scripted serial
    (`mAdmin1DerivedKey`) — the hash-provisioned drive shape (upstream-sedutil
    default, e.g. the lab's 1.20.0) that motivated #112.
  - New **`auth-lockout`** fault (every StartSession → `AUTHORITY_LOCKED_OUT`
    `0x12`) and `MOCKOPAL: startsession N` attempt markers.
- **PBA under test:** `-tags sednvmetest,hwdebug` build with the embedded test
  policy `internal/policy/policy_sednvme.json` — `sed_unlock: required`,
  `policy-pin` "correct horse", `derive: sedutil-pbkdf2`,
  `derive_params: { iterations: "auto" }`, `on_error: halt`. The derive makes
  `run()` select the NVMe-passthru carrier (the only transport exposing the
  drive serial).
- **Harness:** `test/qemu/nvme-opal-matrix.sh` (Taskfile target
  `nvme-opal-matrix`, CI job `qemu-nvme-matrix`); `harness-selftest.sh` re-proves
  FORBID/grace liveness at the start of every invocation; ESP on virtio-blk so
  the mock driver is the sole pass-thru instance (QEMU exposes none without a
  real `-device nvme`), making the no-driver scenario a true zero-instance
  negative.

## Scenarios and results (local, 2026-07-19)

| Scenario | Assertions | Result |
|---|---|---|
| POS `auto`-unlock over NVMe | REQUIRE: pass-thru install, `nvme identify` (salt read), attempt-1 `auth fail` (`NOT_AUTHORIZED` at 500000), `startsession 2`, `auth ok`, `unlocked`, `mbr-done set`, hwdbg `sedutil-pbkdf2 auto: authenticated at 75000 iterations`, `sed unlock ok`, `TEST-APP: ok`, chainload return; FORBID: `sed unlock failed` | **PASS** |
| NEG `auth-lockout` (try-limit safety) | REQUIRE: `fault auth-lockout active`, `startsession 1`, `auth lockout`, `sed unlock failed`; FORBID: boot markers **and `MOCKOPAL: startsession 2`** — the `auto` loop must never burn a second Admin1 try after `0x12` | **PASS** |
| NEG no-driver (zero pass-thru handles) | REQUIRE: `sed unlock failed`; FORBID: boot markers, `MOCKOPAL: dispatched` — `NewAllNVMe` hard-fails, fail closed, no boot | **PASS** |

`NVME OPAL MATRIX: PASS` (3/3).

## Regression runs (shared driver/mock changes)

- `mock-opal-matrix` (Storage Security carrier, 6 scenarios): **PASS 6/6** —
  the added pass-thru surface and the wrong-credential status change do not
  regress the existing matrix (its `auth-fail` fault now returns `0x01`, still a
  non-success status → same fail-closed verdict).
- `keyfile-matrix` (POS + NEG): **PASS 2/2**.
- Host tests: `go test ./internal/credential ./internal/opal ./internal/policy`
  green (re-verified by the compliance agent, 2026-07-19); `-tags sednvmetest`
  policy build compiles.

## Mock-fidelity fix (R-010-relevant)

Both mocks — host `internal/opal/mocktper.go` and the EDK2 driver — returned
`AUTHORITY_LOCKED_OUT` (`0x12`) for a **wrong credential**. Real drives return
`NOT_AUTHORIZED` (`0x01` — observed on lab hardware, and the status the #112
`auto` mode advances on). This was a genuine QEMU-vs-real-drive divergence:
with the old behavior, a MockTPer-backed `auto`-mode test would have wrongly
**stopped** (lockout semantics) instead of advancing. Both mocks and the shared
spec (`test/fixtures/opal/README.md`) now use `0x01` for wrong-credential;
`0x12` is an explicit `auth-lockout` fault shape. Supersedes the #112 residual
note that "MockTPer conflates the two"; real-drive `NOT_AUTHORIZED`-vs-lockout
*timing* remains a Phase-8 hardware item.

## Drift guard

`TestMockDerivedKeySync` (`internal/credential/derive_test.go`) pins the
driver's `mAdmin1DerivedKey` byte-for-byte to
`SedutilPBKDF2("correct horse", "TPBA-MOCK-0001      ", 75000, 32)` — the
KAT-verified primitive — so the mock's hash-provisioned credential cannot drift
from the product derive. Verified PASS.

## Reviews

- **go-reviewer:** APPROVE (no changes requested).
- **Independent security review:** APPROVE — record
  `evidence/security-review-records/2026-07-19-nvme-opal-matrix-110.md`.

## Traceability

- **Requirement:** ER-10 (regular security testing — status unchanged,
  evidence strengthened); CRA matrix otherwise no impact.
- **Risks:** R-010, R-002 (`docs/compliance/risk-assessment.md`, 2026-07-19
  change-log row; no rating change).
- **Threat model:** TB3 (both carriers now exercised virtually), §9 test-mapping
  rows for `nvme-opal-matrix`; 2026-07-19 change-log row.
- **Test tooling:** `docs/test-tooling-plan.md` §2 / §3.3 (MockOpalDxe NVMe
  pass-thru extension; QEMU device model §3.7 stays deferred).
- **Files (change under review):** `test/edk2-mock-opal/MockOpalDxe.{c,inf}` +
  README, `test/fixtures/opal/README.md`, `internal/opal/mocktper.go`,
  `internal/credential/derive_test.go`, `internal/policy/embed.go` +
  `embed_sednvmetest.go` + `policy_sednvme.json`, `test/qemu/nvme-opal-matrix.sh`,
  `Taskfile.yml` (`nvme-opal-matrix`), `.github/workflows/ci.yml`
  (`qemu-nvme-matrix`).
