# CRA Essential Requirements Matrix — Trusted PBA

Per [compliance baseline §22](../compliance-and-secure-development-baseline.md).
Maps each CRA essential cybersecurity requirement (CRA Annex I) to its
interpretation for Trusted PBA, the design control, the implementation artifact,
test and documentation evidence, status, owner, and open gaps. Living document:
reviewed before every release and on any security-relevant change.

Pairs with [`cra-scope-assessment.md`](cra-scope-assessment.md),
[`cra-classification.md`](cra-classification.md),
[`risk-assessment.md`](risk-assessment.md), and the
[threat model](../security/threat-model.md).

- **Status legend:** Implemented (virtual) = built and exercised in CI/QEMU, not yet
  hardware/production-validated · Partial · Planned (gated, not built) · Process.
- **Owner:** Compliance Owner coordinates; per-row owner named.

## Summary register

| # | Essential requirement | Interpretation (Trusted PBA) | Status | Owner |
|---|---|---|---|---|
| ER-1 | Secure by default | Fail-closed; never boots an untrusted target; no debug/backdoor unlock | Implemented (virtual) | Security |
| ER-2 | Integrity of code/data | PBA binary, policy, and target images verified before use | Implemented (virtual) | Security |
| ER-3 | Confidentiality of secrets | Unlock secret never logged; pre-boot memory only; zeroized | Implemented (virtual) | Security |
| ER-4 | Availability / recovery | A recovery path exists if unlock or update fails | Partial | Product |
| ER-5 | No known exploitable vulns at release | Vuln review + fix gate before release | Process | Vuln Response |
| ER-6 | Security update mechanism | Signed, anti-rollback, recovery-safe updates | Planned | Release |
| ER-7 | Vulnerability handling + CVD | Triage, fix, advisory, coordinated disclosure | Planned | Vuln Response |
| ER-8 | SBOM | SBOM generated per release, machine-readable | Partial | Release |
| ER-9 | Third-party component due diligence | Pinned, hash-locked, reviewed dependencies | Partial | Architecture |
| ER-10 | Regular security testing | SAST, fuzz, negative, Secure Boot, integration | Implemented (virtual) | Security |
| ER-11 | Support period + secure-use docs | Defined support period; install/operate instructions | Planned | Product |
| ER-12 | Technical documentation + DoC | Conformity evidence package + EU DoC readiness | Partial | Compliance |

## Detailed rows

Each: **interpretation · design control · implementation · test evidence · doc
evidence · status · gaps.**

### ER-1 — Secure by default
- **Interpretation:** the production PBA fails closed on any auth/unlock/policy/
  verification failure, never boots an untrusted or revoked target, and ships with
  no debug or unconditional unlock.
- **Design control:** fail-closed-everywhere invariant (ADR-0002 terminal halt, no
  boot-order fallback); `sed_unlock` defaults to `required` on absence (ADR-0009);
  policy is compiled-in and parsed fail-closed.
- **Implementation:** `cmd/pba` (`terminate`, `run`), `internal/policy`,
  `internal/opal`, `internal/imageverify`.
- **Test evidence:** `internal/policy` parse-negative + `FuzzParse`;
  `TestUnlockFailsClosed/*`; `run-negative`, `sb-require-test`, `pba-matrix`,
  `mock-opal-matrix` (mutation-proven FORBIDs); `linux-boot-matrix` NEG
  (a failed unlock never boots a **real OS** — early-chainload-marker FORBIDs,
  mutation-proven, 2026-07-21).
- **Doc evidence:** ADR-0002, ADR-0009; threat model §6.1; risk R-001/R-002.
- **Status:** Implemented (virtual).
- **Gaps:** release-time assertion that production defaults are not a test/`none`
  policy (a `check-release-policy` gate exists for `sed_unlock`); hardware
  validation (Phase 8). On the gated (`-tags trustbroker`, non-release)
  `pba-override` measured-boot path (ADR-0015/0016, Proposed), the new
  **`require_tpm`** flag makes measurement fail-closed when set (`true` → missing
  TPM / failed extend refuses to boot); its **default `false`** is best-effort
  (boot the already-verified image *unattested*, logged loudly — never a silent
  fallback), keeping the override usable on TPM-less platforms while
  authorization stays intact either way (measurement is advisory-to-attestation,
  post-verify/post-arm). Deployments that mandate attestation set `require_tpm: true`.

### ER-2 — Integrity of code and data
- **Interpretation:** the PBA binary, its policy, and any target EFI image are
  integrity-verified before they are trusted or executed.
- **Design control:** firmware Secure Boot validates the PBA (TB1) and the Windows
  handoff (ADR-0002); PBA-side Authenticode verification for custom images
  (ADR-0007); verified-buffer load closes the SB-off TOCTOU (#46); compiled-in
  policy (not attacker-writable).
- **Implementation:** `internal/imageverify`, `internal/truststore`, `internal/secureboot`, `cmd/pba` `verifyAndLoad`.
- **Test evidence:** `TestVerifyAccepts`/`TestVerifyFailsClosed/*`, `FuzzVerify`,
  `TestVerifyAndLoadVerifiedBufferInvariant`; `pba-matrix`, `secureboot-matrix`
  (unsigned/wrong-key rejected); `linux-boot-matrix` POS-SB (accept side: a
  db-signed real Linux UKI boots to userspace under enforcing Secure Boot).
- **Doc evidence:** ADR-0007, ADR-0006; threat model §6.1/TB2; risk R-001/R-012.
- **Status:** Implemented (virtual).
- **Gaps:** real Windows Boot Manager handoff is hardware/manual (R-007);
  trust-anchor staleness (R-011); `imageverify` parser hardening tracked via fuzz
  (`FuzzVerify`; a 2026-07-18 nightly-fuzz finding — a go-uefi parser panic on a
  malformed PE — is fixed by a `recover()`→`ErrParse` fail-closed backstop, R-009).
  The gated `pba-override` Secure Boot override (ADR-0012/0013, R-014) is a deliberate,
  non-default, non-release capability that makes the PBA's verdict authoritative for the
  one pre-verified out-of-`db` image; **ADR-0014 (Proposed)** would extend it to the
  Windows path for **our-keys-only** platforms, gated on a mandatory provisioning
  obligation (BitLocker sealed with the PBA measured) plus an open PCR-7 pre-condition
  (verify against a primary Microsoft source + validate on real hardware before
  production), and pending the §5.3 human gate + an independent security review. Release
  builds stay override-free, so the shipped ER-2 posture is unchanged (see risk R-014,
  threat-model TB2).
  **Attestation extensions (ADR-0015/0016, Proposed).** Within the same gated override,
  ADR-0015 measures the override's *own authorization* into PCR 7 (`EV_EFI_VARIABLE_AUTHORITY`,
  PBA-owned namespace + the trust-store CA that validated the image) and ADR-0016 measures the
  chained image into policy-configured PCR(s) (default `[4]`, `EFI_TCG2_PE_COFF_IMAGE`),
  restoring the boot-application measurement `LoadImageBuffer` skips — so the override's full
  authorization chain becomes **measurable/attestable** (integrity) and BitLocker can bind the
  default `0,2,4,11` profile under the override. Authorization is unchanged (measurement is
  post-verify/post-arm, advisory-to-attestation); the new **`require_tpm`** flag (default
  `false`) is the measurement-path fail-closed control (see ER-1). Independent security review
  this session: **APPROVE**, all findings LOW; the PCR-4 `PE_COFF` value is firmware-dependent
  and its real-hardware confirmation is an **open pre-condition, deferred by decision** (ADR-0016
  F-1). Both ADRs Proposed, `-tags trustbroker`, pending the §5.3 human gate — shipped ER-2
  posture unchanged. Evidence:
  `evidence/security-review-records/2026-08-29-override-measured-boot-adr-0015-0016.md`.

### ER-3 — Confidentiality of secrets
- **Interpretation:** the unlock secret is never logged, lives only in pre-boot
  memory, and is zeroized where feasible.
- **Design control:** never-log-secrets rule; client-side PIN buffers zeroized on
  all paths with an append-reallocation guard (#51 item 1); errors carry no secret.
- **Implementation:** `internal/opal` (`zeroize`, `Unlock` contract); `cmd/pba`
  policy-PIN holder cleared after use.
- **Test evidence:** `TestUnlockZeroizesSecrets`, `TestUnlockEmitsNoConsoleOutput`
  (fd-level log scrub), `TestStartSessionReserves` — all mutation-verified.
- **Doc evidence:** ADR-0009; threat model §6.2; risk R-003.
- **Status:** Implemented (virtual), residual Low.
- **Gaps:** firmware/DMA-side copies out of reach (evil-maid residual); the future
  console PIN-prompt must zeroize its input buffer; compiled-in MVP PIN is
  test-only and replaced before production.

### ER-4 — Availability / recovery
- **Interpretation:** a failed unlock or a failed update must not permanently deny
  access to the encrypted data; a recovery path must exist.
- **Design control:** recovery EFI application as a boot target (plan §3); PSID
  reset / recovery flow (plan Phase 8); updates must be recovery-safe (baseline §16).
- **Implementation:** chainloader supports a recovery target; **recovery/PSID flow
  not yet built.**
- **Test evidence:** chainload availability exercised virtually; recovery flow
  **untested** (hardware).
- **Doc evidence:** plan §3/§7.5; risk R-007; (planned) `residual-risks.md`.
- **Status:** Partial.
- **Gaps:** recovery process, PSID reset, anti-brick on failed update — Phase 8 +
  the update pipeline.

### ER-5 — No known exploitable vulnerabilities at release
- **Interpretation:** no known exploitable vulnerability ships in a release.
- **Design control:** vulnerability management (baseline §15) + release checklist
  vuln-review gate (DoD §24); SAST/dependency scanning in CI.
- **Implementation:** CI `sast`/`dependency-scan` (skeleton, #9); `govulncheck`
  planned.
- **Test evidence:** (planned) SAST + dependency-scan reports under `evidence/`.
- **Doc evidence:** `release-process.md` checklist; (planned) `security-policy.md`.
- **Status:** Process (gate defined; scanners are CI skeletons).
- **Gaps:** real SAST/`govulncheck`/dependency-scan jobs (#9); triage records.

### ER-6 — Security update mechanism
- **Interpretation:** updates are produced on controlled CI, signed, anti-rollback,
  recovery-safe, and verifiable by the user.
- **Design control:** baseline §16/§19; release on controlled CI; anti-rollback
  (R-005); signed artifacts + provenance.
- **Implementation:** **not built.**
- **Test evidence:** none yet (update-verification-failure is a mandatory negative
  test category, baseline §17.2, to be added with the mechanism).
- **Doc evidence:** (planned) `secure-update-design.md`, `release-process.md`.
- **Status:** Planned (gated).
- **Gaps:** the entire update/signing/anti-rollback pipeline — R-005/R-006.

### ER-7 — Vulnerability handling and coordinated disclosure
- **Interpretation:** receive, triage, fix, and disclose vulnerabilities over the
  support period.
- **Design control:** baseline §15; CVD policy; advisory flow; §5.3 human gates for
  advisory publication and critical-vuln closure.
- **Implementation:** `evidence/vulnerability-triage/` exists; **process docs not
  written.**
- **Doc evidence:** (planned) `security-policy.md`, `coordinated-vulnerability-disclosure.md`.
- **Status:** Planned.
- **Gaps:** CVD policy, advisory process, intake channel.

### ER-8 — SBOM
- **Interpretation:** a machine-readable SBOM (SPDX/CycloneDX) is generated per
  release and links artifact ↔ source.
- **Design control:** baseline §14/§19; CI SBOM stage; provenance.
- **Implementation:** CI `sbom` job (skeleton, #9); trust-material provenance in
  `internal/truststore/materials/PROVENANCE.md`.
- **Doc evidence:** (planned) `evidence/sbom/`.
- **Status:** Partial.
- **Gaps:** real SBOM generation + per-release storage (#9).

### ER-9 — Third-party component due diligence
- **Interpretation:** dependencies are inventoried, pinned, hash-locked, and
  reviewed; the maintained go-boot fork is governed.
- **Design control:** pinned modules + `go.sum`; the `walterchris/go-boot` fork
  pinned by tag (`v1.6.2-tpba.5`) + hash with an additive/minimal-edit policy
  (ADR-0008); vendored MS materials with recorded SHA-256.
- **Implementation:** `go.mod`/`go.sum`, ADR-0008, `materials/PROVENANCE.md`.
- **Test evidence:** published-tag hash verified byte-identical on each fork bump;
  (planned) dependency vuln/license scan.
- **Doc evidence:** ADR-0008; (planned) `dependency-management.md` (#27).
- **Status:** Partial.
- **Gaps:** formal dependency onboarding (license/vuln/SBOM) — #27; R-006.

### ER-10 — Regular security testing
- **Interpretation:** effective, regular, automated security testing.
- **Design control:** layered test strategy (baseline §17); every PR runs the
  virtual matrices; negative/fail-closed cases mandatory.
- **Implementation:** unit + `FuzzParse`/`FuzzResponseParse`/`FuzzVerify` +
  `pba-matrix` + `secureboot-matrix` + `mock-opal-integration` +
  `qemu-linux-matrix` (real-OS linux-boot matrix) + harness self-test.
- **Test evidence:** the CI jobs above (green on every PR); mutation-proofs in the
  security-review records; the nightly `deep-fuzz` job found and drove the fix of a
  real fail-closed defect (R-009 `imageverify.Verify` panic, 2026-07-18 —
  `evidence/fuzzing-reports/2026-07-18-imageverify-fuzzverify-panic-R-009.md`),
  demonstrating the testing process working.
- **Doc evidence:** baseline §17; ADR-0005; test-tooling-plan.
- **Status:** Implemented (virtual).
- **Gaps:** SAST/dependency scanners still skeletons (#9); hardware tests (Phase 8).

### ER-11 — Support period and secure-use documentation
- **Interpretation:** a defined support period and clear secure-installation/use
  instructions for the customer.
- **Design control:** baseline §20 (before first customer release).
- **Implementation:** **not written.**
- **Doc evidence:** (planned) `support-period.md`, `secure-installation.md`,
  `secure-operation.md`, `user-instructions.md`.
- **Status:** Planned.
- **Gaps:** all of the above — first-customer-release docs.

### ER-12 — Technical documentation and Declaration of Conformity
- **Interpretation:** a complete CRA technical-documentation package and EU DoC
  readiness for the chosen conformity route.
- **Design control:** baseline §21 mapping; `technical-documentation-index.md`;
  conformity-assessment plan.
- **Implementation:** `docs/` + `evidence/` trees populated per phase; index/DoC
  **not yet written**.
- **Doc evidence:** this matrix, threat model, risk assessment, ADRs, review
  records; (planned) `technical-documentation-index.md`, `conformity-assessment-plan.md`, DoC draft.
- **Status:** Partial.
- **Gaps:** technical-documentation index, conformity-assessment plan, DoC draft —
  before first release.
