# Security review record — firmware-path dbx-by-hash revocation test (scenario E, #18)

- **Date:** 2026-06-16
- **Change under review:** issue **#18** (EPIC: Secure Boot test matrix). Adds
  **scenario E** to the QEMU/OVMF Secure Boot matrix
  (`test/qemu/secureboot-matrix.sh`): it proves the **firmware's own** Secure Boot
  engine rejects a **db-trusted** PBA image because the image's **Authenticode hash
  is in dbx** — i.e. *revocation overrides trust (dbx > db)* on the
  firmware-validation path. This closes the previously-missing firmware-path
  revocation case; the PBA-validation-path dbx revocation in our own Go code
  (dbx-by-cert and dbx-by-hash) is already covered by #37's `pba-matrix` and the
  `internal/imageverify` unit tests (`verify_test.go:206`) — this is the
  complementary firmware-engine coverage.
  - New host CLI helper `test/qemu/authenticode-hash/main.go` computes the image's
    Authenticode SHA-256 via `github.com/foxboron/go-uefi/authenticode` — the SAME
    library `internal/imageverify` uses (one source of truth for the digest).
  - `test/qemu/sb-lib.sh`: `enroll_keys` gained an optional dbx-hash arg →
    `virt-fw-vars --add-dbx-hash`.
  - `secureboot-matrix.sh` scenario E boots the same db-signed PBA that scenario B
    boots, but against a store whose dbx contains that image's hash; REQUIRE
    `Access Denied|Security Violation`, FORBID `TRUSTED-PBA: start`.
  - CI: `actions/setup-go` added to the `secureboot-matrix` job (the helper needs
    host Go).
- **Reviewers:** independent **go-reviewer** (helper) and independent
  **security-review agent** (did not implement). Verified by build, by test, and by
  source — not by reading the implementer's claims.
- **Verdict:** **PASS.** go-reviewer **APPROVE** on the helper; security-review
  **PASS**, no blocking findings.

## The critical invariant — confirmed three ways

**Scenario E rejects iff the matching image hash is revoked in dbx, on the
firmware's own enforced bytes** (not because of a malformed store, not because of a
db/signature problem):

1. **One source of truth for the digest.** The host helper
   `test/qemu/authenticode-hash/main.go` computes the Authenticode SHA-256 with
   `go-uefi/authenticode` — the exact library `internal/imageverify` uses — so the
   bytes enrolled into dbx are the same digest definition the firmware enforces.
2. **The digest excludes the signature.** The Authenticode digest is identical for
   the signed and the unsigned input (it excludes the certificate table), confirming
   the dbx entry matches the bytes OVMF actually loads, regardless of the embedded
   signature.
3. **The firmware engine is the one under test.** Scenario E boots the *same*
   db-signed PBA that scenario B boots; only the variable store differs (its dbx
   carries the image's hash). Rejection comes from the firmware Secure Boot engine
   (`Access Denied` / `Security Violation`), and the FORBID `TRUSTED-PBA: start`
   marker proves the image never executed — i.e. dbx > db on TB1.

## Non-vacuousness — confirmed (B / E / control differential)

- **B** — same image, dbx has **no** entry for it → **BOOTS** (`TRUSTED-PBA: start`
  fires).
- **E** — same image, **its hash** in dbx → **REJECTED** (`Access Denied`),
  `TRUSTED-PBA: start` never fires.
- **control** — same image, a **wrong random** dbx hash → **BOOTS** (PBA runs),
  proving E's rejection is not an artefact of a malformed/over-broad store.

So E rejects **iff** the matching hash is revoked. The FORBID `TRUSTED-PBA: start`
marker is load-bearing. Full matrix A–E PASSES locally in QEMU/OVMF.

## Reviewer checks

- **go-reviewer (APPROVE):** the host helper is idiomatic, errors checked, single
  responsibility (compute + print the digest), no speculative abstraction.
- **security-review (PASS):** re-verified that the hash matches OVMF's enforced
  bytes (one-source-of-truth digest, signature-excluded); `set -u` array safety in
  `sb-lib.sh`/`secureboot-matrix.sh`; **no fail-open path** introduced — the new
  scenario only adds a negative assertion and a dbx-hash enrollment arg.

## Findings

| # | Severity | Finding | Disposition |
|---|----------|---------|-------------|
| INFO-1 | INFO | Helper shares the digest library with `internal/imageverify` rather than re-deriving the Authenticode hash | Intended — one source of truth; a divergent re-implementation would weaken the test. No change. |
| INFO-2 | INFO | `secureboot-matrix` CI job now requires host Go (`actions/setup-go`) for the helper | Expected; the helper is a host-side test tool, not shipped in the PBA. No change. |

## Risk disposition

- **R-001** strengthened: end-to-end QEMU firmware-path **dbx-by-hash** revocation
  negative (dbx > db), complementary to #37's PBA-path dbx-by-cert coverage; residual
  **Low** unchanged. **TB1** (Firmware → PBA) coverage strengthened. No new threats;
  no rating change.
- **Test-only change.** No security-critical product behavior changed — the new
  code is a host test helper plus test-harness/CI wiring; the PBA binary and
  `internal/imageverify` are untouched. No ADR required (no security-critical
  behavior change, no threat-model-assumption change) and **no §5.3 human gate**
  triggered. No key material or secret committed.
