# Trusted PBA — Risk Assessment

Living risk assessment per the
[compliance baseline §9](../compliance-and-secure-development-baseline.md). Pairs
with the [threat model](../security/threat-model.md) (adversaries, trust
boundaries, attack trees); this document quantifies and tracks each risk.

- **Status:** through **Phase 3**. Risks whose mitigations are not yet built
  (update pipeline, anti-rollback, signing/key management, Opal unlock) are listed
  with their current (unmitigated/partial) standing and a *planned* mitigation.
- **Owner:** Security Owner, unless a row names another.
- **Review cadence (baseline §9):** before MVP, before first hardware test, before
  first customer delivery, before every release, after every critical
  vulnerability, after every architecture change.

## Scales

**Likelihood:** Low (needs rare conditions / strong attacker) · Medium (plausible
for a motivated attacker) · High (easy / default-path).
**Severity:** Low (limited) · High (boots untrusted code, leaks secret, or bricks
boot) · Critical (silent, persistent compromise of the boot chain or unlock
secret).
**Residual** = standing after current (implemented) mitigations.

## Risk register

| ID | Risk | Asset | C/I/A | Likelihood | Severity | Residual | Status |
|---|---|---|---|---|---|---|---|
| R-001 | PBA accepts an untrusted EFI image | A6/A5 | I | Medium | Critical | **Low** | Mitigated (imageverify) |
| R-002 | PBA unlocks SED before authentication succeeds | A1/A7 | C/I | Medium | Critical | **High** | Open — Phase 4–6 |
| R-003 | Unlock secret leaks through logs | A1 | C | Medium | Critical | **High** | Open — Phase 4–6 (rule defined) |
| R-004 | Attacker modifies PBA policy file | A3 | I | Low | High | **Low** | Mitigated (compiled-in, fail-closed) |
| R-005 | Rollback to a vulnerable PBA version | A2/A5 | I | Medium | Critical | **High** | Open — anti-rollback not built |
| R-006 | Malicious update accepted | A8/A2/A5 | I | Medium | Critical | **High** | Open — update/signing not built |
| R-007 | Windows Boot Manager chainload fails after unlock | A6 | A | Medium | High | **Medium** | Partial — virtual only |
| R-008 | MBRDone does not take effect until reboot | A7 | A/I | Medium | High | **Medium** | Open — Phase 6/8 |
| R-009 | Opal/PE command parser accepts malformed response | A7/A6 | I/A | Medium | High | **Low (PE) / High (Opal)** | Partial |
| R-010 | QEMU tests pass but real SED differs | — | I/A | High | High | **Medium** | Open — Phase 8 |
| R-011 | Embedded trust anchors go stale (2011 CAs expire 2026-06-27) | A5 | I/A | High | High | **Medium** | Open — ADR-gated refresh |
| R-012 | TOCTOU: target re-read after verification (SB-off) | A6 | I | Low | High | **Low** | Open — #46 |
| R-013 | Expired-but-valid signing key reused (expiry ignored) | A6 | I | Low | High | **Low** | Accepted — control is dbx; #48 |

## Detailed risks

Each: threat · attack path · mitigations · residual · tests · evidence.

### R-001 — PBA accepts an untrusted EFI image
- **Threat/path:** a pre-boot/evil-maid attacker stages an unsigned, tampered, or
  untrusted-/revoked-signer image on the ESP and the PBA chainloads it.
- **Mitigations:** `pba` mode computes the Authenticode hash, checks `dbx`-by-hash
  first, binds the signature, chains the signer to embedded `db` with
  `ExtKeyUsageCodeSigning`, and applies `dbx`-by-cert across the chain; any failure
  → fail closed before `LoadImage`. `firmware` mode defers to firmware Secure Boot.
- **Residual:** Low (parser-bug risk in `go-uefi`, bounded by pinning + fuzz).
- **Tests:** `TestVerifyFailsClosed/*`, `TestVerifyAccepts`; `pba-matrix`.
- **Evidence:** ADR-0007; `internal/imageverify/verify.go`.

### R-002 — PBA unlocks SED before authentication succeeds
- **Threat/path:** logic error unlocks the drive when auth failed/was skipped.
- **Mitigations (planned):** fail-closed unlock sequencing in Phase 4–6; do not
  unlock on auth failure; do not chainload on unlock failure (baseline §11).
- **Residual:** High (unimplemented). **Tests:** planned (mock Opal). **Owner:** Security Owner.

### R-003 — Unlock secret leaks through logs
- **Threat/path:** secret/PIN/session data written to console/serial.
- **Mitigations:** "never log secrets" is a non-negotiable rule (CLAUDE.md,
  baseline §11); current console output prints only banners/markers (no secret
  handled yet). Phase 4–6 must add buffer zeroization + log review.
- **Residual:** High until unlock exists. **Tests:** planned (log-scrub assertion).

### R-004 — Attacker modifies PBA policy file
- **Threat/path:** tamper with the boot policy to redirect/relax validation.
- **Mitigations:** policy is **compiled-in** (`go:embed`), not ESP-resident, so it
  shares the PBA binary's Secure Boot integrity; parsing is fail-closed
  (`DisallowUnknownFields`, rejects trailing data). External/signed policy files
  are out of scope (ADR-0007).
- **Residual:** Low. **Tests:** `TestParseFailsClosed`, `FuzzParse`. **Evidence:** ADR-0007.

### R-005 — Rollback to a vulnerable PBA version
- **Threat/path:** re-deploy an older PBA or a stale `dbx` to regain a fixed hole.
- **Mitigations (planned):** version floor / anti-rollback policy; `dbx` refresh
  process (ADR-gated). **Not yet built.**
- **Residual:** High. **Tests:** none yet. Linked to R-011.

### R-006 — Malicious update accepted
- **Threat/path:** crafted PBA/policy/trust-material update via a future update
  channel, a compromised dependency, CI runner, or signing key.
- **Mitigations:** pinned deps + vendored materials with recorded SHA-256/commit;
  protected `main`, PR-only, signed commits; ephemeral CI test keys (no prod keys
  in CI). **Planned:** signed updates, SLSA provenance, key management, vuln/SBOM
  scan (#9, #10, #27).
- **Residual:** High until the pipeline lands. **Tests:** `TestLoad`,
  `TestRealMicrosoftSignedImage` (CI-only, `real-image-verify` job; skips without
  `TPBA_REAL_SHIM`). **Evidence:** `PROVENANCE.md`.

### R-007 — Windows Boot Manager chainload fails after unlock
- **Threat/path:** handoff to the OS loader fails post-unlock → unbootable system.
- **Mitigations:** `firmware`-mode handoff lets firmware own Windows validation
  (ADR-0006); QEMU chainload smokes assert markers. Real Windows boot is a manual
  step (proprietary `bootmgfw`; see threat-model §9 gap).
- **Residual:** Medium (virtual only). **Tests:** `run`; `pba-matrix`. **Owner:** Product + Security.

### R-008 — MBRDone does not take effect until reboot
- **Threat/path:** Shadow-MBR remains visible after unlock, OS reads wrong data.
- **Mitigations (planned):** Phase 6 MBRControl handling + hardware validation.
- **Residual:** Medium. **Tests:** planned (mock + hardware).

### R-009 — Opal/PE command parser accepts malformed response
- **Threat/path:** malformed device/image input drives the parser into an unsafe
  state or panic.
- **Mitigations:** PE/Authenticode + dbx parsing fail closed and never panic on
  attacker input (`ErrParse`; `stripAuth2` bounds-checked); policy parser fuzzed.
  Opal response parsing (Phase 4) **must be fuzzed** before merge.
- **Residual:** Low for PE/policy today; High for Opal until built. **Tests:**
  `TestStripAuth2Rejects`, `FuzzParse`, `TestVerifyFailsClosed/tampered`.

### R-010 — QEMU tests pass but real SED differs
- **Threat/path:** behavioral gap between mock/QEMU and real hardware causes an
  unsafe state in the field.
- **Mitigations:** virtual-first strategy (ADR-0005); documented mock equivalents;
  gated hardware bring-up (Phase 8). **Residual:** Medium. **Tests:** QEMU matrices.

### R-011 — Embedded trust anchors go stale
- **Threat/path:** the embedded `db`/`dbx` ages; notably the *Microsoft Corporation
  UEFI CA 2011* expires **2026-06-27**, and `dbx` revocations accrue upstream.
- **Mitigations:** both 2011 and 2023 CA generations are embedded; refresh is
  **ADR-gated** (pinned commit + recorded SHA-256). Because the verifier ignores
  cert expiry (R-013), an expired *CA* does not by itself break validation, but a
  stale `dbx` means missed revocations.
- **Residual:** Medium. **Tests:** `TestLoad`; `TestRealMicrosoftSignedImage`
  (CI-only, needs `TPBA_REAL_SHIM`). **Evidence:** ADR-0007; `PROVENANCE.md`.

### R-012 — TOCTOU: target re-read after verification
- **Threat/path:** the PBA verifies the image bytes it read, but `LoadImage`
  re-reads the path; a swap between the two reads could load unverified bytes.
- **Mitigations:** pre-boot is single-threaded with no concurrent ESP writer
  (assumption §5); under *enforcing* Secure Boot firmware revalidates on load. The
  exposed case is Secure-Boot-off.
- **Residual:** Low. **Status:** Open — fix is to load from the verified in-memory
  buffer (#46). **Evidence:** `cmd/pba/main.go` `verifyAndLoad` comment.

### R-013 — Expired-but-valid signing key reused
- **Threat/path:** the verifier ignores signing-cert validity (to match firmware
  and boot real, short-lived-leaf Microsoft images), so a signing cert that expired
  and whose key later leaked—but was never revoked—could sign a bootable image.
- **Mitigations:** the control is **`dbx` revocation, not expiry** (exactly as
  firmware); EKU + chain still enforced.
- **Residual:** Low. **Status:** Accepted (owner decision, ADR-0007). Research into
  Authenticode-timestamp validation tracked in **#48**.
- **Tests:** `TestVerifyAcceptsExpiredSigner`; `dbx` negatives. **Evidence:** ADR-0007.

## Change log

| Date | Change |
|---|---|
| 2026-06-08 | Initial risk assessment (#5): R-001..R-010 from baseline §9 plus R-011 (trust-anchor staleness), R-012 (SB-off TOCTOU, #46), R-013 (ignore-expiry, ADR-0007/#48). Reflects Phase 3 mitigations. |
