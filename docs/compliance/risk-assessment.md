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
| R-002 | PBA unlocks SED before authentication succeeds | A1/A7 | C/I | Medium | Critical | **Medium** | Library fail-closed; boot-path gate wired (ADR-0009); QEMU MockOpalDxe e2e in place, mutation-proven (#22); hardware pending (Phase 8) |
| R-003 | Unlock secret leaks through logs | A1 | C | Medium | Critical | **Low** | Mitigated in library (zeroize + log-scrub tested); PIN-entry wiring #51 |
| R-004 | Attacker modifies PBA policy file | A3 | I | Low | High | **Low** | Mitigated (compiled-in, fail-closed) |
| R-005 | Rollback to a vulnerable PBA version | A2/A5 | I | Medium | Critical | **High** | Open — anti-rollback not built |
| R-006 | Malicious update accepted | A8/A2/A5 | I | Medium | Critical | **High** | Open — update/signing not built |
| R-007 | Windows Boot Manager chainload fails after unlock | A6 | A | Medium | High | **Medium** | Partial — virtual only |
| R-008 | MBRDone does not take effect until reboot | A7 | A/I | Medium | High | **Medium** | Open — Phase 6/8 |
| R-009 | Opal/PE command parser accepts malformed response | A7/A6 | I/A | Medium | High | **Low** | Mitigated (parsers fuzzed, fail closed) |
| R-010 | QEMU tests pass but real SED differs | — | I/A | High | High | **Medium** | Open — Phase 8 |
| R-011 | Embedded trust anchors go stale (2011 CAs expire 2026-06-27) | A5 | I/A | High | High | **Medium** | Open — ADR-gated refresh |
| R-012 | TOCTOU: target re-read after verification (SB-off) | A6 | I | Low | High | **Low** | Mitigated (verified-buffer load, #46) |
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
- **Mitigations:** Phase 4 `internal/opal` unlock flow is fail-closed by
  construction — `Set` (range unlock / MBRDone) requires an authenticated session,
  and wrong PIN / non-success status / transport error abort before any unlock, so
  the drive stays locked (verified by the negative-test matrix). **Wired into the
  boot path** (Phase 6, ADR-0009): the `sed_unlock` policy gate defaults to
  `required` on absence, a missing Storage Security device under `required` is a
  hard failure, and any unlock error — including a partial unlock — terminates
  via the on-error action with no retry and no fallback to chainload (#51 item 2).
  Skipping the unlock needs an explicit, loudly-logged `"sed_unlock": "none"`.
  **QEMU end-to-end** (#22): the MockOpalDxe integration matrix drives the wired
  boot path over the real UEFI Storage Security protocol — unlock-chainload and
  secure-boot positive scenarios (tied to driver dispatch/auth/unlock/MBRDone
  markers, so a skipped driver cannot false-pass), and auth-fail / fail-mbrdone /
  fail-after-unlock (partial unlock) / no-driver negative scenarios with FORBID
  assertions on the chainload markers, **mutation-proven** (a fail-open PBA
  mutant fails the matrix; harness FORBID liveness re-proven by
  `harness-selftest.sh` on every run).
- **Residual:** Medium — narrows to **hardware-pending (Phase 8)**: local 6/6
  matrix runs plus the mutation proof are in evidence; the green
  `mock-opal-integration` CI run on the PR completes the runs-in-CI claim
  (pending at the time of writing). Real-drive divergence remains tracked under
  R-007/R-008/R-010.
  **Tests:** `TestUnlockHappyPath`, `TestUnlockFailsClosed/*`;
  `cmd/pba` `TestUnlockSED*`; `internal/policy` `TestParseSEDUnlock`;
  `mock-opal-matrix` (6 scenarios) + `harness-selftest.sh` (CI job
  `mock-opal-integration`).
  **Evidence:** ADR-0004, ADR-0009;
  `evidence/security-review-records/2026-06-10-mock-opal-integration-matrix-22.md`.
  **Owner:** Security Owner.

### R-003 — Unlock secret leaks through logs
- **Threat/path:** secret/PIN/session data written to console/serial.
- **Mitigations:** "never log secrets" is a non-negotiable rule (CLAUDE.md,
  baseline §11); `internal/opal` logs nothing (it returns errors without the PIN/
  session material). All client-side PIN-bearing buffers — the caller's `pin`
  slice, the StartSession method payload, and every transmitted ComPacket frame —
  are zeroized on success **and on every failure path** (wrong PIN, pre-auth
  failure, transport failure mid-session, malformed response after the PIN was
  transmitted); append-reallocation after the PIN bytes (which would strand a
  stale copy in an unreachable backing array) is prevented by a 64-byte
  pre-reservation budget pinned by a regression test at the real call site. A
  log-scrub test runs the full unlock exchange with stdout/stderr captured at the
  **file-descriptor level** (so the runtime's builtin `print`/`println` is caught
  too) and asserts opal-layer silence plus PIN-free error text across raw,
  lower/upper hex, std/url/raw base64, and Go decimal-slice (`%v`) encodings.
  Both leak assertions are mutation-verified (injected `println`/`fmt.Printf` PIN
  leaks and PIN-bearing error text each fail the suite).
- **Residual:** Low — remaining exposures: copies beyond the transport boundary
  (firmware command buffers, device DMA) are out of the client's reach (existing
  evil-maid residual, threat model §6.2); zeroization relies on the Go compiler
  not dead-store-eliminating `clear()` (true with the current toolchain, not a
  language guarantee); transient register/temporary copies are unscrubbed;
  swap/crash-dump exposure does not apply pre-boot under TamaGo. The Phase 6
  boot-path wiring (ADR-0009) holds no PIN copy of its own: the policy's PIN is
  moved out and handed to `Unlock` exactly once (which zeroizes it), with a
  belt-and-braces clear on the transport-construction failure path
  (`TestUnlockSED*` assert backing-array zeroization on every path). MVP-only
  residual: the compiled-in policy embeds the PIN in the binary's policy JSON
  (extractable from the image) and the JSON decoder's intermediate string copy
  is unscrubable; `json.Decoder`'s internal read buffer likewise holds a heap
  copy of the PIN-bearing JSON — accepted because the compiled-in PIN is
  test-only and replaced by real auth before production (ADR-0009). **Open scope:** when the
  console PIN prompt lands, its input buffer must be zeroized (#51) — #51 item 1
  closed the library layer, this wiring the policy-holder layer.
- **Tests:** `TestUnlockZeroizesSecrets`, `TestTransactZeroizesMethodPayload`,
  `TestStartSessionGrowBudget`, `TestBuilderGrowPreventsReallocation`,
  `TestUnlockEmitsNoConsoleOutput`. **Evidence:** ADR-0004; #51 item 1
  (commits 8946c93/25c1229/32e8401); independent security review (pass, code
  approved).

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
  the `walterchris/go-boot` fork (ADR-0008) pinned by tag (`v1.6.2-tpba.3`) +
  `go.sum` — its patch set over upstream v1.6.2 is additive files **plus exactly
  one functional edit to an upstream file** (the `callFn` stack-alignment fix in
  `uefi/uefi.s`, a latent upstream ABI bug; ADR-0008 Amendment 2026-06-10), a
  tiny, individually security-reviewed diff to be submitted upstream; protected
  `main`, PR-only, signed commits; ephemeral CI test keys (no prod keys in CI).
  **Planned:** signed updates, SLSA provenance, key management, vuln/SBOM scan
  covering the fork (#9, #10, #27).
- **Residual:** High until the pipeline lands. Accepted sub-residual (TB5, #22
  integration review finding 5): the `mock-opal-integration` CI job's EDK2 cache
  verification is **ref-level only** — a tampered cached tree whose recorded HEAD
  still matches would go undetected; bounded by GitHub Actions' same-repo cache
  scoping. **Tests:** `TestLoad`,
  `TestRealMicrosoftSignedImage` (CI-only, `real-image-verify` job; skips without
  `TPBA_REAL_SHIM`). **Evidence:** `PROVENANCE.md`;
  `evidence/security-review-records/2026-06-10-go-boot-tpba3-abi-fixes.md`;
  `evidence/security-review-records/2026-06-10-mock-opal-integration-matrix-22.md`.

### R-007 — Windows Boot Manager chainload fails after unlock
- **Threat/path:** handoff to the OS loader fails post-unlock → unbootable system.
- **Mitigations:** `firmware`-mode handoff lets firmware own Windows validation
  (ADR-0006); QEMU chainload smokes assert markers. Real Windows boot is a manual
  step (proprietary `bootmgfw`; see threat-model §9 gap).
- **Residual:** Medium (virtual only). **Tests:** `run`; `pba-matrix`. **Owner:** Product + Security.

### R-008 — MBRDone does not take effect until reboot
- **Threat/path:** Shadow-MBR remains visible after unlock, OS reads wrong data.
- **Mitigations:** Phase 4 sets `MBRControl.Done` as part of the unlock flow (the
  mock reflects it in discovery); real MBRDone timing/visibility needs hardware
  validation (Phase 6/8).
- **Residual:** Medium. **Tests:** `TestUnlockHappyPath` (asserts MBRDone set);
  hardware planned.

### R-009 — Opal/PE command parser accepts malformed response
- **Threat/path:** malformed device/image input drives the parser into an unsafe
  state or panic.
- **Mitigations:** PE/Authenticode + dbx parsing fail closed and never panic on
  attacker input (`ErrParse`; `stripAuth2` bounds-checked); policy parser fuzzed
  (imageverify fuzz target: #56).
  Opal response parsing (token/packet/discovery/method) now fails closed and is
  fuzzed (`FuzzResponseParse`), satisfying baseline §12.
- **Residual:** Low. **Tests:** `TestStripAuth2Rejects`, `FuzzParse`,
  `FuzzResponseParse`, `TestTokenizeFailsClosed`, `TestDecodePacketFailsClosed`,
  `TestParseDiscoveryFailsClosed`, `TestVerifyFailsClosed/tampered`.

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
- **Threat/path:** the PBA verifies the image bytes it read; if `LoadImage`
  re-read the path, a swap between the two reads could load unverified bytes.
- **Mitigations:** `verifyAndLoad` loads via the fork's `LoadImageBuffer` from the
  exact buffer `Verify` checked (LoadImage SourceBuffer) — the firmware never
  re-reads the file, so verified bytes == executed bytes regardless of Secure Boot
  state (#46). Defense-in-depth: pre-boot is single-threaded with no concurrent
  ESP writer (assumption §5); under *enforcing* Secure Boot firmware revalidates
  the buffer.
- **Residual:** Low — physical/DMA modification of PBA memory between Verify and
  LoadImage (out of scope per threat-model assumptions); firmware's own buffer
  handling under SB-on (trusted, unchanged); `Verify` parser exposure tracked
  under R-009/#56.
- **Tests:** `TestVerifyAndLoadVerifiedBufferInvariant` (ordering + single-read +
  reassignment ban, mutation-verified). **Evidence:** `cmd/pba/main.go`
  `verifyAndLoad`; fork pinned in `go.sum` (`LoadImageBuffer` landed in
  `v1.6.2-tpba.2`; current pin `v1.6.2-tpba.3`, ADR-0008);
  `evidence/security-review-records/2026-06-10-chainload-verified-buffer-46.md`.

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
| 2026-06-08 | Phase 4 (Opal unlock library + simulator, ADR-0004): R-009 → Low (Opal response parsers fuzzed + fail closed); R-002/R-003 High → Medium (unlock flow fail-closed by construction, no secret logged) — both still pending boot-path wiring (Phase 5/6) and hardware (Phase 8); R-008 now sets MBRDone in the unlock flow. |
| 2026-06-08 | Phase 5 (UEFI Storage Security transport, ADR-0008): R-006 mitigations updated to cover the pinned first-party `walterchris/go-boot` fork (tag + go.sum, minimal additive patch). |
| 2026-06-10 | #51 item 1 (Phase 5/6 gate from the Phase 4 security review): R-003 Medium → Low — all client-side PIN-bearing buffers zeroized on success and all failure paths, append-reallocation guarded by a tested 64-byte grow budget; fd-level log-scrub test proves opal-layer silence and PIN-free error text (raw/hex/base64/decimal-slice), mutation-verified. Remaining residuals recorded (firmware/DMA-side copies §6.2, compiler dead-store assumption, transient register copies); console PIN-input zeroization stays open for the Phase 6 wiring (#51 item 2). |
| 2026-06-10 | R-012 Open → Mitigated (#46): `verifyAndLoad` chainloads from the verified in-memory buffer via the fork's `LoadImageBuffer` (pin bumped to `v1.6.2-tpba.2`), closing the SB-off verify-then-load TOCTOU; invariant test `TestVerifyAndLoadVerifiedBufferInvariant`; review record `evidence/security-review-records/2026-06-10-chainload-verified-buffer-46.md`. Imageverify fuzz follow-up noted under R-009 (#56). |
| 2026-06-10 | Phase 6 boot-path wiring (#22, #51 item 2, ADR-0009): R-002 mitigation extends from library to boot path — policy-gated `sed_unlock` (absence = required, explicit loud `none`), hard failure on missing Storage Security device, partial-unlock/any error → on-error action with no retry/fallback; residual stays Medium pending QEMU MockOpalDxe e2e + hardware. R-003: wiring holds no PIN copy (policy holder cleared, every path tested); MVP compiled-in-PIN residual recorded (binary-embedded JSON + decoder string copy, test-only credential, replaced before production). |
| 2026-06-10 | go-boot fork `v1.6.2-tpba.3` (#22, ADR-0008 Amendment 2026-06-10): R-006 mitigation wording corrected — the fork patch set is no longer "minimal additive": it carries one functional upstream-file edit (the `callFn` stack-alignment fix in `uefi/uefi.s`, latent upstream ABI bug, to be submitted upstream) alongside the additive files; SSC slot-dispatch fix + fail-closed NULL-slot check in the additive `storagesecurity.go`. R-012 evidence pin reference updated to the current tag. Review record: `evidence/security-review-records/2026-06-10-go-boot-tpba3-abi-fixes.md`. |
| 2026-06-10 | Phase 6 QEMU MockOpalDxe integration matrix (#22): R-002 QEMU e2e in place — six-scenario matrix (positive unlock-chainload/secure-boot tied to driver markers; negative auth-fail/fail-mbrdone/fail-after-unlock/no-driver with mutation-proven FORBIDs), real `mock-opal-integration` CI job, release-policy gate; residual stays Medium but narrows to hardware-pending (Phase 8) — local 6/6 + mutation proof in evidence, green CI run on the PR completes the runs-in-CI claim. Harness false-PASS (FORBID dead after final REQUIRE) found, fixed, self-tested. R-006/TB5 accepted sub-residual recorded: EDK2 cache verification is ref-level only. Review record: `evidence/security-review-records/2026-06-10-mock-opal-integration-matrix-22.md`. |
