# Trusted PBA — Risk Assessment

Living risk assessment per the
[compliance baseline §9](../compliance-and-secure-development-baseline.md). Pairs
with the [threat model](../security/threat-model.md) (adversaries, trust
boundaries, attack trees); this document quantifies and tracks each risk.

- **Status:** through **Phase 6** (Opal unlock wired into the boot path over the
  UEFI Storage Security transport and exercised end-to-end by the QEMU
  MockOpalDxe matrix — ADR-0004/0008/0009). Risks whose mitigations are not yet
  built (update pipeline, anti-rollback, signing/key management, hardware
  validation) are listed with their current (unmitigated/partial) standing and a
  *planned* mitigation.
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
| R-008 | MBRDone does not take effect until reboot | A7 | A/I | Medium | High | **Medium** | Partial — virtual e2e (Phase 6 mock matrix); hardware timing Phase 8 |
| R-009 | Opal/PE command parser accepts malformed response | A7/A6 | I/A | Medium | High | **Low** | Mitigated (parsers fuzzed, fail closed) |
| R-010 | QEMU tests pass but real SED differs | — | I/A | High | High | **Medium** | Open — Phase 8 |
| R-011 | Embedded trust anchors go stale (2011 CAs expire 2026-06-27) | A5 | I/A | High | High | **Medium** | Open — ADR-gated refresh |
| R-012 | TOCTOU: target re-read after verification (SB-off) | A6 | I | Low | High | **Low** | Mitigated (verified-buffer load, #46) |
| R-013 | Expired-but-valid signing key reused (expiry ignored) | A6 | I | Low | High | **Low** | Accepted — control is dbx; #48 |
| R-014 | `pba-override` Secure Boot override boots an out-of-`db` image | A2/A5/A6 | I/A | Low | High | **Low** | Gated — `-tags trustbroker` + explicit `pba-override` policy opt-in, off by default (not in release builds); fail-closed (enforcing-SB precondition + verify before arm, one-shot disarm); PCR-7 divergence characterized, scoped away from Windows/BitLocker (ADR-0012/0013; threat-model TB2/R-014). Accepted (ADR-0013, PR #88, 2026-07-05); independent security review recorded (evidence/security-review-records/2026-07-05-pba-override-trust-broker-82.md); #82 |

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
- **Tests:** `TestVerifyFailsClosed/*`, `TestVerifyAccepts`; `pba-matrix`
  (accept / unsigned-reject / **dbx-revoked-reject** end-to-end in QEMU — #37,
  mutation-proven, PBA-validation path); `secureboot-matrix` scenario **E**
  (firmware-validation path — the firmware's own Secure Boot engine rejects a
  **db-trusted** PBA image because its Authenticode hash is in **dbx**, proving
  **dbx > db** / revocation overrides trust; non-vacuous vs scenario B and a
  wrong-hash control — #18).
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
- **Credential source (ADR-0011, #98/#99/#100):** the secret is now **policy-selected**
  via `sed_credential` rather than a single compiled-in `sed_pin`. The `console`
  source (#99, A2) resolves an interactive secret from UEFI `SimpleTextInput` with
  **no secret at rest** (lowering exposure versus the compiled-in `policy-pin`, which
  is extractable from the image), caps retries then fails closed (no unbounded
  prompt/brute-force oracle), and never falls back to a weaker source. The `keyfile`
  source (#100, A3) reads the seed from a file on the ESP / boot volume (via an
  `Env.Files fs.FS` seam) — the secret is **at rest on the volume, extractable**, so
  it does **not** defend the evil-maid attacker (ADR-0011 §Security Impact); it fails
  closed on nil-`Files` / read-error / empty-file / missing-file / no-path, zeroizes
  the read buffer on every error path, and never falls back. `keyfile` is a legitimate
  production source and is therefore **release-eligible** — `CheckReleaseReady` does
  not block it (unlike `policy-pin`, which is build-tag-gated and rejected by the
  release policy gate #90). Every source is fail-closed on resolve failure →
  `on_error`, never chainload.
- **Derive stage (ADR-0011 §3, #104, A4a):** orthogonal to the source, an optional
  `derive` turns the resolved seed into the drive credential — `raw` (unchanged) or
  `sedutil-pbkdf2` (`PBKDF2-HMAC-SHA512(seed, salt = drive serial, 500000, 32B)`,
  KAT-verified vs sedutil's `cf_pbkdf2_hmac`+`cf_sha512`), which enables unlocking a
  default (hash-provisioned) drive. `unlockSED` derives after drive selection (the salt
  is the selected drive's serial, read via an optional `Serialer` capability;
  `opal.Transport` unchanged). Fail-closed on empty seed/salt, not-a-`Serialer`,
  `Serial()` error, and unknown derive — never sends a credential. The
  **NVMe-passthru carrier (A4b, #104)** now supplies the serial via `Serial()`
  (`credential.Serialer`), so `sedutil-pbkdf2` is **functional pending hardware
  validation**; `run()` selects that carrier **only** for the `sedutil-pbkdf2`
  derive (nil-`SEDCredential` guarded) and fails closed on zero carriers /
  unresolved handles / host build / `Serial()` error — no cross-carrier fallback,
  the raw/Storage-Security path unchanged. The operative residual is
  **R-010/R-007/R-008** (real-drive divergence; HW validation pending). The
  consumed seed and the new derived key are
  zeroized on every path (F-2 closed). **Accepted residual:** the `crypto/pbkdf2.Key`
  `string(seed)` transient copy is unscrubable — same class as the firmware/DMA
  transient copies (R-003 residual); kept first-party stdlib `crypto/pbkdf2` over
  promoting `x/crypto/pbkdf2` to a direct dep.
- **Residual:** Medium — narrows to **hardware-pending (Phase 8)**: local 6/6
  matrix runs plus the mutation proof are in evidence; the green
  `mock-opal-integration` CI run on the PR completes the runs-in-CI claim
  (pending at the time of writing). Real-drive divergence remains tracked under
  R-007/R-008/R-010. The `console` source is fail-closed on every resolve path (two
  independent reviews APPROVE, #99); **no rating change** — the unlock-before-auth
  invariant is structural and source-independent.
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
  pre-reservation budget — two regression tests pin it: `TestStartSessionGrowBudget`
  bounds the non-PIN overhead at ≤64, and `TestStartSessionReserves` asserts the
  reservation is actually performed at the real call site (deleting it turns the
  test red). A
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
  test-only and replaced by real auth before production (ADR-0009); the `console` source
  (#99, ADR-0011) avoids the binary-embedded-secret residual entirely — **no secret at
  rest**. **Console input-buffer scrub (landed):** the `console` source's read buffer is
  zeroized on **every** path — success and all failure branches (empty/EOF/read-error/
  retry-cap) — satisfying the #51/#101 obligation for interactive sources (#51 item 1
  closed the library layer, the Phase 6 wiring the policy-holder layer, and #99 the
  interactive-entry layer).
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
  the `walterchris/go-boot` fork (ADR-0008) pinned by tag (`v1.6.2-tpba.5`) +
  `go.sum` — its patch set over upstream v1.6.2 is additive files (incl. the
  `tpba.5` handle-aware Storage Security surface — `LocateHandleBuffer`/`FreePool`,
  `LocateStorageSecurityHandles`/`GetStorageSecurityByHandle`) **plus a few small
  functional edits to upstream files** (the `callFn` stack-alignment fix in
  `uefi/uefi.s`, the `path.go` device-path Length-underflow guard, and the
  `error.go` typed status errors; ADR-0008 Amendments 2026-06-10/06-11/06-28), each a
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
  mock reflects it in discovery); the Phase 6 QEMU MockOpalDxe matrix exercises
  MBRDone end-to-end against the EDK2 mock (#22) — `unlock-chainload` covers the
  full unlock + MBRDone + chainload path, and `fail-mbrdone` proves a failed
  MBRDone never reaches chainload (FORBID on chainload markers,
  mutation-proven). Real MBRDone timing/visibility on actual drives (in-session
  MBRDone) still needs hardware validation (Phase 8).
- **Residual:** Medium. **Tests:** `TestUnlockHappyPath` (asserts MBRDone set);
  `mock-opal-matrix` `unlock-chainload` + `fail-mbrdone`; hardware planned.

### R-009 — Opal/PE command parser accepts malformed response
- **Threat/path:** malformed device/image input drives the parser into an unsafe
  state or panic.
- **Mitigations:** PE/Authenticode + dbx parsing fail closed and never panic on
  attacker input (`ErrParse`; `stripAuth2` bounds-checked); policy parser fuzzed
  (imageverify fuzz target: #56).
  Opal response parsing (token/packet/discovery/method) now fails closed and is
  fuzzed (`FuzzResponseParse`), satisfying baseline §12.
  **`Verify` panic-to-error backstop (2026-07-18, #114, `fix/imageverify-parse-panic`):**
  nightly `deep-fuzz` (`FuzzVerify`, CI run 29632495833) found a malformed PE whose
  out-of-range size field panicked *inside* the third-party
  `go-uefi/authenticode` parser (`checksum.go:179` via `verify.go:57`) instead of
  returning an error. `Verify` now wraps the whole go-uefi parse/verify path in a
  `defer`/`recover()` that converts **any** panic into an `ErrParse`-wrapped error
  ("panic parsing image: …"), so a crafted image fails closed (do-not-boot) rather
  than crashing the PBA. Hardening only — the accept/reject decision is unchanged,
  so **no ADR**. The exact crasher is a permanent regression seed
  (`internal/imageverify/testdata/fuzz/FuzzVerify/30950a34c9c628dc`).
- **Residual:** Low — the panic backstop closes the last known
  fuzz-reachable crash in the trusted image parser; the residual is future go-uefi
  parser bugs, now bounded by both the recover backstop and the corpus.
  **Tests:** `TestStripAuth2Rejects`, `FuzzParse`,
  `FuzzResponseParse`, `TestTokenizeFailsClosed`, `TestDecodePacketFailsClosed`,
  `TestParseDiscoveryFailsClosed`, `TestVerifyFailsClosed/tampered`, `FuzzVerify`
  (+ regression seed `30950a34c9c628dc`).
  **Evidence:** `evidence/fuzzing-reports/2026-07-18-imageverify-fuzzverify-panic-R-009.md`.

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
  `v1.6.2-tpba.2`; current pin `v1.6.2-tpba.5`, ADR-0008);
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
| 2026-06-11 | Full-codebase audit (DRAFT record) test-evidence fixes: the R-003 grow-budget claim above is now backed by `TestStartSessionReserves` (pins that the reservation is actually performed at the real call site — F-M1), and the SyncSession status/HSN fail-closed guards gained mutation-proven negative tests (F-M2/F-L3, `TestUnlockFailsClosed`). No rating change; closes audit test-evidence gaps for R-002/R-003/R-009. |
| 2026-06-11 | go-boot fork `v1.6.2-tpba.4` (audit #11, ADR-0008 Amendment 2026-06-11): R-006 pin → tpba.4 and wording updated — the fork now carries a few small functional upstream-file edits (added: `path.go` device-path Length<4 underflow guard [F-L5], `error.go` typed status errors [F-L5/F-S3]) alongside the `uefi.s` alignment fix; F-S4 kept (audit false positive — the `dummy:` block is load-bearing for the assembler), F-S5 naming. QEMU mock-Opal matrix passes against the bump; published-tag hash verified. Review record: `evidence/security-review-records/2026-06-11-go-boot-tpba4-audit-followups.md`. |
| 2026-06-15 | R-001 test coverage (#37): `pba-matrix` gains an end-to-end **dbx-by-cert revocation** scenario (db-chaining, validly-signed target whose signer is revoked → rejected specifically by dbx; mutation-proven). Test-only + a mechanical build-tag refactor of the embedded-dbx source (pbatest substitutes a crafted test dbx; default/`trustfull` keep the full real Microsoft dbx — verified 431). No rating change; closes the revocation-coverage gap noted under R-001/R-011. |
| 2026-06-10 | Phase 6 wrap-up (#60 merged; epics #22/#19 closed): staleness refresh only. Status header updated from "through Phase 3" to coverage through Phase 6 (Opal unlock no longer in the "not yet built" list). R-008 updated: MBRDone is now exercised end-to-end against the EDK2 mock (`unlock-chainload` + `fail-mbrdone`, #22); status Open → Partial, residual stays Medium — real-drive in-session MBRDone timing remains the Phase 8 item. ADR-0009 Proposed → Accepted (§5.3/§23 human gate satisfied by the Release Owner merging #59). No rating changes. |
| 2026-06-16 | R-001 test coverage (#18, Secure Boot test matrix epic): `secureboot-matrix` gains scenario **E** — the **firmware's own** Secure Boot engine rejects a **db-trusted** PBA image whose Authenticode hash is in **dbx** (revocation overrides trust, **dbx > db**), closing the previously-missing firmware-validation-path revocation case (complementary to #37's PBA-path dbx coverage). Non-vacuous: scenario **B** (same image, no dbx entry) boots, **E** (its hash in dbx) is rejected ("Access Denied"), a wrong-random-hash **control** boots — so E rejects iff the matching hash is revoked, not from a malformed store; the Authenticode digest is computed by the new host helper via the SAME `go-uefi/authenticode` library `internal/imageverify` uses (one source of truth). Test-only; no product behavior change, no new threats. No rating change (residual stays Low). Review record: `evidence/security-review-records/2026-06-16-firmware-path-dbx-hash-revocation-18.md`. |
| 2026-06-28 | First real-hardware bring-up (Swissbit OPAL drive, 4-NVMe board; ADR-0009 Amendment 2026-06-28, Proposed): R-002 unlock path now **selects the Opal SED among multiple Storage Security carriers** — `transport.NewAll()` enumerates every `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` handle and `cmd/pba selectSED` picks the one whose Level-0 Discovery succeeds, then unlocks only that one. Fail-closed preserved and now **unit-tested**: `TestUnlockSEDSelectsResponsiveSED` (skips a carrier that fails Discovery, authenticates the responsive SED, PIN spent only on it) and `TestUnlockSEDNoResponsiveSEDFailsClosed` (no responsive carrier → hard error, nothing unlocked, PIN still consumed) — added in `c962b12`; the PIN is still consumed/zeroized exactly once on the selected device. The earlier "MediaId 0" hypothesis was **disproven** — MediaId 0 is correct (no `EFI_BLOCK_IO` derivation added). ComID byte-swap is a transport-layer conformance detail (firmware writes SP-Specific in the opposite byte order to the TCG ComID; `transport.swapComID` corrects it, the EDK2 mock mirrors it, host MockTPer unaffected) — not a security-model change. **Accepted residual:** targeting a *specific* drive among MULTIPLE Opal SEDs is a future refinement; today the first Discovery-responsive SED is taken, and a wrong-drive pick just fails auth → fail closed (never unlocks the wrong drive). No rating change (residual stays Medium, hardware validation now in progress). Review record: `evidence/security-review-records/2026-06-28-opal-hw-bringup-handle-select-comid.md`. |
| 2026-06-28 | go-boot fork `v1.6.2-tpba.5` (ADR-0008 Amendment 2026-06-28): R-006 pin → tpba.5. The bump adds the additive handle-aware Storage Security surface (`LocateHandleBuffer` + `EFI_LOCATE_SEARCH_TYPE` consts + `FreePool` slot `0x48`; `LocateStorageSecurityHandles`/`GetStorageSecurityByHandle`/`newStorageSecurity`) — no new upstream-file edit beyond the three carried since tpba.3/tpba.4. It also pulled new **indirect** deps into `go.sum` (the usbarmory stack: `gvisor`, `gliderlabs/ssh`, `arl/statsviz`, `armory-boot`, `go-net`, `x/term`/`x/time`/`x/exp`, etc.) — these are `// indirect` and **not reachable from the `tamago && amd64` `trusted-pba.efi` build graph** (reachability being verified separately); the #27 scan covers the fork's full transitive set. Published-tag `go.sum` hash recorded. No rating change. Review record: `evidence/security-review-records/2026-06-28-opal-hw-bringup-handle-select-comid.md`. |
| 2026-07-05 | **R-014 added** — `pba-override` Secure Boot trust broker (ADR-0012/0013, `-tags trustbroker`, #82 tasks 2–5): a gated validation mode installs a SHIM-style `EFI_SECURITY2_ARCH_PROTOCOL` override authorizing exactly the one PBA-verified buffer (pointer+size, one-shot disarm, restore) so an out-of-`db` image the PBA trusts loads under enforcing Secure Boot — making the PBA an authority for out-of-`db` images. Fail-closed (verify before arm; any error refuses to boot; absent the tag a `pba-override` entry fails closed); off by default (not in release builds). PCR-7 divergence characterized and scoped away from Windows/BitLocker. Rated Likelihood Low / Severity High / Residual **Low** given the gating + fail-closed design. **Accepted** (ADR-0013, PR #88 rebase-merged to `main` 2026-07-05, tip `5fc25fd`); independent security review recorded (`evidence/security-review-records/2026-07-05-pba-override-trust-broker-82.md`). Mirrors the threat-model 2026-07-05 change-log entry (TB2/R-014). |
| 2026-07-06 | **`keyfile` credential source added (#100, A3, ADR-0011 §4).** R-002/R-003 mitigation wording extended: a third `sed_credential` source, `keyfile`, reads the unlock seed from a file on the ESP / boot volume (via an `Env.Files fs.FS` seam; twin of the A2 `console` source). Fail-closed on nil-`Files` / read-error / empty-file / missing-file / no-path / wrong-source stray field; the read buffer is zeroized on every error path (read-error scrub **mutation-proven**), errors carry only the path (never the key bytes), single consume-once-zeroize invariant unchanged. **Per-source residual:** the seed is **at rest on the volume, extractable**, and does **not** defend the evil-maid attacker (ADR-0011 §Security Impact) — a low-assurance source; it is **release-eligible** (`CheckReleaseReady` does not block it, unlike `policy-pin`), being a legitimate production source. R-002's unlock-before-auth invariant is structural and source-independent. Two independent reviews (go-reviewer + security-review-agent) APPROVE; both nits fixed (validator stray-`path` symmetry; read-error scrub mutation-proven). Automated `qemu-keyfile-matrix` POS+NEG passes. **No rating change** (R-002 Medium, R-003 Low). Within the already-Accepted ADR-0011 (no new ADR gate); `internal/opal`/`internal/transport` untouched. Final Milestone-1 source: `sedutil-pbkdf2` derive (A4, #104). Review record: `evidence/security-review-records/2026-07-06-keyfile-credential-100.md`. |
| 2026-07-06 | **`sedutil-pbkdf2` derive primitive (#104, A4a, ADR-0011 §3).** R-002/R-003 mitigation wording extended with the derive stage: `SedutilPBKDF2(seed, salt)` = `PBKDF2-HMAC-SHA512(seed, salt = drive serial, 500000, 32B)`, KAT-verified (recomputed via python `hashlib`, mutation-proven) against sedutil's `cf_pbkdf2_hmac`+`cf_sha512`, enabling unlock of a default (hash-provisioned) drive. `unlockSED` reordered to *resolve → selectSED → derive → Unlock* (salt = selected drive's serial via an optional `Serialer`; `opal.Transport` unchanged). Fail-closed on empty seed/salt / not-a-`Serialer` / `Serial()` error / unknown derive — never sends a credential; today's Storage-Security carrier is not a `Serialer`, so `sedutil-pbkdf2` fails closed until the NVMe-passthru carrier (A4b). **F-2 closed** — consumed seed + new derived key zeroized on success and unlock-failure paths (mutation-style tests). **Accepted residual (R-003 class):** the `crypto/pbkdf2.Key` `string(seed)` transient copy is unscrubable (same class as firmware/DMA copies); kept first-party stdlib `crypto/pbkdf2` over promoting `x/crypto/pbkdf2` to a direct dep. Two independent reviews (go-reviewer + security-review-agent) APPROVE; go-reviewer nits applied. Within the already-Accepted ADR-0011 (no new ADR gate; §3 parameters corrected from the stale SHA-1/75000 sketch, Status unchanged). **No rating change** (R-002 Medium, R-003 Low) — the unlock-before-auth invariant is structural and derive-independent; not functional end-to-end until A4b + hardware validation. `internal/opal`/`internal/transport` untouched. Review record: `evidence/security-review-records/2026-07-06-sedutil-pbkdf2-derive-104.md`. |
| 2026-07-06 | **NVMe-passthru Opal transport carrier (#104, A4b, ADR-0011 §3 / ADR-0008 tpba.6).** R-002/R-003 derive bullet extended: a **second `opal.Transport` carrier** — the NVMe-passthru carrier over `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` (NVMe Security Send/Receive) — now supplies the drive serial via `Serial()` (`credential.Serialer`, the first transport implementing it), so the A4a `sedutil-pbkdf2` derive moves from fail-closed to **functional pending hardware validation**. `cmd/pba run()` selects it **only** for the `sedutil-pbkdf2` derive (nil-`SEDCredential` guarded); fail-closed on zero carriers / unresolved handles / host build / `Serial()` error, **no cross-carrier fallback**, the proven raw/Storage-Security path unchanged (default constructor untouched). NO ComID byte-swap (native NVMe order, deliberate divergence documented in code). ADR-0004 layering preserved (`internal/transport` does not import `internal/credential`; `Serialer` assertion in the test file). The operative residual is **R-010/R-007/R-008** — end-to-end is not provable off-hardware (the `tamago && amd64` carrier cannot run host-side; real-drive Opal-session-over-NVMe + Identify-Controller-salt correctness need the Swissbit / multi-NVMe board; the known HW Discovery0 IF-RECV `EFI_DEVICE_ERROR` finding is directly relevant). Two independent reviews (go-reviewer + security-review-agent) APPROVE; within the already-Accepted ADR-0011 (no new ADR gate). **No rating change** (R-002 Medium, R-003 Low). Review record: `evidence/security-review-records/2026-07-06-nvme-passthru-carrier-104b.md`. |
| 2026-07-06 | **`sed_credential` schema + interactive `console` source (#99, A2, ADR-0011).** R-002/R-003 mitigation wording updated: the unlock secret is now **policy-selected** via `sed_credential` (`policy-pin` compiled-in debug — build-tag-gated + release-gated; or `console` — interactive UEFI `SimpleTextInput`, **no secret at rest**, bounded retries then fail closed, input buffer zeroized on every path #51/#101). Follows A1 (#98, the `credential.Source` abstraction). The `console` source **lowers R-003 exposure** versus the compiled-in PIN (no binary-embedded/extractable secret) and is fail-closed on every resolve path; R-002's unlock-before-auth invariant is structural and source-independent. Two independent reviews (go-reviewer + security-review-agent) APPROVE — fail-closed on all ~10 paths, single consume-once zeroization intact, console error-path scrub satisfied, no regression vs `main`. **No rating change** (R-002 Medium, R-003 Low). `internal/opal`/`internal/transport` untouched. A4 `sedutil-pbkdf2` derive-buffer zeroize hazard tracked on #104 (out of A2 scope). Review record: `evidence/security-review-records/2026-07-06-console-credential-99.md`. |
| 2026-07-18 | **R-009 — `imageverify.Verify` panic-to-error backstop (#114, `fix/imageverify-parse-panic`).** The nightly `deep-fuzz (./internal/imageverify, FuzzVerify)` job on `main` (GitHub Actions run 29632495833) found a malformed PE with an out-of-range size field that panicked *inside* the third-party `go-uefi/authenticode` parser (`bytes.Buffer.Truncate` out of range at `checksum.go:179`, reached from `verify.go:57`) instead of returning an error — a fail-closed / no-panic contract violation (the contract stated in `fuzz_test.go` and baseline §12). `Verify` now uses a named return + `defer`/`recover()` that converts **any** panic from the go-uefi parse/verify path into an `ErrParse`-wrapped error ("panic parsing image: …"), so a crafted attacker-supplied ESP image fails closed (do-not-boot) rather than crashing the PBA. The exact crasher is committed as a permanent regression seed (`internal/imageverify/testdata/fuzz/FuzzVerify/30950a34c9c628dc`); crasher passes, package tests green, fresh 30s `FuzzVerify` burst clean, gofmt/vet/lint clean. **Severity Low** — a crash still fails closed w.r.t. booting untrusted code (no C/I bypass), the impact is a pre-boot availability/DoS and the contract violation; found pre-release, no shipped versions ⇒ no CVD/advisory (baseline §15). **Hardening only, no change to the trust decision ⇒ no ADR** (baseline §23). **No rating change** (R-009 residual stays Low; mitigation strengthened). Evidence: `evidence/fuzzing-reports/2026-07-18-imageverify-fuzzverify-panic-R-009.md`. |
| 2026-07-05 | **R-001/R-004 — release policy gate broadened (#90).** The release-only gate (`policy.CheckReleaseReady`, run by `release.yml`) previously blocked only `sed_unlock:"none"`; a release built from the dev default (`require_secure_boot:false` + firmware-mode `EFI/TEST/…` target) would have booted any ESP image with Secure Boot off (firmware mode does no PBA-side validation). The gate now also requires enforcing Secure Boot (an *absent* `require_secure_boot` is treated as unsafe — the opposite default from `sed_unlock`) and rejects a test-fixture target (normalized against `\`/`.`/`//`/leading-`/` variants). Reduces the R-001/R-004 release-time residual; no rating change (residual was already Low; boot path and dev-build behavior unchanged, PR CI unaffected — the gate runs only at release). Table-tested (`TestCheckReleaseReady`); independent security review APPROVE. Review record: `evidence/security-review-records/2026-07-05-release-gate-hardening-90.md`. |
