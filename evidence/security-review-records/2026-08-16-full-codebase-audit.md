# Security review record — full-codebase audit (synthesis)

- **Date:** 2026-08-16
- **Scope:** full repository on `main` (HEAD `3612343`, post-Phase-6 + the complete
  ADR-0011 credential stack, NVMe-passthru carrier, `pba-override` trust broker, and
  the three QEMU matrices), including the pinned `walterchris/go-boot` fork
  (`v1.6.2-tpba.6`), `internal/tbstub`, `test/edk2-mock-opal/`, the QEMU harness, and
  the CI/release workflows.
- **Successor to:** `evidence/security-review-records/2026-06-11-full-codebase-audit.md`.
  The product Go roughly doubled since that audit (≈3268 insertions across
  `internal/`+`cmd/`); this pass re-verifies the June area and covers everything new.
- **Method:** five independent adversarial reviewers over trust-boundary clusters
  (image trust · SED unlock · credential/secrets · Secure Boot + trust broker ·
  supply-chain/CI), plus a deep Opal/transport pass — each mandated to *break*
  fail-closed with a concrete attack path and to report a confidence score, skipping
  anything already fixed or dispositioned in the June audit. Reporting threshold ≥0.7.

## Verdict

**No boot-path fail-open, no live secret-disclosure, no authorization-boundary defect.**
The core invariants held under adversarial review: dbx>db precedence, verify-before-load
(R-012), unlock-before-auth (R-002), fail-closed-on-error, and the gated trust broker
(R-014). One confirmed new **Medium** code defect (console secret-in-memory) is fixed in
this change; the remaining findings are release-pipeline / supply-chain hardening gaps
that are **latent** (no production release build exists yet — `release.yml` build/sign
steps are TODO placeholders).

## Findings & disposition

| # | Finding | Sev | Conf | Disposition |
|---|---|---|---|---|
| 1 | Console passphrase prefixes stranded in reallocated heap (`console_prompt_tamago.go`) — `append` from nil left un-scrubbed prefix copies; contradicts the A1/R-003 "zeroized on every path" claim | Medium | 0.90 | **FIXED here** (#124): pre-allocate to `maxPassphraseLen`, `TestPassphraseBufNoRealloc`, A1/R-003 wording corrected |
| 2 | Release gate validates the policy *file*, not the built artifact's build tags; the `policy-pin` source compiles into every build | High (latent) | 0.85 | Tracked — folded into **#90** with a concrete pre-implementation guard |
| 3 | GitHub Actions pinned by mutable tags (esp. `release.yml`, `arduino/setup-task`) | Medium | 0.70 | Tracked — **#121** (SHA-pin) |
| 4 | `PIN` redaction bypassable via `%#v`/`%d` (no live call site) | Low | 0.80 | Tracked — **#122** (`GoString()`) |
| 5 | go-boot NVMe `submit()` ignores the completion-queue status (verified not fail-open) | Low | 0.55 | Tracked — **#123** (next `-tpba` tag) |

### Finding 1 detail (fixed in this change)
`out` began nil and `out = append(out, ch)` reallocated the backing array at caps
1→2→4→…→128 as the operator typed; each superseded array held a passphrase *prefix* and
was never zeroized (the deferred `clear(out)` and the backspace scrub only touch the
current array). UEFI boot-services memory reaches the OS unscrubbed after
ExitBootServices, so a post-boot reader (compromised OS, crash dump, DMA, cold boot)
could recover most of the console passphrase — defeating the `console` source's
"no secret at rest" value. Fix: `newPassphraseBuf()` pre-allocates `make([]byte, 0,
maxPassphraseLen)`; the existing `len(out) >= maxPassphraseLen` guard bounds input to
128 bytes, so `append` never reallocates and one backing array holds every possible
passphrase — the single `clear()` scrubs all of it. Same stranded-secret class the opal
layer already guards with its grow-budget reservation (`TestStartSessionReserves`).

## Confirmed sound (refutation attempts that failed)

- **Image trust:** dbx-by-hash precedence before any trust decision; the sole `return
  nil` reached only after full validation (hash not revoked, signature binds leaf, leaf
  chains to db with `ExtKeyUsageCodeSigning`, no chain cert revoked); `ignoreValidity`
  preserves `Raw` so dbx `c.Equal` still matches; verified-buffer load (R-012); parser
  panic backstop (R-009) + asn1 recursion fix (go1.26.6).
- **SED unlock:** `Unlock` never returns nil without success statuses on StartSession +
  both Sets; spoofed-drive response parsers all length-bounded/panic-free (FuzzResponseParse
  3.5M execs clean); the #112 auto-loop is try-limit-safe (advance only on
  `NOT_AUTHORIZED`, stop on lockout/other); partial unlock is a hard error; June F-L2
  truncation fix holds; fork June F-L5 fixed.
- **Trust broker:** build-tag gate mutually-exclusive & exhaustive (non-trustbroker
  builds fail closed); enforcing-SB precondition independent of policy; verify-before-arm,
  arm-exactly-one-buffer, one-shot disarm + restore, asm-mutation-tested across all five
  stub branches; SB-disabled cannot be spoofed as enforcing (`Enforcing()` = SecureBoot
  && !SetupMode, detection failure folds to not-enforcing).
- **Policy/supply chain:** `Parse` fail-closed (`DisallowUnknownFields`, trailing-data
  check, closed enums, the `IterationSpec` union empirically fuzzed, explicit-0 vs
  absent); every conflicting build-tag combination is a hard `defaultJSON redeclared`
  compile error (no silent double-embed); TamaGo toolchain SHA-256-verified before use;
  fork content-pinned via `go.sum`, no `replace`/`GOINSECURE`; CI uses `pull_request` +
  `contents: read`, no untrusted interpolation into `run:`; real SAST/secret-scan/vuln/SBOM
  jobs with no false-green path.

## Below-threshold / hygiene notes (not blocking; captured for the record)

- **ADR-0012 doc drift:** its Security Impact text still describes a content-exact
  `memcmp` that the accepted ADR-0013 implementation replaced with pointer+size
  authorization — reconcile the ADR text (no security regression: a `memcmp` against the
  same retained buffer would not re-run Authenticode either).
- **`MockTPer` in the non-test `opal` package** (`mocktper.go`, no build tag) is linked
  into `trusted-pba.efi` — dead code, never instantiated in production (verified). Move to
  a `_test.go`/build tag for binary hygiene; not a fail-open.
- **`atomToken` silently wraps >8-byte integer atoms** — strictness nit, no attacker
  advantage (`syncSessionIDs` range-checks; the drive already controls those bytes).
- **`task deps`** references upstream `usbarmory/go-boot` though the fork is what builds
  (dropped by `mod tidy`) — process hygiene, not a TCB issue.
- **Duplicate JSON keys are last-wins** in the compiled-in policy — not fail-open (gate
  and boot path resolve identically); consider rejecting as anti-obfuscation.

## Reviews

- Five independent adversarial cluster reviews (security-review-agent) + a deep
  Opal/transport pass — all APPROVE at the boot-path level.
- Finding 1 fix reviewed independently: go-reviewer + security-review-agent (recorded on
  PR for #124).

## Threat-model / risk-assessment impact

- **R-003** wording corrected (A1 row + R-003 detail): the "zeroized on every path"
  claim now explicitly rests on the pre-allocation (finding 1).
- **R-004 / R-006** — findings 2 & 3 are concrete instances of the already-Open
  release/supply-chain residuals; no rating change (latent, no shipped artifact).
- **R-001, R-002, R-012, R-014** confirmed sound; no rating changes.
- **#91** (dbx-by-cert winning-chain scope) — **CLOSED by `fix/imageverify-dbx-full-bundle-91`
  (2026-08-16, HEAD `b40e038`):** `Verify` now checks dbx-by-cert against every cert in the
  signer's PKCS#7 bundle (`slices.ContainsFunc(certs, v.revoked)`), closing the revocation
  bypass where a stapled dbx-revoked intermediate `x509.Verify` routed around was never
  consulted; mutation-proven regression subtest `revoked bundled cert off the winning chain
  (#91)`. go-reviewer + security-review-agent both APPROVE; no ADR (tightens acceptance, no
  trust-decision change); R-001 residual stays Low. Review record
  `evidence/security-review-records/2026-08-16-imageverify-dbx-full-bundle-91.md`.
- Known-open items unchanged: **R-011** (trust-anchor staleness), **R-005** (rollback), the
  update pipeline (R-006), **#81** (selectSED heuristic), and the accepted `string(seed)`
  PBKDF2 transient.

No ADR triggered (finding 1 is a secret-hygiene fix, no behavior change to the trust or
unlock decision).
