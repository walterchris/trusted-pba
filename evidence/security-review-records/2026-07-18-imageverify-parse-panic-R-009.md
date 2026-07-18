# Security review — `imageverify.Verify` panic-to-error backstop (#114, R-009)

- **Date:** 2026-07-18
- **Change:** branch `fix/imageverify-parse-panic` (issue #114). Fixes a fail-closed
  defect the nightly `deep-fuzz (./internal/imageverify, FuzzVerify)` job found on
  `main` (GitHub Actions run 29632495833):
  1. `internal/imageverify/verify.go` — `(*Verifier).Verify` now uses a named return
     `(err error)` and a leading `defer`/`recover()` that converts **any** panic from
     the go-uefi PE/Authenticode/PKCS#7 parse/verify path into an `ErrParse`-wrapped
     error (`"panic parsing image: …"`). A malformed PE with an out-of-range size
     field drove `bytes.Buffer.Truncate` out of range **inside** the third-party
     `github.com/foxboron/go-uefi/authenticode` parser (`checksum.go:179`, reached
     from `verify.go:57`), panicking instead of returning an error; the backstop makes
     an attacker-supplied ESP image fail closed (do-not-boot) rather than crash the PBA.
  2. `internal/imageverify/testdata/fuzz/FuzzVerify/30950a34c9c628dc` — the exact
     crasher committed as a permanent regression seed.
- **Origin:** the no-panic / fail-closed contract stated in
  `internal/imageverify/fuzz_test.go` and compliance baseline §12, tracked as risk
  **R-009**. Hardening only — the accept/reject trust decision is unchanged, so **no
  ADR** (baseline §23).
- **Reviewer:** independent **security-review-agent** (adversarial fail-closed / trust-path
  review); it did **not** implement the change.
- **Method:** read the full `internal/imageverify/verify.go` as changed and
  `fuzz_test.go` (the contract); reasoned through the named-return + `recover()`
  semantics for every return path; grepped the pinned go-uefi module
  (`v0.0.0-20251010190908-d29549a44f29`, packages `authenticode`, `pkcs7`, `efi/util`,
  `efi/signature`, `pecoff`) for goroutine launches in the parse path; reproduced the
  crasher against the **unpatched** code to confirm the panic is synchronous within
  `Verify`'s frame; confirmed the patched seed passes, package tests green, `go vet`
  clean.

## Verdict: APPROVE — safe to merge as fail-closed hardening

The reviewer actively tried to find a path that lets an untrusted image through or
still crashes the PBA and could not.

- **Every panic fails closed.** `fmt.Errorf` is always non-nil, so a recovered panic
  always yields a non-nil error (do-not-boot). The only `nil` return is the fully
  validated success path, which runs synchronously to completion before the deferred
  `recover()` sees no panic — a panic can only *replace* the return with `ErrParse`,
  i.e. turn a crash into a rejection, never a rejection into an accept.
- **No goroutine-escape.** The pinned go-uefi parse path launches no goroutines, so
  the panic is synchronous within `Verify`'s frame and the `defer`/`recover()` catches
  it (confirmed by the unpatched-code stack trace).
- **No shadowing hazard.** The top-level `pe, err := authenticode.Parse(...)` reuses
  the named return; inner block-scoped `err` shadows are irrelevant because the recover
  writes the named return directly.
- **Rest of `verify.go` unchanged and sound:** dbx-by-hash precedence, leaf-then-chain
  dbx-by-cert, required `ExtKeyUsageCodeSigning`, and fall-through to `ErrUntrusted`
  are all intact; `ignoreValidity`'s shallow copy preserves `Raw` so `revoked()`'s
  raw-DER `Equal` still matches DBXCerts.

## Findings (all non-blocking)

- **F-1 (Low, residual):** the backstop's guarantee is coupled to go-uefi being
  goroutine-free; a future dependency bump that introduces a parser goroutine would let
  a panic escape this `recover`. Recommend the go-uefi pin-bump checklist (ADR-0008 /
  threat-model §6.6) add a "no new goroutine in the parse path" check. Tracked under
  R-009's residual.
- **F-2 (Informational):** `recover()` does not catch fatal runtime conditions
  (OOM, stack overflow from unbounded parser recursion). Pre-existing, out of scope for
  this change; image size is bounded by the caller-loaded ESP buffer. Tracked under
  R-009's "future go-uefi parser bugs" residual.

## Threat-model / risk-assessment confirmation

threat-model §6.3 (malicious EFI application), §4 entry-point (PE/COFF+Authenticode
parser), TB2 (PBA → attacker-controlled second-stage image), §9 test mapping, and
risk-assessment R-009 are all consistent with the code as it now stands. Residual
stays **Low**; the accept/reject decision is unchanged ⇒ no rating change, no ADR.
