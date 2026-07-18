# Fuzzing finding — `imageverify.Verify` panic on malformed PE (R-009)

- **Date:** 2026-07-18
- **Target:** `FuzzVerify` in `internal/imageverify` (`go test -fuzz=FuzzVerify`).
- **Where found:** nightly `deep-fuzz (./internal/imageverify, FuzzVerify)` job on
  `main` — GitHub Actions run **29632495833** (2026-07-18).
- **Issue:** #114.
- **Fix branch:** `fix/imageverify-parse-panic`.
- **Risk:** **R-009** (parser accepts / mishandles malformed input). Class:
  fail-closed / no-panic contract violation.
- **Severity:** **Low.** Availability / contract only — a crafted image crashed the
  verifier rather than returning `ErrParse`. A crash halts the PBA (fail-stop) and
  does **not** boot the untrusted image, so no trust bypass (no C/I impact); the
  defect is that it violates the documented no-panic / fail-closed contract
  (`internal/imageverify/fuzz_test.go`, baseline §12) and gives an attacker-supplied
  ESP image a pre-boot denial-of-service. Found pre-release; no shipped versions,
  so no CVD/advisory required (baseline §15).

## Finding

`internal/imageverify.(*Verifier).Verify` runs on attacker-controlled
PE/Authenticode/PKCS#7 bytes — an EFI image an attacker can place on the ESP for
the PBA to authenticate as second-stage trust broker (threat model §4, §6.3, TB2).

The fuzzer produced a malformed PE with an out-of-range size field that drove
`bytes.Buffer.Truncate` out of range **inside the third-party
`github.com/foxboron/go-uefi/authenticode` parser** (`checksum.go:179`, reached
from `verify.go:57`, i.e. `authenticode.Parse`). The parser **panicked** instead
of returning an error, so a malformed / attacker-supplied image crashed the
verifier rather than failing closed.

- **Affected component:** `github.com/foxboron/go-uefi`
  `v0.0.0-20251010190908-d29549a44f29` (pinned). Upstream parser bug; our fix is a
  defensive wrapper (we do not fork go-uefi for this).

## Root cause

`authenticode.Parse` / the go-uefi PKCS#7 path does not fully bounds-check PE size
fields before slicing/truncating, so specific malformed inputs panic. `Verify`
did not contain that panic, so it propagated up and would crash the PBA.

## Fix (branch `fix/imageverify-parse-panic`)

- `internal/imageverify/verify.go`: `Verify` now uses a named return
  (`err error`) and a `defer`/`recover()` that converts **any** panic from the
  go-uefi parse/verify path into an `ErrParse`-wrapped error
  (`"%w: panic parsing image: %v"`), so malformed input fails closed
  (do-not-boot) instead of panicking. **Hardening only** — no change to the trust
  decision itself, so **no new ADR** (baseline §23; the accept/reject logic is
  unchanged).
- Regression seed committed as a permanent corpus entry:
  `internal/imageverify/testdata/fuzz/FuzzVerify/30950a34c9c628dc` — the exact
  crashing input, so `go test ./internal/imageverify` replays it forever.

## Verification

- The crashing seed now passes (returns `ErrParse`, no panic).
- Full `internal/imageverify` package tests green.
- Fresh 30s `FuzzVerify` burst found no new crashers.
- `gofmt` / `go vet` / `golangci-lint` clean.

## Traceability

- **Requirement:** ER-2 (integrity of code/data), ER-10 (regular security testing —
  this finding is the fuzz process working as intended).
- **Risk:** R-009 (mitigation strengthened; residual stays **Low** — see
  `docs/compliance/risk-assessment.md`).
- **Threat model:** §4 entry points (PE/COFF+Authenticode parser), §6.3 malicious
  EFI application; change-logged in `docs/security/threat-model.md`.
- **Tests / evidence:** `FuzzVerify` + regression seed above; CI run 29632495833.
