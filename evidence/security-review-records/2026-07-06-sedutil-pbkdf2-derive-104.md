# Security review — `sedutil-pbkdf2` SED-unlock derive primitive (#104, A4a)

- **Date:** 2026-07-06
- **Change:** branch `feat/sedutil-pbkdf2-derive-104` (A4a, issue #104). Lands the verifiable
  core of ADR-0011 §3's `sedutil-pbkdf2` derivation stage:
  1. `internal/credential/derive.go` — the `SedutilPBKDF2(seed, salt)` primitive:
     `PBKDF2-HMAC-SHA512`, `500000` iterations, `32`-byte derived key, with the drive's
     20-byte serial as the salt. Fail-closed on empty seed / empty salt. Parameterized
     named constants (sedutil versions differ). `crypto/pbkdf2` stdlib — no new dependency.
     Adds an **optional `Serialer` capability** (`Serial() ([]byte, error)`) a transport MAY
     implement to supply the salt — discovered by type assertion, **NOT** part of
     `opal.Transport` (ADR-0004 layering unchanged).
  2. `cmd/pba/sedunlock.go` — reorders `unlockSED` to *resolve → selectSED → derive → Unlock*
     (the salt is the selected drive's serial, so `derive` must run after drive selection).
     `selectSED` now returns the selected transport alongside the client; `applyDerive` takes
     the transport, and for `sedutil-pbkdf2` reads the salt from its optional `Serialer`.
     `derive: raw` behavior is unchanged.
- **Origin:** ADR-0011 easy→hard rollout (Milestone 1); A4a is the final Milestone-1 item after
  the A1 abstraction (#98), the A2 `console` source (#99), and the A3 `keyfile` source (#100).
  Closes the A2/A3-tracked **F-2** derive-buffer zeroize hazard (`2026-07-06-keyfile-credential-100.md`).
- **Reviewers:** two independent reviews — **go-reviewer** (idiomatic-Go / correctness) and
  the adversarial **security-review-agent** (fail-closed / secret-hygiene); neither
  implemented the change.
- **Method:** read `internal/credential/derive.go` (the primitive, the constants, the empty-input
  guards, the `Serialer` capability) and the `cmd/pba/sedunlock.go` flow reorder; traced every
  derive/select/resolve path against the ADR-0011 §5 invariants; confirmed the KAT is
  non-vacuous by recomputing the vector with `python3 hashlib.pbkdf2_hmac` and mutation-checking
  that changing the hash or iteration count turns it red; confirmed seed + derived-key
  zeroization on the success and unlock-failure paths; ran the host unit tests
  (`internal/credential`, `cmd/pba`), `go vet`, `golangci-lint` (0 findings), and the
  `tamago && amd64` default + `sedtest` builds.

## Verdict: APPROVE (within the already-Accepted ADR-0011)

Both reviews APPROVE. ADR-0011 is already **Accepted** (2026-07-06, via #99); A4a is the
derive stage *within* that accepted design, so it does **not** open a new ADR gate — its human
gate is the Security/Release Owner merging the A4a PR (#104) after the two independent reviews
below. No ADR *status* change; a **factual correction** to ADR-0011 §3's parameters is part of
this change (see D-1).

- **go-reviewer — APPROVE.** Idiomatic; the primitive is a small first-party wrapper over
  `crypto/pbkdf2` + `crypto/sha512` with no UEFI/Opal dependency (credential material stays out
  of Opal protocol code, CLAUDE.md layering); `Serialer` is a 1-method optional capability
  defined where consumed; errors wrapped (`%w`) and never ignored. Two **nits** raised, both
  **applied in this branch** (commit `519511e`): wrap `crypto/pbkdf2.Key`'s error with `%w`
  (cross-layer consistency), and drop an aspirational "future config knob" comment for a knob
  that does not exist (Rule 2). No behavior change; KAT + zeroization tests unchanged. No
  remaining blockers.
- **security-review-agent — APPROVE.** Fail-closed confirmed on all enumerated paths:
  empty seed, empty salt, transport is **not** a `Serialer` (today's Storage-Security carrier),
  `Serial()` returns an error, and an unknown `derive` value — each aborts to the policy
  `on_error` action, **never sends a credential to the drive, never chainloads**, and never
  silently falls back to sending the raw seed. The **KAT is non-vacuous**: the expected output
  is recomputed independently via `python3 hashlib.pbkdf2_hmac('sha512', …, 500000, 32)`
  (bit-identical to sedutil's `cf_pbkdf2_hmac` + `cf_sha512`) and mutation-proven — flipping the
  hash to SHA-1 or the iteration count away from 500000 turns the test red. **F-2 closed:** the
  seed is scrubbed once consumed by the derive, the NEW derived key has its own deferred
  `clear()`, and `Unlock` zeroizes whichever slice it receives; both are proven zeroed on the
  success and unlock-failure paths (mutation-style tests). No secret in errors — messages carry
  only the stage / the "needs the NVMe-passthru carrier" note, never the seed or key bytes;
  nothing logged. No secret-hygiene regression versus A3/A2 or `main`.

## Findings

- **F-2 (closed — was deferred from A2/A3): derive-buffer zeroize hazard.** The
  `sedutil-pbkdf2` stage holds intermediate seed / derived-key buffers. A4a closes this: the
  derive consumes and `clear()`s the seed once it has derived the key, the caller wraps the new
  key in its own deferred `clear()`, and `Unlock` zeroizes it as well — the seed's own deferred
  clear then runs idempotently. Zeroization is proven on both the success and the unlock-failure
  paths. (Tracked as F-2 in `2026-07-06-keyfile-credential-100.md`; no longer open.)
- **D-1 (documentation — corrected in this change): ADR-0011 §3 parameters were stale.**
  ADR-0011 §3 stated the sedutil derivation as `PBKDF2-HMAC-SHA1(seed, salt = drive serial
  padded to 20, 75000, 32B)`. That is **wrong** — verified against the sedutil source in use.
  A4a corrects §3 to `PBKDF2-HMAC-SHA512`, `500000` iterations, `32`-byte key, salt = the
  drive's 20-byte serial, and notes the parameters are parameterized (sedutil versions differ)
  and that A4a KAT-verified them against sedutil's `cf_pbkdf2_hmac` + `cf_sha512`. Only §3's
  parameters change; the ADR **Status stays Accepted** and no other section changes.
- **N-1 (residual — accepted, documented): `crypto/pbkdf2.Key`'s `string(seed)` transient
  copy.** `crypto/pbkdf2.Key` takes the password as a `string`, so the seed is copied into an
  immutable Go string for the duration of the call; that transient copy cannot be zeroized. This
  is the **same class of unscrubable transient copy** as the transport / firmware / DMA buffers
  already documented (threat model §6.2, opal.Transport). **Decision: accepted** — keep
  first-party stdlib `crypto/pbkdf2` rather than promote `golang.org/x/crypto/pbkdf2` to a
  **direct** dependency of the credential path for a marginal gain (its `[]byte` password API
  would avoid the string copy). The caller's seed slice is still zeroized by the caller; only
  the returned derived key is under the primitive's control and is scrubbed. `x/crypto`'s
  `[]byte` API remains a possible future revisit if the residual is ever tightened. Documented
  in `derive.go` and in the `519511e` commit trail.

## Disposition

APPROVE. A4a is a security-critical behavior change (credential derivation / Opal unlock flow)
but sits **within the already-Accepted ADR-0011** — no new ADR gate; the §5.3/§23 human gate is
satisfied by the Security/Release Owner merging the A4a PR (#104) after the two independent
reviews above. Both go-reviewer nits are applied; the KAT is mutation-proven non-vacuous; F-2
(derived-key + seed zeroization) is closed; N-1 is an accepted, documented residual.
`opal.Transport` and `internal/transport` are untouched (ADR-0004 layering). No new dependency
(stdlib `crypto/pbkdf2`).

**A4a is fail-closed-until-A4b.** The `sedutil-pbkdf2` path derives the credential correctly but
needs the drive's real serial as the salt; today's Storage-Security carrier does not implement
`Serialer`, so a `sedutil-pbkdf2` policy **fails closed** (never sends a credential). The
NVMe-passthru carrier that supplies `Serial()` is **A4b** — the sedutil-pbkdf2 unlock is not
functional end-to-end until A4b lands and is validated on hardware. A4a is the KAT-verified,
host-testable core of the derivation, fail-closed on every path until then.
