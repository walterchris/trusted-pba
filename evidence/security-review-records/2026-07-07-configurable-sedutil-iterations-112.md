# Security review — configurable sedutil-pbkdf2 iterations + `auto` mode (#112)

- **Date:** 2026-07-07
- **Change:** branch `feat/configurable-sedutil-iterations-112` (issue #112; commits
  `2ede135` + `2856797`). Makes the `sedutil-pbkdf2` derive parameters (PBKDF2 iteration
  count + key length) policy-configurable via a new `sed_credential.derive_params` block —
  `{ "iterations": <int> | "auto", "key_len": <int> }` — with an `auto` mode that tries a
  fixed best-first candidate list. An **absent** `derive_params` keeps today's behavior
  **byte-for-byte** (derive once at 500000/32, one Unlock). Motivated by the A4b HW finding:
  the lab host's sedutil 1.20.0 provisioned drives at a different iteration count (75000)
  than the hardcoded 500000, so the derived key did not match → `NOT_AUTHORIZED`.
  1. `internal/opal/method.go` — exposes two method-status sentinels wrapping `ErrMethod`:
     `ErrNotAuthorized` (TCG `NOT_AUTHORIZED`, status `0x01`) and `ErrAuthLockedOut`
     (`AUTHORITY_LOCKED_OUT`, status `0x12`). `checkStatus` maps the two auth statuses so the
     auto loop can distinguish "wrong credential, advance" from "locked out, stop". Both use
     `fmt.Errorf("%w: …", ErrMethod, …)`, so `errors.Is(err, ErrMethod)` still holds; the
     `Unlock → startSession → checkStatus` chain already wraps with `%w`, so `errors.Is`
     reaches these sentinels end-to-end.
  2. `internal/credential/derive.go` — `SedutilPBKDF2(seed, salt, iterations, keyLen)` is now
     parameterized; `SedutilPBKDF2Iterations` (500000) / `SedutilPBKDF2KeyLen` (32) stay as
     the exported DEFAULT constants. Fails closed on empty seed, empty salt, non-positive
     iterations, or non-positive key length. SHA-512 unchanged.
  3. `internal/policy/policy.go` — `Credential` gains `DeriveParams *DeriveParams`
     (`{ Iterations IterationSpec; KeyLen int }`). `IterationSpec` is a JSON **union** with a
     custom `UnmarshalJSON`: a JSON number → `Count`; the exact string `"auto"` → `Auto`;
     anything else (other strings incl. a quoted number, bool, object, array) is a
     fail-closed error. A `present` flag distinguishes an explicit `0` (rejected) from an
     absent field (resolves to the default). `validateSEDCredential` rejects a stray
     `derive_params` on any non-`sedutil-pbkdf2` derive, an explicit `iterations` outside
     `1..100_000_000`, and an explicit `key_len` outside `1..64`. `ResolvedIterations()` /
     `ResolvedKeyLen()` return validated concrete values; the policy layer holds its own
     `defaultSedutilPBKDF2Iterations`/`KeyLen` constants (does **not** import
     `internal/credential` — ADR-0004 layering), with `2856797`'s
     `TestResolvedDerivDefaultsMatchCredentialConstants` pinning that the two stay in sync.
  4. `cmd/pba/sedunlock.go` — `unlockWithDerive` threads the resolved params. For `raw` and an
     explicit `sedutil-pbkdf2` count, derive once and attempt Unlock once (control flow
     identical to today). For `auto`, iterate `sedutilPBKDF2AutoIterations = [500000, 75000]`
     best-first: derive + attempt Unlock per candidate, advancing **only** on
     `opal.ErrNotAuthorized`, stopping closed on lockout / any other error / exhaustion. The
     salt (drive serial) is read once via the transport's optional `credential.Serialer`; every
     derived key is zeroized on every path; the winning count is logged only under the
     compile-time `hwdbg` gate.
- **Origin:** within ADR-0011 §3 — the derive parameters were already described there as
  "parameterized because sedutil versions differ", so making them policy-configurable is inside
  the **already-Accepted** ADR (no new ADR gate). §3 is extended (not re-decided) to document
  `derive_params`, `auto`, and the operator-must-know-the-count contract; Status unchanged.
- **Reviewers:** two independent reviews — **go-reviewer** (idiomatic-Go / correctness) and the
  adversarial **security-review-agent** (fail-closed / secret-hygiene); neither implemented the
  change.
- **Method:** read `method.go` (the two sentinels + `checkStatus` mapping), `derive.go` (the
  parameterized primitive + fail-closed guards), `policy.go` (the `DeriveParams` /
  `IterationSpec` union unmarshal + `validateSEDCredential` bounds + `Resolved*`), and
  `sedunlock.go` (`unlockWithDerive` and the auto trial loop); traced the `errors.Is` chain
  `Unlock → startSession → checkStatus`; ran the host unit tests (`internal/opal`,
  `internal/credential`, `internal/policy`, `cmd/pba`), `go vet`, `golangci-lint`, and the
  `!tamago` host + `tamago && amd64` default builds.

## Verdict: APPROVE (within the already-Accepted ADR-0011 §3)

Both reviews APPROVE. ADR-0011 is already **Accepted** (2026-07-06, via #99); #112 tunes the §3
`sedutil-pbkdf2` derive that A4a/A4b made functional and stays *within* that accepted design, so
it does **not** open a new ADR gate. The one required item the security reviewer raised is exactly
the threat-model / risk-assessment change-log recorded alongside this record.

- **go-reviewer — APPROVE (nits only, applied).** Idiomatic; the `IterationSpec` union unmarshal
  is the correct way to model a scalar-or-string JSON field; errors wrapped with `%w`; the
  `unlocker` interface (single `Unlock` method) is defined where consumed (accept interfaces).
  Nits applied in `2856797`: `strconv.Itoa(i)` replaces `string(rune('0'+i))` in the auto-loop
  zeroization assertions (correct past index 9), and `TestResolvedDerivDefaultsMatchCredentialConstants`
  guards that the policy-local defaults track the authoritative `credential` constants. No
  behavior change, no blockers.
- **security-review-agent — APPROVE.** Fail-closed and secret-hygiene confirmed on every new
  path (below); the one **required** item is the threat-model/risk-assessment change-log entry,
  which is the work recorded alongside this record.

## Fail-closed / correctness evidence (security-review-agent, refutation-verified)

- **`auto` advances ONLY on `NOT_AUTHORIZED`.** The loop `continue`s solely on
  `errors.Is(err, opal.ErrNotAuthorized)`; every other non-nil `err` returns immediately. A
  wrong iteration count is the only condition that consumes another candidate.
- **Lockout / any other error stops immediately and is never masked.** `AUTHORITY_LOCKED_OUT`
  (`opal.ErrAuthLockedOut`) and any transport/malformed error fall through the `NOT_AUTHORIZED`
  check and `return err` — the loop never advances past them, so a lockout can never be hidden
  by trying the next candidate. Attempted refutation (could a lockout be misclassified as
  NOT_AUTHORIZED?) fails: the two map from distinct status codes (`0x12` vs `0x01`) in
  `checkStatus`.
- **`errors.Is` chain intact through `Unlock → startSession → checkStatus`.** Each layer wraps
  with `%w`, and the sentinels are `fmt.Errorf("%w: …", ErrMethod, …)`, so `errors.Is` matches
  the sentinel through the full return path (`internal/opal` sentinel tests confirm).
- **Try-limit safety via best-first + bounded fixed list.** `[500000, 75000]` puts the common
  (lumentum/v1.15) count first, so the normal case authenticates on attempt #1 and burns no
  extra Admin1 try; the list is fixed and small, bounding worst-case try consumption.
- **F-2 zeroization on every path.** The consumed seed is scrubbed (deferred `clear(seed)`), and
  every derived key is `clear`ed on success, on retry (before the next candidate), on
  lockout/other-error return, and on exhaustion — the auto loop `clear(key)`s after each Unlock
  regardless of outcome (idempotent with Unlock's own zeroization).
- **Union unmarshal rejects all non-`{int,"auto"}`.** `IterationSpec.UnmarshalJSON` accepts only
  a JSON number or the exact string `"auto"`; other strings (incl. a quoted number `"500000"`),
  bools, objects, and arrays fail closed with a field-named error.
- **Validator bounds + explicit-0-vs-absent.** The `present` flag lets validation reject an
  explicit `iterations: 0` while an absent field resolves to the default; explicit values are
  bound-checked (`1..100_000_000` iterations, `1..64` key_len); a stray `derive_params` on a
  non-`sedutil-pbkdf2` derive is rejected.
- **Backward-compatible byte-identical.** With no `derive_params`, `ResolvedIterations()` returns
  `(500000, false)` and `ResolvedKeyLen()` returns `32`, so `unlockWithDerive` derives once and
  attempts one Unlock — the pre-#112 control flow and output bytes.
- **No secret/param leakage.** Errors carry only the failing stage (never the seed, key, or
  count); the winning iteration count is emitted only under the compile-time `hwdbg` gate, never
  in normal output.

## Findings / residual (both informational, non-blocking)

- **Iterations lower bound is `>0` with no floor.** An explicit `iterations: 1` would derive a
  weak credential, but this is acceptable under the compiled-in **trusted-policy** model — the
  policy is baked into the signed artifact and is not attacker-supplied, and the count must match
  what sedutil actually used (a too-low count simply fails to authenticate → fail closed). No
  minimum-strength floor is imposed.
- **MockTPer conflates wrong-PIN with lockout.** The host mock does not distinguish
  `NOT_AUTHORIZED` from `AUTHORITY_LOCKED_OUT` timing/state the way a real drive does, so the
  real-drive `NOT_AUTHORIZED`-vs-lockout ordering (does the drive return NOT_AUTHORIZED before it
  locks out, so `auto` can safely try the second candidate?) is an **R-010 / Phase-8 hardware**
  item. The auto loop's correctness is unit-tested against the sentinels; the real-drive timing
  is validated on hardware.

## Disposition

APPROVE. #112 is a security-relevant change (it tunes the SED unlock credential derivation and
adds a multi-attempt auto path) but sits **within the already-Accepted ADR-0011 §3** — no new ADR
gate. It is backward-compatible byte-for-byte when `derive_params` is absent; SHA-512 is unchanged;
`auto` advances only on `NOT_AUTHORIZED` and stops closed on lockout / other / exhaustion (never
masking a lockout, protecting the Admin1 try-limit via best-first); F-2 zeroization holds on every
path; the union unmarshal and validator are fail-closed. The operative residuals are the accepted
no-iterations-floor note and the **R-010** real-drive NOT_AUTHORIZED-vs-lockout timing (Phase 8).
No new trust boundary, no rating change (R-002 Medium, R-003 Low).

**Human gate (§5.3/§23):** because this changes the SED unlock credential-derivation behavior, the
human gate is the Security/Release Owner **merging the #112 PR** after the two independent reviews
above. This record documents the gate definition; the merge is the gate.
