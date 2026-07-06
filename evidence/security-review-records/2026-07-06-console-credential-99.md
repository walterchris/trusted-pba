# Security review — `sed_credential` schema + interactive `console` source (#99, A2)

- **Date:** 2026-07-06
- **Change:** branch `feat/console-credential-99` (A2, issue #99). Lands ADR-0011 §1–§5:
  the `sed_credential` policy schema (replacing the bare `sed_pin` field) and the first
  interactive credential `Source` — `console` — reading the Admin1 secret from UEFI
  `SimpleTextInput` at boot with bounded retries and input-buffer zeroization. Follows A1
  (#98), which landed the `credential.Source` abstraction and routed the compiled-in PIN
  (`policy-pin`) through it. `internal/opal` and `internal/transport` are untouched
  (ADR-0011 layering).
- **Origin:** ADR-0011 easy→hard rollout (Milestone 1); A2 is the first real interactive
  source after the A1 abstraction.
- **Reviewers:** two independent reviews — **go-reviewer** (idiomatic-Go / correctness) and
  the adversarial **security-review-agent** (fail-closed / secret-hygiene); neither
  implemented the change.
- **Method:** read `internal/credential` (`Source`, `console`, `policy-pin`), the
  `sed_credential` schema in `internal/policy`, and the `cmd/pba` unlock wiring; traced
  every resolve/error path against the ADR-0011 §5 invariants; confirmed the single
  consume-once zeroization contract (ADR-0009) and the #51/#101 input-buffer scrub; diffed
  secret-hygiene behavior against `main`.

## Verdict: APPROVE (behind the ADR-0011 §5.3 human gate)

Both reviews APPROVE.

- **go-reviewer — APPROVE.** Idiomatic; interfaces small and defined where consumed;
  errors wrapped and never ignored. One **should-fix** raised — the console read loop
  busy-polled `SimpleTextInput` — **fixed in this branch** (yields between polls; commit
  `4ff91a2`). No remaining blockers.
- **security-review-agent — APPROVE.** Fail-closed confirmed on all ~10 enumerated
  paths (empty PIN, EOF/closed console, read error, retry-cap exhausted, absent
  `SimpleTextInput`, malformed `sed_credential`, unknown `source`, `policy-pin` in a
  release build, resolve error propagated to `on_error`, no fallback to a weaker source):
  each aborts to the policy `on_error` action and never chainloads, never retries into
  boot. Single consume-once zeroization (ADR-0009) intact — the resolved PIN is zeroized
  exactly once by the unlock caller. The console **error-path scrub** (the #101 carry-over
  from #51: input buffer cleared on every failure branch, not only success) is satisfied.
  `policy-pin` remains build-tag-gated and rejected by the release policy gate (§90). No
  secret-hygiene regression versus `main`.

## Findings

- **F-1 (process blocker — being closed by this record): missing compliance evidence.**
  The A2 code shipped with no security-review evidence record, no threat-model / risk-
  assessment update, and ADR-0011 still `Proposed`. Traceability (requirement → risk →
  design → test → evidence) was broken for a security-critical change (§7/§23). **Closed
  here:** this record, plus the threat-model A1-row + change-log update, the risk-assessment
  R-002/R-003 + change-log update, and ADR-0011 `Proposed → Accepted (2026-07-06)`.
- **F-2 (deferred — tracked, not in A2): A4 derive-buffer zeroize hazard.** The
  `sedutil-pbkdf2` derivation stage (ADR-0011 §3, source A4) will hold intermediate
  seed/derived-key buffers that must be zeroized on every path; flagged now so the A4 PR
  lands with the scrub in place. Tracked on **#104**; out of scope for A2 (which is `raw`
  only). No A2 impact.

## Disposition

APPROVE. This is a security-critical behavior change (credential sourcing / Opal unlock
flow), so it requires the ADR-0011 §5.3/§23 human gate: satisfied by the Security/Release
Owner merging the A2 PR (#99) after the two independent reviews above. F-1 closed in this
PR; F-2 deferred to #104. Advances R-002 / R-003 and the ADR-0011 easy→hard source rollout;
remaining Milestone-1 sources are `keyfile` (A3, #100) and the `sedutil-pbkdf2` derive
(A4, #104).
