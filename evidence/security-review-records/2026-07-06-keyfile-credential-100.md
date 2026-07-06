# Security review — `keyfile` SED-unlock credential source (#100, A3)

- **Date:** 2026-07-06
- **Change:** branch `feat/keyfile-credential-100` (A3, issue #100). Lands ADR-0011 §4:
  the `keyfile` credential `Source` — reads the unlock seed from a file on the ESP /
  boot volume, behind an `Env.Files fs.FS` seam (so `internal/credential` stays
  UEFI-free; host tests use `fstest.MapFS`, tamago wires `x64.UEFI.Root()`). The twin
  of the A2 `console` source (#99): same `Source` abstraction, same single
  consume-once-zeroize contract (ADR-0009), differing only in *where* the secret comes
  from (file at rest vs. interactive entry). `policy` gains the `keyfile` source with a
  required `path` field (composes with `derive`); `cmd/pba` opens the ESP root once
  (fail-closed) and sets `env.Files`. `internal/opal` and `internal/transport` are
  untouched (ADR-0011 layering).
- **Origin:** ADR-0011 easy→hard rollout (Milestone 1); A3 is the third source after the
  A1 abstraction (#98) and the A2 interactive `console` source (#99), landing per
  ADR-0011 §5 "each new source is a unit of review."
- **Reviewers:** two independent reviews — **go-reviewer** (idiomatic-Go / correctness) and
  the adversarial **security-review-agent** (fail-closed / secret-hygiene); neither
  implemented the change.
- **Method:** read `internal/credential` (`keyfile`, the `Env.Files` seam, `Source`), the
  `sed_credential` `keyfile`/`path` schema in `internal/policy`, and the `cmd/pba` ESP-root
  wiring; traced every resolve/error path against the ADR-0011 §5 invariants; confirmed the
  single consume-once zeroization contract (ADR-0009) — the caller owns and zeroizes the
  returned key, `keyfile` zeroizes any buffer it holds on the error paths; diffed
  secret-hygiene behavior against the A2 source and `main`; ran the automated
  `qemu-keyfile-matrix` (POS + NEG).

## Verdict: APPROVE (within the already-Accepted ADR-0011)

Both reviews APPROVE. ADR-0011 is already **Accepted** (2026-07-06, via #99); A3 is a new
source *within* that accepted design, so it does **not** open a new ADR gate — its human
gate is the Security/Release Owner merging the A3 PR (#100) after the two independent
reviews below.

- **go-reviewer — APPROVE.** Idiomatic; the `fs.FS` seam is small and defined where consumed;
  errors wrapped (`%w`) and never ignored; the path is ESP-relative and validated by
  `io/fs.ValidPath` semantics (path traversal rejected). One **nit** raised —
  `validateSEDCredential` rejected a stray `pin` on `policy-pin`/`console` but not a stray
  `path` (now a known field, so `DisallowUnknownFields` no longer catches it) — **fixed in
  this branch** (reject a stray `path` on `policy-pin`/`console` too — symmetric per-source
  validation; + negative tests, commit `de04589`). No remaining blockers.
- **security-review-agent — APPROVE.** Fail-closed confirmed on all enumerated paths:
  nil `Env.Files` (no filesystem capability), read error, empty file, wrong-content key,
  missing file, no `path` configured, and a stray `pin`/`path` on the wrong source — each
  aborts to the policy `on_error` action and never chainloads, never falls back to a weaker
  source. Single consume-once zeroization (ADR-0009) intact — the resolved key is zeroized
  exactly once by the unlock caller; `keyfile` additionally `clear()`s any buffer it read on
  every error branch so a partial read never escapes un-scrubbed. The **read-error scrub is
  now mutation-proven** (`TestKeyFileResolveReadErrorScrubs`: a partial-read `fs.FS` captures
  the buffer `Resolve` reads into — it aliases `fs.ReadFile`'s — and asserts the scrub ran;
  dropping the `clear` turns the test red, matching the A2 console-source bar). No secret in
  errors — error text carries only the stage and the path (a path is not secret), never the
  key bytes; nothing logged. No secret-hygiene regression versus the A2 source or `main`.

## Findings

- **F-1 (residual — accepted, documented): key at rest on the volume.** Unlike the A2
  `console` source (no secret at rest), `keyfile` leaves the unlock seed **extractable from
  the ESP / boot volume** — a low-assurance, operational-simplicity source (ADR-0011 §4 /
  §Security Impact). It does **not** defend the evil-maid attacker (who can read the volume),
  and it does not lower the R-002/R-003 exposure the way `console` does. This is inherent to
  a file-backed credential and is documented, not a defect: `keyfile` is a **legitimate
  production source** and is therefore **NOT release-gated** (`policy.CheckReleaseReady` does
  not block it, unlike the debug-only `policy-pin`). The `keyfiletest` policy variant used by
  the QEMU matrix is tag-gated and does not ship. Tracked as the R-002 per-source residual;
  no rating change.
- **F-2 (deferred — tracked, not in A3): A4 derive-buffer zeroize hazard.** The
  `sedutil-pbkdf2` derivation stage (ADR-0011 §3, source A4) will hold intermediate
  seed/derived-key buffers that must be zeroized on every path — flagged since A2 so the A4
  PR lands with the scrub in place. Tracked on **#104**; out of scope for A3 (which returns
  the file bytes verbatim, no derivation). No A3 impact.

## Disposition

APPROVE. A3 is a security-critical behavior change (credential sourcing / Opal unlock flow)
but sits **within the already-Accepted ADR-0011** — no new ADR gate; the §5.3/§23 human gate
is satisfied by the Security/Release Owner merging the A3 PR (#100) after the two independent
reviews above. Both A3 review nits are fixed (validator stray-`path` symmetry; read-error
scrub now mutation-proven). The automated `qemu-keyfile-matrix` passes POS (key
`"correct horse"` → sed unlock ok → chainload) and NEG (wrong-content key → sed unlock
failed, fail closed). Advances R-002 / R-003 and the ADR-0011 easy→hard rollout; the final
Milestone-1 source is the `sedutil-pbkdf2` derive (A4, #104).
