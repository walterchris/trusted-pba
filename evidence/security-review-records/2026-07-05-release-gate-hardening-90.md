# Security review — release policy gate hardening (#90, PR #95)

- **Date:** 2026-07-05
- **Change:** branch `fix/release-gate-hardening-90` (PR #95). Broadens the release-only
  policy-safety gate so an unsafe default boot policy cannot silently reach a release
  artifact: adds `policy.CheckReleaseReady`, a host runner `cmd/release-policy-check`, and
  wires it into `Taskfile.yml`/`release.yml`.
- **Origin:** the 2026-07-05 Secure Boot chain security review — the one finding above
  defense-in-depth.
- **Reviewer:** independent security-review-agent (adversarial; did not implement the change).
- **Method:** read `CheckReleaseReady`/`isTestFixturePath`, the runner, the test, and the
  Taskfile/release.yml wiring; ran `go test ./internal/policy/` and exercised
  `go run ./cmd/release-policy-check` against crafted safe/unsafe/edge-case policies to
  confirm exit codes; traced the boot-path resolution in go-boot `v1.6.2-tpba.5`.

## Verdict: APPROVE (safe to merge)

Closes the #90 gap for the real release flow: the committed dev default is blocked on all
three counts (Secure Boot not required, `sed_unlock:"none"`, `EFI/TEST/…` target); a
production-safe policy passes. The runner is strictly fail-closed — missing file, directory,
malformed JSON, empty entries, and empty file all exit non-zero (Parse runs before the
release check). An *absent* `require_secure_boot` parses to false and is treated as unsafe.
`CheckReleaseReady` is called only from the host tool, never from the boot path — no runtime
or dev-default behavior change. The test is non-vacuous / mutation-resistant.

## Findings

- **LOW — `isTestFixturePath` missed path-normalization equivalents** of the fixture
  (`./EFI/TEST/…`, `/EFI/TEST/…`, `EFI//TEST//…`, backslashes) that the boot path would
  resolve to the same file. Bounded (the gate defends a committed, reviewed artifact, not
  attacker input) but a benign path edit could defeat a defense-in-depth gate.
  **Resolved in this PR:** `isTestFixturePath` now normalizes (`\`→`/`, `path.Clean("/"+p)`,
  uppercase) before the prefix match; the four variants are added to `TestCheckReleaseReady`
  as expected-block cases and confirmed exit=1.

- **Hardening (non-blocking, deferred):** a positive production-path allow-list would be
  stronger than the `EFI/TEST/` denylist (other non-production targets still pass). Accepted
  as-is because the gated file is committed and reviewed.

- **Compliance completeness (addressed in this PR):** threat-model **TB4** and the
  risk-assessment change log now reflect the broadened gate (previously "planned").

## Disposition
APPROVE with the LOW finding fixed in-PR. No ADR required — this hardens an existing gate
rather than changing security-critical boot behavior. Advances TB4 / R-001 / R-004.
