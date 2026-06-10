# Security review record — mock-Opal QEMU integration matrix (#22, Phase 6)

- **Date:** 2026-06-10
- **Change under review:** branch `feat/phase-6-mock-opal-integration`
  (sedtest policy variant, fork pin bump to `v1.6.2-tpba.3`,
  `test/qemu/mock-opal-matrix.sh` + harness changes, release-policy gate,
  real `mock-opal-integration` CI job). Findings resolved in `b22811b`.
- **Reviewer:** independent security-review agent (did not implement). Subject:
  **test integrity** — this branch is the MVP's primary virtual integration
  test; a hole here means broken PBAs pass CI.
- **Verdict:** initially **BLOCK** (demonstrated false PASS); blocker fixed and
  mutation-proven; remaining findings resolved or recorded below.

## The blocker — demonstrated, fixed, and proven fixed

The reviewer **demonstrated** a false PASS: `expect-serial.py` stopped reading
the moment the last REQUIRE marker matched, so a fail-open PBA printing
`sed unlock failed` (the chronologically last REQUIRE in every negative
scenario) and then chainloading anyway passed all four negative scenarios —
the FORBID assertions were syntactically present but structurally dead. The
same shape affected the pre-existing negative suites.

**Fix (`b22811b`):** after the last REQUIRE, the harness keeps draining serial
for a bounded grace window (`EXPECT_GRACE`, default 8 s; timer-armed so
halted guests can't hang it), evaluating every FORBID over everything read,
and only then declares PASS.

**Proof, both directions:**
- A QEMU-free harness self-test (`test/qemu/harness-selftest.sh`, runs at the
  start of every matrix invocation) covers fail-open-then-halt,
  fail-open-then-EOF, clean-negative bounded by the grace timer, early-FORBID,
  and missing-REQUIRE. Re-introducing the buggy `break` makes the self-test
  fail exactly on the two fail-open cases.
- The reviewer's exact attack re-run end-to-end: a PBA mutated to log the
  unlock error and fall through to chainload now fails `auth-fail` with
  `FAIL: forbidden marker observed: TEST-APP: ok`; reverted, the scenario
  passes.

## What the review confirmed clean (refutation attempted, failed)

- **Marker integrity:** every REQUIRE/FORBID string cross-checked byte-for-byte
  against `MockOpalDxe.c` and `cmd/pba` sources — no typo'd never-firing
  FORBID; all regex-safe; pairwise substring-disjoint.
- **SB silent-skip countermeasure:** the Secure Boot scenario REQUIREs the
  driver's dispatch/auth/unlock/mbr-done markers, so a silently-skipped
  unsigned driver cannot false-pass.
- **Policy-variant hygiene:** the four embed files are mutually exclusive
  under every build-tag combination — the sedtest policy (with the shared-spec
  test credential `correct horse`, nothing new) cannot leak into a default
  build.
- **`none`-run guards:** catch both mixup directions without breaking
  legitimate runs.
- **Release gate:** `check-release-policy` parse logic correct (absent field =
  required passes, matching the product parser); wired unconditionally into
  release.yml; fails closed on malformed input. Future: assert release
  artifacts are built without test tags once the real release build exists.
- **`QEMU_DISK_IF=virtio`:** inert for existing suites; rationale (OVMF AtaBus
  installs a competing real SSC instance on IDE/SATA disks) documented.
- **go.sum:** computed pin verifies byte-identical against the published fork
  tag; no replace directives.

## Findings and resolution

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | BLOCKER | FORBID dead after final REQUIRE (false PASS demonstrated) | `b22811b` — grace-window drain + self-test + end-to-end mutation proof |
| 2 | BLOCKER (sequencing) | fork tag unpublished, matrix never run in CI | tag published (see fork tpba.3 record); CI run on this PR is the remaining proof |
| 3 | NIT | threat model / risk assessment / evidence not updated | compliance update + this record, same change set |
| 4 | NIT | secureboot-matrix scenarios lacked the unlock-outcome guards | `b22811b` |
| 5 | INFO | EDK2 cache verification is ref-level only (tampered tree with matching HEAD undetected); bounded by Actions same-repo cache scoping | accepted residual, recorded under R-006/TB5 |
| 6 | INFO | release gate is source-level | noted; artifact-level assertion when the real release build lands |

## MVP acceptance disposition

- Mock Opal unlock through the real UEFI protocol path in QEMU: **evidenced**
  (unlock-chainload + secure-boot scenarios, tied to driver markers).
- Refuses to boot the target when unlock fails: **evidenced** post-fix
  (mutation-proven FORBID on chainload markers across four failure shapes,
  including partial unlock).
- Runs in CI without hardware: design verified; the green
  `mock-opal-integration` run on this PR completes the claim.

R-002 disposition: QEMU end-to-end now in place — residual reduces to
hardware-pending (Phase 8) once CI is green on this PR.
