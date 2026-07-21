# Security review — QEMU linux-boot matrix (real-OS chainload after SED unlock)

- **Date:** 2026-07-21
- **Change:** branch `feat/linux-boot-matrix`. Test tooling only — **no product
  code changed** (verified: only `ci.yml` + `Taskfile.yml` modified; all new files
  under `test/`):
  1. `test/fixtures/linuxinit/main.go` — static Go PID-1 for the matrix's
     initramfs (prints `TEST-LINUX: userspace ok` on serial, powers off).
  2. `test/qemu/build-linux-uki.sh` — real distro kernel + that initramfs +
     embedded `console=ttyS0,115200 panic=-1` cmdline → one UKI PE via ukify (a
     UKI because the PBA's chainloader passes no LoadOptions).
  3. `test/qemu/linux-boot-matrix.sh` + Taskfile `linux-boot-matrix` + CI
     `qemu-linux-matrix` — the unchanged `-tags sedtest` PBA chainloads the UKI
     staged at its existing target path after the MockOpalDxe unlock. POS
     (unlock → kernel → userspace), NEG auth-fail (the OS never boots), POS-SB
     (enforcing Secure Boot, throwaway per-run keys, db-signed driver+PBA+UKI →
     Linux userspace under enforcement). First real-OS end-to-end of the product
     claim. All scenarios PASS locally (2026-07-21).
- **Reviewers:** two independent reviews — **go-reviewer** (REQUEST CHANGES: two
  lint items, `errcheck` on `f.Close` and a justified `//nolint:gosec`; both
  applied, `golangci-lint` 0 issues) and the adversarial **security-review-agent**
  (initial **BLOCK**, final **APPROVE** after the required fix — below); neither
  implemented the change.

## The finding (empirically demonstrated) and its fix

**Finding 1 (High, assertion integrity):** the NEG's only fail-open detector was
the userspace marker — but a TCG kernel reaches userspace minutes after the last
REQUIRE, far outside `expect-serial.py`'s 8s FORBID grace window. A fail-open PBA
(logs `sed unlock failed`, chainloads anyway) would therefore **false-PASS**. The
reviewer reproduced the false-PASS via the harness's own `EXPECT_STUB` seam (exit
0 with the forbidden marker delayed 20s). The `harness-selftest.sh` comment
over-claimed: the self-test proves FORBID liveness only for markers whose latency
fits the grace window.

**Fix (required by the review, applied):** the NEG now FORBIDs the PBA's **early
chainload-side markers** (`TRUSTED-PBA: starting`, `TRUSTED-PBA: ESP opened`),
emitted within milliseconds of a fail-open chainload — inside the window; the
userspace marker stays as defense-in-depth; the comment now states the
grace-window precondition.

**Mutation proof (2026-07-21):** a deliberately fail-open sedtest PBA mutant
(logged the unlock failure, continued to chainload; never committed) was run
against the hardened NEG in QEMU — caught: `FAIL: forbidden marker observed:
TRUSTED-PBA: ESP opened`, exit 1. Product tree reverted and verified clean.

## Verdict: APPROVE (final)

Independently re-verified by the reviewer after the fix:
- The original false-PASS stub reproduction now **FAILs** on `ESP opened`
  (sub-second, before `starting` on the firmware-validation path).
- **No false-FAIL**: the `TRUSTED-PBA: starting` FORBID does not match the
  `TRUSTED-PBA: start` banner (line terminator breaks the substring); an honest
  fail-closed run stubs to PASS. The honest PBA returns before `Select()` on
  unlock error, so no chainload marker can legitimately appear in the NEG.
- POS assertion strength adequate (MOCKOPAL markers only occur in response to
  PBA-driven traffic; the UKI is not a BDS fallback path).
- POS-SB sound: `LoadImage(BootPolicy=FALSE)` under enforcing SB rejects an
  unsigned UKI → the userspace REQUIRE goes missing → FAIL; `sbsign` over the
  ukify PE covers the embedded kernel+initrd+cmdline — exactly the UKI integrity
  claim. Unsigned-rejection coverage stays with `secureboot-`/`pba-matrix`.
- No secrets committed (per-run throwaway SB keys; the PIN is the pre-existing
  shared-spec fixture credential). No ADR (no product behavior change).

## Residuals (non-blocking)

- **R-1 (accepted):** this NEG detects fail-open via the PBA's chainload markers;
  a mutant that fails open *and* silences those markers would evade it (the
  userspace marker is outside grace). A two-part deliberate evasion, not a
  plausible regression — and `mock-opal-matrix.sh` auth-fail still catches a
  silent chainload via the fast `TEST-APP: ok` fixture marker. Complementary
  coverage; no change.
- **R-2 (Low):** CI uses the ephemeral GitHub runner's own kernel (world-readable
  copy at a fixed /tmp path) — fine on hosted runners; add a caution if
  self-hosted runners ever run this job. The UKI content varies with the runner
  image (kernel path is logged; consider `uname -r` too).

## Threat-model / risk-assessment impact

- **R-002** strengthened: real-OS fail-closed evidence ("locked drive never boots
  an OS"), non-vacuous and **mutation-proven**.
- Threat-model **§9** FORBID-liveness row to be qualified with the grace-window
  precondition (handled in the companion compliance update).
- R-001 untouched; the fail-closed product path unchanged and re-confirmed.
