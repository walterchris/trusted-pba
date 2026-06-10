# Security review record — chainload from verified in-memory buffer (#46)

- **Date:** 2026-06-10
- **Change under review:** two-part change closing the SB-off verify-then-load
  TOCTOU (threat model A.3, risk R-012):
  1. go-boot fork `github.com/walterchris/go-boot` tag **`v1.6.2-tpba.2`**
     (commits `e1bf9c5` + `c544446`): additive `uefi/loadimagebuffer.go` —
     `(*BootServices).LoadImageBuffer(root, name, buf)` calling
     EFI_BOOT_SERVICES.LoadImage with a caller-supplied SourceBuffer.
  2. Product branch `fix/phase-6-chainload-verified-buffer` (commits `171aecd`,
     `f19b178`): pin bump to `v1.6.2-tpba.2`; `cmd/pba` `verifyAndLoad` loads via
     `LoadImageBuffer` from the exact buffer `imageverify.Verify` checked;
     AST-level invariant test.
- **Reviewers:** independent security-review agent per part (neither implemented
  the change); separate idiomatic-Go reviews performed independently.

## Part 1 — fork patch review

**Verdict: PASS with findings — GO for tag `v1.6.2-tpba.2`.**

Verified: UEFI call argument order/types match EFI_BOOT_SERVICES.LoadImage
(UEFI 2.10 §7.4.1) and upstream's audited pattern; no file re-read anywhere in
the new path (device path built from metadata only); `parseStatus` surfaces every
non-success status including EFI_SECURITY_VIOLATION (never swallowed);
empty-buffer rejected (stricter than upstream); ADR-0008 additive-only policy
held (one new file, no upstream edits, no new ABI code). Dispositions: nil-root
panic = upstream-consistent dead stop (fail-closed, not attacker input);
`name`-matches-buffer is a documented caller contract enforced product-side;
firmware copies SourceBuffer during LoadImage, so no buffer pinning across
StartImage is needed. Recommended hardening (`runtime.KeepAlive` on both slices)
applied in `c544446` before the tag was cut.

## Part 2 — product-side review

**Verdict: PASS with findings (non-blocking).**

All three fork-review conditions verified met in `cmd/pba/main.go`
`verifyAndLoad`:

1. **Same buffer, same path:** `image` assigned exactly once from
   `fs.ReadFile(root, target)`, passed unmodified to `Verify` and
   `LoadImageBuffer`; `Verify` consumes it read-only (`bytes.Reader`); single
   `target` parameter feeds read, reporting, and device path.
2. **Failed load never used:** error path returns before `StartImage`, handle
   stored nowhere, propagates to `terminate()` (halt/reset); no fallback to the
   unverified path or firmware boot order.
3. **Nil-root guarded** (dead code against the current fork, kept as
   defense-in-depth with explanatory comment).

Pin verified end-to-end: `go mod verify` clean; module-cache origin hash =
fork tag commit `c544446`; `git archive` of the tag byte-identical to the module
cache; firmware-validated `load()` path confirmed byte-identical to main.

## Findings and resolution

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | NIT (both reviewers) | AST invariant test did not enforce ordering/single-read — re-read-after-Verify mutation escaped | `f19b178` — exactly-one-ReadFile, `token.Pos` ordering, reassignment ban; all three escapes mutation-verified failing |
| 2 | INFO | Test does not tie StartImage to the handle / chainload routing | covered behaviorally by QEMU pba-matrix reject tests |
| 3 | INFO | Nil-root guard dead code today | kept + comment (`f19b178`) |
| 4 | INFO | No `UnloadImage` on load failure (fork lacks wrapper); firmware pool leak | moot — every error path dead-stops/resets; revisit if fork grows `UnloadImage` |
| 5 | INFO | Pre-existing: no fuzz target for `internal/imageverify`; R-009 wording overclaims | follow-up issue #56 |

## Risk disposition

**R-012: Open → Mitigated.** Verified bytes are the bytes handed to firmware
regardless of Secure Boot state. Residual (Low): physical/DMA modification of
PBA memory between Verify and LoadImage (out of scope per threat-model
assumptions); firmware's own buffer handling under SB-on (trusted, unchanged);
`Verify` parser exposure tracked under R-009 / #56.
