# Security review record — PBA-path dbx revocation test + dbx-embed refactor (#37)

- **Date:** 2026-06-15
- **Change under review:** branch `feat/sb-target-revocation-37` (commits
  `a77d36f` trust-store dbx-embed refactor + `9d784ab` test). Adds an end-to-end
  **dbx-by-cert revocation** scenario to `pba-matrix`, and build-tag-selects the
  embedded dbx source so the `pbatest` build substitutes a crafted test dbx.
- **Reviewer:** independent security-review agent (did not implement). Verified by
  build, by test, and by source — not by reading the implementer's claims.
- **Verdict:** PASS (no blockers; two INFO findings, both addressed/benign).

## The critical invariant — confirmed three ways

**No production/release build can embed the test dbx** (which would shrink the
revocation set to a single test cert):

1. **Build-tag algebra is gap-free and conflict-free.** `embed_windowsonly.go`
   (`!trustfull && !pbatest`) and `embed_full.go` (`trustfull && !pbatest`) embed
   the real dbx; `embed_pbatest.go` (`pbatest`) embeds the test dbx. Every tag
   combination resolves to exactly one `dbxUpdateBytes()` (incl. `pbatest+trustfull`
   → pbatest only, since both production files carry `!pbatest`). The test embed is
   unreachable in any non-`pbatest` build.
2. **Production builds load the full real revocation set.** `TestLoad` reports 431
   dbx hashes for both windows-only and `trustfull`; both compile and parse the
   real `materials/dbx/dbx-amd64.bin` (untouched vs main; sha256 matches PROVENANCE).
3. **`pbatest` is test-only and cannot ship.** Set only via `EXTRA_TAGS:
   ",pbatest"` in the one QEMU test task; not in the default `BUILD_TAGS`. A clean
   checkout cannot even build `pbatest` — `testdata/` tracks only `.gitignore`, so
   the test embeds fail to compile without the generated material.

## Non-vacuousness — confirmed

- The crafted test dbx round-trips through the **real** `parseDBX` → 0 hashes, 1
  CERT_X509 that `.Equal`s the leaf `L` (GUID/stripAuth2 offsets correct).
- The revoked fixture is validly signed by `L` (codeSigning EKU, chain embedded);
  `pe.Verify(L)` succeeds, then `revoked(L)` → `ErrRevokedCert` **before** the
  db-chain build — so rejection is specifically dbx-by-cert, not no-signature or
  untrusted (the three `pba-matrix` scenarios show distinct reasons).
- **Mutation proof** (implementer + reviewer + this record's author independently):
  neuter `revoked()` → the revoked target is accepted (`pba-verified` fires) and
  the scenario FAILs. The FORBID `pba-verified` marker is load-bearing.
- `Load`/`parseDBX`/`stripAuth2` are byte-identical for real builds (only the
  embed source moved); `imageverify` and `cmd/pba` untouched; no key material
  committed.

## Findings

| # | Severity | Finding | Disposition |
|---|----------|---------|-------------|
| INFO-1 | INFO | `embed_pbatest.go` uses bare `//go:build pbatest` (not `pbatest && !trustfull`) | Safe — production files carry `!pbatest`, so no double-embed is possible; `pbatest` always wins. No change. |
| INFO-2 | INFO | Threat-model / risk-assessment edits were uncommitted working-tree changes | Committed with the branch (this change ships with its §10/§23 doc update). |

## Risk disposition
- **R-001** strengthened: end-to-end QEMU dbx-by-cert revocation negative; residual
  Low unchanged. **R-011:** the full 431-entry real dbx remains embedded in
  production builds — the refactor does not shrink the shipped revocation set.
- No product behavior change; mechanical build-tag refactor + test-only material.
  No ADR/§5.3 human-gate trigger.
