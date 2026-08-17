# Security review — dbx-by-cert revocation across the whole signing bundle (#91, R-001)

- **Date:** 2026-08-16
- **Change:** branch `fix/imageverify-dbx-full-bundle-91` (issue #91), HEAD `b40e038`.
  Closes a **revocation bypass** (fail-open) on the pba-mode image-acceptance path:
  1. `internal/imageverify/verify.go` — `(*Verifier).Verify` now checks dbx-by-cert
     against **every** certificate in the signer's PKCS#7 bundle
     (`slices.ContainsFunc(certs, v.revoked)`), not only the leaf plus the certs on
     the chain(s) `x509.Verify` returns. The per-chain revocation loop is **retained**
     — it uniquely covers a dbx-revoked `db` root, which is not part of the bundle.
     Doc-comment updated to state that the whole bundle / resolved chain / db root are
     all consulted.
  2. `internal/imageverify/verify_test.go` — new subtest
     `TestVerifyFailsClosed/"revoked bundled cert off the winning chain (#91)"`.
- **The gap (R-001):** a signer can staple an extra intermediate into the PKCS#7
  bundle that `x509.Verify` routes around when a cross-signed or otherwise alternate
  path to `db` exists — so `x509.Verify`'s winning chain (e.g. `[leaf, root]`) never
  includes that intermediate. If that stapled intermediate is dbx-revoked, checking
  only the leaf + the returned chain(s) never consults it and the image is accepted —
  a revocation bypass, violating the non-negotiable "never ignore revocation" invariant
  (CLAUDE.md, baseline §11). `dbx` must override trust (dbx > db) for **any** cert the
  signer presents.
- **Origin:** finding on the 2026-08-16 full-codebase audit
  (`evidence/security-review-records/2026-08-16-full-codebase-audit.md`, tracked as the
  #91 dbx-by-cert winning-chain-scope open item). This change supersedes / closes it.

## Reviews

- **go-reviewer — APPROVE.** Idiomatic Go: replaced the manual leaf-only check with
  `slices.ContainsFunc(certs, v.revoked)` (stdlib-first); doc-comment nits applied.
- **security-review-agent — APPROVE.** Independent adversarial review; it did **not**
  implement the change. **Mutation proof:** in an isolated worktree, reverting the
  full-bundle loop back to the leaf-only check made the new subtest
  `revoked bundled cert off the winning chain (#91)` the **only** failing subtest —
  `Verify` returned `nil` (the image would boot), empirically demonstrating the
  bypass; restoring the fix turns it green. Confirmed:
  - No new fail-open — the change only adds a rejection condition; the sole `return nil`
    is still reached only after full validation (hash not revoked, signature binds the
    leaf, leaf chains to db with `ExtKeyUsageCodeSigning`, and now no bundled/chain cert
    and no db root is revoked).
  - Over-rejection is **fail-closed-safe**: a legitimate image does not bundle
    dbx-revoked material; rejecting one is the safe pre-boot direction. Windows uses
    firmware mode (firmware owns validation), so imageverify governs only pba-mode
    custom/recovery targets.
  - R-009 fuzz path (`FuzzVerify` + recover backstop) is unaffected.

## Scope / classification

- **Security-critical (R-001)**, but **tightens** acceptance — never weakens; touches no
  Secure Boot, chainloader, key-handling, or cryptographic behavior, and does not change
  the trust decision beyond closing the bypass. ⇒ **No ADR** (baseline §23).
- Found pre-release, no shipped versions ⇒ no CVD/advisory (baseline §15).

## Threat-model / risk-assessment / CRA confirmation

- **risk-assessment R-001** — mitigations + Tests updated (full-bundle revocation; new
  subtest); dated change-log row added. **Residual stays Low** — strengthened mitigation
  on an already-Mitigated risk, **no rating change** (concur).
- **threat-model §6.3 / §9 / §10** — malicious-EFI-application mitigations + Tests and the
  §9 "reject untrusted/tampered/revoked image" mapping updated; §10 change-log row added.
  No new threat, no trust-boundary change (TB2 image-acceptance scope unchanged in shape,
  now correctly enforced over the whole bundle).
- **CRA matrix ER-2 (Integrity)** — **no impact**: the control was already
  Implemented (virtual); this closes a bypass within it, no status or gap change.
