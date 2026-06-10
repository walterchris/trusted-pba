# Security review record — PIN zeroization + log-scrub gate (#51 item 1)

- **Date:** 2026-06-10
- **Change under review:** branch `feat/phase-6-pin-zeroization`, commits
  `8946c93` (implementation), `25c1229` (log-scrub + zeroize tests); findings
  resolved in `32e8401`; docs recorded in `0d7d56a`.
- **Scope:** issue #51 item 1 (Phase 5/6 gate from the Phase 4 security review) —
  zeroization of all PIN-bearing buffers in `internal/opal` plus a log-scrub
  assertion proving PIN/session material never reaches console/serial.
- **Reviewer:** independent security-review agent (did not implement the change);
  separate idiomatic-Go review performed independently.
- **Verdict:** pass-with-findings — code approved; one process BLOCKER
  (security docs not updated in the same change), resolved by `0d7d56a`.

## What the review verified (adversarial, executed not assumed)

1. **End-to-end PIN trace:** no remaining reachable client-side copy. Caller
   `pin` (deferred zeroize, all paths incl. panic unwind), method payload
   (zeroized after the single `encodePacket` copy; no payload/frame aliasing),
   frame (deferred zeroize on send/recv/decode failure and success).
2. **Grow-budget math verified independently:** worst-case non-PIN overhead 41
   bytes against the 64-byte reservation; confirmed empirically (no backing-array
   reallocation) for PIN lengths 0–65536 across hsn values.
3. **Recv buffers:** SyncSession does not echo HostChallenge (spec + MockTPer);
   hostile-TPer reflection noted as INFO-level hardening (TB3), not required for
   this gate.
4. **`Transport.Send` must-not-retain contract:** verified against the pinned
   go-boot fork (`v1.6.2-tpba.1` `storagesecurity.go`) — synchronous, no Go-side
   retention; a hypothetical retaining transport fails closed (invalid ComPacket
   → device rejection → error).

## Findings and resolution

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | BLOCKER (process) | Threat model B.2 / risk R-003 not updated by the change | `0d7d56a` (R-003 Medium → Low; B.1/B.2 + §6.2 + test mapping updated) |
| 2 | NIT | Output capture missed builtin `print`/`println` (raw fd 2) — empirically confirmed | `32e8401` — fd-level capture via dup/dup3; mutation-verified |
| 3 | NIT | Encoding set missed Go default decimal byte-slice formatting (`%v`) | `32e8401` — decimal-slice added; mutation-verified |
| 4 | INFO | Recv-buffer zeroization vs hostile TPer (defense in depth) | open — candidate for Phase 6 wiring or follow-up |
| 5 | INFO | Residuals to state in docs (dead-store elimination, registers, swap N/A) | `0d7d56a` — recorded in R-003 residual |
| 6 | INFO | `endSession` frame zeroized inline (non-secret) — no change needed | none required |

Go review (same date): approve; 7 NITs (regression test pinning the 64-byte
budget, capture defer hygiene, `io.ReadAll` error → vacuous-pass risk, style
items, one-clause `Transport.Send` doc tightening) — all applied in `32e8401`
with mutation evidence for the test-soundness items.

## Risk disposition

**R-003 residual: Medium → Low**, conditional items satisfied. Explicit open
scope carried in R-003 and the threat model: the Phase 6 boot-path wiring must
zeroize the console PIN-input buffer (#51 item 2) — item 1 closes the library
layer only. Firmware/DMA-side copies remain the documented evil-maid residual
(threat model §6.2).
