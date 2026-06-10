# Security review record — boot-path SED unlock wiring (#22, #51 item 2)

- **Date:** 2026-06-10
- **Change under review:** branch `feat/phase-6-opal-boot-wiring`, commits
  `b197347`/`2268c9a`/`0487202` (policy gate, wiring, ADR-0009, docs); findings
  resolved in `2ecb0cf`.
- **Scope:** the Opal unlock goes live in the boot path (threat model A1/A7
  "in-library" → wired): explicit `sed_unlock: required | none` policy gate
  (absence = required, fail closed; `none` loudly logged), MVP compiled-in PIN,
  unlock between `CheckSecureBoot` and `Select`, any `Unlock` error →
  on-error action with no retry and no fallback (#51 item 2, ADR-0009).
- **Reviewers:** independent security-review agent (did not implement);
  separate idiomatic-Go review performed independently.
- **Verdict:** APPROVE (pass-with-findings) — no blocker; **#51 item 2
  satisfied**.

## What the review verified (adversarial, executed not assumed)

1. **Gate semantics — could not refute fail-closed:** absent field normalizes
   to required (tested); unknown/garbage values are parse errors, not
   fallbacks; `none`+PIN and `required`-without-PIN rejected; a malformed
   embedded policy terminates with the pre-policy halt default (fails closed);
   a zero-value `Policy` that never went through `Parse` takes the unlock
   path, not the skip — the skip branch is reachable only via the literal
   `none` and always prints the marker first.
2. **#51 item 2:** exactly one `Unlock` attempt per boot (single call chain,
   no construction retry — test-asserted); every error class (no SSC device,
   transport fault, auth failure, partial unlock) collapses into one error
   return that reaches `terminate(onErrorAction)` before `Select()`; no
   terminate mode returns to the firmware boot order.
3. **Secrets:** PIN traced end-to-end; `[]byte(pol.SEDPIN)` shares the backing
   array (moved, not copied — alias-asserted in tests), holder nulled,
   `defer clear` covers the construction-failure path, `opal.Unlock` zeroizes
   its own copies (#51 item 1); no format verb anywhere can print the PIN.
4. **Ordering and markers:** no Load/StartImage before unlock succeeds; `none`
   changes nothing else; `sed unlock ok` emitted strictly after MBRDone;
   marker set regex-safe and pairwise substring-disjoint including against all
   existing markers.
5. **Docs:** R-002 movement justified, R-003 correctly *not* claimed closed
   (console-input scrub re-scoped to the future PIN prompt), A1/A7 accurate.

## Findings and resolution

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | NIT | Partial-unlock shape (range cleared, MBRDone fails) had no reproducing test at any layer | `2ecb0cf` — `FaultMBRDone` in MockTPer (drive genuinely unlocks, MBRControl Set returns status 0x3F) + `TestUnlockSEDFailsClosedOnPartialUnlock` asserting `Locked()==false && MBRDone()==false`, fail-closed error, no `ok` marker, PIN zeroized; mutation-verified |
| 2 | NIT | Stale attack-tree annotations (Phase 4/5 wording; #51-item mislabel) | `2ecb0cf` |
| 3 | INFO | Third unscrubable PIN copy (`json.Decoder` read buffer) missing from residuals | `2ecb0cf` (R-003) + ADR-0009 touch-up |
| 4 | INFO | `halt` leaves a partially-unlocked drive powered (#51 allows "re-lock **or** halt" — contract met) | follow-up hardening candidate (tracked with #6 below) |
| 5 | INFO | Best-effort EndOfSession → chainload can proceed with the Locking SP session open (pre-existing, now live) | A7 note added in `2ecb0cf`; hardening candidate |
| 6 | INFO | Nothing catches a production artifact shipping `sed_unlock: none` | release-time policy assertion + FORBID lines → QEMU integration ticket |
| 7 | INFO | Duplicate-JSON-key last-wins (unreachable without modifying the signed binary); fuzz seed gap | seed added in `2ecb0cf`; rest noted for future external provisioning |

Go review (same date): approve — verified the backing-array identity conversion
behind the "moved, not copied" claim, the `PIN` unmarshaler's fail-closed
behavior incl. JSON `null`, fixture changes only add the new mandatory field,
and a real TamaGo build of the tag-free wiring file. Nits (package comment,
boolean idiom, `t.Parallel`, structural `PIN.String()` redaction guard) applied
in `2ecb0cf`.

## Risk disposition

**R-002:** library → boot-path gate wired and host-tested; residual stays
Medium pending QEMU end-to-end (next ticket) and hardware (Phase 8).
**R-003:** stays Low; compiled-in-PIN MVP residuals honestly recorded (three
copies); console-input scrub attaches to the future PIN prompt.
**R-008:** confirmed held — every traced error path ends at `terminate`.
**#51:** closeable on merge — item 1 (library zeroization) and item 2
(partial-unlock caller contract) both implemented, tested, and reviewed.
