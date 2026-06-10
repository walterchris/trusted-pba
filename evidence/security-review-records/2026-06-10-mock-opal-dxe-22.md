# Security review record — MockOpalDxe EDK2 driver (#22, test tooling)

- **Date:** 2026-06-10
- **Change under review:** branch `feat/phase-6-mock-opal-dxe`, commit `b0a2b2c`
  (driver + build/smoke infrastructure); findings resolved in `090f2cd`.
- **Scope:** test-tooling-plan §3.3 — `test/edk2-mock-opal/` DXE driver installing
  EFI_STORAGE_SECURITY_COMMAND_PROTOCOL with deterministic responses from the
  shared fake-Opal spec (§3.2), UEFI-variable fault injection, serial markers;
  pinned-edk2 build script; QEMU runner `DRIVER=` staging extension.
- **Reviewer:** independent security-review agent (did not implement the change).
  Test tooling, not product code — reviewed because a wrong mock produces wrong
  CI verdicts.
- **Verdict:** PASS with findings (approve) — no blocker.

## What the review verified (adversarial, executed not assumed)

1. **The mock cannot make a broken PBA look good:** no path reports
   unlocked/MBR-done without a correct-PIN Admin1 StartSession (`Set` without
   session → NOT_AUTHORIZED; unlock gated on TSN set only by successful auth);
   Discovery0 locking-flags patching is the identity while locked, so the
   response stays byte-identical to the golden fixture as the spec requires.
2. **Fail-closed defaults:** no fault variable → no fault (guarded by smoke
   FORBID); unknown fault value or any unexpected GetVariable error → auth-fail
   with a loud marker.
3. **Memory safety of the C parser:** all nested ComPacket lengths validated
   before payload deref (matching `packet.go`); every atom header/body
   bounds-checked; reserved tokens rejected; bounded builder output; no OOB
   read/write found.
4. **Wire consistency with `MockTPer`:** UIDs, status codes, TSN, ComIDs,
   framing offsets, EOS framing, response truncation — all byte-consistent.
5. **Hygiene:** edk2 tree never modified (standalone DSC via PACKAGES_PATH);
   `DRIVER=` extension inert when unset (Phase 0–3 tests unaffected);
   `add-driver-entry.py` writes only the per-run VARS copy; drift guard
   genuinely fails on fixture drift; no key material committed.
6. **Fault shapes confirmed correct** for the planned negative tests:
   `fail-mbrdone` = method-status failure after auth+unlock ("Opal failure → no
   chainload"); `fail-after-unlock` = transport drop after a real unlock
   ("partial unlock → halt"). Tests must assert via FORBID on chainload markers
   (not mock-marker absence) because the staged success stream stays readable —
   intentional, mirrors `MockTPer.resp`.

## Findings and resolution

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | NIT | Parenthesized markers can never match expect-serial.py's raw-regex patterns — FORBID would silently never fire | `090f2cd` — regex-metacharacter-free marker set |
| 2 | NIT | `mbr-done` success marker was a prefix of the refusal marker | `090f2cd` — substring-disjoint set (verified pairwise) |
| 3 | NIT | Stale staged response readable after `fail-after-unlock` | kept (mirrors MockTPer), documented in README with test guidance |
| 4 | NIT | MAX_TOKENS/RESP_MAX caps undocumented; no `fail-garbled` shape | `090f2cd` — documented as divergences + known gap |
| 5 | NIT | edk2 pinned by mutable tag, not commit (TB5) | `090f2cd` — `EDK2_COMMIT` = `b03a21a63e3bd001f52c527e5a57feddb53a690b`, verified after clone/cache reuse, negative-tested |
| 6 | INFO | Go-side fixture guard was parse-level only (pre-existing) | `090f2cd` — `bytes.Equal(buildDiscovery(want), fixture)` added |

## Risk disposition

**R-010 (mock vs real SED gap):** mitigated at this layer — C ≡ fixture by
construction (embedded header + drift guard); Go side now byte-guarded too.
**TB5:** residual closed by the commit pin. Known gap carried in the README:
no `fail-garbled` fault shape yet, so the PBA tokenizer fail-closed path is
QEMU-untested until one is added.
