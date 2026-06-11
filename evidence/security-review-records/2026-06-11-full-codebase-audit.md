# Security review record — full-codebase audit (synthesis)

- **Date:** 2026-06-11
- **Scope:** full repository on `main` post-Phase-6, including the pinned `walterchris/go-boot` fork (`v1.6.2-tpba.3`, ADR-0008), `test/edk2-mock-opal/`, QEMU harness, and CI/release workflows.

> **Verification-rigor note.** The Find phase (24 finders, 96 raw findings) completed
> fully. The adversarial Verify phase was interrupted by an org spend limit: findings
> in `internal/opal` (and part of the go-boot fork) received the full 2-of-3
> independent-refuter protocol; findings in policy/bootflow/tooling/supply-chain were
> dispositioned by the single synthesis pass against code and evidence records
> instead. Confirmed findings are reliable (they survived scrutiny); the *refuted*
> appendix entries for the under-verified areas carry single-reviewer confidence and
> can be re-verified by resuming workflow run `wf_34549ffb-bcd` once budget allows.

## Disposition (2026-06-11)

All confirmed findings were triaged and addressed across three merged PRs; nothing
confirmed remains open except items that require the EDK2 build + QEMU matrix / CI to
verify and so are deferred until the agent pipeline is available again.

- **PR #62** — F-M1 (grow-budget reservation pinned at the real call site; R-003
  evidence wording corrected), F-M2 (SyncSession status-check negative test), F-L3
  (HSN echo-match negative test). All mutation-verified.
- **PR #63** — F-L1 (mock parser short-UID panic guards + Locking-SP validation),
  F-L2 (reject truncated 64-bit session ids), F-L4 (MBR-skip assertion).
- **PR #64** — Go style F-S1/2/6/7/8/9/10/11/12 (incl. F-S8 revocation-set
  fail-closed default) and locally-verifiable F-S16/F-S20.
- **Deferred (need EDK2/QEMU/CI to verify):** F-L5, F-S3/4/5 (go-boot fork — bundle
  with the `tpba.4` + upstream `uefi.s` submission), F-S13/F-S14 (`MockOpalDxe.c`),
  F-S15/F-S17 (QEMU harness shell), F-S18/F-S19 (CI/Taskfile dedup). Tracked for the
  agent pipeline once the spend limit clears.

- **Original scope (as audited):** the full repository, the pinned `walterchris/go-boot` fork (`v1.6.2-tpba.3`, ADR-0008), `test/edk2-mock-opal/`, QEMU harness, and CI/release workflows.
- **Method:** multi-lens audit (security, bugs, tests, style) with independent adversarial verification of every candidate finding (mutation testing and live reproduction where claimed). Items already adjudicated in the existing review records or recorded as accepted residuals in `docs/compliance/risk-assessment.md` were excluded and are not re-reported here.
- **Verdict:** PASS with findings — no blocker, no high-severity finding.

---

## 1. Executive summary

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Style / informational | 20 |
| **Total confirmed (after de-duplication)** | **27** |
| Refuted after adversarial verification | 30 (appendix) |

**Posture.** The fail-closed core holds: no confirmed finding gives an attacker a boot-policy bypass, secret disclosure, or unlock-without-auth path, and every refuted "fail-open" claim died under reproduction. The two medium findings are both *test-evidence* defects, not live bugs — a documented zeroization regression guard that does not actually pin the invariant it claims (and is cited as mitigation evidence for R-003), and zero mutation coverage on the SyncSession status check, a load-bearing fail-closed gate. The low findings are parser-strictness and robustness defects (silent 64-bit truncation of device-controlled session IDs; panics on short atoms in the in-package mock; a firmware-device-path underflow panic in upstream fork code), none with demonstrated attacker capability. The remaining 20 items are idiom, duplication, and documentation debt — notable mainly where duplicated strings or delegated invariants guard security oracles.

**Three most important findings:**
1. **F-M1** — the `startSessionCmd` grow-budget zeroization invariant is unpinned: deleting the `b.grow()` call strands a live PIN copy and the whole suite stays green, while the risk register cites the test as R-003 evidence.
2. **F-M2** — `syncSessionIDs`' `checkStatus` call has zero mutation resistance: a regression would let a failure-status SyncSession with non-zero TSN be accepted as an authenticated session.
3. **F-L2** — `u32` silently truncates device-controlled 64-bit token integers in SyncSession parsing, defeating the HSN echo check's intent and falsifying the documented "bounded wire value" / `//nolint:gosec` justification.

---

## 2. Confirmed findings

### Medium

#### F-M1 — Zeroization grow-budget invariant not actually pinned; cited compliance evidence is partly false (area: opal / tests)
- **Where:** `internal/opal/zeroize_test.go:179` (test), `internal/opal/method.go:53` (guarded call), `docs/compliance/risk-assessment.md:245` (evidence claim).
- **Evidence:** Mutation-verified: deleting `b.grow(64 + len(pin))` at method.go:53 leaves the entire host suite green. `TestStartSessionGrowBudget` measures only output-length overhead (identical with or without grow); `TestBuilderGrowPreventsReallocation` (zeroize_test.go:208) tests the primitive in isolation, not the call site. A pointer probe of the mutated sequence shows the backing array reallocates *after* the PIN bytes are written, stranding a live PIN copy unreachable by `zeroize` — exactly the failure mode the invariant claims to prevent. The shipped code is correct today (grow present, worst-case overhead 41 < 64 per the #51-item-1 record), but risk-assessment.md:245 claims the budget is "tested" / "pinned by a regression test at the real call site", which the mutation disproves.
- **Fix:** Regression test at the real call site: capture the PIN byte's address (or `&b.buf[0]`) immediately after `b.bytes(pin)` and assert it is unchanged in the returned command — i.e. assert no post-secret reallocation, not just overhead ≤ 64. Correct the risk-assessment evidence wording.
- **Maps to:** R-003 (unlock secret leaks); threat model A1/§6.2, test mapping at threat-model.md:273.

#### F-M2 — `syncSessionIDs` status check has zero mutation coverage; the only auth-failure negative path is absorbed by the TSN==0 guard (area: opal / tests)
- **Where:** `internal/opal/method.go:128`; mock behavior at `internal/opal/mocktper.go:170`; gap at `internal/opal/client_test.go:101`.
- **Evidence:** Mutation-verified twice independently: removing the `checkStatus(payload)` call at method.go:128 leaves the full suite green, including `TestUnlockFailsClosed/"wrong password"`. Cause: MockTPer always pairs a failure status with TSN 0, so the TSN==0 guard (client.go:123) catches the wrong-password case regardless; the only crafted SyncSession in tests uses statusSuccess+TSN 0. With the check regressed, a hostile/buggy TPer returning `statusAuthLockedOut` with a non-zero TSN would be accepted as an authenticated session and nothing would fail.
- **Fix:** Add a transport variant returning a non-success-status SyncSession with non-zero TSN; assert Unlock fails closed (drive stays locked).
- **Maps to:** R-002 (unlock before authentication succeeds), R-009 (parser accepts malformed response); CLAUDE.md "every negative security case must be tested".

### Low

#### F-L1 — MockTPer request parsers panic on short byte-string atoms (unchecked slice-to-`[8]byte` conversions in a non-test file) (area: opal)
- **Where:** `internal/opal/mocktper.go:146` (`handle`), `:251` (`parseStartSession`), `:281` (`parseSet`); correct pattern at `:267-268`.
- **Evidence:** Reproduced live: `m.handle([]byte{0xF8, 0xA0, 0xA0})` panics ("cannot convert slice with length 0 to array with length 8"). All three sites guard only `isBytes`, never `len(data) == 8`, while tokenize (token.go:115-122) happily yields 0–7-byte bytes atoms; the adjacent authority parse at :267 checks length, proving the omission an oversight. Contradicts handle's own fail-closed doc contract (mocktper.go:134-136) and the package's never-panic discipline (doc.go:12) in a non-`_test.go` file. No production/attacker reachability: MockTPer has only test consumers, the real Client always emits 8-byte UIDs, and a test panic fails loudly. `FuzzResponseParse` does not cover the request-side parsers.
- **Fix:** Require `len(toks[N].data) == 8` before each conversion, mirroring :267 (NOT_AUTHORIZED / `ok=false` otherwise); optionally add a fuzz target over `MockTPer.handle`.
- **Maps to:** R-010 (test-harness fidelity) — indirect; no product risk.

#### F-L2 — `u32` silently truncates device-controlled 64-bit token integers in `syncSessionIDs`; documented "cannot overflow" invariant is false (area: opal)
- **Where:** `internal/opal/method.go:141`; doc/nolint at `internal/opal/token.go:29-32`; affected check at `internal/opal/client.go:117-125`.
- **Evidence:** Token integer atoms decode up to a full uint64 (token.go:160-164), so the boundedness claim justifying `u32` and its `//nolint:gosec` holds for the length-field call sites but not here. Reproduced: a SyncSession response carrying HSN `0x1_0000_0001` truncates to 1 and passes the echo check at client.go:117; TSN `0x1_0000_1000` truncates to `0x1000` and is stored for all session packets (only exact multiples of 2^32 hit the TSN==0 reject). No attacker capability gain — the drive controls these bytes and could echo conforming values — but it weakens a desync sanity check, violates the package's fail-closed-on-every-device-byte invariant (doc.go:12-13), and the nolint justification is wrong at this call site. (Same pattern on the host-request side at mocktper.go:250, test code.)
- **Fix:** Reject token values > `math.MaxUint32` in `syncSessionIDs` (wrap `ErrMethod`); scope the token.go:29-32 comment to host-computed length fields.
- **Maps to:** R-009.

#### F-L3 — HSN echo-match check has no negative test; mock always echoes the sent HSN (area: opal / tests)
- **Where:** `internal/opal/client.go:117-119`; mock at `internal/opal/mocktper.go:172-174`.
- **Evidence:** Mutation-verified: removing the `gotHSN != hsn` block (binding `c.hsn = hsn`) leaves the full host suite green. MockTPer faithfully echoes the sent HSN and the only fault transport (`zeroTSNTransport`, client_test.go:91-102) also returns HSN=1, so the session-confusion guard can never trip in any existing test. Asymmetric with the TSN==0 guard, which has a dedicated negative test.
- **Fix:** A wrong-HSN transport stub mirroring `zeroTSNTransport` (valid non-zero TSN), asserting fail-closed. Natural bundle with F-M2.
- **Maps to:** R-002/R-009 (session-establishment fail-closed).

#### F-L4 — `TestUnlockSkipsMBRWhenDone` does not assert the skip it is named for (area: opal / tests)
- **Where:** `internal/opal/client_test.go:104-113`; guard at `internal/opal/client.go:98`.
- **Evidence:** Mutation-verified: changing the guard to `if d.MBREnabled` (always send the MBRControl Set) survives the suite, because the mock's Set is idempotent (mocktper.go:197-201) and the test asserts only success + unlocked. No security impact; the test name overstates coverage.
- **Fix:** Count MBRControl Set invocations via a spy transport and assert zero when `MBRDone` is already true (or rename the test).
- **Maps to:** none (R-008-adjacent test hygiene only).

#### F-L5 — `devicePath()` node Length 1–3 underflows uint16 and panics, defeating the parser's stated anti-DoS intent (area: transport-fork, upstream code)
- **Where:** `go-boot/uefi/path.go:79` (guard), `:89` (underflow), `:92` (OOB slice).
- **Evidence:** The guard rejects only `Length == 0 || Length > 0xff`, so Length 1–3 passes; `uint(d.Length - 4)` wraps to ~65533 and `copy(d.Data, buf[off:off+dataSize])` slices past the 65536-byte DMA reservation — guaranteed slice-bounds panic, reachable on every chainload via `LoadImageBuffer → FilePath → devicePath` (cmd/pba/main.go:172). Contradicts the function's own anti-DoS rationale (path.go:45-47) and the CLAUDE.md no-panic-on-external-input rule in letter; in effect it is fail-closed (pre-chainload dead stop), and the device-path producer is platform firmware, which the tpba.3 record treats as trusted at this boundary. Unmodified upstream code — fix gated by ADR-0008 fork policy.
- **Fix:** Reject `node.Length < 4` (spec minimum: 4-byte generic node header); bundle with the planned upstream submission of the `uefi.s` alignment fix.
- **Maps to:** R-007 (chainload availability); TB firmware-trusted per tpba.3 record.

### Style / informational

**Opal (2)**
- **F-S1** Constant-string `fmt.Errorf` instead of `errors.New`; the three non-parser security rejections (no-locking, HSN mismatch, TSN==0 — `internal/opal/client.go:83,118,124`) wrap no sentinel, so they are the only device-input failures not branchable via `errors.Is`. Fix: `errors.New` / wrap `ErrMethod`. Maps to: none.
- **F-S2** `buildDiscovery` capacity hint under-sized (`make([]byte, 0, 32)` for 36 bytes of appends, `internal/opal/discovery.go:101`) — guaranteed realloc; misleading in a package where capacity reasoning is load-bearing for zeroization. Maps to: none.

**Transport-fork (3)**
- **F-S3** `parseStatus` returns only opaque `fmt.Errorf` strings (`go-boot/uefi/error.go:53-61`) — no typed/sentinel error, so EFI statuses cannot be discriminated with `errors.Is/As` up the stack; fail-closed semantics intact. Maps to: none.
- **F-S4** Dead `dummy:` block (unreachable `POPQ` pair) in the `callFn` trampoline (`go-boot/uefi/uefi.s:83-86`) — review noise in the one upstream file re-audited on every rebase; fold removal into the upstream submission. Maps to: §6.6/ADR-0008 hygiene.
- **F-S5** Inconsistent laundered-pointer naming between `SendData` (`buf`, storagesecurity.go:63) and `ReceiveData` (`ptr`, :84-86) — friction precisely where the tpba.3 double-deref bug class lives. Maps to: §6.6 hygiene.

**Policy / truststore (4)**
- **F-S6** Swallowed errors in the imageverify leaf-selection loop lack the justification comments the standard requires (`internal/imageverify/verify.go:87-89, 93-95` vs the commented skip at :115-117), and the terminal bare `ErrUntrusted` (:128) discards all diagnostic context. Fail-closed unaffected. Maps to: R-001 (diagnosability of refused boots).
- **F-S7** `revoked()` hand-rolls containment (`internal/imageverify/verify.go:145-152`); stdlib-first: `return slices.ContainsFunc(v.DBXCerts, c.Equal)`. Maps to: none.
- **F-S8** `parseDBX` has no `default:` case (`internal/truststore/truststore.go:112-130`): Load's documented "never a silently smaller trust store" invariant currently rests on the pinned go-uefi's unimplemented-type error, not local code. A future go-uefi bump implementing more ESL types would let a dbx refresh silently shrink the revocation set (the `len==0` backstop at :59 misses partial drops). Fix: explicit default error (ignore only `CERT_EXTERNAL_MANAGEMENT_GUID` with spec citation). Maps to: R-001/R-011 (revocation integrity across dependency bumps).
- **F-S9** Stale forward-reference doc on `Policy.Select` ("availability-ordered selection arrives with the chainloader wiring", `internal/policy/policy.go:161-162`) — the chainloader is wired (cmd/pba/main.go:107); Select still returns `Entries[0]`. Maps to: none.

**Bootflow (3)**
- **F-S10** `load()` lacks the nil-root defense-in-depth guard its sibling `verifyAndLoad` deliberately keeps with a rationale comment (`cmd/pba/main.go:189,195` vs :150-155) — same hypothetical fork change would nil-deref (dead-stop panic) instead of the clean fail-closed error. The #46 record adjudicated the guard's *presence* in verifyAndLoad only, not the asymmetry. Maps to: R-007 (consistency only; still fail-closed).
- **F-S11** Load-bearing "chainload failed" harness prefix hand-typed 11 times with no constant or pinning test (`cmd/pba/main.go:130,148,154,160,165,168,176,181,191,197,202`); the QEMU harness consumes the exact string as REQUIRE/FORBID oracle (Taskfile.yml:132, ci.yml:117, test/qemu/pba-run.sh:35,40). A one-site typo silently decouples that path from the harness contract. Maps to: R-001 (negative-test oracle integrity).
- **F-S12** The #46 AST invariant gate matches callees by bare name only (`cmd/pba/main_invariant_test.go:150-158`) — a decoy `x.Verify(...)` or shadowed `ReadFile` would still satisfy it. QEMU reject matrices remain the behavioral backstop, so this is test rigor, not a false-passing gate. Maps to: R-012 (gate hardening).

**Test tooling (5)**
- **F-S13** `FaultValueIs` hand-rolls strlen (`test/edk2-mock-opal/MockOpalDxe.c:777-778`); BaseLib `AsciiStrLen` is one include away. Maps to: none.
- **F-S14** ComPacket/Packet/SubPacket field offsets are magic numbers duplicated between `FrameResponse` (MockOpalDxe.c:427-438) and `DecodeFrame` (:460,469,473), with offset 52 colliding textually with `DISCOVERY_LOCKING_FLAGS_OFF`. Named offset macros would make encoder/decoder desync unmissable. Maps to: R-010 (byte-faithfulness review safety).
- **F-S15** Throwaway-key generation/enrollment, virt-fw-vars resolution, and `scenario()` copy-pasted between `mock-opal-matrix.sh` (:55-60,82-85,122-133) and `secureboot-matrix.sh` (:24-29,33-53,63-66) — drift (e.g. losing `--no-microsoft`) would silently change SB scenario semantics; the sourced-helper pattern (`ovmf-pair.sh`) already exists. Maps to: R-010.
- **F-S16** REQUIRE/FORBID markers are compiled as raw regexes (`test/qemu/expect-serial.py:55-60`) but documented as plain markers; the metacharacter-free convention (#22 record finding 1) is load-bearing yet deliberately violated by `secureboot-matrix.sh:103`'s alternation, enforced only by reviewer memory. Fix: document regex semantics (or `re.escape` by default with an explicit prefix). Maps to: R-010 (oracle integrity).
- **F-S17** `run-qemu.sh`'s EXIT trap never fires on the normal path (`exec qemu...` at :88 replaces the shell), orphaning the per-run 64 MiB ESP image + VARS copy in `$TMPDIR` locally; the comment (:85-87) acknowledges only CI. Maps to: none.

**Supply chain / CI (3)**
- **F-S18** Fail-closed REQUIRE/FORBID marker lists of the negative security test duplicated byte-for-byte between `ci.yml:117-118` and `Taskfile.yml:132-133` — a marker rename updated in one copy silently desynchronizes CI from `task check`. Fix: CI calls `task run-negative`. Maps to: R-001 (negative-test oracle).
- **F-S19** golangci-lint version pin and gofmt-check snippet each maintained twice (`ci.yml:24-33` vs `Taskfile.yml:195-210`) — a deliberate bump drifts the other copy with no failure signal. Maps to: R-006 (build-pipeline hygiene).
- **F-S20** real-image-verify shim selection `ls ... | head -1` (`ci.yml:147-149`) does not honor the written preference order (ls sorts; `.signed.latest` never wins when `.signed` coexists). Every candidate is a genuine MS-signed shim, so the oracle is unaffected — code no longer says what it means. Maps to: none.

---

## 3. Refuted-findings appendix

Adversarially considered and rejected; recorded for auditability. Duplicate submissions merged.

**go-boot fork**
1. *SendData missing `runtime.KeepAlive(payload)` (4 submissions)* — refuted as exploitable: both product call sites root the frame across the firmware call (`client.go:158` defer zeroize; `:145` post-call zeroize), so GC reclamation is unreachable; latent API-parity gap noted for the upstream bundle (same disposition as the c544446 LoadImageBuffer hardening).
2. *LoadImage same KeepAlive gap on the Windows path (2)* — same class, same refutation: caller keeps the buffer live; firmware copies at call time.
3. *ReceiveData signed-compare/bit-63 `PayloadTransferSize` bypass → panic (3)* — out-param is written only by platform firmware, trusted at this boundary per the tpba.3 record; the hypothesized value requires already-compromised firmware and ends in a pre-chainload dead stop (fail-closed in effect).
4. *Firmware out-params via raw addresses of stack locals → wild write on stack relocation* — not reproducible: no stack growth/relocation can occur between address capture and the blocking firmware CALL at these sites in this runtime configuration.
5. *ErrTruncated guard dead under every test level / hides a bypass* — guard is live fail-closed code; the "hidden bypass" is item 3 above (refuted); fork surface is host-untestable by design (ADR-0005/ADR-0008), exercised by the QEMU matrix.
6. *NULL-slot check has no negative test* — the check was added and reviewed under the tpba.3 record; host-untestable fork surface accepted under ADR-0008/R-010.
7. *Entire fork TCB invisible to vet/lint/unit tests* — recorded architecture (ADR-0005 virtual-first, ADR-0008 fork policy, §6.6), not a finding.

**imageverify / truststore / policy**
8. *Forged image accepted: signature not bound to image hash* — false: go-uefi's `pe.Verify` recomputes the Authenticode digest and binds the signature to the image hash; forged images fail.
9. *TestVerifierWired vacuous for DBXCerts* — dbx-by-cert negative coverage exists (threat-model §6.9 test mapping).
10. *ignoreValidity only leaf-tested; 2011 CAs expire 2026* — trust-anchor staleness is the recorded open R-011; expiry semantics are the recorded ADR-0007/R-013 acceptance.
11. *parseDBX CERT_X509 branch zero coverage* — dbx-by-cert negative exercises the branch.
12. *Verify malformed/non-PE fail-closed paths uncovered* — known accepted residual: imageverify fuzz gap, issue #56.
13. *policy.Parse trailing-data rejection untested* — `dec.More()` rejection (policy.go:119-120) is covered by the parse-negative suite and `FuzzParse` (CI ci.yml:53).
14. *PIN redaction %d bypass* — fd-level log-scrub test asserts PIN-free output, mutation-verified (#51-item-1 record).
15. *Revoked-leaf early return zero coverage* — redundant defense-in-depth; the revocation outcome is pinned via the chain walk by the dbx-by-cert negative.
16. *Build-tag policy JSON variants never host-parsed* — variants are exercised end-to-end by the QEMU matrices that build with those tags (ADR-0005 recorded strategy).

**bootflow**
17. *SetWatchdogTimer(0) warn-and-continue voids the dead-stop guarantee (2)* — fail-closed direction: a still-armed firmware watchdog reboots, it does not boot anything untrusted (main.go:47-49).
18. *AST gate: decoy callee / ignored Verify error / in-place buffer mutation passes (3)* — stronger variants not reproducible as false passes; receiver-blindness retained as confirmed style finding F-S12 with the QEMU reject matrix as behavioral backstop.
19. *terminate() never-return invariant has no oracle* — dead-stop behavior is asserted behaviorally by QEMU negative scenarios (FORBID + grace window).
20. *on_error reboot/shutdown zero behavioral coverage* — modes are pinned at parse level (policy_test.go:47-64); halt is the shipped fail-closed default; behavioral reset-type validation is recorded Phase-8/hardware scope.
21. *SB detection-failure fold is fail-open* — fold to "not enforcing" is the conservative direction: under `require_secure_boot` it halts (policy.go:173-176); where SB is not required, the status is not load-bearing.
22. *unlockSED `== SEDUnlockNone` → `!= SEDUnlockRequired` mutation survives* — semantics-preserving mutation: parse normalization leaves exactly two values, making the predicates equivalent post-parse.

**test tooling**
23. *Mock unlocks on EITHER ReadLocked/WriteLocked cleared (3)* — the PBA's unlock Set is byte-pinned at the Go layer (both columns in one command), so the coarse single-flag mock cannot mask a one-column PBA; mock-fidelity divergences are documented and carried under R-010 (#22 record).
24. *Mock never validates TSN/HSN/SPID; zero-tuple Set returns SUCCESS (5)* — deliberate mock scope adjudicated in the #22 record: unlock is gated on an authenticated session and the mock cannot make a broken PBA look good; field-validation gaps fall under the documented R-010 divergence list.
25. *expect-serial.py never scans an unterminated final line (4)* — `readline()` returns the partial tail at EOF/pipe-close (timeout kill of the process group), so FORBID still scans it.
26. *EXPECT_STUB / ambient EXPECT_GRACE honored by matrix runs (3)* — self-test hook by design; an actor controlling the harness environment already controls the verdict (CI-runner compromise is recorded R-006); the grace-window bound itself is a known accepted residual.
27. *pba-setup.sh leaves the code-signing CA private key in the checkout (2)* — per-run throwaway key in the untracked work directory, trusted only by the per-run varstore; no asset.

**supply chain / CI**
28. *TamaGo toolchain unverified download; setup-task mutable-tag pin + GITHUB_TOKEN; virt-firmware PyPI unpinned; release.yml `${{ inputs.version }}` expression injection; check-release-policy gate never negative-tested (9 submissions)* — all fall inside the recorded open R-006 residual (update/release pipeline, provenance, and signing not yet built; release workflow is a placeholder behind a protected-environment human gate with `contents: read`); to be resolved by the release-pipeline milestone, not piecemeal.
29. *`task deps` dead-pins upstream usbarmory/go-boot while the product imports the walterchris fork (3)* — go.mod (`walterchris/go-boot v1.6.2-tpba.3`) is the sole effective, reviewed pin; the convenience task cannot move or mask it. Hygiene nit at most.
30. *real-image-verify / fuzz-smoke jobs pass vacuously on pattern mismatch (2)* — `go test -fuzz` fails hard when the pattern matches no (or multiple) targets; the `-run` job's `-v` output makes a no-tests run visible and no mismatch exists; hypothetical-rename hazard, not an evidenced defect.

---

## 4. Triage proposal

| # | Finding | Action |
|---|---|---|
| F-M1 | Grow-budget invariant unpinned + false evidence claim | **Fix-PR now** (PR-A): call-site no-realloc regression test; correct risk-assessment.md:245 wording in the same PR |
| F-M2 | syncSessionIDs checkStatus zero mutation coverage | **Fix-PR now** (PR-A): failure-status + non-zero-TSN transport negative test |
| F-L3 | HSN echo check no negative test | **Fix-PR now** (PR-A, same stub pattern as F-M2) |
| F-L2 | u32 truncation of device-controlled session IDs | **Fix-PR now** (PR-A): range-check in syncSessionIDs + scope the token.go comment |
| F-L1 | MockTPer short-atom panics | **Fix-PR now** (PR-A): len==8 guards; optional request-side fuzz target |
| F-L4 | MBR-skip test overclaim | **Backlog issue** (or fold into PR-A if a spy transport lands there) |
| F-L5 | devicePath uint16 underflow panic (upstream) | **Backlog issue** → fork fix at next `-tpba` tag, bundled into the planned upstream submission (ADR-0008) |
| F-S8 | parseDBX missing default (revocation-shrink on dep bump) | **Fix-PR now** (PR-B): cheap, dependency-bump-proofs a revocation invariant |
| F-S6, F-S7, F-S9 | imageverify comments/Join, ContainsFunc, stale Select doc | **Fix-PR now** (PR-B, trivial bundle) |
| F-S11 | "chainload failed" prefix constant | **Fix-PR now** (PR-C): harness-contract integrity |
| F-S18 | ci.yml duplicates run-negative markers | **Fix-PR now** (PR-C): CI calls `task run-negative` |
| F-S16 | expect-serial regex semantics undocumented | **Fix-PR now** (PR-C, one-paragraph doc) |
| F-S20 | `ls \| head` shim preference order | **Fix-PR now** (PR-C, trivial loop) |
| F-S1, F-S2 | opal errors.New / capacity hint | **Backlog** (fold into next opal touch; do not open a dedicated PR) |
| F-S12 | AST gate receiver identity | **Backlog issue**: tighten + mutation-verify, per the f19b178 precedent |
| F-S10 | load() nil-root asymmetry | **Backlog**: extract shared `openESP()` helper |
| F-S4, F-S5 | uefi.s dead block; SendData naming | **Backlog**: bundle into the fork's upstream submission batch — keep the fork diff minimal until then |
| F-S3 | parseStatus typed error | **Accept + record**: not needed for current fail-closed semantics; revisit when a caller must discriminate statuses |
| F-S13, F-S14 | MockOpalDxe AsciiStrLen / offset macros | **Backlog**: bundle with the next mock change (e.g. the known fail-garbled gap) |
| F-S15 | matrix-script duplication | **Backlog**: extract sourced `sb-keys.sh` helper |
| F-S17 | run-qemu.sh trap/exec leak | **Accept + record** with an extended comment stating the local-leak tradeoff |
| F-S19 | lint pipeline duplicated | **Backlog**: make CI call `task lint` (can ride PR-C) |

Suggested PR bundles: **PR-A** `fix/opal-session-hardening-tests` (F-M1, F-M2, F-L1–L3, optionally F-L4); **PR-B** `fix/policy-truststore-nits` (F-S6–S9); **PR-C** `chore/ci-harness-oracle-integrity` (F-S11, F-S16, F-S18–S20, optionally F-S19). The fork items (F-L5, F-S4, F-S5) travel together under ADR-0008 as the next `-tpba` tag plus the upstream submission.