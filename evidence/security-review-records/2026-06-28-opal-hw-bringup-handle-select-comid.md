# Security review record — first real-hardware SED unlock bring-up: multi-device handle selection + ComID byte-order

- **Date:** 2026-06-28
- **Branch / commits:** `feat/opal-hw-handle-select-comid` — `94f4327`
  (`fix(opal): select the SED among multiple SSC devices + swap ComID for UEFI (hw
  bring-up)`) and `c962b12` (`test(opal): cover selectSED fail-closed selection +
  clarify comments`).
- **Change under review:** the **first real-hardware bring-up** of the SED unlock
  path, validated on a **Swissbit OPAL drive** in a 4-NVMe test board **and** against
  the QEMU MockOpalDxe integration matrix. Two real-hardware correctness/conformance
  fixes to the unlock path (neither changes the unlock security model — unlock still
  requires the Admin1 PIN and fails closed):
  1. **Multi-drive Storage Security handle selection.** Real firmware exposes one
     `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` handle **per NVMe drive** (4 on the test
     board); the transport used the *first* instance — a non-Opal disk that rejects
     TCG commands with `EFI_DEVICE_ERROR`. Now `transport.NewAll()` enumerates every
     handle (one transport each) and `cmd/pba selectSED` picks the one whose **Level-0
     Discovery succeeds** (the Opal SED), then unlocks it. Fail-closed preserved (no
     Discovery-responsive SED → hard error, never chainload; the PIN is consumed and
     zeroized exactly once, on the selected device).
  2. **ComID byte-order.** EDK2 firmware places `SecurityProtocolSpecificData` onto
     the SECURITY PROTOCOL command in the **opposite byte order** to the TCG ComID,
     so Level-0 Discovery (ComID `0x0001`) returned a **zero-filled buffer** until
     passed as `0x0100`. `transport.UEFI.swapComID` byte-swaps every ComID on the EFI
     transport; the EDK2 MockOpalDxe mirrors it (swaps back, `MOCK_COMID`); the host
     MockTPer bypasses this transport entirely and is unaffected.
  3. **go-boot fork pin `v1.6.2-tpba.4` → `v1.6.2-tpba.5`** (ADR-0008 Amendment
     2026-06-28): adds `LocateHandleBuffer` + the `EFI_LOCATE_SEARCH_TYPE` consts +
     `FreePool` (slot `0x48`), and handle-aware Storage Security
     (`LocateStorageSecurityHandles` / `GetStorageSecurityByHandle` /
     `newStorageSecurity`). Published tag; `go.sum` hash recorded.
- **Reviewers:** independent **go-reviewer** and independent **security-review agent**
  (neither implemented). The Compliance Agent (this record) updated docs/evidence and
  traceability; it did not write product code and does not gate release.
- **Verdict:** go-reviewer **APPROVE-WITH-NITS**; security-review **BLOCK → CLEARED**
  (see Findings). The §5.3/§23 human gate (Release Owner merge) is **pending** —
  ADR-0009 Amendment 2026-06-28 carries **Status: Proposed** until then.

## Root-cause chain (the bring-up story)

The first attempt to unlock the real Swissbit drive failed before authentication.
The root cause was found in three steps:

1. **"MediaId 0" hypothesis — DISPROVEN.** The first hypothesis was that the
   firmware needed a non-zero MediaId derived from `EFI_BLOCK_IO`. It does not: the
   SED answers Discovery and unlock with **MediaId 0**. The contemplated
   `BlockIo`/MediaId derivation (and the "minimal MediaID-only" go-boot note) was
   **dropped** — no `BlockIo` path was added.
2. **Handle selection.** The real failure was that the transport talked to the
   *first* Storage Security handle — a non-Opal NVMe disk — which returned
   `EFI_DEVICE_ERROR`. Fix: enumerate all handles, select the Opal SED by Level-0
   Discovery.
3. **ComID byte-order.** With the right device selected, Discovery still returned a
   **zero buffer**: firmware writes the SP-Specific UINT16 in the opposite byte order
   to the TCG ComID. Fix: `swapComID` on the EFI transport (mock mirrors it).

After all three, **real-hardware unlock reaches `StartSession`** on the drive. The
remaining **session-setup conformance gap** (Properties exchange / Authenticate) is
**tracked separately** — it is not part of this change.

## Fail-closed invariant — confirmed

Selection does not open a silent fallback:

- **Selection is read-only and PIN-free.** `selectSED` probes each carrier with
  Level-0 Discovery (no credential); the non-SED carriers error and are skipped. The
  PIN is handed to `Unlock` exactly once, on the selected device, and zeroized.
- **No responsive SED → hard error.** `selectSED` returns `no Opal SED among N
  storage security device(s)`; `unlockSED` wraps it with the `sed unlock failed`
  stage marker and terminates via the policy on-error action — never chainload, no
  retry. Proven by `TestUnlockSEDNoResponsiveSEDFailsClosed` (nothing unlocked, no
  success marker, PIN still consumed).
- **Right device wins, dead carriers untouched.** `TestUnlockSEDSelectsResponsiveSED`
  injects a Discovery-failing carrier ahead of a healthy SED and proves the SED is
  unlocked (+ MBRDone), the dead carrier is left locked, and the PIN is spent on the
  selected SED.

## Reviewer checks

- **go-reviewer (APPROVE-WITH-NITS):** `NewAll` returns concrete `[]*UEFI`,
  caller widens to `[]opal.Transport` (Go has no covariant slice conversion — the
  element-wise loop is unavoidable and commented); errors checked and `%w`-wrapped;
  selection (Opal protocol logic) kept out of the transport layer; `swapComID` is a
  pure 1-line helper with a load-bearing doc comment; the intentional extra Discovery
  round-trip in `selectSED` is documented ("do not optimize away by caching").
- **security-review (BLOCK → CLEARED):** re-derived the fail-closed selection
  (read-only probe, PIN once, no-SED hard error), confirmed `swapComID` does not
  change the security model (transport conformance only; mock mirrors it; host
  MockTPer unaffected), and confirmed no fail-open path is introduced.

## Findings

| # | Severity | Finding | Disposition |
|---|----------|---------|-------------|
| F-1 | HIGH | Selection logic (`selectSED`) lacked negative coverage — skip-dead-carrier and no-SED-found were unverified, so a fail-open regression could pass CI | **CLEARED** in `c962b12`: `TestUnlockSEDSelectsResponsiveSED` + `TestUnlockSEDNoResponsiveSEDFailsClosed` added (skip + no-SED, PIN-consumption asserted on both). |
| F-2 | HIGH | Security-relevant decision (SED selection among multiple SSC carriers; ComID byte-swap; go-boot handle-aware surface) was unrecorded — the code comments cite ADR-0008/ADR-0009 but the ADRs did not yet cover it | **CLEARED:** ADR-0008 Amendment 2026-06-28 (`v1.6.2-tpba.5`, handle-aware SSC, MediaId-0-confirmed/BlockIo-dropped) and ADR-0009 Amendment 2026-06-28 (**Proposed**: SED selection + ComID byte-swap + multi-SED residual). |
| F-3 | MEDIUM | No evidence record / risk-threat changelog for the first hardware bring-up | **CLEARED:** this record; risk-assessment R-002 + R-006 changelog (2026-06-28); threat-model A1/A7 changelog (2026-06-28); pin tpba.4 → tpba.5 across risk/threat/dependency/CRA docs + ADR-0008. |

## Risk disposition

- **R-002** (PBA unlocks SED before auth): mitigation extends from "QEMU e2e,
  hardware-pending" to **first real-hardware bring-up reaching `StartSession`**, with
  the new fail-closed *selection* path unit-tested. Residual stays **Medium**
  (hardware validation now in progress; session-setup conformance gap tracked
  separately). No rating change.
- **R-006** (malicious update / compromised dependency): pin → `v1.6.2-tpba.5`;
  additive handle-aware surface, no new upstream-file edit beyond the three carried
  since tpba.3/tpba.4; published-tag `go.sum` hash recorded. The bump pulled new
  **indirect** deps (usbarmory stack: `gvisor`, `gliderlabs/ssh`, `arl/statsviz`,
  `armory-boot`, `go-net`, `x/term`/`x/time`/`x/exp`, etc.) — these are `// indirect`
  and **not reachable from the `tamago && amd64` `trusted-pba.efi` build graph**
  (reachability verified separately); the #27 dependency scan covers the fork's full
  transitive set. Residual stays **High** until the update/signing pipeline lands.
- **Accepted residual — multi-SED targeting.** Selecting a *specific* drive among
  **multiple Opal SEDs** is a future refinement; today the first Discovery-responsive
  SED is taken, and a wrong-drive pick just fails auth → fail closed. Tracked for a
  later phase. No rating change.

## §5.3 human gate

ADR-0009 Amendment 2026-06-28 changes the Opal unlock flow — a §5.3 mandatory human
gate (Opal unlock flow). Status is **Proposed**; the gate is the **Release Owner
merging this branch**. No key material or secret committed.
