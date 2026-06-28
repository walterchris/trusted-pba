# ADR-0009: Policy-gated SED unlock in the boot path

## Status
Accepted — §5.3/§23 human gate satisfied by the Release Owner merging the
Phase 6 wiring PR (#59). Authored in Phase 6 (#22, #51 item 2). Amended
2026-06-28 (**Proposed**): SED device selection among multiple Storage Security
carriers + ComID byte-swap for the EFI transport, from the first real-hardware
bring-up — pending the §5.3/§23 human gate (Release Owner merge); see *Amendment
2026-06-28* below.

## Context
Phases 4/5 delivered the fail-closed Opal unlock library (`internal/opal`, with
PIN zeroization and a partial-unlock caller contract on `Client.Unlock`) and the
UEFI Storage Security transport (`internal/transport`), but neither was wired
into the boot flow — threat model A1/A7 stood at "in-library, not yet wired".
Phase 6 connects them: the PBA must unlock the SED (and set MBRDone) between
policy enforcement and chainload, without ever opening a silent fallback for
deployments or virtual tests that have no Opal device.

## Decision
- **Explicit policy gate.** A new policy field `sed_unlock` with exactly two
  values: `required` (the boot path must complete the full unlock before any
  target selection/chainload) and `none` (this deployment has no SED). There is
  no implicit behavior: an **absent field means `required`** (fail closed), and
  `none` is logged loudly at boot ("sed unlock not required by policy") so
  skipping the unlock is always a visible, explicit policy statement — never a
  silent fallback.
- **Flow when required:** construct the UEFI Storage Security transport →
  `opal.Client.Unlock` (Discovery0, authenticated Admin1 session, global-range
  unlock, MBRDone, EndOfSession) → only on success continue to target selection
  and chainload. **Any** error — no Storage Security device, transport error,
  auth failure, partial unlock — logs the failing stage (never the PIN or
  session material) and terminates via the policy's on-error action
  (halt/shutdown/reboot). No retry loop, no fallback to chainload; a partially
  unlocked drive ends at the same dead-stop, and reboot/power-cycle returns the
  drive to its locked-on-reset state (#51 item 2).
- **MVP PIN source: the compiled-in policy** (`sed_pin`, allowed by plan §7.1
  for MVP). `required` without a PIN is rejected at parse time (the policy is
  the only PIN source, so it could never succeed); `none` with a PIN is rejected
  as a stray credential. The wiring moves the PIN out of the policy and hands it
  to `Unlock` exactly once, which consumes and zeroizes it; the wiring makes no
  copy and clears the slice itself on the one path `Unlock` never sees it.
  **Production replaces this before any real deployment** with real
  authentication (console prompt / TPM / challenge-response); when the console
  prompt lands, the #51 console-input scrub obligation (zeroizing the input
  buffer the PIN was typed into) attaches to that change.

## Amendment (2026-06-28): SED device selection + ComID byte-swap (hardware bring-up)

**Status: Proposed.** This is the security-relevant decision of the first
real-hardware bring-up (a Swissbit OPAL drive on a 4-NVMe test board); the §5.3/§23
human gate is the Release Owner merging this branch. The original Phase 6 flow
above assumed a single Storage Security carrier (true for the single-device EDK2
MockOpalDxe); real firmware breaks that assumption two ways. Both are
correctness/conformance fixes — **neither changes the unlock security model**:
unlock still requires the Admin1 PIN and fails closed on any error.

1. **SED selection among multiple Storage Security carriers.** A multi-NVMe machine
   exposes one `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` handle per drive; most are
   non-Opal disks that reject TCG commands with `EFI_DEVICE_ERROR`. The transport
   used the first instance — a non-Opal disk on the test board — so unlock failed
   before it began. **Decision:** `transport.NewAll()` enumerates every handle
   (go-boot `v1.6.2-tpba.5`, ADR-0008 Amendment 2026-06-28) and returns one
   transport per carrier; `cmd/pba selectSED` picks the one whose **Level-0
   Discovery succeeds** (the Opal SED) and unlocks only that one. Discovery is
   read-only and PIN-free, so probing the non-SED carriers (which error) touches no
   credential; the PIN is consumed and zeroized exactly once, on the selected
   device. Fail-closed is preserved: **no Discovery-responsive SED → hard error,
   never chainload** (`selectSED` returns "no Opal SED among N storage security
   device(s)"). Selection (a Discovery probe) is Opal protocol logic and lives in
   `cmd/pba`/`internal/opal`, **not** in the transport layer (which only enumerates
   carriers).

   The **earlier "MediaId 0" hypothesis was DISPROVEN** — MediaId 0 is correct; no
   `EFI_BLOCK_IO`/MediaId derivation was needed or added (see ADR-0008 Amendment
   2026-06-28).

2. **ComID byte-order for the EFI transport.** EDK2 firmware places the
   `SecurityProtocolSpecificData` UINT16 onto the SECURITY PROTOCOL command in the
   **opposite byte order** to TCG's on-wire ComID, so Level-0 Discovery (ComID
   `0x0001`) returned a zero-filled buffer until passed as `0x0100`. **Decision:**
   `transport.UEFI.swapComID` byte-swaps every ComID on `Send`/`Recv`; the EDK2
   MockOpalDxe mirrors it (swaps back); the host MockTPer bypasses this transport
   entirely and is unaffected. This is a transport-layer conformance detail, not a
   security-model change.

**Accepted residual (multi-SED targeting).** Selecting a *specific* drive among
**multiple Opal SEDs** is a future refinement. Today the boot path takes the
**first Discovery-responsive SED**. If that is the wrong SED for the policy's PIN,
authentication simply fails → fail closed (the drive stays locked, no chainload);
it never unlocks the wrong drive silently. Naming/pinning the intended SED (by
serial, device path, or policy) is tracked for a later phase. No rating change.

The code comments in `cmd/pba/sedunlock.go` (`selectSED`) and
`internal/transport/uefi_tamago.go` (`NewAll`/`swapComID`) cite ADR-0009/ADR-0008;
this amendment and the ADR-0008 Amendment 2026-06-28 cover what they cite.

**Test impact (this amendment).** Host unit tests added (`cmd/pba`,
`c962b12`): `TestUnlockSEDSelectsResponsiveSED` (selectSED skips a carrier that
fails Discovery and authenticates the responsive SED; the PIN is spent on the
selected device, the dead carrier left locked) and
`TestUnlockSEDNoResponsiveSEDFailsClosed` (no responsive carrier → hard error,
nothing unlocked, PIN still consumed). `TestUnlockSEDFailsClosedWithoutCarrier` and
the host `transport` fail-closed test move from `New` to `NewAll`. The QEMU
MockOpalDxe matrix (single handle) still passes — selection collapses to the one
carrier, and the mock's `MOCK_COMID` swap proves the byte-order round-trip.

**Real-hardware status.** Unlock now reaches `StartSession` on the real drive; the
remaining session-setup conformance gap (Properties exchange / Authenticate) is
tracked separately. **Production still replaces the compiled-in MVP PIN with real
authentication** (unchanged from the original Decision).

## Alternatives Considered
- **Always require unlock** — breaks every non-SED deployment and all existing
  QEMU CI tests (no Storage Security device present). Rejected.
- **Implicit detection** (unlock if a Storage Security device happens to be
  present, otherwise continue) — a silent secure-to-insecure fallback: removing
  or hiding the device would skip the unlock. Forbidden by the never-silently-
  fall-back rule. Rejected.

## Security Impact
Wires A1 (unlock secret) and A7 (session state) into the live boot path. The
gate is fail-closed at every level: absent field = required; required + any
failure = on-error action (never chainload, never retry); a missing device under
`required` is a hard failure. Residual (accepted for MVP, documented in the risk
assessment): the compiled-in PIN is embedded in the policy JSON inside the
binary — it is extractable from the image and transient unscrubable copies exist
in the embedded JSON bytes, the JSON decoder's intermediate string, and the
`json.Decoder`'s internal read buffer. This is
exactly why the compiled-in PIN is test-only and replaced before production.
R-002 mitigation moves from "library only" to "wired, virtual-tested"; hardware
validation remains Phase 8.

## Compliance Impact
Threat model A1/A7 rows and risk assessment R-002 updated (changelogged). The
test credential in fixtures/policies is the shared-spec value
(`test/fixtures/opal`), never a real secret. No release/signing behavior
changes.

## Test Impact
Host unit tests cover the policy gate parsing (absence = required; unknown
values, required-without-PIN, none-with-PIN rejected) and the wiring
(`cmd/pba/sedunlock.go`, tag-free so it is host-testable): loud skip on `none`,
happy path against the native MockTPer (unlocked + MBRDone), fail-closed on
wrong PIN / transport fault / missing carrier, single transport construction (no
retry), and PIN consumption+zeroization on every path. Existing QEMU CI tests
(no mock Opal driver) carry explicit `"sed_unlock": "none"` policies. The
end-to-end QEMU path (EDK2 MockOpalDxe → unlock → chainload, plus the fail-
closed negative) is the next Phase 6 ticket, keyed on the serial markers
`sed unlock ok` / `sed unlock failed` / `sed unlock not required by policy`.

## Rollback Plan
Revert the wiring commit(s): remove `cmd/pba/sedunlock.go` and the `run()` call,
drop the `sed_unlock`/`sed_pin` policy fields and the `"none"` lines from the
embedded test policies. `internal/opal` and `internal/transport` are untouched
(one doc comment aside), so Phases 0–5 behavior is fully restored.
