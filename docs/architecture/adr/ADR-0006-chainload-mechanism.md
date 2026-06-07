# ADR-0006: Phase 1 chainload mechanism (LoadImage/StartImage via go-boot)

## Status
Proposed (chainloader behavior is a §5.3 human-gated change — pending Release/Security Owner approval on PR #31)

## Context
Phase 1 (#15/#16) requires the PBA to open the EFI System Partition and chainload a
second-stage EFI image. go-boot v1.6.2 exposes `x64.UEFI.Root()` (single-volume:
the ESP the running image was loaded from; returns an `io/fs.FS`) and
`x64.UEFI.Boot.LoadImage` / `StartImage`. It does **not** expose
`LocateHandleBuffer`/`OpenProtocol`, so multi-volume handle enumeration is not
available without adding bindings.

## Decision
Chainload via go-boot's single-volume model:
`root := x64.UEFI.Root()` → `Boot.LoadImage(0, root, target)` → `Boot.StartImage(img)`,
failing closed on any error (report, then `halt()`; never report success or
continue). `target` is link-time overridable; Phase 1 uses a test fixture.

**Explicitly deferred (NOT in Phase 1):** image verification (signature/hash/
revocation) and Secure Boot state enforcement before load. These are the trust
gate added in **Phase 2** (Secure Boot test matrix) and **Phase 3** (policy
engine) / **Phase 7** (shim-like LoadImage wrapper). **Therefore this build is
CI/dev-only and MUST NOT gate a real boot until that gate exists.**

## Alternatives Considered
- **Handle enumeration / multi-volume ESP discovery** — not available in go-boot
  v1.6.2; would require adding `LocateHandleBuffer`. Deferred; single-volume is
  sufficient (the PBA loads from the same ESP it booted from).
- **Manual PE/COFF loader + Authenticode (plan Approach B)** — rejected for now;
  high risk/maintenance, deferred to a controlled custom path if ever needed.
- **Verify images now** — deferred to Phase 2/3 per the phase plan; doing it here
  would pull Secure Boot scope forward.
- **Second TamaGo image as the test fixture** — rejected: go-boot's `uefi/x64`
  re-initializes CPU/heap on entry and `#GP`s on top of the running PBA. The
  fixture is an independent, relocation-free gnu-efi app instead.

## Security Impact
Introduces the chainload attack surface: a successfully-loaded image is started
without PBA-side verification, so an attacker who can write the ESP `target` could
have it started (depending on firmware Secure Boot). This is acceptable **only**
because (a) the product performs no SED unlock yet, and (b) this build is CI/dev-
only per the Decision. The `halt()` `Boot.Exit` fallback is a residual fail-open
path ("continue to next boot option") — documented in-code as last-resort and not
to be copied into the unlock/policy phases. These two risks must be carried into
`docs/security/threat-model.md` (#4) and `docs/compliance/risk-assessment.md` (#5)
when those are authored.

## Compliance Impact
Satisfies the §23 ADR requirement and the §5.3 human gate for chainloader behavior
(via approval of PR #31). CRA "secure by default" is **not yet** met — verification
deferral is recorded here and must be reflected in the CRA essential-requirements
matrix (#7). gnu-efi is a new build-time toolchain dependency for the test fixture
(track under §14 / #27).

## Test Impact
Covered by two QEMU/OVMF smokes: the happy path (PBA → LoadImage+StartImage →
`TEST-APP: ok` → `chainload returned`) and a **fail-closed negative test** (no
target staged → `chainload failed`, and the success markers must NOT appear).
Verification/Secure-Boot tests arrive with Phase 2/3.

## Rollback Plan
Revert the `chainload()`/`halt()` addition in `cmd/pba/main.go`; the PBA returns to
the Phase 0 print-and-halt behavior. The fixture and harness changes are test-only
and independent.
