# ADR-0005: Virtual SED test strategy — EDK2 mock driver now, QEMU device model later

## Status
Accepted (2026-06-07)

## Context
QEMU provides no ready-to-use upstream TCG Opal SED emulator. We need a way to test
the PBA's Opal unlock + chainload flow virtually, in CI, without real hardware. Two
candidate "modify the world" approaches exist, and they test different layers:
- An **EDK2 mock DXE driver** that installs `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL`
  and answers like a fake Opal device — tests *our* code path inside real OVMF.
- A **QEMU device model** that models a locked SED with Shadow-MBR block visibility
  — tests the firmware/transport layer *below* our code, including in-session
  MBRDone semantics.

## Decision
Build the EDK2 `MockOpalDxe` driver (on top of a native Go Opal simulator) as the
primary virtual integration test **now**. Keep a QEMU virtual SED device model as a
**planned later phase**, built only after the PBA architecture is proven; real
hardware bring-up (plan Phase 8) may answer the same questions with more authority
and reduce its priority. See [`../../test-tooling-plan.md`](../../test-tooling-plan.md).

## Alternatives Considered
- **QEMU device model first** — highest fidelity but requires patching/forking QEMU
  (its NVMe/AHCI models lack Opal security send/receive) and depends on OVMF driver
  support. High effort/maintenance for diminishing returns in validating our code.
- **Native Go simulator only** — fast and deterministic but never exercises the real
  UEFI protocol path; insufficient as the sole integration test.

## Security Impact
Neither mock is shipped in the product; product code must not depend on test
tooling. Mocks must be able to produce failure as well as success so the PBA's
fail-closed behavior on Opal failure is provable.

## Compliance Impact
Supports CRA "effective and regular security testing" and the baseline §17 test
strategy with a hardware-free, deterministic virtual path. Committing to the QEMU
model later warrants its own ADR.

## Test Impact
Native Go simulator and EDK2 mock must share a single fake-Opal spec and golden
fixtures (`test/fixtures/opal/`) so the two layers stay behaviourally consistent.

## Rollback Plan
If the EDK2 mock cannot adequately exercise the protocol path, escalate the QEMU
device model from "later" to "now" via a follow-up ADR, or rely on early
real-hardware bring-up.
