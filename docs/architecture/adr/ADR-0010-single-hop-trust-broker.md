# ADR-0010: PBA is a single-hop trust broker — no boot-services wrapping

## Status
Accepted (2026-06-12). The scope of boot-chain validation is a §5.3 human-gated
decision; the gate is satisfied by the Owner's explicit direction to drop the
loader-wrapper feature. Supersedes the "Phase 7 — shim-like loader wrapper"
ambition in the product plan (Approach A1).

## Context
The PBA is a pre-boot trust broker: firmware Secure Boot validates
`trusted-pba.efi`, and the PBA then unlocks the SED and starts the next stage
under customer-controlled policy. From Phase 3/6 the PBA already validates **the
image it hands control to**:

- `firmware`-validation targets (e.g. Windows Boot Manager) are loaded with the
  firmware's `LoadImage`/`StartImage`, so firmware Secure Boot validates them;
- `pba`-validation targets are verified by `internal/imageverify` against the
  embedded trust store (Authenticode + dbx) and loaded from the verified buffer
  (ADR-0006/0007, #46); any failure fails closed.

The plan's Phase 7 (Approach A1) proposed going further: **wrapping the firmware's
`LoadImage`/`StartImage`** so the PBA's policy would also gate images that the
*next* stage loads after handoff (shim→GRUB→kernel, a custom loader→its modules) —
a transitive, shim/MOK-style enforcement layer persisting across the whole boot.

Two findings bear on whether to build that:

1. **Feasibility.** Persistent firmware-table hooks require firmware/next-stage C
   code to call *into* Go through a swapped function pointer — a UEFI→Go
   reverse-ABI callback. go-boot's UEFI model is one-way (Go→firmware: `callFn`
   abandons the Go stack for a scratch stack, does not preserve `g`, and `CLI`s on
   return; no foreign-entry path). A reverse trampoline is feasible *in principle*
   (TamaGo's CPU-exception entry is precedent) but is substantial, novel runtime
   work — `g`/TLS survival across the handoff, a dedicated Go callback stack, and
   GC/reentrancy — in a security-critical boot path.
2. **Necessity.** Transitive enforcement is **redundant** on the paths that matter:
   firmware Secure Boot already validates the Windows chain, and shim already
   brokers its own downstream trust (MOK, SBAT) for the Linux chain. Its only
   distinctive value is a custom non-shim loader that does not broker its own trust
   *and* a customer policy stricter than firmware db *and/or* Secure Boot off — a
   narrow, not-yet-demonstrated case. No hardware bring-up or customer requirement
   has surfaced a real need.

## Decision
**The PBA is a single-hop trust broker.** It validates the one image it chainloads
(per policy: firmware-validated or PBA-validated) and then transfers control. It
does **not** wrap or replace firmware boot services, and it does **not** attempt to
enforce its trust policy transitively on what the next stage loads.

The loaded EFI application owns its own downstream trust: it establishes its own
trust broker (as shim does for GRUB/kernel via MOK/SBAT) or relies on the keys
provisioned in firmware (Secure Boot db/dbx). Extending the PBA's policy *into* the
next stage is explicitly out of scope.

Consequently the **Phase 7 "shim-like loader wrapper" is dropped**; epic #23 is
closed as won't-do. The comparable A2 (Security2 protocol hooking) and Approach B
(manual PE/COFF loader) remain out of scope as before.

## Alternatives Considered
- **Approach A1 — wrap `LoadImage`/`StartImage` (the dropped feature).** Best
  long-term reach of enforcement, but requires the risky UEFI→Go reverse-ABI
  trampoline (finding 1) for a benefit that is largely redundant with firmware and
  shim (finding 2). Rejected now; may be reconsidered if a concrete deployment
  needs transitive enforcement a downstream loader does not provide — at which
  point this ADR would be superseded and the trampoline spiked under its own ADR.
- **A2 — hook `EFI_SECURITY2_ARCH_PROTOCOL`.** More invasive/firmware-sensitive,
  may interfere with measured boot; the plan already recommends against starting
  here. Rejected.
- **Approach B — manual PE/COFF loader for all targets.** High responsibility, may
  bypass measured boot, Windows Boot Manager may not tolerate it. Rejected as a
  default; the `pba`-path already does verified-buffer loading via firmware
  `LoadImage` (ADR-0006), not a hand-rolled loader.

## Security Impact
No reduction in the PBA's actual guarantees: it still validates every image **it**
loads and fails closed. The trust boundary is stated precisely — the PBA does not
claim to police the next stage's own loads (threat model TB2). On the Windows path,
firmware Secure Boot governs the chain; on the shim path, shim governs it; a custom
loader is responsible for its own downstream validation. The decision avoids adding
a complex, hard-to-review reverse-ABI callback to the boot-critical path, which is
itself a security benefit (smaller attack surface, no new TCB runtime machinery).

## Compliance Impact
Clarifies the CRA "integrity" essential requirement (ER-2) scope in the
essential-requirements matrix: integrity is enforced for the image the PBA loads,
not transitively. No change to classification. Resolves the plan's open question on
loader-wrapping. ADR recorded as the §5.3 evidence for the boot-chain-validation
scope decision.

## Test Impact
None — no code changes. The existing `pba-matrix` / `secureboot-matrix` /
`mock-opal-matrix` continue to prove the single-hop validate-then-handoff behavior
(firmware rejects an untrusted PBA; the PBA rejects an untrusted `pba`-path target;
fail-closed on every error). No wrapper tests are added because no wrapper exists.

## Rollback Plan
If a real deployment later requires transitive enforcement (a customer loader that
does not self-broker, under a stricter-than-firmware policy), reopen the question:
supersede this ADR, timebox the UEFI→Go trampoline PoC (the documented feasibility
risks first), and gate it behind a demonstrated requirement. Nothing in the current
codebase needs to be undone to do so — this decision removes planned work, it does
not add anything to revert.
