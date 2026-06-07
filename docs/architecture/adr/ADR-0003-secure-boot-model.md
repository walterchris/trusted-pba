# ADR-0003: Secure Boot trust model

## Status
Proposed (Secure Boot behavior is a §5.3 human-gated decision — pending Security/Release Owner approval on the Phase 2 PR)

## Context
The PBA runs before the OS and must be Secure-Boot-aware (plan §4.5, §5). It must
not weaken the platform trust chain, and CLAUDE.md forbids treating Secure Boot
disabled and enabled as equivalent. We must decide how the PBA fits into Secure
Boot and how we test it.

## Decision
Adopt **Approach A (shim-like trust broker)** from the plan:

1. **Firmware validates the PBA.** `trusted-pba.efi` is signed by a key in the
   firmware `db`; under enforcing Secure Boot the firmware refuses to load an
   unsigned/untrusted PBA. The PBA does **not** modify firmware Secure Boot
   variables at boot and does **not** hook the Security2 architectural protocol
   (plan §5 A2 — rejected as too firmware-sensitive).
2. **The PBA detects Secure Boot state** (`SecureBoot`/`SetupMode` global
   variables) and reports it. *Enforcing* = `SecureBoot==1 && SetupMode==0`.
   Phase 2 is detection + reporting; *enforcing a policy* (e.g. refusing to proceed
   when not enforcing) is deferred to the policy engine (Phase 3).
3. **Second-stage validation:** Windows path → let firmware validate Windows Boot
   Manager; custom path → the PBA applies its own policy (Phase 3) and/or a
   shim-like LoadImage wrapper (Phase 7). Under enforcing Secure Boot today, the
   firmware already validates the chainloaded image (LoadImage SourceBuffer →
   db/dbx) — demonstrated by the test matrix.
4. **Keys:** test PK/KEK/db are generated throwaway and enrolled into an OVMF
   variable store with `virt-fw-vars`; signing uses `sbsign`. Production/customer
   signing and key provisioning are out of scope here (separate flow; never from
   developer machines; never commit private keys — baseline §13).

## Alternatives Considered
- **A1 — wrap LoadImage/StartImage (shim-like wrapper):** the long-term product
  architecture for PBA-validated custom images; scheduled for Phase 7, not needed
  for the Phase 2 foundation.
- **A2 — hook EFI_SECURITY2_ARCH_PROTOCOL:** rejected — invasive, firmware-
  sensitive, can interfere with measured boot.
- **Approach B — manual PE/COFF loader + Authenticode:** rejected as the default;
  reserved for controlled custom images if ever required.

## Security Impact
Establishes the trust chain: firmware → PBA → (firmware- or PBA-validated)
second stage. Phase 2 delivers detection + the test matrix; it does **not** yet
enforce "refuse when not enforcing" (deferred). The matrix proves the firmware
rejects an unsigned PBA under enforcing Secure Boot (fail closed) and that a signed
PBA + signed chainload target load.

## Compliance Impact
Satisfies the §5.3 human gate (Secure Boot behavior) and §23 ADR requirement via
approval of the Phase 2 PR. Advances CRA "secure by default" (SB test matrix
exists); full enforcement and the target/revocation matrix (#37) follow. Test keys
only (§13). The threat model (#4) and risk assessment (#5) must capture the Secure
Boot trust chain (a core asset, baseline §10) and the Phase-2 detection-failure
fail-open boundary; that documentation is deferred to those issues and tracked here.

## Test Impact
Secure Boot matrix (`task sb-matrix`): SB-off unsigned boots; SB-on signed boots;
SB-on unsigned rejected by firmware (fail closed). Plus a host unit test for the
`secureboot.State.Enforcing()` logic.

## Rollback Plan
Revert the `secureboot` detection call and the matrix tooling; the PBA still boots
(Phase 1 behavior). The product modifies no firmware Secure Boot variables, so
there is nothing persistent to undo.
