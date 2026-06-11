# ADR-0002: UEFI-native PBA — stay in boot services, never call ExitBootServices

## Status
Accepted (2026-06-07). Recorded retroactively as a foundational decision
(baseline §6); it is the architectural premise of the whole product and is
realised by `cmd/pba` chainloading via firmware `LoadImage`/`StartImage`
(ADR-0006) rather than booting a kernel.

## Context
A Pre-Boot Authentication environment must authenticate, unlock the SED, disable
the Shadow MBR, and then hand control to the real OS bootloader. The dominant
existing approach is a **Linux-based PBA**: a small Linux kernel boots from the
Shadow MBR, unlocks the drive, then calls `ExitBootServices()` and kexecs or
chainloads onward.

That approach has a structural defect for our goal. Once `ExitBootServices()` is
called, the UEFI boot-services environment is gone: the firmware's
`LoadImage`/`StartImage`, the Secure Boot image-verification path, and the boot
manager are no longer available. Cleanly launching **Windows Boot Manager** — a
UEFI application that expects to run in a normal UEFI boot environment, validated
by firmware Secure Boot — is then effectively impossible, and measured/secure boot
continuity is broken.

Our product goal is a Secure-Boot-compatible PBA that hands off cleanly to Windows,
shim/GRUB, or a customer EFI app. That requires staying inside UEFI boot services
through the handoff.

## Decision
Build the PBA as a **UEFI-native application that never calls
`ExitBootServices()`**. It remains a UEFI boot-services client for its entire
lifetime and transfers control to the next stage with the firmware's own
`LoadImage`/`StartImage` (ADR-0006), so:

- the firmware validates Windows Boot Manager via Secure Boot on the normal path,
- the PBA can additionally act as a second-stage trust broker for custom images
  (`internal/imageverify`, ADR-0007), and
- the boot environment the OS loader expects is intact at handoff.

The fail-closed terminal action on any error is halt/reset (`terminate`), never a
return to the firmware boot order and never a kernel boot.

## Alternatives Considered
- **Linux-based PBA (kexec/chainload after `ExitBootServices`)** — mature and
  flexible, but forfeits clean UEFI/Windows handoff and Secure Boot continuity (the
  motivating defect above). Rejected.
- **Custom PE/COFF loader + manual Authenticode (Approach B)** — load and verify
  the next stage entirely ourselves without firmware `LoadImage`. Maximum control
  but high responsibility, may bypass measured boot, and Windows Boot Manager may
  not tolerate it. Rejected as the default; see ADR-0006/ADR-0007. Reserved for
  controlled custom images only.

## Security Impact
Keeping firmware Secure Boot in the loop for the Windows path means we do not
re-implement (and cannot weaken) Authenticode validation for it; the PBA adds
policy on top rather than replacing the root of trust (TB1/TB2 in the threat
model). Never calling `ExitBootServices` preserves the firmware's verification and
(future) measured-boot services through handoff. The no-fallback-to-boot-order
terminal behavior is the fail-closed backstop (R-002/R-008, ADR-0009).

## Compliance Impact
Central to the CRA "secure by default" and "integrity" essential requirements:
targets are firmware- or PBA-verified before control transfer, and the design never
drops to an unverified boot path. Anchors the architecture documentation
(boot-flow, chainloader-design) in the CRA technical-documentation package
(baseline §21).

## Test Impact
Validated by the QEMU/OVMF chainload smoke and matrices: the PBA boots under OVMF,
chainloads a test app via firmware `LoadImage`/`StartImage`, and the Secure Boot
matrix proves firmware rejects an unsigned/untrusted PBA and that signed handoff
works — all without the PBA ever leaving boot services. Negative tests assert the
fail-closed terminal action instead of a boot-order fallback.

## Rollback Plan
This is the product's defining premise; abandoning it would mean building a
different product (a Linux-style PBA) and is out of scope for a rollback. Specific
mechanisms layered on top — the chainload mechanism (ADR-0006), PBA-side
verification (ADR-0007) — have their own rollback plans without disturbing this
decision.
