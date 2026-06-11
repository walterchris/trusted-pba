# ADR-0001: Use TamaGo as the bare-metal Go runtime for the PBA

## Status
Accepted (2026-06-07). Recorded retroactively as a foundational decision
(baseline §6); the choice predates the ADR log and is realised throughout
`cmd/pba` and `internal/`.

## Context
Trusted PBA is a UEFI application that runs before any operating system. We need
a language and runtime in which to write it that:

- produces a freestanding x86_64 PE/COFF EFI application (no host OS, no libc),
- can call UEFI boot services and locate/use UEFI protocols,
- gives us a memory-safe language for security-critical parsing (TCG Opal
  responses, PE/Authenticode, policy) where C's manual memory management is a
  recurring source of pre-boot vulnerabilities, and
- is productive enough to build a non-trivial policy/Opal/transport stack.

The conventional choice for UEFI code is C (EDK2). The alternative the project was
founded on is Go, for memory safety and developer velocity, which requires a
bare-metal Go runtime since the standard `gc` runtime assumes an OS.

[TamaGo](https://github.com/usbarmory/tamago) is a bare-metal Go runtime/compiler
fork (maintained by F-Secure/WithSecure, usbarmory) that already targets UEFI
x86_64 and runs Go without an operating system. `usbarmory/go-boot` builds on it to
provide the UEFI board layer (CPU/serial bring-up, System Table parsing, heap) and
a set of UEFI protocol wrappers.

## Decision
Build `trusted-pba.efi` as a **TamaGo** application. Pin the TamaGo toolchain
(`go1.26.4` build, `usbarmory/tamago` library) and the `go-boot` board layer; the
PBA's `cmd/pba` `//go:build tamago && amd64` entry point relies on go-boot's
`uefi/x64` package for automatic bring-up on import. Host (`!tamago`) stubs keep
`go test`/`go vet`/lint working off-target.

## Alternatives Considered
- **C / EDK2** — the standard UEFI toolchain with the broadest protocol support,
  but manual memory management in a pre-boot security product is exactly the risk
  class we want to avoid; and it forgoes Go's stdlib (crypto/x509, encoding) that
  the policy/verification layers lean on. Rejected as the primary language; we
  still use a *small* amount of EDK2 C for **test tooling only** (MockOpalDxe,
  ADR-0005), never in the product.
- **Rust / `r-efi` + `uefi-rs`** — memory-safe with mature UEFI bindings and
  arguably the most natural fit. Rejected for this project on team-familiarity and
  velocity grounds, not technical merit; revisit if TamaGo's maintenance or
  protocol gaps become limiting.
- **Standard Go with a custom UEFI shim** — not viable: the `gc` runtime assumes
  an OS (threads, syscalls, mmap) that does not exist pre-boot.

## Security Impact
Memory safety across the attacker-facing parsers (Opal device responses, PE images
from the ESP, policy) is a direct mitigation for the parser-bug class (risk R-009)
and supports the fail-closed posture. TamaGo and go-boot become part of the trusted
computing base; their supply-chain risk is managed by pinning + `go.sum` and tracked
under R-006 and dependency onboarding (#27). The fork policy for go-boot is
ADR-0008. Hand-written assembly is confined to the go-boot dependency layer, not the
product (ADR-0008 *Alternatives Considered*).

## Compliance Impact
Supports CRA "secure by design" and ISO 27002 A.8.27/A.8.28 (secure architecture /
secure coding) by choosing a memory-safe language for a security-critical product.
TamaGo/go-boot/tamago must appear in the SBOM and dependency due-diligence
(baseline §14, §19; #27). No effect on CRA classification.

## Test Impact
Establishes the dual-build model the whole test strategy depends on: host-buildable
`!tamago` stubs make `internal/*` unit-testable and fuzzable without firmware, while
the real UEFI path is exercised in QEMU/OVMF (ADR-0005). TamaGo-only files
(`//go:build tamago && amd64`) are not host-linted and are reviewed by hand.

## Rollback Plan
Reversing the runtime choice is a rewrite, not a revert — there is no cheap
rollback. If TamaGo proves untenable (unmaintained, unfixable protocol gaps), the
realistic path is a port to Rust/`uefi-rs` or C/EDK2, re-using the
language-agnostic design (the layered architecture, the policy/Opal/transport
split, the test fixtures and shared Opal spec) rather than the Go source. The
`TCGTransport` abstraction (ADR-0004) and the byte-faithful Opal spec are
deliberately portable to ease such a port.
