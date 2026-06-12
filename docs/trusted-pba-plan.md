# Trusted PBA for Self-Encrypting Devices — Project Plan

> Working project name: **trusted-pba**

## 1. Project Goal

We want to implement a new type of Pre-Boot Authentication (PBA) environment for
self-encrypting drives, especially TCG Opal / SED devices.

The core idea is to build a **UEFI-native PBA** that runs before the operating
system, unlocks the encrypted drive, and then chainloads the real operating
system bootloader.

The project should avoid the common Linux-PBA limitation where the PBA boots a
Linux kernel, calls `ExitBootServices()`, leaves the UEFI execution environment,
and therefore cannot cleanly chainload Windows or another UEFI application
afterward.

Instead, we want to build the PBA as a **TamaGo-based UEFI application written in
Go**. The PBA should stay inside the UEFI boot-services environment, unlock the
drive, and then load another EFI application such as:

- Windows Boot Manager
- shim
- GRUB
- a customer-specific bootloader
- a recovery EFI application
- a test EFI application

**Long-term vision:** A Secure-Boot-compatible, UEFI-native, customer-controlled
PBA for TCG Opal self-encrypting drives.

> **Scope:** this document is the **product** track — what we build to ship
> `trusted-pba.efi`. The **test tooling** we build only to test the product
> virtually (Go Opal simulator, EDK2 mock driver, OVMF/key material, QEMU runner,
> fixtures, and the later QEMU SED model) lives in a separate document:
> [`test-tooling-plan.md`](test-tooling-plan.md).

## 2. Problem Statement

Self-encrypting drives often use a Shadow MBR mechanism. When the drive is
locked, the host does not see the real boot disk. Instead, the drive exposes a
small pre-boot environment from the Shadow MBR area.

The PBA is loaded from this Shadow MBR. It authenticates the user or device
policy, unlocks the SED, disables Shadow MBR visibility, and then allows the real
operating system to boot.

Many existing PBAs are Linux-based. This creates a handoff problem:

```
Firmware
  -> PBA from Shadow MBR
  -> Linux kernel boots
  -> Linux calls ExitBootServices()
  -> UEFI boot services are gone
  -> clean UEFI chainloading is no longer possible
```

That is especially problematic for Windows, because Windows Boot Manager is a
UEFI application and expects to be loaded in the normal UEFI boot environment.

We want to solve this by avoiding Linux entirely in the PBA.

## 3. Proposed Solution

Implement the PBA as a UEFI-native TamaGo application. Intended boot flow:

```
Platform firmware
  -> sees locked SED / Shadow MBR
  -> loads trusted-pba.efi
  -> trusted-pba.efi runs inside UEFI
  -> PBA authenticates user/device/policy
  -> PBA sends TCG Opal commands to unlock the drive
  -> PBA sets MBRDone / disables Shadow MBR
  -> PBA locates the real EFI System Partition
  -> PBA chainloads Windows Boot Manager or another EFI application
```

The PBA must stay inside the UEFI boot-services environment until it launches the
actual OS bootloader. The design should treat the PBA as both:

1. A TCG Opal unlocker
2. A UEFI boot manager / policy engine

## 4. Technical Building Blocks

### 4.1 TamaGo

Use [TamaGo](https://github.com/usbarmory/tamago) as the bare-metal Go runtime
target. TamaGo already supports UEFI x86_64 and allows building Go programs that
run without a normal operating system. Potential starting points:

- `usbarmory/tamago`
- `usbarmory/go-boot` — already implements a UEFI shell / loader concept in Go and
  can load EFI applications.

### 4.2 UEFI Boot Services

The PBA needs UEFI boot services to enumerate handles, locate block devices and
filesystems, read/load/start EFI applications, possibly wrap image loading
behavior, and inspect Secure Boot state and variables.

Core UEFI APIs/protocols:

```
LoadImage() / StartImage() / UnloadImage() / Exit()
LocateHandleBuffer() / HandleProtocol() / OpenProtocol()
Simple File System Protocol
Loaded Image Protocol
Device Path Protocol
Block IO Protocol / Disk IO Protocol
Storage Security Command Protocol
```

### 4.3 TCG Opal / SED Unlocking

Functional areas: Level 0 Discovery, ComID discovery, StartSession,
Authenticate, Admin SP, Locking SP, locking-range unlock, global-range unlock,
`MBRControl.Enable`, `MBRControl.Done`, MBRDone behavior, session cleanup, error
handling.

The Opal protocol logic must be **separated from the transport**. Do not hardcode
"UEFI" into the Opal logic — use an abstract transport interface:

```go
type TCGTransport interface {
    Send(comID uint16, payload []byte) error
    Recv(comID uint16, size int) ([]byte, error)
}
```

Implementations: native mock transport, UEFI Storage Security Command Protocol
transport, future QEMU virtual SED transport, real hardware transport.

### 4.4 UEFI Storage Security Command Protocol

For real UEFI-based SED access the key protocol is
`EFI_STORAGE_SECURITY_COMMAND_PROTOCOL`, providing `SendData()` / `ReceiveData()`.

- SATA: firmware may map this to ATA trusted send/receive commands.
- SCSI-like: firmware may map this to Security Protocol In/Out commands.
- NVMe: behavior depends on firmware support; an NVMe pass-through path may be
  needed later if the protocol is unavailable.

### 4.5 Secure Boot

The PBA must be Secure-Boot-aware. It should **not** modify the firmware Secure
Boot key database at every boot. Preferred model (similar to shim):

- Firmware Secure Boot trusts the PBA.
- The PBA implements its own additional trust policy for later images.

Firmware acceptance of `trusted-pba.efi` can happen through: customer enrolls a key
into firmware `db`; OEM ships firmware with a customer/vendor key; PBA is signed by
an already-trusted key; or PBA is signed through a Microsoft-compatible signing
process if appropriate.

## 5. Secure Boot Design Approaches

### Approach A: Shim-like Loader / Policy Layer (recommended)

Firmware validates `trusted-pba.efi`; the PBA unlocks the SED, verifies the next EFI
image using its own policy, and starts it. The PBA becomes a second-stage trust
broker.

Possible PBA trust inputs: embedded customer CA, embedded product CA, hash
allowlist, revocation list, customer policy file, MOK-like enrollment database,
SBAT-like generation metadata, TPM-bound policy, signed configuration file.

**For Windows**, do not replace Windows Secure Boot validation:

```
Windows path:  let firmware validate Windows Boot Manager
Custom path:   let PBA validate custom EFI applications
```

**Sub-approach A1: Wrap LoadImage / StartImage** — install wrapper functions for
`LoadImage`, `StartImage`, `UnloadImage`, `Exit`. The wrapper intercepts image
loading, validates against PBA policy, allows trusted images, rejects
revoked/untrusted images, optionally calls original firmware services first, and
falls back to PBA validation if firmware rejects. This is likely the best
long-term product architecture.

> **Not pursued (ADR-0010).** A1 was dropped: the persistent firmware-table hooks
> need a UEFI→Go reverse-ABI callback TamaGo's UEFI mode does not support
> out of the box, and the transitive enforcement is largely redundant with
> firmware Secure Boot (Windows) and shim (Linux). The PBA validates the single
> image it loads and hands off; the next stage brokers its own downstream trust.

**Sub-approach A2: Hook Security2 Protocol** — hooking
`EFI_SECURITY2_ARCH_PROTOCOL` is more invasive and firmware-sensitive (global side
effects, harder to security-review, may interfere with measured boot).
**Recommendation: do not start with Security2 hooking;** only investigate if
required by real platforms.

### Approach B: Fully Manual Crypto and PE/COFF Loader

The PBA reads the EFI binary, parses PE/COFF, verifies Authenticode/hash, checks
cert chain and revocation, allocates/relocates, and calls the entry point itself.
Maximum control but high responsibility and security risk; may bypass measured
boot; Windows Boot Manager may not tolerate this path.

**Recommendation:** do not use as the default Windows path. Use only for
controlled custom EFI applications if needed. Prefer firmware LoadImage/StartImage
for Windows.

## 6. Recommended Architecture — Repository Layout

```
trusted-pba/
  cmd/pba/main.go
  internal/
    uefi/        boot.go handles.go protocols.go secureboot.go filesystem.go devicepath.go logging.go
    opal/        discovery.go session.go auth.go locking.go mbr.go comid.go errors.go
    transport/   transport.go mock.go uefi_storage_security.go
    policy/      policy.go image_verify.go keys.go revocation.go chainload.go config.go
    ui/          console.go password.go status.go
    tpm/         measurements.go pcr.go
  test/
    qemu/        run-qemu.sh expect-serial.py ovmf/ keys/ images/
    edk2-mock-opal/  MockOpalDxe.inf MockOpalDxe.c
    fixtures/    unsigned.efi signed-good.efi signed-bad.efi revoked.efi windows-placeholder.efi grub-placeholder.efi
  docs/          architecture.md secure-boot.md opal-flow.md test-plan.md
```

## 7. Component Responsibilities

- **7.1 PBA Entrypoint** — init runtime/logging, read UEFI system table, detect
  Secure Boot state, enumerate devices, display status, authenticate, unlock SED,
  disable Shadow MBR, locate next boot target, chainload. MVP may use a hardcoded
  password/test policy. Later: password prompt, TPM-bound unlock,
  challenge-response, signed policy file, remote unlock, multi-factor.
- **7.2 Opal Layer** — command/session logic, discovery parsing, session
  start/close, auth to Admin/Locking SP, locking-range state, `MBRControl.Done`,
  detailed errors. Must be testable without UEFI; depends only on a transport
  interface.
- **7.3 Transport Layer** — abstract IF-SEND/IF-RECV; provide MockTransport,
  UEFIStorageSecurityTransport, FutureQEMUTransport, HardwareTransport.
- **7.4 Policy Layer** — boot policy, trusted keys, allowed hashes, revocation
  list, next-target selection, custom image verification, defer-to-firmware
  decision. MVP policy can be static/compiled-in.
- **7.5 Chainloader** — load/start target EFI app, handle errors, report
  validation failure, fallback to recovery. Windows uses firmware
  LoadImage/StartImage; custom apps are PBA-verified first.

## 8. Development Environment

Slim and virtual: Linux host, Go toolchain, TamaGo, QEMU/KVM, OVMF/TianoCore,
`sbsigntool` or equivalent, Python or Go test harness, Makefile.

Primary loop (via [go-task](https://taskfile.dev)): `task setup`, `task build`,
`task run`, `task test`, `task check`.

QEMU: x86_64, KVM if available, `OVMF_CODE.fd` + `OVMF_VARS.fd`, serial console
logging, FAT EFI System Partition image, optional second disk, Secure Boot enabled
and disabled variants.

## 9. Virtual SED Testing Strategy

QEMU does not provide a ready-to-use upstream TCG Opal SED emulator, so we use a
layered strategy: native Go Opal simulator → EDK2 mock SSC-protocol driver in OVMF
(the primary virtual integration test) → a QEMU SED device model later → real
hardware. **The decision is EDK2 mock driver now, QEMU device model later.**

The full strategy, tool inventory, the EDK2-vs-QEMU rationale, and the CI stages
are specified in the test-tooling track:
[`test-tooling-plan.md`](test-tooling-plan.md). Real-hardware testing is covered by
§Phase 8 below.

## 10. Implementation Phases

> Several phases depend on test tooling (QEMU runner, fixtures, Go simulator, EDK2
> mock driver). The tooling deliverables and which phase each aligns with are in
> [`test-tooling-plan.md` §4](test-tooling-plan.md).

- **Phase 0 — Research & Skeleton:** repo, Makefile, TamaGo target, minimal
  `trusted-pba.efi`, QEMU/OVMF runner, serial capture, docs. AC: builds
  reproducibly, OVMF starts it, prints version/halts cleanly, CI smoke test.
- **Phase 1 — UEFI Boot Manager MVP:** enumerate handles, find ESP, open FS, load
  & `StartImage()` a test app, capture result. AC: harness detects success marker.
- **Phase 2 — Secure Boot Test Matrix:** test PK/KEK/db/dbx, OVMF var stores,
  signed PBA, signed/unsigned/untrusted/revoked test apps. Automate all cases;
  negative tests fail closed.
- **Phase 3 — PBA Policy Engine:** policy format, embedded public key, hash
  allowlist, revocation list, target path, firmware-validation vs PBA-validation
  mode. Initial policy compiled-in.
- **Phase 4 — Opal Native Simulator:** `TCGTransport`, MockTransport, fake device
  state machine, Discovery0/StartSession/Authenticate/Locking SP/MBRControl, unit
  tests for success and failure. AC: `go test ./...` passes.
- **Phase 5 — UEFI Storage Security Transport:** locate handles exposing the
  protocol, implement SendData/ReceiveData, map errors, feature detection.
- **Phase 6 — UEFI Mock Opal Driver:** `MockOpalDxe.efi`, full virtual
  unlock+chainload inside OVMF; fails closed on Opal failure.
- **Phase 7 — Shim-like Loader Wrapper: DROPPED (ADR-0010, 2026-06-12).** The PBA
  is a **single-hop trust broker**: it already validates the image it chainloads
  (firmware-trusted Windows path + PBA-trusted custom path, reject untrusted/
  revoked, log decisions — Phases 3/6, `cmd/pba`). Wrapping firmware
  `LoadImage`/`StartImage` to enforce policy *transitively* on the next stage's own
  loads was dropped: it needs a risky UEFI→Go reverse-ABI callback and is largely
  redundant with firmware Secure Boot (Windows) and shim (Linux). The loaded EFI
  app brokers its own downstream trust (shim-style) or relies on firmware-
  provisioned keys. Reconsider only if a concrete deployment demonstrates the need.
- **Phase 8 — Real Hardware Bring-up:** SATA/NVMe SED, Shadow MBR boot, unlock,
  MBRDone, Windows/Linux chainload, PSID reset/recovery, per-drive results.
- **Phase 9 — CI/CD Integration:** virtual CI on every PR (unit, smoke, Secure
  Boot matrix, mock Opal, chainload, negative tests); hardware CI nightly/manual.

## 11. Testing Criteria (summary)

Build tests, unit tests (Opal encoding/parsing, Discovery0, session state machine,
auth success/failure, locking-range & MBRControl changes, transport errors, policy
parsing/decisions, allowlist, revocation), UEFI smoke tests, Secure Boot matrix,
Opal mock tests, chainload tests, and hardware tests. See
[`test-plan`](#) and the secure-development baseline for full detail.

## 12. MVP Definition

> A signed TamaGo-based `trusted-pba.efi` boots in QEMU/OVMF with Secure Boot
> enabled, performs a fake Opal unlock using a mock UEFI Storage Security Command
> Protocol, then chainloads a second EFI application according to PBA-controlled
> policy.

MVP acceptance: builds; boots in QEMU/OVMF; Secure Boot matrix exists; chainloads a
test app; rejects an untrusted app; performs mock Opal unlock; refuses to boot the
target if mock unlock fails; runs in CI without physical hardware.

## 13. Non-Goals for MVP

Full QEMU Opal SED model, real hardware support, TPM-bound unlock, remote unlock,
graphical UI, Windows BitLocker integration, production key enrollment UX,
MOK-style management UI, full Authenticode implementation, manual Windows Boot
Manager loading, complete measured boot integration.

## 14. Open Technical Questions

Does target firmware expose `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` for SATA and
NVMe SEDs? Is NVMe pass-through needed? Can MBRDone take effect in the same UEFI
boot session? Does Windows Boot Manager boot cleanly after same-session unlock, or
require a reboot? How much of `go-boot` can be reused? How much UEFI protocol
binding is missing in TamaGo/go-boot? How do
we preserve/extend measured boot? How are customer trust anchors provisioned?

> **Resolved (ADR-0010, 2026-06-12):** *"Can LoadImage/StartImage wrapping be
> implemented safely in TamaGo? Do we need Security2 hooking?"* — wrapping needs a
> UEFI→Go reverse-ABI callback that TamaGo's UEFI mode does not provide
> out of the box (feasible in principle but substantial/risky runtime work), and
> the transitive enforcement it would buy is largely redundant with firmware
> Secure Boot (Windows) and shim (Linux). **Decision: the PBA is a single-hop
> trust broker** — it validates the image it loads and does not wrap firmware boot
> services; the next stage brokers its own downstream trust. Phase 7 and Security2
> hooking are dropped. See §10 Phase 7 and ADR-0010.

## 15. Recommended Development Order

1. Create repo and build system. 2. Build minimal TamaGo UEFI app. 3. Boot in
QEMU/OVMF. 4. Add serial logging. 5. Chainload a simple test EFI app. 6. Add Secure
Boot signing + OVMF variable store. 7. Add Secure Boot test matrix. 8. Add PBA
policy engine. 9. Add native Go Opal mock transport. 10. Add Opal
session/discovery/unlock logic. 11. Add UEFI Storage Security transport. 12. Add
MockOpalDxe driver. 13. Run full virtual unlock+chainload. 14. Add shim-like
LoadImage/StartImage wrapper. 15. Add hardware test plan. 16. Bring up first real
SED. 17. Add hardware CI. 18. Consider QEMU virtual SED model only after
architecture is proven.

## 16. Implementation Rules (for agents)

Keep it small and layered. Do not mix Opal protocol logic with UEFI transport
code. Do not require real SED hardware for normal tests. Do not start with QEMU
device emulation. Do not manually load Windows Boot Manager in the first version —
let firmware validate it. **Fail closed on all security or unlock errors.** Make
every policy decision visible in logs. Every feature must have a virtual test path.
Prefer deterministic tests over hardware-dependent tests.

**Security rules:** Never boot an untrusted image silently. Never continue to
chainload if SED unlock fails. Never ignore revocation. Never treat Secure Boot
disabled and enabled as equivalent. Never modify firmware Secure Boot variables
without an explicit provisioning flow.

**Testing rules:** Every new Opal command needs mock tests. Every new boot policy
path needs QEMU tests. Every negative security case must be tested. Every
hardware-only behavior must have a documented mock equivalent.

## 17. High-Level Architecture Summary

```
trusted-pba.efi
  +-- UEFI layer        (boot services, filesystem, image loading, Secure Boot state, storage security protocol)
  +-- Opal layer        (discovery, sessions, authentication, locking ranges, MBRControl)
  +-- Transport layer   (mock, UEFI storage security, future QEMU, real hardware)
  +-- Policy layer      (trusted keys, hashes, revocation, boot target selection)
  +-- Chainloader       (firmware-validated Windows path, PBA-validated custom path, recovery path)
```

## 18. Success Criteria for the Project

A UEFI-native Go PBA can boot under Secure Boot; can unlock a TCG Opal SED; can
chainload Windows Boot Manager after unlock; can chainload customer EFI
applications under customer-controlled policy; can be tested almost completely in
QEMU/OVMF CI; real hardware is needed only for compatibility and release
validation.

> **Core product claim:** Trusted PBA is a Secure-Boot-compatible, UEFI-native
> pre-boot trust broker for self-encrypting drives. It unlocks the drive before the
> operating system boots and then hands off cleanly to Windows, Linux, or
> customer-controlled EFI applications.
