# trusted-pba

A Secure-Boot-compatible, **UEFI-native pre-boot trust broker** for TCG Opal
self-encrypting drives (SEDs), written in Go on [TamaGo](https://github.com/usbarmory/tamago).
It boots from the drive's Shadow MBR, unlocks the SED before the OS starts, disables
the Shadow MBR, and hands off cleanly to Windows, Linux, or a customer-controlled EFI
application — **without ever leaving UEFI boot services** (no `ExitBootServices`, so the
Windows Boot Manager handoff stays clean, unlike Linux-kernel PBAs).

> **Security-critical pre-boot product.** It **fails closed** on every authentication,
> unlock, verification, or policy error and never boots an untrusted or revoked image.
> Development follows a documented secure-development lifecycle for CRA / ISO 27001 /
> SSDF / SLSA readiness. Read [`CLAUDE.md`](CLAUDE.md) and
> [`AGENTS.md`](AGENTS.md) before contributing.

## Status

**MVP complete** (plan Phases 0–6) and validated almost entirely in QEMU/OVMF CI.
**Hardware bring-up (Phase 8) is in progress** — SED unlock has been validated on a real
NVMe Opal drive; full on-hardware chainload, recovery, and a per-drive matrix are next.
See the [issues](../../issues) and [milestones](../../milestones).

## Features

### Available today

- **UEFI-native, boot-services-resident** PBA on TamaGo — stays in UEFI through the
  handoff; never calls `ExitBootServices` (ADR-0001/0002).
- **TCG Opal SED unlock** — Level-0 Discovery → authenticated Locking-SP session
  (Admin1, PIN as host challenge) → clear the global locking range → set `MBRDone`
  (disable the Shadow MBR) → end session. Byte-faithful TCG wire format, proven against
  real hardware and the Linux kernel's `sed-opal`.
- **UEFI Storage Security transport** — `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL`
  (IF-SEND/IF-RECV), enumerating every drive and selecting the locked SED with an active
  Shadow MBR. Opal protocol logic is cleanly separated from the transport (ADR-0004).
- **Secure Boot aware & enforcing** — detects `SecureBoot`/`SetupMode` and, when the
  policy sets `require_secure_boot`, **fails closed** unless the firmware is enforcing
  (ADR-0003). Never treats Secure Boot on and off as equivalent.
- **Compiled-in boot policy** (fail-closed JSON) — `require_secure_boot`, `sed_unlock`
  (`required` default / `none`), `on_error` (`halt`/`shutdown`/`reboot`), and boot
  `entries` each carrying a per-target validation mode (ADR-0007/0009).
- **Two second-stage validation modes:**
  - `firmware` — the PBA loads the target and lets **firmware Secure Boot** validate it
    (the Windows Boot Manager path — we don't re-implement Windows validation).
  - `pba` — the PBA validates the image **itself**: full Authenticode PE hashing + PKCS#7
    chain to an embedded Microsoft trust store, with `dbx` revocation (hash and cert).
    Time-independent, exactly like firmware. The **verified buffer is the executed
    buffer** (no verify-then-load gap).
- **Embedded Secure Boot trust store** — Windows-only by default (Windows Production PCA
  2011 + Windows UEFI CA 2023); `-tags trustfull` adds the third-party Microsoft UEFI CAs
  for shim/GRUB/Linux. Byte-identical Microsoft materials + the real `dbx` (ADR-0007).
- **Single-hop trust broker** (ADR-0010) — validates the one image it chainloads, then
  transfers control; the next stage brokers its own downstream trust (shim/MOK for Linux,
  firmware `db` for Windows). No boot-services wrapping.
- **Fail-closed by construction** — any error (policy parse, Secure Boot gate, transport,
  discovery, unlock, verification, load) terminates via the policy `on_error` action;
  control never returns to the firmware boot order. PINs are zeroized once and never logged.
- **Fully virtual test path** — unit + fuzz tests, an EDK2 `MockOpalDxe` driver, and QEMU
  matrices (mock-Opal unlock, Secure Boot, PBA verification, Windows-handoff) run on every
  PR in CI, with no hardware.

### Planned / in progress

- **Real hardware bring-up (Phase 8, in progress)** — SED unlock validated on real NVMe
  Opal hardware; remaining: on-hardware chainload to Windows/Linux, PSID reset/recovery,
  and a per-drive compatibility matrix.
- **Real user/device authentication (ADR-0011, proposed)** — replace the compiled-in test
  PIN with a pluggable `credential.Source` (console prompt, key file, TPM-PCR-sealed,
  YubiKey, Tang/Clevis, …) and MFA composition. This is the path to a shippable unlock UX.
- **Robust drive targeting ([#81](../../issues/81))** — a policy/config-specified drive
  identity (NVMe serial / WWN) to replace the interim "locked SED with a Shadow MBR"
  selection heuristic.
- **Full trust-broker override (ADR-0012, spike)** — optionally boot an image firmware `db`
  does *not* trust (a SHIM-style Security-protocol override), scoped **away** from the
  Windows/BitLocker path (it diverges PCR 7). Go/no-go spike tracked in [#82](../../issues/82).
- **NVMe PassThru transport** — a raw-NVMe carrier (prototyped and HW-validated in the
  go-boot fork) for firmware whose Storage Security mediation is unreliable; not yet in the
  shipping tree.
- **Multi-entry boot selection / fallback** — today the policy selects the first entry;
  availability-based fallback is not yet implemented.
- **QEMU virtual SED device model** (deferred) — faithful Shadow-MBR block visibility, to
  test the locked→revealed disk transition virtually (today's mock exercises the protocol,
  not real block gating).
- **Reproducible release build + SBOM/provenance/signing** — `release.yml` scaffolding
  exists; the signed, provenanced release artifact is still TODO.

## Architecture

```
trusted-pba.efi
  ├── uefi/ (go-boot)   boot services, filesystem, image loading, Secure Boot state, storage security protocol
  ├── opal/             Level-0 Discovery, sessions, auth, locking ranges, MBRControl  (transport-agnostic)
  ├── transport/        EFI Storage Security carrier  | future: NVMe PassThru | mock (MockTPer)
  ├── policy/           compiled-in policy: require_secure_boot, sed_unlock, on_error, boot entries
  ├── imageverify/ + truststore/   Authenticode + dbx verification against embedded Microsoft CAs
  └── chainloader       firmware-validated (Windows) | PBA-validated (custom) | fail-closed
```

**Boot flow:** detect Secure Boot → parse policy (fail closed) → enforce `require_secure_boot`
→ unlock the SED (discover → auth → clear locks → `MBRDone`) → select the boot entry →
chainload it (`firmware` or `pba` validation) → on any failure, `halt`/`shutdown`/`reboot`
per policy. Keep the layers separate: **the Opal logic depends only on an abstract transport
interface** and never on UEFI.

## Build & test

Built with [go-task](https://taskfile.dev) (no Makefile); TamaGo is pinned and auto-installed.

```bash
task setup            # install the pinned TamaGo toolchain + resolve deps (one-time)
task build            # build bin/trusted-pba.efi
task run              # boot in QEMU/OVMF and assert the chainload markers
task check            # local CI: lint + unit tests + the QEMU matrices
```

Test suites (all virtual, run in CI on every PR — **CI fails closed**):

| Suite | What it proves |
|-------|----------------|
| `task test` / `lint` / `fuzz` | Opal codec, policy parse, Authenticode verify, Secure Boot state — with fuzzing and fail-closed negatives |
| `task mock-opal-matrix` | End-to-end unlock → `MBRDone` → chainload against the EDK2 `MockOpalDxe` SED, plus auth-fail / MBRDone-fail / partial-unlock / no-driver fail-closed cases |
| `task sb-matrix` | Secure Boot: off, enforcing-signed, unsigned-rejected, untrusted-key-rejected, `dbx`-hash-revoked |
| `task pba-matrix` | `pba`-validation: accept a trusted image, reject unsigned, reject `dbx`-revoked |
| `task win-handoff` | Windows handoff: firmware `db` + PBA both validate a real MS-signed loader (gated on an operator-provided loader) |

Real hardware, real Windows boot, and the faithful Shadow-MBR reveal are **not** covered
virtually — see [`docs/test-tooling-plan.md`](docs/test-tooling-plan.md).

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — working agreement, the four rules, non-negotiable security rules
- [`docs/trusted-pba-plan.md`](docs/trusted-pba-plan.md) — product plan (phases, MVP, success criteria)
- [`docs/test-tooling-plan.md`](docs/test-tooling-plan.md) — virtual test tooling
- [`docs/architecture/adr/`](docs/architecture/adr/) — architecture decision records (ADR-0001…0012)
- [`docs/compliance-and-secure-development-baseline.md`](docs/compliance-and-secure-development-baseline.md) — the dev/compliance process
- [`docs/`](docs/) — product / security / compliance / architecture / development docs

## Development process (short version)

Every change starts as an **issue** (milestone = development phase), is worked on a branch,
opened as a PR against the checklist, passes CI (which **fails closed**), and is reviewed
before merge. Security-critical and release changes require human approval and, where
applicable, an ADR. See the compliance baseline §7 (SDLC) and §23 (change management).
