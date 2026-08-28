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
> SSDF / SLSA readiness. Read [`CLAUDE.md`](CLAUDE.md) and [`AGENTS.md`](AGENTS.md)
> before contributing.

## Contents

[Status](#status) · [Features](#features) · [How it works](#how-it-works) ·
[Project structure](#project-structure) · [Build &amp; run](#build--run) ·
[Configuration](#configuration) · [Testing](#testing) · [Security](#security) ·
[Documentation](#documentation) · [Contributing](#contributing) · [License](#license)

## Status

The core PBA is **feature-complete and validated in QEMU/OVMF CI**; hardware bring-up
is **in progress**.

| Capability | State |
|---|---|
| Opal SED unlock (discovery → auth → unlock → `MBRDone`) | ✅ Working, proven against real hardware and the Linux `sed-opal` wire format |
| UEFI Storage Security transport | ✅ Working |
| Secure Boot detection &amp; `require_secure_boot` enforcement | ✅ Working |
| Compiled-in fail-closed boot policy | ✅ Working |
| Image validation — `firmware` / `pba` / `pba-override` modes | ✅ Working |
| Chainload to Windows / Linux / custom EFI | ✅ Working (virtual) |
| Real on-hardware chainload, recovery, per-drive matrix | 🚧 In progress |
| Real user/device authentication (vs. compiled-in test PIN) | 📋 Planned |
| Signed, provenanced release artifact | 📋 Planned |

See the [issues](../../issues) and [milestones](../../milestones) for current work.

## Features

### Working today

- **UEFI-native, boot-services-resident** PBA on TamaGo — stays in UEFI through the
  handoff; never calls `ExitBootServices` (ADR-0001/0002).
- **TCG Opal SED unlock** — Level-0 Discovery → authenticated Locking-SP session
  (Admin1, PIN as host challenge) → clear the global locking range → set `MBRDone`
  (disable the Shadow MBR) → end session. Byte-faithful TCG wire format.
- **UEFI Storage Security transport** — `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL`
  (IF-SEND/IF-RECV), enumerating every drive and selecting the locked SED with an active
  Shadow MBR. Opal protocol logic is cleanly separated from the transport (ADR-0004).
- **Secure Boot aware &amp; enforcing** — detects `SecureBoot`/`SetupMode` and, when the
  policy sets `require_secure_boot`, **fails closed** unless the firmware is enforcing
  (ADR-0003). Never treats Secure Boot on and off as equivalent.
- **Compiled-in boot policy** (fail-closed JSON) — see [Configuration](#configuration).
- **Three second-stage validation modes** (per boot entry):
  - `firmware` — the PBA loads the target and lets **firmware Secure Boot** validate it
    (the Windows Boot Manager path — we don't re-implement Windows validation).
  - `pba` — the PBA validates the image **itself**: full Authenticode PE hashing + PKCS#7
    chain to an embedded Microsoft trust store, with `dbx` revocation (hash and cert).
    Time-independent, exactly like firmware. The **verified buffer is the executed
    buffer** (no verify-then-load gap).
  - `pba-override` — `pba` validation **plus** a SHIM-style Secure Boot override so an
    image firmware `db` does *not* trust still loads (a platform trusting only our PBA
    key). Compiled only with `-tags trustbroker`; diverges PCR 7, so it is scoped **away**
    from BitLocker/measured-boot targets (ADR-0012/0013).
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
  matrices run on every PR in CI, with no hardware.

### Planned / in progress

- **Real hardware bring-up** — SED unlock is validated on real NVMe Opal hardware;
  remaining: on-hardware chainload to Windows/Linux, PSID reset/recovery, and a per-drive
  compatibility matrix.
- **Real user/device authentication (ADR-0011, proposed)** — replace the compiled-in test
  PIN with a pluggable `credential.Source` (console prompt, key file, TPM-PCR-sealed,
  YubiKey, Tang/Clevis, …) and MFA composition. This is the path to a shippable unlock UX.
- **Robust drive targeting ([#81](../../issues/81))** — a policy/config-specified drive
  identity (NVMe serial / WWN) to replace the interim "locked SED with a Shadow MBR"
  selection heuristic.
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

## How it works

The PBA runs as a UEFI application launched from the drive's Shadow MBR. Its boot flow:

```
detect Secure Boot state
  → parse the compiled-in policy (fail closed on any error)
  → enforce require_secure_boot (fail closed if required but firmware isn't enforcing)
  → unlock the SED: discover → authenticate (Admin1) → clear the locking range → MBRDone
  → select the boot entry (first entry today)
  → chainload it, validated per the entry's mode (firmware | pba | pba-override)
  → on ANY failure: halt / shutdown / reboot per policy — never return to firmware boot order
```

Two architectural rules keep it auditable: **the Opal protocol layer depends only on an
abstract transport interface** (never on UEFI), and the PBA is a **single-hop trust
broker** — it validates only the one image it hands control to, then that image brokers
its own downstream trust.

## Project structure

```
cmd/pba/            UEFI app entry point + boot flow: main.go, SED unlock (sedunlock.go),
                    chainload + validation modes (override_trustbroker.go / override_notbuilt.go),
                    console sink selection (console_*.go), host build stub (main_stub.go)
internal/
  opal/             TCG Opal protocol: Level-0 Discovery, sessions, methods, tokens, packets,
                    UIDs — transport-agnostic; MockTPer for tests
  transport/        UEFI Storage Security carrier (uefi_tamago.go) + !tamago host stub
  policy/           compiled-in JSON boot policy: schema + fail-closed parse (policy.go),
                    the policy_*.json variants, and embed_*.go (build tag → which JSON)
  imageverify/      Authenticode PE hashing + PKCS#7 chain + dbx verification
  truststore/       embedded Microsoft db CAs + real dbx (build-tag variants);
                    materials under materials/{db,dbx} with PROVENANCE.md
  secureboot/       reads firmware SecureBoot / SetupMode state (+ host stub)
  tbstub/           the Security2-override trust-broker asm stub used by pba-override
test/
  qemu/             QEMU/OVMF harness scripts + the test matrices
  edk2-mock-opal/   the MockOpalDxe EDK2 driver (virtual SED for integration tests)
  fixtures/         test images, keys, and helpers
docs/               product / security / compliance / architecture (ADRs) / development docs
evidence/           CRA/ISO compliance evidence (SBOM, threat model, test/fuzz/SAST reports,
                    provenance, security-review records)
Taskfile.yml        the build system (go-task; there is no Makefile)
```

## Build &amp; run

Built with [go-task](https://taskfile.dev) (no Makefile); TamaGo is pinned and auto-installed.

```bash
task setup            # install the pinned TamaGo toolchain + resolve deps (one-time)
task build            # build bin/trusted-pba.efi
task run              # boot in QEMU/OVMF and assert the chainload markers
task check            # local CI: lint + unit tests + the QEMU matrices
```

## Configuration

The PBA takes **no runtime configuration** — no config file on disk, no flags, no
environment variables. Everything is fixed at **build time**, in two layers: a **compiled-in
JSON boot policy** and a set of **build tags**. This is deliberate for a pre-boot binary:
the policy is part of the signed, measured artifact and cannot be tampered with at runtime.

### Boot policy (compiled-in JSON)

One JSON policy is embedded into the binary via `//go:embed` (see
[`internal/policy/`](internal/policy/)). It is parsed **fail-closed**: unknown fields,
trailing data, or an invalid value yield an error and **no** usable policy, so the PBA
refuses to boot rather than guessing.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `require_secure_boot` | bool | `false` | If `true`, fail closed unless firmware Secure Boot is **enforcing** (`SecureBoot=1 && SetupMode=0`). |
| `sed_unlock` | `"required"` \| `"none"` | **`required`** (absent ⇒ required) | Whether the PBA must unlock an Opal SED before chainload. `"none"` is an explicit, logged decision for non-SED machines — never an implicit fallback. |
| `sed_credential` | object | — | Where the unlock credential comes from. Required when `sed_unlock` is `required`; must be **absent** when `none`. Fields: `source` (`"policy-pin"` \| `"console"` \| `"keyfile"`), `pin` (string; **`policy-pin` only** — a compiled-in Admin1 credential, redacts as `[redacted]`, zeroized after use; a debug source rejected by the release gate), `path` (string; **`keyfile` only** — ESP-relative path to the key file), `derive` (`"raw"` default \| `"sedutil-pbkdf2"`). `console` prompts the operator at the pre-boot console (no `pin`/`path`). **`keyfile` is low-assurance:** the file content *is* the credential in cleartext, so its security is only the confidentiality of its location — on the ESP it does **not** defend a physical/evil-maid attacker (who can read it); it is meaningful only on separate removable media or as one factor in MFA. Bytes are used exactly as stored (no trimming). The drive authenticates the credential, so a wrong/tampered keyfile fails closed (never a bypass). |
| `on_error` | `"halt"` \| `"shutdown"` \| `"reboot"` | **`halt`** | Terminal fail-closed action. None of them return control to the firmware boot order; `reboot` re-runs the PBA from the start. |
| `entries` | array (≥1, required) | — | Candidate boot targets. Today only the **first** entry is used (availability-based selection is not yet implemented). |
| `entries[].name` | string | — | Human-readable entry name (required). |
| `entries[].path` | string | — | ESP-relative image path, e.g. `EFI/TEST/TESTAPP.EFI` (required). |
| `entries[].validation` | `"firmware"` \| `"pba"` \| `"pba-override"` | — | How the image is validated before it is started — see [validation modes](#features). `pba-override` requires the `trustbroker` build tag or it fails closed at chainload. |

Example (the default development policy):

```json
{
  "require_secure_boot": false,
  "sed_unlock": "none",
  "entries": [
    { "name": "test-fixture", "path": "EFI/TEST/TESTAPP.EFI", "validation": "firmware" }
  ]
}
```

### Build tags

Build tags select which policy JSON and trust store are embedded, the console output, and
whether the override path is compiled in. The **default build (no tags)** embeds
`policy.json`, the **Windows-only** trust store, and dual console output. TamaGo also needs
the base linker tags `linkcpuinit,linkramsize,linkramstart,linkprintk` (set automatically by
the Taskfile).

| Tag | Effect |
|---|---|
| *(none)* | Default: embed `policy.json`, Windows-only trust store, ConOut + serial console. |
| `sedtest` | Embed `policy_sed.json` (`sed_unlock: required` + a test PIN) — mock-Opal unlock matrix. |
| `pbatest` | Embed `policy_pba.json` (validation `pba`) **and** substitute a test trust store (test CA + crafted dbx) — PBA-validation matrix. |
| `policytest` | Embed `policy_require_sb.json` (`require_secure_boot: true`) — Secure Boot enforcement case. |
| `overridetest` | Embed `policy_overridetest.json` (validation `pba-override`); build with `overridetest,pbatest,trustbroker`. |
| `trustfull` | Add the third-party Microsoft UEFI CAs (shim/GRUB/Linux) on top of the two Windows CAs. Default is Windows-only. |
| `trustbroker` | Compile in the `pba-override` Security2-override path (`internal/tbstub`). Without it, a `pba-override` entry fails closed. |
| `serialonly` | Console output to COM1 serial only (headless/CI). Default fans out to both UEFI ConOut and COM1. |

The policy-embed tags are **mutually exclusive by construction** — exactly one policy JSON
is ever embedded; an invalid combination is a compile error, not a silent wrong policy.

## Testing

Every feature has a virtual test path; the suites below run in CI on every PR
(**CI fails closed**), with no hardware:

| Suite | What it proves |
|---|---|
| `task test` / `task lint` / fuzz | Opal codec, policy parse, Authenticode verify, Secure Boot state — with fuzzing and fail-closed negatives |
| `task mock-opal-matrix` | End-to-end unlock → `MBRDone` → chainload against the EDK2 `MockOpalDxe` SED, plus auth-fail / MBRDone-fail / partial-unlock / no-driver fail-closed cases |
| `task sb-matrix` | Secure Boot: off, enforcing-signed, unsigned-rejected, untrusted-key-rejected, `dbx`-hash-revoked |
| `task pba-matrix` | `pba`-validation: accept a trusted image, reject unsigned, reject `dbx`-revoked |
| `task override-pcr` | `pba-override`: confirms the PCR-7 divergence under a vTPM (why it is scoped away from BitLocker) |

Real hardware, real Windows boot, and the faithful Shadow-MBR reveal are **not** covered
virtually — see [`docs/test-tooling-plan.md`](docs/test-tooling-plan.md).

## Security

- **Fail-closed always.** Any authentication, unlock, verification, or policy error
  terminates per `on_error` and never returns control to the firmware boot order. The
  non-negotiable rules are in [`CLAUDE.md`](CLAUDE.md).
- **Secure Boot is not optional-equivalent.** The PBA never treats Secure Boot enabled and
  disabled as the same, and never silently falls back from secure to insecure boot.
- **No secrets in logs.** PINs, keys, and Opal session material are never logged; the PIN
  type renders as `[redacted]` and is zeroized after use.
- **Do not deploy the compiled-in test PIN.** The MVP embeds a test credential in the
  policy; it is a placeholder, extractable from the image, and must be replaced by real
  authentication (ADR-0011) before any production use.
- **Threat model &amp; risk assessment:** [`docs/security/threat-model.md`](docs/security/threat-model.md)
  and [`docs/compliance/risk-assessment.md`](docs/compliance/risk-assessment.md).

> **Reporting a vulnerability:** please **don't** open a public issue. Use GitHub's
> **Report a vulnerability** (Security tab) or email <security@9elements.com>. See
> [`SECURITY.md`](SECURITY.md) for scope and process.

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — working agreement, the four rules, non-negotiable security rules
- [`docs/trusted-pba-plan.md`](docs/trusted-pba-plan.md) — product plan, MVP, success criteria
- [`docs/test-tooling-plan.md`](docs/test-tooling-plan.md) — virtual test tooling
- [`docs/architecture/adr/`](docs/architecture/adr/) — architecture decision records (ADR-0001…0013)
- [`docs/compliance-and-secure-development-baseline.md`](docs/compliance-and-secure-development-baseline.md) — the dev/compliance process
- [`docs/`](docs/) — product / security / compliance / architecture / development docs

## Contributing

Every change starts as an **issue**, is worked on a `feat/`·`fix/`·`chore/`·`docs/` branch,
and is opened as a PR against `main` (protected — PR only, no direct/force push). CI must
pass (it **fails closed**), and the change is reviewed before merge. Security-critical and
release changes require human approval and, where applicable, an ADR.

- **Sign off every commit** with `git commit -s` (DCO `Signed-off-by:` trailer) — no
  exceptions, including amends and squashes:
  ```
  Signed-off-by: Your Name <you@example.com>
  ```
- See [`docs/development/branching.md`](docs/development/branching.md) and the compliance
  baseline §7 (SDLC) / §23 (change management).

## License

_Not yet finalized._ A `LICENSE` file will be added; until then, all rights are reserved by
the project owners. Contact the maintainers before redistributing.
