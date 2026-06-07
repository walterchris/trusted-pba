# trusted-pba

A Secure-Boot-compatible, **UEFI-native pre-boot trust broker** for TCG Opal
self-encrypting drives, written in Go on [TamaGo](https://github.com/usbarmory/tamago).
It unlocks the drive before the OS boots, then hands off cleanly to Windows,
Linux, or a customer-controlled EFI application — without leaving UEFI boot
services.

> **Security-critical pre-boot product.** Development follows a documented secure
> development lifecycle for CRA / ISO 27001 / SSDF / SLSA readiness. Read
> [`CLAUDE.md`](CLAUDE.md) and [`AGENTS.md`](AGENTS.md) before contributing.

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — working agreement + the four rules + non-negotiable security rules
- [`docs/trusted-pba-plan.md`](docs/trusted-pba-plan.md) — product plan
- [`docs/test-tooling-plan.md`](docs/test-tooling-plan.md) — virtual test tooling
- [`docs/compliance-and-secure-development-baseline.md`](docs/compliance-and-secure-development-baseline.md) — the dev/compliance process
- [`docs/`](docs/) — granular product / security / compliance / architecture / development docs (filled per ticket)

## Development process (short version)

Every change starts as an **issue** (milestone = development phase), is worked on a
branch, opened as a PR against the checklist, passes CI (which **fails closed**),
and is reviewed before merge. Security-critical and release changes require human
approval and, where applicable, an ADR. See the compliance baseline §7 (SDLC) and
§23 (change management).

## Status

Pre-MVP. Process foundation and Phase 0 skeleton in progress — see the repo
[issues](../../issues) and [milestones](../../milestones).
