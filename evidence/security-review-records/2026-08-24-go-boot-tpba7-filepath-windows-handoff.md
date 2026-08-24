# Security review record — go-boot `tpba.7` FilePath normalization (Windows handoff)

- **Date:** 2026-08-24
- **Change:** `fix/windows-handoff-demos` — pin the `walterchris/go-boot` fork to
  `v1.6.2-tpba.7` (commit `ce4d75b`): `uefi/path.go` `FilePath()` normalizes the
  `FILEPATH_DEVICE_PATH` node to absolute, backslash-separated form. See ADR-0008
  *Amendment 2026-08-24*.
- **Scope:** the chainload device-path node emitted for every target; verified against
  the firmware-validated Windows path (`internal/policy/policy_demowin.json`:
  `require_secure_boot: true`, `validation: firmware`, target
  `EFI/MICROSOFT/BOOT/BOOTMGFW.EFI`).
- **Method:** DEBUG-OVMF (`SECURE_BOOT_ENABLE` + `TPM2_ENABLE`) firmware-log
  differential between a working firmware-direct Windows boot and the failing PBA
  boot, isolating the divergence; then end-to-end boot verification through the
  db-signed PBA under Secure Boot enforcing.

## Finding (root cause)

`FilePath()` encoded the caller's name into the `FILEPATH_DEVICE_PATH` node verbatim.
The policy target is relative + forward-slash (`EFI/MICROSOFT/BOOT/BOOTMGFW.EFI`), so
the node was malformed. The Windows Boot Manager re-opens its own image via
`LoadedImage->FilePath` to self-measure into the TPM; with a malformed node that open
fails and bootmgr bails to recovery (`0xc000000d`) right after loading its CI
policies (`WinSiPolicy.p7b`, `CiPolicies\Active\*.cip`).

## Fix + verification

Normalize `/`→`\` and prepend a leading `\` before encoding (UEFI 2.10 §10.3.5.4).

- **Firmware-log differential (DEBUG OVMF):**
  - before: `[Security] ... /HD(1,GPT,...)/EFI/MICROSOFT/BOOT/BOOTMGFW.EFI` (forward
    slash); bootmgr jumps to the recovery `Fonts` path, no `boot.wim`.
  - after: `[Security] ... /HD(1,GPT,...)/\EFI\MICROSOFT\BOOT\BOOTMGFW.EFI`
    (backslash); bootmgr opens `BOOTMGFW.EFI` (self-measure) → `boot.stl` →
    `boot.wim` → `boot.sdi` — the same sequence as a firmware-direct boot.
- **End-to-end (Secure Boot enforcing):** firmware → db-signed PBA → Windows Boot
  Manager → Windows 11 Setup GUI (install media) and an installed disk to the
  Windows 11 login screen. Reproduced from a clean build of the pinned tag
  (`Version=demo-tpba7`), not a local module-cache edit.

## Verdict

No fail-open and no weakening of the boot trust chain. The Windows target stays
`require_secure_boot` + firmware-validated (ADR-0006 / CLAUDE.md); the change only
makes the caller-supplied, in-TCB device-path node well-formed so the firmware and
bootmgr can consume it and complete the TPM self-measure. Pure normalization — no new
input surface. Fail-closed preserved: a target that fails db validation is still
rejected; an unresolved/absent target still fails closed. Pinned by tag + `go.sum`
hash; the change adds only a stdlib `strings` import, so the #27 dependency scan set
and risk R-006 are unchanged.
