# ADR-0014: Extend `pba-override` to the Windows path for our-keys-only platforms

## Status
**Proposed** — reverses ADR-0013 decision #3 (and relaxes ADR-0012 #1's blanket
exclusion) for the Windows/measured-boot path, **conditioned** on the provisioning
requirement and the open pre-condition below. This is a §5.3/§23 security-critical
boot-behavior change: it requires the Security/Release Owner human gate **and** an
independent security review before it may move to Accepted (the same gate ADR-0013
went through). It does **not** change shipped defaults; release builds stay
override-free.

## Context
ADR-0010 established the single-hop trust broker; ADR-0012 spiked a SHIM-style
`EFI_SECURITY2_ARCH_PROTOCOL` override; ADR-0013 accepted it as a gated,
non-default capability **and explicitly excluded the Windows/measured-boot path**
(decision #3) because the override diverges PCR 7 and BitLocker seals its VMK to
PCR 7 by default. The sanctioned Windows path was firmware-`db` validation: enroll
the Microsoft CA in the platform `db` so firmware itself validates Windows Boot
Manager (modes `firmware`/`pba`).

The product owner has set a different target architecture for **our-keys-only
platforms**: firmware Secure Boot `db` holds **only our PBA key (key A)**, and the
PBA trust-brokers the *entire* OS — the Linux UKI **and** Windows Boot Manager —
against the PBA's own embedded trust store via the Security2 override. This is one
symmetric trust model: firmware trusts only the PBA; the PBA vouches for the OS. It
makes the "key A only in firmware" property hold for Windows too, which it does
**not** under ADR-0013's Windows path (that requires the Microsoft CAs in firmware
`db`, so firmware trusts Microsoft directly).

### Reconsidered BitLocker / PCR 7 analysis
The PCR 7 divergence is real and empirically confirmed (`override-pcr.sh`: an
override-authorized image omits its `EV_EFI_VARIABLE_AUTHORITY(db→…)` event, so
PCR 7 differs from a firmware-`db` boot). The refinement is *when* that breaks
BitLocker:

- BitLocker fails to auto-unlock only when it was sealed to a PCR 7 value that does
  **not** reflect the override. That is the case ADR-0012/0013 rejected: a stock
  Windows sealed **without** the PBA, then the PBA inserted underneath it.
- On an our-keys-only platform where the PBA is in the boot chain **from
  provisioning**, BitLocker is (re)enabled **with** the PBA-override already
  measured. PCR 7 at seal time includes the override; every subsequent boot
  reproduces the same PCR 7; the TPM releases the VMK → auto-unlock works. BitLocker
  needs the measurement to be *reproducible*, not identical to a stock boot.
- Cost: any change to the PBA binary or the override changes PCR 7 again →
  recovery-key prompt until re-seal. This is the **same** operational event as a
  firmware or bootloader update on any BitLocker machine, and is managed the same
  way (suspend BitLocker across the update, or reseal). It is a deliberate
  provisioning commitment, not a defect.

## Decision
1. **Permit `pba-override` on the Windows path for our-keys-only platforms**,
   superseding ADR-0013 decision #3, **subject to** the provisioning requirement (2)
   and the open pre-condition (4). The capability stays **doubly gated** (`-tags
   trustbroker` **and** an explicit `validation: pba-override` policy entry) and
   **absent from release builds** — this ADR does not activate it by default.
2. **Mandatory provisioning requirement (deployment obligation).** A deployment using
   `pba-override` for Windows **must** enable/seal BitLocker with the PBA-override
   already in the measured boot chain, **and** must treat PBA/override updates as
   PCR-7-affecting events (BitLocker suspend + reseal, or an accepted recovery-key
   prompt). A deployment that cannot guarantee this **must** use firmware-`db`
   validation (`pba`/`firmware`) instead — ADR-0013's Windows path remains valid and
   is the safer default where the operator does not own provisioning order.
3. **Demonstrator.** `task demo:windows` shows this model — firmware `db` = key A only
   (no Microsoft), the broker verifies `bootmgfw.efi` against the Microsoft Windows CAs
   in the PBA's **own** trust store (trust set `windows-only`), and the Security2
   override admits it. Two paths:
   - **Default (`demowin,trustbroker`)** — self-contained: a Windows 11 Eval ISO boots
     to the **WinPE/Setup** screen through the override (+ a mock Opal SED console
     unlock). No BitLocker on the media, so the demo is unaffected by the PCR-7 caveat.
   - **`WIN_OSDISK=<disk>` (`demowinnosed,trustbroker`)** — boots a **full,
     pre-installed Windows** through the override on **SATA/AHCI**, all the way to the
     **Windows logon screen** (empirically validated, below). No mock SED on this path
     (its Storage-Security protocol confuses the installed OS's boot-device
     enumeration).

   The fail-closed gate is demonstrated by a negative build (broker trust store
   **without** the Windows CAs): the broker rejects `bootmgfw` (`signer does not chain
   to a trusted db certificate`) and the override is **never armed** — no `override
   armed`, no load.
4. **Open pre-condition (carried, NOT closed by this ADR).** The precise BitLocker
   PCR-7 seal profile (which PCRs the default policy binds on a Secure-Boot system,
   and the exact `EV_EFI_VARIABLE_AUTHORITY` reproduction semantics) **must be
   verified against a primary Microsoft source**, and the auto-unlock-after-reseal
   claim **validated on real hardware with real BitLocker**, before any **production**
   Windows deployment enables this. This ADR accepts the *demonstrator and the
   architecture direction*; it does **not** clear production Windows use.
5. **Release default unchanged.** The shipped default policy and `release.yml` builds
   remain override-free (`release-policy` gate untouched). This is opt-in per
   deployment.

## Empirical validation (in-emulation, QEMU/OVMF/swtpm)

Established (screenshot- and serial-backed):

- **The override boots a full, installed Windows 11 to the logon screen** on a
  key-A-only firmware `db`: firmware → PBA → Security2 override → `bootmgfw` →
  **`winload` → the Windows kernel → the Windows logon screen**. This resolves the
  central open question about the Windows path: **`winload` is *not* blocked by the
  key-A-only `db`** — Windows validates its later stages (winload, ntoskrnl, drivers)
  with its own code-integrity, independent of the UEFI `db`. So the override model is
  Windows-compatible through the whole boot chain, not just at `bootmgfw`.
- **Controller note (deployment-relevant).** An offline-applied Windows image bugchecks
  `INACCESSIBLE_BOOT_DEVICE` on **virtio-blk** (no inbox boot driver); on **SATA/AHCI**
  (inbox `storahci`) it boots. The `WIN_OSDISK` demo attaches the disk as AHCI.
- **PCR 7 is reproducible and authority-stable** (`test/qemu/pcr7-reproducibility.sh`,
  under a TPM-enabled OVMF + swtpm + a guest `EFI_TCG2` reader): two identical override
  boots produce **byte-identical PCR 7**, and a **same-key PBA content update leaves
  PCR 7 unchanged** (PCR 4, the image hash, differs). This **refines decision (2)**: a
  same-key PBA binary update is **not** a BitLocker reseal event; only a
  **signing-key / `db` / Secure-Boot-config** change reseals. (The over-broad "any
  change to the PBA … reseals" wording in the analysis above is superseded by this
  measurement.)
- **BitLocker can be enabled through the override-booted Windows** — one run produced
  the `-FVE-FS-` (BitLocker Full Volume Encryption) volume signature, with the TPM
  visible to Windows via Fedora's 4M OVMF (the minimal custom PCR-test OVMF instead
  bugchecks Windows `KMODE_EXCEPTION_NOT_HANDLED`).

**NOT established in emulation — requires real TPM hardware.** The *rigorous* BitLocker
auto-unlock A/B test (protection fully On → positive: sealed-TPM + override auto-unlocks;
negative: a fresh/wrong TPM → recovery) could **not** be made reproducible here:
`swtpm`'s BitLocker sealing is unreliable (`Enable-BitLocker -TpmProtector` intermittently
returns "no valid TPM" / COM `E_FAIL`; the TPM protector often will not attach, leaving
`ProtectionStatus=Off`), compounded by QEMU segfaulting on ~half of TPM+KVM boots. These
are **emulation-stack limitations, not properties of the PBA or the override.** This
**strengthens open pre-condition (4)**: the auto-unlock-after-reseal claim must be
validated on **real TPM hardware with real BitLocker** — `swtpm` is not a sufficient
substitute for the seal step.

## Alternatives Considered
- **Keep ADR-0013 #3 (firmware-`db` Windows).** Windows still boots and BitLocker
  stays on the stock PCR 7 seal (no provisioning obligation). Rejected as the *demo*
  model because it puts the Microsoft CAs in firmware `db` — firmware then trusts
  Microsoft directly, so the "key A only" property does not hold for Windows and the
  trust model is asymmetric with the Linux path. Retained as the sanctioned
  alternative for deployments that cannot own provisioning order (decision 2).
- **Symmetric override for both OSes but with SHIM-style PCR 7 re-measurement.**
  Re-adding a PCR 7 authority event (as SHIM does) would still record *our* authority,
  not a Microsoft `db` PCA, so PCR 7 still diverges from a stock boot — it does not
  avoid the provisioning obligation, only adds runtime complexity. Deferred.

## Security Impact
Widens R-014 to include the Windows path. The **fail-closed** properties are
unchanged and re-validated here: enforcing-SB precondition, verify-before-arm,
exactly-one-buffer (pointer+size) one-shot authorization, self-restore; absent the
tag a `pba-override` entry fails closed. The negative demo (broker without the
Windows CAs → `bootmgfw` rejected, override never armed) is the direct evidence. The
**new** residual is operational, not authorization: PCR-7/BitLocker recovery on
PBA/override change, mitigated by the decision-2 provisioning requirement. The
override remains, by design, a Secure Boot bypass **scoped to the single
pre-verified image** — it cannot make an unverified image load.

## Compliance Impact
CRA integrity (ER-2) / §5.3 boot-chain-validation scope. Requires:
`risk-assessment.md` R-014 mitigation + change-log updated to record the Windows
extension and the provisioning obligation; `threat-model.md` TB2 exception + R-014
row updated; `cra-essential-requirements-matrix.md` cross-check; `CLAUDE.md`
architecture rule amended (firmware-`db` is the BitLocker-safe default; the override
Windows path is the our-keys-only alternative with the provisioning obligation). An
independent security-review record and the Security/Release Owner gate are merge
pre-conditions, as for ADR-0013.

## Test Impact
`demo:windows` covers both override paths: the self-contained WinPE/Setup path
(`test/qemu/demo-windows.sh`) and the full pre-installed Windows path
(`test/qemu/demo-windows-installed.sh`, `WIN_OSDISK=<disk>`, boots to the logon screen
on AHCI). The broker-without-Windows-CAs negative (fail closed, override never armed)
is validated in-session and should be wired as a permanent headless matrix (candidate:
`test:override` extended with a Windows-target rejection case, or a dedicated
`test:win-override-negative`). `test/qemu/override-pcr.sh` characterizes the PCR-7
divergence; `test/qemu/pcr7-reproducibility.sh` proves PCR-7 is reproducible and
authority-stable (the mechanism the auto-unlock claim rests on). The rigorous BitLocker
auto-unlock A/B test is **not** an emulation test — it needs real TPM hardware (see
Empirical validation).

## Rollback Plan
Isolated behind `-tags trustbroker` + the `pba-override` mode. Reverting the Windows
extension is: set `demo:windows` back to the ADR-0013 firmware-`db` model (validation
`pba`, Microsoft CAs in firmware `db`) — the diff is the policy `validation` field,
the firmware enrollment (`--no-microsoft` vs `--add-db` MS CAs), and the build tag.
Nothing in a shipped build depends on this ADR.
