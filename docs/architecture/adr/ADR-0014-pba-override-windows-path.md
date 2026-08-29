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
> **Disproved by the Empirical validation below.** This block's hypothesis — that sealing
> BitLocker *with* the override in the measured chain reproduces PCR 7 and auto-unlocks — does
> **not** hold on a genuine Key-A-only override. PCR 7 (OS-loader authority) and PCR 4 (Bootmgr)
> both diverge; BitLocker's default profile drops to recovery, and only a reduced **PCR 0+11**
> seal auto-unlocks. (An intermediate draft here wrongly reported the full PCR 7,11 profile
> working after a reseal — that was a firmware-`db` boot caused by an MS-tainted `db` template;
> see the CORRECTION in the Empirical validation.) Kept for the reasoning trail; read the
> Empirical validation for what actually holds.

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
2. **~~Provisioning / seal-with-PBA obligation.~~ WITHDRAWN — superseded by the Empirical
   validation below.** BitLocker under the genuine Key-A-only override does **not** auto-unlock
   with the default profile: PCR 4 (Bootmgr) and PCR 7 (OS-loader authority) diverge → recovery.
   The only working configuration is an explicit **PCR 0+11** TPM protector (reseal to `@(0,11)`),
   which trades away PCR 4/7 binding (boot-chain integrity then rests on Secure Boot key A + the
   PBA's `require_secure_boot` + PCR 0). A deployment that needs the **stock PCR-7 seal**
   (Microsoft-`db` authority for `bootmgfw`) must use the firmware-`db` model (ADR-0013). The
   override's PCR-7 authorization is *attested* (ADR-0015) but not *bound* by BitLocker. As for
   any BitLocker machine, a signing-key/`db`/SB-config or PBA change is a reseal event.
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
   - **`BITLOCKER=1 WIN_OSDISK=<disk>` (`demowinbl`, firmware-`db` model)** — the shipped
     BitLocker demo, with the **strongest** (stock PCR-7) seal: db = key A + Microsoft CAs,
     `validation: pba`, so PCR 7 is a normal firmware-`db` boot. `test/qemu/demo-windows-bitlocker.sh`
     enables BitLocker (TPM protector) on a copy of the disk (`SETUP=1`, one-time), then
     boots it and the **TPM auto-unlocks** the encrypted volume to the Windows logon screen —
     no recovery prompt. (The **override** model can also auto-unlock BitLocker, but **only
     with a reduced PCR 0+11 protector** — PCR 4/7 diverge under the override; see the Empirical
     section — and it is not wired as a demo target; `demowinbl` uses the firmware-`db` model for
     the strongest, stock PCR-7 seal.)

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
### BitLocker auto-unlock — the decisive A/B result

Real Windows 11 + real BitLocker + a properly-manufactured swtpm (Fedora 4M TPM-enabled
OVMF; the minimal custom PCR-test OVMF bugchecks Windows `KMODE_EXCEPTION_NOT_HANDLED`).
The prerequisites that made in-emulation BitLocker reliable: `swtpm_setup` to manufacture
the TPM (SRK/EK + sha256 PCR bank), `Initialize-Tpm` inside Windows to take ownership
("The TPM does not have an owner set" otherwise), and waiting for `FullyEncrypted` before
shutdown (protection engages only at 100%). With those, the A/B test is clean and
repeatable — and it **overturns this ADR's central premise**:

> **CORRECTION (supersedes an earlier draft of this section).** An earlier version claimed
> the override auto-unlocks BitLocker with the **full default PCR 7,11** profile once the
> protector is *resealed on a steady-state boot*. That was a **test-harness artifact** and is
> **wrong for the override**. Root cause: the 4M TPM-enabled OVMF varstore template ships with
> the **Microsoft CAs pre-enrolled in `db`**, and `virt-fw-vars --no-microsoft` only skips
> *adding* MS keys — it does **not** clear the ones already there. So that "reseal" boot booted
> `bootmgfw` **directly via firmware `db`** (a firmware-`db` boot: PCR 7,11 reproducible, MS-CA
> authority present) — the **PBA never ran** (`BdsDxe: loading … bootmgfw.efi`, zero
> `TRUSTED-PBA` log lines). Clearing `db` first (`-d db`, db = key A only) forces the PBA to be
> the only path; the results below are on that **genuine override**.

> **RESOLVED by ADR-0016.** The finding below — that the override cannot bind PCR 4 and only
> PCR 0+11 works — was true *before* the override measured the chained image. The root cause is
> that `LoadImageBuffer` (SourceBuffer) load is **not measured into PCR 4** by firmware, so
> `bootmgfw` was absent there and BitLocker's PCR-4 seal never reproduced. **ADR-0016** has the
> override measure the chained image's Authenticode hash into PCR 4 itself (default), restoring
> that measurement — and BitLocker's **full default 0,2,4,11 profile then auto-unlocks under the
> override** (validated 5/5 reboots + fresh-TPM negative). PCR 7 still cannot be bound (the
> `db`-config divergence is real). So the override now supports the full boot-chain BitLocker
> profile; the PCR 0+11 fallback below is retained (set `measure_image_pcrs: []`) but is no
> longer the only option. The pre-ADR-0016 analysis is kept for the reasoning trail.

- **On the genuine Key-A-only override, BitLocker's default profile is 0,2,4,11 and PCR 4 does
  NOT reproduce → recovery. Only the reduced PCR 0+11 profile auto-unlocks.** Real Win11 + real
  BitLocker + swtpm, db = key A only (PBA verified running + measuring each boot, per ADR-0015):
  - **Default profile → recovery.** With SB-for-integrity unavailable under the override,
    Windows binds **PCRs 0,2,4,11**; a steady-state reseal to that profile still drops to
    **recovery** across reboots — `4_2_…_Bootmgr_…` — because **PCR 4 is not reproducible**
    under the Key-A-only override. Root cause, tracked via the firmware serial + the TCG event
    log: a Key-A-only `db` **rejects the Microsoft-signed `bootmgfw` boot entries** that OVMF
    auto-discovers (`BdsDxe: … Access Denied -- rejected … by Secure Boot`), and **each
    rejected attempt injects a `Calling`/`Returning` "EFI Application from Boot Option"
    `EV_EFI_ACTION` event into PCR 4** — a variable number of them, depending on the mutable
    NVRAM boot-entry set (OVMF re-adds + re-prioritises the Windows Boot Manager entry every
    boot). Firmware-`db` never hits this because `bootmgfw` succeeds on the first attempt.
    **Mitigation (partial):** provisioning an explicit PBA boot entry as `BootOrder[0]`
    (`--append-boot-filepath \EFI\BOOT\BOOTX64.EFI`, booting from a fresh vars copy each boot)
    makes firmware boot the PBA directly with **zero bootmgfw rejections** (verified) — but a
    **residual PCR 4 non-determinism remains** (the seal-boot vs verify-boot app-measurement
    sequence for the PBA/`bootmgfw` images loaded via the override's `LoadImageBuffer`, which
    the Windows WBCL log does not fully capture), so the default profile still recovers. The
    reduced **PCR 0+11** profile below sidesteps PCR 4 entirely and is the validated-solid
    BitLocker configuration.
  - **PCR 7 also diverges** — the override authorizes `bootmgfw` with no firmware-`db`
    authority, so Windows' OS-loader authority (`OSLoaderAuthoritySignature`) does not
    reproduce as a firmware-`db` boot's would.
  - **Reduced PCR 0 (firmware) + 11 (BitLocker) → auto-unlock, validated solid.** Resealing the
    TPM protector to an explicit `@(0,11)` (WMI `ProtectKeyWithTPM`) — the registers the
    override leaves untouched — auto-unlocks:
    - **Positive:** **N consecutive independent reboots** (swtpm `startup-clear` resets PCRs
      each boot) all reach the Windows **logon screen** — no recovery.
    - **Negative:** a fresh/wrong TPM → **BitLocker recovery** (recovery-key ID matches) —
      genuinely TPM-gated.
  - **Cost of the reduced profile:** it drops PCR 4 (boot-manager/PBA/`bootmgfw` code) and
    PCR 7 (SB state + authorities) from the *seal*. Boot-chain integrity then rests on Secure
    Boot (key A) admitting only the our-signed PBA + override-vouched `bootmgfw`, the PBA's
    `require_secure_boot` fail-closed precondition, and PCR 0 (firmware tamper → recovery).
- **PCR 7 is now measured/attestable even though BitLocker does not bind it (ADR-0015).** The
  override records an `EV_EFI_VARIABLE_AUTHORITY` event into PCR 7 naming the PBA as the
  authority (verified in the MeasuredBoot event log: PCR 7, type `0x800000E0`, PBA namespace +
  the authorizing CA). This makes the brokering visible to remote attestation; it does **not**
  change the BitLocker seal profile (Windows still won't use PCR 7 for integrity under the
  override), so the reduced PCR 0+11 seal remains the working BitLocker configuration.
- **The firmware-`db` model DOES auto-unlock (validated positive + negative).** db = key A
  **+ Microsoft CAs**, `validation: pba` (the PBA trust-brokers `bootmgfw` AND firmware
  re-validates it against the Microsoft `db`). PCR 7 is then a normal firmware-`db` boot,
  reproducible, so BitLocker's TPM protector releases the VMK:
  - **Positive** (same sealed TPM, same SB vars): boots to the Windows **logon screen** —
    auto-unlocked, no recovery.
  - **Negative** (a fresh/wrong TPM): **BitLocker recovery** — confirming the unlock is
    genuinely TPM-gated, not a leftover clear key.
  This is exactly ADR-0013's BitLocker-safe path, now demonstrated end-to-end as
  `task demo:windows BITLOCKER=1` (`demowinbl` variant, `test/qemu/demo-windows-bitlocker.sh`).

**Consequence for this ADR:** both models auto-unlock BitLocker, but with very different
seal strength.
- **Firmware-`db` model (ADR-0013): stock PCR-7 seal, strongest binding — recommended.** PCR 7
  carries the Microsoft-`db` authority for `bootmgfw`; auto-unlocks with no reseal (validated
  positive + negative, shipped as `task demo:windows BITLOCKER=1`). Use where the Microsoft CAs
  in firmware `db` are acceptable.
- **Override model: BitLocker works only with the reduced PCR 0+11 seal.** On the genuine
  Key-A-only override, PCR 4 and PCR 7 both diverge, so the default profile drops to recovery;
  the protector must be (re)sealed to an explicit `@(0,11)`. That trades away PCR 4/7 binding —
  boot-chain integrity then rests on Secure Boot (key A) + the PBA's `require_secure_boot` +
  PCR 0. It is **not** equivalent to the firmware-`db` stock PCR-7 seal and needs its own
  security sign-off. The override additionally *attests* its authorization in PCR 7 (ADR-0015)
  even though BitLocker does not bind PCR 7. Decision (2)'s original "seal-with-PBA provisioning
  obligation" is therefore **withdrawn**: the enable-time seal it assumed does not reproduce,
  and the working configuration is the explicit PCR 0+11 seal, not the default one.

Open pre-condition (4)'s HW caveat is **resolved in emulation**: positively for the firmware-`db`
model (full PCR 7 seal), and for the override **only under the reduced PCR 0+11 profile**
(default/PCR-4/PCR-7 profiles drop to recovery). Confirm on real hardware before any
**production** Windows deployment.

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
divergence; `test/qemu/pcr7-reproducibility.sh` proves the override PCR-7 is reproducible
and authority-stable. The BitLocker auto-unlock A/B test IS an emulation test with a
properly-manufactured swtpm: `test/qemu/demo-windows-bitlocker.sh` (+
`bitlocker-enable.ps1`, `win-utilman-drive.py`) enables BitLocker in the firmware-`db`
model and shows the TPM auto-unlock (positive), and a fresh/wrong TPM forces recovery
(negative). It also demonstrates the override's BitLocker **incompatibility** (recovery
with `OSLoaderAuthoritySignature` PCR-7 mismatch). A real-hardware confirmation with a
real TPM remains desirable but is no longer the blocking gap.

## Rollback Plan
Isolated behind `-tags trustbroker` + the `pba-override` mode. Reverting the Windows
extension is: set `demo:windows` back to the ADR-0013 firmware-`db` model (validation
`pba`, Microsoft CAs in firmware `db`) — the diff is the policy `validation` field,
the firmware enrollment (`--no-microsoft` vs `--add-db` MS CAs), and the build tag.
Nothing in a shipped build depends on this ADR.
