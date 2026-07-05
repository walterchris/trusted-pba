# ADR-0012: SHIM-style Security-protocol override for a full trust broker — spike, scoped away from the measured-boot/Windows path

## Status
Proposed (spike). This ADR **reconsiders and refines** ADR-0010's rejection of
Approach A2 (hooking `EFI_SECURITY2_ARCH_PROTOCOL`), now that a concrete driver has
surfaced: booting a second stage the PBA trusts but the firmware `db` does **not**
(e.g. Windows Boot Manager on a platform provisioned with *our* keys only). It does
**not** commit the feature to product; it records the mechanism, a source-grounded
measured-boot analysis, the resulting scope limit, and a spike plan. A follow-up
ADR will decide the production implementation.

## Context

The PBA is validated by firmware Secure Boot (our keys in `db`) and then chainloads
a second stage. Today (ADR-0006/0007/0010) the `pba`-validation path verifies the
target with `internal/imageverify` and hands the **verified buffer** to firmware via
`LoadImageBuffer`. Under enforcing Secure Boot the firmware **re-validates that
buffer against `db`** (`cmd/pba/main.go` `verifyAndLoad` invariant). So on a platform
whose `db` holds only our keys, a Microsoft-signed `bootmgfw.efi` — which the PBA can
happily verify against the Microsoft CA in its own trust store — is nonetheless
**rejected by firmware at load** (`EFI_SECURITY_VIOLATION`). The PBA's own verdict
does not authorize the firmware.

The proposal (this ADR's subject) is to do what SHIM does: **override the firmware
security-arch protocol** so the PBA's verdict *is* what gates the load, letting it
boot an image not in `db`.

### How SHIM actually does it (source-grounded; `rhboot/shim` `main`)

- **Override mechanism** — `lib/security_policy.c:security_policy_install()`
  overwrites, *in place*, the function pointers of the two firmware protocols:
  `EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication` and
  `EFI_SECURITY_ARCH_PROTOCOL.FileAuthenticationState`, saving the originals. The
  replacement **chains to the original firmware handler first**; only if firmware
  denies (image not in `db`) does it call `shim_verify` against vendor_cert / MOK /
  allowlist, returning `EFI_SUCCESS` for a trusted-but-not-in-`db` image. It also
  *installs* a `SHIM_LOCK` protocol so a second stage can ask SHIM to verify a blob
  directly. Override installed only when `secure_mode()` and under
  `OVERRIDE_SECURITY_POLICY`.
- **Loader** — modern SHIM does **not** use `gBS->LoadImage` for the second stage;
  it reads the file itself and runs its **own PE loader** (`pe.c:handle_image`),
  giving it control over verification + measurement and avoiding recursion through
  the protocol it just hooked. (The `LoadImage` fallback is the *original* design;
  the exact security incident that motivated the switch was not found in a primary
  source — treat as design rationale, not a cited CVE.)

### The measured-boot consequence (this is the decisive finding)

Per the TCG PC Client Platform Firmware Profile:

- **PCR 4** ← the **image hash** (`EV_EFI_BOOT_SERVICES_APPLICATION`), measured on the
  *image-load* path, independent of the authorization verdict.
- **PCR 7** ← the **Secure Boot authority**: the specific `db` entry that *validated*
  the image (`EV_EFI_VARIABLE_AUTHORITY`), measured on the *firmware authentication*
  path, with a dedup rule.

If a custom override authorizes an image **without consulting `db`**, the PCR 7
`EV_EFI_VARIABLE_AUTHORITY(db → …)` event for that image is **missing or different**
— the firmware never recorded a `db` authority it didn't use. SHIM compensates by
re-creating the measurements itself: image hash into **PCR 4** (`tpm.c:tpm_log_pe`),
the authority it actually used into **PCR 7** in the same Microsoft
`EV_EFI_VARIABLE_AUTHORITY` format (`verify.c`/`mok.c:tpm_measure_variable`), and the
raw MOK list state into **PCR 14** (the MOK PCR). Ordering in `efi_main`: measure
MOK/SBAT (PCR 7 + 14) → install the override → load + measure the second stage
(PCR 4 + its PCR 7 authority). SHIM itself is measured by *firmware* before it runs,
so the override never affects SHIM's own measurement — only the next stage's.

**Crucially for us:** even when SHIM re-adds a PCR 7 authority event, the recorded
authority is **SHIM's own vendor_cert/MOK, not a firmware `db` PCA** — so PCR 7
**diverges from a normal firmware-`db` boot**. BitLocker seals its VMK to **PCR 7**
by default. Therefore **authorizing `bootmgfw.efi` through a Security-protocol
override changes PCR 7 → the TPM will not release the key → BitLocker drops to its
recovery prompt.** This is exactly why `CLAUDE.md` mandates "*For Windows, let
firmware validate Windows Boot Manager — do not manually load it*." (The general
PCR 7 dependency is well established; the precise BitLocker seal profile was not
verified against a primary Microsoft spec and must be confirmed before any Windows
override work.)

### Measured-boot characterization — spike finding (task 5)

Verified virtually (`test/qemu/override-vtpm.sh`, swtpm + QEMU `tpm-tis`): the
`pba-override` path **boots correctly with a vTPM present** — the override does not
break booting under measured boot; firmware measures the boot as usual.

Empirical PCR-7 *digit* capture was **not** achievable with the QEMU/swtpm/tpm2-tools
toolchain, and this is itself a finding: QEMU's `tpm-emulator` establishes the TPM
data channel by passing an fd to swtpm via `CMD_SET_DATAFD` over a **UNIX** control
socket (`SCM_RIGHTS`), which (a) rules out a TCP control socket and (b) precludes a
concurrent swtpm `--server` channel for `tpm2-tools`; and PCRs are volatile, lost when
swtpm exits with QEMU. So a post-boot read-back is blocked. Getting real PCR-7 digits
therefore requires a **guest-side `EFI_TCG2_PROTOCOL` event-log dumper** (a small EFI
app) — tracked as a follow-up. The PCR-7 **divergence itself** is not in doubt: it
follows directly from the TCG mechanism above (an image authorized outside `db` gets
no `db` `EV_EFI_VARIABLE_AUTHORITY` event in PCR 7), which is why this override is
**scoped away from the Windows/BitLocker path**.

### Feasibility in our stack (go-boot / TamaGo)

Verified in the fork: go-boot exposes **no** Security/Security2 arch protocol, **no**
`InstallProtocolInterface`, and its UEFI bridge is **one-way** (`callService`,
Go→firmware only; no foreign-entry path). A firmware→Go callback (the override's
`FileAuthentication` handler is *called by* the DXE core) is the reverse-ABI
trampoline ADR-0010 finding 1 describes: `g`/TLS survival, a dedicated Go callback
stack, GC/reentrancy — substantial, novel, security-critical runtime work.

## Decision

1. **Do not** use a Security-protocol override on the **Windows / measured-boot
   path.** It breaks BitLocker's default PCR 7 seal (above). The sanctioned Windows
   approach remains firmware-`db` validation: enroll the Microsoft CA in the
   platform `db` so firmware produces the genuine PCR 7 authority event. This is what
   the new QEMU **Windows-handoff (A′)** test exercises (our keys validate the PBA;
   MS CA in `db` validates Windows Boot Manager; the PBA additionally `pba`-verifies
   it) — see Test Impact.

2. **Spike** the override as a *general trust-broker* capability for the **narrow
   non-measured-boot case** ADR-0010 already identified: a custom second stage the
   PBA trusts, not in firmware `db`, where no downstream PCR 7 seal depends on the
   firmware authority (or Secure Boot is customer-configured accordingly). Prefer the
   cheaper **C/asm authorization stub** over a full Go reverse-ABI callback: the PBA
   has already run `imageverify`, so the installed `FileAuthentication` handler need
   only authorize the *one* pre-approved buffer (by hash) and restore the original —
   a C-ABI function firmware can call with no Go runtime. The stub **must** re-create
   the PCR 4 (and, where a consumer needs it, PCR 7) measurements SHIM-style, or
   explicitly document the measured-boot divergence for its target.

3. This supersedes ADR-0010's blanket A2 rejection **only** to permit the spike; the
   single-hop-via-firmware-`LoadImage` design stays the default and the sole Windows
   path until a follow-up ADR accepts a production implementation.

## Alternatives Considered

- **MS CA in firmware `db` (A′), no override.** The correct Windows path: firmware
  validates `bootmgfw` and produces the real PCR 7 authority, so BitLocker holds.
  Chosen for Windows. Does not help the "our-keys-only, not-in-`db`" custom case.
- **Full Go reverse-ABI callback for the override.** Most general (SHIM-parity), but
  the heaviest, riskiest runtime work in the boot-critical TCB (ADR-0010 finding 1).
  Deferred behind the C/asm stub.
- **Hand-rolled PE loader for all targets (ADR-0010 Approach B).** Bypasses firmware
  re-validation without a protocol override, but takes on full load responsibility,
  may disturb measured boot, and Windows Boot Manager may not tolerate it. Still
  rejected as a default.

## Security Impact

A Security-protocol override is a change to the firmware TCB during boot: it makes
the PBA's verdict authoritative for the next load. Done wrong it is a Secure Boot
bypass. Constraints for the spike: only under enforcing Secure Boot; authorize
exactly the single buffer already `imageverify`-validated — the stub `memcmp`s the
firmware-supplied `FileBuffer` against the retained verified bytes (content-exact,
one-shot), never a blanket "return success"; restore the original handler
immediately after; fail closed on any install/restore error. The measured-boot divergence is itself a
security-relevant property (attestation/BitLocker) and must be characterized, not
discovered in the field. No change to the PBA's current guarantees until a
production ADR lands.

## Compliance Impact

Touches CRA integrity (ER-2) and the boot-chain-validation §5.3 scope decision.
This ADR is the recorded evidence that the override was evaluated and **scoped away
from the Windows/measured-boot path** on a source-grounded basis. Update the
threat model (TB1/TB2, add a measured-boot/PCR-7 note) and the CRA matrix when a
production implementation is proposed. No classification change from the spike.

## Test Impact

- **Now:** QEMU **Windows-handoff (A′)** scenario — PBA built `-tags winhandoff,trustfull`
  (`pba`-validation policy targeting the staged loader + the real full trust set),
  OVMF enrolled with our keys **and** the Microsoft CA, a real Microsoft-signed
  loader staged as the target; assert the PBA verifies it and firmware launches it
  under enforcing Secure Boot. Gated on an operator/CI-provided loader (skips when
  absent), like `TestRealMicrosoftSignedImage`.
- **Spike:** a measured-boot characterization (PCR 4/7 event log with and without the
  override) is a required deliverable before any production acceptance, plus a
  negative test that the override authorizes *only* the pre-approved hash.

## Rollback Plan

The spike is isolated (a test/experimental build tag and, if built, a go-boot branch
addition); reverting is dropping it. The production default (firmware `LoadImage`
re-validation) is unchanged, so nothing in the shipping boot path depends on this
ADR until a follow-up ADR accepts an implementation.

## Spike Plan (Option B — asm-stub override)

Chosen approach: the firmware-called `FileAuthentication` handler is a **runtime-free
MS-ABI assembly stub**, not Go — so the firmware→callback never enters the Go runtime
(no `g`/TLS/growable-stack/GC re-entry). Go's only role is to **arm** the stub (plain
memory writes) before `LoadImageBuffer`. Two design refinements over the initial
sketch:

- **Authorize by content `memcmp`, not pointer identity or a hash.** The stub compares
  the firmware-supplied `FileBuffer` byte-for-byte against the exact buffer Go already
  `imageverify`'d. Correct whether firmware passes our `SourceBuffer` through *or*
  copies it, and it authorizes only those exact bytes. One-shot: disarm on match.
- **The override QEMU test needs no Microsoft/Windows binary.** Reuse the `pbatest`
  pattern: a throwaway CA signs our own `testapp`, that CA is embedded in the PBA
  trust store, and OVMF `db` holds a *different* key — so firmware rejects `testapp`
  while the PBA trusts it. Fully self-contained and deterministic.

### Runtime flow
```
verifyAndLoadOverride(target):
  read file → imageverify (Authenticode + dbx)          # unchanged, fail-closed
  gate: Secure Boot enforcing AND policy opts in
  LocateProtocol(Security2)  [+ legacy Security]         # fail-closed if absent
  ARM: armed_ptr=&image[0]; armed_size=len; armed=1      # plain Go writes; hold ref
  save original FileAuthentication; install &stub
  LoadImageBuffer(image) + StartImage                    # firmware calls stub → SUCCESS
  (any return) restore original; disarm; fail-closed
```
Stub (firmware-called, no Go): `!armed` → tail-call original; `FileSize != armed_size`
→ original; `memcmp(FileBuffer, armed_ptr, armed_size)==0` → `armed=0`, return
`EFI_SUCCESS`; else → original.

### Workstreams
0. **Spike / go-no-go (throwaway).** Prove: `LocateProtocol(Security2)` → overwrite
   `FileAuthentication` with our asm stub → **firmware actually calls the stub** →
   clean return, no Go runtime entered → boots one out-of-`db` image under enforcing
   SB. Instrument: is `FileAuthentication` called once per load? Hook Security2 only
   or also legacy `EFI_SECURITY_ARCH_PROTOCOL`? Confirm firmware doesn't mutate the
   authenticated bytes.
1. **go-boot (fork, ADR-0008):** `LocateProtocol`; read/write of the protocol's
   `FileAuthentication` field (save/restore original); export the stub symbol + arm
   block; fail-closed on locate failure.
2. **asm stub (Plan9 `.s`, MS x64 ABI):** correct shadow space / 16-byte alignment /
   callee-saved regs; inline `memcmp`; one-shot disarm; tail-call the saved original.
3. **PBA (`cmd/pba`):** explicit `pba-override` policy mode (never on by default);
   `verifyAndLoadOverride` per the flow above; keep the verified Go buffer alive
   across the firmware call (Go GC is non-moving); fail-closed on every path.
4. **Measured boot:** characterize + **document** the PCR 7 divergence; mark these
   targets not-BitLocker-safe. TCG2 re-measurement is a later optional increment.
5. **Docs/governance:** threat-model update (PBA as an out-of-`db` authority; the
   override window); a **follow-up ADR that accepts** the production implementation.

### Test plan
- **Unit (host Go):** arm/disarm/restore state machine (mock the pointer write);
  `imageverify` failure → nothing armed; `LocateProtocol` failure → hard error, no
  boot; `pba-override` policy parsing.
- **Stub-level (asm called directly as MS-ABI from a harness):** armed+match →
  `EFI_SUCCESS` + disarm; armed+wrong-size → original; armed+same-size-different-bytes
  → original (the core tamper test); not-armed → original; second-call-after-disarm →
  original (one-shot).
- **QEMU (self-contained, deterministic):** POS — without override firmware rejects
  `testapp` (= today's `win-handoff` NEG), with override it boots (REQUIRE
  `pba-verified` + `TEST-APP: ok`; FORBID `chainload failed`); NEG — corrupt/unsigned
  `testapp` → `imageverify` fails → nothing armed → fail-closed; regression — existing
  `firmware`/`pba` modes + SB/pba matrices unchanged.
- **swtpm evidence:** boot POS with swtpm, dump the TCG log / PCR 7, show the missing
  `db`-authority event vs a firmware-`db` boot (ADR evidence, not an initial gate).

### Sequencing
Spike (go/no-go) → go-boot API → stub + stub tests → PBA `pba-override` + unit tests →
QEMU override matrix → swtpm PCR evidence + threat model + acceptance ADR.

### Top risks (all spike-gated)
MS-ABI correctness in Plan9 asm; keeping the armed buffer alive/immutable across the
firmware call; multiple `FileAuthentication` calls per load; restore-on-all-paths +
one-shot disarm; accepting PCR 7 divergence as a conscious, documented call.

Also: verify BitLocker's exact PCR 7 seal profile against a primary Microsoft source
before *any* Windows use of the override.
