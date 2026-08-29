# ADR-0016: The pba-override measures the chained image into PCR 4 (config-driven)

## Status
**Proposed** — extends ADR-0012/0013's `pba-override` and complements ADR-0015. It changes
measured-boot behavior (the PBA now extends a PCR), so it is §5.3/§23 security-critical and
requires the Security/Release Owner human gate + an independent security review before
Accepted. It rides inside the already-gated `-tags trustbroker` override path and is **not**
in release builds; within that path it is **on by default** (policy-configurable).

**Tracking issue:** [#132](https://github.com/walterchris/trusted-pba/issues/132).

## Context
The override loads the next boot image with `LoadImageBuffer` from a memory **SourceBuffer**
(the bytes the PBA read and verified), not from a firmware device-path boot option. Firmware
measures an `EV_EFI_BOOT_SERVICES_APPLICATION` event (the image's Authenticode hash) into
**PCR 4** for a device-path load, but **not** for a SourceBuffer load. Confirmed by reading
PCR 4 directly from the TPM: under the override, PCR 4 holds the PBA (which firmware loaded)
but **not** the chained `bootmgfw`.

Consequences:
- **BitLocker's default (PCR-4) profile fails.** On an our-keys-only override, Windows cannot
  bind PCR 7 (the `db`-config diverges; ADR-0014/0015), so it falls back to PCR 0,2,4,11.
  With `bootmgfw` absent from PCR 4, BitLocker's seal never reproduces → **recovery every
  boot** (`4_2_…_Bootmgr_…`). Empirically confirmed.
- **The chained image is unrepresented in measured boot** — a remote attestor sees the PBA in
  PCR 4 but not the OS loader the PBA actually launched.

The override deliberately loads via SourceBuffer (that is how the Security2 override authorizes
an out-of-`db` image), so the fix is to have the PBA make the measurement firmware would have.

## Decision
1. **After verifying and loading the target, the override extends the target image's
   Authenticode hash into the policy-configured PCR(s)** as an `EV_EFI_BOOT_SERVICES_APPLICATION`
   event (`EFI_TCG2_PROTOCOL.HashLogExtendEvent` with `EFI_TCG2_PE_COFF_IMAGE`), before
   `StartImage` — restoring exactly the measurement a firmware device-path load would make.
2. **Generic, not Windows-specific.** It measures **whatever image the override boots** (the
   Windows Boot Manager, a Linux UKI, a recovery app), with the event's device path derived
   from the entry's ESP path. Because it always runs, it is consistent across targets and never
   "breaks" a path by only sometimes measuring.
3. **Config: `measure_image_pcrs` on the boot entry.** Absent → default **`[4]`** (mimics
   firmware). An explicit list sets the PCRs; an explicit empty list **disables** it. Accepted
   only on `pba-override` entries (rejected on `firmware`/`pba`, where firmware measures the
   image itself); PCR indices are range-checked (0–23).
4. **Failure handling is policy-driven (`require_tpm`), same as ADR-0015.** A missing TPM or a
   failed extend is fatal only when `require_tpm: true` (abort — do not boot an image we cannot
   measure); with `require_tpm: false` (default) it is best-effort (log loudly, boot the
   already-verified image unattested — never silent). This keeps the override usable on TPM-less
   platforms while letting attestation-mandating deployments enforce measurement.
5. **Effect on BitLocker: full-profile binding.** With the measurement, BitLocker's default
   **PCR 0,2,4,11** seal reproduces under the override and auto-unlocks — boot-manager +
   firmware + BitLocker binding, materially stronger than the ADR-0014 PCR 0+11 fallback.
   Validated in emulation: **positive** — the resealed default profile auto-unlocks across N
   independent reboots (0 recoveries); **negative** — a fresh TPM → recovery (genuinely gated).
   PCR 7 still cannot be bound (the `db`-config divergence is real; that is unchanged).

## Alternatives Considered
- **Gate behind a separate build tag (the initial experiment).** Rejected: the whole override
  is already gated by `-tags trustbroker`; within it, the measurement should be on by default
  for the case that needs it and scoped by policy, not by a second compile flag.
- **Measure only `bootmgfw` / only for Windows.** Rejected: hard-coding the Windows path would
  misfire on the Linux override (the UKI would carry a bootmgfw device path) and is
  inconsistent. Measuring the actual target generically is correct for every override.
- **Do not measure; keep BitLocker on the PCR 0+11 fallback (ADR-0014).** Retained as the
  fallback (explicit empty `measure_image_pcrs`), but it binds neither the boot manager nor
  Secure-Boot state — weaker. The default is now the stronger PCR-4 binding.
- **Byte-match a firmware device-path event exactly (full HD-partition device path).** Not
  required: BitLocker gates on the PCR-4 **value** (the Authenticode hash), which a minimal
  MEDIA/FILEPATH device path already produces correctly; the fuller device path only affects
  the human-readable log. (This is the main thing to reconfirm on real hardware.)

## Security Impact
Strengthens the measured-boot chain: the chained OS loader is now measured into PCR 4 (and any
configured PCR), so remote attestation and BitLocker bind it. No change to authorization — the
extend runs after `imageverify` accepted the image and after the tbstub arm gate; a failed
extend fails closed. No new external input is trusted (the measured bytes are the already-
verified image). New residual, operational not authorization: adopting the measurement, or
changing the measured PCRs, is a one-time BitLocker reseal event (the standard class). Widens
ADR-0014's R-014 note accordingly.

## Compliance Impact
Supports CRA integrity/attestation: the full boot chain (including the override-loaded loader)
becomes measurable and bindable. Update risk-assessment R-014, the threat model
(TB2/measured-boot), and the CRA matrix; record the reseal + multi-reboot + fresh-TPM evidence.

## Test Impact
- `internal/tcgmeasure`: host tests for `MeasureImage` (one PE_COFF_IMAGE extend per PCR, correct
  event type, `UEFI_IMAGE_LOAD_EVENT` body) and `deviceFilePath` layout; fail-closed on error.
- `internal/policy`: `measure_image_pcrs` resolution (default `[4]`, explicit list, explicit
  empty = disabled, non-override = nil) and Parse rejection (non-override entry, PCR > 23).
- Empirical: reseal BitLocker's default profile on the override + N reboots auto-unlock; fresh
  TPM → recovery; **real-hardware confirmation of the expected PCR-4 event is an open
  pre-condition before production.**

## Rollback Plan
Set `measure_image_pcrs: []` on the entry to disable (reverting to the ADR-0014 PCR 0+11
BitLocker path), or drop the measurement block from `verifyAndLoadOverride`. Either returns
PCR 4 to its prior value; a BitLocker volume bound to the measured PCR 4 then takes one reseal
(or its recovery key) to return to the unmeasured baseline. No on-disk format change.
