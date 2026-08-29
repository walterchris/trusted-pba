# Security review — `pba-override` measured boot (ADR-0015 + ADR-0016)

- **Date:** 2026-08-29
- **Change:** branch `fix/windows-handoff-demos` — two Proposed, security-critical measured-boot
  extensions to the `-tags trustbroker` `pba-override` path (ADR-0012/0013/0014). Both are gated
  behind `-tags trustbroker` and are **absent from release builds**.
  - **ADR-0015** (`docs/architecture/adr/ADR-0015-measure-override-authority-pcr7.md`): the
    override measures its own authorization into **PCR 7** — an `EV_EFI_VARIABLE_AUTHORITY` event
    in a **PBA-owned namespace** (variable `PbaOverride`, fixed PBA `VendorGuid`/`SignatureOwner`)
    carrying the embedded-trust-store `db` CA the image's signer chained to — before `StartImage`,
    making the override attestable instead of silent.
  - **ADR-0016** (`docs/architecture/adr/ADR-0016-override-measure-chained-image-pcr.md`): the
    override measures the chained image (`bootmgfw`, UKI, …) into policy-configured PCR(s)
    (`measure_image_pcrs`, default `[4]`) via `EFI_TCG2_PE_COFF_IMAGE`, restoring the
    `EV_EFI_BOOT_SERVICES_APPLICATION` measurement a SourceBuffer `LoadImageBuffer` skips — so
    BitLocker's full default `0,2,4,11` profile auto-unlocks under the override.
- **New policy config:** `require_tpm` (bool, default `false`) and per-entry `measure_image_pcrs`
  (default `[4]`, explicit empty disables, range-checked 0–23, `pba-override` entries only).
- **Implementation surface:** new pure-Go, host-tested `internal/tcgmeasure` (event byte layout)
  behind a 1-method `Extender` seam; the TCG2 firmware call is a new go-boot binding — fork bumped
  **`v1.6.2-tpba.7` → `v1.6.2-tpba.8`**, an **additive new file** `uefi/tcg2.go` (`GetTCG2` +
  `HashLogExtendEvent`), **no change to existing files or asm**.
- **Reviewer:** independent security-review-agent (adversarial, did not implement the change).
- **Method:** reviewed both ADRs, the `tcgmeasure` event construction + host tests, the
  policy schema/validation (`require_tpm`, `measure_image_pcrs`), the override call site
  (measure post-`imageverify`, post-`tbstub` arm/verify gate, pre-`StartImage`), the go-boot
  tpba.8 additive binding, and the emulation evidence (reseal + reboot loop, fresh-TPM negative)
  against the threat model and the non-negotiable security rules.

## Verdict: APPROVE — security-neutral-to-positive

The change **does not touch the authorization boundary.** Authorization still rests on
`internal/imageverify` (Authenticode verify against the embedded trust store) plus the
`internal/tbstub` arm/verify one-shot gate; the measurement runs strictly *after* both and is
**advisory-to-attestation** — it can never authorize an image. No new external input is trusted:
the measured CA is the compiled-in trust-store cert and the measured image bytes are the
already-verified ones; the only new firmware interaction is one `HashLogExtendEvent` call on the
already-privileged override path. The measurements make the override **attestable** (a verifier
can now see that the PBA, not firmware `db`, vouched for the loader) — a strengthening of the
measured-boot chain. All findings are **LOW**.

## Findings (all LOW)

- **F-1 — PCR-4 `PE_COFF` value is firmware-dependent, unproven off-hardware.** The
  `EFI_TCG2_PE_COFF_IMAGE` extend's resulting PCR-4 value depends on the firmware's TCG2
  implementation; it is validated only in emulation, not on real hardware. This is ADR-0016's
  **open pre-condition** — real-hardware confirmation of the expected PCR-4 event is required
  before any production Windows use, and is **DEFERRED by decision this session**. Tracked under
  R-014 / R-010 (mock-vs-real divergence, Phase 8).
- **F-2 — cosmetic `ImageLocationInMemory`.** The `UEFI_IMAGE_LOAD_EVENT` device-path /
  location field is log-only (BitLocker gates on the PCR-4 *value*, i.e. the Authenticode hash,
  which a minimal MEDIA/FILEPATH device path already reproduces — ADR-0016 Alternatives). No
  security effect.
- **F-3 — default PCR-4 measure now also applies to the ADR-0013 non-Windows override path.**
  Because ADR-0016 measures *whatever* the override boots (generic, not Windows-specific), the
  default `[4]` now also measures a Linux/recovery override target. This is intentional and
  consistent; flagged for the human-gate confirm.
- **F-4 — compliance traceability update** (this record + risk-assessment R-014, threat-model
  TB2/measured-boot, CRA matrix ER-1/ER-2). Completed by the Compliance Agent on 2026-08-29.

## Fail-closed control (`require_tpm`)

The measurement path's fail-closed behavior is policy-driven: `require_tpm: true` → a missing
`EFI_TCG2_PROTOCOL` or a failed `HashLogExtendEvent` **refuses to boot** (do not boot an image we
cannot measure); `require_tpm: false` (default) → best-effort (log loudly and boot the
already-verified image **unattested** — never a silent fallback). The default is safe because the
override's *authorization* is intact either way; deployments that mandate attestation set
`require_tpm: true`.

## Residual (R-014) — unchanged rating (Low)

The authorization posture (booting an out-of-`db` image) is unchanged and still gated +
fail-closed. The new residual for **adopting or changing** these measurements — and for any PBA
change — is **operational, not authorization**: a one-time BitLocker reseal event (the managed
case per ADR-0014's provisioning obligation), not a Secure Boot bypass.

## Disposition

ADR-0015 and ADR-0016 are **Proposed / NOT Accepted.** As with ADR-0013/0014, the §5.3
Security/Release Owner human gate is a merge pre-condition; the capability is inert in shipped
builds (release builds stay override-free). The real-hardware PCR-4 confirmation (F-1) remains an
**open, deferred** pre-condition before any production Windows deployment.
