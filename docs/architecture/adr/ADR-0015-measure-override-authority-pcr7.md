# ADR-0015: Measure the pba-override authorization into PCR 7

## Status
**Proposed** — extends ADR-0012/0013's `pba-override` and ADR-0014's Windows path with a
measured-boot record of the override's authorization. Security-critical measured-boot
behavior change: requires the Security/Release Owner human gate + an independent security
review before Accepted. Gated behind `-tags trustbroker`; **does not** change shipped
defaults (release builds stay override-free).

**Tracking issue:** [#131](https://github.com/walterchris/trusted-pba/issues/131).

## Context
The `pba-override` trust broker (ADR-0012/0013) authorizes an out-of-`db` image by
returning `EFI_SUCCESS` from a Security2 `FileAuthentication` override (`internal/tbstub`).
It extends **nothing** into the TPM. Firmware, by contrast, records an
`EV_EFI_VARIABLE_AUTHORITY` event into **PCR 7** naming the `db` certificate that
authorized each image it validates.

Consequence, confirmed empirically in ADR-0014 by parsing the guest's Windows MeasuredBoot
TPM event log: under the override, `bootmgfw` is authorized but **no authority event is
recorded for it** — PCR 7 carries only the key-A event firmware measured for the *PBA*.
The override is therefore **invisible** in PCR 7 / remote attestation: a verifier reading
PCR 7 cannot tell that a pre-boot component (the PBA), rather than firmware `db`, vouched
for the OS loader. That is a measured-boot gap, not an authorization gap (the tbstub gate,
enforcing-SB precondition, and verify-before-arm are unchanged).

SHIM closes the analogous gap: when it authorizes an image via MOK/vendor cert it calls
`EFI_TCG2_PROTOCOL.HashLogExtendEvent` to extend PCR 7 with an `EV_EFI_VARIABLE_AUTHORITY`
event naming *its own* authority. We adopt the same pattern for the PBA.

**PCR 7 cannot be made byte-identical to a firmware-`db` boot on an our-keys-only platform**
— firmware measures the `db` *variable contents* into PCR 7 (`EV_EFI_VARIABLE_DRIVER_CONFIG`)
at boot, and our `db` holds only key A whereas a firmware-`db` platform's `db` holds key A +
the Microsoft CAs, so the two diverge before any image is loaded. Spoofing a `db` authority
event would make PCR 7 *claim* firmware `db` authorized the loader while still not matching a
real firmware-`db` boot — a dishonest attestation with no functional upside. Rejected (see
Alternatives). We record an honest **PBA-namespaced** authority instead.

## Decision
1. **When the `pba-override` path authorizes an image, measure an `EV_EFI_VARIABLE_AUTHORITY`
   event into PCR 7 before `StartImage`**, via `EFI_TCG2_PROTOCOL.HashLogExtendEvent`. The
   event's `UEFI_VARIABLE_DATA` uses a **PBA-owned namespace** — variable name `PbaOverride`,
   a fixed PBA `VendorGuid` and `SignatureOwner` (`2f7e5a3c-...`, recorded in the code) — and
   its `VariableData` is the `db` CA certificate from the PBA's embedded trust store that the
   image's signer chained to (the authorizing authority, surfaced from `imageverify`). This
   makes the override's authorization **explicit and attestable** in PCR 7 while being truthful
   about who authorized it (the PBA, not firmware `db`).
2. **Deterministic → BitLocker-safe.** The event data (namespace GUIDs, name, trust-store CA
   DER) is compile-time-fixed, so the extend is byte-identical on every boot. It lands in PCR 7,
   which BitLocker does **not** bind under the override anyway (per ADR-0014 the working seal is
   the reduced **PCR 0+11** protector; PCR 4/7 diverge). Adopting the measurement therefore does
   not perturb the BitLocker seal — the PBA binary changing is already a PCR-4 change, and PCR 0
   and 11 are untouched. **Validated: with the measuring PBA, a PCR 0+11 protector resealed on a
   steady-state override boot auto-unlocks across N consecutive independent reboots (positive);
   fresh TPM → recovery (negative); and the PBA changing is a one-time PCR-0-independent reseal.**
3. **Advisory to attestation, never to authorization; failure handling is policy-driven
   (`require_tpm`).** The measurement runs only after `imageverify` has accepted the image; the
   tbstub arm/verify gate is unchanged, so it can never *authorize* anything. How a measurement
   failure (absent `EFI_TCG2_PROTOCOL`, or a failed `HashLogExtendEvent`) is handled is the
   policy's `require_tpm` decision: **`true` → fail closed** (abort — do not boot an image we
   cannot measure); **`false` (default) → best-effort** (log loudly and boot the
   already-verified image *unattested* — never a silent fallback). Rationale: a platform with no
   TPM has no measured boot to record into, and the override's authorization is intact either
   way; deployments that mandate attestation set `require_tpm: true`. The whole path stays behind
   `-tags trustbroker` and an explicit `validation: pba-override` entry; absent the tag it is not
   compiled.
4. **Layering.** Event construction is pure Go (`internal/tcgmeasure`, host-tested for exact
   byte layout); the TCG2 firmware call is a new go-boot binding (`uefi.TCG2`,
   `HashLogExtendEvent`) consumed through a 1-method `Extender` interface — no UEFI in the
   testable layer, mirroring the Opal/`TCGTransport` split.

## Alternatives Considered
- **Measure nothing (status quo).** Leaves the override invisible in PCR 7 / attestation.
  Rejected: a security product should make its trust-brokering measurable, and the change is
  cheap and deterministic.
- **Spoof a firmware-`db` authority event** (variable name `db`, Microsoft `SignatureOwner`,
  the MS CA) to try to match a stock PCR 7. Rejected: (a) it cannot match — the `db`-config
  PCR-7 event already diverges on an our-keys-only platform (see Context); (b) it makes the
  measured-boot log falsely attest that firmware `db` authorized the loader. Dishonest with no
  upside.
- **Extend a different PCR (e.g. a Windows debug PCR).** Rejected: PCR 7 is the Secure-Boot
  authority register that firmware and SHIM use for exactly this; attestors look there.
- **Also re-measure the image hash.** Unnecessary: firmware already measures the loaded image
  into PCR 4 (`EV_EFI_BOOT_SERVICES_APPLICATION`); only the PCR-7 authority event was missing.

## Security Impact
Strengthens the measured-boot chain: PCR 7 now records that the PBA authorized the OS loader,
so remote attestation and BitLocker seals bind that fact instead of silently omitting it. No
change to authorization: the extend runs post-verify, post-arm-gate; a failed extend
fails closed (override aborted). Attack surface: one added firmware call
(`HashLogExtendEvent`) on the already-privileged override path; no new external input is
trusted (the measured CA comes from the compiled-in trust store, not the image). Widens
R-014's residual from "PCR-7 recovery on PBA/override change" to include "…on adopting this
measurement" — a one-time reseal, already the managed case.

## Compliance Impact
Supports CRA "secure by default / integrity" and attestation evidence: the boot's full
authorization chain becomes measurable. Update risk-assessment R-014, the threat model
(TB2/measured-boot), and the CRA matrix; add the reseal+multi-reboot evidence run.

## Test Impact
- `internal/tcgmeasure`: host tests asserting the exact `UEFI_VARIABLE_DATA` /
  `EV_EFI_VARIABLE_AUTHORITY` byte layout (name, lengths, GUIDs, CA DER) and a golden digest.
- go-boot `uefi.TCG2`: build + a smoke test of the event-header packing.
- Negative: with `require_tpm: true`, a `HashLogExtendEvent`/absent-TCG2 error → override aborts
  (fail closed); with `require_tpm: false`, it logs and proceeds unattested.
- Empirical: rebuild the override PBA, reseal BitLocker on a steady-state boot, then **N
  consecutive reboots** must all auto-unlock to the Windows logon (no recovery); fresh TPM →
  recovery.

## Rollback Plan
The measurement is compile-gated. To revert, drop the `tcgmeasure` call from
`verifyAndLoadOverride` (or the whole `-tags trustbroker` build); PCR 7 returns to its prior
value and any BitLocker volume sealed against the measured PCR 7 takes one reseal (or its
recovery key) to return to the unmeasured baseline. No on-disk format change.
