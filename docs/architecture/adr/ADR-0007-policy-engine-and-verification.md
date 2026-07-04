# ADR-0007: PBA policy engine and second-stage verification model

## Status
Accepted — §5.3/§23 human gate satisfied by the Release Owner merging PR #43 (policy engine + this ADR). The verifier (#41) and chainloader wiring (#42) implement it.

## Context
Phase 1 chainloads a target without PBA-side validation (ADR-0006); Phase 2 detects
Secure Boot but does not enforce it. Phase 3 (#19) adds a PBA-controlled trust
policy: which target boots, how it is validated, and whether Secure Boot is
required. The product goal is for the PBA to be a *second-stage trust broker* — it
must be able to validate a second-stage EFI image (e.g. Windows Boot Manager) **on
its own**, the way firmware does, using real Secure Boot materials.

## Decision

### 1. Policy
A compiled-in policy, embedded as JSON via `go:embed`, parsed **fail-closed** (any
parse/validation error → refuse to boot). Shape:
```jsonc
{
  "require_secure_boot": false,
  "entries": [ { "name": "...", "path": "EFI/...", "validation": "firmware|pba" } ]
}
```
- `validation: firmware` — the PBA calls `LoadImage`/`StartImage`; **firmware**
  Secure Boot validates (the Windows path). Phase 1 behavior.
- `validation: pba` — the PBA validates the image itself (§3) before loading.
External/signed policy files are out of scope (deferred).

### 2. Secure Boot enforcement
`require_secure_boot: true` ⇒ if the firmware is not *enforcing*
(`SecureBoot==1 && SetupMode==0`, via `internal/secureboot`) — or detection fails —
the PBA **fails closed** and refuses to boot. This realizes the enforcement deferred
in Phase 2 and honors CLAUDE.md ("never treat Secure Boot disabled and enabled as
equivalent").

### 3. PBA-side verification (the `pba` path)
Replicate firmware UEFI image authentication in Go/TamaGo:
1. Compute the **Authenticode PE hash** (`github.com/foxboron/go-uefi/authenticode`,
   excludes CheckSum + cert table).
2. Parse the **PKCS#7 SignedData**; confirm it binds that hash; extract signer +
   intermediate certs.
3. **Chain** the signer to an embedded **`db`** CA pool with stdlib `crypto/x509`
   (`ExtKeyUsageCodeSigning`) — the fail-closed core we own.
4. **`dbx` revocation** (takes precedence over `db`): reject if the image's SHA-256
   is a `dbx` `EFI_CERT_SHA256` entry, or the signer matches a `dbx`
   `EFI_CERT_X509` entry.

**Trust anchors** are vendored from `github.com/microsoft/secureboot_objects`
(pinned commit + per-blob SHA-256 recorded in `internal/truststore/materials/PROVENANCE.md`)
and `go:embed`ed. The embedded set is **configurable at build time**. The **default
is Windows-only** (Microsoft Windows Production PCA 2011 + Windows UEFI CA 2023), so
only Windows Boot Manager validates via the `pba` path — the tightest default trust
surface. Building with `-tags trustfull` adds the third-party Microsoft (Corporation)
UEFI CA 2011/2023 for shim/GRUB/Linux. Both 2011 and 2023 generations are embedded
for forward-compat. The amd64 `dbx` update is embedded as Microsoft's exact signed
artifact; `truststore` strips its `EFI_VARIABLE_AUTHENTICATION_2` header and parses
the revoked image hashes (it trusts the pinned, hash-recorded blob rather than
re-verifying the update's PKCS#7).

**Time policy — signing-cert validity is NOT enforced (matches firmware).** Like
UEFI Secure Boot, image acceptance is **time-independent**: the trust decision is
the signer chaining to `db` plus the absence of any chain certificate (or the image
hash) from `dbx`. Signing-certificate **validity periods are deliberately ignored**
(`imageverify.ignoreValidity`). This is required for real-world booting: Microsoft's
image-signing **leaves are short-lived (~1 year) and routinely expired** (e.g. shim
15.8's leaf expired 2024-10; the Microsoft Corporation UEFI CA 2011 itself expires
2026-06-27), yet the signed images must keep booting, and pre-boot firmware has no
reliable clock. Enforcing current-time validity rejected every genuine Windows/shim
image (surfaced while validating a real Microsoft-signed shim). The control for a
compromised-but-expired key is **`dbx` revocation**, not expiry — exactly as
firmware does. **Open research (#48):** optionally validate an Authenticode
**timestamp countersignature** (cert valid *at signing time*) when present. This
supersedes the earlier RTC-clamped-to-build-floor design (the `internal/boottime`
package and `imageverify`'s `Now`/`ErrNoTime` were removed accordingly).
(Documented here because it is a security-behavior choice.)

### Scope boundary
Under *enforcing* Secure Boot the firmware already validates images, so the `pba`
path is an **additional** gate (it can reject more, not make firmware accept more).
Loading a PBA-only-trusted image that firmware would reject requires the shim-like
LoadImage wrapper — that is **Phase 7**, not Phase 3.

## Alternatives Considered
- **Hash allowlist only** (no signature verification) — simpler, but cannot validate
  Windows/shim "the way firmware does"; rejected as the primary mechanism (may still
  exist as a policy option).
- **Authenticode via a manual PKCS#7/PE implementation** — rejected; reuse the
  audited pure-Go `go-uefi` (compile under TamaGo already proven) + stdlib `x509`.
- **Trust the firmware only (no PBA verification)** — defeats the product's
  second-stage-trust-broker purpose.

## Security Impact
Adds the PBA's own trust decision over second-stage images and the Secure Boot
enforcement gate. Risks: correctness of Authenticode hashing/`dbx` (mitigated by
differential tests vs `sbverify`/relic and required negative tests — tampered image,
untrusted chain, `dbx` hash hit); trust-anchor **staleness** (2011 vs 2023 CAs, and
`dbx` updates) — embedded materials are pinned and refreshed via an ADR-gated
process; and **ignoring signing-cert expiry** (matches firmware; the control is
`dbx` revocation, not validity — see Time policy and research #48). The threat model
(#4) and risk assessment (#5) must capture the second-stage-verification asset and
these risks.

## Compliance Impact
§5.3 human gate (boot-chain validation) + §23 ADR satisfied by approving this.
Advances CRA "integrity" (PBA verifies target images) and "secure by default".
New deps (`go-uefi`, vendored Microsoft materials) onboarded under §14 (#27); MS
materials are public (no secrets); no private keys committed.

## Test Impact
Host unit + **fuzz** for policy parse (fail-closed) and verifier, using a
**self-signed test CA** (CI-deterministic): accept; expired-signer-accepted (firmware
semantics); negatives that must fail closed (tampered hash, untrusted chain, `dbx`
hash hit, non-code-signing EKU, revoked intermediate). QEMU `pba-matrix`: pba-accept
(test-CA-signed fixture) / pba-reject (unsigned) → fail closed (firmware-defer +
policy-error covered by existing matrices). **Real-image test** (`real-image-verify`
CI job): a genuine Microsoft-signed **shim** (Ubuntu `shim-signed`, not committed) is
accepted by the full trust set and rejected by the windows-only default — proving the
embedded CAs validate a real third-party image and the trust-set boundary holds.

**Coverage gap — real Windows boot:** the constraint is redistribution, not use.
We cannot *commit* `bootmgfw.efi` (proprietary), but a Windows **Evaluation** image
is freely downloadable, so a real Microsoft-signed loader can be fetched at CI time
and staged (see the QEMU **Windows-handoff (A′)** scenario, which does exactly this
with a real Microsoft-signed loader against the full trust set + MS CA in `db`). Two
things remain genuinely out of automated scope: (1) booting *all the way into
Windows* needs a full licensed disk + BCD — heavy, and deferred to hardware/manual;
(2) a *faithful SED reveal* (locked disk hides the real ESP; MBRDone reveals it)
needs the deferred QEMU virtual-SED device model (`test-tooling-plan.md §3.7`), since
the current EDK2 mock is a protocol mock that does not gate a real backing disk.
Separately, having the PBA *itself* authorize Windows Boot Manager (a SHIM-style
Security-protocol override, rather than firmware `db`) is **not** a substitute — it
diverges PCR 7 and breaks BitLocker's default seal; see ADR-0011.

## Rollback Plan
Revert the policy wiring in `cmd/pba/main.go`; the PBA falls back to the Phase 1/2
chainload. `internal/policy` and `internal/imageverify` are additive packages.
