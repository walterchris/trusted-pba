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

**Time policy:** chain validity is checked against the platform **RTC** (read via
go-boot's `x64.RTC`), **clamped to a compiled-in build-time floor** (`internal/boottime`):
a failed read or a reading earlier than the floor (an unset/garbage pre-boot clock)
falls back to the floor, so validity is never checked against an attacker-influenced
earlier time. A zero/unset time fails closed in `imageverify` (`ErrNoTime`).
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
process; pre-boot time trust (RTC vs floor). The threat model (#4) and risk
assessment (#5) must capture the second-stage-verification asset and these risks.

## Compliance Impact
§5.3 human gate (boot-chain validation) + §23 ADR satisfied by approving this.
Advances CRA "integrity" (PBA verifies target images) and "secure by default".
New deps (`go-uefi`, vendored Microsoft materials) onboarded under §14 (#27); MS
materials are public (no secrets); no private keys committed.

## Test Impact
Host unit + **fuzz** for policy parse (fail-closed) and verifier, using a
**self-signed test CA** (CI-deterministic): accept; negatives that must fail closed
(tampered hash, untrusted chain, `dbx` hash hit); plus an *optional* real
`bootmgfw.efi` check (not committed). QEMU matrix: pba-accept / pba-reject / revoked
/ firmware-defer / policy-error → fail closed.

## Rollback Plan
Revert the policy wiring in `cmd/pba/main.go`; the PBA falls back to the Phase 1/2
chainload. `internal/policy` and `internal/imageverify` are additive packages.
