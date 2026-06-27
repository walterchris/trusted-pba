# ADR-0011: Pluggable SED unlock credential sources

## Status
Proposed — pending the §5.3/§23 human gate (security-critical behavior change).
Supersedes the "MVP PIN source" portion of [ADR-0009](ADR-0009-boot-path-sed-unlock.md);
ADR-0009's policy gate (`sed_unlock` required/none, fail-closed flow) stands
unchanged.

## Context
ADR-0009 wired the SED unlock into the boot path but hard-wired the credential
to a single source: the Admin1 PIN compiled into the policy JSON (`sed_pin`),
sent to `opal.Client.Unlock` as **raw bytes** (no derivation). ADR-0009 marked
this explicitly MVP/test-only — extractable from the image, with unscrubable
transient copies — and named "real authentication (console prompt / TPM /
challenge-response)" as the production replacement.

Real deployments need more than one answer, and they are not
interchangeable in strength:
- **Hardcoded PIN** — zero protection of the secret; only acceptable for
  bring-up/debug.
- **Keyfile** — a key read from a partition/ESP; operational simplicity.
- **Console PIN entry** — interactive user secret; no secret stored at rest.
- **TPM NVRAM, read-once** — secret released once per power cycle (the
  customer lumentum-pba model: owner-auth NV + `ReadSTClear`).
- **TPM PCR-sealed** — secret only unseals when measured-boot PCRs match,
  directly defending the evil-maid attacker (threat model §6.2): a tampered
  PBA/firmware cannot obtain the unlock secret.

Our layering already supports this cleanly: `opal.Client.Unlock(authority, pin)`
only consumes raw PIN bytes — it is indifferent to where they came from. So the
change is **additive**: a credential-source abstraction in front of the existing
unlock, not a rewrite of the Opal or transport layers.

The dominant constraint is the runtime: we are bare-metal UEFI on TamaGo and
have **no TPM stack today** (unlike lumentum-pba, which runs on Linux with
`go-tpm` + `/dev/tpmrm0`). A TamaGo TPM transport (TPM CRB/TIS MMIO, or command
submission via `EFI_TCG2_PROTOCOL`) is a prerequisite building block for the two
TPM-backed sources and is the main cost driver.

## Decision
1. **A credential-source abstraction**, consumed by `cmd/pba/sedunlock.go`, with
   the Opal and transport layers untouched (CLAUDE.md layering: credential
   sourcing must not mix into Opal protocol code). Sketch:
   ```go
   // internal/credential
   type Source interface {
       // Resolve returns the raw Admin1 PIN bytes or fails closed. The caller
       // consumes and zeroizes the result; a Source performs no fallback.
       Resolve(ctx Context) ([]byte, error)
   }
   ```
2. **Policy selects the source and its config**, replacing the bare `sed_pin`
   field. `sed_unlock` (required/none) from ADR-0009 is unchanged; required now
   carries a credential block, e.g.:
   ```json
   "sed_unlock": "required",
   "sed_credential": { "source": "tpm-pcr-sealed", "tpm_handle": "0x...", "derive": "sedutil-pbkdf2" }
   ```
3. **An optional derivation stage, orthogonal to the source.** Today the PIN is
   sent raw; several sources yield a *seed* that must be turned into the drive
   credential. `derive` ∈ {`raw` (default, current behavior), `sedutil-pbkdf2`
   (`PBKDF2-HMAC-SHA1(seed, salt = drive serial padded to 20, 75000, 32B)` —
   interoperable with sedutil/lumentum-provisioned drives)}. Any source composes
   with either convention.
4. **Initial source menu**, sequenced by TamaGo feasibility:
   | Source | Effort | Prereq |
   |---|---|---|
   | `policy-pin` (debug only) | done | — |
   | `keyfile` | low | ESP/FS access (already present) |
   | `console` | moderate | UEFI `SimpleTextInput` |
   | `tpm-nvram` (read-once) | high | TamaGo TPM transport |
   | `tpm-pcr-sealed` | highest | TPM transport + policy sessions / `TPM2_Unseal` |
   Implement easy→hard: `keyfile` + `console` unblock real-world use without the
   TPM stack; `tpm-nvram` and `tpm-pcr-sealed` follow the TPM transport
   building block (its own ADR/epic).
5. **Non-negotiable invariants for every source:**
   - **Fail closed.** Any failure to resolve — TPM absent, PCR mismatch, keyfile
     missing, wrong/empty PIN — aborts to the policy `on_error` action; never
     proceeds to chainload, never retries into boot (ADR-0009 contract).
   - **No silent downgrade.** A policy selects exactly **one** source. We do not
     ship a fallback chain where a weaker source can rescue a failed stronger one
     (e.g. PCR-sealed → hardcoded would be a self-inflicted bypass). If a future
     ADR ever introduces ordered sources, it must carry an explicit, audited
     "never downgrade strength" rule and its own human gate.
   - **Debug source is release-gated.** `policy-pin` must be impossible to ship:
     gated behind a build tag (as `sedtest` already is) and rejected by
     `check-release-policy` in release builds.
   - **Secret hygiene unchanged.** The resolved PIN is consumed and zeroized
     exactly once (ADR-0009); `console` additionally inherits the #51
     input-buffer scrub obligation.

## Alternatives Considered
- **Keep the single compiled-in PIN.** Cannot reach production (ADR-0009 already
  says so); offers no measured-boot protection. Rejected.
- **Select the source by build tag only (no policy field).** Forces a separate
  binary per deployment and hides the security-relevant choice from the policy
  that is otherwise the single source of boot-trust truth. Rejected in favor of
  a policy field (with the debug source still tag-gated).
- **Default-on fallback chain (try TPM, else keyfile, else prompt).** Convenient
  but is a silent secure-to-insecure downgrade — forbidden by the same rule that
  killed implicit unlock in ADR-0009. Rejected as a default.
- **Adopt lumentum's model wholesale (TPM NVRAM only).** A good baseline but
  single-source and Linux-shaped; does not cover PCR-sealing (evil-maid) or
  no-TPM deployments. Taken as one menu entry, not the whole answer.

## Security Impact
Turns the credential source into an explicit, policy-stated security decision
with per-source residual risk rather than a single hardcoded secret:
- **R-002** (SED unlock secret handling): `tpm-pcr-sealed` materially lowers
  residual by binding secret release to measured boot — it is the first source
  that defends the **evil-maid attacker** (§6.2), since a tampered PBA cannot
  unseal. `tpm-nvram` (read-once) is intermediate; `keyfile`/`policy-pin` leave
  the secret extractable and stay debug/low-assurance.
- Fail-closed and never-silently-downgrade are preserved structurally (single
  source per policy; no rescue fallback).
- The debug `policy-pin` source carries ADR-0009's residual unchanged and is
  release-gated so it cannot reach a shipped image.
- New attack surface: the TPM transport and (for PCR) the policy-session/PCR
  selection. To be threat-modeled when that building block is specified.

## Compliance Impact
Supersedes ADR-0009's "MVP PIN source" note; ADR-0009 otherwise stands. On
adoption, the compliance stage updates: risk assessment R-002 (per-source
residuals + evil-maid coverage for PCR-sealed), threat model §6.2 (evil-maid
mitigation status) and the A1 row, and the CRA essential-requirements matrix
(secure-by-default / authentication rows). Each source's landing PR carries its
own evidence record. No release/signing behavior changes from this ADR itself;
the `check-release-policy` gate gains a rule forbidding `policy-pin` in release
builds.

## Test Impact
- **Per-source unit tests** behind the `Source` interface: happy path + every
  fail-closed branch (absent/expired secret, PCR mismatch, missing keyfile,
  wrong PIN), all asserting abort-to-on_error and never-chainload.
- **Derivation tests**: `raw` vs `sedutil-pbkdf2` vectors (cross-checked against
  a sedutil-provisioned drive's expected credential).
- **Release-gate test**: a release build with `source: policy-pin` must fail
  `check-release-policy`.
- **Virtual**: `keyfile` and `console` are testable in the QEMU/MockOpalDxe
  matrix (extend the Phase 6 unlock→MBRDone→chainload flow). `tpm-*` need either
  a virtual TPM (swtpm) in QEMU or land as hardware-only (FirmwareCI, #24) with a
  documented mock equivalent per CLAUDE.md.
- **Negative security cases** for each source are mandatory (CLAUDE.md).

## Rollback Plan
The abstraction is additive. To reverse: collapse `Source` back to the single
`policy-pin` reader and restore the `sed_pin` policy field; `internal/opal` and
`internal/transport` are untouched throughout. Individual sources can also be
withdrawn independently by removing their `Source` implementation and the
policy-schema value, with no effect on the others or on the ADR-0009 gate.
