# ADR-0011: Pluggable SED unlock credential sources

## Status
Accepted (2026-07-06) — the §5.3/§23 human gate (security-critical behavior change) was
satisfied by the Security/Release Owner merging the A2 PR (**#99**) after two independent
reviews (go-reviewer + security-review-agent, both APPROVE), recorded in
`evidence/security-review-records/2026-07-06-console-credential-99.md`. Landed in stages:
**A1** (#98) the `credential.Source` abstraction (routing the compiled-in `policy-pin`
through it); **A2** (#99) the `sed_credential` schema + the first interactive source
(`console`). Remaining Milestone-1 items: **A3** `keyfile` (#100) and the **A4**
`sedutil-pbkdf2` derive (#104). Supersedes the "MVP PIN source" portion of
[ADR-0009](ADR-0009-boot-path-sed-unlock.md); ADR-0009's policy gate (`sed_unlock`
required/none, fail-closed flow) stands unchanged.

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
  customer PBA model: owner-auth NV + `ReadSTClear`).
- **TPM PCR-sealed** — secret only unseals when measured-boot PCRs match,
  directly defending the evil-maid attacker (threat model §6.2): a tampered
  PBA/firmware cannot obtain the unlock secret.

Our layering already supports this cleanly: `opal.Client.Unlock(authority, pin)`
only consumes raw PIN bytes — it is indifferent to where they came from. So the
change is **additive**: a credential-source abstraction in front of the existing
unlock, not a rewrite of the Opal or transport layers.

The dominant constraint is the runtime: we are bare-metal UEFI on TamaGo and
have **no TPM stack today** (unlike the customer PBA, which runs on Linux with
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
       // env exposes the platform capabilities a Source may need (prompt the
       // user, talk to a token, reach the network, read the TPM) without the
       // unlock path knowing how — so interactive and round-trip (challenge-
       // response) flows live entirely inside Resolve and stay host-mockable.
       Resolve(env Env) ([]byte, error)
   }

   // Env is the capability bundle; any field may be absent on a given platform:
   //   Console (text in/out) · TPM (TCG2) · USB (HID/CCID) · Net · FS/Block
   //   · DriveInfo (serial, for derivation)
   ```
   **Multi-factor is composition, not a new abstraction.** An MFA method is just
   a `Source` whose `Resolve` calls sub-`Source`s — e.g. `sealed{ blob: tpm,
   auth: console }` (a console PIN unseals a TPM blob), `challengeResponse{
   token: yubikey, challenge: console }` (the PIN is the challenge, the token's
   HMAC is the key), or `combine{ kdf, sources: [...] }` (derive the key from
   several contributions — Shamir/XOR/KDF). The interface never changes; this is
   what keeps "add authentication ways as we like" true without reopening the
   contract.
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
   (`PBKDF2-HMAC-SHA512(seed, salt = the drive's 20-byte serial, 500000, 32B)` —
   interoperable with sedutil-provisioned drives, incl. the customer fork)}. The parameters are
   parameterized because sedutil versions differ; A4a KAT-verified these values
   against the sedutil source in use (bit-identical to sedutil's `cf_pbkdf2_hmac`
   + `cf_sha512`). Any source composes with either convention.

   **Configurable derive parameters + `auto` mode (#112).** The `sedutil-pbkdf2`
   iteration count and key length are **policy-configurable** via an optional
   `derive_params` block on the credential —
   `{ "iterations": <int> | "auto", "key_len": <int> }` — so a deployment can match
   whatever sedutil provisioned its drives without rebuilding the PBA. An **absent**
   `derive_params` (or an absent field within it) uses the defaults **500000
   iterations / 32-byte key**, which is **byte-for-byte identical to the pre-#112
   behavior** (derive once, one Unlock). The hash is unchanged (SHA-512). Validation
   is fail-closed: `derive_params` is rejected on any non-`sedutil-pbkdf2` derive
   (a dead knob), an explicit `iterations` must be `1..100_000_000` (an explicit `0`
   is rejected, distinguished from an absent field), and an explicit `key_len` must
   be `1..64`; the iterations lower bound is `>0` with no higher floor (acceptable
   under the compiled-in trusted-policy model — the policy is not attacker-supplied).

   `"iterations": "auto"` tries a **fixed, best-first candidate list**
   `[500000, 75000]`: derive with each count, attempt Unlock, and advance to the next
   candidate **only** on an Opal `NOT_AUTHORIZED` result (the new `opal.ErrNotAuthorized`
   sentinel — "wrong iteration count, try the next"). It **stops immediately and fails
   closed** on `AUTHORITY_LOCKED_OUT` (`opal.ErrAuthLockedOut`) — further tries are
   futile and burn no more of the Admin1 try-limit — or on any other error (transport,
   malformed; never masked by advancing), and fails closed on list exhaustion. This is
   the **try-limit safety** rationale: best-first means the common case authenticates on
   attempt #1 and burns no extra Admin1 tries; the list is kept small and fixed because a
   large candidate list would be an unacceptable try-limit exposure for a pre-boot
   product. The consumed seed and every derived key are zeroized on all paths (F-2
   preserved: success, retry, lockout, other-error, exhaustion). The winning iteration
   count is emitted only under the compile-time `hwdbg` gate — never in normal output.

   **Operator contract.** A PBKDF2 credential is only reproducible if you know the
   iteration count the provisioning sedutil used; the PBA **cannot** read it back from
   the drive, so the operator must know (or discover via `auto`) that count. Known
   values: the **customer sedutil fork (v1.15) = 500000**; **upstream older builds
   (e.g. the lab host's 1.20.0) = 75000**. Prefer an explicit count for production
   (deterministic, single try) and reserve `auto` for lab / bring-up / recovery where
   the provisioning count is unknown. `auto` is what unblocks the A4b HW finding (a lab
   drive provisioned by sedutil 1.20.0 at 75000 → `NOT_AUTHORIZED` against the hardcoded
   500000).
4. **Source menu, grouped by factor and graded by pre-boot feasibility.** The
   hard filter is the runtime: we run pre-`ExitBootServices`, so we get whatever
   the firmware exposes as a protocol (keyboard text-input, filesystem, network,
   TPM via TCG2) cheaply, but anything needing *raw USB device protocols* (CCID,
   FIDO/CTAP) we must implement ourselves — which splits the options sharply.

   *Something you know*
   | Source | Effort | Prereq |
   |---|---|---|
   | `console` (keyboard passphrase) | low | UEFI `SimpleTextInput` (firmware drives the keyboard) |

   *Something you have*
   | Source | Effort | Prereq |
   |---|---|---|
   | `keyfile` (USB stick / GUID-tagged partition) | low | FS/Block (already present) |
   | `yubikey-typed` (static password / typed OTP) | low | none — the key acts as a USB **keyboard**, captured by `console` |
   | `yubikey-hmac` (HMAC-SHA1 challenge-response) | high | raw USB HID stack; PIN = challenge, token HMAC = key (offline, know+have) |
   | `fido2-hmac-secret` (CTAP2) | high | USB HID + CTAP stack |
   | `smartcard-piv` (CCID) | high | CCID USB stack; card decrypts a sealed key blob |

   *Platform-bound / measured*
   | Source | Effort | Prereq |
   |---|---|---|
   | `tpm-nvram` (read-once) | high | TamaGo TPM transport |
   | `tpm-pcr-sealed` | highest | TPM transport + policy sessions / `TPM2_Unseal` |

   *Network-bound (NBDE)*
   | Source | Effort | Prereq |
   |---|---|---|
   | `tang-clevis` (network-bound) | medium | UEFI network stack; key released only on a trusted network |
   | `kms-tls` (key server) | medium | network stack + TLS; optionally attestation-gated |

   *Debug only*
   | Source | Effort | Prereq |
   |---|---|---|
   | `policy-pin` (compiled-in) | done | — (release-gated, see §5) |

   Biometrics are out of scope (not viable pre-boot). MFA combinations
   (`sealed`, `challengeResponse`, `combine`) are expressed by composition (§1),
   not as new menu entries.

   **Implement easy→hard:** `console` + `keyfile` + `yubikey-typed` unblock
   real-world use today (no new building block); the rest gate on three
   building blocks, each its own ADR/spike — a **TamaGo TPM transport**
   (`tpm-*`), a **USB HID/CCID stack** (`yubikey-hmac`/`fido2`/`smartcard`), and a
   **network stack** (NBDE). Note that `yubikey-typed` is essentially the
   `console` source — the token types the secret — so YubiKey support is not one
   feature but a cheap mode and an expensive (challenge-response) mode that
   shares the USB-stack cost with smartcards and FIDO2.
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
     exactly once (ADR-0009); `console` and any other interactive/token source
     inherit the #51 input-buffer scrub obligation.
   - **Bounded interactivity.** Interactive sources cap retries (e.g. 3 attempts)
     then fail closed — never an unbounded prompt loop or brute-force oracle (the
     drive's own try-limit and the TPM dictionary-attack lockout backstop this).
   - **Recovery is not a backdoor.** Tokens get lost; any recovery/escrow path is
     itself an enrolled `Source` under all rules above, never a bypass of the gate.
   - **Each new source is a unit of review.** Adding one requires its own
     threat-model entry and negative tests — different factors carry different
     residual risk and attack surface.

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
- **Adopt the customer's model wholesale (TPM NVRAM only).** A good baseline but
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
- **Virtual**: `keyfile`, `console`, and `yubikey-typed` (a typed-keyboard
  source) are testable in the QEMU/MockOpalDxe matrix (extend the Phase 6
  unlock→MBRDone→chainload flow). `tpm-*` need a virtual TPM (swtpm) in QEMU or
  land hardware-only (FirmwareCI, #24); the USB-token sources (`yubikey-hmac`,
  `fido2`, `smartcard`) and NBDE sources (`tang-clevis`, `kms-tls`) are
  exercised against an emulated token / a test Tang/KMS endpoint, or hardware,
  each with a documented mock equivalent per CLAUDE.md.
- **Composition**: an MFA `Source` is tested as a unit (sub-sources mocked) plus
  end-to-end for at least one real combination (e.g. `sealed{tpm, console}`).
- **Negative security cases** for each source are mandatory (CLAUDE.md),
  including the bounded-retry cap and the no-silent-downgrade invariant.

## Rollback Plan
The abstraction is additive. To reverse: collapse `Source` back to the single
`policy-pin` reader and restore the `sed_pin` policy field; `internal/opal` and
`internal/transport` are untouched throughout. Individual sources can also be
withdrawn independently by removing their `Source` implementation and the
policy-schema value, with no effect on the others or on the ADR-0009 gate.
