# Trusted PBA — Threat Model

Per the [compliance baseline §10](../compliance-and-secure-development-baseline.md).
This is a **living document**: every security-relevant change must update it or
explicitly confirm "no change" (baseline §10, §23).

- **Status:** covers the product through **Phase 3** (boot manager, Secure Boot
  detection + enforcement, PBA policy engine, second-stage image verification).
  Opal/SED unlock (Phases 4–6), the shim-like loader wrapper (Phase 7), real
  hardware (Phase 8), and the update/release-signing pipeline are **planned**;
  their assets and adversaries are modelled here with mitigations marked
  *planned/deferred* so the gaps are explicit.
- **Companion:** quantified risks live in
  [`risk-assessment.md`](../compliance/risk-assessment.md) (R-001..R-013); this
  document references those IDs rather than duplicating the scoring.
- **Owner:** Security Owner (review/approval gate per baseline §5.3).
- **Review cadence (baseline §9):** before MVP, before first hardware test, before
  first customer delivery, before every release, after every critical
  vulnerability, and after every architecture change.

## 1. Methodology

Asset-centric model with a STRIDE lens, per-adversary abuse cases, and attack
trees for the two highest-value goals (boot an untrusted image; obtain the SED
unlock secret). Each adversary maps to the quantified risks (R-0xx) and the
automated tests that exercise the mitigation. The guiding invariant is the
baseline's **fail-closed** rule: any failure of authentication, unlock, policy, or
verification must stop the boot — never silently continue.

## 2. Assets

The ten core assets from baseline §10, with current location/status:

| # | Asset | Where / status |
|---|---|---|
| A1 | **SED unlock secret** (Opal password/PIN, derived key material) | Handled in-memory by `internal/opal` (Phase 4 library); **not yet wired into the boot path**. Never logged; all client-side PIN-bearing buffers zeroized on success and all failure paths (#51 item 1). |
| A2 | **PBA binary** (`trusted-pba.efi`) | Built from `cmd/pba`; integrity is firmware Secure Boot's job (we are the signed image). |
| A3 | **PBA policy** | `internal/policy`, compiled-in via `go:embed`, parsed fail-closed. |
| A4 | **Customer trust anchors** | Planned (external/provisioned anchors deferred; ADR-0007 scope boundary). |
| A5 | **Secure Boot trust chain** (db/dbx) | Embedded Microsoft materials in `internal/truststore` (pinned, SHA-256-recorded). |
| A6 | **Windows Boot Manager handoff** | `cmd/pba` chainload (`firmware`/`pba` validation modes). |
| A7 | **Opal session state** | Modeled in `internal/opal` (Phase 4; byte-faithful sessions, in-memory IDs); PIN-bearing frames zeroized after the exchange (#51 item 1). Real transport Phase 5. |
| A8 | **Update signing key** | Planned (release/update pipeline not yet built; ADR-0003 defers signing). |
| A9 | **Release signing key** | Planned (no production signing yet; test keys only, ephemeral, never committed). |
| A10 | **SBOM / provenance data** | CI skeleton (#9); trust-material provenance recorded in `internal/truststore/materials/PROVENANCE.md`. |

## 3. Trust boundaries

- **TB1 Firmware → PBA.** UEFI firmware validates and launches `trusted-pba.efi`
  (Secure Boot). The PBA trusts the firmware-provided System Table, boot services,
  and the `SecureBoot`/`SetupMode` variables it reads (`internal/secureboot`).
- **TB2 PBA → ESP / second-stage image.** The PBA reads the target image from the
  EFI System Partition (attacker-writable storage) and must validate it before
  transferring control (`internal/imageverify` for `pba` mode; firmware revalidates
  for `firmware` mode).
- **TB3 PBA → SED (Opal transport).** Planned. The Opal layer talks to the drive
  through the abstract `TCGTransport` interface; the drive is untrusted until a
  session authenticates.
- **TB4 Build/release → artifact.** The embedded policy and trust materials cross
  from the build into the signed binary; their integrity rests on pinning +
  recorded hashes + the (planned) release-signing gate.
- **TB5 Developer / AI agent / CI → repository.** Code, tests, and evidence enter
  via PRs under role-separated review (baseline §5, §8); `main` is protected.

## 4. Entry points / attack surface

- The PE/COFF + Authenticode parser fed by an attacker-controlled ESP image
  (`internal/imageverify`, via `go-uefi`) — **fuzz-relevant**.
- The embedded policy JSON parser (`internal/policy`, fail-closed,
  `DisallowUnknownFields`) — **fuzzed** (`FuzzParse`).
- The dbx `EFI_VARIABLE_AUTHENTICATION_2` / `EFI_SIGNATURE_LIST` parser
  (`internal/truststore.stripAuth2`/`parseDBX`).
- UEFI variable reads (`SecureBoot`, `SetupMode`) and boot-service calls
  (`LoadImage`/`StartImage`/`GetTime`/`ResetSystem`).
- Planned: TCG Opal response parsing (Phase 4) — **fuzz-relevant**.

## 5. Assumptions

1. Firmware Secure Boot is trustworthy when *enforcing*; the PBA does not attempt
   to detect a maliciously-modified firmware (out of scope — root of trust).
2. The PBA binary, once signed and enrolled, is integrity-protected by firmware
   Secure Boot.
3. Pre-boot execution is **single-threaded**; no concurrent process mutates the ESP
   or SED between a check and its use (basis for the TOCTOU reasoning, R-012).
4. The pre-boot clock (RTC) is **not** trustworthy and is not relied on for trust
   decisions (ADR-0007; see §6 *malicious-update*/*rollback*).
5. Embedded Microsoft trust materials are authentic at build time (pinned commit +
   recorded SHA-256); a compromised build host is covered by TB4/R-006.

## 6. Adversaries (baseline §10 required set)

Each entry: capability → goals → abuse cases → mitigations (with status) →
residual risk → tests → risk IDs.

### 6.1 Pre-boot attacker (local, runs before/instead of the OS)
- **Capability:** can place EFI binaries on the ESP, alter boot order, supply a
  malicious second-stage target.
- **Abuse cases:** stage an unsigned/tampered loader and have the PBA chainload it;
  point policy at an attacker image.
- **Mitigations:** `pba` mode validates the target's Authenticode signature against
  the embedded `db` and rejects `dbx` hits before `LoadImage`
  (`internal/imageverify`); `firmware` mode defers to firmware Secure Boot; the
  policy is compiled-in (not ESP-resident); **fail closed** on any error;
  `halt()` dead-stops and never returns control to the firmware boot order.
- **Residual risk:** a TOCTOU re-read window under Secure-Boot-off (R-012,
  follow-up #46); accepting an image whose short-lived signing leaf expired is
  *intentional* (matches firmware — R-013/#48).
- **Tests:** `TestVerifyFailsClosed/*`, `pba-matrix` (accept/reject),
  `run-negative` (no target → fail closed). → **R-001**.

### 6.2 Evil-maid attacker (transient physical access)
- **Capability:** boots their own media, swaps the ESP, attempts to observe unlock.
- **Abuse cases:** replace the PBA or target; capture the unlock secret; downgrade
  to an insecure boot.
- **Mitigations:** Secure Boot enforcement gate (`require_secure_boot` ⇒ refuse to
  boot unless `SecureBoot==1 && SetupMode==0`); never treat SB-off == SB-on; SED
  remains locked until authentication (planned Phase 4–6); no unlock material in
  logs (opal-layer silence enforced at the file-descriptor level,
  `TestUnlockEmitsNoConsoleOutput`); client-side PIN buffers zeroized on all paths
  (#51 item 1).
- **Residual risk:** with Secure Boot off and no policy requiring it, firmware does
  not validate — the PBA's own `pba`-mode check is the only gate; physical DMA /
  cold-boot capture of unlock material is out of scope for the pre-boot product.
- **Tests:** `sb-require-test` (SB off → fail closed), `TestCheckSecureBoot`,
  `sb-matrix`. → **R-002, R-003**.

### 6.3 Malicious EFI application (the chainload target)
- **Capability:** a syntactically-valid PE that is unsigned, tampered, or signed by
  an untrusted/ revoked key.
- **Mitigations:** Authenticode hash + signature binding; chain to `db` with
  `ExtKeyUsageCodeSigning`; `dbx`-by-hash (precedence) and `dbx`-by-cert across the
  whole chain; parser failures fail closed (`ErrParse`).
- **Residual risk:** parser bugs in `go-uefi` (mitigated by fuzzing + pinned dep).
- **Tests:** `TestVerifyFailsClosed/{tampered,untrusted root,unsigned,revoked by
  image hash,revoked by signer cert,non-code-signing EKU,revoked intermediate}`,
  `TestStripAuth2Rejects`. → **R-001, R-009**.

### 6.4 Malicious update
- **Capability:** offers a crafted PBA/policy/trust-material update.
- **Mitigations (planned):** signed updates + version floor (anti-rollback) are
  **not yet built**; today there is no in-field update path (compiled-in policy +
  materials, delivered as a signed image). Trust-material refresh is **ADR-gated**
  (pinned commit + recorded SHA-256).
- **Residual risk:** **high until the update pipeline exists** — tracked as R-006.
- **Tests:** none yet (pipeline pending). → **R-006**.

### 6.5 Rollback attacker
- **Capability:** re-deploys an older, vulnerable PBA or trust set (e.g. stale
  `dbx`).
- **Mitigations (planned):** version floor / anti-rollback policy is **not yet
  built**; `dbx` staleness is bounded by the ADR-gated refresh process.
- **Residual risk:** high until anti-rollback exists — R-005; trust-anchor
  staleness R-011.
- **Tests:** none yet. → **R-005, R-011**.

### 6.6 Compromised dependency
- **Capability:** a malicious/buggy `go-boot`, `go-uefi`, `tamago`, or vendored
  Microsoft material.
- **Mitigations:** pinned module versions; vendored materials byte-identical to
  upstream with recorded SHA-256 + commit (`PROVENANCE.md`); the **`walterchris/go-boot`
  fork** (ADR-0008) is a first-party-maintained dependency, pinned by tag
  (`v1.6.2-tpba.1`) + `go.sum` hash, with a minimal additive patch over upstream
  v1.6.2 (small, reviewable diff); dependency onboarding/scan **planned** (#27);
  SBOM/vuln-scan CI **skeleton** (#9).
- **Residual risk:** medium until #27/#9 land vuln + license scanning (must cover the
  fork).
- **Tests:** `TestRealMicrosoftSignedImage` (materials validate a real signed
  image), `TestLoad` (materials parse). → **R-006**.

### 6.7 Compromised AI agent output
- **Capability:** an agent introduces a subtle fail-open or weakens a test.
- **Mitigations:** role separation (no agent implements + approves + releases the
  same change; baseline §5, §8); independent adversarial security review;
  `go-reviewer`; never weaken/delete tests to pass CI; human approval gate.
- **Residual risk:** low-medium; depends on reviewer diligence.
- **Tests:** the full negative-test suite is the regression guard. → cross-cutting.

### 6.8 Compromised CI runner
- **Capability:** tampers with build artifacts or injects secrets.
- **Mitigations (partial):** `main` protected, PR-only, signed commits (DCO); no
  production keys in CI (test keys are ephemeral, generated per-run, never
  committed); reproducible/trimmed builds. SLSA provenance + artifact signing
  **planned** (#9, #10).
- **Residual risk:** medium until provenance/signing land. → **R-006**.

### 6.9 Compromised signing key
- **Capability:** signs malicious PBA/updates with a leaked release/update key.
- **Mitigations (planned):** key management, HSM/custody, and revocation are **not
  yet built** (no production signing exists; ADR-0003 defers it). For *image*
  verification, a compromised-but-expired signing key is handled by **`dbx`
  revocation, not expiry** (ADR-0007).
- **Residual risk:** high until key management exists — R-006; the ignore-expiry
  decision's residual risk is R-013/#48.
- **Tests:** `dbx`-by-cert / `dbx`-by-hash negatives. → **R-006, R-013**.

### 6.10 Real-drive compatibility failure
- **Capability:** not an adversary — a real SED behaves differently from the mock,
  causing an unsafe state (e.g. unlock "succeeds" but MBRDone lags → R-008).
- **Mitigations:** virtual-first test strategy (ADR-0005); the Opal logic is
  **byte-faithful** so the streams it emits match real drives (ADR-0004); the Go
  simulator and the EDK2 mock (Phase 6) share byte-exact golden fixtures
  (`test/fixtures/opal/`); every hardware-only behavior needs a documented mock
  equivalent; hardware bring-up gated (Phase 8).
- **Residual risk:** medium until hardware validation — R-007, R-008, R-010.
- **Tests:** Opal unit + negative matrix + `FuzzResponseParse` (host); QEMU matrices;
  hardware matrix planned. → **R-007, R-008, R-009, R-010**.

## 7. Attack trees (key goals)

```
GOAL A: Boot an attacker-controlled image
├─ A.1 Get firmware to launch a malicious PBA
│   └─ requires SB off OR a valid signature      [mit: SB enforcement gate; root of trust]
├─ A.2 Get the PBA to chainload a malicious target
│   ├─ firmware mode → firmware revalidates       [mit: deferred to SB; ADR-0006]
│   └─ pba mode
│       ├─ unsigned/tampered → ErrNoSignature/hash mismatch   [mit: imageverify]
│       ├─ untrusted signer  → ErrUntrusted (no db chain)     [mit: db chain + EKU]
│       └─ revoked signer/hash → ErrRevoked*                  [mit: dbx precedence]
└─ A.3 Swap the target after verification (TOCTOU)            [residual: R-012/#46]

GOAL B: Obtain the SED unlock secret    [Phase 4 unlock LIBRARY done; boot wiring Phase 5/6]
├─ B.1 Read it from logs            [mit: never log secrets — opal-layer silence + PIN-free
│                                         errors, fd-level: TestUnlockEmitsNoConsoleOutput]
├─ B.2 Capture Opal session state   [mit: in-memory session IDs; PIN buffers/frames zeroized
│                                         on all paths: TestUnlockZeroizesSecrets,
│                                         TestStartSessionGrowBudget; residual: firmware/DMA
│                                         copies (§6.2); PIN-input buffer → #51 item 2]
└─ B.3 Unlock before auth succeeds  [mit: fail closed — Set requires an auth'd session;
                                          wrong PIN/timeout/malformed keep drive Locked]
```

## 8. Residual-risk summary

| ID | Residual risk | Status |
|---|---|---|
| R-005 | Rollback to vulnerable PBA / stale dbx | Open — anti-rollback not built |
| R-006 | Malicious update / compromised supply chain | Open — update pipeline + signing not built |
| R-011 | Trust-anchor staleness (2011 CAs expire 2026-06-27) | Open — ADR-gated refresh; 2023 CAs embedded |
| R-012 | SB-off TOCTOU re-read window | Open — follow-up #46 |
| R-013 | Ignore signing-cert expiry (firmware semantics) | Accepted — control is dbx; research #48 |

## 9. Test mapping

| Mitigation | Tests / CI |
|---|---|
| Reject untrusted/tampered/revoked image | `internal/imageverify` `TestVerifyFailsClosed/*`; `pba-matrix` |
| Accept genuine signed image (incl. expired leaf) | `TestVerifyAccepts`, `TestVerifyAcceptsExpiredSigner`; `TestRealMicrosoftSignedImage` (CI-only, needs `TPBA_REAL_SHIM`) |
| Trust-set boundary (windows-only vs full) | `TestRealMicrosoftSignedImage` (CI-only, `real-image-verify` job; skips without `TPBA_REAL_SHIM`) |
| Policy parsed fail-closed | `internal/policy` `TestParseFailsClosed`, `FuzzParse` |
| Secure Boot detection + enforcement | `internal/secureboot` `TestEnforcing`; `internal/policy` `TestCheckSecureBoot`; `sb-matrix`; `sb-require-test` |
| dbx update parsing bounds | `TestStripAuth2Rejects`, `TestLoad` |
| Chainload + fail-closed on no target | `run`, `run-negative` (QEMU) |
| Opal unlock fails closed (auth/status/transport) | `internal/opal` `TestUnlockHappyPath`, `TestUnlockFailsClosed/*` |
| Opal response parsers never panic on bad input | `FuzzResponseParse`; `TestTokenizeFailsClosed`, `TestDecodePacketFailsClosed`, `TestParseDiscoveryFailsClosed` |
| Unlock secret never logged, buffers zeroized | `internal/opal` `TestUnlockEmitsNoConsoleOutput` (fd-level), `TestUnlockZeroizesSecrets`, `TestTransactZeroizesMethodPayload`, `TestStartSessionGrowBudget`, `TestBuilderGrowPreventsReallocation` |

## 10. Change log

| Date | Change |
|---|---|
| 2026-06-08 | Initial threat model through Phase 3 (#4). Captures second-stage verification, Secure Boot enforcement, embedded trust anchors, the ignore-expiry decision (ADR-0007), and the SB-off TOCTOU (#46). |
| 2026-06-08 | Phase 4: Opal unlock **library** + native simulator (ADR-0004, byte-faithful TCG). A1/A7 move from *planned* to *in-library, not yet wired*; Opal response parsers fuzzed + fail closed (R-009); unlock flow fails closed (R-002). Boot-path wiring + hardware remain Phase 5/6/8. |
| 2026-06-08 | Phase 5: UEFI Storage Security transport (`internal/transport`) over the **`walterchris/go-boot` fork** (ADR-0008, adds `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL`). Compromised-dependency mitigations (§6.6) updated to cover the pinned first-party fork. Real SendData/ReceiveData path validated in Phase 6/8 (no host test possible). |
| 2026-06-10 | #51 item 1 (Phase 5/6 gate): PIN-buffer zeroization in `internal/opal` — caller pin, method payload, and transmitted ComPacket frames cleared on success and all failure paths; tested grow budget prevents append reallocation; fd-level log-scrub test asserts opal-layer silence + PIN-free error text (mutation-verified). A1/A7, §6.2, and attack tree B.1/B.2 updated; R-003 residual Medium → Low. Boot-path PIN-*input* zeroization remains open for the Phase 6 wiring (#51 item 2). |
