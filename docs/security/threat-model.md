# Trusted PBA — Threat Model

Per the [compliance baseline §10](../compliance-and-secure-development-baseline.md).
This is a **living document**: every security-relevant change must update it or
explicitly confirm "no change" (baseline §10, §23).

- **Status:** covers the product through **Phase 6** (boot manager, Secure Boot
  detection + enforcement, PBA policy engine, second-stage image verification,
  Opal/SED unlock wired into the boot path over the UEFI Storage Security
  transport, and the QEMU MockOpalDxe end-to-end matrix — Phases 4–6,
  ADR-0004/0008/0009). The shim-like loader wrapper (Phase 7) was **dropped**
  (ADR-0010: the PBA is a single-hop trust broker); real hardware (Phase 8) and
  the update/release-signing pipeline are **planned**; their assets and
  adversaries are modelled here with mitigations marked *planned/deferred* so the
  gaps are explicit. The gated `pba-override` Secure Boot trust-broker capability
  (ADR-0012/0013, `-tags trustbroker`, off by default) is also covered — TB2
  exception and R-014.
- **Companion:** quantified risks live in
  [`risk-assessment.md`](../compliance/risk-assessment.md) (R-001..R-014); this
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
| A1 | **SED unlock secret** (Opal password/PIN, derived key material) | **Wired into the boot path** (Phase 6, ADR-0009): the policy-gated `sed_unlock` flow hands the secret to `opal.Unlock` exactly once; the single consume-once-zeroize invariant is unchanged (holder cleared and slice zeroized on every path). The credential is now **policy-selected** via `sed_credential` (ADR-0011): `policy-pin` (compiled-in, debug-only — extractable from the image, build-tag-gated and release-gated so it cannot ship) or `console` (interactive UEFI `SimpleTextInput` entry, **no secret at rest**, bounded retries then fail closed, input buffer zeroized on every path — #51/#101). Never logged; all client-side secret-bearing buffers zeroized on success and all failure paths (#51 item 1). |
| A2 | **PBA binary** (`trusted-pba.efi`) | Built from `cmd/pba`; integrity is firmware Secure Boot's job (we are the signed image). |
| A3 | **PBA policy** | `internal/policy`, compiled-in via `go:embed`, parsed fail-closed. |
| A4 | **Customer trust anchors** | Planned (external/provisioned anchors deferred; ADR-0007 scope boundary). |
| A5 | **Secure Boot trust chain** (db/dbx) | Embedded Microsoft materials in `internal/truststore` (pinned, SHA-256-recorded). |
| A6 | **Windows Boot Manager handoff** | `cmd/pba` chainload (`firmware`/`pba` validation modes). |
| A7 | **Opal session state** | Modeled in `internal/opal` (Phase 4; byte-faithful sessions, in-memory IDs); PIN-bearing frames zeroized after the exchange (#51 item 1). **Driven over the real UEFI transport in the boot path** (Phase 6, ADR-0009); any unlock error — including a partial unlock — terminates via the on-error action, never proceeds or retries into boot (#51 item 2). EndOfSession is best-effort, so the chainload can proceed with the authenticated Locking SP session still open on the TPer — pre-existing Phase 4 behavior, now live in the boot path; hardening candidate. |
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
  for `firmware` mode). **Single-hop (ADR-0010):** the PBA validates the one image
  it chainloads and does not wrap firmware boot services or enforce its policy
  transitively; the loaded stage brokers its own downstream trust (shim-style) or
  relies on firmware-provisioned keys.
  **`pba-override` exception (ADR-0012, gated).** In the explicit `pba-override`
  validation mode — compiled only with `-tags trustbroker` (out of default/release
  builds) and opted into per boot entry — the PBA additionally installs a SHIM-style
  `EFI_SECURITY2_ARCH_PROTOCOL` override so an image it verified but firmware `db`
  does *not* trust still loads (an our-keys-only platform booting e.g. an MS-signed
  loader). This makes the PBA an **authority for out-of-`db` images** — a deliberate,
  narrow Secure Boot override, not a widening of the default trust. It is fail-closed
  (verify → arm exactly the one verified buffer by pointer+size → install → load →
  restore/one-shot-disarm; any error refuses to boot) and **scoped away from the
  Windows/measured-boot path**: it omits the image's `EV_EFI_VARIABLE_AUTHORITY`
  event from PCR 7 (empirically confirmed, `override-pcr.sh`), so a BitLocker seal to
  PCR 7 would break. See R-014.
- **TB3 PBA → SED (Opal transport).** Live. The Opal layer talks to the drive
  through the abstract `TCGTransport` interface, implemented over the UEFI
  Storage Security Command Protocol (`internal/transport`, Phase 5, ADR-0008)
  and exercised end-to-end in the boot path by the QEMU MockOpalDxe integration
  matrix (Phase 6, #22); the drive is untrusted until a session authenticates.
  Real-drive validation pending (Phase 8).
- **TB4 Build/release → artifact.** The embedded policy and trust materials cross
  from the build into the signed binary; their integrity rests on pinning +
  recorded hashes + the (planned) release-signing gate. A release-only
  **policy-safety gate** (`policy.CheckReleaseReady`, run by `release.yml`, #90)
  fails the build unless the embedded default policy requires Secure Boot, does
  not skip the SED unlock, and targets no test fixture — so an unsafe development
  default cannot silently ship. Production signing/provenance remain planned.
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
- TCG Opal response parsing (`internal/opal`, Phase 4) — fails closed,
  **fuzzed** (`FuzzResponseParse`).

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
- **Residual risk:** the SB-off TOCTOU re-read window is mitigated — the PBA
  chainloads from the exact verified in-memory buffer (`LoadImageBuffer`
  SourceBuffer), so verified bytes == executed bytes regardless of Secure Boot
  state (R-012, #46); accepting an image whose short-lived signing leaf expired is
  *intentional* (matches firmware — R-013/#48).
- **Tests:** `TestVerifyFailsClosed/*`, `pba-matrix` (accept / unsigned-reject /
  dbx-revoked-reject — the revoked target is validly signed and chains to db but
  its signer is in dbx, so it is rejected specifically by revocation; #37),
  `secureboot-matrix` scenario **E** (firmware-validation path: the firmware's own
  Secure Boot engine rejects a db-trusted PBA image because its Authenticode hash
  is in dbx — revocation overrides trust, dbx > db; non-vacuous vs scenario B and a
  wrong-hash control; #18), `run-negative` (no target → fail closed). → **R-001**.

### 6.2 Evil-maid attacker (transient physical access)
- **Capability:** boots their own media, swaps the ESP, attempts to observe unlock.
- **Abuse cases:** replace the PBA or target; capture the unlock secret; downgrade
  to an insecure boot.
- **Mitigations:** Secure Boot enforcement gate (`require_secure_boot` ⇒ refuse to
  boot unless `SecureBoot==1 && SetupMode==0`); never treat SB-off == SB-on; SED
  remains locked until authentication — wired (Phase 6, ADR-0009) and now
  exercised end-to-end by the QEMU MockOpalDxe integration matrix
  (`mock-opal-matrix`), whose refuse-to-boot assertions are **mutation-proven**
  (a PBA mutated to fall through to chainload after a failed unlock fails the
  matrix; harness FORBID liveness re-proven by `harness-selftest.sh` on every
  run — review record
  `evidence/security-review-records/2026-06-10-mock-opal-integration-matrix-22.md`);
  hardware validation pending (Phase 8); no unlock material in
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
  (`v1.6.2-tpba.5`) + `go.sum` hash; its patch set over upstream v1.6.2 is
  additive files (incl. the `tpba.5` handle-aware Storage Security surface for
  multi-drive SED selection) **plus a few small functional edits to upstream
  files** — the `callFn` stack-alignment fix in `uefi/uefi.s`, the `path.go`
  device-path Length-underflow guard, and `error.go` typed status errors (ADR-0008
  Amendments 2026-06-10/06-11/06-28) — so the fork-vs-upstream diff includes assembly in the TCB
  call path, kept tiny and individually security-reviewed
  (`evidence/security-review-records/2026-06-10-go-boot-tpba3-abi-fixes.md`,
  `evidence/security-review-records/2026-06-11-go-boot-tpba4-audit-followups.md`);
  dependency onboarding/scan **planned** (#27); SBOM/vuln-scan CI **skeleton** (#9).
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
└─ A.3 Swap the target after verification (TOCTOU)   [mit: verified-buffer load,
                                              firmware never re-reads — R-012/#46]

GOAL B: Obtain the SED unlock secret    [Phase 4 unlock library + Phase 6 boot wiring done;
                                         hardware Phase 8]
├─ B.1 Read it from logs            [mit: never log secrets — opal-layer silence + PIN-free
│                                         errors, fd-level: TestUnlockEmitsNoConsoleOutput]
├─ B.2 Capture Opal session state   [mit: in-memory session IDs; PIN buffers/frames zeroized
│                                         on all paths: TestUnlockZeroizesSecrets,
│                                         TestStartSessionGrowBudget; residual: firmware/DMA
│                                         copies (§6.2); prompt-input scrub → future
│                                         console PIN-prompt change (#51)]
└─ B.3 Unlock before auth succeeds  [mit: fail closed — Set requires an auth'd session;
                                          wrong PIN/timeout/malformed keep drive Locked]
```

## 8. Residual-risk summary

| ID | Residual risk | Status |
|---|---|---|
| R-005 | Rollback to vulnerable PBA / stale dbx | Open — anti-rollback not built |
| R-006 | Malicious update / compromised supply chain | Open — update pipeline + signing not built |
| R-011 | Trust-anchor staleness (2011 CAs expire 2026-06-27) | Open — ADR-gated refresh; 2023 CAs embedded |
| R-012 | SB-off TOCTOU re-read window | Mitigated (#46) — verified-buffer chainload; residual Low |
| R-013 | Ignore signing-cert expiry (firmware semantics) | Accepted — control is dbx; research #48 |
| R-014 | `pba-override` is a Secure Boot override (authorizes an out-of-`db` image) | Gated — `-tags trustbroker` + explicit `pba-override` policy opt-in; fail-closed (verify→arm-one-buffer→restore); PCR-7 divergence characterized, scoped away from Windows/BitLocker (ADR-0012/0013). Accepted (ADR-0013, PR #88, 2026-07-05); independent security review recorded (`evidence/security-review-records/2026-07-05-pba-override-trust-broker-82.md`); #82. |

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
| Verified bytes are the loaded bytes (no re-read TOCTOU) | `cmd/pba` `TestVerifyAndLoadVerifiedBufferInvariant` (ordering + single-read + reassignment ban, mutation-verified) |
| SED unlock gate fails closed in the boot path | `internal/policy` `TestParseSEDUnlock`, `TestParseFailsClosed` (absence = required); `cmd/pba` `TestUnlockSEDNoneSkipsLoudly`, `TestUnlockSEDRequiredHappyPath`, `TestUnlockSEDFailsClosedOnWrongPIN`, `TestUnlockSEDFailsClosedOnTransportFault`, `TestUnlockSEDFailsClosedWithoutCarrier` |
| SED unlock end-to-end over the real UEFI Storage Security path (QEMU + EDK2 MockOpalDxe) | `mock-opal-matrix` `unlock-chainload` (full unlock + MBRDone + chainload), `secure-boot` (SB enforcing, db-signed driver/PBA/fixture, driver markers REQUIREd so a silently-skipped driver cannot false-pass); CI job `mock-opal-integration` |
| Unlock failure never reaches chainload (incl. partial unlock, missing device) | `mock-opal-matrix` `auth-fail`, `fail-mbrdone`, `fail-after-unlock` (partial unlock), `no-driver` — FORBID on chainload markers, mutation-proven (fail-open PBA mutant fails `auth-fail`) |
| Harness FORBID assertions stay live to end of run (no false PASS) | `test/qemu/harness-selftest.sh` (QEMU-free, runs at the start of every matrix invocation; covers fail-open-then-halt, fail-open-then-EOF, grace-bounded clean negative, early FORBID, missing REQUIRE) |

## 10. Change log

| Date | Change |
|---|---|
| 2026-06-08 | Initial threat model through Phase 3 (#4). Captures second-stage verification, Secure Boot enforcement, embedded trust anchors, the ignore-expiry decision (ADR-0007), and the SB-off TOCTOU (#46). |
| 2026-06-08 | Phase 4: Opal unlock **library** + native simulator (ADR-0004, byte-faithful TCG). A1/A7 move from *planned* to *in-library, not yet wired*; Opal response parsers fuzzed + fail closed (R-009); unlock flow fails closed (R-002). Boot-path wiring + hardware remain Phase 5/6/8. |
| 2026-06-08 | Phase 5: UEFI Storage Security transport (`internal/transport`) over the **`walterchris/go-boot` fork** (ADR-0008, adds `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL`). Compromised-dependency mitigations (§6.6) updated to cover the pinned first-party fork. Real SendData/ReceiveData path validated in Phase 6/8 (no host test possible). |
| 2026-06-10 | #51 item 1 (Phase 5/6 gate): PIN-buffer zeroization in `internal/opal` — caller pin, method payload, and transmitted ComPacket frames cleared on success and all failure paths; tested grow budget prevents append reallocation; fd-level log-scrub test asserts opal-layer silence + PIN-free error text (mutation-verified). A1/A7, §6.2, and attack tree B.1/B.2 updated; R-003 residual Medium → Low. Boot-path PIN-*input* zeroization remains open for the Phase 6 wiring (#51 item 2). |
| 2026-06-10 | #46: chainload from the verified in-memory buffer via the fork's `LoadImageBuffer` (pin `v1.6.2-tpba.2`) closes the SB-off verify-then-load TOCTOU (attack tree A.3); R-012 Open → Mitigated. §6.1 residual risk, A.3, §8 summary, and test mapping updated. Review record: `evidence/security-review-records/2026-06-10-chainload-verified-buffer-46.md`. |
| 2026-06-10 | Phase 6 boot-path wiring (#22, #51 item 2, ADR-0009): policy-gated `sed_unlock` (`required`\|`none`, absence = required, `none` logged loudly) drives `opal.Unlock` over the UEFI transport before any chainload; any error — incl. partial unlock and missing Storage Security device — terminates via the on-error action, no retry/fallback. A1/A7 move to *wired*; MVP compiled-in PIN residual documented (ADR-0009). QEMU MockOpalDxe end-to-end is the next Phase 6 ticket. |
| 2026-06-10 | go-boot fork `v1.6.2-tpba.3` (#22, ADR-0008 Amendment 2026-06-10): two UEFI ABI fixes found by the integration matrix's first real run — SSC slot-dispatch double-dereference in the additive `storagesecurity.go` (+ fail-closed NULL-slot check) and the `callFn` stack-alignment pad in upstream's `uefi/uefi.s` (latent upstream bug; also affects upstream SNP Transmit/Receive). §6.6 updated: the fork patch set is no longer purely additive — one reviewed upstream-file edit, to be submitted upstream. Review record: `evidence/security-review-records/2026-06-10-go-boot-tpba3-abi-fixes.md`. |
| 2026-06-10 | Phase 6 QEMU MockOpalDxe integration matrix (#22): six scenarios (unlock-chainload, auth-fail, fail-mbrdone, fail-after-unlock partial unlock, no-driver, secure-boot) exercise the boot path end-to-end over the real UEFI Storage Security protocol; real `mock-opal-integration` CI job; release artifacts gated on a non-`none` default SED policy. Security review found and fixed a harness false-PASS (FORBID dead after the final REQUIRE) — grace-window drain + `harness-selftest.sh` + end-to-end mutation proof. §6.2 and test mapping updated. Review record: `evidence/security-review-records/2026-06-10-mock-opal-integration-matrix-22.md`. |
| 2026-06-10 | Phase 6 wrap-up (#60 merged; epics #22/#19 closed): staleness refresh only. Status header updated from "through Phase 3" to coverage through Phase 6 (unlock wired + QEMU e2e); TB3 (PBA → SED transport) updated from *planned* to live (Phase 5 transport, Phase 6 e2e, hardware pending Phase 8); §4 Opal response parsing no longer *planned* (shipped + fuzzed in Phase 4). No new threats, no mitigation or risk changes. |
| 2026-06-11 | go-boot fork `v1.6.2-tpba.4` (audit #11, ADR-0008 Amendment 2026-06-11): §6.6 pin → tpba.4. Added upstream-file edits — `path.go` device-path Length<4 underflow guard (F-L5, a chainload-path panic on a malformed firmware device path) and `error.go` typed status errors (F-S3) — alongside the existing `uefi.s` alignment fix; F-S4 retained (audit false positive: the `dummy:` block is load-bearing for the assembler's PUSH/POP balance). No new threats; firmware remains trusted at the device-path boundary. Review record: `evidence/security-review-records/2026-06-11-go-boot-tpba4-audit-followups.md`. |
| 2026-06-12 | TB2 clarified single-hop (ADR-0010): Phase 7 loader-wrapper dropped. The PBA validates the one image it chainloads and does not wrap firmware boot services / enforce policy transitively; the next stage brokers its own downstream trust (shim) or relies on firmware-provisioned keys. No new threats; narrows (does not widen) the PBA's claimed trust boundary. |
| 2026-06-15 | §6.1/R-001 test coverage (#37): added an end-to-end **dbx-by-cert revocation** scenario to `pba-matrix` (a validly-signed, db-chaining target whose signer is in dbx → rejected specifically by revocation; mutation-proven non-vacuous). Test-only + a mechanical trust-store refactor (the embedded dbx source is now build-tag-selected so the `pbatest` build substitutes a crafted test dbx; default/`trustfull` builds keep the full real Microsoft dbx — verified, 431 hashes). No behavior change to real builds, no new threats. |
| 2026-06-16 | §6.1/R-001 test coverage (#18, Secure Boot test matrix epic): added `secureboot-matrix` scenario **E** — the **firmware's own** Secure Boot engine rejects a **db-trusted** PBA image because its Authenticode hash is in **dbx** (revocation overrides trust, **dbx > db**), closing the missing firmware-validation-path revocation case (complementary to #37's PBA-path coverage). Strengthens R-001 and **TB1** (Firmware → PBA); non-vacuous (scenario B boots, E rejected "Access Denied", wrong-hash control boots); digest from the new host helper via the same `go-uefi/authenticode` library `internal/imageverify` uses (one source of truth). Test-only; **no rating change** (residual stays Low), no new threats. Review record: `evidence/security-review-records/2026-06-16-firmware-path-dbx-hash-revocation-18.md`. |
| 2026-06-28 | First real-hardware bring-up (Swissbit OPAL drive, 4-NVMe board; ADR-0009 Amendment 2026-06-28, Proposed). **A1/A7 / R-002:** on a multi-NVMe machine firmware exposes one Storage Security carrier per drive, so the unlock now **selects the Opal SED** — `transport.NewAll()` enumerates every `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` handle (go-boot `v1.6.2-tpba.5`) and `cmd/pba selectSED` picks the one whose Level-0 Discovery succeeds, unlocking only that one. Fail-closed preserved (no Discovery-responsive SED → hard error, never chainload) and now unit-tested (`TestUnlockSEDSelectsResponsiveSED`, `TestUnlockSEDNoResponsiveSEDFailsClosed`, `c962b12`); PIN consumed/zeroized once on the selected device. ComID byte-swap (`transport.swapComID`) is a transport-layer conformance detail — firmware writes SP-Specific in the opposite byte order to the TCG ComID; the EDK2 mock mirrors it, host MockTPer unaffected — not a trust-boundary or security-model change. **Accepted residual:** targeting a *specific* drive among MULTIPLE Opal SEDs is a future refinement (today: first Discovery-responsive SED; wrong-drive pick fails auth → fail closed). The "MediaId 0" hypothesis was disproven (MediaId 0 correct). §6.6 pin → tpba.5. No new threats, no rating change. Review record: `evidence/security-review-records/2026-06-28-opal-hw-bringup-handle-select-comid.md`. |
| 2026-07-05 | `pba-override` Secure Boot trust broker (ADR-0012/0013, `-tags trustbroker`, #82 tasks 2–5). **TB2 exception + R-014:** a new, explicit, gated validation mode installs a SHIM-style `EFI_SECURITY2_ARCH_PROTOCOL` override (runtime-free asm stub authorizing exactly the one PBA-verified buffer by pointer+size, one-shot disarm, restore) so an out-of-`db` image the PBA trusts loads under enforcing Secure Boot — making the PBA an authority for out-of-`db` images. Fail-closed (verify before arm; any error refuses to boot); absent the tag a `pba-override` entry fails closed. **Scoped away from Windows/BitLocker:** empirically confirmed to diverge PCR 7 (`override-pcr.sh`; TPM-enabled OVMF via `build-ovmf-tpm.sh` + guest `EFI_TCG2` reader `test/fixtures/tpmread`). Not in default/release builds. **Accepted (ADR-0013)** — the §5.3/§23 human gate was satisfied by the Security/Release Owner rebase-merging **PR #88** to `main` (tip `5fc25fd`) after the independent security review recorded in `evidence/security-review-records/2026-07-05-pba-override-trust-broker-82.md`. No change to default-build trust. |
| 2026-07-05 | **TB4 release gate broadened (#90):** the release-only policy-safety gate (`policy.CheckReleaseReady`, run by `release.yml` via `cmd/release-policy-check`) previously blocked only `sed_unlock:"none"`; it now also fails the release build unless the embedded default policy requires enforcing Secure Boot and targets no test fixture (`EFI/TEST/…`, normalized against separator/`.`/`//`/leading-`/` variants). Closes the reviewer-found gap where a release built from the dev default (`require_secure_boot:false` + firmware-mode fixture) would boot any ESP image with Secure Boot off. An *absent* `require_secure_boot` is treated as unsafe (blocked). Table-tested (`TestCheckReleaseReady`, mutation-resistant); independent security review APPROVE (record `evidence/security-review-records/2026-07-05-release-gate-hardening-90.md`). No change to the boot path or the dev default's runtime behavior; PR CI unaffected (gate runs only in `release.yml`). Advances TB4 / R-001 / R-004. |
| 2026-07-06 | **A1 credential now policy-selected — `sed_credential` schema + `console` source (#99, A2, ADR-0011 §1–§5).** The bare `sed_pin` field is replaced by a `sed_credential` block choosing the unlock `Source`: `policy-pin` (compiled-in debug, build-tag-gated + release-gated) or `console` (interactive UEFI `SimpleTextInput`, **no secret at rest**, bounded retries then fail closed, input buffer zeroized on every path — #51/#101). Follows A1 (#98, the `credential.Source` abstraction). The A1 asset row is updated; the single consume-once-zeroize invariant (ADR-0009) is **unchanged**. Fail-closed on all ~10 resolve/error paths; `internal/opal`/`internal/transport` untouched. Two independent reviews (go-reviewer + security-review-agent) APPROVE — no secret-hygiene regression vs `main`. **Accepted** (ADR-0011 §5.3/§23 human gate satisfied by the Security/Release Owner merging PR #99). Remaining Milestone-1 sources: `keyfile` (A3, #100), `sedutil-pbkdf2` derive (A4, #104 — derive-buffer zeroize hazard tracked there). No new trust boundary, no rating change. Review record: `evidence/security-review-records/2026-07-06-console-credential-99.md`. |
