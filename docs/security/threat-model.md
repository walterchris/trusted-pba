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
| A1 | **SED unlock secret** (Opal password/PIN, derived key material) | **Wired into the boot path** (Phase 6, ADR-0009): the policy-gated `sed_unlock` flow hands the secret to `opal.Unlock` exactly once; the single consume-once-zeroize invariant is unchanged (holder cleared and slice zeroized on every path). The credential is now **policy-selected** via `sed_credential` (ADR-0011): `policy-pin` (compiled-in, debug-only — extractable from the image, build-tag-gated and release-gated so it cannot ship), `console` (interactive UEFI `SimpleTextInput` entry, **no secret at rest**, bounded retries then fail closed, input buffer pre-allocated to the line-length cap so it never reallocates and is zeroized on every path — #51/#101/#124), or `keyfile` (a file on the ESP / boot volume, read via an `Env.Files fs.FS` seam — the seed is **at rest on the volume**, so it is extractable and does not defend evil-maid: a low-assurance source, fail-closed on nil-Files/read-error/empty-file with the read buffer zeroized on every error path — ADR-0011 §4, #100). Orthogonal to the source, an optional **`derive` stage** (`raw` | `sedutil-pbkdf2`, ADR-0011 §3) can transform the resolved seed into the drive credential: `raw` sends it unchanged; `sedutil-pbkdf2` runs `PBKDF2-HMAC-SHA512(seed, salt = drive serial, 500000, 32B)` (A4a, #104) so the PBA can unlock a **default (hash-provisioned)** drive. The iteration count and key length are **policy-configurable** via an optional `derive_params` block (`iterations: <int>|"auto"`, `key_len`; #112) — absent means the defaults 500000/32 (byte-for-byte the pre-#112 behavior), and `auto` tries a fixed best-first candidate list `[500000, 75000]`, advancing only on Opal `NOT_AUTHORIZED` and stopping closed on lockout / any other error / exhaustion (SHA-512 unchanged). The derived key and the consumed seed are zeroized on every path (success and failure); the `sedutil-pbkdf2` path needs the drive serial as salt via an optional `Serialer` capability, now supplied by the **NVMe-passthru carrier (A4b, #104)** — the first transport implementing `Serialer` — so the path is **functional pending hardware validation** (selected only for that derive; the raw/Storage-Security path is unchanged, no fallback). The `crypto/pbkdf2.Key` `string(seed)` transient copy is unscrubable and is an accepted, documented residual (same class as the firmware/DMA copies below). Never logged; all client-side secret-bearing buffers zeroized on success and all failure paths (#51 item 1). |
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
  restore/one-shot-disarm; any error refuses to boot). It omits the image's
  `EV_EFI_VARIABLE_AUTHORITY` event from PCR 7 (empirically confirmed,
  `override-pcr.sh`), so it **diverges PCR 7 from a firmware-`db` boot**; ADR-0012/0013
  therefore scoped it away from the Windows/measured-boot path.
  **ADR-0014 (Proposed) relaxes that for our-keys-only platforms:** the override may
  also broker Windows Boot Manager (firmware `db` = key A only; the Microsoft Windows
  CAs live in the PBA's own embedded trust store, not in firmware `db`). BitLocker still
  **breaks unless it is sealed with the PBA already in the measured chain** — a boot
  sealed *without* the PBA that then has the PBA inserted underneath drops to the
  recovery prompt. ADR-0014 therefore makes sealing-with-the-PBA a **mandatory
  provisioning obligation** (enable/seal BitLocker with the PBA-override already
  measured; treat PBA/override updates as PCR-7-affecting reseal events) and carries an
  **OPEN pre-condition**: the precise BitLocker PCR-7 seal profile must be verified
  against a primary Microsoft source **and** the auto-unlock-after-reseal claim
  validated on real hardware before any **production** Windows use. The fail-closed
  authorization properties are unchanged and evidenced by the negative demo (broker
  trust store without the Windows CAs → `bootmgfw` rejected, override never armed).
  ADR-0014 is **Proposed** — the Security/Release Owner human gate and an independent
  security review are pending, and release builds stay override-free. See R-014.
- **TB3 PBA → SED (Opal transport).** Live. The Opal layer talks to the drive
  through the abstract `TCGTransport` interface, implemented over **two
  carriers**: the UEFI Storage Security Command Protocol (`internal/transport`,
  Phase 5, ADR-0008), exercised end-to-end in the boot path by the QEMU
  MockOpalDxe integration matrix (Phase 6, #22), and the **NVMe-passthru
  carrier** over `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` (A4b, #104 — NVMe Security
  Send/Receive, native ComID order, `Serial()` for the sedutil-pbkdf2 salt),
  exercised end-to-end by the QEMU `nvme-opal-matrix` against MockOpalDxe's
  pass-thru surface (#110); the drive is untrusted until a session
  authenticates. Real-drive validation pending (Phase 8).
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
  signer's **whole PKCS#7 bundle** — every stapled cert, not only the leaf + the
  chain(s) `x509.Verify` returns, so a dbx-revoked intermediate the signer staples
  that `x509.Verify` routes around cannot slip through (#91) — plus a per-chain loop
  that additionally covers a revoked `db` root; parser failures fail closed
  (`ErrParse`).
- **Residual risk:** parser bugs in `go-uefi` (mitigated by fuzzing + pinned dep).
  A panic *inside* the go-uefi parser can no longer crash the PBA: `Verify` wraps
  the whole parse/verify path in a `defer`/`recover()` that converts any panic into
  an `ErrParse` fail-closed result (added 2026-07-18 after `FuzzVerify` found a
  malformed PE panicking at `authenticode` `checksum.go:179` — R-009).
- **Tests:** `TestVerifyFailsClosed/{tampered,untrusted root,unsigned,revoked by
  image hash,revoked by signer cert,non-code-signing EKU,revoked intermediate,
  revoked bundled cert off the winning chain (#91)}`,
  `TestStripAuth2Rejects`, `FuzzVerify` (+ regression seed
  `30950a34c9c628dc`). → **R-001, R-009**.

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
| R-014 | `pba-override` is a Secure Boot override (authorizes an out-of-`db` image) | Gated — `-tags trustbroker` + explicit `pba-override` policy opt-in; fail-closed (verify→arm-one-buffer→restore). PCR-7 divergence characterized; scoped away from Windows/BitLocker by ADR-0012/0013. Accepted for the non-Windows/custom-loader path (ADR-0013, PR #88, 2026-07-05; review `evidence/security-review-records/2026-07-05-pba-override-trust-broker-82.md`). **ADR-0014 (Proposed)** extends it to the Windows path for **our-keys-only** platforms, gated on a mandatory provisioning obligation (BitLocker sealed with the PBA measured; PBA updates = reseal) + an OPEN pre-condition (verify the PCR-7 seal profile vs a primary Microsoft source + validate on real HW before production); new residual is operational (recovery-key prompt on PBA change), the fail-closed authorization properties unchanged. Pending the human gate + independent security review; release builds stay override-free. #82. |

## 9. Test mapping

| Mitigation | Tests / CI |
|---|---|
| Reject untrusted/tampered/revoked image (dbx-by-cert covers the signer's whole PKCS#7 bundle, not only the winning chain — #91) | `internal/imageverify` `TestVerifyFailsClosed/*` (incl. `revoked bundled cert off the winning chain (#91)`, mutation-proven); `pba-matrix` |
| Accept genuine signed image (incl. expired leaf) | `TestVerifyAccepts`, `TestVerifyAcceptsExpiredSigner`; `TestRealMicrosoftSignedImage` (CI-only, needs `TPBA_REAL_SHIM`) |
| Trust-set boundary (windows-only vs full) | `TestRealMicrosoftSignedImage` (CI-only, `real-image-verify` job; skips without `TPBA_REAL_SHIM`) |
| Policy parsed fail-closed | `internal/policy` `TestParseFailsClosed`, `FuzzParse` |
| Secure Boot detection + enforcement | `internal/secureboot` `TestEnforcing`; `internal/policy` `TestCheckSecureBoot`; `sb-matrix`; `sb-require-test` |
| dbx update parsing bounds | `TestStripAuth2Rejects`, `TestLoad` |
| Chainload + fail-closed on no target | `run`, `run-negative` (QEMU) |
| Opal unlock fails closed (auth/status/transport) | `internal/opal` `TestUnlockHappyPath`, `TestUnlockFailsClosed/*` |
| PE/Authenticode image parser never panics on bad input (fails closed) | `internal/imageverify` `FuzzVerify` (+ permanent regression seed `30950a34c9c628dc`); nightly `deep-fuzz` CI job; `Verify` `recover()`→`ErrParse` backstop |
| Opal response parsers never panic on bad input | `FuzzResponseParse`; `TestTokenizeFailsClosed`, `TestDecodePacketFailsClosed`, `TestParseDiscoveryFailsClosed` |
| Unlock secret never logged, buffers zeroized | `internal/opal` `TestUnlockEmitsNoConsoleOutput` (fd-level), `TestUnlockZeroizesSecrets`, `TestTransactZeroizesMethodPayload`, `TestStartSessionGrowBudget`, `TestBuilderGrowPreventsReallocation` |
| Verified bytes are the loaded bytes (no re-read TOCTOU) | `cmd/pba` `TestVerifyAndLoadVerifiedBufferInvariant` (ordering + single-read + reassignment ban, mutation-verified) |
| SED unlock gate fails closed in the boot path | `internal/policy` `TestParseSEDUnlock`, `TestParseFailsClosed` (absence = required); `cmd/pba` `TestUnlockSEDNoneSkipsLoudly`, `TestUnlockSEDRequiredHappyPath`, `TestUnlockSEDFailsClosedOnWrongPIN`, `TestUnlockSEDFailsClosedOnTransportFault`, `TestUnlockSEDFailsClosedWithoutCarrier` |
| SED unlock end-to-end over the real UEFI Storage Security path (QEMU + EDK2 MockOpalDxe) | `mock-opal-matrix` `unlock-chainload` (full unlock + MBRDone + chainload), `secure-boot` (SB enforcing, db-signed driver/PBA/fixture, driver markers REQUIREd so a silently-skipped driver cannot false-pass); CI job `mock-opal-integration` |
| Unlock failure never reaches chainload (incl. partial unlock, missing device) | `mock-opal-matrix` `auth-fail`, `fail-mbrdone`, `fail-after-unlock` (partial unlock), `no-driver` — FORBID on chainload markers, mutation-proven (fail-open PBA mutant fails `auth-fail`) |
| SED unlock end-to-end over the real NVMe-passthru carrier (TB3 second carrier: locate pass-thru handles, Identify-Controller serial as sedutil-pbkdf2 salt, Security Send/Receive session, native ComID order) | `nvme-opal-matrix` POS (#110): `auto` advances 500000→75000 — attempt 1 `NOT_AUTHORIZED`, attempt 2 authenticates, the hwdbg winning-count marker REQUIREd — then unlock + MBRDone + chainload, entirely over `EFI_NVM_EXPRESS_PASS_THRU`; CI job `qemu-nvme-matrix` |
| `auto` iteration loop is try-limit-safe and fails closed without a carrier | `nvme-opal-matrix` NEG `auth-lockout` (`AUTHORITY_LOCKED_OUT` on attempt 1 → loop stops: FORBID `MOCKOPAL: startsession 2` + boot markers) and NEG `no-driver` (zero pass-thru handles → hard fail, FORBID boot markers) — the #112 advance-only-on-`NOT_AUTHORIZED` semantics proven end-to-end (#110) |
| Unlock then boot a **real OS** (product claim end-to-end, virtual) | `linux-boot-matrix` POS (unlock → real Linux UKI → kernel → `TEST-LINUX: userspace ok`; no "chainload returned" REQUIRE — a kernel never returns) and POS-SB (enforcing Secure Boot, throwaway per-run keys, db-signed driver+PBA+UKI to userspace); CI job `qemu-linux-matrix` |
| Unlock failure never boots a **real OS** (locked drive → no OS) | `linux-boot-matrix` NEG `auth-fail` — FORBIDs the PBA's *early* chainload-side markers (`TRUSTED-PBA: starting` / `TRUSTED-PBA: ESP opened`, emitted within milliseconds — inside the FORBID grace window; the slow userspace marker is defense-in-depth only), mutation-proven (fail-open PBA mutant caught on `TRUSTED-PBA: ESP opened`, 2026-07-21) |
| Harness FORBID assertions stay live through the grace window (no false PASS) | `test/qemu/harness-selftest.sh` (QEMU-free, runs at the start of every matrix invocation; covers fail-open-then-halt, fail-open-then-EOF, grace-bounded clean negative, early FORBID, missing REQUIRE). **Qualified (2026-07-21):** the self-test guarantees FORBID liveness **only for markers whose latency fits the grace window** (`EXPECT_GRACE`, default 8s after the last REQUIRE) — a negative scenario whose forbidden signal is slower (e.g. a TCG-emulated kernel reaching userspace, minutes) must FORBID a fast proxy marker instead, as the linux-boot NEG does |

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
| 2026-07-06 | **A1 credential — `sedutil-pbkdf2` derive primitive (#104, A4a, ADR-0011 §3).** Adds the derivation stage orthogonal to the source: `SedutilPBKDF2(seed, salt)` = `PBKDF2-HMAC-SHA512(seed, salt = drive serial, 500000, 32B)`, KAT-verified (recomputed via python `hashlib`, mutation-proven — hash/iters changes fail it) against sedutil's `cf_pbkdf2_hmac`+`cf_sha512`, so the PBA can unlock a **default (hash-provisioned)** drive. `unlockSED` reordered to *resolve → selectSED → derive → Unlock* (the salt is the selected drive's serial); an optional `Serialer` capability supplies it (`opal.Transport` **unchanged** — type-assert, ADR-0004 layering). **Fail-closed** on empty seed/salt, not-a-`Serialer`, `Serial()` error, and unknown derive — never sends a credential, never chainloads, never falls back to the raw seed; today's Storage-Security carrier is not a `Serialer` so `sedutil-pbkdf2` fails closed until the NVMe-passthru carrier (A4b). **F-2 closed:** the consumed seed and the new derived key are zeroized on success and unlock-failure paths (mutation-style tests). **Accepted residual:** the `crypto/pbkdf2.Key` `string(seed)` transient copy is unscrubable (same class as the firmware/DMA copies, §6.2) — kept first-party stdlib `crypto/pbkdf2` over promoting `x/crypto/pbkdf2` to a direct dep. Two independent reviews (go-reviewer + security-review-agent) APPROVE; go-reviewer nits applied. Within the already-Accepted ADR-0011 (no new ADR gate; §3 parameters corrected from the stale SHA-1/75000 sketch, Status unchanged); presented at the ADR-0011 §5.3/§23 human merge gate (PR #104). **Not functional end-to-end until A4b + hardware validation.** No new trust boundary, no rating change. Review record: `evidence/security-review-records/2026-07-06-sedutil-pbkdf2-derive-104.md`. |
| 2026-07-06 | **TB3 second carrier — NVMe-passthru Opal transport (#104, A4b, within ADR-0011 §3 / ADR-0008 tpba.6).** **TB3 (PBA → SED transport)** gains a second carrier under the same abstract `opal.Transport`: the **NVMe-passthru carrier** over `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` (NVMe Security Send/Receive), the **first transport implementing the optional `credential.Serialer` capability** (`Serial()` = the drive serial, i.e. the sedutil-pbkdf2 salt). This flips A1's `sedutil-pbkdf2` derive from "fails closed / non-functional" (2026-07-06 A4a entry) to **functional pending hardware validation** — `cmd/pba run()` selects the NVMe carrier **only** for the `sedutil-pbkdf2` derive (nil-`SEDCredential` guarded); the proven raw/Storage-Security path is unchanged (default constructor untouched) — **no regression, no cross-carrier fallback**. **ADR-0004 layering preserved** (`internal/transport` does not import `internal/credential`; the `Serialer` assertion lives in the test file). **NO ComID byte-swap** — the NVMe carrier uses native (SP-Specific) ComID order, a deliberate divergence documented in code; consistent with the 2026-06-28 note that `swapComID` is a Storage-Security *conformance* detail, not a security-model element. **Residual (explicit):** end-to-end is **not provable off-hardware** — the `tamago && amd64` carrier cannot run host-side, so real-drive Opal-session-over-NVMe and Identify-Controller-salt correctness require hardware validation on the Swissbit / multi-NVMe board (sits under **R-010** QEMU/mock-vs-real, and **R-007/R-008**); the known HW Discovery0 IF-RECV `EFI_DEVICE_ERROR` finding is directly relevant. Two independent reviews (go-reviewer + security-review-agent) APPROVE; within the already-Accepted ADR-0011 (no new ADR gate). No rating change. Review record: `evidence/security-review-records/2026-07-06-nvme-passthru-carrier-104b.md`. |
| 2026-07-06 | **A1 credential — `keyfile` source added (#100, A3, ADR-0011 §4).** A third `sed_credential` source alongside `policy-pin` and `console`: `keyfile` reads the unlock seed from a file on the ESP / boot volume via an `Env.Files fs.FS` seam (twin of the A2 `console` source; `internal/credential` stays UEFI-free). Fail-closed on nil-`Files` / read-error / empty-file / missing-file / no-path / wrong-source stray field; the read buffer is zeroized on every error path (read-error scrub mutation-proven), the single consume-once-zeroize invariant (ADR-0009) is **unchanged**, and errors carry only the path — never the key bytes. **Residual (accepted):** the seed is **at rest on the volume** (extractable) — a low-assurance source that does **not** defend evil-maid; it is a legitimate production source and is therefore **not release-gated** (unlike `policy-pin`). No new trust boundary. `internal/opal`/`internal/transport` untouched. Within the already-Accepted ADR-0011 (no new ADR gate); human gate satisfied by the Security/Release Owner merging PR #100 after two independent reviews (go-reviewer + security-review-agent) both APPROVE. Automated `qemu-keyfile-matrix` POS+NEG passes. No rating change. Final Milestone-1 source: `sedutil-pbkdf2` derive (A4, #104). Review record: `evidence/security-review-records/2026-07-06-keyfile-credential-100.md`. |
| 2026-07-18 | **§6.3 / R-009 — `imageverify.Verify` panic-to-error backstop (#114, `fix/imageverify-parse-panic`).** The nightly `deep-fuzz (./internal/imageverify, FuzzVerify)` job on `main` (GitHub Actions run 29632495833) found a malformed PE (out-of-range size field) that panicked *inside* the third-party `go-uefi/authenticode` parser (`bytes.Buffer.Truncate` out of range at `checksum.go:179`, reached from `verify.go:57`) instead of returning an error — the attacker-controlled second-stage image parser (§4, §6.3, TB2). `Verify` now wraps the whole go-uefi parse/verify path in a `defer`/`recover()` that converts any panic into an `ErrParse` fail-closed result, so a crafted ESP image fails closed (do-not-boot) rather than crashing the PBA; the exact crasher is a permanent regression seed (`internal/imageverify/testdata/fuzz/FuzzVerify/30950a34c9c628dc`). **Hardening only, no change to the accept/reject decision ⇒ no ADR, no new threat, no rating change** (R-009 residual stays Low). Demonstrates the fuzz test mapping (§9) working as intended. Evidence: `evidence/fuzzing-reports/2026-07-18-imageverify-fuzzverify-panic-R-009.md`. |
| 2026-07-06 | **A1 credential now policy-selected — `sed_credential` schema + `console` source (#99, A2, ADR-0011 §1–§5).** The bare `sed_pin` field is replaced by a `sed_credential` block choosing the unlock `Source`: `policy-pin` (compiled-in debug, build-tag-gated + release-gated) or `console` (interactive UEFI `SimpleTextInput`, **no secret at rest**, bounded retries then fail closed, input buffer zeroized on every path — #51/#101). Follows A1 (#98, the `credential.Source` abstraction). The A1 asset row is updated; the single consume-once-zeroize invariant (ADR-0009) is **unchanged**. Fail-closed on all ~10 resolve/error paths; `internal/opal`/`internal/transport` untouched. Two independent reviews (go-reviewer + security-review-agent) APPROVE — no secret-hygiene regression vs `main`. **Accepted** (ADR-0011 §5.3/§23 human gate satisfied by the Security/Release Owner merging PR #99). Remaining Milestone-1 sources: `keyfile` (A3, #100), `sedutil-pbkdf2` derive (A4, #104 — derive-buffer zeroize hazard tracked there). No new trust boundary, no rating change. Review record: `evidence/security-review-records/2026-07-06-console-credential-99.md`. |
| 2026-07-07 | **A1 credential — configurable `sedutil-pbkdf2` iterations + `auto` mode (#112, within ADR-0011 §3).** The `sedutil-pbkdf2` derive iteration count + key length are now **policy-configurable** via an optional `sed_credential.derive_params` block (`iterations: <int>\|"auto"`, `key_len`). **Absent → defaults 500000/32, byte-for-byte identical to the pre-#112 behavior** (derive once, one Unlock); SHA-512 **unchanged**. `auto` tries a fixed **best-first** candidate list `[500000, 75000]`: derive + attempt Unlock per candidate, advancing **only** on Opal `NOT_AUTHORIZED` (new `opal.ErrNotAuthorized` sentinel) and **stopping immediately, fail-closed, on `AUTHORITY_LOCKED_OUT`** (`opal.ErrAuthLockedOut`) to protect the Admin1 try-limit, on any other error, and on list exhaustion. **F-2 preserved** — consumed seed + every derived key zeroized on all paths (success/retry/lockout/other/exhaustion). Validation fail-closed (rejects a stray `derive_params` on non-sedutil derives, explicit `iterations` outside 1..100_000_000 incl. explicit-0, `key_len` outside 1..64). Motivated by the **A4b HW iteration mismatch** (lab sedutil 1.20.0 provisioned at 75000 vs the hardcoded 500000 → `NOT_AUTHORIZED`). Within the already-Accepted ADR-0011 §3 (no new ADR gate; §3 extended, Status unchanged); **no new trust boundary**; **no rating change** (R-002 Medium, R-003 Low). Two independent reviews (go-reviewer + security-review-agent) APPROVE; go-reviewer nits applied. **Residuals:** the operator must know the iteration count the provisioning sedutil used — the PBA cannot read it back from the drive (`auto` discovers it; known values: customer fork / v1.15 = 500000, upstream older e.g. 1.20.0 = 75000); the real-drive `NOT_AUTHORIZED`-vs-lockout timing that `auto` relies on is an **R-010 / Phase-8 hardware** item (MockTPer conflates the two). Review record: `evidence/security-review-records/2026-07-07-configurable-sedutil-iterations-112.md`. |
| 2026-07-19 | **TB3 virtual coverage — QEMU NVMe-passthru Opal matrix + mock wrong-credential fidelity fix (#110, branch `feat/nvme-opal-matrix-110`; test tooling + mock-fidelity only, NO product code change).** MockOpalDxe now also produces `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` on the same handle — Identify Controller (scripted 20-byte serial = the sedutil-pbkdf2 salt) and Security Send/Receive (`0x81`/`0x82`) into the shared scripted TPer with the ComID in **native** order (no swap — the product NVMe carrier's contract; the Storage Security surface keeps its swap) — so **both TB3 carriers** are now exercised end-to-end virtually. The new `nvme-opal-matrix` (CI job `qemu-nvme-matrix`; `-tags sednvmetest,hwdebug` PBA, embedded test policy policy-pin + `sedutil-pbkdf2` + `iterations:"auto"` + `on_error:halt`) drives the **real product NVMe-passthru carrier code** (locate pass-thru handles, go-boot command-packet marshalling, Identify-serial salt, no-swap session): POS `auto` advances 500000→75000 → unlock → MBRDone → chainload; NEG `auth-lockout` — the loop stops after attempt 1 (FORBID `startsession 2`; the #112 try-limit safety proven e2e); NEG no-driver — zero pass-thru handles → hard fail-closed, no boot. **Mock-fidelity fix:** both mocks returned `AUTHORITY_LOCKED_OUT` (`0x12`) for a *wrong credential*; real drives return `NOT_AUTHORIZED` (`0x01`, observed on lab HW — the status `auto` advances on). Both mocks + the shared spec now use `0x01` for wrong-credential, `0x12` as an explicit `auth-lockout` fault — closing an actual mock/real divergence (R-010) and superseding the #112 "MockTPer conflates the two" note (real-drive *timing* stays Phase 8). Drift guard: `TestMockDerivedKeySync` pins the mock's 75000-iteration credential to the KAT-verified `SedutilPBKDF2`. All 3 scenarios PASS locally (2026-07-19); `mock-opal-matrix` 6/6 + `keyfile-matrix` 2/2 regression-PASS. **No new threats, no trust-boundary change, no rating change** (R-002/R-010 stay Medium). **No new ADR** — within ADR-0005's virtual-first test strategy and the already-Accepted ADR-0011 §3; no product behavior change. CRA matrix: no impact (ER-10 unchanged). Two independent reviews (go-reviewer + security-review-agent) APPROVE, no changes. Review record: `evidence/security-review-records/2026-07-19-nvme-opal-matrix-110.md`; test evidence: `evidence/test-reports/2026-07-19-nvme-opal-matrix-110.md`. |
| 2026-08-16 | **§6.3 / R-001 — dbx-by-cert revocation now covers the whole signing bundle (#91, branch `fix/imageverify-dbx-full-bundle-91`).** `internal/imageverify.Verify` checked dbx-by-cert only on the leaf + the certs on the chain(s) `x509.Verify` returns; a dbx-revoked intermediate the signer stapled into the PKCS#7 bundle that `x509.Verify` routes around (cross-signing / an alternate path to `db`) was never consulted — a **revocation bypass** (fail-open on the §6.1/§6.3 / TB2 pba-mode image-acceptance path). Fixed to check dbx-by-cert against **every** bundled cert (`slices.ContainsFunc(certs, v.revoked)`); the per-chain loop is retained (uniquely covers a revoked `db` root). §6.3 mitigations + Tests and the §9 "reject untrusted/tampered/revoked image" row updated with the new mutation-proven subtest `revoked bundled cert off the winning chain (#91)`. **Tightens** acceptance (never weakens); over-rejection is fail-closed-safe (Windows uses firmware mode; imageverify is pba-mode custom/recovery only). **No new threat, no trust-boundary change, no ADR** (no change to the trust decision beyond closing the bypass), **no rating change** (R-001 residual stays Low). go-reviewer + security-review-agent both APPROVE (security review mutation-proved the bypass in an isolated worktree). Supersedes the #91 open-gap note in the 2026-08-16 full-codebase audit (finding C-1). Review record: `evidence/security-review-records/2026-08-16-imageverify-dbx-full-bundle-91.md`. |
| 2026-08-27 | **TB2 exception + R-014 — `pba-override` extended to the Windows path (ADR-0014, Proposed; branch `fix/windows-handoff-demos`).** ADR-0014 reverses ADR-0013 decision #3 (and relaxes ADR-0012's blanket Windows exclusion) for **our-keys-only** platforms: firmware `db` = key A only, and the PBA trust-brokers Windows Boot Manager against the Microsoft Windows CAs in the PBA's **own** embedded trust store, admitting it via the Security2 override — one symmetric trust model (firmware trusts only the PBA; the PBA vouches for the whole OS, Linux UKI **and** `bootmgfw`). The TB2 exception is no longer a blanket "scoped away from Windows": the PCR-7 warning is **refined**, not removed — BitLocker still breaks **unless it is sealed with the PBA already in the measured chain**, which ADR-0014 makes a **mandatory provisioning obligation** (seal with the PBA measured; PBA/override updates = PCR-7 reseal events) and gates behind an **OPEN pre-condition** (verify the BitLocker PCR-7 seal profile against a primary Microsoft source + validate on real hardware before any production Windows use). The **fail-closed authorization properties are unchanged** (enforcing-SB precondition, verify-before-arm, one-shot pointer+size authorization, restore) and re-evidenced by the in-session negative demo (broker trust store **without** the Windows CAs → `bootmgfw` rejected `signer does not chain to a trusted db certificate`, `override armed` never printed → fail closed); the positive demo boots to Windows 11 Setup (evaluation media, no BitLocker enrolled). The **new residual is operational, not authorization** (PCR-7/BitLocker recovery-key prompt on PBA change), mitigated by the provisioning obligation. **No rating change** (R-014 residual stays Low; the authorization posture is unchanged, the new residual is an availability/recovery item bounded by provisioning). ADR-0014 is **Proposed** — the §5.3/§23 Security/Release Owner human gate and an independent security review (running separately) are merge pre-conditions, and **shipped/release defaults are unchanged** (release builds stay override-free). No product-code trust decision changed for release. |
| 2026-07-21 | **Linux-boot matrix — first real-OS end-to-end (branch `feat/linux-boot-matrix`, #118; test tooling only, no product code — verified by the independent security review).** The unchanged `-tags sedtest` PBA chainloads a **real Linux UKI** (distro kernel + static Go-init initramfs via `ukify`; cmdline/initramfs embedded because the PBA passes no LoadOptions) after the MockOpalDxe unlock: POS to userspace, NEG auth-fail (a locked drive never boots an OS), POS-SB under enforcing Secure Boot with db-signed driver+PBA+UKI. **§9 test mapping** gains the two real-OS rows above. **Security-review finding (initially BLOCK, empirically demonstrated via the harness `EXPECT_STUB` seam):** the NEG's sole fail-open detector was the userspace marker, whose TCG latency (minutes) exceeds `expect-serial.py`'s 8s FORBID grace window — a fail-open PBA would have false-PASSed. Fixed per review: the NEG FORBIDs the PBA's early chainload-side markers (`TRUSTED-PBA: starting`/`ESP opened`, milliseconds); the §9 harness-liveness row is **qualified** — the self-test guarantees FORBID liveness only for markers whose latency fits the grace window; the harness-selftest comment states the precondition. **Mutation-proven (2026-07-21):** a deliberately fail-open PBA mutant (never committed; product tree reverted byte-identical, verified clean) was caught — `FAIL: forbidden marker observed: TRUSTED-PBA: ESP opened`, exit 1. **No new threats, no trust-boundary change, no ADR, no rating change** — strengthens the §6.2 evil-maid refuse-to-boot evidence (R-002) and the §6.10/R-007 chainload coverage with a real kernel. Evidence: `evidence/test-reports/2026-07-21-linux-boot-matrix.md`; review record `evidence/security-review-records/2026-07-21-linux-boot-matrix.md`. |
