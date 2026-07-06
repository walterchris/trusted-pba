# Security review — NVMe-passthru Opal transport carrier (#104, A4b)

- **Date:** 2026-07-06
- **Change:** branch `feat/nvme-passthru-carrier-104b` (A4b, issue #104; commit `0f7be51`).
  Adds the second `opal.Transport` carrier that A4a's `sedutil-pbkdf2` derive needs to become
  functional — the drive serial (the PBKDF2 salt):
  1. `internal/transport/nvme_tamago.go` (`//go:build tamago && amd64`) — the `NVMe` carrier
     over `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` (NVMe Security Send/Receive admin commands, go-boot
     `v1.6.2-tpba.6`). Implements `opal.Transport` (`Send`/`Recv`) **and** the optional
     `credential.Serialer` (`Serial()` returns the drive's raw 20-byte serial from
     Identify-Controller, the sedutil-pbkdf2 salt). `NewAllNVMe()` locates every pass-thru
     handle and returns one carrier each; a handle whose protocol cannot be resolved is skipped;
     **zero usable carriers is a hard error**. **NO ComID byte-swap** — NVMe carries the TCG
     ComID in native (SP-Specific) order; the swap the Storage-Security carrier performs is a
     property of `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` marshalling, not of NVMe, and is
     deliberately absent here (documented in `Send`/`Recv`).
  2. `internal/transport/nvme_host.go` (`//go:build !tamago`) — the off-target placeholder so the
     package builds and the assertions hold on the host; every method (`NewAllNVMe`, `Send`,
     `Recv`, `Serial`) fails closed via `ErrUnavailable`.
  3. `cmd/pba/main.go run()` — carrier selection: default is the proven firmware Storage-Security
     carrier (`newUEFITransports`, **unchanged**); `run()` switches to `newNVMeTransports` **only**
     when `pol.SEDCredential != nil && pol.SEDCredential.Derive == policy.DeriveSedutilPBKDF2`. The
     nil-`SEDCredential` guard covers `SEDUnlockNone` (no credential). `newNVMeTransports` widens
     `[]*transport.NVMe` to `[]opal.Transport` and propagates `NewAllNVMe`'s fail-closed error.
  4. `internal/transport/transport.go` — compile-time `var _ opal.Transport = (*NVMe)(nil)` added
     alongside `*UEFI`. `internal/transport/transport_test.go` — the `var _ credential.Serialer =
     (*NVMe)(nil)` assertion (in the **test** file so the non-test package never imports
     `internal/credential`) and `TestNVMeHostFailsClosed`.
- **Origin:** ADR-0011 §3 easy→hard rollout (Milestone 1). A4a (#104, `2026-07-06-sedutil-pbkdf2-derive-104.md`)
  landed the KAT-verified derive and declared itself **fail-closed-until-A4b**: the derive needs
  the drive serial as salt, and no carrier implemented `Serialer`. A4b supplies that carrier and
  flips the contract to **functional pending hardware validation**.
- **Reviewers:** two independent reviews — **go-reviewer** (idiomatic-Go / correctness) and the
  adversarial **security-review-agent** (fail-closed / secret-hygiene); neither implemented the
  change.
- **Method:** read `nvme_tamago.go` (the carrier, the `nvmePassThru` seam, the NewAllNVMe
  enumeration + zero-carrier guard, the no-ComID-swap comments, `Serial()`), `nvme_host.go` (the
  host stub), the `run()` carrier-selection guard and `newNVMeTransports`, and the compile-time /
  `Serialer` assertions; traced the derive-selection path against ADR-0011 §3 and the ADR-0004
  layering invariant; ran the host unit tests (`internal/transport`, `cmd/pba`), `go vet`,
  `golangci-lint`, the `!tamago` host build, and the `tamago && amd64` default + `sedtest` builds.

## Verdict: APPROVE (within the already-Accepted ADR-0011)

Both reviews APPROVE. ADR-0011 is already **Accepted** (2026-07-06, via #99); A4b is the
transport carrier that makes the §3 `sedutil-pbkdf2` derive stage functional *within* that
accepted design, so it does **not** open a new ADR gate. It is also within ADR-0008's Accepted
`tpba.6` amendment (that amendment already added the NVMe surface; A4b is its first consumer —
recorded in the ADR-0008 Amendment note dated 2026-07-06). The two documentation items the
security reviewer raised as **non-blocking** are exactly the compliance/evidence updates recorded
alongside this record (threat-model TB3 change-log + A1 asset row, risk-assessment R-002/R-003
bullet + change-log row, this record, and the ADR-0008 amendment note).

- **go-reviewer — APPROVE.** Idiomatic; the carrier is a small wrapper over the go-boot NVMe
  pass-thru primitive behind a 3-method `nvmePassThru` seam defined where consumed; errors wrapped
  (`%w`, carrying only proto/comID/stage) and never ignored; `Serial()` returns concrete `[]byte`;
  the `[]*NVMe`→`[]opal.Transport` widen is the unavoidable element-wise loop (Go has no covariant
  slice conversion), commented as such. CLAUDE.md layering held: `internal/transport` does not
  import `internal/credential`. Only **nits** (comment wording / naming), no behavior change, no
  blockers.
- **security-review-agent — APPROVE.** Fail-closed confirmed on every enumerated path (see below);
  no secret-hygiene regression versus A4a or `main`; the sole substantive residual is that
  end-to-end is not provable off-hardware (below). Two **non-blocking documentation items** raised
  — the threat-model/risk-assessment updates and this evidence record — which are the work
  recorded here.

## Fail-closed evidence (security-review-agent confirmed)

- **`NewAllNVMe` zero-carrier → hard error.** On TamaGo, no pass-thru handle (no NVMe controller /
  firmware without the protocol) returns an error; the caller never proceeds without a real
  carrier. `newNVMeTransports` propagates it, so `run()` aborts via the policy `on_error` action.
- **Unresolved-handle skip never yields a nil/empty carrier set.** A handle whose protocol cannot
  be resolved is skipped (`continue`), not turned into a usable carrier; if the skip drains every
  handle, `len(ts) == 0` still returns the hard error — the enumeration cannot hand back a nil or
  bogus transport.
- **Host stub fails closed on every method.** `NewAllNVMe`, `Send`, `Recv`, and **`Serial`** all
  return `ErrUnavailable` off-target (`TestNVMeHostFailsClosed`), so a `sedutil-pbkdf2` policy can
  never proceed host-side — including via the salt source.
- **Client-over-unavailable Unlock fails.** `opal.NewClient(&NVMe{}).Unlock(...)` over the host
  stub fails rather than pretending to talk to a drive (`TestNVMeHostFailsClosed`).
- **nil-`SEDCredential` guard provably sufficient.** `run()` dereferences `pol.SEDCredential.Derive`
  only after the `pol.SEDCredential != nil` guard. `SEDCredential` is nil exactly for
  `SEDUnlockNone`, and `validateSEDCredential` rejects a credential whenever `SEDUnlock == none`,
  so the two states cannot co-occur — the guard is sufficient, no nil deref, no accidental NVMe
  selection for a no-unlock policy.
- **No cross-carrier fallback.** Carrier choice is a single up-front branch on the derive; there is
  no path that retries the other carrier after a failure. The raw/Storage-Security path keeps the
  default constructor untouched (no regression), and the NVMe path never falls back to
  Storage-Security (which could not supply the salt anyway).
- **No plausible-but-wrong salt.** `Serial()` returns the drive's raw serial as reported or a
  wrapped error; it never fabricates or pads a stand-in salt, so a `Serial()` failure fails closed
  rather than deriving a wrong key.
- **NO-ComID-swap is intentional.** The absent byte-swap is native NVMe (SP-Specific) ComID order,
  documented in `Send`/`Recv`; consistent with the 2026-06-28 finding that `swapComID` is a
  Storage-Security conformance detail, not a security-model element. It is a transport-conformance
  choice, not a fail-open.

## Secret hygiene

- **Errors carry only proto / comID / stage** (`"transport: NVMe IF-SEND proto=… comID=…: %w"`,
  `"transport: NVMe IF-RECV …"`, `"transport: NVMe serial number: %w"`), never payload or key
  bytes; nothing logged.
- **No Go-side copy of data.** `Send` hands the caller's buffer straight to the firmware call and
  does not retain it, per the `opal.Transport` retention contract (firmware/DMA-side copies remain
  beyond zeroization reach — same documented residual as the other carriers).
- **`Serial` is credential-free.** The serial is device-descriptor data used as a public salt, not
  a secret; `Serial()` is read-only and touches no credential.

## Findings / residual

- **Residual (accepted, documented): end-to-end not provable off-hardware.** The NVMe carrier is
  `tamago && amd64` only and cannot run host-side, so real-drive **Opal-session-over-NVMe** and
  **Identify-Controller-salt correctness** are unverified until hardware validation on the
  Swissbit / multi-NVMe board. This is the R-010 class (QEMU/mock vs real SED) and touches
  **R-007/R-008**; the known HW **Discovery0 IF-RECV `EFI_DEVICE_ERROR`** finding is directly
  relevant to the NVMe ReceiveData path. Follow-ups: **QEMU NVMe-passthru mock support (#110)** and
  a **hardware re-run** are pending. No rating change (R-002 Medium, R-003 Low).
- **ADR-0004 layering: verified preserved.** `internal/transport` does not import
  `internal/credential`; the `var _ credential.Serialer = (*NVMe)(nil)` assertion lives in the
  test file, and the method set is identical across build tags, so the guarantee is checked without
  a layering violation. No amendment to ADR-0004 is needed.

## Disposition

APPROVE. A4b is a security-relevant change (a new PBA→SED transport carrier, TB3) but sits
**within the already-Accepted ADR-0011 §3** and ADR-0008's Accepted `tpba.6` amendment — no new
ADR gate. The A4a `sedutil-pbkdf2` contract flips from "fails closed / non-functional" to
**functional pending hardware validation**. The proven raw/Storage-Security path is unchanged
(default constructor untouched); ADR-0004 layering held; NO ComID swap is intentional; fail-closed
holds on zero carriers / unresolved handles / host build / `Serial()` error / nil-`SEDCredential`,
with no cross-carrier fallback. Secret hygiene is intact. The operative residual is
**R-010/R-007/R-008** — end-to-end requires hardware validation (QEMU NVMe-passthru mock + HW
re-run pending).

**Human gate (§5.3/§23):** because this changes the Opal unlock transport path, the human gate is
the Security/Release Owner **merging the A4b PR (#104 follow-on)** after the two independent
reviews above. That PR is not yet open/merged — this record documents the gate definition, not a
completed merge.
