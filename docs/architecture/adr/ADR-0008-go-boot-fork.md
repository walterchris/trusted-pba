# ADR-0008: Pinned go-boot fork for UEFI protocol access

## Status
Accepted — §5.3/§23 human gate satisfied by the Release Owner merging the Phase 5
PR. Authored in Phase 5. Amended 2026-06-10: pin bumped to `v1.6.2-tpba.2`
(additive `LoadImageBuffer`, #46). Amended 2026-06-10: pin bumped to
`v1.6.2-tpba.3` (fork commits `a5b1163` — SSC slot-dispatch fix in our additive
`uefi/storagesecurity.go` — and `558b95b` — `callFn` stack-alignment fix in
upstream's `uefi/uefi.s`; see *Amendment 2026-06-10* below — the patch set is no
longer purely additive). Amended 2026-06-11: pin bumped to `v1.6.2-tpba.4`
(commit `6db0670`, full-codebase-audit follow-ups; see *Amendment 2026-06-11*
below). Amended 2026-06-28: pin bumped to `v1.6.2-tpba.5` (handle-aware Storage
Security for the first real-hardware bring-up; see *Amendment 2026-06-28* below).
Amended 2026-07-06: pin bumped to `v1.6.2-tpba.6` (NVMe PassThru transport +
Identify-Controller serial read + ConnectController; for the A4 sedutil-PBKDF2
salt #104 and serial-based drive targeting #81; see *Amendment 2026-07-06* below).

## Context
go-boot v1.6.2 wraps only a **fixed set** of UEFI protocols/services (graphics,
network, simple filesystem, `LoadImage`-by-path, `GetVariable`, `ResetSystem`). It
exposes `LocateProtocol`/`HandleProtocol` (returning a protocol's address) but **no
way to *call* an arbitrary located protocol's methods** — the UEFI-ABI call
trampoline (`callService`/`callFn`) and the struct reader (`decode`) are
unexported, and there is no Storage Security support.

This is the **third** time go-boot's surface has blocked us: the RTC `GetTime` gap
(pre-boot time), `LoadImage`-from-buffer (#46, the verify-then-load TOCTOU), and now
`EFI_STORAGE_SECURITY_COMMAND_PROTOCOL.SendData`/`ReceiveData` — the carrier the
Phase 5 Opal transport (EPIC #21) requires. Calling a firmware function pointer
needs the Microsoft x64 ABI; there is no pure-Go way to do it.

## Decision
Maintain a **pinned fork** of go-boot and keep all firmware-ABI code in that
dependency layer (rather than adding `unsafe`/assembly to the product).

- **Fork:** `github.com/walterchris/go-boot`, branched from upstream **v1.6.2**. Its
  module path is renamed to `github.com/walterchris/go-boot`; the Trusted PBA
  imports it **by that name** (a plain `require`, no `replace` — replace-with-rename
  causes a "module used for two paths" conflict). Pinned by the tag
  **`v1.6.2-tpba.5`** (upstream v1.6.2 + our patch set; see the Amendments below)
  and locked in `go.sum`.
- **Addition (minimal, additive):** one file `uefi/storagesecurity.go` —
  `GetStorageSecurity()` (locate + resolve `ReceiveData`/`SendData` pointers via the
  existing `decode`) and `SendData`/`ReceiveData` (via the existing `callService`).
  We did **not** write new ABI/assembly; we reuse go-boot's audited primitive.
- **Re-base process:** track upstream; on a bump, re-fork from the new tag, re-apply
  the (small, additive) patch, re-tag `vX.Y.Z-tpba.N`, update `go.mod`/`go.sum`.
  Keeping the patch additive (no edits to upstream files beyond the mechanical
  module-path rename) keeps re-base cheap. The fork's open follow-ups (GetTime,
  `LocateHandleBuffer` + `EFI_BLOCK_IO` MediaId for real hardware) land as further
  additive files; `LoadImageBuffer` (#46) landed this way in `v1.6.2-tpba.2`
  (`uefi/loadimagebuffer.go`). *(Superseded in part by the Amendment 2026-06-10
  below: the patch set now also carries one functional edit to an upstream file.)*

## Amendment (2026-06-10): `v1.6.2-tpba.3` — UEFI ABI fixes

The first real execution of the fork's Storage Security call path — the Phase 6
MockOpalDxe QEMU integration matrix (#22) — crashed with #GP faults and exposed
two bugs, fixed in `v1.6.2-tpba.3`:

1. **`a5b1163` — SSC slot-dispatch fix (our additive `uefi/storagesecurity.go`).**
   `callFn` dispatches memory-indirect (`CALL (DI)`), so it must be passed the
   protocol member-slot *address* (`base+0x00`/`base+0x08` per UEFI 2.10 §13.14),
   not the resolved pointer *value*; the pre-fix double dereference was a
   deterministic wild jump into the callee's prologue bytes. The fix also adds a
   **fail-closed NULL-slot check**: NULL `ReceiveData`/`SendData` slots return an
   error instead of ever calling address 0.
2. **`558b95b` — `callFn` stack-alignment fix (upstream's `uefi/uefi.s`).** The
   MS x64 / UEFI ABI requires RSP ≡ 0 mod 16 at CALL, i.e. a pad iff the pushed
   stack-argument count is odd; the old pad fired only for exactly one pushed
   argument. This is a **latent upstream bug**, not one our additions introduced:
   upstream's own SNP `Transmit`/`Receive` (`uefi/net.go`, 7-argument calls) are
   equally affected, not only our `SendData`.

**The patch set is therefore no longer purely additive.** It now contains exactly
**one functional edit to an upstream file**: the `callFn` stack-alignment pad in
`uefi/uefi.s` (2 instructions + comment). It cannot be made additive: `callFn` is
the single shared ABI trampoline through which every firmware call dispatches,
and duplicating it in-repo was already rejected by this ADR (*Alternatives
Considered*, in-repo `unsafe`+asm primitive).

**Re-base process update:** on every upstream re-fork, re-apply the additive
files **and** the `uefi.s` patch, explicitly re-reviewing that small diff. We
commit to submitting the alignment fix upstream to `usbarmory/go-boot` and
dropping the local patch once an upstream release contains it.

**Security impact update:** the fork-vs-upstream diff now includes assembly in
the TCB call path. Mitigations: the diff is tiny and individually reviewed (the
independent security review re-derived the alignment requirement and enumerated
every call site by argument count — regression surface none); the pin is by
tag and `go.sum` hash; the review record is committed. The storage-security
surface additionally gained the fail-closed NULL-slot check above.

**Evidence:** the QEMU mock-Opal integration matrix (#GP faults before the fix,
passing matrix after) and the committed review record
`evidence/security-review-records/2026-06-10-go-boot-tpba3-abi-fixes.md`.

## Amendment (2026-06-11): `v1.6.2-tpba.4` — full-codebase-audit follow-ups

The 2026-06-11 full-codebase audit surfaced four fork items, batched into
`v1.6.2-tpba.4` (commit `6db0670`):

1. **F-L5 — `uefi/path.go` device-path Length guard (upstream file).** `devicePath()`
   rejected only `Length == 0 || > 0xff`; a node `Length` of 1..3 made
   `dataSize = uint16(Length-4)` underflow to ~65533 and the `copy` slice past the
   DMA buffer — a panic reachable on every chainload via `LoadImageBuffer→FilePath`.
   Now rejects `Length < 4` (the 4-byte generic node header minimum). The device-path
   producer is platform firmware (trusted at this boundary), so fail-closed in effect,
   but it violated the function's own anti-DoS intent.
2. **F-S3 — typed EFI status errors (upstream `uefi/error.go`).** `parseStatus` now
   wraps `EFI_NOT_FOUND` as `ErrEfiNotFound` and other non-success statuses as the
   new `ErrEFIStatus` sentinel, so callers can branch with `errors.Is`.
3. **F-S4 — `uefi/uefi.s` `dummy:` block: kept, comment rewritten.** The audit flagged
   the unreachable `POPQ` pair as dead code; it is **not** — it satisfies the Go
   assembler's per-function PUSH/POP balance check (removing it fails assembly with
   `unbalanced PUSH/POP`, verified). Comment rewritten so it no longer reads as
   removable; **no functional change** (audit false positive recorded).
4. **F-S5 — `uefi/storagesecurity.go` (our additive file): naming.** `SendData`'s
   laundered payload pointer renamed `buf`→`ptr` to match `ReceiveData`.

This **adds two more upstream-file edits** (`path.go`, `error.go`) on top of the
`uefi/uefi.s` edit, plus a comment-only `uefi.s` touch. The re-base process
(re-apply + re-review the upstream diff; upstream the changes) now covers
`uefi.s` + `path.go` + `error.go`. The `path.go` underflow guard and the `error.go`
typed errors are good upstream-PR candidates alongside the alignment fix.

**Evidence:** the Trusted PBA QEMU mock-Opal matrix (full unlock→MBRDone→chainload,
which exercises `devicePath`) passes against this tree; the published tag's `go.sum`
hash was verified byte-identical to the pinned commit.

## Amendment (2026-06-28): `v1.6.2-tpba.5` — handle-aware Storage Security

The **first real-hardware bring-up** (a Swissbit OPAL drive on a 4-NVMe test
board) hit the limitation this ADR deferred to Phase 8: real firmware exposes one
`EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` handle **per NVMe drive**, and go-boot's
`GetStorageSecurity()` (built on `LocateProtocol`) returns the *first* instance —
on the test board a non-Opal disk that rejects TCG commands with
`EFI_DEVICE_ERROR`. The fork gains the additive primitives needed to enumerate and
address handles individually, batched into `v1.6.2-tpba.5`:

1. **`LocateHandleBuffer` boot-services wrapper** + the `EFI_LOCATE_SEARCH_TYPE`
   constants (`AllHandles`/`ByRegisterNotify`/`ByProtocol`) and a **`FreePool`**
   wrapper (boot-services slot `0x48`) to release the firmware-allocated handle
   buffer. These are thin, additive wrappers over go-boot's existing audited
   `callService` primitive — no new ABI/assembly.
2. **Handle-aware Storage Security (additive `uefi/storagesecurity.go`):**
   `LocateStorageSecurityHandles()` (enumerate every SSC carrier handle via
   `LocateHandleBuffer` by the Storage Security protocol GUID) and
   `GetStorageSecurityByHandle(h)` (resolve `SendData`/`ReceiveData` for a *named*
   handle via the existing `decode`), plus the internal `newStorageSecurity` helper
   they share with the original `GetStorageSecurity()`. The original locate-first
   call is retained; the new entry points let the **caller** enumerate carriers and
   pick the Opal SED.

**Rationale:** real systems need handle enumeration to find the SED among multiple
Storage Security carriers; the transport cannot assume the first instance is the
SED. Selection itself (Level-0 Discovery probe) is **Opal protocol logic and stays
out of go-boot** — `internal/transport.NewAll()` returns one transport per handle
and `cmd/pba selectSED` chooses (see ADR-0009 Amendment 2026-06-28).

**MediaId stays 0 — the earlier "minimal MediaID-only" / `EFI_BLOCK_IO` path is
DROPPED.** The deferred-to-Phase-8 follow-up that this ADR contemplated ("deriving
the real MediaId from `EFI_BLOCK_IO`") was disproven on hardware: the SED answers
Discovery and unlock with **MediaId 0**, so no `BlockIo`/`MediaId` derivation was
added to the fork. `tpba.5` adds **only** the handle-enumeration surface above.

**Still additive.** `tpba.5` adds new wrappers/files only; it does not add a new
upstream-file edit beyond the three carried since `tpba.3`/`tpba.4` (`uefi.s`,
`path.go`, `error.go`). The re-base process (re-apply + re-review the upstream
diff; upstream the functional edits) now also re-applies the
`LocateHandleBuffer`/`FreePool` and handle-aware-SSC additive files.

**Security impact update:** the new surface is enumeration + per-handle resolution
only; it changes *which* carrier the transport talks to, not the unlock security
model (still Admin1-PIN-authenticated, fail-closed — see ADR-0009 Amendment). A
handle whose protocol cannot be resolved is skipped (not a usable carrier); zero
usable carriers fails closed. The pin remains by tag + `go.sum` hash; published-tag
hash verified. The `tpba.5` bump also pulled new **indirect** deps into `go.sum`
(the usbarmory stack: `gvisor`, `gliderlabs/ssh`, `arl/statsviz`, `armory-boot`,
`go-net`, `x/term`/`x/time`/`x/exp`, etc.); these are **not reachable from the
`tamago && amd64` `trusted-pba.efi` build graph** (build-graph reachability being
verified separately), and the #27 dependency scan covers the fork's transitive set
(see `docs/development/dependency-management.md`, R-006).

**Evidence:** the first real-hardware bring-up record
`evidence/security-review-records/2026-06-28-opal-hw-bringup-handle-select-comid.md`
(real-drive selection + ComID byte-order root-cause chain; review verdicts); the
Trusted PBA QEMU mock-Opal matrix still passes against the bump (the EDK2 mock is
single-handle, so the host-side selection collapses to picking that one); the
published tag's `go.sum` hash recorded.

### Amendment 2026-07-06 — pin bumped to `v1.6.2-tpba.6`

Adds `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` (`uefi/nvmepassthru.go`: handle
enumeration + per-handle resolution, NVMe **Security Send/Receive** as an
alternative Opal carrier, and **Identify Controller** → `SerialNumber()` returning
the drive's 20-byte serial) and `ConnectController`/`DisconnectController`
(`uefi/protocol.go`). Motivation: the **A4 `sedutil-pbkdf2` credential derivation
salt is exactly the 20-byte NVMe serial** (#104), and serial-based **drive
targeting** (#81) needs the same; the NVMe-passthru carrier is the README's
"NVMe PassThru transport" (firmware whose Storage-Security mediation is
unreliable).

**Still additive.** New files/wrappers only, reusing the existing admin-queue
`submit()` and `LocateHandleBuffer`/`HandleProtocol`; no new upstream-file edit
beyond the three carried since `tpba.3`/`tpba.4` (`uefi.s`, `path.go`, `error.go`).

**Security impact:** the new surface is NVMe admin-command submission (Security
Send/Receive + read-only Identify) and controller (dis)connect. `SerialNumber()`
reads device-descriptor data — the serial is **not secret** (it is used only as a
public salt). None of it is wired into the boot path by this bump alone (A4 wires
the salt; the NVMe carrier is not yet selected), so the pin bump changes no runtime
behavior. Pinned by tag + `go.sum` hash (published-tag hash recorded). No new
external/indirect deps beyond the `tpba.5` set (first-party fork code); the #27
scan set is unchanged. R-006 unchanged.

**Amendment note (2026-07-06, A4b #104):** the additive `tpba.6` NVMe-passthru
surface is now **consumed** — the new `internal/transport` NVMe carrier (A4b) uses
`EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` (Locate/Get handles, SecuritySend/SecurityReceive,
and Identify-Controller `SerialNumber`) as a second `opal.Transport` carrier that
also exposes the drive serial (the sedutil-pbkdf2 salt) via `credential.Serialer`.
So "not yet selected" above no longer holds: `cmd/pba run()` selects the NVMe
carrier for the `sedutil-pbkdf2` derive. Status unchanged (Accepted); no fork change.

## Alternatives Considered
- **In-repo `unsafe`+asm UEFI-call primitive** — keeps everything in our tree but
  duplicates go-boot's `callFn` ABI trampoline and puts hand-written assembly in a
  security-critical product. Rejected (owner decision) in favour of the fork.
- **Upstream PR to usbarmory/go-boot, then pin the release** — cleanest long-term
  and we may still do it, but it blocks the roadmap on an external maintainer's
  review/release timing. Rejected as the immediate path.

## Security Impact
The fork is part of the trusted computing base. Risk: divergence from / unreviewed
changes vs upstream. Mitigations: the patch is **minimal** (additive files + a
mechanical module-path rename + a few small functional upstream-file edits — the
`uefi.s` alignment fix, the `path.go` Length guard, and the `error.go` typed
errors; see Amendments 2026-06-10 and 2026-06-11), so the diff against upstream
v1.6.2 is small and reviewable; it is **pinned by tag and `go.sum` hash**; and the added code reuses go-boot's existing, audited call machinery
rather than introducing new ABI code. As of `v1.6.2-tpba.5` the first-instance
limitation is resolved (handle enumeration; see Amendment 2026-06-28) and MediaId 0
is confirmed correct on hardware. A missing protocol / zero usable carriers fails
closed (`NewAll` returns an error). No secrets; the fork carries upstream's license.

## Compliance Impact
The fork must be onboarded under §14 dependency management (#27) and recorded in the
SBOM/provenance (§19) as a first-party-maintained dependency pinned by tag + hash.
§5.3/§23 satisfied by approving this ADR. Threat model "compromised dependency"
(§6.6) and risk R-006 are updated to name the fork.

## Test Impact
`internal/transport` builds under TamaGo against the fork and has a `!tamago` host
stub with a fail-closed test (no carrier off-target → Opal client fails closed). The
real `SendData`/`ReceiveData` path is exercised end-to-end in **Phase 6** (EDK2
`MockOpalDxe` in QEMU) and **Phase 8** (hardware); it cannot be unit-tested on the
host (no firmware).

## Rollback Plan
Revert the imports (`walterchris` → `usbarmory`) and `go.mod` to upstream v1.6.2.
This removes Storage Security (blocking Phase 5+ unlock) but leaves Phases 0–4
unaffected, since only `internal/transport` (Phase 5) consumes the new protocol.
