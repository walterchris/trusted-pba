# ADR-0008: Pinned go-boot fork for UEFI protocol access

## Status
Accepted — §5.3/§23 human gate satisfied by the Release Owner merging the Phase 5
PR. Authored in Phase 5. Amended 2026-06-10: pin bumped to `v1.6.2-tpba.2`
(additive `LoadImageBuffer`, #46). Amended 2026-06-10: pin bumped to
`v1.6.2-tpba.3` (fork commits `a5b1163` — SSC slot-dispatch fix in our additive
`uefi/storagesecurity.go` — and `558b95b` — `callFn` stack-alignment fix in
upstream's `uefi/uefi.s`; see *Amendment 2026-06-10* below — the patch set is no
longer purely additive).

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
  **`v1.6.2-tpba.3`** (upstream v1.6.2 + our patch set; see Amendment 2026-06-10)
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
mechanical module-path rename + since `v1.6.2-tpba.3` one functional upstream-file
edit, the `uefi.s` alignment fix — see Amendment 2026-06-10), so the diff against
upstream v1.6.2 is small and reviewable; it is **pinned by tag and `go.sum`
hash**; and the added code reuses go-boot's existing, audited call machinery
rather than introducing new ABI code. The transport's MediaId-0 / first-instance
limitations are documented in `internal/transport` and deferred to Phase 8. A missing protocol fails closed
(`New` returns an error). No secrets; the fork carries upstream's license.

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
