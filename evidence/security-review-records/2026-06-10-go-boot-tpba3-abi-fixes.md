# Security review record — go-boot fork v1.6.2-tpba.3 (UEFI ABI fixes)

- **Date:** 2026-06-10
- **Change under review:** go-boot fork tag **`v1.6.2-tpba.3`** (final commit
  `558b95b`; reviewed at content-identical `bd79310` before a message-only
  amend — module h1 hash unchanged, re-verified by fresh fetch after publish).
  Two commits over `v1.6.2-tpba.2`:
  1. `uefi/storagesecurity.go` — fix SSC dispatch double-dereference (pass the
     protocol member-slot address `base+0x00/0x08` to `callService`, not the
     resolved pointer value) + fail-closed NULL-slot check.
  2. `uefi/uefi.s` — fix `callFn` 16-byte stack alignment: old pad fired only
     for exactly one pushed argument; now pads for ANY odd stack-arg count.
- **How found:** the Phase 6 MockOpalDxe QEMU integration matrix — the
  first-ever real execution of this call path — crashed with #GP faults; both
  bugs were root-caused from crash frames and disassembly.
- **Reviewer:** independent security-review agent (did not implement).
- **Verdict:** pass-with-findings — **GO for the tag**, with the ADR-0008
  amendment gating the TrustedPBA pin bump.

## What the review verified (re-derived, not trusted)

1. **Fix 1:** `callFn` dispatches memory-indirect (`CALL (DI)`, `ff 17`) — the
   operand must be the slot address; every other call site in the tree passes
   one (firmware-table `base+offset` or decoded-slot addresses);
   `storagesecurity.go` was the single deviating site; offsets 0x00/0x08 match
   EFI_STORAGE_SECURITY_COMMAND_PROTOCOL (UEFI 2.10 §13.14); `LoadImageBuffer`
   and all other sites clean of the bug class. The pre-fix code was a
   deterministic wild jump into the callee's prologue bytes — matching the
   observed `RIP=0x56415741E5894855`.
2. **Fix 2:** derived the alignment requirement from the MS x64 / UEFI ABI
   (RSP ≡ 0 mod 16 at CALL): pad needed iff stack-arg count is odd; the old
   code padded only for count==1; the new code is correct for all counts.
   **Regression surface: none** — enumerated every call site by arg count
   (1,2,3,4 register-only; 5 = 1 stack arg, padded identically before and
   after; 6, 8, 10 even, never padded; 7 = the previously-undefined case).
3. **Fail-closed:** NULL ReceiveData/SendData slots error out (address 0 never
   called); `LocateProtocol` status checked; zero-base rejected by `decode`;
   no payload/session data logged. Residual: a corrupt non-NULL slot or
   firmware rewriting the slot post-check is undetectable — firmware is
   trusted at this boundary per the threat model.
4. **Upstream relevance:** the alignment bug is latent in upstream go-boot
   itself — SNP `Transmit`/`Receive` (uefi/net.go) are 7-argument calls with
   the same misalignment (the original commit message claimed otherwise; fixed
   before the tag was published, per this review's finding 1). The fix should
   be submitted upstream to usbarmory/go-boot.

## Findings and resolution

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | NIT | Commit message falsely claimed upstream never makes odd stack-arg calls | message amended (SNP Transmit/Receive named), tag recut before publish |
| 2 | INFO | Fix quality: minimal (2 instructions + comment in uefi.s), convention-consistent, fail-closed; nothing else in upstream files changed | none required |
| 3 | REQUIRED | `uefi.s` edit violates ADR-0008's additive-only invariant — amendment must land with the pin bump | ADR-0008 amended in the same TrustedPBA change set |
| 4 | REQUIRED | R-006 / threat-model §6.6 "minimal additive patch" wording + tpba.2 pin references stale | updated in the same change set |

## Disposition

Tag `v1.6.2-tpba.3` published; TrustedPBA pin bump rides with the Phase 6
integration PR carrying the ADR-0008 amendment. The fork-vs-upstream diff now
contains one functional upstream-file edit (the trampoline alignment fix) —
re-applied and explicitly re-reviewed on every upstream re-base until the fix
lands upstream and the local patch is dropped.
