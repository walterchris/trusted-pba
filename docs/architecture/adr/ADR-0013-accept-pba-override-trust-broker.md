# ADR-0013: Accept the `pba-override` Security2 trust broker (gated, non-Windows)

## Status
Accepted (2026-07-05) — the §5.3/§23 human gate (security-critical boot behavior) was
satisfied by the Security/Release Owner merging PR #88 (rebase; `main` tip `5fc25fd`)
after the independent security review recorded in
`evidence/security-review-records/2026-07-05-pba-override-trust-broker-82.md`. Follow-up
to **ADR-0012** (the spike/decision record), which deferred the production decision to
this ADR.

## Context
ADR-0012 evaluated a SHIM-style `EFI_SECURITY2_ARCH_PROTOCOL` override that lets the
PBA boot an image it trusts but firmware `db` does **not** — for platforms provisioned
with only our PBA key (so firmware would reject an otherwise-trusted second stage). It
recorded the mechanism, the measured-boot consequence, and a spike plan, and scoped the
capability **away from the Windows/measured-boot path**.

The spike and production build-out (#82, tasks 1–5) are complete and validated:
- **Go/no-go (task 1):** firmware calls an installed runtime-free MS-ABI asm stub and
  honors its verdict; an out-of-`db` image boots under enforcing Secure Boot with no Go
  runtime entered (`spike/security2-override`).
- **Implementation (tasks 2–4):** validation mode `pba-override` (`internal/policy`);
  `verifyAndLoadOverride` (verify → arm → install → `LoadImageBuffer` → restore),
  gated behind `-tags trustbroker`; a runtime-free asm stub authorizing **exactly the
  one PBA-verified buffer** by pointer+size identity, one-shot disarm, tail-calling the
  saved firmware handler on any mismatch. Self-contained QEMU matrix
  (`override-trustbroker.sh`): CONTROL rejects, POS boots, TAMPER fails closed before
  arming. Finding: firmware passes `SourceBuffer` through unchanged, so pointer+size is
  exact — no `memcmp` needed.
- **Measured boot (task 5):** PCR 7 divergence **empirically confirmed**
  (`override-pcr.sh` + a TPM-enabled OVMF from `build-ovmf-tpm.sh` + a guest `EFI_TCG2`
  reader `test/fixtures/tpmread`): the override omits the image's
  `EV_EFI_VARIABLE_AUTHORITY` event from PCR 7, so a BitLocker seal to PCR 7 breaks.

## Decision
**Accept `pba-override` into the tree as a gated, opt-in capability.**

1. **Doubly gated, off by default.** Compiled only with `-tags trustbroker` (absent from
   default and release builds — `release.yml` builds without it) **and** active only for
   a boot entry whose policy explicitly sets `validation: pba-override`. Without the tag,
   a `pba-override` entry **fails closed** ("not built").
2. **Fail-closed, single-buffer, self-restoring.** The override is armed only after
   `imageverify` accepts the image, authorizes exactly that one buffer (pointer+size),
   one-shot disarms on the match, and restores the original firmware handler; any error
   refuses to boot.
3. **Not for the Windows/measured-boot path.** It diverges PCR 7 (breaks BitLocker); the
   Windows path stays firmware-`db` validation (`firmware`/`pba` modes). This is
   documented at the mode, in ADR-0012, and in the threat model (TB2 exception, R-014).
4. **Merge, but keep it inert in shipped builds** until a concrete deployment needs it;
   this ADR accepts the *capability and its gating*, not its default activation.

## Pre-merge requirements (satisfied at merge — PR #88, 2026-07-05)
- ✅ **Independent security review** (security-review-agent) of `feat/trust-broker-override`
  with no unresolved merge-blockers. Round 1 BLOCK (F1 enforcing-SB gate, F2/F3 stub test
  gap) → both resolved → Round 2 APPROVE. Record:
  `evidence/security-review-records/2026-07-05-pba-override-trust-broker-82.md`.
- ✅ **Stub test gap closed:** `internal/tbstub/stub_test.go` drives the real asm stub via a
  host MS-ABI harness across all five branches (armed+match → SUCCESS + one-shot disarm,
  re-call → chain, wrong-size → chain + stays-armed, wrong-ptr → chain, not-armed → chain);
  mutation-proven and re-run by the reviewer.
- ✅ **CI green** on the branch (12/12 checks, including the `internal/tbstub` test under
  Go 1.26.4 via `go-version-file: go.mod`).

## Alternatives Considered
- **Do not build it (stay ADR-0010 single-hop-via-firmware-`LoadImage`).** Simplest and
  the only Windows-safe path, but leaves the our-keys-only custom-loader case unserved.
  Kept as the default; this ADR adds the override alongside, gated.
- **Go reverse-ABI callback stub (full SHIM parity).** Heavier, riskier TamaGo runtime
  work; unnecessary — the C-ABI asm stub + arm-from-Go pattern suffices (ADR-0012).
- **`memcmp`-based authorization.** Was the ADR-0012 default; the spike showed firmware
  passes `SourceBuffer` through, so pointer+size identity is exact and cheaper.

## Security Impact
Adds a deliberate, gated Secure Boot override (R-014). The PBA becomes an authority for
out-of-`db` images **only** in this mode. Mitigations: doubly gated + off by default;
authorizes exactly the pre-verified buffer, one-shot, then restores; fail-closed on every
error; excluded from release builds. Residual: it is, by design, a Secure Boot bypass for
its target — acceptable only for non-measured-boot targets on our-keys-only platforms.
Threat model updated (TB2, R-014); the precise BitLocker PCR-7 seal profile must be
verified against a primary Microsoft source before **any** Windows use (which this ADR
forbids regardless).

## Compliance Impact
CRA integrity (ER-2) / §5.3 boot-chain-validation scope. This ADR + review record are the
evidence that the override was accepted as a gated, non-default capability with the
Windows path explicitly excluded. `risk-assessment.md` gains a scored R-014 at merge.

## Test Impact
`override-trustbroker.sh` (POS/CONTROL/TAMPER), `override-vtpm.sh` (boots under a vTPM),
`override-pcr.sh` (PCR-7 divergence, via `build-ovmf-tpm.sh` + `tpmread`). The stub
mismatch/one-shot test (above) is a pre-merge requirement.

## Rollback Plan
The capability is isolated behind `-tags trustbroker` + the `pba-override` mode; reverting
is dropping the tag/mode (the default boot path is unchanged). Nothing in a shipped build
depends on it.
