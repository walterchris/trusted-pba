# Record — go-boot fork v1.6.2-tpba.4 (audit follow-ups)

- **Date:** 2026-06-11
- **Change:** go-boot fork tag **`v1.6.2-tpba.4`** (commit `6db0670` over
  `v1.6.2-tpba.3`) + the Trusted PBA pin bump and ADR-0008 amendment.
- **Source:** the 2026-06-11 full-codebase audit (deferred fork items F-L5 /
  F-S3 / F-S4 / F-S5, tracked in issue #11).
- **Nature of this record:** direct implementation with local verification — the
  independent multi-agent review pipeline was unavailable (org spend limit). The
  audit is the review input; this record captures the disposition and the
  verification actually run. An independent adversarial pass can be run on the
  pin-bump PR once budget allows.

## Findings dispositioned

| # | File (upstream?) | Disposition |
|---|------------------|-------------|
| F-L5 | `uefi/path.go` (upstream) | **Fixed.** `devicePath()` rejected only Length 0 / >0xff; Length 1..3 underflowed `uint16(Length-4)` → OOB copy → panic on every chainload via `LoadImageBuffer→FilePath`. Now rejects `Length < 4`. Firmware-produced (trusted) so fail-closed in effect, but it broke the function's own anti-DoS intent. |
| F-S3 | `uefi/error.go` (upstream) | **Fixed.** `parseStatus` returns typed errors (`ErrEfiNotFound` for EFI_NOT_FOUND, new `ErrEFIStatus` otherwise) so callers can `errors.Is`. |
| F-S4 | `uefi/uefi.s` (upstream) | **Not removed — audit false positive.** The unreachable `dummy:` `POPQ` pair satisfies the Go assembler's per-function PUSH/POP balance check; removing it **fails assembly** with `unbalanced PUSH/POP` (verified empirically). Kept; comment rewritten so it no longer reads as dead code. No functional change. |
| F-S5 | `uefi/storagesecurity.go` (our additive file) | **Fixed.** `SendData`'s laundered payload pointer renamed `buf`→`ptr` to match `ReceiveData`. |

## Verification

- `GOOS=tamago … go build`/`go vet` of `github.com/walterchris/go-boot/uefi` — clean.
- F-S4 removal empirically rejected: assembler errored `callFn: unbalanced PUSH/POP`.
- Full Trusted PBA TamaGo build (`task build`) against the fork — OK.
- **QEMU mock-Opal matrix** (`task mock-opal-matrix`, full unlock→MBRDone→chainload
  incl. the path that exercises `devicePath`) — 6/6 PASS + harness self-test.
- Pin integrity: the published `v1.6.2-tpba.4` `go.sum` `h1:` hash was confirmed
  byte-identical to the pinned commit via an independent `GOPROXY=direct` fetch.

## Residuals / follow-ups

- The fork now carries three small functional upstream-file edits (`uefi.s`,
  `path.go`, `error.go`) plus the additive files. Re-base re-applies and
  re-reviews them (ADR-0008). All three are upstream-PR candidates to
  `usbarmory/go-boot`; submitting them and dropping the local patches remains the
  long-term exit (tracked under the fork's re-base process / #27).
- This change touched no Secure Boot, chainload-policy, key, or secret-handling
  behavior; no new threat introduced (R-006 wording refreshed only).
