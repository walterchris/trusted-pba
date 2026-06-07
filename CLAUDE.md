# CLAUDE.md — Trusted PBA

UEFI-native Pre-Boot Authentication (PBA) for TCG Opal self-encrypting drives,
written in Go on **TamaGo**. It boots under Secure Boot, unlocks the SED, disables
Shadow MBR, and chainloads the real OS bootloader (Windows Boot Manager, shim,
GRUB, or a customer/recovery EFI app) — all without leaving UEFI boot services.

**This is a security-critical pre-boot product.** Treat every change accordingly.

## Project documents

- **[Project plan (product track)](docs/trusted-pba-plan.md)** — goal,
  architecture, building blocks (TamaGo, UEFI boot services, TCG Opal, Storage
  Security Command Protocol, Secure Boot), repo layout, implementation phases, MVP
  definition, success criteria.
- **[Test tooling plan (virtual testing)](docs/test-tooling-plan.md)** — the tools
  we build only to test virtually: Go Opal simulator, EDK2 `MockOpalDxe` driver,
  OVMF/Secure-Boot key material, QEMU runner + harness, fixtures, and the deferred
  QEMU SED model. Decision: **EDK2 mock driver now, QEMU device model later.**
- **[Compliance & secure-development baseline](docs/compliance-and-secure-development-baseline.md)**
  — the development, testing, documentation, and compliance process (CRA, ISO
  27001/27002, SSDF, OWASP SAMM, SLSA). Read this before touching anything
  security-, release-, or evidence-relevant.

## The Four Rules

Behavioral guidelines to reduce common LLM coding mistakes. Bias toward caution
over speed; for trivial tasks, use judgment.

### 1. Think Before Coding
**Don't assume. Don't hide confusion. Surface tradeoffs.** Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First
**Minimum code that solves the problem. Nothing speculative.**
- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

### 3. Surgical Changes
**Touch only what you must. Clean up only your own mess.**
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.
- Remove imports/variables/functions that *your* changes made unused; leave
  pre-existing dead code unless asked.

### 4. Goal-Driven Execution
**Define success criteria. Loop until verified.**
- "Add validation" → "Write tests for invalid inputs, then make them pass."
- "Fix the bug" → "Write a test that reproduces it, then make it pass."
- For multi-step tasks, state a brief plan with a verify step per step.

> Source: the widely-shared four-rule CLAUDE.md derived from Andrej Karpathy's
> observations on LLM coding mistakes
> (github.com/forrestchang/andrej-karpathy-skills).

## Non-negotiable security rules

These come from the plan and the compliance baseline — **fail closed, always:**

- Never boot an untrusted or revoked EFI image. Never silently.
- Never continue to chainload if authentication, SED unlock, or policy
  verification fails.
- Never ignore revocation.
- Never treat Secure Boot disabled and enabled as equivalent, and never silently
  fall back from secure to insecure boot.
- Never log passwords, PINs, keys, raw unlock material, or sensitive Opal session
  data.
- Never commit private keys; never modify firmware Secure Boot variables without
  an explicit provisioning flow.
- Never ignore errors from UEFI calls or Opal transport calls.
- Never change security-critical behavior without an ADR; never weaken or delete
  tests to make CI pass.

## Architecture in one breath

Keep layers separate — **do not mix Opal protocol logic with UEFI transport
code.** The Opal layer depends only on an abstract `TCGTransport` interface so it
is testable without UEFI.

```
trusted-pba.efi
  +-- uefi/       boot services, filesystem, image loading, Secure Boot, storage security protocol
  +-- opal/       discovery, sessions, auth, locking ranges, MBRControl
  +-- transport/  mock | UEFI storage security | future QEMU | real hardware
  +-- policy/     trusted keys, hashes, revocation, boot-target selection
  +-- chainloader firmware-validated Windows path | PBA-validated custom path | recovery
```

For Windows, let firmware validate Windows Boot Manager — do not manually load it.

## Go code rules

Idiomatic, clean Go — enforced by the **go-reviewer** agent in review and by
`gofmt`/`go vet`/`golangci-lint` in CI. Full guide:
[`docs/development/go-coding-standards.md`](docs/development/go-coding-standards.md).

- **Reach for the stdlib before writing a helper** — `io.Writer`/`io.MultiWriter`,
  `errors.Join`, `slices`/`maps`, `cmp.Or`. (The PR #26 `emit()`→`io.MultiWriter`
  miss is exactly what this prevents.)
- Check **every** error; wrap with `%w`; compare via `errors.Is`/`errors.As`. Never
  ignore a UEFI/transport error. Never `panic` on attacker/device input — fail closed.
- **Accept interfaces, return concrete types.** Small interfaces (1–3 methods),
  defined where consumed. `any`, not `interface{}`.
- Least code; no speculative abstraction. Early returns; no global mutable state.
- Doc-comment every exported symbol (start with its name); `gofmt` is mandatory.
- TamaGo-only files: `//go:build tamago && amd64` + a `!tamago` host stub.

## Testing & evidence expectations

- Every feature must have a virtual test path; prefer deterministic tests over
  hardware-dependent ones. Real SED hardware is not required for normal tests.
- Every new Opal command needs mock tests; every new boot-policy path needs QEMU
  tests; every negative security case must be tested; every hardware-only behavior
  needs a documented mock equivalent.
- For security-, release-, or compliance-relevant changes, update the linked docs
  and the evidence references described in the compliance baseline.

## Commits & branches

- **Sign off every commit** with `git commit -s` (DCO `Signed-off-by:` trailer) —
  no exceptions, including amends and squashes.
- Work on `feat/`·`fix/`·`chore/`·`docs/` branches; `main` is protected (PR only,
  no direct/force push). See [`docs/development/branching.md`](docs/development/branching.md).

## Agent output format

For every change, report: **summary · files changed · tests run · security impact ·
documentation impact · open questions.**
