# Agent Rules for Trusted PBA

This is a **security-critical pre-boot product.** These rules bind every AI agent
(and human) working in this repo. They mirror the compliance baseline §8 and §26
and complement the four rules in [`CLAUDE.md`](CLAUDE.md). Read both before acting.

## Scope Control
- Make only the changes requested by the issue.
- Do not perform broad refactoring unless explicitly requested.
- Do not modify unrelated modules.
- Do not change security behavior without an ADR.
- Do not change release/signing configuration without explicit approval.

## Security Rules (fail closed, always)
- Fail closed on all authentication, unlock, verification, and policy errors.
- Never boot an untrusted or revoked EFI image.
- Never continue after SED unlock failure.
- Never log secrets, passwords, PINs, keys, or raw unlock material.
- Never commit private keys.
- Never weaken or delete tests to make CI pass.
- Never ignore errors from UEFI calls or Opal transport calls.
- Never silently fall back to insecure behavior.
- Never treat Secure Boot disabled and enabled as equivalent.

## Documentation Rules
For every security-relevant change, update or explicitly confirm "no impact" on:
- `docs/security/threat-model.md`
- `docs/compliance/risk-assessment.md`
- `docs/compliance/cra-essential-requirements-matrix.md`
- the relevant `docs/architecture/` design document
- ADRs where architecture decisions change

## Testing Rules
Every change must include relevant tests. Required where applicable: unit,
negative, QEMU/OVMF, Secure Boot matrix, mock Opal, parser fuzz, policy
verification. Every new Opal command needs mock tests; every new boot-policy path
needs QEMU tests; every negative security case must be tested.

## Evidence Rules
If a change affects release, security, or compliance behavior, update evidence
references under `evidence/`. Do not mark a task complete unless tests and
documentation are complete (Definition of Done, baseline §24).

## Agent Roles & Separation of Duties (baseline §5.2)
Work is divided across role agents; **no single agent may implement, approve, and
release the same change.** Role definitions live in [`.claude/agents/`](.claude/agents/):
- **Implementation** — writes code within the issue's allowed files.
- **Test** — adds/validates tests, including negative security tests.
- **Security Review** — independent, adversarial review against the threat model.
- **Compliance** — updates risk/threat/CRA evidence and traceability.
- Human **Release Owner** approves release-relevant changes (baseline §5.3).

## Output Format (every change)
Report: **summary · files changed · tests run · security impact · documentation
impact · open questions.**
