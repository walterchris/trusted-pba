<!-- Trusted PBA PR — change management §23, Definition of Done §24 -->

## Summary
<!-- What does this change do and why? -->

Closes #

## Files changed
<!-- Brief list / rationale for each touched area -->

## Security impact
<!-- Required. State the impact or write "No security impact" with justification. -->

## Tests
- [ ] Unit tests added/updated
- [ ] Negative / fail-closed tests added where security behavior is touched
- [ ] QEMU/OVMF test added/updated (if boot/policy/chainload behavior)
- [ ] Mock Opal tests (if Opal command/session behavior)
- [ ] Parser fuzz target (if a parser is added/changed)
- [ ] `go test ./...` passes locally

## Documentation impact
- [ ] `docs/security/threat-model.md` updated or confirmed no impact
- [ ] `docs/compliance/risk-assessment.md` updated or confirmed no impact
- [ ] `docs/compliance/cra-essential-requirements-matrix.md` updated or confirmed no impact
- [ ] Relevant `docs/architecture/` doc updated or confirmed no impact
- [ ] ADR added/updated (required for security-critical changes — see below)

## Evidence
- [ ] Evidence artifacts under `evidence/` updated (if release/security/compliance behavior changed)

## Gates (baseline §5.3)
- [ ] This change does **not** alter Secure Boot, chainloader, Opal unlock, key handling, crypto, or release/signing behavior — **OR** an ADR is linked and human approval is requested.
- [ ] No secrets, private keys, or raw unlock material added.
- [ ] No tests weakened or deleted to make CI pass.

## Agent attribution
<!-- Which role agents touched this (Implementation / Test / Security-Review / Compliance)?
     Reminder: no single agent may implement, approve, and release the same change. -->
