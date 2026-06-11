# Secure Development Process — Trusted PBA

The secure development lifecycle (SDLC) for Trusted PBA, elaborating
[compliance baseline §7](../compliance-and-secure-development-baseline.md). It
applies to **every** change — human- or agent-authored — to a security-critical
pre-boot product. Companion docs:
[`agent-development-process.md`](agent-development-process.md) (how AI agents
operate within this lifecycle) and [`release-process.md`](release-process.md)
(step 13).

- **Owner:** Security Owner (process); Architecture Owner (design steps).
- **Scope:** all of `cmd/`, `internal/`, `test/`, `docs/`, CI, and the pinned
  go-boot fork.

## 1. Lifecycle (the 13 steps)

Every feature or fix follows these steps in order. Small/trivial changes still pass
every gate, but steps with no applicable content are explicitly recorded as
"no change" (e.g. "threat model: no change") rather than skipped silently.

1. **Requirement** — a linked GitHub issue with a clear goal and acceptance
   criteria. No work without a tracked requirement.
2. **Risk classification** — is the change security-critical (Secure Boot,
   chainloader, Opal unlock, key handling, policy engine, update/signing,
   cryptography, threat-model assumptions)? If so, the ADR and human-gate rules
   (baseline §5.3) apply.
3. **Threat-model update** — update [`../security/threat-model.md`](../security/threat-model.md)
   or explicitly confirm "no change" (baseline §10/§23).
4. **Design / ADR** — for architecture- or security-critical decisions, an ADR
   (`docs/architecture/adr/`, ADR template) authored and, where §5.3 requires,
   human-gated before code.
5. **Implementation** — minimal, in-scope code that matches existing style; check
   every error; fail closed; never log secrets (CLAUDE.md, baseline §12).
6. **Unit tests** — including the host-buildable `!tamago` paths.
7. **Integration tests** — QEMU/OVMF where a boot-path behavior changed.
8. **Security tests** — negative / fail-closed cases for every security behavior
   (baseline §17.2); fuzz for new parsers of attacker-controlled input.
9. **Code review** — idiomatic-Go review (the `go-reviewer` standards) on any
   `.go` change; surgical-change discipline.
10. **Security review** — independent, adversarial review of security-sensitive
    behavior by a reviewer that did **not** implement it (separation of duties).
11. **Compliance evidence update** — risk assessment, CRA matrix, evidence records
    as applicable (baseline §6/§22); a committed review record for
    security-relevant changes.
12. **Merge** — only after the no-merge-without gate (below) is satisfied.
13. **Release qualification** — release-relevant changes additionally go through
    [`release-process.md`](release-process.md) and the Release Owner gate.

## 2. No merge without

A change does not merge unless **all** hold (baseline §7; enforced by branch
protection + CI + review):

- a linked issue / requirement;
- defined acceptance criteria;
- test coverage (incl. negative tests for security behavior);
- a security impact statement (in the PR / agent output);
- a review record (code review; security review for security-relevant changes);
- CI green;
- documentation updated if behavior changed (or an explicit "not needed").

`main` is protected: PR-only, no force-push/deletion, linear history, review
required. Every commit is signed off (DCO `Signed-off-by`). Required status checks
are wired as CI gains real check contexts (#9, #1).

## 3. Security-critical changes

For changes in the §5.3 set (threat model, cryptographic design, boot-chain
validation, Secure Boot behavior, Opal unlock flow, key handling, release signing):
an **ADR is mandatory**, and the relevant **human Owner gate** applies before the
change is considered Accepted/released. These changes never land on the strength of
agent review alone (baseline §5.1: agents do work, humans own accountability).

## 4. Fail-closed and never-weaken rules

Non-negotiable (CLAUDE.md, baseline §8.1): never boot an untrusted/revoked image;
never continue on auth/unlock/policy/verification failure; never treat Secure Boot
enabled and disabled as equivalent; never log secrets; never commit private keys;
never ignore UEFI/transport/crypto errors; never weaken or delete tests to make CI
pass; never change security-critical behavior without an ADR.

## 5. Traceability

Each change is traceable requirement → (threat-model/ADR) → implementation →
tests → review record → evidence. Security-review records live under
[`../../evidence/security-review-records/`](../../evidence/); risk movements are
logged in the risk assessment change log.

## 6. Mapping to ISO 27002

This process implements A.8.25 (secure development lifecycle), A.8.26 (application
security requirements), A.8.27/A.8.28 (secure architecture / coding), A.8.29
(security testing in development), A.8.32 (change management), and — for
agent-authored work — A.8.30 (outsourced development, interpreted broadly per
baseline §4 and [`agent-development-process.md`](agent-development-process.md)).
