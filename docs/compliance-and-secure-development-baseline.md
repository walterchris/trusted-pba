# Trusted PBA — Compliance and Secure Development Baseline

## 1. Purpose

This document defines the baseline development, testing, documentation, and
compliance process for the Trusted PBA project. The goal is to make the project
developable by AI agents while still producing the evidence needed for later
compliance with:

- EU Cyber Resilience Act (CRA)
- ISO/IEC 27001-style secure development and ISMS practices
- ISO/IEC 27002 Annex A development-related controls
- NIST Secure Software Development Framework (SSDF)
- OWASP SAMM as a maturity model
- SLSA-style software supply-chain integrity
- Future customer security reviews

This is **not** a final legal conformity assessment. It is the engineering process
baseline that should make later conformity assessment, audit, and certification
much easier.

## 2. Product Context

UEFI-native Pre-Boot Authentication environment for self-encrypting drives
(working name **trusted-pba**). It boots as a UEFI application, authenticates
user/device/policy, unlocks a TCG Opal / SED, disables Shadow MBR / sets MBRDone,
chainloads Windows Boot Manager or another EFI application, and enforces a
customer-controlled pre-boot policy.

Security relevance: runs before the OS, handles drive-unlock secrets, controls
boot flow, may verify EFI applications, may affect Secure Boot policy, and may
affect confidentiality, integrity, and availability of the protected system. **It
must be developed as a security-critical product.**

## 3. CRA Baseline Assessment

- **3.1 Likely scope** — If made available on the EU market commercially, treat as
  a CRA product with digital elements. Likely **important product**, likely
  **Annex III Class I** because it acts as a boot manager. Classification must be
  formally reviewed before release.
- **3.2 Consequence** — If confirmed Class I, the manufacturer must demonstrate
  conformity with CRA essential cybersecurity requirements; depending on
  harmonised standards/common specs/certification schemes, this may allow internal
  control/self-assessment or require EU-type examination or full QA. Develop so we
  can support either path.
- **3.3 Requirements to design for from day one** — risk-based secure design,
  secure-by-default configuration, no known exploitable vulnerabilities at
  release, security update mechanism, vulnerability handling process, SBOM
  generation, third-party component due diligence, regular security testing,
  coordinated vulnerability disclosure, secure update distribution, support-period
  definition, technical documentation, secure-installation/use instructions,
  conformity assessment evidence, EU Declaration of Conformity readiness.

## 4. ISO 27001 / ISO 27002 Baseline

ISO 27001 is the organizational process framework. The product is not "ISO 27001
certified"; the organization and process run so they fit an ISMS. Relevant
controls:

```
A.5.8  Information security in project management
A.5.9  Inventory of information and associated assets
A.5.23 Information security for use of cloud services
A.5.31 Legal, statutory, regulatory and contractual requirements
A.5.34 Privacy and protection of PII
A.5.37 Documented operating procedures
A.8.4  Access to source code
A.8.5  Secure authentication
A.8.8  Management of technical vulnerabilities
A.8.9  Configuration management
A.8.15 Logging
A.8.16 Monitoring activities
A.8.24 Use of cryptography
A.8.25 Secure development lifecycle
A.8.26 Application security requirements
A.8.27 Secure system architecture and engineering principles
A.8.28 Secure coding
A.8.29 Security testing in development and acceptance
A.8.30 Outsourced development
A.8.31 Separation of development, test and production environments
A.8.32 Change management
A.8.33 Test information
A.8.34 Protection of information systems during audit testing
```

For AI-agent-based development, **A.8.30 is interpreted broadly**: if AI agents
produce code, tests, documentation, architecture, or release artifacts, their work
is governed like outsourced/externally-assisted development. Agents must follow
documented rules; outputs must be reviewed; actions must be traceable;
agent-created code must pass the same tests as human code; agent changes must not
bypass change control; agent-created documentation must be version controlled.

## 5. Development Governance Model

- **5.1 Required human roles (accountability):** Product Owner, Security Owner,
  Architecture Owner, Release Owner, Compliance Owner, Vulnerability Response
  Owner. AI agents perform work but do not own accountability.
- **5.2 AI agent roles:** Product Agent, Architecture Agent, Implementation Agent,
  Test Agent, Security Review Agent, Compliance Agent, Release Agent. **No single
  agent may implement, approve, and release the same change.**
- **5.3 Mandatory human gates:** initial CRA classification; changes to threat
  model, cryptographic design, boot-chain validation, Secure Boot behavior, Opal
  unlock flow, key handling; release signing; publication of a security advisory;
  closure of a critical vulnerability; release of a production binary.

## 6. Repository Structure for Compliance Evidence

```
trusted-pba/
  cmd/ internal/ test/
  docs/
    product/      product-description.md intended-use.md supported-platforms.md
                  support-period.md user-instructions.md secure-installation.md secure-operation.md
    compliance/   cra-scope-assessment.md cra-classification.md cra-essential-requirements-matrix.md
                  iso27001-control-mapping.md risk-assessment.md conformity-assessment-plan.md
                  technical-documentation-index.md evidence-index.md
    security/     security-policy.md coordinated-vulnerability-disclosure.md threat-model.md
                  attack-surface.md secure-boot-design.md opal-security-design.md cryptographic-design.md
                  key-management.md secure-update-design.md logging-and-monitoring.md residual-risks.md
    architecture/ architecture-overview.md boot-flow.md opal-flow.md chainloader-design.md
                  policy-engine.md testing-architecture.md
                  adr/ ADR-0001-use-tamago.md ADR-0002-use-uefi-native-pba.md
                       ADR-0003-secure-boot-model.md ADR-0004-opal-transport-abstraction.md
    development/  secure-development-process.md agent-development-process.md secure-coding-guidelines.md
                  code-review-guidelines.md test-strategy.md release-process.md change-management.md
                  dependency-management.md ci-cd-security.md
  evidence/
    risk-assessments/ threat-model-reviews/ test-reports/ fuzzing-reports/ sast-reports/
    dependency-scans/ sbom/ release-provenance/ code-review-records/ security-review-records/
    vulnerability-triage/ release-checklists/
```

## 7. Secure Development Lifecycle

Every feature follows: 1. Requirement → 2. Risk classification → 3. Threat-model
update → 4. Design/ADR (if architecture-relevant) → 5. Implementation → 6. Unit
tests → 7. Integration tests → 8. Security tests → 9. Code review → 10. Security
review → 11. Compliance evidence update → 12. Merge → 13. Release qualification.

No code merges without: a linked issue/requirement, defined acceptance criteria,
test coverage, a security impact statement, a review record, CI pass, and updated
documentation if behavior changes.

## 8. AI Agent Development Rules

- **8.1 General:** Do not make unrelated changes. Do not expand scope without
  updating the issue and design. Do not change security-critical behavior without
  an ADR. Do not remove tests to make CI pass. Do not weaken validation checks. Do
  not ignore failing security tools. Do not hardcode secrets. Do not silently
  change dependencies. Do not change release/signing config without approval. Do
  not bypass review gates.
- **8.2 Required agent output for every change:** summary of intent, files
  changed, security impact, tests added/changed, documentation updated, known
  limitations, evidence artifacts produced.
- **8.3 Agent prompt contract:** every implementation task includes scope,
  non-goals, allowed files/modules, security constraints, required tests, required
  documentation updates, definition of done. Example: *"Implement only the mock
  Opal transport. Do not change the UEFI transport or the policy engine. Add unit
  tests for successful unlock, wrong password, malformed response, and timeout.
  Update `docs/security/opal-security-design.md` if mock behavior affects
  assumptions."*
- **8.4 Agent review model:** Implementation Agent writes; Test Agent
  adds/validates tests; Security Review Agent reviews security-sensitive behavior;
  Compliance Agent checks docs/evidence impact; human Release Owner approves
  release-relevant changes.

## 9. Risk Management Process

Maintain a living risk assessment in `docs/compliance/risk-assessment.md`. Each
risk includes: risk ID, asset, threat, attack path, C/I/A impact, likelihood,
severity, mitigations, residual risk, owner, status, linked tests, linked
evidence.

```
R-001 PBA accepts untrusted EFI image
R-002 PBA unlocks SED before authentication succeeds
R-003 Unlock secret leaks through logs
R-004 Attacker modifies PBA policy file
R-005 Rollback to vulnerable PBA version
R-006 Malicious update accepted
R-007 Windows Boot Manager chainload fails after unlock
R-008 MBRDone does not take effect until reboot
R-009 Opal command parser accepts malformed response
R-010 QEMU tests pass but real SED behavior differs
```

Risk review is mandatory: before MVP, before first hardware test, before first
customer delivery, before every release, after every critical vulnerability, and
after every architecture change.

## 10. Threat Modeling

Maintain `docs/security/threat-model.md` with assets, trust boundaries, entry
points, adversaries, assumptions, abuse cases, attack trees, mitigations, residual
risks, test mapping.

Core assets: SED unlock secret, PBA binary, PBA policy, customer trust anchors,
Secure Boot trust chain, Windows Boot Manager handoff, Opal session state, update
signing key, release signing key, SBOM/provenance data.

Required sections: pre-boot attacker, evil-maid attacker, malicious EFI
application, malicious update, rollback attacker, compromised dependency,
compromised AI agent output, compromised CI runner, compromised signing key,
real-drive compatibility failure. **Every security-relevant change must update or
explicitly confirm no change to the threat model.**

## 11. Secure Architecture Principles

Fail closed; least privilege; minimal attack surface; no hidden bypass paths;
explicit trust boundaries; separation of policy and mechanism; defense in depth;
secure defaults; cryptographic agility; reproducible/traceable builds; no secrets
in source; no production keys in CI; no debug unlock paths in production builds.

Product-specific: Do not chainload if authentication fails. Do not chainload if SED
unlock fails. Do not chainload if policy verification fails. Do not treat Secure
Boot disabled and enabled as equivalent. Do not silently fall back from secure to
insecure boot. Do not log passwords, PINs, keys, raw unlock material, or sensitive
Opal session data. Do not accept unsigned policy files in production mode. Do not
allow rollback to vulnerable PBA versions without explicit policy.

## 12. Secure Coding Guidelines

Small functions; explicit error handling; no ignored errors; constant-time
comparison for secrets where applicable; input length checks; bounds checks;
structured logging; no sensitive data in logs; no panics on attacker-controlled
input; fuzz parsers; test malformed inputs; document unsafe operations; minimize
global mutable state.

**Go/TamaGo:** avoid unnecessary `unsafe`; wrap all `unsafe` with justification;
document UEFI pointer ownership/lifetime; check all UEFI status codes; map UEFI
errors to internal errors; zero sensitive buffers where feasible; avoid dynamic
behavior that cannot be tested in QEMU.

**Parsers (fuzz):** TCG Opal response parsing; PE/COFF parsing if implemented;
policy parsing; configuration parsing; device path parsing if custom.

## 13. Cryptographic Controls

Maintain `docs/security/cryptographic-design.md` and `key-management.md`.
Document: algorithms, key sizes, signature formats, hash algorithms, certificate
handling, revocation model, rollback protection, key generation/storage/rotation,
key-compromise process, production and test signing processes.

Rules: Do not invent cryptography. Use standard algorithms/formats. Separate test
and production keys. Do not commit production private keys. Do not allow production
release from developer machines. Document every trust anchor, every
signature-verification decision, and revocation behavior.

## 14. Dependency and SBOM Management

Generate an SBOM for every release (SPDX or CycloneDX): machine-readable,
top-level dependencies at minimum, exact versions, source repo, license, hashes
where available, release-artifact reference.

Process: pin all dependencies; updates require a PR, changelog review,
vulnerability scan, and license check; security-critical dependencies require
architecture/security review. Evidence: `evidence/sbom/`,
`evidence/dependency-scans/`, `docs/development/dependency-management.md`.

## 15. Vulnerability Management

Maintain `docs/security/coordinated-vulnerability-disclosure.md`,
`security-policy.md`, `docs/development/vulnerability-management.md`. Define:
public security contact, private intake, triage, severity scoring, impact
analysis, fix owner, patch timeline, advisory process, customer notification,
regulatory notification assessment, security-update release, postmortem/RCA.

Severity levels: Critical, High, Medium, Low, Informational. Mandatory evidence:
report, triage decision, affected versions, severity rationale, fix commit, tests
added, advisory draft, release note, customer communication, regulatory reporting
assessment, RCA for Critical/High. For CRA readiness, support actively-exploited
vulnerability handling and the early-warning / main / final report flow.

## 16. Security Update Process

Maintain `docs/security/secure-update-design.md` and
`docs/development/release-process.md`. Define how updates are produced, signed,
distributed, verified by users, revoked, and rollback-controlled, plus
emergency-update handling and communication of vulnerable versions.

PBA-specific: update must not brick access to encrypted data; a recovery process
must exist; users must know how to recover from a failed update; update must
preserve/migrate customer policy safely and must not weaken boot policy.

## 17. Testing Strategy

- **17.1 Layers:** unit, native Opal mock, parser fuzz, policy, UEFI smoke,
  QEMU/OVMF, Secure Boot matrix, mock UEFI Storage Security Protocol, chainload,
  negative security, hardware SED, release qualification.
- **17.2 Mandatory categories:** auth success/failure, wrong password, unlock
  success/failure, MBRDone success/failure, missing storage security protocol,
  malformed Opal response, unsupported Opal feature, untrusted/revoked/trusted EFI
  image, Windows firmware-validated handoff, custom PBA-validated handoff, Secure
  Boot enabled/disabled, policy parse failure, policy signature failure, rollback
  attempt, update verification failure.
- **17.3 Security tests:** SAST, secret scanning, dependency vulnerability
  scanning, SBOM validation, fuzzing, negative tests, Secure Boot matrix, tamper
  tests, signature-verification tests, revocation tests, reproducible-build check
  where feasible.
- **17.4 Test evidence per CI run:** test report, coverage where applicable,
  fuzzing summary, SAST report, dependency-scan report, SBOM, build provenance,
  signed-artifact metadata. Store in `evidence/test-reports/`,
  `evidence/fuzzing-reports/`, `evidence/sast-reports/`,
  `evidence/dependency-scans/`, `evidence/release-provenance/`.

## 18. CI/CD Security Baseline

Enforce: protected main branch; mandatory PR review; mandatory CI pass before
merge; signed commits or signed tags for releases; artifact signing; SBOM
generation; build provenance; secret scanning; dependency scanning; SAST; test
report upload; release checklist.

CI stages: lint → unit test → mock Opal test → fuzz smoke → SAST → dependency scan
→ SBOM generation → QEMU UEFI smoke → QEMU Secure Boot matrix → QEMU mock Opal
integration → release artifact build → artifact signing → provenance generation.
**Release builds run on controlled CI, not developer workstations.**

## 19. Supply Chain Integrity

Target: SLSA Build Level 1 (early MVP) → Level 2 (first customer release) → Level 3
(long-term). MVP: consistent build process, documented inputs, build provenance,
artifact↔source-commit link, SBOM, signed artifact. First customer release: hosted
CI release build, signed provenance, protected release workflow, build/approval
separation, no production signing from laptops. Long-term: hardened build platform,
reproducible/hermetic builds where feasible, dependency & artifact verification
instructions for customers.

## 20. Documentation Required Before MVP

`product-description.md`, `intended-use.md`, `cra-scope-assessment.md`,
`cra-classification.md`, `risk-assessment.md`, `threat-model.md`,
`security-policy.md`, `opal-security-design.md`, `secure-boot-design.md`,
`secure-development-process.md`, `agent-development-process.md`, `test-strategy.md`,
`release-process.md`, `architecture-overview.md`, `boot-flow.md`,
`chainloader-design.md`.

Before first customer release, additionally: `support-period.md`,
`user-instructions.md`, `secure-installation.md`, `secure-operation.md`,
`cra-essential-requirements-matrix.md`, `technical-documentation-index.md`,
`conformity-assessment-plan.md`, `coordinated-vulnerability-disclosure.md`,
`secure-update-design.md`, `key-management.md`, `residual-risks.md`.

## 21. CRA Technical Documentation Mapping

The technical documentation package includes: general product description;
intended purpose; supported versions; architecture overview; software component
overview; security design; risk assessment; threat model; development process
description; production/release process description; vulnerability handling
process; SBOM; test reports; security review reports; update mechanism
description; user instructions; support period; conformity assessment plan; EU
Declaration of Conformity draft. Maintain
`docs/compliance/technical-documentation-index.md` pointing to the exact files and
evidence artifacts that satisfy each requirement.

## 22. CRA Essential Requirements Matrix

Maintain `docs/compliance/cra-essential-requirements-matrix.md`. Each row: CRA
requirement, interpretation for Trusted PBA, design control, implementation
artifact, test evidence, documentation evidence, status, owner, open gaps.

Examples — **Secure by default:** production PBA fails closed, does not boot
untrusted targets, no debug unlock (evidence: policy tests, Secure Boot matrix,
release config review). **Vulnerability updates:** release process supports signed
security updates and advisory flow. **Confidentiality:** unlock secrets not logged,
handled only in pre-boot memory, zeroed where feasible. **Integrity:** PBA binary,
policy, and target EFI images verified before use. **Availability:** recovery path
exists if unlock or update fails.

## 23. Change Management

Every change is traceable. Required for every PR: linked issue; risk/security
impact statement; test evidence; review evidence; documentation update or explicit
"not needed". Security-critical changes require an ADR (Secure Boot, chainloader,
Opal unlock, key handling, policy engine, update system, release signing,
cryptography, threat-model assumptions).

```
# ADR-NNNN: Title
## Status        Proposed / Accepted / Rejected / Superseded
## Context
## Decision
## Alternatives Considered
## Security Impact
## Compliance Impact
## Test Impact
## Rollback Plan
```

## 24. Definition of Done

**Feature done** when: requirements documented; security impact assessed; risk
assessment updated if needed; threat model updated if needed; code implemented;
unit tests exist; integration tests where applicable; negative tests for security
behavior; CI passes; documentation updated; evidence artifacts generated; review
complete.

**Release done** when: release checklist complete; all required tests pass; SBOM
generated; artifact signed; provenance generated; known vulnerabilities reviewed;
risk assessment reviewed; threat model reviewed; release notes written; security
advisory status checked; support period documented; human Release Owner approved.

## 25. Immediate Next Steps

1. Add `docs/` and `evidence/` structure. 2. Add `secure-development-process.md`.
3. Add `agent-development-process.md`. 4. Add initial `threat-model.md`. 5. Add
initial `risk-assessment.md`. 6. Add initial CRA scope and classification
documents. 7. Add initial CRA essential requirements matrix. 8. Add PR template
with security/compliance checklist. 9. Add ADR template. 10. Add CI jobs for
tests, SAST, dependency scan, secret scan, SBOM. 11. Add release checklist. 12.
Define AI agent rules in `AGENTS.md` / `CLAUDE.md`.

## 26. AGENTS.md Baseline Rules

```markdown
# Agent Rules for Trusted PBA
This is a security-critical pre-boot product.

## Scope Control
- Make only the changes requested by the issue.
- Do not perform broad refactoring unless explicitly requested.
- Do not modify unrelated modules.
- Do not change security behavior without an ADR.
- Do not change release/signing configuration without explicit approval.

## Security Rules
- Fail closed on all authentication, unlock, verification, and policy errors.
- Never boot an untrusted EFI image.
- Never continue after SED unlock failure.
- Never log secrets, passwords, PINs, keys, or raw unlock material.
- Never commit private keys.
- Never weaken tests to make CI pass.
- Never ignore errors from UEFI calls or Opal transport calls.
- Never silently fall back to insecure behavior.

## Documentation Rules
For every security-relevant change, update or confirm no impact on:
- docs/security/threat-model.md
- docs/compliance/risk-assessment.md
- docs/compliance/cra-essential-requirements-matrix.md
- docs/architecture/ relevant design document
- ADRs where architecture decisions change

## Testing Rules
Every change must include relevant tests. Required where applicable:
unit, negative, QEMU/OVMF, Secure Boot matrix, mock Opal, parser fuzz, policy verification.

## Evidence Rules
If a change affects release, security, or compliance behavior, update evidence references.
Do not mark a task complete unless tests and documentation are complete.

## Output Format
Every agent response must include:
summary; files changed; tests run; security impact; documentation impact; open questions.
```

## 27. Compliance Positioning

Trusted PBA is developed under a documented secure development lifecycle. The
project maintains traceability from requirements to risks, design, implementation,
tests, and release evidence. It maintains SBOMs and vulnerability handling
processes, and generates technical documentation suitable for CRA conformity
assessment. Development governance aligns with ISO 27001 / ISO 27002 secure
development controls, uses SSDF-style practices for secure development and
vulnerability response, and uses SLSA-style build provenance and artifact integrity
controls. AI agents may generate code and documentation, but their outputs are
governed by the same secure development, review, testing, and evidence
requirements as human development.
