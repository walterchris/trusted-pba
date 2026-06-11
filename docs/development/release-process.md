# Release Process — Trusted PBA

How a Trusted PBA release is produced, qualified, signed, and published.
Elaborates [compliance baseline §16, §18, §19, §24](../compliance-and-secure-development-baseline.md)
and is step 13 of the [secure development process](secure-development-process.md).

- **Owner:** Release Owner (accountable); Security, Compliance, and
  Vulnerability-Response Owners for their gates.
- **Status:** the production release pipeline (signing, anti-rollback, SBOM/
  provenance jobs) is **planned, not yet built** (CI jobs are skeletons, #9;
  signing deferred per ADR-0003). This document is the target process and the
  checklist the first real release must satisfy.

## 1. Principles

- **Release builds run on controlled CI, never on developer workstations**
  (baseline §18/§19). No production signing from laptops.
- **Build/approval separation:** the build is reproducible from a tagged commit;
  approval and signing are a separate, human-gated step (§5.3).
- **Supply-chain target:** SLSA Build L1 at MVP → L2 at first customer release →
  L3 long-term (baseline §19): documented inputs, artifact ↔ source-commit link,
  SBOM, signed artifact, signed provenance.
- **Updates must be safe:** an update must not brick access to encrypted data,
  must preserve/migrate customer policy without weakening it, and must have a
  user-recoverable failure path (baseline §16).

## 2. Pipeline (target)

Release runs the full virtual gate, then the release-only stages:

```
lint → unit → fuzz smoke → SAST → dependency scan → SBOM →
QEMU UEFI smoke → Secure Boot matrix → QEMU mock-Opal integration →
chainload + negative tests
  → release artifact build (controlled CI, tagged commit)
  → artifact signing (production key — human-gated, §5.3)
  → provenance generation (artifact ↔ commit, signed)
  → publish + Declaration of Conformity
```

The pre-release virtual gate is exactly what every PR already runs (CI), so a
release adds the build/sign/provenance/publish stages on top of a green tree, plus
a `check-release-policy` assertion that the shipped default policy is not a test/
`none` configuration.

## 3. Human gates (§5.3)

Before any production release: the **Release Owner** approves the release; the
**Security Owner** confirms the threat-model/risk review; the **Compliance Owner**
confirms the CRA classification and conformity evidence; the **Vulnerability-
Response Owner** confirms no known exploitable vulnerability ships. Production
**signing** and **advisory publication** are themselves human-gated actions.

## 4. Release checklist (DoD §24)

A release is **done** only when every item is checked and recorded in
[`../../evidence/release-checklists/`](../../evidence/):

- [ ] Release checklist instance created and linked to the release tag.
- [ ] All required tests pass on the tagged commit (the full CI gate, green).
- [ ] **SBOM** generated (SPDX/CycloneDX) and stored in `evidence/sbom/`.
- [ ] **Build provenance** generated, linking artifact ↔ source commit, and signed.
- [ ] **Artifact signed** with the production key on controlled CI (not a laptop).
- [ ] **Known vulnerabilities reviewed** — no known exploitable vuln ships
      (Vulnerability-Response Owner); dependency + SAST reports attached.
- [ ] **Risk assessment reviewed** and current (Security Owner).
- [ ] **Threat model reviewed** and current (Security Owner).
- [ ] **CRA classification + conformity evidence** confirmed current
      (Compliance Owner); EU Declaration of Conformity draft updated.
- [ ] **Support period** documented (`support-period.md`).
- [ ] **Secure update path** verified: signed, anti-rollback, recovery-safe; an
      update-verification-failure negative test passes.
- [ ] **Release notes** written; **security-advisory status** checked.
- [ ] **Human Release Owner approval** recorded.

## 5. Emergency / security updates

Security fixes follow the same checklist on an expedited timeline (baseline §15/§16):
triage and fix under the vulnerability process, build/sign on controlled CI,
publish the update **and** a coordinated advisory identifying affected versions,
with the Vulnerability-Response and Release Owner gates. Anti-rollback prevents
re-installing the vulnerable version (risk R-005).

## 6. Gaps to first real release

Tracked, not yet built: the signing/anti-rollback/update pipeline (R-005/R-006),
real SBOM/SAST/dependency-scan CI jobs (#9), `secure-update-design.md`,
`support-period.md`, the conformity-assessment plan, and the DoC draft. Until these
land, only **non-production** virtual builds are produced; `task build` output is
**unsigned** and not a release artifact.
