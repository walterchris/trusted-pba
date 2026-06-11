# CRA Scope Assessment — Trusted PBA

Elaborates [compliance baseline §3](../compliance-and-secure-development-baseline.md).
Pairs with [`cra-classification.md`](cra-classification.md) (classification +
conformity path) and [`cra-essential-requirements-matrix.md`](cra-essential-requirements-matrix.md)
(per-requirement evidence).

- **Status:** preliminary self-assessment, pre-release. The formal scope +
  classification review is a release gate (baseline §5.3 / §3.1).
- **Owner:** Compliance Owner (with the Product Owner for market-placement facts).
- **Review cadence:** before MVP, before first customer delivery, before every
  release, and on any change to product purpose, distribution model, or
  network/update capability.

## 1. Is Trusted PBA in scope of the CRA?

The EU Cyber Resilience Act (Regulation (EU) 2024/2847) applies to **products with
digital elements** made available on the EU market in the course of a commercial
activity. Trusted PBA is software (a UEFI application) with digital elements whose
**intended purpose includes a security function** — pre-boot authentication and
self-encrypting-drive unlock.

**Assessment: in scope** once made available on the EU market commercially. This
holds whether it ships as a standalone product, embedded in an OEM firmware/image,
or delivered to customers as a component — the obligations attach to the
manufacturer placing it (or a product integrating it) on the market.

Out-of-scope cases (recorded so the boundary is explicit): purely internal,
non-commercial, never-placed-on-the-market builds; and any future open-source
release **not** monetised/commercialised by us would fall under the CRA's
open-source-steward regime rather than full manufacturer obligations — but the
project is developed to manufacturer-grade requirements regardless, so this changes
process, not engineering.

## 2. Why it is security-relevant (drivers of obligation)

The product runs before the OS and:

- handles the **SED unlock secret** (Opal PIN / key material) — confidentiality;
- controls the **boot flow** and chainloads the OS loader — integrity/availability;
- **verifies EFI images** and interacts with **Secure Boot** state — integrity;
- can enforce a **customer-controlled pre-boot policy** — integrity.

A defect or compromise can boot untrusted code, leak the unlock secret, or deny
access to encrypted data. It is therefore developed as a **security-critical
product** (baseline §2).

## 3. Manufacturer obligations to design for from day one (§3.3)

The CRA essential requirements (Annex I) and processes we build toward, with the
current project locus for each (gaps tracked in
[`cra-essential-requirements-matrix.md`](cra-essential-requirements-matrix.md)):

| Obligation | Current locus |
|---|---|
| Risk-based secure design | threat model, risk assessment, ADRs |
| Secure-by-default configuration | fail-closed policy engine; no debug unlock |
| No known exploitable vulnerabilities at release | vuln review gate (baseline §15), release checklist |
| Security update mechanism | **planned** — `secure-update-design.md`, release process (#10) |
| Vulnerability handling + coordinated disclosure | **planned** — security-policy / CVD docs |
| SBOM generation | CI SBOM stage (skeleton, #9) → release artifact |
| Third-party component due diligence | dependency management (#27), pinned deps + `go.sum` |
| Regular security testing | unit/fuzz/SAST/QEMU matrices in CI (baseline §17) |
| Secure update distribution | **planned** — signed updates, anti-rollback |
| Support-period definition | **planned** — `support-period.md` |
| Technical documentation | `docs/` tree + `technical-documentation-index.md` (planned) |
| Secure installation/use instructions | **planned** — `secure-installation.md`, `secure-operation.md` |
| Conformity-assessment evidence | `evidence/` tree; conformity-assessment-plan (planned) |
| EU Declaration of Conformity readiness | **planned** — DoC draft before first release |

"Planned" items are not blockers for the virtual MVP but **are** blockers for a
first customer release; they are enumerated in baseline §20 and tracked as Phase F /
release-readiness work.

## 4. Consequence

Because the product is in scope and likely an **important product** (see
[`cra-classification.md`](cra-classification.md)), the manufacturer must be able to
demonstrate conformity with the CRA essential cybersecurity requirements and run a
vulnerability-handling process for the defined support period. The development
process (baseline §5–§24) is structured so the evidence for either conformity path
(internal control vs. third-party involvement) can be produced.

## 5. Open questions / decisions deferred to the formal review

- Exact market-placement model (standalone, OEM-embedded, component) — sets which
  entity is "manufacturer" for which placement.
- Confirmation of the Annex III classification (see classification doc).
- Support-period length (CRA expects a period appropriate to the product; to be
  set with the Product Owner).
