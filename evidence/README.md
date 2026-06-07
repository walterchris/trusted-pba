# Evidence

Machine- and human-readable evidence artifacts that back the compliance claims in
[`../docs/compliance-and-secure-development-baseline.md`](../docs/compliance-and-secure-development-baseline.md)
(§6, §17.4). Release-relevant evidence is committed here so conformity assessment,
audit, and customer security reviews can trace requirement → risk → design →
implementation → test → release.

| Directory | Contents |
|---|---|
| `risk-assessments/` | snapshots of the living risk assessment per milestone/release |
| `threat-model-reviews/` | dated threat-model review records |
| `test-reports/` | CI test reports, coverage summaries |
| `fuzzing-reports/` | parser fuzzing summaries |
| `sast-reports/` | static analysis output |
| `dependency-scans/` | dependency vulnerability + license scan results |
| `sbom/` | SBOMs (SPDX / CycloneDX) per release |
| `release-provenance/` | build provenance, artifact↔commit links, signed-artifact metadata |
| `code-review-records/` | review records for merged changes |
| `security-review-records/` | independent security-review records |
| `vulnerability-triage/` | vulnerability reports, triage decisions, RCA for Critical/High |
| `release-checklists/` | completed release checklists (DoD §24) |

**Never commit private key material or raw secrets here** (baseline §13).
