# Documentation index

Two layers of documentation live here:

## Consolidated overview docs (start here)
- [`trusted-pba-plan.md`](trusted-pba-plan.md) — product plan (goal, architecture, phases, MVP).
- [`test-tooling-plan.md`](test-tooling-plan.md) — virtual test tooling (EDK2 mock now, QEMU later).
- [`compliance-and-secure-development-baseline.md`](compliance-and-secure-development-baseline.md) — the development & compliance process.

## Granular docs (compliance baseline §6 / §20 structure)
These directories hold the per-topic documents required for CRA/ISO evidence.
Each is filled in via its own ticket; until then it may be empty or a stub.

| Directory | Holds |
|---|---|
| [`product/`](product/) | product-description, intended-use, supported-platforms, support-period, user/secure-installation/operation instructions |
| [`security/`](security/) | threat-model, security-policy, CVD, secure-boot/opal/crypto/key-management/secure-update design, logging, residual-risks |
| [`compliance/`](compliance/) | CRA scope/classification, CRA essential-requirements matrix, ISO 27001 mapping, risk-assessment, conformity plan, tech-doc & evidence index |
| [`architecture/`](architecture/) | architecture-overview, boot/opal/chainloader flows, policy engine, testing architecture, [`adr/`](architecture/adr/) |
| [`development/`](development/) | secure-development & agent-development process, secure-coding & code-review guidelines, test strategy, release/change/dependency mgmt, CI/CD security |

Required-before-MVP and required-before-customer-release doc sets are listed in the
compliance baseline §20.
