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

## Authored documents (so far)

Populated as their tickets land; this index links the per-topic docs that now exist.

- **Architecture / ADRs** ([`architecture/adr/`](architecture/adr/)):
  [0001 use TamaGo](architecture/adr/ADR-0001-use-tamago.md) ·
  [0002 UEFI-native PBA](architecture/adr/ADR-0002-use-uefi-native-pba.md) ·
  [0003 Secure Boot model](architecture/adr/ADR-0003-secure-boot-model.md) ·
  [0004 Opal transport](architecture/adr/ADR-0004-opal-transport-abstraction.md) ·
  [0005 virtual test strategy](architecture/adr/ADR-0005-virtual-test-strategy.md) ·
  [0006 chainload mechanism](architecture/adr/ADR-0006-chainload-mechanism.md) ·
  [0007 policy engine + verification](architecture/adr/ADR-0007-policy-engine-and-verification.md) ·
  [0008 go-boot fork](architecture/adr/ADR-0008-go-boot-fork.md) ·
  [0009 boot-path SED unlock](architecture/adr/ADR-0009-boot-path-sed-unlock.md) ·
  [0010 single-hop trust broker](architecture/adr/ADR-0010-single-hop-trust-broker.md)
- **Compliance** ([`compliance/`](compliance/)):
  [CRA scope assessment](compliance/cra-scope-assessment.md) ·
  [CRA classification](compliance/cra-classification.md) ·
  [CRA essential-requirements matrix](compliance/cra-essential-requirements-matrix.md) ·
  [risk assessment](compliance/risk-assessment.md)
- **Security** ([`security/`](security/)):
  [threat model](security/threat-model.md)
- **Development** ([`development/`](development/)):
  [secure-development process](development/secure-development-process.md) ·
  [agent-development process](development/agent-development-process.md) ·
  [release process](development/release-process.md) ·
  [go coding standards](development/go-coding-standards.md) ·
  [branching](development/branching.md)
