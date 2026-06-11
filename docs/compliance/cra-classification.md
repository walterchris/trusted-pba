# CRA Classification — Trusted PBA

Elaborates [compliance baseline §3.1–§3.2](../compliance-and-secure-development-baseline.md).
Pairs with [`cra-scope-assessment.md`](cra-scope-assessment.md).

- **Status:** preliminary. **The classification must be formally reviewed and
  confirmed before release** (baseline §3.1, §5.3 human gate).
- **Owner:** Compliance Owner.

## 1. Preliminary classification

The CRA splits products with digital elements into the default category and two
higher-criticality sets: **important** products (Annex III, Classes I and II) and
**critical** products (Annex IV). Classification drives which conformity-assessment
routes are available.

**Preliminary determination: important product, Annex III — Class I.**

**Rationale.** Annex III lists "boot managers" among important products. Trusted PBA
**acts as a boot manager**: it runs before the OS, selects a boot target, and
transfers control to the OS loader (chainloading Windows Boot Manager / shim / GRUB
/ a customer EFI app). It also performs a security function (pre-boot authentication
and SED unlock). Boot managers sit in Annex III Class I, which is the more likely
fit than Class II (which covers a narrower, higher-criticality set such as
hypervisors, OS, and certain security appliances). We therefore classify
conservatively as **at least Class I** and design to satisfy it.

This is a self-assessment input, not a determination: the **formal review before
release** confirms the class (and revisits if the product's function broadens, e.g.
toward firmware-level or hypervisor-adjacent behavior that could argue Class II).

## 2. Conformity-assessment consequence

| Class | Available conformity routes (simplified) |
|---|---|
| Default | Internal control (self-assessment) |
| **Important Class I** | **Internal control IF a harmonised standard / common specification / cybersecurity certification scheme is applied and covers the requirements; otherwise a third-party route** (EU-type examination, or full-QA) |
| Important Class II | Third-party involvement effectively required |
| Critical | Possible mandatory certification under a scheme |

For our preliminary **Class I**: if applicable harmonised standards or common
specifications exist and we apply them fully, **internal control / self-assessment**
may suffice; otherwise a **third-party conformity assessment** (notified body) is
required. Because the harmonised-standards landscape is still maturing, we develop so
that **either path is supportable** (baseline §3.2): complete technical
documentation, a conformity-assessment plan, security review records, and an EU
Declaration of Conformity draft.

## 3. What this requires of the project

- **Formal-review-before-release gate** (§5.3): no production release until the
  Compliance Owner confirms the classification and the chosen conformity route.
- **Technical documentation package** sufficient for the chosen route
  (`technical-documentation-index.md`, baseline §21) — planned before first
  customer release.
- **Essential-requirements evidence** maintained continuously
  ([`cra-essential-requirements-matrix.md`](cra-essential-requirements-matrix.md)).
- **Conformity-assessment plan** recording the chosen route and the
  standards/specs relied upon (planned).

## 4. Status of inputs

| Input | Status |
|---|---|
| Product acts as a boot manager (Annex III trigger) | confirmed by design (ADR-0002, chainloader) |
| Performs a security function (PBA / SED unlock) | confirmed by design |
| Class I vs II determination | **preliminary Class I — formal review pending** |
| Applicable harmonised standards / common specs identified | **open** — to assess at formal review |
| Conformity route chosen | **open** — depends on the above |
