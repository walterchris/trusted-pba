# Security Policy

`trusted-pba` is a **security-critical pre-boot product** — it authenticates users,
unlocks self-encrypting drives, and decides which EFI image is allowed to boot. We take
vulnerability reports seriously and are grateful for responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use one of these private channels:

1. **Preferred — GitHub Private Vulnerability Reporting.** Open the repository's
   **Security** tab → **Report a vulnerability**. This creates a private advisory where we
   can triage, discuss, fix, and coordinate disclosure (including a CVE request) in one place.
2. **Email fallback:** <security@9elements.com>. Use this if you can't or prefer not to use
   GitHub. If you need to send sensitive details encrypted, say so in your first mail and we
   will arrange a key.

Please include, as far as you can:

- affected component/path and version or commit,
- a description of the issue and its security impact,
- steps to reproduce or a proof of concept,
- any suggested mitigation.

## Scope

In scope — issues that undermine the product's security guarantees, for example:

- booting an untrusted, unverified, or revoked image;
- bypassing Secure Boot enforcement or the fail-closed behavior;
- leaking SED credentials, keys, or Opal session material;
- unlocking or authenticating against an unintended device;
- memory-safety or parsing flaws reachable from attacker-controlled device/firmware input.

Out of scope — the deliberately documented development posture, for example:

- the **compiled-in test PIN** in the MVP policy (a known placeholder, extractable by
  design; it is replaced by real authentication before any production use — see the README
  and ADR-0011);
- issues that only apply to `-tags` test builds, not the default/release build.

If you're unsure whether something is in scope, report it privately anyway.

## Our commitment

- We aim to **acknowledge** a report within a few business days and to keep you updated as
  we triage and fix.
- We will **credit** reporters who wish to be named, once a fix is available.
- We follow **coordinated disclosure**: we ask that you give us reasonable time to release a
  fix before any public disclosure, and we will work with you on timing.

## Learn more

- [`docs/security/threat-model.md`](docs/security/threat-model.md) — assets, adversaries, and mitigations
- [`docs/compliance/risk-assessment.md`](docs/compliance/risk-assessment.md) — the quantified risk register
- [`CLAUDE.md`](CLAUDE.md) — the non-negotiable security rules the code is held to
