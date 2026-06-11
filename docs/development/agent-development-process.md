# AI Agent Development Process — Trusted PBA

How AI agents operate within the [secure development process](secure-development-process.md),
elaborating [compliance baseline §8](../compliance-and-secure-development-baseline.md)
and the role model in §5.2. Trusted PBA is built largely by AI agents under human
accountability; this document is the governing contract for that work.

- **Owner:** Security Owner (process) + the accountable human Owners (§5.1).
- **Governing principle (ISO 27002 A.8.30, interpreted broadly, baseline §4):**
  when AI agents produce code, tests, documentation, architecture, or release
  artifacts, their work is governed like outsourced/externally-assisted
  development — documented rules, reviewed outputs, traceable actions, the same
  test gates as human code, no bypass of change control, version-controlled
  agent-authored docs.

## 1. Roles and separation of duties

**Human roles own accountability** (§5.1): Product, Security, Architecture,
Release, Compliance, and Vulnerability-Response Owners. **Agents do work, not
accountability.**

**Agent roles** (§5.2; definitions in [`.claude/agents/`](../../.claude/agents/)):
Product, Architecture, Implementation, Test, Security-Review, Compliance, and
Release agents.

**The cardinal rule:** *no single agent may implement, approve, and release the
same change.* In practice:

- the **implementation agent** writes product code within its allowed files;
- the **test agent** adds/validates tests (especially negative/fail-closed);
- the **go-reviewer** reviews idiomatic Go;
- the **security-review agent** adversarially reviews security-sensitive behavior
  and **must not** review a change it implemented;
- the **compliance agent** updates risk/threat/CRA evidence;
- a **human Owner** approves anything release- or §5.3-gated.

This mirrors the SDLC review steps (secure-development-process §1, steps 9–11) and
is enforced by spawning reviewers as independent agents from the implementer.

## 2. Scope control (§8.1)

Agents must not: make unrelated changes; expand scope without updating the issue
and design; change security-critical behavior without an ADR; remove or weaken
tests to make CI pass; ignore failing security tools; hardcode secrets; silently
change dependencies; change release/signing config without approval; or bypass
review gates. Touch only the files the task allows; clean up only your own mess
(CLAUDE.md "Surgical Changes").

## 3. Required agent output for every change (§8.2)

Every change reports: **summary of intent · files changed · tests added/changed ·
security impact · documentation impact · known limitations / open questions ·
evidence artifacts produced.** This output is the basis of the PR's security impact
statement and the review record.

## 4. The prompt contract (§8.3)

Every implementation task is dispatched with an explicit contract:

- **scope** and **non-goals**;
- **allowed files/modules** (the agent must stay within them);
- **security constraints** (fail-closed, never-log-secrets, never-weaken);
- **required tests** (including the negative cases);
- **required documentation updates**;
- **definition of done**.

Example (baseline §8.3): *"Implement only the mock Opal transport. Do not change the
UEFI transport or the policy engine. Add unit tests for successful unlock, wrong
password, malformed response, and timeout. Update the Opal security design doc if
mock behavior affects assumptions."*

## 5. Review model (§8.4) and verification

- Implementation agent writes → Test agent adds/validates tests → Security-Review
  agent reviews security-sensitive behavior → Compliance agent checks docs/evidence
  → human Release Owner approves release-relevant changes.
- **Adversarial verification is expected** for security findings: independent
  reviewers default to skepticism, and claims (e.g. "this fails closed") are
  proven, ideally by a **mutation** (delete the guard → a test must turn red).
- Reviewers run, not just reason: build, run the tests/matrices, and reproduce
  before asserting. "Verify before claiming done."

## 6. Traceability and evidence

Agent-authored changes are as traceable as human ones: linked issue, signed-off
commits (DCO), PR with the §8.2 output, committed review records under
[`../../evidence/`](../../evidence/), and risk/threat/CRA updates. Agent-authored
documentation is version-controlled like any other.

## 7. Limits

Agents do not approve their own security-critical work, do not perform §5.3
human-gated approvals, and do not place artifacts on external systems or release
without the responsible human Owner. When an agent is blocked on a decision that is
genuinely a human Owner's, it stops and surfaces the decision rather than guessing.
