# Branching & PR policy

## Branch naming
Work happens on short-lived topic branches off `main`:

| Prefix | Use |
|---|---|
| `feat/<feature-name>` | new functionality |
| `fix/<fix-name>` | bug fixes |
| `chore/<name>` | tooling, deps, CI, repo housekeeping |
| `docs/<name>` | documentation-only changes |

Use lowercase, hyphen-separated names (e.g. `feat/phase-0-skeleton`,
`fix/opal-discovery-parse`).

## `main` is protected
The `protect-main` ruleset enforces:
- no direct pushes — all changes land via pull request;
- no force-push and no deletion of `main`;
- linear history;
- review threads must be resolved before merge.

(Required status checks are added once CI produces real check contexts — see issue #9.)

## Flow
1. Branch from `main` using the prefix above.
2. Implement within the issue's allowed scope (see the issue's prompt contract).
3. Open a PR using the template; **link the issue** (`Closes #NN`).
4. Self-review via the role agents (Implementation → Test → independent
   Security-Review → Compliance) per [`../../AGENTS.md`](../../AGENTS.md).
5. CI must pass (fails closed).
6. Human review and merge — security-critical / release changes also require an ADR
   and explicit human approval (compliance baseline §5.3).

One PR should map to one coherent unit of work; tightly-coupled issues that cannot
be reviewed or verified independently may share a PR if it links all of them.
