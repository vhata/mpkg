# Decisions

These entries index agreed direction and repository choices. The linked
specifications carry the detailed requirements; recording a decision does
not claim its implementation exists.

## 2026-10-31: repository workflow

Use Docket's vendored contract, a sourced TODO queue, an empty review
index, independent review, and shared local/CI checks. Keep Git hooks in
`.githooks` and use a Python 3.12 venv per worktree. The existing standard
library tests need no new test framework or dependency lockfile.

Scheduled extended validation, stacked PRs, and a separate roadmap queue
are deferred while the repository has no expensive system suite or stack
requiring them. Whole-codebase review starts only when requested; the
empty ledger makes that absence visible. Product planning is not authority
to implement the redesigned server manager.

## 2026-10-31: Arch server environment design

- Manage an Arch host's intended software environment, including native
  packages, Docker deployments, configuration, identities, and accountable
  files. Container base distributions are not constrained to Arch.
- Use direct native tooling. Ansible and similar configuration frameworks
  are outside the selected direction; do not create a general playbook
  engine or replace native dependency solvers and container orchestration.
- Record intent separately from applying it. Status reports pending work,
  observed differences, inspection limits, and previous partial failures.
- Report manual configuration edits so the user can keep them as intent
  or restore the recorded version through a separate application step.
- Ask whether to retain or delete persistent data on each retirement.
  Retained and shared resources remain attributable and usable.
- Support version intent where the native source permits it. Observed
  versions are not automatic pins, and permitting upgrades does not
  schedule them. Arch's coordinated upgrade constraints still apply.
- Begin with a conventional Compose application selected from its actual
  deployment definition. Codeman's potential source/build lifecycle is a
  stretch case; native AUR dependency handling remains first-release work.

Sources: [mandate](specs/2026-10-30-server-environment.md),
[user journeys](specs/2026-10-30-server-environment-journeys.md),
[architecture direction](specs/2026-10-31-server-environment-architecture.md),
[resource model](specs/2026-10-31-server-environment-resources.md), and
[milestones](../plans/2026-10-31-server-environment-milestones.md).
