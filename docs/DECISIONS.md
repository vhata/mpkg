# Decisions

These entries index agreed direction and repository choices. The linked
specifications carry the detailed requirements; recording a decision does
not claim its implementation exists.

## 2026-11-01: begin replacement implementation

The user authorized implementation against the selected first-release
design, including parallel work and reviewable PRs while unattended.
Final review and landing remain with the user; this does not authorize
production package, service or Docker operations.

Keep the existing `mpkg` helper usable while the replacement is developed
in the `mpkg_manager` Python 3.12 namespace. The implemented command
validates a closed TOML model and produces an immutable nonsecret snapshot.
Separate libraries provide [durable recording](manager-store.md),
[verified host policy and bounded capture](manager-capture.md),
[native](manager-observations.md) and
[Compose](manager-compose-observations.md) observations,
[non-executable comparisons](manager-planning.md), and protected
[Sonarr Port transformation](manager-sonarr-xml.md). These do not expose
host application through the validation command.

Accepted authority, consumers and original verification predicates come
from retained host history. Observations carry explicit identity, source
and time; they do not grant authority. Matching properties do not imply
application readiness or successful functional checks. Imported report
JSON and transformed candidate bytes cannot authorize host effects.
[Protected declaration bindings](manager-protected-bindings.md) add an
explicit trusted recording path with authenticated origin, exact snapshot
and input scope. Bound comparisons always require a current-policy fresh
read. Legacy decision/name captures remain compatible but do not become
bound merely because a declaration supplies a UUID. Complete input closure
and application remain separate gates.

Combined library checks use private temporary stores and synthetic query
responses, including unavailable evidence, retained data, relinquishment
and changed check declarations. This evidence is separate from disposable
mechanism experiments and A1–A12 acceptance. An installed privileged
recorder, worker, apply protocol, attempt history and real native/Docker
acceptance remain future implementation and validation work. The
[declaration guide](manager-declarations.md) owns the schema; the original
first-release contract and acceptance evidence requirements remain in
force.

## 2026-11-01: disposable mechanism execution

The user authorized assembling the isolated guest and running focused
mechanism proofs. Use local private runner/input files and the bound
disposable guest; this scope does not include production package or
service changes, full replacement implementation, or landing branches.

Keep artifact acquisition, guest assembly, source builds, mechanism
observations and product acceptance distinct. The
[execution record](fixtures/2026-11-01-disposable-execution-evidence.md)
records actual results and limitations against the existing design.

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
