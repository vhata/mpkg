# Working on mpkg

The existing helper remains usable while its replacement is designed.

<!-- docket:begin -->

## Docket

This project is run with docket. Read [docket/CONTRACT.md](docket/CONTRACT.md) before any work; it is the authoritative workflow, and this section records only this project's settings. The installer keeps this section current: the text above the list is rewritten on every run, the list keeps the values this project has set, and the section may sit anywhere in this file.

- Queue areas: `[DESIGN]`, `[NATIVE]`, `[DOCKER]`, `[TOOLING]`, `[DOCS]`.
- Concurrency cap: two heavy builds or system runs at once; up to four agents including the coordinator. Use isolated worktrees for concurrent writers.
- Merging and releases: the user performs final review and landing unless explicitly delegated; no standing merge, release, or deployment delegation.
- Optional pieces in force: TODO queue, claims and markers, and the review ledger are in force. Defer a separate roadmap queue, stacked PRs, and scheduled extended main validation until they have a concrete use. Whole-codebase reviews run when requested.
- Environment: Arch Linux is the product host target. Use Bash and a Python 3.12 project venv via scripts/setup.sh for repository checks; never substitute another Python minor. Package and Docker operations on the real server are outside validation scope.

<!-- docket:end -->

## Project scope

Read [ARCHITECTURE.md](ARCHITECTURE.md), [docs/DECISIONS.md](docs/DECISIONS.md),
and the linked design specifications before changing product behavior.
The redesign remains in planning until the user authorizes implementation.
Preserve the design goals, not the current CLI API. Native Arch tooling and
Docker are the direction; Ansible and similar frameworks are excluded.

## Validation and review

Run `bash scripts/setup.sh` and `bash scripts/check.sh`; see
[docs/QUALITY.md](docs/QUALITY.md) for exact scope and limits. The owner's
standalone Python environment is `/Users/jonathan.hitchcock/.venv/3.12/`;
this repository uses a Python 3.12 `.venv` when that path is unavailable.
Keep unrelated checkout work intact. Never run real package installations,
service changes, or Docker lifecycle commands merely to validate a patch.

Pair every code author, including the coordinator, with an independent
reviewer. Authors fix findings; reviewers inspect the actual changes,
verify fixes, and review subsequent changes. Automated checks and
self-review do not replace this review. Keep work pending while actionable
correctness findings remain. Record reviewed commits or scope, checks, and
limitations in the PR review comment or local Docket review file; a task
review does not create a whole-codebase review snapshot. Mark a PR ready
once its scope, checks, and review are complete, leaving final review and
landing to the user. Return it to draft if those gates become incomplete.

## Billable actions

Before creating or changing billable third-party resources, state that the
action is billable, describe what it provisions, and obtain confirmation.
Use non-interactive approval flags only after that confirmation.
