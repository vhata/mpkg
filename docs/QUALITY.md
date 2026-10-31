# Quality and validation

## What quality means here

- Preserve the current helper's package-operation ordering, failure
  reporting, scoped commits, and unrelated local changes.
- Keep routine checks isolated from real package tools and live services.
- Distinguish the implemented helper from the planned server manager.
  Mocked integration tests cannot establish real Arch or Docker behavior.
- Make queue blockers, missing evidence, and unperformed reviews visible.

## Gates

Install the worktree's Python 3.12 environment and hooks with
`bash scripts/setup.sh`. `.python-version` selects the minor version;
patch updates within 3.12 are allowed. Setup uses an existing 3.12
interpreter (`MPKG_PYTHON` can specify it) and downloads no dependencies.
It preserves an incompatible existing venv or hooks configuration and
fails with a diagnostic instead of replacing it.

| Entrypoint | Check | Callers |
| --- | --- | --- |
| `scripts/lint.sh --staged` | Index whitespace and Python/Bash syntax for staged changes | pre-commit |
| `scripts/lint.sh` | Worktree Python/Bash syntax, including `mpkg`, PKGBUILDs and vendored scripts; staged and unstaged diff whitespace | check entrypoint |
| `scripts/test.sh` | Complete unittest discovery from `tests/`; fails on zero tests, skipped tests, or failures | check entrypoint |
| `scripts/check.sh` | Syntax/whitespace, tests, strict queues, relative Markdown links | pre-push, agents, project CI |
| `docket/scripts/ci.sh` | Strict queues and links; PR markers when PR metadata is supplied | hygiene CI |
| `docket/scripts/review-due.sh` | Report review cadence; does not claim a review took place | on demand |

Project scripts resolve their paths from their own location and can be
invoked from any directory. Vendored Docket scripts operate on the current
repository, so invoke them from its worktree.

Hooks are the tracked `.githooks/` directory, enabled with clone-local
`core.hooksPath=.githooks`. This shared setting covers worktrees containing
those hooks; older branches without them have no hook to execute. No
global Git configuration is changed. Pre-commit reads staged content and
only checks it; unstaged changes are preserved. A warm check of one staged
Python file measured 0.067 seconds on the setup host. Pre-push runs the
full entrypoint, without a documentation-only skip. Bypass only a broken
toolchain, documenting the reason and equivalent manual checks in the PR.

The suite uses standard-library unittest, temporary repositories, and
stubs for `pacman`, `makepkg`, `yay`, and `sudo`. The test wrapper removes
inherited repository-local Git variables and suppresses global/system Git
configuration and templates, so hooks cannot redirect fixture operations
into the real checkout. It puts the venv first in PATH for subprocesses.
There is no formatter, static type checker, coverage threshold, package
build gate, or real-service suite. Syntax checking is not semantic lint.
Add those gates when a concrete need warrants them; no placeholder scripts
claim to run them.

## Test policy

Run the existing tests for code changes. Add focused regression coverage
for meaningful behavior changes; documentation and reversible formatting
changes do not require new tests. An empty or skipped suite is a failed
gate. No automatic retries or silent gate weakening. Report a flaky test
with its evidence in TODO and investigate the failure.

The [first-release milestones](../plans/2026-10-31-server-environment-milestones.md)
require disposable Arch demonstrations with real repository and AUR
packages plus Docker. This workflow does not supply those demonstrations
or authorize running them on the production host.

## Review inputs

- Read [ARCHITECTURE.md](../ARCHITECTURE.md),
  [DECISIONS.md](DECISIONS.md), and the relevant design specification.
- Focus on package subprocess arguments and ordering, failure paths,
  dependency parsing, scoped Git writes, and preservation of local edits.
  For workflow changes also check staged-file behavior, empty/failing
  suite propagation, Git fixture isolation, and CI event handling.
- Baseline: `bash scripts/check.sh`, `bash docket/scripts/ci.sh`, and
  `bash docket/scripts/review-due.sh --paths "mpkg tests scripts .githooks"`.
  With the Docket skill available, run its `install.sh --check` from this
  worktree to verify the vendored files and managed AGENTS block.
- Compare described CLI behavior with `mpkg`, future claims with the
  planning documents, and this file with hooks and CI. Do not treat design
  acceptance as already verified behavior.
- Expected tracked files: `mpkg`, `vhata-*/PKGBUILD`, tests, project scripts,
  hooks, Python version declaration, ignore rules, Markdown records,
  GitHub workflow/template, and the verbatim Docket installation. Venvs,
  package artifacts, captures containing secrets, and local review drafts
  do not belong in commits.
- `review/README.md` is an empty whole-codebase review index. Independent
  task review is recorded separately and does not establish that baseline.

## CI and hosting

`.github/workflows/ci.yml` declares `Project checks` and `Queue and PR
hygiene` on pull requests and pushes to `main`. PR body edits retrigger
hygiene. Superseded PR runs are cancelled; main runs are not. Failed
project checks upload their log for seven days. The Linux runner exercises
the mocked suite; using Ubuntu for it does not expand product host support.

There is no Git remote configured in this checkout. Hosted CI execution,
PR checks, and branch protection therefore remain unverified. Local-only
work keeps its prepared PR body and independent review under `.docket/`.

Scheduled extended main validation is deferred until a substantive system
suite exists. The review cadence report remains available on demand. When
hosted CI exists, a red main is reverted or filed as P1 (P0 if release
blocking) the same day; recovery requires a green subsequent main run.

Recommended hosting settings, for the user to apply after adding a remote:
require `Project checks` and `Queue and PR hygiene`, linear history, and
squash merges using the PR title and body. Delete merged head branches.
Require neither current-base freshness nor a forge approval count by
default; independent agent review is still mandatory. Leave administrator
enforcement off to permit the contract's direct planning-document commits.
Agents may not force-push or delete main. No hosting settings have been
applied by this setup.

## PR evidence

Describe what changed, why, and relevant validation in the PR body, which
becomes the squash commit message. Keep review history, status, and
instructions in comments. Record the independent reviewer, reviewed
revision or scope, findings and their dispositions, actual checks, and
limitations in a review comment; use `.docket/review-<slug>.md` when no PR
can be opened. Leave final review and landing to the user.
