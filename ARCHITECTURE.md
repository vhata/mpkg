# Architecture

This file maps the current implementation. The
[proposed architecture](docs/specs/2026-10-31-server-environment-architecture.md)
and [resource model](docs/specs/2026-10-31-server-environment-resources.md)
describe future work; the redesign remains in planning.

## Current boundaries

- `mpkg` contains the CLI, PKGBUILD metadata handling, dependency edits,
  package-tool calls, and scoped Git commits. Paths are resolved relative
  to the executable, including when invoked through a symlink.
- `vhata-*/PKGBUILD` contains the five metapackage definitions. Metadata
  queries use `makepkg --printsrcinfo`; these are executable Bash files.
- `tests/test_mpkg.py` copies the helper to temporary repositories and
  substitutes package tools. It exercises real Git behavior there.
- `scripts/`, `.githooks/`, and `.github/` own repository validation.
  `docket/` is vendored workflow machinery, updated only by its installer.
- `docs/specs/` and `plans/` retain the design requirements and milestones.
  `TODO.md` selects future work; `review/` records whole-codebase reviews.

## Existing behavior to protect

Mutating commands require `yay` before changing files. Missing native
package dependencies are installed before building the local metapackage.
Installation failure leaves edits available for diagnosis and does not
create a success commit. Commits select the relevant PKGBUILD and preserve
unrelated staged files. Literal dependency editing must not execute a
package's dependency expression.

The current CLI couples recording, installation, and commits. The design
requires separate recording and application, but that separation has not
been implemented. Do not describe the current helper as satisfying the
new mandate or infer a backward-compatible API requirement.

## Worktree isolation

Each worktree has its own ignored `.venv`, `.cache`, `test-results`, and
`.docket` files. Check scripts resolve paths from their own location;
tests use temporary Git repositories with package-tool stubs. No check
requires installing packages, changing service accounts, or running Docker
on the host. Hooks use the clone-local relative `.githooks` path, so each
worktree containing that directory runs its own version of the hooks.
