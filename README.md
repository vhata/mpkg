# mpkg

This repository currently contains an Arch Linux metapackage helper and
five `vhata-*` package groups. `mpkg` is a Python executable; its
existing mutation commands edit package definitions, install software,
and commit changes. Run `./mpkg --help` for the current interface.

Create, edit and refresh resolve dependency requirements to satisfying
installed package names before changing installation reasons. Version
constraints use pacman's `vercmp`, including epoch and package-release
semantics. A satisfying direct-name package takes priority; otherwise,
only compatible virtual providers are marked as dependencies. Unresolved
requirements prevent marking and prevent an update's success commit.

Literal dependency edits preserve quoted descriptions and source outside
`depends` and `pkgrel`, including comments around those fields. The editor
accepts one top-level integer `pkgrel` and one literal `depends` array;
array comments may contain parentheses. Fields may appear in either
order, and single- or double-quoted descriptions may span lines.

This editor supports simple top-level assignments and functions containing
simple commands. It rejects ambiguous or unsupported shell constructs,
including expansions, escapes, redirections, compound commands and
repeated editable fields, before writing or invoking package tools. It
does not source the PKGBUILD to parse dependencies. Bash checks the original and
resulting syntax without executing code before the file is changed.
Installation still uses `makepkg`, which evaluates PKGBUILDs normally.

The standalone [viminumrc package](packages/viminumrc/README.md)
supplies the shared Vim configuration and its system-wide login
environment. Its build and migration instructions preserve an existing
`/usr/local/etc/vimrc` directory before pacman takes ownership.

A broader server environment tool is being designed. It will cover
native packages, Docker deployments, configuration, service identities,
and file accountability. These are design goals, not implemented
capabilities. Start with the
[design mandate](docs/specs/2026-10-30-server-environment.md) and
[milestone plan](plans/2026-10-31-server-environment-milestones.md).

The [disposable fixture tools](scripts/fixture/README.md) and
[mechanism experiments](scripts/proofs/README.md) support the separately
authorized design proofs. Their
[execution record](docs/fixtures/2026-11-01-disposable-execution-evidence.md)
distinguishes acquired inputs, actual guest observations and remaining
gates. These experiments are separate from the replacement manager.

For repository work, read [AGENTS.md](AGENTS.md), then the
[architecture map](ARCHITECTURE.md) and
[quality gates](docs/QUALITY.md). Deferred work lives in
[TODO.md](TODO.md).

Development checks require Bash, Git, and Python 3.12. Setup creates a
worktree-local `.venv` and enables the tracked Git hooks in this clone:

```bash
bash scripts/setup.sh
bash scripts/check.sh
```

If Python 3.12 is outside PATH, set `MPKG_PYTHON` to its executable when
running setup. Setup also recognizes the owner's standalone environment
at `/Users/jonathan.hitchcock/.venv/3.12/bin/python` when present. No
Python packages are downloaded; the current tests use only the standard
library. The tests stub package tools and run Git in temporary
repositories.
