# mpkg

The replacement server environment manager is in staged implementation.
Its CLI validates an explicit TOML declaration locally:

```sh
.venv/bin/python -m mpkg_manager validate environment.toml --json
```

See [manager declarations](docs/manager-declarations.md) for setup, schema
and examples. This command does not read referenced inputs, inspect the
host, record adoption or apply changes. Separate
[recording commands](docs/manager-recording-cli.md) initialize and update
accepted host history or inspect current/history summaries through the
[staged host helper](docs/manager-host-helper.md). They require the
explicitly installed helper and administrator-provided host policy;
recording does not change running software. The separate
[`status` command](docs/manager-status-cli.md) compares recorded or
working-tree intent with read-only observations. Endpoint probes are
explicit and matching properties never authorize application. The existing
`mpkg` helper below remains available.

The replacement Python libraries provide these foundations:

- [Durable host records](docs/manager-store.md) for intent, adoption,
  relinquishment, protected captures and original accepted checks.
- [Verified host policy and protected capture](docs/manager-capture.md)
  for bounded reads beneath explicitly allowed input roots.
- Read-only [native](docs/manager-observations.md) and
  [Compose](docs/manager-compose-observations.md) observations with
  explicit identity, scope, time and unavailable evidence.
- Positive [package request satisfaction](docs/manager-package-satisfaction.md)
  through native dependency testing. Unmet requests and provider
  provenance remain unknown.
- [File metadata](docs/manager-file-observation.md) observations for
  bounded path targets, without reading contents or checking access.
- [Bounded file accountability](docs/manager-file-accountability.md)
  enumerates explicit scope with configuration/runtime attribution and
  visible gaps. Package baselines and consumer access remain unavailable.
- [Recorded input evidence](docs/manager-recorded-input-evidence.md) and
  [report binding](docs/manager-recorded-input-reporting.md) keep current
  and retained declared-file baselines separate across classifications.
- Positive [local account properties](docs/manager-account-observation.md)
  cross-checked against effective name resolution. Missing identities,
  supplementary memberships and safe account creation remain unknown.
- [Endpoint transport](docs/manager-endpoint-observations.md) and
  [recorded check collection](docs/manager-endpoint-checks.md) with
  bounded loopback requests and retained original predicates. Route
  agreement leaves listener and application identity unverified.
- [Immutable comparisons](docs/manager-planning.md) of desired state,
  retained authority, consumer requirements and current evidence,
  including [recorded endpoint results](docs/manager-endpoint-reporting.md)
  kept separate from functional verification.
- A pure [Sonarr Port transformation](docs/manager-sonarr-xml.md) of
  protected XML bytes that preserves unrelated content.

The [status collector](docs/manager-status-collection.md) connects these
observers and comparisons through live trusted read-only handles. The
status and recording clients use a fixed privileged request boundary with
a staged install payload; real installation and sudo acceptance remain
separate checks.
There is no application worker or apply command. Comparison reports
remain non-executable, and transformed candidate bytes carry no apply
authority.
[Authenticated protected bindings](docs/manager-protected-bindings.md)
connect exact declaration snapshots to captures through a trusted recorder.
Generic legacy captures retain decision/name comparisons. Recording can
[explicitly capture declared nonsecret files](docs/manager-recording-capture.md);
protected preparation remains a trusted library API. Legacy missing
baselines stay unavailable. Status reports current and retained declared-file
freshness independently of resource properties. Full effective Compose
input closure remains unverified; matching properties do not imply
unchanged inputs.

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

Native package solving, Docker lifecycle changes, functional checks,
file accountability and first-release acceptance remain incomplete. The
[design mandate](docs/specs/2026-10-30-server-environment.md) and
[milestone plan](plans/2026-10-31-server-environment-milestones.md)
describe the intended product beyond these foundations.

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
library. The tests stub package and service tools and Docker responses,
use private temporary stores, and run Git in temporary repositories.
Integration tests exercise real declaration, storage, observation-parser
and comparison code together, including private captures, metadata reads
and owned ephemeral HTTP listeners. They never invoke live package,
service or Docker tools and do not establish production acceptance.
