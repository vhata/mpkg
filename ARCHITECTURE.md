# Architecture

This file maps the current implementation. The
[proposed architecture](docs/specs/2026-10-31-server-environment-architecture.md)
and
[resource model](docs/specs/2026-10-31-server-environment-resources.md)
describe the target design. Its declaration, recording, observation and
comparison foundations are now in staged implementation alongside the
existing helper; application and product acceptance remain incomplete.
The [first-release contract](docs/specs/2026-10-31-first-release-contract.md)
and [acceptance scenarios](docs/specs/2026-10-31-first-release-acceptance.md)
define requirements beyond the implemented foundations below.
The [storage and execution design](docs/specs/2026-10-31-first-release-storage-and-execution.md)
selects encoding, persistence and native operation boundaries. Recording
and comparison primitives implement part of that design. A bounded
recording/status client and staged privileged helper implement the initial
request boundary; installation acceptance and application remain
separate work.
The [disposable fixture design](docs/specs/2026-10-31-first-release-fixture.md)
binds source inputs and proposed assembly/checks. The separate
[execution record](docs/fixtures/2026-11-01-disposable-execution-evidence.md)
records actual acquisition and guest outcomes separately from library
checks and product acceptance.

## Current boundaries

- `mpkg_manager.declarations` owns the Python 3.12 replacement's typed
  nonsecret model, contextual consumer constraints and exact snapshots.
  `mpkg_manager.cli` exposes local declaration validation plus explicit
  recording, history and status commands through `host_client`; see the
  [declaration guide](docs/manager-declarations.md) and
  [recording CLI guide](docs/manager-recording-cli.md) and
  [status guide](docs/manager-status-cli.md). `status_wire` validates the
  closed public status schema at both ends of the transport.
- `mpkg_manager.store` owns private SQLite intent/adoption records,
  retained consumers, protected captures and historical accepted check
  predicates. It validates durable history before projecting authority.
  Its [store guide](docs/manager-store.md) defines recording and ownership
  boundaries. [Explicit migration](docs/manager-store-migration.md) requires
  a verified private backup and retains authenticated maintenance receipts;
  opening a legacy store does not silently upgrade it. `host_protocol` and `host_helper` provide closed recording
  and status requests, verified paths, serialization and sanitized output. The
  [host-helper guide](docs/manager-host-helper.md) describes the staged
  installed launcher and its unverified real-host acceptance; protected
  recording through requests and application remain separate work.
- `mpkg_manager.host_policy` loads and verifies host identity, engine
  aliases and allowed input roots. `mpkg_manager.protected_capture` reads
  bounded regular files beneath a verified policy handle. The
  [capture guide](docs/manager-capture.md) defines path, metadata and
  ownership checks and their concurrency limits. Trusted fixture path/UID
  overrides are not a production privilege boundary.
- `mpkg_manager.observe_native` and `mpkg_manager.observe_compose` collect
  time-bounded observations through closed read-only queries. Their
  [native](docs/manager-observations.md) and
  [Compose](docs/manager-compose-observations.md) guides define exact
  scope and limitations. `observations` supplies immutable scalar facts;
  Compose keeps nested inventory separate. `query_process` supplies
  bounded process capture shared by these adapters.
- `mpkg_manager.observe_packages` complements direct inventory with
  [positive native request satisfaction](docs/manager-package-satisfaction.md).
  It accepts no version expression or alternate package root, and
  cannot establish absence, provider identity or provenance. Planner
  source/property guards keep that evidence distinct from installed
  version and installation-reason facts.
- `mpkg_manager.observe_accounts` collects
  [local account scalar properties](docs/manager-account-observation.md)
  through bounded fixed queries and repeated local/default NSS checks.
  Missing or conflicting identities stay unknown. Supplementary
  memberships, account creation and numeric-ID changes remain outside
  its observation and comparison capabilities.
- `mpkg_manager.observe_files` collects bounded file, directory and
  symlink metadata using Linux descriptors without reading contents.
  Its [metadata guide](docs/manager-file-observation.md) defines path
  race checks, name-resolution limits and unsupported content/access.
- `mpkg_manager.file_accountability` enumerates explicit filesystem roots,
  exclusions and budgets, with conservative configuration/runtime
  attribution and visible gaps. Its
  [accountability guide](docs/manager-file-accountability.md) distinguishes
  metadata classification from package baselines and consumer access.
- `mpkg_manager.recorded_inputs` collects current and retained declared
  files against authenticated private baselines. The
  [evidence guide](docs/manager-recorded-input-evidence.md) describes
  separate original dependency and consumer-content obligations;
  [report binding](docs/manager-recorded-input-reporting.md) checks them
  against independent `HostStore.current_with_inputs()` history manifests.
  This is declared-file coverage, not complete effective Compose closure.
- `mpkg_manager.file_content` compares authenticated recorded bytes with
  explicit targets under policy-approved roots. Its
  [collector](docs/manager-file-content.md) and
  [report binding](docs/manager-file-content-reporting.md) preserve complete
  current/accepted desired/consumer roles, with source freshness separate.
  Installed status requires `--check-file-content` and exact recorded
  intent before target reads. Missing evidence never changes a baseline.
- The trusted [Compose preflight](docs/manager-compose-input-bundles.md)
  remains a pure library boundary.
- `runtime_checks` collects [runtime attribution](docs/manager-runtime-endpoint-attribution.md)
  and [consumer access](docs/manager-consumer-access.md) with original
  current/retained private scopes. `runtime_reporting` validates them
  against independent history. Explicit [status options](docs/manager-runtime-check-reporting.md)
  keep socket ownership, local-user access and application health separate.
- `mpkg_manager.observe_endpoint` uses a fixed isolated Python worker
  for bounded loopback HTTP status evidence. `endpoint_checks` collects
  required current and retained accepted predicates from actual host
  history. Their [transport](docs/manager-endpoint-observations.md) and
  [collection](docs/manager-endpoint-checks.md) guides distinguish route
  agreement from listener attribution and application health. Recording
  intent or removing a resource never initiates a probe.
- `mpkg_manager.planning` compares validated intent, trusted store
  projections and current facts without reads or effects. The
  [comparison guide](docs/manager-planning.md) owns source/identity
  binding, retained constraints and separate accepted/current checks.
  [Endpoint report binding](docs/manager-endpoint-reporting.md) requires
  typed complete role coverage, exact recorded context and freshness;
  every route result remains functionally unverified.
  Reports are always non-executable; attempts, native preparation and
  application are not supplied.
- `mpkg_manager.status_collection` coordinates fixed read-only adapters
  with live policy/history checks, bounded query scheduling and explicit
  gaps. The [collection guide](docs/manager-status-collection.md) defines
  retained scope, legacy and complete input modes, exact recorded endpoint
  targets, optional exact recorded file-content comparisons and the lack
  of a hard filesystem/history latency deadline.
  The installed helper opts into complete input mode and pins the chosen
  revision before queries; no observation records or repairs intent.
- `mpkg_manager.sonarr_xml` transforms only the existing Port value in
  protected XML bytes, preserving unrelated bytes. Its
  [adapter guide](docs/manager-sonarr-xml.md) defines the supported subset
  and protected candidate interface. It performs no live file operation,
  writer coordination or restart, and grants no apply authority.
- `mpkg` contains the CLI, PKGBUILD metadata handling, dependency edits,
  package-tool calls, and scoped Git commits. Paths are resolved
  relative to the executable, including when invoked through a symlink.
- `vhata-*/PKGBUILD` contains the five metapackage definitions. Metadata
  queries use `makepkg --printsrcinfo`; these are executable Bash files.
- `packages/viminumrc/` records the shared Vim configuration, bundled
  plugins, and a profile snippet. Its package owns
  `/usr/local/etc/vimrc` payload files and
  `/etc/profile.d/viminumrc.sh`; see its
  [guide](packages/viminumrc/README.md) for adoption and activation
  limits. Standalone payload packages live under `packages/`, outside
  the helper's metapackage discovery and rewriting scope.
- `tests/test_mpkg.py` copies the helper to temporary repositories and
  substitutes package tools. It exercises real Git behavior there.
- `tests/test_manager_integration.py` connects the real model, temporary
  store, native/Compose parsers and planner using synthetic query results.
  Its test assembly routes disjoint resource sets with a common host and
  timestamp. It is not a production observation coordinator or status CLI.
  Protected Sonarr candidates are also checked against stored capture
  evidence without turning a pure transformation into observation or
  application authority. Temporary loaded policies and actual XML reads
  exercise capture-to-store freshness and stale candidate refusal.
- `tests/test_manager_observation_pipeline.py` combines authenticated
  captures, real metadata descriptors, synthetic native queries and an
  owned HTTP listener through the fixed endpoint worker. It checks that
  changed inputs, property agreement and original accepted predicates
  stay distinct while durable history remains unchanged. This explicit
  test assembly is not a production observation coordinator.
- `scripts/fixture/` owns private runner acquisition, disposable guest
  assembly, supervised builds and bounded input/artifact transport.
  `scripts/proofs/` contains guarded mechanism experiments. These tools
  run separately from routine checks and do not expose a product CLI.
- The top-level `scripts/` entrypoints, `.githooks/`, and `.github/`
  own repository validation.
  `docket/` is vendored workflow machinery, updated only by its
  installer.
- `docs/specs/` and `plans/` retain the design requirements and
  milestones. `TODO.md` selects future work; `review/` records
  whole-codebase reviews.

## Existing behavior to protect

Mutating commands require `yay` before changing files. Missing native
package dependencies are installed before building the local
metapackage. Installation failure leaves edits available for diagnosis
and does not create a success commit. Commits select the relevant
PKGBUILD and preserve unrelated staged files. Literal dependency editing
must not execute a package's dependency expression.

The existing helper CLI couples recording, installation, and commits.
Replacement libraries separate recording and read-only comparisons from
effects, but do not yet implement application. Do not describe either as
satisfying the complete mandate or infer a backward-compatible API
requirement. Synthetic integration checks establish how the library
interfaces compose, not real Arch/Docker behavior, production privilege
isolation or the first-release acceptance scenarios.

[Protected declaration bindings](docs/manager-protected-bindings.md) use
store-issued preparations and durable authentication of capture origins,
exact snapshots and declared input scope. The trusted recorder compares
bound inputs under current policy and preserves original history. Generic
legacy captures still use decision/name comparisons and do not authenticate
declaration UUIDs. Neither path establishes complete effective Compose
input closure, replay authorization or application readiness.
`input_evidence` binds fresh protected comparisons to the exact current
recorded snapshot and complete protected slot coverage. Public reports
redact input paths, references and content digests. This legacy subset
leaves historical coverage unavailable; the separate `recorded_inputs`
mode covers current and retained declared files without claiming full
bundle closure.

## Worktree isolation

Each worktree has its own ignored `.venv`, `.cache`, `test-results`, and
`.docket` files. Check scripts resolve paths from their own location;
tests use temporary Git repositories with package-tool stubs. No check
requires installing packages, changing service accounts, or running
Docker on the host. Hooks use the clone-local relative `.githooks` path,
so each worktree containing that directory runs its own version of the
hooks.
