# First-release storage and execution design

This proposes a concrete implementation of the
[resource contract](2026-10-31-first-release-contract.md). It does not
implement the replacement or authorize package, service or Docker
changes. The existing helper remains usable. The
[Sonarr baseline](2026-10-31-sonarr-runtime-baseline.md) supplies an
observed example; the [acceptance scenarios](2026-10-31-first-release-acceptance.md)
remain the product's completion criteria.

## Selected structure

Use a Python 3.12 coordinator, TOML declarations, one local SQLite
management store, and an installed host worker with a closed set of
operations. A small C bridge uses libalpm for native transaction
preparation and installation. Compose remains the container orchestrator;
systemd supervises application attempts. There is no executable recipe
language, repository plugin loader or continuously reconciling daemon.

The C bridge is a deliberate additional implementation boundary:
parsing a successful `pacman --print` run cannot reserve a transaction
or prove what a later process will install. Keep dependency/provider
selection in libalpm, and compare its prepared transaction with the
accepted proposal before committing. This design needs the focused
proofs below before broader product implementation.

| Layer | Responsibility | May change |
| --- | --- | --- |
| Coordinator | Parse intent, compare observations, display decisions, submit typed requests | Explicitly requested declaration edits; its own scratch files |
| Host record/observation helper | Validate and store decisions, capture protected inputs, inspect bounded host facts | Management store for explicit recording; observation alone does not adopt or rewrite intent |
| Source preparation | Acquire accepted metadata, recipes, sources and package/image artifacts | Declared staging/cache scope; no live installation, sync-DB refresh, restart or permission change |
| Attempt worker | Validate accepted plan, own lock/journal, invoke fixed integrations, observe results | Only the accepted host effects |
| Native integrations | libalpm, makepkg, Compose/Docker, systemd, account and descriptor-based path operations | Their individually authorized scope; native partial effects remain possible |

## Declaration encoding and identity

The entry file is `environment.toml`, with `schema = 1`, `components`
and `resources` arrays. A component has a unique logical `id`, purpose
and resource references. A resource has a unique logical `id`, a
closed `kind`, typed physical `identity`, a `manage` property list,
typed `desired` properties, consumer references and required checks.
Logical IDs aid editing; accepted physical identities live in the host
store and survive declaration removal or renaming.

A component may also declare typed `requirements` entries containing
`resource`, `property` and `value`. They constrain a shared resource
without granting mutation authority. For example, two components can
reference `media-root` while requiring GID `1001` and `1002`; the
planner reports both incompatible requirements before proposing any
effect. A resource's desired value must satisfy every accepted consumer
requirement, including recorded external consumers. The shared resource
has one declaration and physical identity; compatible references merge.

This valid TOML fragment illustrates the encoding, not a complete
Sonarr input bundle or final CLI:

```toml
schema = 1

[[components]]
id = "television"
purpose = "Organize television media"
resources = ["sonarr", "media-root"]

[[resources]]
id = "sonarr"
kind = "compose"
manage = ["running"]
consumers = ["television"]
identity = { engine = "local-docker", project = "sonarr" }
desired = { running = true }
input = { bundle = "sonarr-inputs" }
checks = ["sonarr-ping", "sonarr-media-root"]

[[resources]]
id = "media-root"
kind = "directory"
manage = []
consumers = ["television", "external:radarr", "external:sabnzbd", "external:plex"]
identity = { path = "/mnt/media" }
desired = {}
```

The root schema also accepts typed `inputs`, `checks` and `runtime_rules`
arrays. Input entries identify ordered nonsecret files or protected
references and their base directory; checks select built-in endpoint,
service, package or access-check kinds with bounded parameters; runtime
rules specify root, path/type patterns and explicit configuration
exceptions. No shell expressions, interpolation in declaration syntax,
arbitrary callbacks or caller-supplied executables are accepted.

Resource kinds are `package`, `compose`, `volume`, `network`, `service`,
`user`, `group`, `file`, `directory`, `symlink` and `sonarr_xml`. Each
kind has an installed validator for its identity, properties and check
parameters; an unknown kind/property is an error, never an extension
module request. The XML kind is the bounded adapter described below.

Validate unknown keys, duplicate logical/physical identities, reference
cycles, missing references and property types before recording. TOML
datetimes and floating-point values are excluded from v1. Check IDs
and input-bundle IDs must resolve; this fragment intentionally omits
their full definitions. Reject conflicting values from components
referencing the same physical property; do not use last-writer wins.

Physical keys are typed tuples: host/package name; engine/project;
engine/volume or network name; system-manager/unit name; local
account/group name; or normalized absolute path. A host-generated UUID
and accepted Docker engine ID bind local aliases. Paths also retain
observed device/inode/mount identity and traversal limits as evidence,
not as a promise that an inode permanently names a logical resource.

Package intent separates requested name/source and version policy
(`any` or `exact`) from resolved provider/version/reason. Exact AUR
intent also binds recipe revision; exact Docker intent binds digest
and platform. Observation never changes `any` to `exact`.

Preserve source bytes for nonsecret inputs and encode validated values
as canonical UTF-8 JSON: sorted object keys, fixed scalar types and
preserved meaningful array order. SHA-256 identifies nonsecret content;
store schema/normalization version with every snapshot. A Git commit
is optional provenance, never the snapshot itself. No generated
metapackage is required to represent a collection in v1.

## Host store and protected inputs

Use `/var/lib/mpkg/state.sqlite3` under a root-owned `0700` directory;
database and journals are `0600`. The store is on a local filesystem
whose locking and synchronization behavior has been tested. A separate
root-owned `/etc/mpkg/host-policy.toml` binds host identity, allowed
input roots and installed integration/tool locations. Git declarations
cannot alter that policy or select another privileged executable.

The coordinator and logical recorder run unprivileged. Explicit
recording uses the bounded helper to update the protected store;
needing access to the store is not permission to apply host effects.
Ordinary output is a sanitized projection, not a SQLite connection or
raw file read granted to the caller. Missing inspection authority is
reported as unknown without granting Docker-group membership.

Use SQLite rollback journaling with `journal_mode=DELETE`,
`synchronous=EXTRA`, `foreign_keys=ON` and explicit short transactions.
Read back configuration, check the linked SQLite version and fail
closed on unsupported settings. Use `BEGIN IMMEDIATE` for a write;
commit errors prevent advancing to the associated external effect.
SQLite's atomic commit covers only this store, never a package
transaction, Docker action or another filesystem file.
[SQLite synchronization settings](https://sqlite.org/pragma.html#pragma_synchronous)

| Table | Key and retained content |
| --- | --- |
| `host` | Host UUID, schema version and accepted engine aliases |
| `snapshots` | Immutable ID, normalization version, nonsecret source/model blobs and provenance |
| `protected_inputs` | Random opaque ID, immutable bytes, purpose, source identity and access class |
| `decisions` | Monotonic revision, parent revision, adoption/authority/relinquishment/retention decision and snapshot |
| `resources` / `edges` | Stable resource IDs and revisioned physical identities, properties, consumers and uncertainty |
| `plans` | Immutable ID, exact target, decision revision, prerequisites, effects and checks |
| `attempts` | Random UUID, plan, requesting operator, boot ID, worker unit and overall outcome |
| `actions` / `events` | Attempt-local IDs, prerequisites, durable start, append-only events, bounded outcomes and observations |
| `dispositions` | Retirement-specific decision, exact resource/data scope and retained access requirements |

Foreign keys bind the records; append-only decisions/events retain prior
facts. Current-resource and attempt summaries are transactional
projections of those records, not replacements for history. Migration
is an explicit maintenance operation with a verified backup and
exclusive lock; unknown/newer schema versions block writes.

Capture secret-bearing `.env`, XML or Compose input bytes only through
the protected-input path. A protected copy has an opaque ID and a
private keyed comparison token covering full bytes and source identity.
Neither secret values nor raw/keyed digests appear in exported history.
Freshness comparison happens inside the helper; its result is
same/changed/unavailable. Never substitute redacted placeholders into
configuration. If capture or comparison is unavailable, application is
blocked. Do not treat automatic secret detection as a guarantee: input
classification is an explicit accepted responsibility.

Small configuration snapshots, including protected ones, are stored in
the same database transaction as their references. Set a v1 per-input
limit of 16 MiB; larger inputs require a supported explicit mechanism,
not truncation. Application databases/media are not snapshots of intent.
Large software artifacts use a private staging directory: copy into a
new file, verify content/signature, synchronize it and its directory,
then publish the reference transactionally. Orphans are harmless;
missing/corrupt referenced artifacts block execution.

Protected history is plaintext behind host access controls, not a
claim of encryption at rest. V1 retains accepted snapshots and history
without automatic deletion. Explicit encrypted off-host backup must
include the database, host key/policy and needed artifact inventory;
media/database backups are separate operator prerequisites. Take a
SQLite-consistent backup, never copy a live database file blindly.
Restoring history cannot prove external effects rolled back; require
re-observation and explicit recovery before new mutations.

## Requests, privilege and supervision

The installed helper accepts a versioned, length-bounded JSON request
on stdin with fixed verbs: `observe`, `record`, `prepare`, `plan`,
`apply`, `recover` and `export`. The names describe an internal
protocol, not a commitment to CLI spelling. No shell string, argv array,
environment override, Python module or systemd unit body is a request
field. Installed handlers build arguments from validated typed values.

Use interactive `sudo` to enter the root helper when required; v1
installs no blanket passwordless rule or rootful Docker group grant.
Root authorization and the accepted plan are both required for apply.
Unprivileged repository content is input, not installed helper code.
The helper uses fixed paths and a minimal environment, validates file
descriptors/owners and imports no modules from the checkout. Operator
identity comes from the trusted privilege launcher, not a JSON field.
Root remains trusted; this is not containment against a hostile root.

The worker captures child stdout/stderr through bounded pipes; they
are never inherited by the terminal or systemd journal. Emit only
allowlisted structured outcomes and fixed diagnostics, suppressing
unknown raw errors rather than relying on regex secret removal. Use
private temporary files for secret-bearing adapter inputs, avoid secret
argv values, disable core dumps, and test sentinel leakage through
exception, timeout and daemon error paths. Application-owned container
logs remain outside ordinary attempt history.

On apply, the helper loads a protected, immutable plan ID, revalidates
its authority and input bindings, and creates a system-manager service
`mpkg-attempt-<uuid>.service` running the fixed installed worker with
only that UUID. It is a service, not a caller-owned scope. Use
`Type=exec`, `ExitType=cgroup`, `KillMode=control-group`, `Restart=no`
and `RemainAfterExit=yes`; record the unit/boot identity before launch.
The exact supported systemd version is part of installation checks.
Unit startup success alone is not action or application success.
[systemd service semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)

The worker holds an exclusive `flock` on `/run/mpkg/apply.lock` for
the complete attempt. Record/authority changes take the same lock;
read-only status uses a consistent database read without waiting on
external actions. Native package locking is additional. SQLite write
locks are short and never held through a subprocess or user prompt.

The durable unresolved-attempt check is as important as the advisory
lock. A dead controller can leave its worker alive; a dead worker can
leave Docker daemon work alive. If an attempt lacks a terminal record,
inspect its unit/cgroup, boot identity, native transaction lock and
affected Docker/resources. Do not delete a package lock, kill a worker
or restart an action just to clear uncertainty. Unknown quiescence
blocks another mutation, even when `flock` can be acquired. Recovery
records an evidence-backed disposition; it does not invent success.
Stopping a worker does not undo Docker daemon effects.
[systemd process termination](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)

## Plan and action protocol

Plans contain typed effects produced by installed integrations, with
prerequisite edges derived by the planner. Users cannot author an
arbitrary action graph. Every effect has an adapter version, resource
identity, before-evidence token, target, input/artifact IDs, authority,
timeout, interruption policy and required after-checks. Package hooks
and accepted application interruption are visible effects/risks, not
assumed to be confined to the requested package's file list.

1. Observe bounded live facts and load current decisions. Compare
   working-tree inputs without adopting or applying them.
2. Explicitly prepare sources if needed. Report resulting acquisition,
   build and dependency-install requirements as distinct phases.
3. Produce an immutable proposal. Required unknowns/conflicts make it
   non-executable. Present exact scope and retirement-specific choices.
4. On an explicit apply of that plan, acquire the host lock, check for
   unresolved workers, and validate current inputs, decisions and live
   prerequisites. Changed facts require a revised plan and acceptance.
5. At every mutation boundary, revalidate relevant input, authority and
   live prerequisites against the accepted target and expected effects
   of preceding completed actions. Unexpected changes stop application
   and require a revised accepted plan; do not silently update tokens.
   Commit `action-started`, then invoke one bounded native operation.
   An invocation failure is still a recorded action. Observe effects,
   record command outcome and verification independently, then commit.
6. Stop further mutations after a failure or failed required check.
   Observe remaining scope if useful. Do not silently roll back or
   restart a stopped application after a failed configuration write.

Actions move from `planned` to `started`, then to `observed-complete`,
`failed` or `unverified`. Crash with only a start record is `unknown`.
Attempts preserve completed and not-attempted work separately. A retry
is a new plan/attempt linked to its predecessor, never replay of an old
command list. If every desired property already matches, perform the
required checks and record verification without a mutating action.

Ordinary status uses a read-only database connection. If hot-journal
recovery is required and read-only access cannot proceed, report that
history needs explicit recovery; do not silently change authority or
claim an empty history. A lost store blocks destructive operations.

## Arch package and AUR boundaries

Use separate libalpm handles for source preparation and live commit.
Preparation reads a consistent copy of installed-package metadata and
refreshes sync metadata only under an isolated staging DB path. Record
source servers, database content identities, signature policy, package
artifacts and installed-state fingerprint. Reject an unstable installed
inventory during capture. Do not run `pacman -Sy` on the host as part
of status or hidden preparation.

For updated repository metadata, run native system-upgrade selection
in that staged context before requested additions; expose the complete
coordinated upgrade when needed. Download the full accepted artifact
closure and verify provenance. A preparation result is a proposal,
not a claim of a reserved live transaction.

At application, the installed C bridge opens the real local database,
acquires libalpm's normal transaction lock, adds only accepted package
artifacts and removals, calls `alpm_trans_prepare`, and compares the
prepared add/remove/provider/version set and current package/reason
inventory with the plan. Commit only an exact accepted transaction;
unresolved dependencies, replacement questions or extra effects return
a revised proposal/block. No `NODEPS`, `NOLOCK`, forced overwrite or
automatic cascading removal is allowed. Do not refresh live sync
databases or fetch alternative artifacts during commit.
[libalpm transaction API](https://man.archlinux.org/man/libalpm_trans.3.en)

Preserve accepted native configuration, signature checks and package
hooks. Preparation cannot predict every scriptlet/hook effect; show
those executable inputs and require their trust, then verify actual
outcomes. Package reason changes are separately journaled native
operations, preserving pre-existing independent reasons. Never sweep
all orphan/foreign packages. A package or hook failure can leave partial
state despite a native lock and must be re-observed before retry.

The bridge must prove that a staged full-upgrade solution can be
revalidated as an exact artifact transaction without losing native
dependency/provider/replacement semantics. Until that proof passes,
native apply is blocked; CLI print output is not a fallback that
weakens the contract. A libalpm ABI mismatch also blocks execution.

For AUR, fetch pinned recipes and read `.SRCINFO` as untrusted metadata
without evaluating PKGBUILD. Accept the recipe/source trust decision,
then run metadata regeneration/source verification and `makepkg` only
as the dedicated unprivileged build identity in its own workspace.
Compare generated metadata with the accepted declaration before build;
changes invalidate downstream effects. Pin recursive AUR recipe inputs
when needed and use native resolution for repository/providers.

Required build dependencies are explicit install effects before the
build action; source preparation cannot secretly install them. The AUR
build is not allowed to use sudo or install dependencies itself. Bind
the output package hash, metadata and source/build provenance in a new
installation proposal after the build. Accept that proposal before
privileged installation; unknown output bytes cannot have been covered
by the earlier recipe decision. Local AUR artifacts require explicit
operator trust and protected import; they do not inherit Arch signing
trust. Do not auto-remove temporary build dependencies in v1.

## Compose and configuration boundaries

Accept a closed bundle: original ordered files, original base/project
directory, explicit project/engine, profiles/services, interpolation
environment, referenced env/config/secret files and resolved bind paths.
Remove inherited Compose/Docker overrides. Source `.env` existence is
not proof of effective values. Store protected inputs separately and
parse rendered output only in memory, exposing whitelisted fields.

V1 supports local ordinary services, bind mounts, local named volumes,
ordinary project/external networks and host networking. Before invoking
Compose, reject unsupported includes, extends, remote inputs, builds,
providers, lifecycle hooks and unbounded custom integration fields.
Reject unknown Compose schema fields rather than silently ignoring
them; the supported Compose version/schema is pinned by the adapter.
Includes can resolve external/recursive content, so config rendering
is not automatically an offline or harmless parser.
[Compose includes](https://docs.docker.com/compose/how-tos/multiple-compose-files/include/)

The protected attempt bundle is immutable. Before application, render
it in an isolated input workspace with explicit environment and
base-path mapping, then compare its effective resources to the accepted
model. Preserve literal-dollar semantics and input precedence; capture
all files before rendering. No source resolution may escape the
accepted closure. Mount backing files supplied by the tool remain
durable for the lifetime of their consumers; deleting a temporary
render directory must not break a running application.

For recreation, resolve and acquire image digest/platform explicitly
and bind them in the effective model. Use explicit engine/project and
`up --detach --pull never --no-build` with accepted service/dependency scope;
missing content blocks. Compare the complete prospective deployment,
not just a service name. Do not call `up` when no mutation is needed:
changing a tag to a digest in generated input can itself change Compose
configuration identity and trigger recreation.
Detached invocation avoids attaching application logs or tying the
workload's lifetime to an attached Compose process. Apply bounded
verification separately; timeout still requires daemon-state recovery.
[Compose application options](https://docs.docker.com/reference/cli/docker/compose/up/)

For the initial Sonarr XML-port example, preserve the same accepted
container/image when container configuration is unchanged: stop the
identified container, verify quiescence and restart-policy behavior,
change the supported XML field, start that same container ID, and run
effective endpoint/access checks. A replaced container invalidates
this plan. A future container-configuration change uses the separate
recreation path and exposes interruption and dependent effects.

Select a narrow Sonarr XML adapter, initially `Port`, `UrlBase` and
`LogLevel`; unsupported requested fields block instead of falling back
to whole-file replacement. Parse with DTD/entity expansion disabled;
reject duplicate or unexpected document structure. Preserve other
elements, attributes, comments and secret values, and report any
serialization-only changes before application. Compare a protected
whole-file token as well as selected properties.

Sonarr's versioned implementation caches configuration, writes under
an in-process mutex, can migrate/remove unrecognized elements on
startup, and permits server-option overrides. The adapter therefore
requires a declared maintenance interval excluding other editors and
all identified writers stopped. Re-read after stopping, reject changed
bytes, construct the replacement from that fresh protected input,
recheck identity/content immediately before publication, and verify
effective properties after restart. Missing writer exclusion blocks
the edit. This is not a lock on arbitrary external administrators.
[Versioned Sonarr configuration source](https://raw.githubusercontent.com/Sonarr/Sonarr/v4.0.20.3014/src/NzbDrone.Core/Configuration/ConfigFileProvider.cs)

For any file write, walk from a held directory descriptor with explicit
symlink/mount restrictions; use a same-directory temporary file,
preserve required ownership/mode/access metadata, synchronize content,
replace and synchronize the directory. Unsupported ACL/xattr or alias
preservation blocks the operation. `openat2` can constrain traversal;
it does not make content compare-and-replace atomic against writers.
Atomic rename prevents a partially visible new file, not lost updates.
[Linux path-resolution controls](https://man7.org/linux/man-pages/man2/openat2.2.html)

## Verification and retirement implementation

Built-in checks return typed observations with time, target, expected
predicate, actual result and limitations. Endpoint checks use bounded
local addresses, explicit listener attribution, no redirects/proxy and
limited retained output. Access checks measure full UID/GID slots,
supplementary groups, capabilities and namespace maps before testing
fixed paths. A read/open or write-permission predicate is not a write
trial or application workflow. Required functional checks need their
own supported adapter and fixture evidence, not arbitrary shell hooks.

Native services use individual systemd unit properties and required
application checks. Account operations create missing local identities
or add accepted memberships; conflicting adopted numeric identities
block. Directory management affects only declared properties of that
directory. Stop/start, metadata edits and data handling are separate
actions, so failed verification never fabricates rollback.

Retirement first creates a fresh disposition bound to resource/data
identity and consumer evidence. Keep/deletion is per retirement, never
inferred from declaration removal. For Compose, disable accepted
restart behavior, stop and inspect all target containers including
stopped instances, and remove only authorized containers. Handle
networks/volumes as separately authorized resources; never use blanket
`down --volumes`. Remaining/unknown consumers force retention or block
destruction. Native retirement similarly verifies stopped service and
accepted startup behavior before handling data.

Deletion requires a complete bounded inventory and exclusive writer/use
assumption, held root descriptors, fresh path/mount/consumer checks,
and an explicit private data scope. Unvisited descendants, new entries,
symlink/mount surprises or incomplete stopping block it. Recheck during
traversal and record partial deletion if the process fails. Never
recurse into `/mnt/media` merely because Sonarr referenced it. Kept
data gains continuing attribution and declared access requirements;
those checks cannot require restarting the retired application.

## Focused proofs before product implementation

These are bounded experiments in the disposable fixture, not permission
to run them on the server. Passing them proves the selected mechanisms;
it does not replace any A1–A12 acceptance scenario.

| Proof | Required evidence and failure outcome |
| --- | --- |
| Journal/supervision | Kill coordinator and worker independently around start/effect/completion boundaries; test durable-record failures and continuing native/daemon work; no retry overlaps unresolved work |
| Native transaction | Frozen repository and AUR additions with separate missing prerequisites; preparation does not alter host sync DB; fresh native transaction equals accepted scope or blocks; exact pins and coordinated upgrade remain enforced |
| Protected inputs | Secret sentinels never enter Git/export/errors; changed secret/input invalidates apply; restored history does not manufacture authority or roll back observed effects |
| Compose bundle | Rendered staged inputs preserve original env/path/dollar semantics; no unplanned pull/build/recreation; digest/platform and complete dependency scope are honored |
| Config writer exclusion | Sonarr stop/edit/start preserves protected/unmanaged fields and detects startup normalization/overrides; intervening edits block; endpoint and shared-consumer checks validate actual behavior |
| Retirement | Separate keep/delete with retained access and an unmanaged consumer; changed descendants/mounts/consumers block; partial failure stays incomplete |

The declaration, persistence and operation boundaries are now selected
as a proposal. Implementation remains gated on explicit authorization,
these mechanism proofs and the fixture's acquisition/assembly evidence.
If a proof disproves a selected mechanism, revise this design and its
acceptance mapping before implementing a weaker substitute.
