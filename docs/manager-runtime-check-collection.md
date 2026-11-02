# Recorded runtime and declared-user checks

`mpkg_manager.runtime_checks` collects required endpoint and access checks
from an actual read-only `HostStore` and verified `LoadedHostPolicy`.
It supplies an independent coverage manifest and a separate typed batch
for explicit [status/report integration](manager-runtime-check-reporting.md).
The existing route-only endpoint collector remains separate.

An endpoint result combines the existing
[runtime ownership and HTTP status observer](manager-runtime-endpoint-attribution.md).
An access result uses the existing
[declared-local-user operation observer](manager-consumer-access.md).
Neither result establishes application functionality or management
authority. Every public batch has `functional_result: unverified` and
`executable: false`.

## Trusted interface

```python
expected = runtime_check_manifest(
    readonly_store, loaded_policy,
    revision=revision, snapshot_id=snapshot_id,
    selected_components=selected_components,
)
batch = collect_runtime_checks(
    readonly_store, loaded_policy,
    revision=revision, snapshot_id=snapshot_id,
    selected_components=selected_components,
    probe_endpoints=True,
    check_access=False,
)
```

Both collection flags default to false. Manifest construction performs
no native queries, network probes or access-worker operations. Enabling
`probe_endpoints` explicitly allows the fixed native runtime queries,
process/listener inspection and bounded loopback HTTP(S) probe. Enabling
`check_access` separately allows fixed account queries and the isolated
read/list worker using the declared local account. That worker can drop
privileges if its trusted supervisor already has them; this library does
not invoke sudo or acquire privilege.

Revision and source snapshot identity are mandatory. Policy host identity
and engine aliases must exactly match the actual store. The collector
reads and verifies policy, retained history and current snapshot before
observation and again before returning, including empty selections,
disabled modes and failed checks. A changed or unavailable context
refuses the whole batch with a fixed error. The source selection and
complete private role inventory are frozen before the first adapter call.
No decision, snapshot, observation or other durable history is written.

The query, proc, probe and access-worker keyword arguments are trusted
Python embedding/test seams. They must never be exposed as declaration
fields or installed request options. The interface has no caller-selected
executable, argv, environment, PID, alternate user or Docker endpoint.
The actual observer adapters own their fixed query and worker contracts.

## Complete current and retained scope

The manifest includes each linked endpoint/access check in the current
snapshot, plus each original check from the last explicit adoption of
every retained physical resource. It reads the store's validated
`accepted_checks` projection, which resolves the original adoption
snapshot and predicates. A current same-ID check cannot replace an old
predicate. Removed and relinquished resources keep their retained roles.

An explicit component selection includes its resources and transitive
`requires` closure. Unselected current roles remain present with
`current_not_selected`; every retained role remains selected regardless
of component selection. Retained roles are scheduled first. Disabled
modes, unresolved physical identity, unsupported observations and checks
left unscheduled by limits have explicit rows with fixed reason codes.

Immutable private scope binds the exact normalized check, logical resource
and physical identity; Compose service selection or access consumer;
current or accepted role; stable resource ID; adoption revision and source
snapshot; retained management state; and current selection. Only complete
equal check/resource/consumer/service contexts share an observation. The
separate role rows remain even when one attempt satisfies both contexts.
Historical changes to user, URL, expected status, operation or timeout
therefore require distinct attempts.

The planner must independently call `runtime_check_manifest` against its
fresh trusted store/policy context, then require
`batch.matches_manifest(expected, now=..., max_age_seconds=60)`. This
compares full private coverage and source/selection context and rejects
future timestamps or excessive age. It is a pure comparison, not a live
history check. The caller owns the freshness of the independently derived
manifest. A batch's own embedded manifest cannot prove complete scope.

`RuntimeCheckManifest`, `RuntimeCheckResult` and `RuntimeCheckBatch`
validate their immutable structures. Their constructors do not
authenticate provenance, and caller-created objects are not a trusted
collection path. The redacted `as_dict()` projection cannot reconstruct
private bindings or substitute for independently derived coverage. Public
`coverage_complete` means all manifest roles have rows; it says nothing
about how many were selected, attempted or successful.

## Budgets and failure behavior

The default collection has a 60-second budget, at most 64 distinct check
attempts, 1,024 native queries and 64 MiB of reserved native query output.
Trusted callers may set 1–300 seconds, 1–256 attempts, 1–4,096 queries and
1–128 MiB of reserved output. The byte argument accepts exact positive
byte counts, including less than 1 MiB. A manifest is limited to 4,096
roles and 16 MiB of private canonical bindings; exceeding either refuses
collection before an adapter is called.

All native runtime and account queries share the count, reservation and
time budget. Each attempted query reserves its complete capture allowance
(64 KiB runtime; 16 KiB accounts), including failures. This bounds output
that can be produced by unsuccessful queries as well as accepted output.
The underlying adapters retain their own stricter per-check bounds.
Probe output and access target reads have separate fixed worker bounds;
the shared query reservation is not a total file-read-byte budget.

The original declared timeout must fit before an attempt is scheduled.
The runtime observer receives the remaining collection budget because
its inspection brackets the declared probe timeout. An access check's
timeout covers account resolution, the worker and final resolution.
Queries receive at most the remaining budget, and late query, worker or
observer returns are discarded. Unscheduled checks stay unknown rather
than disappearing. Cancellation propagates without publishing a partial
batch, and no retries occur.

Policy/history verification, proc reads and cleanup remain synchronous.
Individual kernel reads cannot be forcibly preempted by this collector;
count/size guards and late-result refusal do not promise a hard wall-clock
termination bound. Before/after checks are time-bounded observations, not
an atomic host snapshot or protection against a change that reverses
between checks.

## Meaning and validation limits

Public output contains IDs, role/selection/management, observation time,
separate endpoint/access outcomes, attempt counts, reservation totals and
fixed reasons/limitations. It omits predicates, paths, URLs, source hashes,
user names, credentials, PIDs, raw native replies and exception strings.
It does not serialize a reusable private evidence proof.

Runtime attribution establishes selected-runtime ownership of the
observed covering sockets. It does not authenticate the HTTP responder or
application behavior. A local user's successful read/list attempt uses
copied declared credentials in the collector's filesystem view. It does
not reproduce a running application's namespaces, credentials,
capabilities, security domain or workload. The batch preserves these
different observations without turning either into broad functional
health or execution permission.

Regression tests use private temporary policies and stores, synthetic
native replies and injected fixed observer seams. A combined fixture uses
an owned loopback listener, the real proc reader and fixed HTTP/access
workers under the current account, with only native queries injected.
The tests cover original
retained predicates, target/consumer and check-ID reuse, removed resources,
selection, exact private coverage, deduplication, limits, late results,
context races and redaction. They do not invoke real getent, systemctl,
Docker or sudo, install a helper, contact production endpoints, or supply
disposable Arch/Docker and first-release acceptance evidence.
