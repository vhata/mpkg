# Trusted status collection

`mpkg_manager.status_collection.collect_status` connects the existing
observers to the pure comparison report through live, trusted host
handles. It takes an exact validated `Declaration`, a `HostStore` opened
with `open_readonly`, and a `LoadedHostPolicy`. It returns an immutable
`StatusResult`; `as_dict()` copies its public `report` and `collection`
summaries, while `canonical_bytes` and `sha256` bind that whole result.

```python
result = collect_status(
    declaration,
    readonly_store,
    loaded_policy,
    selected_components=None,
    probe_endpoints=False,
)
public_status = result.as_dict()
```

The [installed status command](manager-status-cli.md) invokes this library
through trusted read-only handles. The library itself supplies no
recording operation, store recovery, migration, application protocol or
authorization. A
writable store handle is refused. The caller opens the existing store
and policy through their established trusted boundaries; parsed policy
objects and imported store/report JSON are not accepted substitutes.
No store is created or reopened automatically. Read-only access failure
stays unavailable instead of triggering recovery.

## Exact context and retained obligations

Before queries, the coordinator reparses the exact declaration bytes,
validates component selection and checks the live policy, host UUID,
accepted engine aliases, management projection and current recorded
snapshot. Uncommitted working declarations are valid status targets;
property agreement does not imply that their intent has been recorded.

The manifest contains all current resources and all retained accepted or
relinquished physical resources, independently of component selection.
Retained resources get first positions in the resource scheduling limit.
A physical match uses the current logical label so accepted checks follow
renames. Accepted predicates, grants, stable IDs and adoption bindings
remain the original store records. Removed and unselected resources keep
their accepted checks in the report.

A logical label reused for different physical targets makes its property
observations unavailable with `status_logical_identity_conflict`; both
current and historical checks stay unknown. A physical resource changed
to another kind, or a retained Compose deployment with a different
service aggregation scope, also stays unavailable. This conservative
choice avoids rewriting private store projections or conflating the
planner's single fact per label/property with multiple physical targets.
The collection summary keeps the affected stable IDs. An unresolved
engine alias or unsupported resource kind receives a fixed unavailable
reason without invoking its tools.

The complete manifest permits at most 1024 current-plus-retained resource
entries and 8 MiB of private resource context. Overflow fails before host
queries with `status_scope_limit`; it never returns incomplete coverage
as a complete manifest. Duplicate current identities that resolve to the
same accepted physical target fail with
`status_physical_identity_conflict` before collection.

After collection, the coordinator reads the live policy, management
projection, aliases and recorded snapshot again, including for empty
resource and input sets. Changed or unavailable context returns a fixed
`StatusCollectionError` and no report combining the earlier evidence with
new history. These checks do not exclude changes after the final read or
create an atomic host snapshot.

## Evidence ownership

The coordinator dispatches system services to the
[native observer](manager-observations.md), users/groups to the
[account observer](manager-account-observation.md), explicit paths to the
[file metadata observer](manager-file-observation.md), and Compose
projects to the [Compose observer](manager-compose-observations.md).
Each adapter retains its supported properties, exact physical identity,
fixed evidence source and limitations. Compose uses accepted actual
engine IDs and retains service scope in its private scalar facts.
Nested Docker inventory is not exported by status.

Packages use both direct installed inventory and
[positive request satisfaction](manager-package-satisfaction.md).
Direct positive presence remains the prerequisite for version and
installation-reason checks. Positive dependency satisfaction can replace
only absent or unknown direct presence; it cannot supply version, reason,
provider identity or provenance. Missing/unavailable satisfaction never
becomes absence. The planner's source/property guards remain in force.
Package requests are grouped in batches of at most 256 after other
resource adapters, sharing the same global query budget.

Protected inputs use the existing
[`ProtectedRecorder.observe_inputs`](manager-protected-bindings.md#protected-input-status-evidence)
API against the exact current recorded snapshot. Their status remains
separate from property agreement. This protected subset does not inspect
nonsecret or historical input closure. Input failures do not erase useful
property evidence, and matching properties cannot clear input blockers.

`complete_inputs=True` instead loads `HostStore.current_with_inputs()`
and uses `ProtectedRecorder.observe_recorded_inputs` with the planner's
independent manifest and `recorded_input_observations` argument. The
legacy default remains unchanged; neither mode supplies both batches.
The complete mode includes current and retained declared-file obligations
across classifications, dependencies and consumers. It collects only for
an exact recorded target; edited working declarations keep their history
manifest but unavailable input results and cause no input-file reads.
Its collection summary uses `recorded_input_reason` in place of
`protected_input_reason`. Bounds and unsupported closure are defined by
the [recorded-input guide](manager-recorded-input-evidence.md).

`check_file_content=True` independently opts into
[target-content reporting](manager-file-content-reporting.md). It loads
`file_content_manifest` before host observation, invokes
`collect_file_content` only for the exact recorded target and checks the
manifest again after all collection, including failures and empty scopes.
Its separate `file_content_reason` records scheduling or collection gaps.
The default adds no content section and reads no target bytes. Target
reads retain policy-root and byte limits with no filesystem deadline.

An optional `expected_revision` pins the initial live context before any
host queries. Installed status supplies the revision used to choose its
target, so a race between target selection and collection is refused.
Complete manifests are loaded and compared again at the final check;
unavailable or changed coverage cannot accompany a successful report.

Endpoint probing is opt-in through `probe_endpoints=True`. Even with that
flag, the working declaration must exactly equal the current recorded
snapshot, including source comments, before any probe is scheduled. A
changed working-tree URL or predicate therefore cannot initiate requests.
The [endpoint collector](manager-endpoint-checks.md) derives complete
current and retained roles from the actual store. Recording and removal
never call this coordinator or initiate probes. An explicit later status
request can inspect retained accepted routes after a recorded removal.
Route matches remain functionally unverified and do not establish the
listener or application's identity.

## Scheduling and latency

Defaults are a 60-second scheduling budget, 1024 native queries, 64 MiB of
reserved query-output capacity, 256 scheduled resource targets, and 64
endpoint probes. Callers may lower these limits. Maximum accepted values
are respectively 300 seconds, 4096 queries, 128 MiB, 1024 resources and
256 endpoint probes. Unscheduled targets retain explicit unknown facts
and coverage; query-limit reasons appear in the collection summary.
`coverage_complete` describes manifest coverage, not successful queries,
known properties, complete input closure or health.

Every native/account/Docker query reserves its complete combined
stdout/stderr allowance before execution, including potentially failed
output that parsers never receive. Allowances are 1 MiB for package
inventory, 16 KiB for service/account properties, 128 KiB for package
satisfaction and 256 KiB for Docker queries. This conservative accounting
can leave byte budget unused; it never treats discarded output as free.
The public count is reserved capacity, not actual bytes observed.

Default native, account and Docker runners receive shortened deadlines
from the remaining global budget. The package satisfaction runner has a
fixed ten-second deadline, so its query starts only when that full
interval fits. No new query starts after the time/count/byte limit;
invalid, oversized or late injected results cannot become known facts.
Exceptions expose fixed diagnostics without raw text, and cancellation
propagates. The subprocess adapters retain their bounded cleanup limits.

Endpoint probes share the remaining scheduling time through the existing
collector and have a separate count and transport byte limits. Protected
input reads retain their separate 64-entry, 64 MiB aggregate and 16 MiB
per-file limits. Complete recorded-input mode adds bounded retained-role
coverage and at most 64 distinct capture contexts. Policy/store
verification, file metadata, synchronous NSS
resolution and protected-file reads have **no enforced latency deadline**.
A returned late metadata/input result is discarded and no further
resource work is scheduled after expiry, but an in-progress kernel or
trusted callback operation is not forcibly preempted. This API does not
promise a hard wall-clock bound.

Native scalar facts use one collection-start timestamp; endpoint evidence
keeps its own collector start. The report evaluates freshness at actual
report creation, with a default 60-second maximum age. Slow collection
cannot refresh old facts by assigning a completion timestamp. A
`collected` target means its adapter ran, not that all its properties
were known. Consult the report's property/check results for evidence.

Runner and identity-resolver arguments are trusted Python embedding seams
for tests. They are not declaration fields or request-controlled programs,
and arbitrary callbacks are not process containment. Public projections
omit private facts, filesystem paths, query output, source bytes, input
references, content digests, URLs and predicate values. Every report
remains non-executable with application and attempt-history blockers.

## Validation

The focused tests use real private read-only SQLite stores, authenticated
protected captures and Linux metadata descriptors, with synthetic native,
account, Docker and endpoint responses. They exercise source aggregation,
retained checks, renames, selection/removal, conflicts, context races,
limits, privacy and byte-for-byte store preservation. They perform no
production package/account/service/Docker/endpoint operations and do not
establish an installed privilege boundary or first-release acceptance.

```sh
.venv/bin/python -m unittest discover -s tests \
  -p test_manager_status_collection.py -v
```
