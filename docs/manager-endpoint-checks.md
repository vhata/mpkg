# Recorded endpoint check collection

`mpkg_manager.endpoint_checks.collect_endpoint_checks` explicitly collects
loopback route evidence for the required endpoint checks in an actual
caller-owned `HostStore`. It accepts a positive `revision` and exact
`snapshot_id` from that store's current context. A stale request fails
before probing. A final store read must still match both values; a changed
revision or unavailable store returns a fixed error and no batch.

```python
current = store.current()
batch = collect_endpoint_checks(
    store,
    revision=current["revision"],
    snapshot_id=current["snapshot_id"],
    budget_seconds=60,
    max_probes=64,
)
public = batch.as_dict()
```

This is a trusted library call, used by the
[status command](manager-status-cli.md) only with explicit endpoint
opt-in and exact recorded intent. It is never triggered by declaration
recording or removal, and it grants no health or application authority. Ordinary
recording and declaration removal never request endpoint probes. Use the
[endpoint transport guide](manager-endpoint-observations.md) for the fixed
HTTP(S) request, loopback mapping, TLS verification and transport limits.
GET routes must be selected by trusted authors for their read-only health
semantics; this library cannot establish server-side behavior.

## Coverage and original predicates

Collection retrieves the exact current snapshot through the actual store.
Only checks linked through each resource's `checks` list enter current
coverage. Unreferenced root check definitions never cause requests. Other
check kinds are outside this collector's coverage.

Every retained resource's accepted endpoint definitions also enter
coverage, including resources removed from current intent, renamed in
current intent or explicitly relinquished. Accepted rows keep the original
predicate, logical labels, stable resource UUID, physical target, adoption
revision and adoption snapshot. Relinquished rows explicitly retain their
`relinquished` management state; observing them confers no authority.
The [store](manager-store.md) verifies that historical linkage before the
collector uses it. Arbitrary management projection JSON is not accepted.

Accepted rows get first access to the probe budget, in the store's stable
resource order, followed by current declaration/resource-link order.
Current and accepted roles always remain separate rows. They share one
probe only when the entire normalized check, including logical labels and
timeout, and the exact host-bound physical target agree. Same-ID predicate
replacement, logical renaming or physical replacement cannot reuse the
wrong observation. Compose alias spelling may differ when both aliases
bind the same accepted engine and project.

A current Compose resource with an unresolved engine alias gets an
explicit `physical_identity_unbound` row and causes no request. Accepted
physical keys must match the retained store context. No observation can
substitute for an adoption or identity-binding decision.

## Budgets and completion

The complete role inventory is validated before any network request.
More than 4096 rows or 16 MiB of private manifest fails the whole collection
with `endpoint_coverage_limit`; no partial inventory is returned.

The scheduling budget defaults to 60 seconds and accepts integer values
from 1 through 300. It starts before store reads. The probe count defaults
to 64 and accepts integers from 1 through 256. These bounds are caller
controls, never declaration-selected commands or authority.

Each probe keeps its original declared timeout. A probe starts only when
that entire timeout fits the remaining budget. Setup overhead can therefore
exclude a check whose timeout equals the entire collection budget. This
conservative scheduling preserves the original predicate binding. A long
check that cannot fit does not prevent a later shorter check from running.

Every unscheduled check still has an explicit unavailable row with
`collection_budget_exhausted` or `collection_probe_limit`. A probe that
completes after its own deadline loses its result with
`collection_probe_timeout`; total budget expiry instead records
`collection_budget_exhausted`. Fixed transport failures remain unavailable.
`coverage_complete` means every required endpoint role has a row, not that
every route was probed or functional verification succeeded.

Store locks are nonblocking, but complete-history verification, local
filesystem/SQLite I/O and kernel process cleanup are not forcibly
preemptible here. The scheduling limit is not an absolute realtime bound
on the whole call. An injected `runner(url, timeout_seconds)` is trusted
embedding code and must implement its own deadline and cancellation;
late return cannot produce successful route evidence. Cancellation
propagates, with the default transport cleaning up its worker group.

## Evidence, privacy and limits

`EndpointCheckBatch` and its `EndpointCheckResult` rows are immutable.
Their private bytes retain complete original predicate, snapshot and
physical context. `batch.matches_context(host_id=..., revision=...,
snapshot_id=...)` compares exact requested context without I/O; it does
not recheck store freshness on its own. Row `matches_context` additionally
requires the original check/resource, role, snapshot and, for accepted
rows, stable UUID and adoption revision. It compares the complete check
and physical target, not a check ID. Callers supply trusted current store
context before reuse. There is no JSON-to-authority import API; these
Python objects are not a containment boundary against hostile Python code.

Each `.as_dict()` returns a fresh public projection. It omits URLs,
expected/observed status numbers, target details, snapshot digests,
response content and original predicate values. It retains role labels,
stable IDs, adoption revisions, fixed reasons and management state.
The batch timestamp is collection start; observations are not an atomic
host snapshot and do not guarantee continued endpoint availability.

Every object and projection permanently reports functional verification
as `unverified`, with `listener_attribution_unavailable` and
`application_identity_unverified`. A matching route status cannot pass
an accepted or current functional check. `executable` is always false.
Attributed listener/application evidence remains a separate capability.
The [pure planner](manager-endpoint-reporting.md) can consume a supplied
batch without initiating collection or functional verification.

The focused suite uses private real SQLite stores, trusted synthetic
runners and an owned ephemeral loopback HTTP listener. It checks retained
roles, exact source snapshots, physical aliases, coverage and time/count
limits, revision races, cancellation, immutable projections and store
file preservation. It never probes production endpoints or supplies
listener attribution, real application acceptance or apply authority.
