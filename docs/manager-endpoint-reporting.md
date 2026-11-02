# Recorded endpoint evidence in comparison reports

`mpkg_manager.planning.build_report` accepts an optional typed
`endpoint_observations=EndpointCheckBatch` from the
[recorded endpoint collector](manager-endpoint-checks.md). Report building
is pure: it reads no store, filesystem or socket, starts no processes,
and never initiates collection. A trusted embedding obtains current
management context and evidence separately, then calls the planner.

```python
report = build_report(
    declaration,
    current_store_projection,
    ordinary_observations,
    host_id=host_id,
    engine_aliases=accepted_engine_aliases,
    endpoint_observations=endpoint_batch,
)
```

Only the exact immutable batch type is accepted and its fields are
revalidated. Public dictionaries, serialized projections, subclasses and
malformed batches fail with `invalid_endpoint_observation`. Typed Python
objects are not a containment boundary against hostile Python code.
Management projections still require the existing trusted host boundary;
shape validation does not authenticate caller-created history.

## Complete binding and scope

A usable batch must match the requested host and current management
revision and snapshot. The declaration's exact source, normalized model
and encoding versions must match that recorded snapshot. Changing only
source comments therefore invalidates evidence until the new intent is
recorded and collected. Time is measured from collection start using
`now` and `max_age_seconds`; future evidence and evidence older than that
limit are unavailable. Exactly the maximum permitted age is accepted.

The planner reconstructs the collector's entire required-role manifest
with its pure scope helper. Current coverage includes only checks linked
through resources, never unreferenced root definitions. Accepted coverage
includes retained accepted definitions from every recorded resource,
including removed, renamed, unselected and relinquished resources.

The complete normalized predicate, physical target, original logical
labels, role, stable resource UUID, adoption revision/snapshot and
management state must agree. Check IDs are used for lookup only after
this complete private manifest matches. Same-ID predicate changes or
physical replacements cannot substitute for accepted observations.
Component selection never weakens the required coverage: missing evidence
for an unselected current or accepted endpoint invalidates the whole batch.

Accepted predicates follow their stable physical target through current
logical renames without rewriting the original predicate labels. Selected,
retained and unselected accepted check rows receive their corresponding
route evidence. The top-level summary also retains current endpoint rows
outside the selected component set. Relinquished management remains
explicit and confers no authority.

More than 4096 required endpoint roles makes the summary unavailable with
`coverage_limit` and an empty `entries` inventory; `required_checks` gives
the full count. It never claims a truncated list is complete. Typed evidence
and reconstructed private manifests retain the collector's 16 MiB bound.
Older management projections missing accepted definitions cannot establish
complete coverage and retain their existing required-check blockers.

## Reported outcomes

The top-level `endpoint_checks` summary includes state, fixed reason,
collection time, source, scope, coverage, required count and per-role
entries. `state: available` with `coverage: complete` means the entire
batch is applicable to this report; individual routes may still be
unavailable because of transport failures or collection count/time limits.

Missing history or evidence, unrecorded intent, foreign host/target,
stale/future time, incomplete coverage or mismatched predicates/physical
context make every route unavailable. No unaffected subset is promoted
from a partially applicable batch. Ordinary property and protected-input
evidence remain independently evaluated.

Endpoint checks keep `result: unknown` and report separate
`route_result: match|mismatch|unavailable` and a fixed `route_reason`.
Both check rows and the summary permanently report
`functional_result: unverified`, `listener_attribution_unavailable` and
`application_identity_unverified`. Matching HTTP status is not application
identity or functional success. Existing required-check, functional-health,
protected-input, application and attempt-history blockers remain in force.
The report remains non-executable.

New endpoint summaries expose logical labels, roles, stable UUIDs,
adoption revisions and fixed reasons. They omit URL and expected/observed
status values, physical target details, original predicate values,
response content and private binding bytes. Existing report target and
accepted-check snapshot metadata retain their documented nonsecret
meaning; this integration adds no predicate digest or secret-bearing
output. Every report projection is a fresh copy of immutable bytes.

Focused validation composes real private stores and synthetic endpoint
results with the pure planner. It forbids filesystem, SQLite, socket,
transport and process calls during report construction; checks complete
role coverage and exact snapshot/predicate/physical bindings; and exercises
renames, removals, relinquishment, selection, age boundaries and redaction.
The adjacent protected-input, file-metadata and integration suites remain
part of the relevant checks. These tests establish no production endpoint
health, listener attribution or application acceptance.
