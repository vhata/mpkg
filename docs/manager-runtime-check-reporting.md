# Runtime and consumer checks in status

Two independent status options expose the
[recorded runtime/access collector](manager-runtime-check-collection.md):

```sh
.venv/bin/python -m mpkg_manager status --attribute-endpoints --json
.venv/bin/python -m mpkg_manager status --check-consumer-access --json
```

`--attribute-endpoints` inspects selected-runtime ownership of covering
loopback sockets and performs its own bounded HTTP status probe. It does
not imply `--probe-endpoints`, which remains a separate route-only check.
Using both options deliberately requests both observations. Ownership
does not authenticate the responder or establish application health.

`--check-consumer-access` attempts each recorded read/list predicate as
its declared local user through the fixed isolated worker. It can report
that specific predicate as passed or failed. The copied credentials and
collector filesystem view do not reproduce the running application's
namespace, security domain or workload. Every runtime summary remains
`functional_result: unverified` and `executable: false`.

Both options default to false and are omitted from CLI requests unless
selected. They accept no user, path, executable, process, query, policy
or transport override. The installed helper's authority and the existing
fixed native adapters determine the operation. Neither records intent,
creates captures, changes privileges in the parent, nor repairs access.

## Original roles and exact context

The status collector loads an independent manifest from actual read-only
history and verified policy before collecting. The pure report validates
host, revision, full declaration snapshot, component selection and every
current and accepted private scope. Original check predicates, physical
resource identity, access consumer and selected Compose services must
match. A batch's embedded manifest cannot establish expected coverage.

Current and accepted rows remain distinct when logical/check IDs are
reused, predicates change, resources are renamed or checks are removed.
Retained and relinquished resources keep original requirements, even
outside the selected components. Excluded current rows remain visible as
not selected. An empty selection cannot hide accepted responsibilities.

Edited working declarations cause no runtime queries, HTTP probes or
access-worker attempts. Their requested component selection may name
components absent from recorded intent, so the report retains all
recorded runtime roles as unavailable. These recorded rows never supply
results to the edited declaration, even when it reuses an ID for a
different check kind. Ordinary property/metadata inspection remains the
separate existing status behavior.

After collection, the coordinator rechecks live policy, history, snapshot
and the independent manifest, including empty, failed and unscheduled
batches. Changed context refuses the entire status response. Complete
typed scope, exact collection modes and freshness are required before
any local access result can satisfy its declared predicate. Missing,
partial, replayed or stale evidence stays unknown. Typed constructors and
public JSON are not authentication or application authority.

Trusted library callers pass `runtime_check_manifest`,
`runtime_check_observations`, `attribute_endpoints` and
`check_consumer_access` to `build_report`. The first two arguments must
be the corresponding typed manifest and batch from trusted collection;
dictionary projections are refused. Omitting these arguments preserves
existing report behavior.

## Output and limits

The opt-in `runtime_checks` section lists current/accepted role, stable
ID, adoption revision, logical check/resource IDs, selection and separate
attribution/route or local-user access outcomes. Fixed reasons and
limitations explain unknowns. It omits URLs, paths, user names,
credentials, PIDs, native output, private bindings and exception text.
`coverage: complete` means all required roles have rows, not that every
row was attempted or passed. The closed helper/client schema refuses
unrequested sections, private fields and inconsistent success claims.

Runtime queries share the existing status-wide native query count and
reserved-output allowance. The collector receives only the remaining
allowance; an exhausted allowance skips the phase with explicit unknown
scope. Successful scheduling reserves full capacity before each query,
including failures: 64 KiB for runtime queries and 16 KiB for account
queries. Runtime totals are a subset of the status totals, not another
budget to add. Query-limit reasons appear in the collection summary.

At most 64 distinct runtime/access attempts share the remaining status
scheduling time; library callers may select 1–256 attempts. This bound
is independent of the route-only probe count. Original declared timeouts
must fit before scheduling, and late returned evidence is discarded.
The complete runtime manifest is limited to 4,096 roles and 16 MiB of
private bindings. Input/file reads, proc inspection and worker output
retain their own bounds; reserved query bytes are not total filesystem
bytes. Synchronous kernel, NSS, policy/history and cleanup calls cannot
be forcibly interrupted by the coordinator. No hard wall-clock or atomic
host-snapshot guarantee is implied.

Fixtures cover closed CLI/helper responses, original retained roles,
cross-kind ID reuse, changed intent, selection, missing/partial/replayed
and stale evidence, final context checks, shared reservations, denial,
late queries and redaction. They use private stores with injected native
queries and observer seams. No production package/service/Docker/NSS
operations, sudo installation or actual root credential drops are part
of these tests; real Arch and application-functionality acceptance remain
separate.
