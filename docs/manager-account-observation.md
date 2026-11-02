# Local account and group scalar observations

`mpkg_manager.observe_accounts.observe_accounts` collects positive scalar
facts about explicitly requested local users and groups. It neither
creates accounts nor proves their safe absence. Account/group deletion,
UID/GID changes, membership management and access checks are outside this
adapter. Facts cannot grant management or application authority.

## Interface and evidence

```python
batch = observe_accounts(
    account_resources,
    host_id=accepted_host_uuid,
    observed_at=utc_collection_start,  # optional
)
```

The input is a list or tuple of at most 64 `user`/`group` resource
dictionaries. IDs, kinds and name identities are validated before any
queries, with duplicate IDs rejected. Other declaration context is not
validated or required here: external consumers/check references do not
prevent metadata observation. Invalid requests fail with fixed
`invalid_account_observation_request` diagnostics.

A user can supply known `present=true`, `home`, `shell`, `primary_group`,
`uid` and `gid`; a group can supply known `present=true` and `gid`.
Numeric IDs are internal observation context, not authority to alter an
adopted identity. Unsupported home/shell paths remain unknown while other
stable properties can remain known. Unresolved or conflicting primary
group records leave that property unknown without discarding stable user
properties. All-digit account names remain unknown without queries,
because getent interprets numeric keys as IDs, not exact names.

`groups` and `members` always remain unknown. The contract's required
memberships are additive, and the scalar fact model cannot represent
membership satisfaction safely. Empty member fields never imply no
memberships, and unlisted memberships are never marked for removal.

The immutable `ObservationBatch` binds every fact to the accepted host,
resource ID/kind/name, UTC collection-start time and fixed source
`local_account_properties`. Coverage includes unavailable targets. Raw
internal facts may contain names, home/shell paths and numeric IDs.
Password/hash, GECOS and member-list fields are dropped before evidence
construction; errors never include raw records or diagnostics. Facts are
trusted internal metadata, not authenticated imported JSON. This module
adds no command-line surface or installed privileged boundary.

## Closed native queries

Only `/usr/bin/getent`, `passwd` or `group`, and one validated name or
canonical numeric key are accepted. The adapter uses the fixed `files`
service and default NSS resolution; there is no database enumeration,
`shadow`/`gshadow`, shell, sudo, caller-selected executable/service or
environment override. The closed environment contains only `PATH`,
`LC_ALL` and `LANG`.

For each sample, local-by-name and default-by-name records must agree
with local/default numeric reverse records. Primary groups use the
corresponding numeric-to-name checks. Returned names and IDs must match
the requested identity. Supported fields must agree between local and
default records, and two complete samples must be stable. A user needs
at most 16 queries; a group needs at most 8. Password/GECOS/member fields
are intentionally neither compared nor interpreted as managed facts.

Strict parsing requires one complete UTF-8 line with exactly the passwd
or group field count, no control characters, bounded names and canonical
unsigned 32-bit IDs excluding the sentinel value. Unsupported/ambiguous
records, returned-key mismatches, changing properties, failed queries,
nonempty stderr or unavailable tools produce fixed unknown reasons.
An empty exit-2 result means not found **or unavailable**, never verified
absence. Identical duplicate records or a hidden directory-service record
cannot be excluded by exact native lookups; that limitation remains
explicit even when current local and default results agree.

## Bounds, timing and validation

Each query has a 16 KiB combined stdout/stderr bound and at most two
seconds. Scheduling shares a 30-second monotonic collection budget;
remaining time shortens the next query timeout, late results are refused,
and no new query is scheduled after expiry. The shared process runner
stops descendants on failure and preserves cancellation. Process startup
and bounded cleanup still have their existing operating-system limits;
this is not a hard real-time guarantee or an atomic NSS snapshot.
Collection-start UTC is sampled once before all queries.

A trusted Python `runner(argv, *, timeout)` seam supports fixtures. It
must implement the same output, completion and timing policy; an arbitrary
callback is not process containment. The adapter independently validates
result type, output bound, record protocol and collection deadline. The
normal runner accepts only exits 0 and 2 and requires empty stderr.

Tests use exact response stubs and owned Python children for process
failure, overflow and timeout checks. They never query production passwd,
group, NSS or getent, and never create/change host accounts. This library
evidence does not establish real Arch deployment or first-release
acceptance.

## Pure comparison reports

The [planner](manager-planning.md) accepts this source only for user
`present`, `home`, `shell` and `primary_group`, and group `present`.
Presence evidence must be the boolean `true`: false, numeric or other
values cannot establish absence, even when the desired value is false.
User scalar comparisons also require current positive presence with the
same source, host, resource kind, physical identity and observation scope.
Missing, mismatched, incomplete, stale or future evidence remains unknown.

Membership facts remain unsupported even if a supplied projection claims
they are known. Numeric UID/GID facts supply internal context only; they
do not add management properties. Public reports redact scalar values and
preserve existing authority through logical renames. Declaration removal
retains host records for disposition, and relinquishment keeps external
consumers without restoring grants when observations match. Comparison
writes no store files and retains application and attempt-history blockers.

## Native interface sources

The official [getent manual](https://www.man7.org/linux/man-pages/man1/getent.1.html)
defines keyed passwd/group lookups, numeric-key behavior, the service
override and completion statuses. The GNU C Library's
[NSS configuration manual](https://sourceware.org/glibc/manual/latest/html_node/NSS-Configuration-File.html)
explains per-database service order. These interfaces motivate comparing
explicit `files` results with default NSS rather than assuming a name
always resolves to the local account. The documentation substantiates
interface choices, not successful live-host validation.
