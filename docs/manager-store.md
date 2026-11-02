# Durable host records

`mpkg_manager.store` implements recording primitives for the replacement
manager. Recording never installs software, applies configuration,
changes accounts, starts services or changes package reasons. It is a
library for the future bounded recorder, not an installed privileged
helper or a complete authorization boundary.

## Ownership and lifecycle

`HostStore.create(directory, host_id, engine_aliases=None, owner_uid=0)`
creates a new private directory and a versioned SQLite store. It refuses
an existing destination. `open_existing` and `open_readonly` require an
existing valid store and the expected host UUID; neither initializes,
migrates or repairs one. All three return context managers.

Production ownership defaults to UID 0. The directory must be `0700`,
and the database and pre-existing lock file must be single-link regular
files owned by that UID with mode `0600`. Symlink traversal, unsafe
ancestors, replacement file identities and inappropriate modes are
refused. Tests explicitly pass their temporary fixture owner's UID to
the library; declarations and CLI inputs cannot select that override.
The installed recorder must bind `/var/lib/mpkg` and host identity using
the separate root-owned host policy described in the
[execution design](specs/2026-10-31-first-release-storage-and-execution.md).
That installed recorder and policy dispatcher are not provided here.

SQLite 3.37 or newer is required for the strict schema. The store checks
its exact schema, application/version identifiers, host identity and
database integrity. On open and inside each read/write transaction, it
also validates the complete immutable history: exact source/model
snapshots, contiguous decision revisions and UTC timestamps, stable
UUIDs, host-bound physical keys and accepted resource transitions.
Definitions, retained requirements and relinquishments must agree with
their decision snapshots and previous accepted facts. Protected capture
identities, links and keyed tokens are checked privately. Malformed
records fail with `store_corrupt` before projections or new writes;
schema validity alone cannot establish accepted authority. This is a
corruption check, not authentication against an administrator who owns
the store. Complete-history validation is intentionally unoptimized.

The store uses rollback journaling with `DELETE`,
`synchronous=EXTRA`, foreign keys and short `BEGIN IMMEDIATE` writes.
Settings are read back because SQLite silently ignores unknown pragmas.
`EXTRA` adds synchronization of the directory after rollback-journal
unlink; this does not make an external operation part of the database
transaction. See [SQLite pragmas](https://www.sqlite.org/pragma.html#pragma_synchronous).

Read-only access uses an existing shared lock, `mode=ro` and
`query_only`; it does not create files, change modes or initialize schema.
It does not use `immutable=1`, which would bypass normal change detection
and locking. See [SQLite URI parameters](https://www.sqlite.org/uri.html).
Any leftover rollback journal, WAL or shared-memory sidecar causes an
explicit recovery-required error before SQLite opens. Recovery and
migration need a separate maintenance implementation. An interrupted
creation can leave an incomplete private directory, which is retained
and refused rather than silently repaired.

## Recording and adoption

- `record_intent(declaration, expected_revision, protected_inputs=())`
  records an immutable validated snapshot without adopting resources.
- `adopt(declaration, expected_revision, resource_ids,
  protected_inputs=())` deliberately accepts the selected identities,
  authority, consumers and requirements. It records an unknown
  observation baseline; it does not claim the live resource was checked.
- `relinquish(stable_resource_ids, expected_revision)` records external
  responsibility without stopping or removing resources or their data.
- `current()` projects accepted and relinquished resources, the exact
  latest snapshot and decision revision, and missing-declaration
  dispositions. `history()` projects the append-only decision sequence.

The `current()` projection includes `snapshot_id` and a `snapshot`
metadata object containing `id`, `source_sha256`, `canonical_sha256`,
`schema_version` and `normalization_version` (both fields are null before
the first decision). These identify explicitly nonsecret declaration
content, so a planner can bind exact input without exposing the source.
Protected input digests and tokens are never included.

Each resource also has `accepted_checks`, containing `adoption_revision`,
`snapshot_id` and `definitions`. The definitions are the normalized
required predicates from that stable resource's last explicit adoption
decision. They are recovered from its immutable historical snapshot;
there is no schema change or lookup of replacement current predicates.
Intent recording, logical renaming, declaration removal and
relinquishment preserve this binding. An explicit new adoption records
a new check baseline. Missing or inconsistent historical linkage fails
closed instead of fabricating an empty check list.

The predicate schema contains only declared nonsecret fields. Generated
protected references, capture bytes and tokens remain private. Every
projection is a fresh value; changing a returned check cannot modify
accepted history. The planner consumes these predicates through the
trusted host boundary and emits separate accepted/current result
summaries without predicate values.

Each write compares the expected revision inside the transaction. A
stale request publishes neither a new decision nor its snapshot or
protected inputs. Physical identity is bound to the host UUID and
accepted engine aliases; unresolved aliases cannot be adopted. Two
aliases resolving to the same physical resource are checked together.

Stable resource UUIDs survive logical renaming. Removing declarations or
recording new intent preserves adopted resources and their authority.
An absent declaration requests a disposition; it never authorizes
deletion. Existing consumers and their accepted requirements remain
recorded. Re-adoption cannot silently upgrade authority, change an
active logical identity or discard a consumer constraint. A dedicated
authority/consumer-change decision API remains future work.
The combined retained and new constraints pass the same contextual
validation as declarations, including AUR recipe bindings and file-input
references. Validation-only component entries preserve historical
consumer identities without granting additional management authority.

Snapshots retain both the original nonsecret TOML and normalized model.
Their identity binds both source and canonical digests plus schema and
normalization versions, so changing comments does not substitute an
older source file. Supplied `Declaration` instances are reparsed and all
fields compared; constructing a dataclass is not validation authority.
`snapshot(snapshot_id)` is trusted source retrieval, **not ordinary
status or history output**. Source may include explicitly declared opaque
references, which must not be dumped by an unprivileged projection API.

## Protected capture and failure reporting

`ProtectedInput(name, raw, source_identity, purpose)` accepts already
captured bytes and a complete regular-file identity from the trusted
recorder. That recorder must enforce allowed roots and stable descriptor
reads. This library does not read arbitrary live paths. Inputs above
16 MiB, incomplete identities, hardlink identities and duplicate names
are refused. Protected bytes, generated opaque references and private
HMAC tokens are written in the same transaction as their decision.

The separate [protected recorder](manager-protected-bindings.md) adds
explicit declaration bindings. Its tagged tokens authenticate the exact
origin decision, snapshot and input scope as well as identity/content.
SQL tables remain unchanged; new readers accept legacy 32-byte tokens,
while older readers reject new bound-token records. Generic recording
continues to produce legacy captures and does not authenticate arbitrary
declaration UUIDs.

`compare_protected(revision, name, raw, source_identity)` returns only
`same`, `changed` or `unavailable`. The comparison binds the full bytes
and source identity. `current()` and `history()` omit protected bytes,
references, source identities and raw/keyed digests. Classification of
source as nonsecret is explicit; automatic secret detection is not
claimed. Protected database contents are plaintext behind access
controls, not encryption at rest.

Public failures contain fixed `StoreError.code` values, never raw SQLite
or filesystem errors. A failed commit reports `commit_outcome_unknown`
and closes the handle: the commit may have persisted before its error
was observed. Cancellation during commit preserves the original
interrupt and also closes the transaction before releasing the store
lock. Reopen and inspect the revision/history before deciding
what to do next; do not blindly retry. No external effect is invoked.

The focused tests cover real temporary SQLite transactions, competing
revisions, failure before/after commit, storage exhaustion, retained
adoptions, exact source snapshots, semantic corruption and secret-free
public projections.
They do not establish power-loss durability, encrypted backup, restored
authority recovery, an installed privilege boundary or A1–A12 product
acceptance. Attempts, action execution and plan storage are separate
future work.
