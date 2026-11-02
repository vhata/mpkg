# Explicit host-store migration

`mpkg_manager.store_migration` provides one administrative library
operation: upgrade an existing valid version-1 management store to
version 2 after a verified private backup. Version 2 adds immutable,
host-bound maintenance receipts. It preserves decision revisions,
snapshots, accepted resources, protected captures and the private key.
It changes no package, file managed by a declaration, account, service
or container. Plan execution remains unsupported.

## Compatibility and trusted entry point

New stores use version 2 and contain a sealed creation receipt. New
readers accept exact version-1 and version-2 schemas. Ordinary writes
require version 2; opening version 1 for recording returns the fixed
`store_migration_required` error through the helper and client. Existing
`current()` and `history()` projections work unchanged on either
version. Old version-1-only readers reject version 2. Unknown schemas,
modified schema SQL, unsafe paths and leftover journal/WAL/shared-memory
files fail before migration; no open silently upgrades or repairs them.

The trusted administrative API is:

```python
migrate_store(
    directory,
    host_id,
    expected_revision=revision,
    backup_directory=unused_backup_directory,
    owner_uid=0,
)
```

All paths and the ownership override are trusted embedding parameters.
There is no installed maintenance command, helper request or caller
field that selects them. Production ownership defaults to UID 0. Tests
use their private fixture owner's UID. An installed maintenance entry
point still needs its own fixed policy and authorization boundary.

The expected revision is mandatory. The operation refuses a stale
revision or any source version other than exactly 1. The destination
must be a new absolute directory beneath an already safe parent, outside
the source store. Existing destinations, including empty directories,
files and symlinks, are never overwritten or removed. Ancestors and
regular files follow the [store ownership rules](manager-store.md).

## Backup and transaction sequence

The migration holds the store's exclusive `state.lock` and a SQLite
`BEGIN IMMEDIATE` transaction from revalidation through schema commit.
The file lock excludes cooperating store readers and writers; SQLite's
reserved writer lock also blocks competing SQLite writers. The source
host identity, exact schema, complete immutable history and revision
are validated while those locks are held.

A separate read-only connection opens a read transaction on the same
verified database. SQLite's backup API copies from that connection into
a new private destination. It deliberately does not copy from the
connection holding the active write transaction. The separate source
connection can read the pre-upgrade database while the reserved writer
lock prevents intervening writes. See the
[SQLite backup API](https://www.sqlite.org/backup.html) and
[Python 3.12 SQLite interface](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup).

Both source connections and the backup must have equal privately
computed logical digests over the exact schema and all typed row
values. The backup also passes ordinary host/schema/history validation.
The read-only source and destination connections close before schema
writes begin. The migration hashes the destination database bytes,
checks stable identities, writes private backup metadata and synchronizes
files, the backup directory and its parent. Source and backup identities
are checked again before committing the new schema and sealed receipt.

The backup has a `0700` directory and three `0600`, single-link files:

- `state.sqlite3`: the verified version-1 database, including protected
  capture bytes and the private comparison key.
- `state.lock`: an empty lock file allowing ordinary read-only
  validation of the backup store.
- `backup.json`: private host/version/revision, backup identity and
  location, database size, byte digest and logical digest.

Backup database size is limited to 1 GiB. The copy progress callback and
completion check enforce a 60-second elapsed budget. This is a checked
budget, not a hard interrupt deadline for filesystem calls or history
validation. Private comparison material never appears in ordinary
projections, returned receipts or fixed error messages.

The backup covers the one management database, including captures and
its private key. It does not back up the external root-owned host policy,
packages, application data or external host effects. It is plaintext
behind access controls; encryption, restore automation, verified restore
acceptance and power-loss testing remain separate work.

## Receipt validation and recovery evidence

Version 2 requires exactly one sealed creation or migration receipt.
An omitted receipt cannot masquerade as a freshly created store. The
seal binds the host UUID, receipt UUID and kind, source and destination
versions, decision revision, timestamp and complete private backup
metadata to the store's private key. Migration receipts require the
exact 1-to-2 transition; creation receipts require revision zero and no
backup. SQL triggers refuse updates and deletion. Every store read or
write validates these invariants alongside existing history checks.
These are corruption checks, not authentication against an
administrator who owns the database and key.

A successful call returns a frozen `MigrationReceipt`. Its `as_dict()`
contains only host/receipt/backup UUIDs, revision, versions and fixed
outcome flags. `HostStore.schema_history()` supplies the durable redacted
evidence after reopening. For version 2 it reports `receipt_evidence`
as `verified` and returns bounded receipt fields without backup paths,
digests, source identities, seals or protected bytes. The verification
describes the backup at migration time; it does not assert the backup
still exists or remains unchanged later.

Version 1 reports `receipt_evidence` as `unavailable`, with an empty
receipt list. That absence does not prove an empty maintenance history
or establish rollback after a failed migration. Decision history and
maintenance history are separate and neither grants execution authority.

Failures before the commit attempt roll back the schema transaction
where possible. Partial or completed backups remain at their selected
location for inspection. A failed rollback can require recovery; no
error is a substitute for reopening and checking the store.

Once commit has been attempted, any ordinary failure, including final
synchronization or lock/handle cleanup, returns the fixed
`migration_outcome_unknown` error. Cancellation preserves its original
interrupt while closing the transaction before releasing the store
lock. Never infer rollback from an exception or automatically retry
against the same backup location. Reopen the source read-only, inspect
its version and `schema_history()` and preserve the backup evidence.
Unknown schemas or sidefiles still require explicit recovery rather
than forced opening. No restore or host-effect rollback is performed.

## Validation scope

Private temporary fixtures cover retained decisions and protected
captures, exact backup comparison, competing writer exclusion, stale
revisions, unsafe destinations, receipt omission/tampering and host/key
mismatches. Failure injection covers backup synchronization, schema
writes, commit before and after persistence, cancellation and final
cleanup. Public projections are checked for private path, byte and
digest leaks. These fixtures do not migrate the actual host or establish
an installed maintenance authorization boundary.
