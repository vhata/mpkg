# Declared-user file access

`mpkg_manager.consumer_access.observe_consumer_access` observes one
validated `access` check without changing accounts, declarations or host
history. It complements [metadata observations](manager-file-observation.md):
matching modes do not prove that a declared user can traverse a path and
perform its required read or list operation.

The API accepts a check and its resource plus trusted host context. The
resource must already name the check's consumer. Local component and
external consumer IDs are supported; neither implies a running process
or grants management authority. The existing declaration schema, planner,
status collector and installed helper remain unchanged by this module.

## Supported operations

- A `read` check on a regular `file` attempts to read the complete file,
  with a 1 MiB ceiling. A larger or growing file is unavailable, not a
  successful prefix check.
- A `list` check on a `directory` attempts to enumerate the directory,
  with a 1,024-entry ceiling. Names and entry counts are never returned.
  An exceeded limit is unavailable, not complete listing evidence.
- Symlink and volume resources, read/list kind mismatches, numeric user
  names, UID 0 and primary GID 0 remain unsupported. Symlinks anywhere in
  a supported target path, FIFOs, devices and other special targets are
  refused. Paths have at most 64 components and 4,096 UTF-8 bytes.

The declaration validator's normalized absolute path is bound before
queries. One observation covers the exact check ID, consumer, operation,
user name, timeout, logical resource and physical target. Changing caller
dictionaries during a query cannot relabel the result.

## Credentials and private worker

The collector uses only fixed `/usr/bin/getent` queries with a minimal
environment. It requires matching local-files and default NSS passwd
records by name and numeric UID, then matching complete `initgroups`
results including the primary GID. It repeats the same six queries after
the worker returns. Conflicts, missing output, malformed results or any
changed UID/GID/group set invalidate the observation. Each response is
bounded to 16 KiB and the group set to 256 IDs. Matching queries do not
prove that no hidden identical account exists in another NSS source.
The [getent interface](https://man7.org/linux/man-pages/man1/getent.1.html)
defines the local-service override and keyed `initgroups` lookup.

The supervisor launches only `_access_worker.py` with the current trusted
Python interpreter in isolated mode, a fixed environment, working
directory `/`, closed inherited descriptors and a new process session.
Numeric credentials and target paths travel through private bounded
stdin, never argv. Output is a fixed code; stderr and unexpected output
are discarded and fail the check. The declaration's timeout covers
credential resolution, worker scheduling and final resolution. Each NSS
query is also capped at two seconds. The supervisor stops owned worker
processes on completion, timeout or cancellation; a kernel-blocked child
cannot be guaranteed to disappear immediately.

Only the isolated child may change credentials. When launched with root
privilege it sets supplementary groups, all GID slots and all UID slots,
in that order. An unprivileged child proceeds only if its actual complete
credentials already match exactly; missing groups are never approximated.
The worker disables core dumps and enables `no_new_privs`. It verifies
all four Linux UID/GID slots, the complete supplementary group set, zero
inheritable/permitted/effective/ambient capabilities and the observed
bounding set. A nonzero bounding set alone grants no current capability.

Identity UID/GID namespace mappings are required. The inherited user and
mount namespace identities, mappings and credentials are checked again
after the attempt, including empty scopes and denied/failed operations.
There is no namespace-switching or caller-selected executable interface.
The invoking installed boundary must supply the intended host namespace;
this library does not establish that it is an application's namespace.

## Target traversal and results

No target descriptor is opened before credential verification. The
worker walks from `/` under the requested credentials using descriptor
relative, no-follow opens. It holds the resolved object with `O_PATH`,
checks its type, then opens that held regular file or directory through
its own proc descriptor. A replaced pathname therefore cannot trick the
read open into opening a device or FIFO. The initial dropped-credential
walk checks ancestor search permission; no privileged descendant
descriptor bypasses it.

The worker compares held descriptor metadata and freshly walks the path
again after the operation. Replacement, metadata changes or failed final
resolution leave the target unavailable. A denied open after successful
resolution also crosses these checks. An earlier traversal denial is an
actual denied attempt, without claiming the leaf object was inspected.
Reads may update filesystem access timestamps. No writes or permission
changes are requested.

`ConsumerAccessObservation` exposes an immutable private binding and a
fresh redacted `as_dict()` projection. `access_result` is `match` for a
completed bounded operation, `mismatch` for a denied attempt, and
`unavailable` for unknown or unsupported evidence. Fixed reason codes
distinguish denied access from missing targets, limits, account conflicts,
changed credentials/paths and transport failures. Public output contains
no user name, numeric credentials, paths, file contents, entry names,
digests, raw NSS records or exception text. Typed constructors validate
shape; neither imported JSON nor caller-created objects authenticate
collection. Injected query/worker runners are trusted embedding/test
seams and must honor their own bounds.

This measures the named local account's actual read/list attempt in the
caller's mount namespace. It does not reproduce an application's running
credentials, capabilities, mount view, security domain or workflow. A
match is neither content agreement nor application functionality, and
`functional_result` always remains `unverified`. ACLs and other active
kernel access controls participate in the real attempt, but their rules
are not inventoried or managed. Descriptor rechecks are time-bounded
observations, not an atomic filesystem snapshot or mount-identity proof.

## Validation limits

Tests use synthetic NSS replies, owned temporary files/directories and
the fixed worker under the current unprivileged account. They exercise
ancestor and leaf denial, exact credential refusal, full reads/listing,
limits, descriptor replacement, malformed/private outputs, cancellation
and redaction. Root drop ordering and changed namespace/capability slots
are injected tests; no real account change, sudo invocation, root helper
installation, application namespace or Arch acceptance is performed.
