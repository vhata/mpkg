# Native file metadata observation

`mpkg_manager.observe_files.observe_files` collects read-only Linux
metadata for explicitly supplied file, directory and symlink resources.
It does not read file contents, enumerate directories, recurse, hash,
create paths, change permissions or grant management authority. The
[comparison report](manager-planning.md) consumes its facts independently
of protected-input freshness and resource adoption.

## API and trust

```python
batch = observe_files(
    path_resources,
    host_id=accepted_host_uuid,
    observed_at=utc_collection_start,  # optional; defaults to current UTC
)
report = build_report(
    declaration, store.current(), batch.as_dict(),
    host_id=accepted_host_uuid,
)
```

The caller supplies a list or tuple of at most 256 resource dictionaries,
filtered to `file`, `directory` and `symlink`. All IDs, kinds and path
identities are validated before filesystem I/O. Duplicate IDs,
noncanonical paths and unsupported kinds are refused with the fixed
`invalid_file_observation_request` diagnostic. A path has at most 4096
UTF-8 bytes and 128 components. Validation covers these metadata target
fields, not the complete declaration or its content/check/component
references. An otherwise valid file can refer to a content bundle absent
from this observer call. Its content remains unobserved.

The immutable `ObservationBatch` binds every fact to host, resource ID,
kind, path identity, UTC collection-start time and the fixed
`filesystem_metadata` source. Coverage lists every requested resource,
including unknown results. Raw internal facts contain paths, account
names and symlink targets. They are intended for trusted embedding; the
public report exports comparisons and fixed limitations without those
values. Shape validation is not host authentication. There is no CLI or
installed privileged boundary in this adapter.

## Metadata and paths

The adapter observes `present`, integer Unix `mode`, `owner` and `group`.
Symlinks also expose their literal `target`, including dangling targets;
the destination is never opened. Symlink mode is observed metadata, not
an assertion that the tool can or should chmod a symlink. File
`content` and `content_input` remain unknown, including when a supplied
projection tries to claim known content from the metadata source.
Directories describe the directory
itself, not its descendants. Metadata does not establish consumer access,
ACLs, application health or input content freshness.

Traversal starts at `/` and opens each parent using Linux
`O_PATH | O_DIRECTORY | O_NOFOLLOW`. The final entry uses
`O_PATH | O_NOFOLLOW`, so even FIFOs and other special files cannot cause
content reads or blocking data opens. The adapter refuses parent symlinks
and non-directory parents with distinct unknown reasons. It does not
apply the protected-capture ownership/root policy: this is observation
of declared metadata, not a protected-content read or containment API.

Before and after observation, the final entry's identity, type, mode,
ownership, link count, size, mtime and ctime must match both its descriptor
and its parent directory entry. Parent descriptor identities, ownership,
mode and directory entries are rechecked. A missing leaf or ancestor
requires a second absent lookup and verified existing parents before
reporting `present=false`. Other properties then have absent evidence.
Denied access, wrong kinds, replacements and detected races remain
unknown; denial never proves absence. A wrong kind does not authorize
replacement or inherit a different kind's accepted property grants.

Traversal may cross mount points. Device numbers participate in identity
checks, but bind-mount aliases and unobserved changes remain limitations.
This observer neither traverses a symlinked parent nor resolves it to an
alternate resource identity. It makes no claim of a globally atomic
filesystem snapshot, writer exclusion or containment against trusted root.

## Account names and timing

Default `SystemIdentities` lookup uses the observed UID/GID. A reverse
NSS lookup must return a name satisfying the declaration's bounded name
grammar and the same numeric ID. A forward lookup of that name must agree
with both. There is no account enumeration or synthetic numeric name for
an unmapped ID. Resolution errors, unsupported names or conflicting
records leave only the affected ownership property unknown; other
metadata can remain known. There are at most four NSS API calls per
resource, with no cross-resource cache.

The optional `identities` argument is a trusted Python test/embedding
seam exposing `user(uid)` and `group(gid)` methods returning valid names
or failing. A custom resolver is responsible for the same reverse/forward
identity semantics; returned names are still validated. Declarations
cannot select resolvers, commands, account databases or filesystem roots.
Tests use private resolvers or stub all NSS queries; no host account is
created, removed or changed.

Filesystem operations and synchronous NSS calls have no elapsed-time
bound here. The bounded resource/call counts do not imply a deadline,
atomic NSS snapshot or bounded network latency inside an NSS provider.
The timestamp is sampled once before all validation and I/O, so slow
collection cannot refresh evidence age. The planner rejects stale or
future evidence using its own clock and retains all application,
attempt-history and full-input limitations. Cancellation propagates and
closes descriptors owned by the observer.
