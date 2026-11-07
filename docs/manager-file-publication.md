# Managed file publication

`mpkg_manager.file_publication` provides a narrow trusted primitive for
replacing one existing regular configuration file. It holds and rechecks
directory descriptors, requires current adapter authority and writer
exclusion, preserves supported access metadata, synchronizes a complete
candidate, replaces the target, and synchronizes its directory. It has no
public CLI/helper request, application restart, rollback or retry path.

The primitive is separate from the pure
[Sonarr Port transformation](manager-sonarr-xml.md). A transformed candidate
does not authorize publication. Production application, durable attempt
ordering, interruption decisions and post-restart functional verification
remain responsibilities of the execution boundary and lifecycle adapter.

## Trusted input and authority boundary

`capture_publication_input(policy, root=..., relative_path=...)` reads an
existing target beneath an explicit root in a verified `LoadedHostPolicy`.
It returns an immutable private `PublicationInput` containing host/root/path,
complete observed file identity, mount identity and original bytes. This
observation neither authenticates accepted intent nor excludes writers.

`bind_publication(original, candidate, adapter=..., input_reference=...)`
pairs that observation with immutable candidate bytes and an opaque accepted
input reference. Only a trusted installed adapter supplies these Python
values. Construction and shape validation are not authorization. Raw public
JSON, caller-selected paths/commands and imported report objects never reach
this API through an installed request.

`publish_file(policy, binding, revalidate=...)` requires a trusted installed
callback. It must authenticate the exact candidate and original input
against accepted history, verify current authority, and establish the full
writer-exclusion precondition. Its typed `PublicationReadiness` must name
this exact publication UUID and positively establish all four conditions:

- Accepted authority is still current.
- The original protected input and candidate binding are still current.
- All identified application writers are stopped.
- A declared maintenance interval excluding other editors remains active.

The callback runs before target inspection, before creating a temporary
candidate, immediately before the final target checks/publication, and after
publication verification. A false field, wrong UUID, exception or plain
Boolean blocks advancement. Callbacks run in trusted Python, not a public
plugin or user-authored action language. The library cannot independently
prove a caller's claim that every application writer is stopped.

Writer exclusion must span the final comparison and rename. Rename is not
an atomic content compare-and-replace, and does not lock out arbitrary
administrators. A concurrent writer outside the declared maintenance
interval can still cause a lost update in that unavoidable syscall gap.

## Supported files and path restrictions

The root must be policy-approved and canonical; target paths are relative,
bounded to 128 components and 4096 characters, with no empty, dot or parent
components. Every ancestor and parent descriptor remains held. Reopening
each link verifies device, inode, owner, group, mode and Linux mount ID.
Mount transitions above the explicitly approved root are allowed only when
their identities remain unchanged. Descendants and the target must use the
root's same device and mount ID, including same-device bind mounts.

Leaf opens are nonblocking and never follow symlinks. The implementation
refuses missing files, directories, special files, hardlinks, set-ID/sticky
metadata and any extended attributes, including POSIX ACLs. It also refuses
an inherited ACL/xattr on the candidate. Unsupported access metadata is not
silently stripped or approximated. Mount or xattr inspection failure blocks
publication. Real mount creation is not part of routine checks.

Original and candidate contents are bounded to 16 MiB each. Fresh reads
verify file size, inode/device, ownership, mode, link count, mtime, ctime,
mount identity, linked name and complete content. Directory checks ignore
entry-list timestamps because creating/removing the temporary entry changes
them. These are bounded reads and conservative race checks; regular-file
I/O and filesystem synchronization have no hard latency guarantee.

## Publication and outcomes

An unchanged candidate only revalidates authority, exclusion, policy and
original content. It creates no temporary file and performs no rename.

Changed bytes go to a random exclusive same-directory file, initially mode
`0600`. Short writes are completed. The candidate then receives the exact
original UID, GID and ordinary permission bits, verifies supported metadata
and content, and synchronizes the file. An overly restrictive process umask
does not change the final required permissions.

Immediately before replacement, policy, authority, writer exclusion,
original identity/content, held ancestors and the temporary name/descriptor
are rechecked. Replacement uses the held parent descriptor for both names.
Afterward, the directory is synchronized and the linked candidate's inode,
content and supported metadata are verified, followed by policy and adapter
revalidation. Timestamp changes caused by publication are expected; the old
mtime/ctime and inode are not preserved as if the file were unchanged.

Successful outcomes are `unchanged` or `published`. `PublicationError`
reports a fixed code, publication outcome and explicit cleanup completion:

- `not_published`: the target replacement syscall was never attempted.
  Private temporary-file activity may have occurred.
- `unknown`: replacement may have happened. This includes any error after
  entering the rename boundary, a failed directory sync, changed final
  observations, late authority loss, or post-publication cleanup failure.

Errors contain no source paths, input references, contents or raw exception
messages, including cancellation text. No error grants retry authority.
The adapter must preserve an already committed action-start record and use
the later recovery boundary to resolve uncertain effects.

Cleanup removes only a temporary name that still identifies this operation's
own inode. It preserves a substituted entry and reports incomplete cleanup.
An ambiguous rename that already moved the candidate leaves the target in
place. Cleanup never restores original bytes, invokes another rename,
restarts a service or hides a prior publication error. Descriptor close
failures remain explicit even when no target publication occurred.

Linux documents descriptor
[mount identities](https://man7.org/linux/man-pages/man5/proc_pid_fdinfo.5.html),
descriptor-relative [rename](https://man7.org/linux/man-pages/man2/rename.2.html),
and the separate file/directory
[synchronization requirement](https://man7.org/linux/man-pages/man2/fsync.2.html).

## Validation and limits

`tests/test_manager_file_publication.py` uses owned temporary files, verified
fixture policies, typed adapter evidence and simulated mount changes. It
checks source/parent replacement, symlinks, hardlinks, FIFO reads, metadata
drift, xattr/ACL refusal, short writes, restrictive umask, guard refusal at
every boundary, sync ordering, ambiguous rename, cancellation, final drift
and cleanup failures. A sentinel remains absent from errors and public
results. No test mounts a filesystem or operates a real service/package.

The primitive grants no production apply authority and supplies no durable
journal, installed write handler, application writer discovery, host lock or
functional success. The lifecycle integration tasks and original
[first-release acceptance scenarios](specs/2026-10-31-first-release-acceptance.md)
retain those requirements. Synthetic mount evidence is not real mount-race
or production filesystem acceptance.
