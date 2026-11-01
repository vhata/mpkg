# Host policy and protected capture

`mpkg_manager.host_policy` loads the fixed production policy at
`/etc/mpkg/host-policy.toml`. `mpkg_manager.protected_capture` reads bounded
files only beneath input roots from a loaded, verified policy handle.
These libraries supply the protected-input path for a future recorder;
they do not install a privileged helper or grant application authority.

## Policy and trust

The closed version 1 TOML schema is:

```toml
schema = 1
host_id = "12345678-1234-4234-8234-123456789abc"
engine_aliases = { local = "accepted-engine-id" }
allowed_input_roots = ["/srv/environment/inputs"]
```

The policy binds a canonical host UUID, accepted engine aliases and
explicit absolute input roots. Unknown fields, invalid types and
noncanonical paths are refused. `/` is not an allowed input root. The
policy is limited to 64 KiB, with at most 64 aliases and 64 roots. There
are no request-selected executables, environment overrides or store
paths. Installed integration locations require a future explicit schema
extension; this version grants no tool-selection capability.

`parse_host_policy(raw: bytes) -> HostPolicy` returns immutable values.
Its `engine_aliases` property returns a copy, and `allowed_input_roots`
is a tuple. Parsing arbitrary bytes does **not** authenticate policy or
authorize reads. `capture_protected` rejects parsed values.

`load_host_policy() -> LoadedHostPolicy` verifies ownership and opens a
policy handle. Production ownership defaults to UID 0. The policy's
parent directory must be `0700`, and the file must be a single-link
regular file with mode `0600`, both owned by that UID. Ancestors must be
owned by root or the selected owner and cannot be group/world writable,
except root-owned sticky directories used by temporary fixtures. Every
component refuses symlink traversal. The loader holds directory and
file descriptors and verifies links, permissions and full file metadata
before returning and before/after each capture.

The explicit `path` and `owner_uid` keyword arguments exist for isolated
fixtures and trusted Python embedding. They have no declaration or CLI
surface. A future installed recorder must keep the fixed production
path and owner and open the host store using the policy's host UUID and
accepted aliases. Python objects and alternate fixture paths are not a
privilege boundary. Changing or replacing a loaded policy invalidates
that handle; closing it prevents further captures. Use it as a context
manager or call `close()`.

## Capture API

```python
with load_host_policy() as loaded:
    captured = capture_protected(
        loaded,
        root="/srv/environment/inputs",
        relative_path="media/private.env",
        name="media-environment",
        purpose="Compose environment input",
    )
```

The root must exactly match an accepted policy root. Relative paths
cannot contain empty, `.` or `..` components, absolute paths or NULs.
Capture holds the accepted root and descendant directory descriptors,
opens relative to them, and rechecks their directory entries before
returning. The final open uses `O_NOFOLLOW` and `O_NONBLOCK`; the file is
checked before and after opening and must be regular and single-link.
Symlinks, hardlinks, directories, FIFOs and other special files are
refused. Descendants on a different device are refused. Source ownership
and ordinary file modes are recorded rather than rewritten; an allowed
input root can contain files written by an unprivileged author.

Capture reads at most 16 MiB plus one byte for overflow detection and
checks byte count, inode, device, mode, owner/group, link count, size,
mtime and ctime before/after reading. Directory and final-path
replacement, detectable concurrent writes, policy changes and read
errors prevent returning a captured input. Cancellation preserves the
original interrupt and closes descriptors owned by the operation; the
separately loaded policy handle remains the caller's responsibility.

The result is the existing
[`ProtectedInput`](manager-store.md#protected-capture-and-failure-reporting)
value. Its private bytes and source identity are intended for a trusted
recorder, which writes them atomically with the decision. The persisted
identity has exactly `path`, `device`, `inode`, `size`, `mtime_ns`, `uid`,
`gid`, `mode` and `links`; ctime adds a capture-time race check without
changing the store schema. `HostStore.compare_protected` returns only
same/changed/unavailable. A capture error supplies unavailable evidence;
it must never be replaced with empty or redacted content.

The capture's `name` labels its recording and comparison within a
decision. Capture does not return a declaration-reference UUID, and the
store's generated private capture references do not currently resolve
the protected references written in declarations. Capturing and recording
one file therefore neither authorizes a declared protected reference nor
establishes a complete input bundle. Binding those references and closing
the bundle require a separate future recorder integration.

## Output and limits

Policy/capture errors contain only fixed codes. Policy representation
omits its host roots and aliases; captured values omit bytes, source
metadata and purpose from their representation. There is no public raw
file-output command. Ordinary store history excludes captured bytes,
source paths, opaque references and raw/keyed digests. Explicit source
classification remains the recorder's responsibility; no automatic
secret detection is claimed.

Reads are byte-bounded and produce evidence about the observed read,
not atomic writer exclusion. Synchronous filesystem latency has no
elapsed-time bound here; a future supervising worker must impose any
wall-clock deadline. A writer can change data after capture, and
before/after metadata checks do not prove a globally atomic filesystem
snapshot. Reads may update filesystem
access times. Equal device numbers do not detect same-device bind mounts
or every alias of an input tree. Those mounts are a detection limitation,
not an enforced rejection. This library is not filesystem containment
against trusted root, and it does not claim mount isolation or an
installed authorization dispatcher.

Tests use private temporary policies, input trees and SQLite stores.
They exercise permission/path boundaries, size limits, injected races,
cancellation and store freshness comparisons. They never read the real
host policy or invoke package, service, Docker or guest operations.
