# Bounded file accountability

`mpkg_manager.file_accountability.scan_files` enumerates explicit filesystem
scopes and classifies metadata against a validated declaration. It reads no
regular-file contents, symlink targets, package database or host account
records. It does not adopt resources, change intent, grant authority or
supply an executable plan.

## Trusted embedding API

```python
from mpkg_manager.file_accountability import ScanScope, ScanLimits, scan_files

scan = scan_files(
    declaration,
    [ScanScope("application-data", "/srv/application",
               exclusions=("/srv/application/cache",))],
    host_id=accepted_host_uuid,
    limits=ScanLimits(max_entries=4096, max_directories=256,
                      max_depth=32, max_path_bytes=1024 * 1024),
)
public_summary = scan.summary()
```

The caller is trusted Python code responsible for authorizing the host and
scan scopes. This API is not an installed privilege boundary, and a
caller-supplied path or imported JSON is not inspection permission. There
is no CLI or public deserialization interface for scan results.

The declaration is reparsed from its original source and checked against
its immutable snapshot before I/O. All scopes, exclusions, rules and
budgets are validated before opening a path. At most eight disjoint roots
are accepted, with unique bounded scope IDs. Root paths are canonical,
absolute UTF-8 strings with at most 4096 bytes and 128 components; roots
cannot overlap. Each scope permits at most 128 canonical exclusions inside
that root. Excluding a directory excludes its subtree. Excluding the root
produces an unavailable scope without opening it.

`AccountabilityScan` and its nested records are immutable. They bind host,
collection-start UTC time, exact declaration source and normalized model
hashes, requested scopes, exclusions and limits. Raw `scopes`, `entries`
and `gaps` contain private paths for trusted consumers; their representations
hide those paths. `summary()` produces fresh dictionaries with fixed
classification and gap labels, counts and policy. It includes no raw path,
filename, file content, symlink target or exception text. It describes
enumeration coverage, not verified host health or input freshness.

## Traversal and coverage

Traversal uses Linux descriptors. Each ancestor opens with
`O_PATH | O_DIRECTORY | O_NOFOLLOW`; scanned directories open read-only
with `O_DIRECTORY | O_NOFOLLOW`. Only directories are opened for
reading. Regular files, FIFOs, devices, sockets and symlinks receive
non-following metadata lookups. No symlink target is traversed, even when
it is a directory. Traversal beneath a symlinked ancestor is refused.

The mount policy is **same device**, not “no mount crossings.” A directory
on a different device is observed as an entry, but its descendants become
an explicit `device_boundary` gap. Same-device bind mounts may be
traversed; their aliases and cycles are not detected. Entry, depth and
directory budgets still apply. The result always carries that limitation.

Entries are processed in filesystem enumeration order, without collecting
an unbounded directory listing to sort it. Budgets are shared across all
scopes in a call. They count encountered entries, including excluded
entries, and the root itself. Directory budgets count attempted directory
opens. The depth limit bounds descent below each root; depth one allows
root entries but no child-directory enumeration. The path-byte budget
counts UTF-8 relative names, including directory prefixes for each entry.
An encountered relative path longer than 4096 bytes or an undecodable
filename stops that scope with a root-wide gap, including unvisited
ancestor siblings. At most one extra entry
per scope is fetched to discover that a budget cannot accommodate it.

Each directory's descriptor and parent entry are compared before and
after enumeration, including identity, type, ownership, mode, size, link
count and modification/change timestamps. Ancestor identity and metadata
are rechecked at the end. Each entry receives two matching metadata
lookups. A detected replacement or directory change invalidates the whole
scope and removes its entries. Missing, non-directory or no-follow
failures after observing a directory also detect replacement, including
a root replaced before its directory opens. Ordinary permission denial
remains a distinct coverage gap. Other scopes remain independent.

Coverage states are:

- `complete`: enumeration finished under the stated policy, without gaps.
- `partial`: observed entries exist alongside excluded, denied, bounded or
  unavailable scope. An entry's classification cannot cover its gap.
- `unavailable`: the root could not be inspected, its budget was exhausted
  before starting, it was wholly excluded, or a detected race invalidated
  the scope. Missing roots do not establish resource absence.

Cancellation propagates after closing owned descriptors and iterators.
Filesystem calls remain synchronous with no elapsed-time guarantee. The
single timestamp is sampled before validation and traversal; it never
advances per entry. Metadata observations are time-bounded evidence, not
an atomic snapshot or exclusion of other writers. Paths outside the
requested roots and symlink destinations remain uninspected.

## Classification

Classification names record limited supporting evidence:

- `declared_configuration`: an observed regular file matches a declared
  file or Sonarr XML path. Contents and desired properties are unchecked.
- `declared_resource`: a matching declared directory or symlink. This says
  nothing about descendants, symlink destinations or actual consumer access.
- `runtime_rule_match`: the entry's path and type match a declared runtime
  rule with one responsible component. It is not proof of content,
  expected variation, accepted ownership or application health.
- `package_side_file`: an otherwise undeclared `.pacnew` or `.pacsave`
  entry needs package-aware comparison. Runtime patterns cannot hide it.
- `unexplained`: no supported classification applies; this does not imply
  a malicious change, package absence or safe removal.
- `unknown`: declared and observed kinds disagree, or matching runtime
  rules name different responsible components.

Exact declared resources take precedence over runtime matching. The
[declaration validator](manager-declarations.md#runtime-scope) requires
explicit exceptions for declared configuration under runtime roots.
Exceptions exclude their exact path and descendants from that rule's
classification; they do not exclude those paths from scanning. Multiple
matching rules for the same component retain all matching rule IDs.

Patterns are relative and case-sensitive. `*`, `?` and bracket character
classes match within one path segment. A standalone `**` segment matches
zero or more whole segments. For example, `*.log` covers only immediate
children, while `**/*.log` also covers nested logs. Dot-prefixed names use
the same rules. Repeated separators, `.` or `..` segments, backslash
escapes, embedded `**` and malformed brackets are unsupported and rejected
before I/O. There are at most 128 rules and 1024 total patterns; each
pattern has at most 256 UTF-8 bytes and 32 segments. Matching uses bounded
iteration rather than recursive glob expansion.

## Remaining evidence

The existing [metadata observer](manager-file-observation.md) still owns
per-resource property observations. This scan does not replace it or feed
new trusted facts into the planner. Package ownership, installed-version
baselines, content differences, accepted historical runtime rules and
consumer access need separate evidence. A clean scan or matching runtime
pattern cannot satisfy the full
[A3 accountability scenario](specs/2026-10-31-first-release-acceptance.md#a3-accountability-and-coverage).

Tests use private temporary files, injected denial/device results and
controlled replacements. They do not enumerate production paths, create
mounts, read real package metadata or perform native lifecycle operations.
