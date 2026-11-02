# Recorded target-file content

`mpkg_manager.file_content` compares a declared file target with the
bytes authenticated for its recorded `content_input`. It reads only
explicit targets derived from actual host history, returns sanitized
immutable evidence, and never changes files or recording history.

The [status integration](manager-file-content-reporting.md) uses this
trusted library through the explicit `--check-file-content` option. The
metadata observer continues to report metadata separately. Complete file
accountability, package baselines and keep/restore operations remain
outside this API.

## Independent history and collection

```python
from mpkg_manager.file_content import (
    file_content_manifest, collect_file_content,
)

current = store.current()
manifest = file_content_manifest(
    store, revision=current["revision"], snapshot_id=current["snapshot_id"],
)
evidence = collect_file_content(
    recorder, revision=current["revision"], snapshot_id=current["snapshot_id"],
)
summary = evidence.as_dict()
```

The caller owns an actual `HostStore` and `ProtectedRecorder` with a
verified loaded host policy. Both functions require the exact current
revision and source/model snapshot. They accept no target paths, input
references, resource lists, filesystem roots or UID overrides. Existing
policy/store fixture seams remain trusted Python embedding facilities;
the installed status option supplies no public arbitrary-file reader.

`file_content_manifest` returns a `FileContentManifest` containing the
expected obligations, independently of live target reads and observed
results. `collect_file_content` derives its private bindings directly
from the same validated history, not a caller-supplied manifest. Its
`FileContentEvidence` includes collection-start time and results. Both
values have canonical bytes and return independent copies through
`as_dict()`. Representations omit their payloads. Shape validation is
not host authentication, and imported JSON cannot authorize an effect.

The [pure report consumer](manager-file-content-reporting.md) compares
evidence with an independently obtained trusted manifest, including
complete scope/obligation coverage, exact host/revision/snapshot and
freshness. An evidence object's own coverage declaration never proves
completeness.

## Baselines and roles

There is one current scope and one accepted scope for every retained
resource, including empty scopes and relinquished resources. Current
content obligations come from the exact recorded declaration. Accepted
obligations come from the resource's actual latest adoption snapshot,
its original declared resource dependencies, and retained consumer
constraints. Desired content and each consumer requirement keep separate
rows even when they use the same bytes. Consumer requirements never
become desired properties or management grants.

Each row identifies the target's original logical resource ID, requirement
role, optional consumer ID, input bundle ID, single-file index and explicit
classification. Accepted scopes retain stable resource ID, original
logical ID, adoption/recording revision, exact snapshot and management
disposition. Renaming, removing declarations and reusing bundle IDs do not
replace an accepted baseline. A relinquishment changes responsibility;
it preserves the prior recording and accepted content. Explicit
re-adoption establishes that resource's new baseline.

Only `content_input` obligations are covered. The declaration validator
requires their bundle to contain exactly one file. Inline `content`, files
without declared content requirements, package-supplied bytes, directory
contents, runtime scans and `.pacnew`/`.pacsave` discovery are outside this
scope. Empty coverage does not mean those other properties were inspected.

For protected input, the private resolver requires the authenticated
reference's exact snapshot and valid origin at or before that decision.
For nonsecret input, it requires the authenticated capture for the exact
recording decision and declared slot. Generic legacy captures, wrong
classification or snapshot, missing baselines and corrupt history cannot
supply expected bytes. No capture is created during observation.

## Target agreement and source freshness

The collector compares authenticated stored bytes with the target's
freshly read bytes, privately, using a constant-time byte comparison.
It does not compare the target's identity with the source input's
identity: those normally identify different files. A stable target with
equal bytes reports `same` even if its inode differs from a prior target
observation. Metadata agreement remains a separate observation.

A differing target reports `changed` even when its live source input is
unchanged. Conversely, a matching target can coexist with a changed or
missing live source. This collector never rereads the source input and
always reports `source_input_freshness = "not_observed"`. Use the separate
[recorded input evidence](manager-recorded-input-evidence.md) API for that
comparison. Neither stream can stand in for the other.

Each result is `same`, `changed`, or `unavailable`, with a fixed reason.
A missing target, denied read, unsupported file type/metadata, changed
path or unavailable baseline stays unavailable. Missing targets do not
establish safe creation or deletion. A content difference does not say
who changed the file, whether it was intentional, or whether replacing it
would preserve an application's needs.

## Read boundary, bounds and races

Target reads conservatively reuse the loaded policy's
`allowed_input_roots`. A declared target outside those roots is
unavailable. This does not extend the policy schema or silently grant
read access to every declared absolute path. Both source capture and
target reads need their appropriate roots explicitly allowed.

Reads use the existing [protected capture](manager-capture.md) descriptor
walker and per-read identity checks. Parent symlinks, leaf symlinks,
hardlinks, special files and cross-device descendants are refused.
Before/after descriptor, directory-entry, size, owner/mode, timestamp and
link-count checks leave detected writes or replacements unknown. A
replacement may first appear as unsupported link metadata rather than a
specific replacement reason; neither yields a content match. Reads may
update access times. Same-device bind mounts and changes after the
observation remain limitations.

At most 256 scopes, 4,096 role-specific rows and 64 distinct comparison
contexts are represented. A context includes recording revision, exact
snapshot, target resource and input ID; shared current/accepted/consumer
rows in that context reuse one target read. Distinct recording baselines
remain distinct contexts. Oversized coverage is refused before file reads.
The serialized manifest/evidence is limited to 1 MiB.

Target reads share a 64 MiB allowance and the capture reader's 16 MiB
per-file bound. Zero remaining bytes can still inspect an empty file.
A failed read stops later target reads because it may have consumed its
allowance. Remaining rows stay explicitly unobserved. Aggregate overflow
invalidates the entire batch, including earlier matches.

The collector checks policy and current store revision again after all
reads, including empty and failed batches. Policy invalidation, changed
revision, unavailable store or byte overflow makes every result
unavailable. `state = "complete"` means all declared content-input
obligations are represented, including unavailable rows; it does not mean
all targets agree. Store transactions are released before target reads.
Cancellation propagates and closes descriptors owned by the reader.

These checks provide evidence about bounded reads, not writer exclusion,
a globally atomic multi-file snapshot, containment against trusted root
or a synchronous filesystem deadline. Whole-history validation also has
no wall-clock deadline. Final rechecks do not prevent subsequent changes.

## Privacy and remaining authority

Public output contains logical roles and declaration identities, never
source/target paths, input references, captured bytes, byte hashes or
MACs. All classifications receive the same output privacy. A declaration's
explicit nonsecret classification is not automatic secret detection.
Fixed errors and unknown reasons contain no supplied private values.

`application = "unverified"` remains true for every outcome. Content
agreement proves no package ownership or installed-version baseline,
consumer access, functional health, safe restoration, overwrite consent,
execution authority or readiness to apply. Keep/restore decisions and
manual-edit invalidation for application remain future work.

Private fixtures exercise target drift with matching sources, independent
history coverage, both classifications, replay refusal, retained roles,
legacy captures, descriptor races, policy/revision invalidation, count and
byte bounds, read-only history, cancellation and privacy. They perform no
real package/service/Docker operations and do not establish A8 acceptance
or installed-helper security.
