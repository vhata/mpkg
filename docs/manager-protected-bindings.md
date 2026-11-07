# Protected declaration bindings

`mpkg_manager.protected_bindings.ProtectedRecorder` binds the protected
entries of an exact declaration snapshot to authenticated captures. It
uses caller-owned `HostStore` and `LoadedHostPolicy` handles. It is a
trusted recording library, not an installed privileged helper, a Python
containment boundary, or application authorization.
The separate [installed preparation flow](manager-protected-recording.md)
uses these primitives behind closed requests and authenticated private
staging; its preparations can span helper invocations.

## Preparation and recording

```python
recorder = ProtectedRecorder(store, loaded_policy)
prepared = recorder.prepare(
    expected_revision=0,
    input_id="application-inputs",
    base_directory="/srv/environment/inputs",
    path="private.env",
)
# The trusted caller places prepared.reference in the original TOML.
# load_declaration preserves those exact source bytes.
decision = recorder.record_intent(declaration, 0, prepared_inputs=[prepared])
accepted = recorder.adopt(declaration, 1, ["application"])
```

`prepare` captures under the longest accepted policy root containing the
complete declared file path, using components rather than string prefixes.
A public bundle directory can therefore contain a narrower authorized
private subtree without broadening the policy to the whole bundle. It
issues a random reference sealed with the store's private key, expected
revision, declared slot, source identity/content, policy fingerprint and
recorder nonce. The preparation retains the actual policy handle; closing
or replacing that handle prevents its use. A same-host different store,
forged preparation, swapped scope or modified payload cannot authenticate.

`PreparedProtectedInput.reference` is an explicit trusted accessor for
writing nonsecret declaration references. Its representation exposes no
reference, path, metadata, bytes or authentication token. Preparations
are tied to their recorder and expected revision; they are not imported
JSON or reusable authorization credentials. No declaration source is
rewritten by the library.

`record_intent(declaration, expected_revision, prepared_inputs=())` and
`adopt(declaration, expected_revision, resource_ids,
prepared_inputs=())` require every protected entry to be accounted for.
New references need matching preparations; unused preparations and
ambiguous duplicate references are refused. The source is reparsed and
its fields verified before recording. Captures are reread under the
current policy, and the complete source identity and bytes must still
match. Only then does a short compare-and-swap transaction store the
original declaration, protected bytes, links and authenticated bindings.
Adoption retains the existing explicit resource-authority rules; recording
intent alone does not adopt anything.

Each operation supports at most 64 protected entries and 64 MiB total,
with the existing 16 MiB per-file limit. Outstanding preparations for one
recorder revision use the same count/byte budget. The protected subset is
not closure of nonsecret files, interpolation environments, Compose
inputs or any complete executable application bundle.

## Exact-snapshot reuse and fresh comparison

A bound reference may be reused only by the identical immutable snapshot:
exact source bytes, normalized model and schema/normalization versions.
Current policy and source freshness are checked again before recording
or adoption. Reuse retains the original capture's single decision link;
it does not duplicate authority or rewrite history. This supports
recording intent and then adopting that same snapshot. Any source/model
change, including comments, requires fresh preparations and references.

`compare_input(revision=..., snapshot_id=..., input_id=..., path=...)`
returns only `same`, `changed` or `unavailable`. It derives the reference
from the requested immutable snapshot, requires a valid authenticated
origin at or before the requested decision, and performs a fresh capture
under the current loaded policy. It accepts neither a bare UUID nor an
arbitrary raw-byte input. A private historical resolver is an internal
step, not proof of freshness and not a public raw-file read API.

Old snapshot bindings remain comparable after later intent, declaration
removal or relinquishment. A legacy decision repeating an already bound
exact snapshot can retain historical availability, but comparison still
requires a fresh read. A guessed UUID, foreign capture, future origin,
wrong snapshot/slot, missing source, revoked policy or legacy unbound
capture is unavailable. Changed bytes or identity report changed.
Corrupt or unavailable stores leave comparisons unavailable. Direct store
operations continue to report fixed integrity errors; no comparison claims
clean or available evidence from a failed store read.

## Protected input status evidence

```python
evidence = recorder.observe_inputs(
    revision=decision["revision"],
    snapshot_id=decision["snapshot_id"],
)
report = build_report(
    declaration, store.current(), host_observations,
    host_id=accepted_host_uuid,
    input_observations=evidence,
)
```

`observe_inputs` performs fresh policy-authorized comparisons for every
protected entry of the exact **current recorded** decision. A historical
revision or mismatched snapshot is refused, even though `compare_input`
can compare individual historical bindings. It reads the stored source,
not a working declaration or a caller-supplied list of references. Shared
bundles are visited once. Nonsecret entries are not read. A legacy unbound
reference remains unavailable rather than becoming authenticated by its
presence in a declaration.

The result is an immutable `ProtectedInputEvidence` with canonical bytes
and an `as_dict()` copy. Its closed version 1 projection binds the host,
decision revision, exact source and canonical snapshot hashes, versions,
UTC collection-start time, fixed evidence source and scope. Each entry
contains only `input_id`, zero-based `file_index` within the full declared
bundle and `state`: `same`, `changed` or `unavailable`. It exports no
opaque references, source paths, captured content, protected hashes or
authentication tokens. Only declaration snapshot hashes are public.

The optional `observed_at` keyword supplies a UTC `Z` collection-start
timestamp for deterministic trusted callers. The default samples the clock
before any store or filesystem reads. Collection does not refresh the
timestamp after slow reads. The planner applies its own age/future checks.
Evidence shape validation is not authentication; trusted embedding must
preserve the provenance of both object and wire forms.

Collection permits at most 64 protected entries, 64 MiB total and 16 MiB
per file. Each capture receives the remaining byte allowance. Aggregate
overflow makes the entire batch unavailable, including previous matches.
After another failed capture, subsequent entries stay unavailable and no
more files are read: a failed read may already have consumed its allowance.
`complete` denotes complete entry coverage, not that all entries matched.

The collector rechecks the current management revision and whole policy
after the last comparison, including an empty protected set. A changed
revision, unavailable store or revoked policy invalidates the whole batch.
Reads occur outside SQLite transactions; they write no decisions or store
files. These final checks do not eliminate subsequent writer races.

The [pure comparison report](manager-planning.md#protected-input-freshness)
keeps historical protected coverage unavailable and nonsecret/full input
closure unverified. This evidence cannot authorize apply, turn a property
match into functional health or remove application capability blockers.

## Durable authentication and compatibility

The SQL schema remains version 1. Existing 32-byte protected tokens keep
their legacy identity/content authentication and decision/name comparison
behavior. They never authenticate a declaration binding.

New tokens are exactly the nine-byte prefix `MPKGBND\0\x01` followed by a
32-byte HMAC. The MAC has an explicit domain/version and length-framed
canonical context and raw bytes. It authenticates the host, capture UUID,
unique origin decision, exact snapshot, input ID, base directory, relative
path, protected classification, link name, purpose, full source identity
and content. Replay reconstructs this context from immutable history and
rejects tampered links, ambiguous entries and unknown encodings. Snapshot
validation and entry indexing are reused across a batch.

This is a protected-token format extension despite unchanged SQL tables.
New readers accept existing stores. Older readers reject stores containing
bound tokens; backward reading by older binaries is not supported. There
is no implicit migration, downgrade or history rewrite.

Existing generic store recording and decision/name comparison APIs stay
available. They do not mint bound references merely because a declaration
contains a UUID. Public current/history projections and comparison
results expose no protected bytes, capture IDs, source metadata or MACs.

## Failure and timing limits

All live capture and freshness reads finish outside the SQLite write
transaction. CAS, preparation authentication and immutable scope checks
run again inside it. A read-to-commit window remains: source/policy
changes after the final check are not excluded by filesystem locks.
Reads are byte-bounded; synchronous filesystem latency has no deadline
here. The existing same-device mount limitation also remains. These
operations provide evidence about the observed reads, not atomic writer
exclusion, filesystem containment or permission to apply effects.

Stale revisions, missing coverage, changed inputs and invalid preparations
publish no partial decision or references. Commit failures retain the
store's unknown-outcome handling: reopen and inspect before retrying.
Errors contain fixed codes without supplied values. Reports remain
non-executable and full input-bundle/application gates remain blocked.
