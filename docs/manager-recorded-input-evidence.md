# Recorded input evidence

`ProtectedRecorder.record_all_inputs` and `adopt_all_inputs` add explicit
recording of every declared nonsecret file alongside the existing
[authenticated protected bindings](manager-protected-bindings.md).
`observe_recorded_inputs` compares current and retained adopted input
slots under a freshly checked host policy. These trusted library APIs do
not install a helper, render Compose input, or authorize application.

## Explicit recording

```python
recorder.record_all_inputs(declaration, expected_revision,
                           prepared_inputs=protected_preparations)
recorder.adopt_all_inputs(declaration, expected_revision, resource_ids,
                          prepared_inputs=protected_preparations)
```

Protected entries still require authenticated preparations or reusable
bindings for the exact snapshot. Nonsecret entries are captured through
the same bounded, descriptor-based reader and allowed host input roots.
Their classification is an explicit operator decision, not automatic
secret detection. All bytes remain private even when classified nonsecret.

Every captured file and the decision are published in one SQLite
transaction. A missing, denied, changed protected input, revoked policy,
exceeded budget, or revision conflict prevents publication. File reads
happen outside the store transaction. They provide a bounded observed
capture, not writer exclusion or an atomic view of several files.

The existing `record_intent` and `adopt` methods preserve their protected-
only behavior. They do not capture nonsecret files implicitly. Such
records remain readable, but their nonsecret freshness is unavailable.
Observation never creates or updates the missing baseline.

## Stored binding

No SQL schema change is required. Nonsecret captures use the existing
private capture and decision-link tables with a distinct tagged HMAC
domain. The binding covers host, origin decision, exact source/model
snapshot, input ID, path, base directory, classification, private capture
reference, complete source identity, purpose and bytes. These records
cannot be reused as declared protected references. Older readers reject
unsupported tagged records rather than treating them as legacy captures.

Each explicit recording gets its own nonsecret baseline, even when the
TOML source is identical. A later intent decision cannot replace a
resource's earlier accepted baseline. A relinquishment preserves the
previous recording baseline and the original adopted input obligations.
Generic legacy captures cannot substitute for these authenticated rows.

## Collection and coverage

```python
evidence = recorder.observe_recorded_inputs(
    revision=current_revision,
    snapshot_id=exact_recorded_snapshot_id,
)
summary = evidence.as_dict()
```

The target must be the exact current store revision and snapshot. The
result contains one `current` scope covering every declared input file,
and one `accepted` scope for every retained resource, including
relinquished resources and resources removed from current intent.

Accepted scopes use their resource's actual latest adoption snapshot.
They include its direct input bundle, file-content input requirements,
and the input bundles and content requirements of its original declared
resource dependencies. Reusing a logical resource or bundle ID in newer
intent does not change the accepted scope. Explicit re-adoption can
establish a new accepted baseline. Unlinked bundles remain in current
coverage but are not attributed to an unrelated accepted resource.

Every row identifies its input ID, file position, classification and
`same`, `changed`, or `unavailable` result. Equal bytes with a replaced
file identity still compare as changed. The envelope binds the host,
current revision, exact source/model snapshot, collection-start time and
fixed evidence source. Accepted scopes additionally bind the stable
resource ID, original logical ID, adoption revision, snapshot and current
management disposition. Public output contains no input paths, private
references, bytes or content hashes.

`state = "complete"` means all declared coverage is represented; individual
rows can still be unavailable. Policy invalidation, store failure, a
changed target or aggregate read overflow invalidates every row. One
ordinary file-read failure leaves that and subsequent unread rows
unavailable; a failed read may have consumed its allowance. Neither the
current revision nor the policy can change unnoticed at the final
recheck, including when no files are declared.

A shared slot in the same snapshot and recording is read once and its
result is reused across roles. Different recording decisions remain
separate comparison contexts. Collection represents at most 256 scopes,
4,096 role-specific rows and 64 distinct capture contexts. It refuses an
oversized manifest before file reads. Captures share a 64 MiB aggregate
allowance and retain the 16 MiB per-file bound; empty files can use a zero
remaining byte allowance. The redacted evidence is limited to 1 MiB.
These bounds do not impose a wall-clock deadline on synchronous filesystem
or complete-history store validation.

## Trust and remaining work

`RecordedInputEvidence` is immutable and validates its shape. Constructing
one, or importing its JSON, does not authenticate a host or grant
management authority. Callers must obtain it through their trusted host
boundary and verify exact target and accepted-role coverage before use.
The existing protected-only comparison API and planner input remain
unchanged; this new evidence has no planner or public CLI integration yet.

Every result retains `full_input_closure = "unverified"`. Matching declared
files cannot prove all effective Compose environment, recursive references,
rendering inputs, mounts or resolved artifacts were captured. Collection
also cannot establish application health, consumer access or readiness to
apply. It performs no store mutation or native lifecycle operation.

Private fixtures cover both classifications, immutable output, changed
content and identity, exact decision baselines, retained dependencies,
renaming, relinquishment, missing legacy captures, budget limits, policy
and revision races, cancellation, token tampering and unchanged history.
They do not establish installed-helper security, live Arch acceptance or
filesystem containment against trusted root.
