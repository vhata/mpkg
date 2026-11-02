# Target content in status reports

`status --check-file-content` explicitly compares recorded file targets
with their authenticated `content_input` bytes. Default status continues
to collect metadata and source-file freshness. Target equality is a
separate result: a matching source does not hide an edited target, and a
changed or missing live source does not invalidate equal target bytes.

The [content collector](manager-file-content.md) owns target read safety,
byte limits, baseline authentication and retained history. The
[status collector](manager-status-collection.md) loads an independent
history manifest before observation, invokes that collector only for the
exact recorded declaration, then rechecks the manifest, policy and history
before returning. Collection failures, empty content scopes and late
results still cross the final checks. Detected context changes refuse the
whole status result. A result returned after the scheduling budget is
unavailable; synchronous filesystem and history operations cannot be
interrupted by that budget.

An edited working declaration causes no target or input-file reads. The
original current and retained obligations stay visible with unavailable
results. Selecting components cannot remove accepted, unselected,
relinquished or historical dependency obligations from content coverage.
No observation creates a baseline, changes adoption or writes target data.

## Pure comparison boundary

Trusted Python callers supply the separate typed values to `build_report`:

```python
report = build_report(
    declaration, current_with_inputs, observations,
    host_id=host_id,
    file_content_manifest=manifest,
    file_content_observations=evidence,
    file_content_requested=True,
)
```

`file_content_requested=True` retains an explicit unavailable section even
when evidence is absent. Omitting all three arguments preserves existing
report behavior. Dictionary projections are refused for these two typed
inputs. Typed shape validation is not authentication: the caller must
obtain both values through trusted live store/policy handles. Public JSON
cannot establish expected coverage or authorize host effects.

The planner checks host, revision, the full source/model snapshot,
current declaration obligations, retained stable IDs/adoption revisions
and all manifest rows against evidence. When the complete recorded-input
manifest is present, content roles also match its independently loaded
recording contexts and declared slots. Evidence must cover every expected
scope and exact resource/role/consumer/input/classification tuple and
satisfy the report freshness bound. Missing rows, replayed contexts and
stale batches make every content result unavailable. Expected coverage
never comes from an observation's self-declared scope.

Only a file's exact `content_input` predicates can use this evidence for
property comparison. All current desired and consumer rows and the
accepted resource's retained consumer rows must be available. Any missing
applicable row leaves that property unknown. A newer capture under the
same bundle ID cannot replace an older consumer's accepted bytes. Desired
and consumer predicates that disagree remain conflicted; byte matches do
not resolve that conflict. Accepted desired bytes remain separately
visible, even when a newer desired baseline differs from them.

## Public results

Human output lists each current or accepted desired/consumer result.
The opt-in JSON report adds `file_content`; the collection summary adds
`file_content_reason`. The request field `check_file_content` is optional,
strictly boolean and omitted by the CLI unless requested. Both helper and
client enforce the closed response schema; an unrequested content section
or unknown/private fields are refused.

The section reports complete represented coverage separately from each
row's `same`, `changed` or `unavailable` state and fixed reason. Rows retain
logical resource/input IDs and consumer roles; accepted scopes retain
stable IDs, adoption/recording revisions, snapshot IDs and management
state. No source/target path, property value, opaque reference, file bytes,
content digest or MAC appears. Snapshot IDs describe explicitly nonsecret
declaration history, not file content.

`source_input_freshness` stays `not_observed` in this section and
`application` stays `unverified`. The separate recorded-input section owns
source freshness. Content comparisons do not establish package baselines,
consumer access, runtime identity, functional health, keep/restore safety
or permission to overwrite. Reports remain non-executable.

## Limits and validation

Targets must be beneath the policy's `allowed_input_roots`; the option
accepts no path or policy override. The collector's 256 scopes, 4,096
obligations, 64 comparison contexts, 16 MiB per-file and 64 MiB total
read bounds remain in force. Evidence is bounded to 1 MiB. Parent/leaf
symlinks, hardlinks, unsupported metadata and detected races remain
unavailable. Reads can update access times. There is no hard filesystem,
NSS or history latency deadline or global multi-file atomicity guarantee.

Private fixtures exercise the installed CLI/helper transport with
injected identities, independent history, exact retained consumers,
source/target disagreement, legacy baselines, edited intent, stale/replayed
or incomplete evidence, final context changes and closed redacted output.
They perform no production package, NSS, service, Docker or endpoint
queries and do not establish installed sudo or A8 acceptance.
