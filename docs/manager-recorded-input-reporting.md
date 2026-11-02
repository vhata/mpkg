# Recorded inputs in comparison reports

The pure planner can compare typed
[recorded input evidence](manager-recorded-input-evidence.md) against a
separate expected-coverage manifest from actual host history. This covers
current declared files and retained accepted input obligations, while
keeping complete Compose input closure and application unverified.
The [installed status command](manager-status-cli.md) assembles the
trusted manifest and evidence for exact recorded targets.

## Independent history projection

`HostStore.current_with_inputs()` returns the existing `current()`
projection plus `input_manifest`. The existing `current()` method and
its output remain unchanged. An uninitialized store returns a null
manifest; it does not manufacture recorded empty coverage.

The manifest is produced by
`recorded_inputs.recorded_input_manifest(store, revision=..., snapshot_id=...)`
and validated as an immutable `RecordedInputManifest`. It contains exact
host/revision/snapshot metadata, one current scope, and one scope for
every retained resource. Slots identify input ID, position and explicit
classification. No result, observation timestamp, file path, private
reference, byte content or file-content hash is present.

Coverage comes from the actual current and original adoption snapshots,
including accepted dependency and consumer-content requirements. It is
not copied from an observation batch. The store projection refuses a
revision change between its history reads or an oversized manifest with
`input_manifest_unavailable`; it never truncates coverage to make it fit.
Manifest construction reads validated store history, not live input files.
It uses the collector's 256-scope, 4,096-row, 64-context and 1 MiB bounds.

Like the existing store projection, this manifest must come through a
trusted host boundary. Shape validation, a dataclass constructor and
imported JSON do not authenticate authority. The manifest's snapshot
identities are checked against their source/model hashes and versions;
those are declaration identities, not file-content hashes.

## Pure report API

```python
current = store.current_with_inputs()
evidence = recorder.observe_recorded_inputs(
    revision=current["revision"], snapshot_id=current["snapshot_id"],
)
report = build_report(
    declaration, current, property_observations,
    host_id=host_id,
    recorded_input_observations=evidence,
)
```

The planner accepts only `RecordedInputEvidence` for the new argument and
revalidates it. Public evidence dictionaries, raw bytes and malformed
instances produce the fixed `invalid_recorded_input_observation` error.

The planner verifies the manifest's host, revision and exact snapshot
against the management projection. Every accepted scope must correspond
to an actual retained resource, its management disposition and original
adoption binding, even when it has no declared checks or input files.
Visible direct input obligations cannot be replaced by empty coverage.
Current slots are additionally checked against the validated declaration.

Evidence must match that independent manifest's complete roles, exact
scope metadata, classifications and file positions. Selection cannot hide
unselected or retained scopes. Missing or extra evidence slots invalidate
the whole batch. Evidence cannot establish completeness merely by
claiming its own smaller manifest was completely observed.

The requested declaration must match the exact recorded source and model,
including source comments. Host, revision, snapshot and version bindings
must match. Collection time uses the same `now` and `max_age_seconds`
context as ordinary property observations; the exact age limit is allowed,
while stale or future evidence is unavailable. A failed collection remains
unavailable even when ordinary property facts agree.

## Results and compatibility

The `recorded_inputs` summary reports coverage and each current or accepted
slot's `same`, `changed`, or `unavailable` state. Accepted rows retain
stable resource identity, original logical identity, adoption/recording
revision, snapshot identity and management disposition. Renaming, removal,
relinquishment and reusing a bundle ID cannot erase the accepted baseline.

`coverage = "complete"` means every expected role and slot was represented,
not that all its files matched. Legacy records without nonsecret byte
captures therefore have complete known coverage but unavailable results.
Changed or unavailable entries add corresponding `recorded_input_changed`
or `recorded_input_unavailable` blockers. A missing history manifest keeps
historical coverage explicitly unavailable instead of deriving it from
the supplied evidence.

The current protected subset is also exposed through the existing
`protected_inputs` summary. That compatibility view still describes only
current protected slots: its historical coverage stays unavailable and
its unchecked-nonsecret count retains its prior meaning. The new
`recorded_inputs` section carries the complete declared-file roles.

Legacy-only `input_observations` calls keep their existing report behavior.
Supplying both old and new arguments is refused with
`conflicting_input_observation_modes`, even if their results agree. The
planner never chooses the more favorable of overlapping batches. A trusted
manifest with no supplied evidence reports `not_observed`; ordinary old
calls without a manifest keep their prior output shape.

All results retain `full_input_closure = "unverified"` and remain
non-executable. The existing input-closure, functional-check, application
and attempt-history limitations remain in force. Matching declared input
files does not prove the effective Compose environment or all renderer
references, identify an application, or authorize an operation.

## Validation boundary

Report construction performs no file, store, process or network I/O. The
caller explicitly loads history and collects evidence beforehand. Private
fixtures verify the independent projection, partial and forged coverage,
classifications, retained dependencies, identity/role/version/freshness
mismatches, legacy behavior, unavailable baselines and immutable private
output. Explicit guards reject I/O during report construction. This does
not establish installed-helper security or real Arch/Docker acceptance.
