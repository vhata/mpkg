# Immutable Sonarr Port proposals

`mpkg_manager.effect_plans` persists a narrow typed proposal for changing
an existing Sonarr XML `Port`. The trusted library derives candidate
bytes and obligations from actual stored history and an authenticated
protected capture. Every proposal is permanently **blocked** and
**non-executable**. No installed plan/apply verb, worker, file publication
or arbitrary action-graph interface is provided.

The library is groundwork for the
[plan and action protocol](specs/2026-10-31-first-release-storage-and-execution.md#plan-and-action-protocol).
It does not turn a status report, caller JSON or an edited exported
proposal into execution authority. Python library access is not an
installed privilege boundary or containment against a trusted root.

## Derivation and storage

The administrative interface accepts only existing trusted handles and
exact identifiers:

```python
proposal = derive_sonarr_port_proposal(
    recorder,
    expected_revision=revision,
    snapshot_id=snapshot_id,
    stable_resource_id=stable_id,
)
public = proposal.as_dict()
```

`recorder` must be a `ProtectedRecorder` using a verified `HostStore` and
loaded host policy. No argument supplies candidate XML, desired port,
authority, executable, effect list or prerequisite graph. The adapter
loads the exact recorded decision and snapshot, finds the stable
accepted resource by its host-bound physical identity, and derives the
desired port from the current declaration. The target must still be
accepted and explicitly manage `port`; missing targets, relinquishment
and authority conflicts refuse persistence.

The same retained-consumer constraint validation used by adoption checks
the proposed target. New intent cannot discard an earlier consumer's
accepted port requirement. A logical rename can preserve physical
identity and authority, but changing the resource path cannot.

The target's input bundle must identify exactly one authenticated
protected capture of its XML path in the exact target snapshot.
Unbound caller references and generic captures are insufficient. A
fresh descriptor-based capture through the verified policy must match
the stored bytes and full file identity. Capture runs outside SQLite's
write transaction. The trusted
[Sonarr adapter](manager-sonarr-xml.md) produces the candidate internally;
unsupported XML fails without a proposal. It preserves all bytes outside
the Port digits. A numerically unchanged target keeps identical bytes
and remains blocked.

Before insertion, a short expected-revision write transaction rechecks
the policy context, authority, exact snapshot and complete historical
derivation. It stores the private candidate and canonical context in
the same transaction. Neither proposals nor their retrieval advance
decision history or modify accepted resources.

Schema 3 adds the STRICT `sonarr_port_proposals` table. Foreign keys bind
the decision, exact snapshot, stable resource adoption row and protected
capture. SQL constraints fix the adapter and blocked state; immutable
triggers refuse updates and deletion. A private host-key seal binds the
proposal UUID, timestamp, fixed adapter/state, complete context and
candidate bytes. There is no supported transition to executable state.

## Separate historical scopes

The private context retains current intent and accepted authority as
different facts. It includes the accepted definition and consumer
requirements, current target, combined constraints, before-capture
identity/token, policy identity and the derived Port candidate metadata.

Current prerequisites follow `requires` in the target decision's exact
snapshot. Retained prerequisites follow the target's original adoption
snapshot. Every accepted dependency additionally retains its own
adoption snapshot, input obligations, accepted requirements and required
checks; that expansion recurses through separately accepted dependencies.
Removing a prerequisite or reusing its logical ID in current intent does
not substitute the new definition for the retained definition. Different
adoption revisions of the same stable dependency remain distinct.

Both protected and nonsecret input slots retain original snapshot and
decision provenance. Missing authenticated captures or accepted
prerequisite bindings remain explicit unavailable obligations and add
blockers. Current declared checks and historical accepted predicates
are retained independently; no successful check result is invented.
These scopes describe declared relationships and captured files. They
do not prove rendered Compose closure or discover undeclared writers,
containers, input paths or runtime dependencies.

The proposal records a fixed effect kind, adapter version, intended
30-second operation timeout and a requirement for an accepted maintenance
interval. These are obligations for a future implementation, not an
enforced worker timeout or evidence that interruption was accepted.
Installed integration verification, worker/attempt history, maintenance
authorization, writer exclusion, container identity, atomic publication,
complete input closure and required after-checks are always blockers.

## Verification and inspection

Every store read or write verifies the complete proposal history.
Verification independently regenerates authority, constraints,
prerequisite/input/check contexts and transformed candidate from the
original stored decisions, then compares exact canonical bytes and the
seal. A correctly resealed but incorrectly derived candidate or authority
context is still rejected. Invalid proposal rows fail ordinary store
reads with `store_corrupt`, not a partially trusted projection.

```python
proposal = read_sonarr_port_proposal(store, proposal_id)
page = list_sonarr_port_proposals(store, limit=100, after_id=previous_id)
```

Retrieval and listing work through a read-only store handle. Pages are
ordered by proposal UUID, not creation time. `after_id` is an exclusive
UUID cursor; `limit` is an integer from 1 to 100. It bounds returned
records only. Full history validation and candidate regeneration remain
intentionally unoptimized; page size does not bound their total work.

Public projections contain only proposal/host/resource/snapshot IDs,
revisions, time, selected port values, fixed blocker metadata and bounded
scope counts. They omit candidate bytes, capture references, paths,
policy identities, input identities, raw/keyed digests, seals, predicates
and executable details. Each projection is a fresh value; editing it or
constructing the projection dataclass grants no authority.

`input_comparison=matched_at_proposal` records a past comparison.
`decision_state=current` only means the decision revision has not
advanced. Neither asserts current file freshness, live policy validity
or writer exclusion. Historical inspection still works after the input
file or policy disappears. Later intent, re-adoption or relinquishment
does not rewrite a proposal; inspection marks an older revision
`superseded` while validating its original bindings.

The candidate is limited to 16 MiB and private context to 1 MiB. Each
declared prerequisite scope permits at most 64 prerequisites, recursive
accepted dependency expansion permits at most 64 distinct adoption
bindings including the target, and each scope permits 256 input slots.
Exceeding a limit refuses persistence, never truncates obligations.
Protected storage is plaintext behind store access controls.

## Schema evolution and failures

New stores use schema 3. Exact versions 1 and 2 remain readable; ordinary
writes require version 3. The
[explicit maintenance library](manager-store-migration.md) keeps distinct
verified-backup transitions from 1 to 2 and from 2 to 3. It never silently
chains upgrades. Version-3 receipts authenticate the preceding receipt
seal; complete ordered chains and existing version-2 receipts remain
verifiable.

Commit and lock-release errors can occur after a proposal persisted.
`commit_outcome_unknown` makes the store handle unusable; an error never
proves that no proposal persisted. Cleanup preserves cancellation and
resolves any live SQLite transaction before releasing the store lock.
Repeated cleanup failure can retain the lock until explicit cleanup or
process exit; see [store failure reporting](manager-store.md#protected-capture-and-failure-reporting).
After releasing any retained failed handle safely, reopen read-only and
list proposals to inspect durable evidence. No retry or deletion is
automatic. A separate context-final `store_close_failed` also does not
undo completed writes. File or policy changes after capture do not undo
proposal storage. All proposals remain blocked regardless.

Private fixtures exercise candidate preservation, retained/current
scope separation, consumer conflicts, stale input/decision/policy,
tampering, read-only pagination, commit uncertainty and backup isolation.
Compatibility fixtures were generated by unchanged genuine version-1
and version-2 store implementations; their SQL records contain only test
data. No actual host store, configuration, package, service or Docker
lifecycle is changed, and no installed execution acceptance is claimed.
