# Read-only comparisons

`mpkg_manager.planning.build_report` compares validated desired state,
accepted host records and recent observation facts. It returns an
immutable, non-executable report. It performs no file reads, store writes,
queries, native solving or host changes. The report is a foundation for
status and proposals, not an application plan or an installed privilege
boundary.

## Inputs and binding

```python
report = build_report(
    declaration, current, observations,
    host_id=accepted_host_uuid,
    engine_aliases=accepted_engine_aliases,
    selected_components=None,
    now=aware_datetime,
    max_age_seconds=60,
)
```

`declaration` is a `Declaration` from the
[declaration model](manager-declarations.md). Its original source is reparsed and
all fields are checked, so constructing a dataclass does not bypass
validation. `current` is the sanitized projection returned by
[`HostStore.current()`](manager-store.md); `observations` is the wire
dictionary returned by `ObservationBatch.as_dict()`. Either projection
may be `None`, which produces explicit unavailable evidence. Each
projection is limited to 16 MiB of canonical JSON.

The caller must obtain these projections, host identity and engine alias
bindings through its trusted host boundary. Dictionary shape validation
does not authenticate a host or make imported JSON authoritative. This
slice exposes no CLI accepting arbitrary management projections.

The report binds the host UUID, exact source and canonical declaration
digests, schema versions, management revision and accepted snapshot ID.
Comment-only source changes therefore report unrecorded intent even
when the normalized model is identical. No protected input digest,
capture token, opaque reference or source text is exported.

An observation must have coherent host identity and UTC timestamps,
unique resource/property facts and explicit resource coverage. Every
compared fact must match the resource kind and bound physical identity.
Identity fields are validated against the declaration kind's schema
before constructing physical keys. Accepted engine identities are
rebound through the supplied trusted aliases and must agree with their
stored keys; missing historical alias bindings cannot grant authority.
Native package and service facts must identify their corresponding
observer source. Missing properties, unsupported sources, stale evidence
and future timestamps remain unknown. `now` accepts an aware datetime
for deterministic callers and tests; its default is current UTC time.
`max_age_seconds` is an integer from 1 through 3600, inclusive. Facts at
the exact age limit remain usable.

## Property and check results

Each selected resource has separate property results, required checks,
known consumers and blocker codes. Property results are `agreement`,
`difference`, `unknown` or `conflict`. Different results can coexist:
observing one matching property does not establish the rest. Boolean and
integer values remain distinct. Reports summarize results and evidence
sources without returning desired or observed values or arbitrary
observer diagnostics. The scope-limited indicators preserve the
existence of limitations without exporting their private text.

Property authority is the intersection of previously accepted grants
and grants requested by the current declaration. Desired values,
consumer requirements and observations cannot grant authority. Matching
uses accepted physical identity, so a logical rename can retain an
adoption. Changing a resource kind at a shared path cannot inherit the
old kind's grants. Missing accepted engine bindings block identity
matching; symbolic aliases are never inferred to be actual engines.

Accepted consumer requirements remain effective alongside current
requirements, including after relinquishment transfers responsibility
outside the manager. Combined constraints use declaration validation
against the complete target context: an AUR source requirement can
require an exact recipe binding, and retained file input references must
still resolve without conflicting content sources. Invalid combined
contexts report conflicts even when individual facts match.
Conflicting values are explicit, and consumer changes
require recording. Removing a declaration produces a retained resource
requiring a retirement or relinquishment decision; it chooses neither
deletion nor a data disposition. Relinquished records remain external.
A previously recorded pending disposition is not cleared merely by
reintroducing the declaration in the working tree.

`selected_components=None` compares all resources. An explicit list
selects those components and resource prerequisites. It still reports
removed host records under `retained_resources` and accepted resources
outside the selection under `unselected_resources`; selection cannot
hide retained management records. All current and accepted consumer
requirements constrain selected resources, including consumers outside
the selected component set.

Package `any` means the observed direct installation's version meets the
version policy; it does not create a pin. `exact` compares the declared
version string without invoking native solving, replacing packages or
approving a repository/AUR source. A matching installed version cannot
prove an AUR recipe revision. Absence of a direct installed package name
does not prove that a virtual dependency request is unsatisfied. Version
and install-reason comparisons require a direct presence observation.
Native dependency and provider resolution remain explicit capability
limits.

Required checks stay separate from property agreement. Only the closed
package and service property predicates can be evaluated from current
facts. Endpoint and consumer-access checks remain unverified; service
running state is not functional health. Accepted check IDs are retained
even when removed from the working declaration. The current store
projection does not contain their original predicate definitions, so
`accepted_check_definition_unavailable` blocks full verification even
when current same-ID predicates pass. A replacement predicate cannot
silently weaken an accepted requirement.

## Output and limits

`ComparisonReport.canonical_bytes` and `.sha256` bind the report's
canonical JSON representation. `.as_dict()` returns a fresh copy;
mutating it cannot change the immutable report. `PlanningError.code`
contains a fixed diagnostic for invalid context, declaration snapshot,
management projection, observation projection or report inputs. It
never returns raw parser, filesystem or supplied error text.

Every report has `executable: false` and explicit
`application_not_implemented` and `attempt_history_unavailable` blockers.
It includes no commands, effects, action graph or apply authorization.
Current observations are time-bounded evidence, not an atomic host
snapshot. Attempt history, protected input replay, historical check
definitions, native solving and functional verification require separate
implementations before a complete application proposal is possible.

The tests cover mixed results, exact source binding, typed comparison,
stale and mismatched evidence, provider ambiguity, shared-consumer
conflicts, retained host records, immutable output and secret-free
summaries. A real temporary SQLite integration verifies that comparing
an uncommitted removal preserves accepted records without changing store
files. These tests do not establish real Arch/Docker behavior or the
first-release acceptance demonstrations.
