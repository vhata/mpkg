# Immutable execution-plan acceptance

`mpkg_manager.execution_plans` derives closed, versioned descriptors from
recorded authority and trusted adapter evidence. Schema version 5 stores
plans and explicit operator acceptance as separate immutable, authenticated
records. The production adapter registry remains unavailable. The private
fixture adapter and harness exercise the protocol using inert effects only;
all projections remain `fixture_only` and `executable: false`.

No helper request can submit descriptors, dependency edges, commands,
callbacks or adapter registrations. Production attempt creation and request
integration remain separate work. A constructed `AcceptedPlanBinding`, a
copied summary or an existing journal fixture record grants no authority.

## Derivation and retained obligations

The fixture planner accepts selected stable resource IDs, never an action
graph. It resolves their current and originally accepted prerequisite
closures through authenticated historical physical identities, rejects
missing authority or cycles, and derives deterministic dependency order.
Its current effect vocabulary is inert change or inert verification of a
package's presence target. Other resource effects and production adapters
are unavailable.

Each private plan binds the host, exact decision revision and snapshot,
original adoption records and consumer requirements, current and original
check definitions, complete original input-capture references, policy
identity, expected before evidence, artifact identities and content digests,
adapter/version, derived dependency order, timeout, interruption policy and
disposition. Existing retained consumer requirements still constrain new
targets. Plans cannot silently replace check predicates with later ones.

The registered adapter owns four operations:

- `prepare` derives before evidence, artifact bindings and change/verify mode.
- `revalidate` checks those exact prerequisites, including expected results
  of already completed actions.
- `execute` performs the registered effect; verification-only actions skip it.
- `observe` reports desired-property evidence and every required check.

The fixed fixture adapter models these contracts in memory. Its artifact
bytes and observation facts are trusted test assembly, never caller evidence
for a native transaction. No generic plugin or dynamic registration API is
provided.

## Acceptance and action boundaries

Preparing persists a new plan. Accepting identifies that exact plan and
records a trusted operator UID separately; a plan can be accepted once.
Both writes use the ordinary store mutation gate, so unresolved launch
reservations block them. Reading history never accepts or executes it.

Acceptance and every action boundary re-read policy-approved input sources,
compare original bytes and complete source identities, check the exact
policy handle identity and decision revision, and revalidate adapter facts
and artifacts. Missing legacy baselines block acceptance. Unexpected changes
require a fresh plan and fresh acceptance; no comparison token is updated
inside an old plan. The checks cannot exclude an administrator or external
writer after the last observation; concrete production adapters must also
supply their own mutation-boundary exclusion and supported atomicity.

`AcceptedPlanBinding` supplies plan/acceptance IDs, host/revision/snapshot,
operator UID and private descriptor/target digests for later integration.
The fixture bridge reloads durable acceptance and compares every field before
creating a journal attempt. It checks the worker's operator identity and
preserves the existing `PlanReference` fixture-only contract. The journal's
unique plan ID prevents replay through a second attempt. A retry additionally
requires proposal and acceptance timestamps after the predecessor
completion/recovery disposition; a spare older acceptance is insufficient.
Live evidence is revalidated again. Existing blocked
Sonarr proposals are never modified or promoted; a new plan is a separate
record derived by its own registered adapter.

The owned inert harness takes the host application lock, records a launch
reservation and worker ownership, and commits each action start before
calling the adapter. It holds no SQLite transaction while executing or
observing. Successful commands still require all observations; failed,
missing or malformed required checks stop later effects. Interruption and
unknown command results leave unresolved journal ownership. Only a fully
verified inert run releases its reservation. No-op verification records
observations without invoking the mutating adapter method.

## Persistence, privacy and limits

SQL triggers refuse update/delete of plans and acceptances. Reads verify
host-bound seals and re-derive historical authority, closure, order and
checks. Ordinary summaries omit private policy paths, source identities,
comparison tokens, artifacts, raw output and descriptor digests. Errors use
fixed codes. Protected bytes remain in the existing capture table.

The [explicit migration library](manager-store-migration.md) upgrades
version 4 to 5 only after a verified private backup of all prior history.
Legacy readers do not silently acquire plans or acceptances. Existing
proposals and attempt outcomes remain unchanged. Store or commit failures
can have uncertain outcomes; inspect durable history instead of assuming
rollback or repeating execution.

Temporary fixtures and inert adapters establish this library contract.
They do not establish installed authorization, native/package/AUR/Compose
execution, real service ownership, application health, power-loss behavior
or A1–A12 acceptance.
