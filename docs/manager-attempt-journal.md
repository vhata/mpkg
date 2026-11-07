# Durable attempt journal

`mpkg_manager.attempt_journal` stores immutable targets and append-only
activity in schema version 4. It supplies an internal journal and inert
fixture writer. The installed helper has no attempt-creation or execution
verb, and every record this writer creates permanently says
`authority: fixture_only` and `executable: false`. A record, copied
projection or manually constructed `PlanReference` grants no authority.

## Original targets and identity

A frozen `PlanReference` binds a new plan UUID, host UUID, exact decision
revision and snapshot, target digest and contract version. The fixture
plan factory derives its target from authenticated store history. Creation
re-derives it in the write transaction, rejects stale revisions or altered
bindings, and refuses reuse of a plan UUID. This is the internal contract
for later execution-plan integration, not an accepted execution plan.

Each attempt receives a random UUID and an immutable increasing ordinal.
It retains the original selected resources, accepted definitions and
consumer requirements, original accepted checks, current check definitions,
exact declaration snapshots and protected-input identities/comparison
bindings. Missing legacy captures remain missing. Later intent or adoption
does not change historical targets. Protected bytes remain in the private
input table; ordinary projections omit names, paths, tokens and private
binding material.

Trusted embedding arguments supply operator UID, worker UID, boot UUID and
worker UUID. The unit identity is derived as
`mpkg-attempt-<attempt UUID>.service`; callers cannot select a unit body,
command or environment through this journal. Persisting this name does not
launch a worker, reserve ownership or establish quiescence. The separate
supervisor and execution-boundary tasks own those operations.

Actions have stable random IDs, fixed fixture operation descriptors and a
bounded order. This slice accepts at most 128 actions and 4 MiB of private
target context. It does not accept arbitrary effect graphs. Retry ancestry
requires a finished failed or unverified predecessor, a distinct plan ID
and a later attempt ordinal. Unknown attempts cannot be retried through
this fixture interface; recovery must establish a separate disposition.

## Events and uncertainty

A short write transaction durably appends `action_started` before the
fixture harness invokes its inert callback. Any start commit or subsequent
cleanup error prevents that invocation, including a commit whose response
was lost. No database or store lock is held while the inert effect or
observation runs.

`command_completed` records only succeeded, failed, timeout or unknown.
`observation_completed` separately records satisfied, failed or unavailable.
Raw exception strings and child output have no event field. Ordinary
fixture callback exceptions become fixed failed/unavailable outcomes;
process interruption leaves the committed start visible.

Actions begin as planned, with `attempted: false`. A durable start without
command evidence projects unknown; its event still records the exact
started boundary. A successful command alone is unverified. Only command
success and a satisfied observation produce observed-complete. A failed
command remains failed even if a later observation is satisfied. A failed
or missing required observation prevents the next action from starting.
Never infer no effect from a failed command or successful effects from a
commit response.

Every append supplies the expected event sequence; concurrent or repeated
writers receive a conflict. Events carry authenticated predecessor seals,
and reads verify row authentication, exact historical derivation and the
state machine. SQL triggers reject updates and deletions. Completion is a
separate append, preserves unattempted actions and refuses unknown running
work. A newer intent revision can coexist with prior outcomes; this slice
does not implement the supervisor's unresolved-attempt mutation gate.

These checks detect schema/record corruption and invalid transitions. They
are not protection against an administrator owning the database and key,
or against restoration of an older complete database. A restored store
never proves that external effects rolled back.

## Inspection and migration

`read_attempt(store, attempt_id)` returns a detached redacted projection.
`list_attempts(store, limit=100, after_id=None)` pages in durable append
order, resolving the last returned UUID to its ordinal. New UUIDs cannot
sort behind a previous page. This is an advancing history feed: later
appends remain available after its last cursor, while each page has one
consistent read transaction. Missing cursors fail explicitly. Neither read
writes events nor starts recovery. CLI/status reporting remains separate.

Version-3 stores remain readable and require the explicit
`migrate_store_to_v4` library operation before writes. It verifies a new
private backup, preserves existing decisions/proposals/captures and adds
journal tables plus a chained maintenance receipt. See
[store migration](manager-store-migration.md). Old history never acquires
invented attempts. Ordinary opens do not upgrade the store.

## Validation limits

Temporary-store regressions exercise reopen, newer intent, immutable and
tampered rows, invalid transitions, sequence conflicts, retry ancestry,
concurrent append pagination, protected sentinels and complete backups.
Injected failures before/after commit and during lock cleanup prove that a
start error invokes no inert effect; interruption and completion-write
failure preserve the started record and unattempted work. Migration tests
cover refusal, verified backup, preserved original history and ambiguous
commit outcomes.

No native adapter, package operation, Docker lifecycle command, installed
worker or systemd service runs in these tests. Real crash/power-loss,
privilege, supervision, recovery and A1–A12 acceptance remain separate.
