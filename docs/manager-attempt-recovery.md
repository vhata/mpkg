# Evidence-backed attempt recovery

`mpkg_manager.attempt_recovery.AttemptRecovery` records an explicit
disposition for a reserved attempt. It never invokes package tools, kills
processes, deletes locks, replays actions or infers success. The current
boundary accepts trusted fixture collectors only; production evidence
collectors remain unavailable. The installed
[request boundary](manager-execution-requests.md) recognizes recovery
requests but cannot select a fixture collector.

## Ownership and evidence

Recovery acquires the existing host application lock before loading
authenticated history. A live worker that still owns that lock prevents
collection. Acquiring the lock is necessary but does not prove that a dead
worker's children or daemon requests have stopped.

Each collection receives a fresh immutable challenge bound to the host,
attempt, journal sequence, original and current boot identities, fixed
unit, native-lock applicability, exact engine identities and all affected
stable resource IDs. The trusted collector must return evidence for that
same challenge, with complete identity coverage and closed state values:

- Dispatch is settled only when the launcher and all queued manager
  requests can no longer create late work. An absent unit alone is
  insufficient during the launch handoff.
- The unit is inactive, exited or absent, and its cgroup is empty.
- If native packages are affected, native transaction ownership is idle.
  This is stronger than observing a missing lock file.
- Every affected engine and resource is quiescent, including outstanding
  daemon work that can survive a worker's death.

A reboot changes the observation context but supplies none of the other
evidence. Active, pending or unavailable evidence preserves the block.
Unknown engine identity, missing coverage, stale challenge or changed
journal sequence cannot release ownership. Collector exceptions retain
only an unavailable disposition; raw errors and output are never stored.
Collection exceeding the checked 30-second freshness budget is unavailable.
The fixture callback itself is trusted and is not a supervised production
query transport; production collectors need bounded acquisition.

The host lock spans collection and the final short journal transaction.
No database transaction spans collection, so read-only status remains
available. Current policy is revalidated before the disposition commit.
Concurrent recovery cannot acquire ownership, and late journal writes
invalidate a collected challenge instead of being silently overwritten.

## Durable disposition and later work

An authenticated `recovery_recorded` event retains the complete bounded
evidence privately. Its public projection exposes only `blocked` or
`quiescent`. The `supervision.recovery` field records that disposition;
only quiescence releases the durable unresolved-attempt gate. Ordinary
store writes and installed recording continue to use the existing gate.

A quiescent disposition seals the old attempt against further worker,
action or launch events. Its exact target, original command outcomes,
verification results and `finished` flag remain unchanged. An interrupted
action stays unknown even when its owner is demonstrably quiescent.
Recording newer intent becomes possible without changing those results.

Retry requires a different plan and a new attempt linked to the recovered
predecessor. Reusing the original plan or executing the old worker is
refused. The inert fixture journal establishes this identity boundary;
durable plan acceptance and fresh effect authorization are separate
requirements and are never supplied by recovery evidence.

There are at most 128 recovery observations per attempt. At most 127 may
be blocked, reserving a final slot for valid quiescence evidence. Further
blocked observations fail with `attempt_recovery_limit` without changing
the gate or deleting history. Evidence is limited to 128 KiB with exact
engine/resource coverage. No history is expired or truncated.

Missing or corrupt history blocks recovery rather than reconstructing
authority from current resources. Commit failure leaves the result
uncertain, including failures closing the store, policy or host lock after
commit. These return `recovery_outcome_unknown` without exposing raw
cleanup errors; interruptions retain their interruption semantics.
Reopening authenticated history distinguishes a committed
disposition from an uncommitted one. Repeating recovery never replays
effects or treats a lost response as permission to append duplicate work.

## Validation limits

Tests use temporary stores, fake unit/cgroup/native/engine observations
and owned inert workers. They cover unknown native and daemon effects,
reboot, delayed dispatch, unavailable evidence, changed history, concurrent
recovery, before/after-commit failures, newer intent and distinct retry
identities. They do not establish real systemd, native transaction, Docker,
installed privilege-boundary or power-loss acceptance.

See the [supervision guide](manager-attempt-supervision.md),
[journal guide](manager-attempt-journal.md) and original
[interruption acceptance scenario](specs/2026-10-31-first-release-acceptance.md#a7-interrupted-action-and-journal-failure).
