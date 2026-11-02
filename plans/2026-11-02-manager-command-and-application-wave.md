# Manager command and application wave

The user authorized continued parallel implementation, independent
review, stacked PRs, and separately filed bug fixes on 2026-11-02 after
landing the observation wave. Final review and landing remain user-owned.
This scope does not authorize production installation, package/account/
service/Docker changes, deployment, billing or validation-policy changes.

The [first-release contract](../docs/specs/2026-10-31-first-release-contract.md),
[execution design](../docs/specs/2026-10-31-first-release-storage-and-execution.md)
and [acceptance scenarios](../docs/specs/2026-10-31-first-release-acceptance.md)
remain the requirements. The [architecture map](../ARCHITECTURE.md)
distinguishes implemented libraries from installed host capabilities.

## Initial independent slices

- Add a fixed, versioned host request boundary and staged installed
  launcher for existing recording/history operations. Bind policy,
  store, code, operator and lock paths at the trusted boundary; reject
  unsupported observation, preparation and application verbs explicitly.
  Keep initialization deliberate and adoption free of native effects.
- Extend recorded-input evidence to retained accepted snapshots and
  explicitly classified nonsecret files. Preserve authenticated origin,
  exact snapshot/slot bindings and complete bounded role coverage. File
  agreement alone cannot establish complete Compose input closure.
- Add bounded metadata scanning and narrow runtime-file classification.
  Preserve managed-configuration exceptions and report unexplained files,
  unreadable paths, exclusions, races and limits. Package baselines,
  content comparison and consumer access require their own evidence.

Each slice owns separate modules, tests and documentation. Store input
APIs have one owner; shared CLI, planner, architecture and queue changes
are sequenced by the coordinator. There are at most four active agents
and two heavy checks at once. Each author receives independent review.

## Dependent implementation

1. Expose explicit record/adopt/relinquish/history commands through the
   host boundary, then connect real observation collection and text/JSON
   status. Unavailable evidence stays visible rather than becoming
   matching state or authority.
2. Capture and validate complete supported Compose inputs, with explicit
   source order, interpolation, references and base paths. Keep rendering
   isolated and reject unsupported resolution mechanisms before invoking
   native tools.
3. Bind functional application checks to actual runtime identities and
   verify declared consumer access. Existing route status, running state
   and filesystem metadata do not establish these stronger claims.
4. Persist immutable typed effect plans tied to accepted decisions,
   inputs, prerequisites, consumer impact and verification. Reports stay
   non-executable until an installed integration supplies these gates.
5. Add durable attempts/actions, supervised worker ownership and recovery.
   Record action starts before effects; distinguish command outcomes from
   observed results; block overlapping work with unresolved attempts.
6. Implement narrow native package and Sonarr configuration application
   through those interfaces. Preserve exact native transaction semantics,
   coordinated upgrades, writer quiescence, content rechecks and explicit
   interruption. A changed prerequisite requires a new accepted plan.

These areas may require multiple focused PRs. Record assumptions and
undo directions in ignored `.docket/AUDIT.md`; keep process details in
review/state records and PR comments, not future commit descriptions.
Discoveries are filed before separate agents attempt fixes in new
worktrees. Related interfaces can stack without waiting for user merges;
combined checks and independent review cover their integration.

## Evidence and remaining release work

Routine checks use Python 3.12 and owned files, stores, child processes
and loopback fixtures with synthetic native responses. Staged helper
payloads are not installed on the real host as a validation step.
Disposable acceptance requires its own explicit target, prerequisites
and recorded outcomes; earlier mechanism proofs do not supply it.

AUR recipe/build/install handling, retirement-specific retain/delete
decisions, recovery/export completeness and all A1–A12 acceptance gates
remain first-release requirements. Completing a library slice does not
waive any unsupported capability or acceptance condition.
