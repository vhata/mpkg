# Manager implementation wave

The user authorized sustained parallel implementation, stacked pull
requests, and new agents/worktrees for independently filed bugs on
2026-11-02. Final review and landing remain user-owned. This extends the
existing implementation authorization; it does not authorize production
package/service/Docker changes, release/deployment, or gate-policy changes.

The [first-release contract](../docs/specs/2026-10-31-first-release-contract.md)
and [acceptance scenarios](../docs/specs/2026-10-31-first-release-acceptance.md)
remain the requirements. Isolated tests do not establish real acceptance.

## Initial parallel work

1. Expose authenticated protected-input freshness in comparison reports.
   Evidence binds host, exact recorded source/model, management revision,
   conservative observation time and explicit coverage. Initially support
   the exact requested recorded snapshot; retained historical inputs remain
   explicitly unavailable. Preserve complete-input and application blockers.
2. Investigate and implement bounded loopback endpoint observations for
   the existing closed check declarations. Keep transport and result
   validation separate from planner integration until interfaces are
   reviewed. Preserve accepted/current predicates independently. No arbitrary
   commands, redirects, proxies, secret response output or apply authority.
3. Inspect existing boundary/error paths for reproducible bugs. File each
   independently with evidence and then dispatch a new author/worktree;
   authors fix findings and independent reviewers verify them.

Assumptions, choices and undo directions are retained in the coordinator's
ignored `.docket/AUDIT.md` and each worktree's audit. Queue edits remain
coordinator-owned. Each implementation receives independent review,
focused regressions and the repository's full gates before becoming ready.
Dependent work may stack on reviewed interfaces; the coordinator verifies
combined behavior. At most four active agents and two heavy checks run.

Later work is selected from concrete remaining contract gaps after these
interfaces are available. A large architectural ambiguity, a reproduced
critical risk, or production/privilege decisions may require the user's
review; routine reversible decisions are recorded and implemented.
