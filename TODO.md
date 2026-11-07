# Deferred work

Ordinary follow-ups live here; promoted whole-codebase review findings
belong in [review/BACKLOG.md](review/BACKLOG.md). Follow
[docket/TODO_GUIDE.md](docket/TODO_GUIDE.md). Ready entries are unblocked;
understood work awaiting a dependency or external input belongs in Waiting.
The user authorized staged implementation of the product redesign on
2026-11-01 after the disposable mechanism proofs, including parallel
work and reviewable pull requests while away. Production server package
and lifecycle changes remain outside that authorization. Completion is
measured against the first-release contract and acceptance scenarios.

## Needs triage

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized

- [NATIVE] `visualize-installed-package-dependencies` — **Show installed packages as a tree rooted at explicitly requested packages.** Make it possible to follow each requested package's dependencies and understand why packages are installed.
  - Source: user request, 2026-11-07.
  - Show explicitly requested packages at the top level and their transitive installed dependencies underneath.
  - Account for the underlying graph: shared dependencies can have multiple parents. Choose a readable expansion/reference convention that preserves those relationships, identifies repeated packages, and terminates on cycles.
  - Clarify how installation reasons and recorded requests determine roots, how provider relationships are represented, and where packages unreachable from an explicit root appear.
  - Validate with synthetic inventories containing shared dependencies, multiple roots and cycles; the visualization must leave installed package state unchanged.

- [NATIVE] `visualize-pacman-upgrade-reasons` — **Visualize a pacman -Syu transaction with old/new versions and reasons for each change.** Explain what is being updated or upgraded and why it is included.
  - Source: user request, 2026-11-07.
  - Show the currently installed version and proposed target version for each package, with additions and replacements clearly identified.
  - Distinguish newer repository versions, dependency requirements and replacements where the transaction metadata supports those explanations; connect dependency-driven changes to the packages or constraints that require them and show unavailable explanations explicitly.
  - Triage whether the view previews a proposed transaction, explains a completed one, or supports both, and define which package/database snapshots the explanation describes.
  - Validate against synthetic transaction inputs with shared dependencies and version changes; viewing an explanation must not itself perform an upgrade.

- [DESIGN] `refine-later-server-milestones` — **Define concrete scenarios for the later milestones.** Extend accountability, replacement-host recreation, and reusable application knowledge without weakening the first release.
  - Source: [later milestones](plans/2026-10-31-server-environment-milestones.md#later-milestones), 2026-10-31.
  - Clarify dependencies and evidence, then split into bounded planning tasks before implementation. Recreation needs an identified Arch baseline and explicit external data and secret prerequisites.

- [DOCKER] `assess-codeman-lifecycle-stretch` — **Determine Codeman's actual lifecycle requirements from deployment evidence.** Its source/build layout may expose useful later work, but is not the first Docker benchmark.
  - Source: [stretch case](plans/2026-10-31-server-environment-milestones.md#later-milestones), user's Codeman correction, 2026-10-31.
  - Distinguish already-accountable resources from any unsupported checkout, build, or installer orchestration. Keep extensions outside milestone 1; do not turn the tool into a generic build framework.

## Needs proof of concept

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized

## Waiting

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized

- [TOOLING] `update-docket-finding-marker-validation` — **Resync Docket after its finding-marker validation handles early pipe closure correctly.** Valid claims must not fail strict validation while their backlog entry appears in both base and head.
  - Source: [vendored marker validator](docket/scripts/check-pr-markers.sh), reproduction during `review/resolve-installed-dependency-targets`, 2026-11-01.
  - Blocked by: an upstream Docket correction for the base/head entry producer piped to an early-exiting grep under pipefail; integrate the correction through the installer rather than editing vendored files.
  - Reproduction: with the claimed entry and its Findings present in both snapshots, the consumer finds the finding and exits successfully, but the producer receives SIGPIPE (`141 0` pipeline statuses), so valid Claims review finding markers are reported as absent. A draining consumer returns `0 0` on the same input.
  - Verify strict Claims and Resolves cases, retain rejection of absent findings, and preserve the original Claims input and reproduction evidence. This work does not authorize a gate or hooks-policy change.

- [TOOLING] `update-docket-cleanup-worktree-enumeration` — **Resync Docket after cleanup safely enumerates repositories with many worktrees.** The dry run must reach its preservation checks instead of exiting while finding the main worktree.
  - Source: [vendored cleanup helper](docket/scripts/cleanup-landed.sh), cleanup after PR #58 during the parallel execution-control tasks, 2026-11-07.
  - Blocked by: an upstream Docket correction and supported installer update; do not patch the vendored helper directly.
  - Reproduction: `git worktree list --porcelain | awk '/^worktree / { print substr($0, 10); exit }'` returns pipeline statuses `141 0` in this checkout. Under `set -euo pipefail`, cleanup exits 141 after its dry-run heading, before examining any branch.
  - Verify large worktree inventories, correct main-worktree identification, and preservation of dirty worktrees and unique ignored evidence. No branches or worktrees were removed during the reproduction.

- [TOOLING] `expose-execution-requests` — **Connect bounded plan, apply and recover requests.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#expose-execution-requests), 2026-11-07.
  - Depends on: `recover-interrupted-attempts`, `report-attempt-outcomes`, `authorize-execution-plans`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [NATIVE] `apply-native-transactions` — **Commit only an exactly accepted native transaction.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#apply-native-transactions), 2026-11-07.
  - Depends on: `expose-execution-requests`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [NATIVE] `build-aur-artifacts` — **Build accepted AUR sources under an isolated unprivileged identity.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#build-aur-artifacts), 2026-11-07.
  - Depends on: `apply-native-transactions`, `expose-execution-requests`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [NATIVE] `install-aur-artifacts` — **Require separate acceptance of built AUR package artifacts.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#install-aur-artifacts), 2026-11-07.
  - Depends on: `build-aur-artifacts`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [DOCKER] `prepare-compose-images` — **Bind explicitly acquired Docker images to digest and platform.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#prepare-compose-images), 2026-11-07.
  - Depends on: `render-compose-execution-bundles`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [NATIVE] `apply-local-resource-properties` — **Apply bounded local account and directory prerequisites.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#apply-local-resource-properties), 2026-11-07.
  - Depends on: `expose-execution-requests`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [NATIVE] `apply-native-service-configuration` — **Apply the selected native configuration and service change.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#apply-native-service-configuration), 2026-11-07.
  - Depends on: `expose-execution-requests`, `verify-native-application-health`, `apply-local-resource-properties`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [DOCKER] `apply-sonarr-port-change` — **Apply the accepted Sonarr port change to the same container.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#apply-sonarr-port-change), 2026-11-07.
  - Depends on: `expose-execution-requests`, `render-compose-execution-bundles`, `verify-container-application-health`, `verify-runtime-consumer-access`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [DOCKER] `apply-compose-recreation` — **Apply an explicitly accepted Compose deployment change.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#apply-compose-recreation), 2026-11-07.
  - Depends on: `expose-execution-requests`, `prepare-compose-images`, `verify-container-application-health`, `verify-runtime-consumer-access`, `apply-local-resource-properties`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `resolve-manual-configuration-drift` — **Expose separate keep and restore decisions for manual edits.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#resolve-manual-configuration-drift), 2026-11-07.
  - Depends on: `apply-native-service-configuration`, `apply-sonarr-port-change`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `record-retirement-dispositions` — **Require a fresh scoped data decision for every retirement.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#record-retirement-dispositions), 2026-11-07.
  - Depends on: `authorize-execution-plans`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `retire-workloads-with-retained-data` — **Stop and retire workloads while preserving usable retained data.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#retire-workloads-with-retained-data), 2026-11-07.
  - Depends on: `record-retirement-dispositions`, `apply-native-service-configuration`, `apply-compose-recreation`, `verify-runtime-consumer-access`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `delete-exclusive-retirement-data` — **Delete only freshly authorized exclusive retirement data.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#delete-exclusive-retirement-data), 2026-11-07.
  - Depends on: `retire-workloads-with-retained-data`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `export-and-recover-host-history` — **Export complete redacted history and recover from verified backups.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#export-and-recover-host-history), 2026-11-07.
  - Depends on: `recover-interrupted-attempts`, `record-retirement-dispositions`
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `validate-installed-execution-boundary` — **Validate the installed privilege and worker boundary in a disposable guest.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#validate-installed-execution-boundary), 2026-11-07.
  - Depends on: `expose-execution-requests`, `export-and-recover-host-history`
  - Blocked by: explicit approval of exact system commands, write contents and disposable target, and verified fixture/tool prerequisites.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `accept-recording-and-accountability` — **Run first-release adoption and accountability scenarios.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#accept-recording-and-accountability), 2026-11-07.
  - Depends on: `validate-installed-execution-boundary`, `render-compose-execution-bundles`, `compare-package-file-baselines`, `verify-container-application-health`, `verify-native-application-health`, `verify-runtime-consumer-access`
  - Blocked by: explicit approval of exact system commands, write contents and disposable target, and verified fixture/tool prerequisites.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [NATIVE] `accept-native-execution` — **Run native package, configuration and recovery acceptance.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#accept-native-execution), 2026-11-07.
  - Depends on: `validate-installed-execution-boundary`, `install-aur-artifacts`, `apply-native-service-configuration`, `resolve-manual-configuration-drift`, `report-attempt-outcomes`
  - Blocked by: explicit approval of exact system commands, write contents and disposable target, and verified fixture/tool prerequisites.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [DOCKER] `accept-docker-execution` — **Run Docker configuration, update and recovery acceptance.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#accept-docker-execution), 2026-11-07.
  - Depends on: `validate-installed-execution-boundary`, `apply-sonarr-port-change`, `apply-compose-recreation`, `resolve-manual-configuration-drift`, `report-attempt-outcomes`
  - Blocked by: explicit approval of exact system commands, write contents and disposable target, and verified fixture/tool prerequisites.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `accept-retirement-and-release` — **Verify retirement and reconcile every first-release acceptance gate.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#accept-retirement-and-release), 2026-11-07.
  - Depends on: `accept-recording-and-accountability`, `accept-native-execution`, `accept-docker-execution`, `delete-exclusive-retirement-data`, `export-and-recover-host-history`
  - Blocked by: explicit approval of exact system commands, write contents and disposable target, and verified fixture/tool prerequisites.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

## Ready for separate work

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized

- [DOCKER] `verify-container-application-health` — **Verify the selected Sonarr and Radarr application predicates.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#verify-container-application-health), 2026-11-07.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [NATIVE] `verify-native-application-health` — **Verify the selected native service behavior.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#verify-native-application-health), 2026-11-07.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `verify-runtime-consumer-access` — **Check access as the actual declared runtime consumer.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#verify-runtime-consumer-access), 2026-11-07.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [NATIVE] `compare-package-file-baselines` — **Explain package-supplied files and local configuration differences.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#compare-package-file-baselines), 2026-11-07.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [DOCKER] `render-compose-execution-bundles` — **Render a complete authenticated Compose input bundle.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#render-compose-execution-bundles), 2026-11-07.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `report-attempt-outcomes` — **Expose attempt history and partial outcomes in status.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#report-attempt-outcomes), 2026-11-07.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `authorize-execution-plans` — **Bind accepted execution plans to exact authority and inputs.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#authorize-execution-plans), 2026-11-07.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.

- [TOOLING] `recover-interrupted-attempts` — **Recover uncertain attempts without overlapping work.** Deliver the bounded scope and acceptance checks in the linked task.
  - Source: user-requested [execution breakdown](plans/2026-11-07-execution-work-breakdown.md#recover-interrupted-attempts), 2026-11-07.
  - Acceptance: the linked task defines ownership, scope, failure cases and required evidence; slice completion does not waive A1–A12.
