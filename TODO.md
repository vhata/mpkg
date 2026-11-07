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

## Ready for separate work

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized
