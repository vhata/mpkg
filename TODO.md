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

- [NATIVE] `reject-endpoint-url-controls` — **Reject literal ASCII control characters in declared endpoint URLs.** The closed URL validator currently accepts non-whitespace controls that the bounded transport cannot safely send.
  - Source: [endpoint URL validation](mpkg_manager/declarations.py), [closed check schema](docs/manager-declarations.md#checks), endpoint transport investigation and independent model reproduction, 2026-11-02.
  - Reproduction: validate_model accepts a minimal service endpoint with a URL path containing literal U+0001. No network access is needed to demonstrate the discrepancy.
  - Reject literal C0 controls and DEL consistently through TOML/model validation with fixed diagnostics. Preserve ordinary and percent-encoded URL paths, existing loopback/port constraints and private error output; add focused before/after regressions.


- [NATIVE] `report-protected-input-freshness` — **Expose protected-input freshness in comparison reports.** The recorder can compare authenticated captures, while reports still lack input evidence and always retain the full-input freshness blocker.
  - Source: [protected comparison requirements](docs/specs/2026-10-31-first-release-contract.md#6-compose-inputs-and-privileges), [comparison implementation](mpkg_manager/planning.py), PR #15 and follow-up investigation, 2026-11-01.
  - Define immutable evidence bound to host, exact recorded source/model snapshot, management revision, collection-start time and complete protected-entry coverage. Report only same/changed/unavailable using input IDs and file positions; exclude capture references, private paths, bytes and protected digests.
  - Initially cover the exact requested recorded snapshot; leave historical-resource input coverage explicitly unavailable. Keep nonsecret/Compose closure and application blockers intact; property agreement must remain independent of input freshness.
  - Verify the real temporary policy/record/comparison/report path, changed bytes/identity, unavailable or foreign/stale/future evidence, shared bundles, partial coverage, unchanged durable history and private public output. Reports remain non-executable.
