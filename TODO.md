# Deferred work

Ordinary follow-ups live here; promoted whole-codebase review findings
belong in [review/BACKLOG.md](review/BACKLOG.md). Follow
[docket/TODO_GUIDE.md](docket/TODO_GUIDE.md). Ready entries are unblocked;
understood work awaiting a dependency or external input belongs in Waiting.
The product redesign remains in planning. These entries do not authorize
implementation or live server changes, and no implementation is Ready.

## Needs triage

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized

- [DESIGN] `design-first-release-persistence-and-execution` — **Choose the concrete representation and native execution boundaries for the first release.** Turn the behavioral contract into a bounded implementation design before authorizing product work.
  - Source: [remaining design gates](docs/specs/2026-10-31-first-release-contract.md#9-remaining-design-and-evidence-gates), design task, 2026-10-31.
  - Specify declaration encoding, host-store location/format and crash consistency, input/secret capture, privilege boundaries, and native source preparation, planning and application interfaces. Demonstrate how real tool semantics can satisfy the contract; do not create a general task language or select a framework.
  - Related: `work-through-compose-resource-example`, `define-first-release-acceptance-scenarios`

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

- [DESIGN] `define-first-release-acceptance-scenarios` — **Specify repeatable evidence for every first-release criterion.** Concrete demonstrations must preserve the milestone's full acceptance requirements.
  - Source: [milestone 1](plans/2026-10-31-server-environment-milestones.md#1-first-useful-release-manage-an-existing-setup-end-to-end), 2026-10-31.
  - Starting point: [scenario matrix and fixture requirements](docs/specs/2026-10-31-first-release-acceptance.md), drafted 2026-10-31; no demonstrations have run.
  - Depends on: `inspect-existing-compose-deployments`
  - Blocked by: a verified current AUR recipe and sources, and an identified disposable Arch image with a coherent frozen package set; candidate names alone are not a reproducible fixture.
  - Complete the fixture manifest and evidence-backed native/Docker examples, preserving every scenario and milestone acceptance criterion. This task designs the demonstrations; it does not run them or implement the product. Stub results cannot replace required real-tool evidence.
  - Related: `design-first-release-persistence-and-execution`

- [DOCKER] `inspect-existing-compose-deployments` — **Select a conventional Compose application from its real definition.** A directory listing alone cannot establish mounts, identities, dependencies, or runtime behavior.
  - Source: [milestone 1](plans/2026-10-31-server-environment-milestones.md#1-first-useful-release-manage-an-existing-setup-end-to-end), server-capture discussion, 2026-10-31.
  - Blocked by: access to the actual Compose definitions and relevant referenced inputs; none are retained in this repository.
  - Inspect homepage, plex, prowlarr, radarr, sabnzbd, and sonarr definitions as available. Record image/build choices, deployment identity, mounts, shared resources, declared identities, and remaining observation gaps. Do not modify live services or copy secret values into Git.

- [DESIGN] `work-through-compose-resource-example` — **Work through the selected deployment using the proposed resource model.** Ground the model in actual evidence before choosing a declaration format.
  - Source: [resource example](docs/specs/2026-10-31-server-environment-resources.md#one-concrete-example), 2026-10-31.
  - Depends on: `inspect-existing-compose-deployments`
  - Starting point: [first-release contract](docs/specs/2026-10-31-first-release-contract.md), including explicit project identity, secret-safe input closure and volume/network retirement authority.
  - Show adoption without application, pending changes, partial failure, manual edits, and retirement with shared or retained resources. Distinguish observed facts from assumptions and keep command/API/storage choices provisional.

## Ready for separate work

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized
