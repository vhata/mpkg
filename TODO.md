# Deferred work

Ordinary follow-ups live here; promoted whole-codebase review findings
belong in [review/BACKLOG.md](review/BACKLOG.md). Follow
[docket/TODO_GUIDE.md](docket/TODO_GUIDE.md). Ready entries are unblocked;
understood work awaiting a dependency or external input belongs in Waiting.
The full product redesign remains in planning. The user authorized
disposable guest assembly and focused mechanism proofs on 2026-11-01.
That scope does not authorize production server package or lifecycle
changes, or implementation of the complete replacement.

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

- [DESIGN] `prove-first-release-execution-boundaries` — **Prove the selected storage and native execution mechanisms in a disposable fixture.** The concrete design is a proposal whose failure and concurrency boundaries need real evidence before broader product implementation.
  - Source: [focused mechanism proofs](docs/specs/2026-10-31-first-release-storage-and-execution.md#focused-proofs-before-product-implementation), storage/execution design, 2026-10-31.
  - Test durable action boundaries and worker/daemon recovery, exact libalpm transaction revalidation, protected input replay, Compose no-op/recreation behavior, exclusive-writer XML edits, and bounded retirement. Preserve every acceptance criterion; these proofs do not replace A1–A12.
  - The focused proofs are authorized in the acquired disposable fixture; no production server lifecycle or package change is in scope.
  - Depends on: `assemble-first-release-disposable-fixture`

## Waiting

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized

## Ready for separate work

### P0 Critical

### P1 High

### P2 Normal

### P3 Low

### Unprioritized

- [TOOLING] `assemble-first-release-disposable-fixture` — **Acquire, build and verify the isolated guest baseline from the bound fixture design.** Source metadata and a scenario design are not an assembled or accepted system.
  - Source: [fixture assembly and execution evidence](docs/specs/2026-10-31-first-release-fixture.md#assembly-and-execution-evidence), first-release design, 2026-10-31; assembly authorized by the user, 2026-11-01.
  - Verify signatures and complete image layers, build the pinned AUR chain and Python 3.12, record actual runner/guest/input/identity checks, and create bootstrap restore points with the declared missing dependencies. Preserve exact CLI requests and all A1–A12 scenarios; no stub result can replace real-tool evidence.
  - Bootstrap does not require the unimplemented product. Prototype/product revision, injection controls and applied restore points are bound later by their actual runs; setup must not fabricate successful product attempts or preinstall prerequisites in the A4 restore point.
  - Starting point: [scenario matrix](docs/specs/2026-10-31-first-release-acceptance.md) and [frozen source inventory](docs/fixtures/2026-10-31-arch-native-inputs.json).
  - Related: `prove-first-release-execution-boundaries`
