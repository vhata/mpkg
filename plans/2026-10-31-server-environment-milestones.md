# Server environment milestones

This plan turns the [mandate](../docs/specs/2026-10-30-server-environment.md)
and [user journeys](../docs/specs/2026-10-30-server-environment-journeys.md)
into observable delivery milestones. It describes future work; no
capabilities are claimed to exist yet. The direction is direct native
tooling; detailed contracts, command syntax, storage formats, and
application integration mechanisms remain open.

## 1. First useful release: manage an existing setup end to end

**Outcome:** Bring a representative part of an existing Arch Linux
server under management, then change and retire software with clear
accountability and status.

The demonstration must include native software from Arch repositories
and the AUR, plus an existing Docker application. Include configuration,
a service identity, directories and permissions, persistent data,
expected generated files, and a resource shared with another consumer.
At least one shared consumer must be outside management. Named examples
and verification checks will be selected during detailed design.

The [Compose inspection and Sonarr example](../docs/specs/2026-10-31-compose-deployment-evidence.md)
selects Sonarr from the actual definitions as the first Docker case.
It records declared shared media consumers and observed identity/path
facts. The [runtime baseline](../docs/specs/2026-10-31-sonarr-runtime-baseline.md)
adds engine/project binding, image identity, actual mounts and
credentials, and bounded endpoint/root-access results. Accepted fixture
inputs and full functional checks still need verification before this
becomes an executable demonstration.

Use a conventional Compose deployment as the first Docker example,
preferably one using published images with clearly identified
configuration and data mounts. Select the application after inspecting
its Compose definition. Codeman is a stretch case, not the initial
benchmark or a first-release blocker. Its apparent source/build layout
in the previously supplied `opt-docker` directory listing should inform
later work, once the actual deployment requirements are understood. The
raw capture is not retained in this repository.

Shared identities, differing ownership and permissions, persistent
data, and configuration drift remain in scope: the other captured
applications already demonstrate why these distinctions matter.

**Acceptance criteria:**

1. **Adopt without disruption.** Record the existing software selections
   and deliberate configuration without installing, restarting,
   changing permissions, or relocating data merely to adopt them.
   Preserve the meaning of the current metapackage selections without
   requiring the old API or representation. Already-matching state can
   be verified without a redundant application step.
2. **Explain responsibility.** Identify supplied files, deliberate
   modifications, application data, expected generated files, and
   unexplained additions or changes within the inspected scope.
   Distinguish shared, independently wanted, externally managed, and
   unresolved resources. Include an unexpected file and an edit to a
   package-owned configuration file in the demonstration. A clean
   `lostfiles` report or blanket directory attribution is insufficient.
3. **Record separately from applying.** Record both a native
   package-selection change and a Docker application-configuration
   change while the live setup stays intact. Status identifies pending
   work. Separately apply both changes, including required supporting
   resources. The native case must install newly requested repository
   and AUR packages and satisfy an initially missing dependency. Verify
   the stated outcomes and effects on known shared consumers. Repeating
   an already-satisfied operation causes no unnecessary changes.
4. **Explain partial results.** Interrupt or fail an application attempt
   after some work has taken effect. Status identifies the intended
   setup attempted, completed work, failures and their reasons, work
   not attempted, current differences, and inspection limits. Recording
   newer intent does not erase the effects of the earlier attempt.
   A retry accounts for the live state already reached.
5. **Resolve manual changes deliberately.** Detect a direct edit to
   managed configuration. Demonstrate both choices: keep it as recorded
   intent, or restore the recorded version through a separate apply.
   Status inspection itself changes neither live setup nor intent.
6. **Honor version intent.** Demonstrate an unrestricted software choice
   and a supported exact pin. An unavailable or incompatible request is
   explained without silently weakening it. Observed versions do not
   automatically become pins, and permitting upgrades does not trigger
   them. Native changes respect Arch's coordinated upgrade requirements.
7. **Retire with accountable data.** Ask whether to keep or delete
   persistent data for every retirement. Demonstrate both choices in
   separate cases. Retained data remains attributable and accessible;
   shared and independently wanted resources survive. Successful
   retirement requires verified stopping and completed data handling.
   Incomplete or unverified outcomes remain explicit.

**Evidence required:** Repeatable demonstrations in a disposable Arch
environment with real native packages, an AUR package, and Docker,
alongside focused automated checks where useful. Record the starting
conditions, requested outcome, observed result, and inspection limits
for each criterion. Simulated command results alone do not establish
working installation, dependency handling, or service lifecycle behavior.

The first release is complete only when all criteria pass for the native
and Docker cases where applicable, and independent review has no
unresolved actionable findings. Inspection coverage and unsupported
resources must be explicit; they cannot be counted as verified or clean.
This milestone does not require complete adoption of the entire server,
replacement-server recovery, or contributed application support.

## Later milestones

These extend the same requirements rather than relaxing the first
release's acceptance criteria. Their order is proposed.

| Milestone | Outcome | Observable completion |
| --- | --- | --- |
| 2. Account for the existing server | Extend coverage beyond the representative deployments | Existing package collections, Docker applications, and their supporting resources are accounted for. Every discovered file and local modification in the agreed audit scope has an explanation, including recognized resources outside management. Unresolved differences and inspection gaps keep that scope incomplete; exclusions do not establish verified agreement. |
| 3. Recreate on a replacement Arch host | Reestablish the intended environment from its recorded description | Starting from an identified Arch baseline, satisfy the declared software, configuration, identities, permissions, and version requirements. Identify required external data and secrets, report missing prerequisites, and verify the declared application outcomes after they are supplied. |
| 4. Share application knowledge | Reuse knowledge about common applications while preserving local choices | Demonstrate reuse across two distinct local configurations with their customizations visible. Software without dedicated contributed support remains manageable. |

Each later milestone needs its own concrete scenarios and evidence
before implementation. Replacement-server recreation includes an
explicit statement of the required starting environment; it does not
implicitly promise disk provisioning or restoration of application data.

**Stretch case:** Application-specific source checkout, build, or
installer orchestration around Docker deployments, if Codeman or
similar applications require it. Preserve this as future work without
making the first release a general build/installation framework.
Resources outside supported lifecycle management must remain visibly
recognized or unresolved. This deferral does not remove the required
native AUR installation and dependency-handling demonstration.

## Next design work

The [first-release contract](../docs/specs/2026-10-31-first-release-contract.md)
proposes bounded resource behavior and records the remaining design
gates. The [acceptance scenarios](../docs/specs/2026-10-31-first-release-acceptance.md)
map every criterion above to starting conditions and pass/fail evidence.
Neither document claims acceptance execution. The observed Sonarr
baseline still needs accepted fixture inputs and fresh checks. The
[storage/execution proposal](../docs/specs/2026-10-31-first-release-storage-and-execution.md)
selects concrete mechanisms, and the
[fixture design](../docs/specs/2026-10-31-first-release-fixture.md)
binds source metadata and assembly/check choices. Artifact acquisition,
guest assembly, mechanism proofs and all acceptance executions remain
separate gates. The
[execution record](../docs/fixtures/2026-11-01-disposable-execution-evidence.md)
records the authorized disposable work against those gates; fixture or
mechanism success does not imply a product acceptance result.

The [architecture direction](../docs/specs/2026-10-31-server-environment-architecture.md)
selects direct native tooling and excludes Ansible and similar frameworks.
The [minimum resource model](../docs/specs/2026-10-31-server-environment-resources.md)
develops the contracts needed for the first milestone.

Refine the native integrations against milestone 1 and the retained
requirements for later milestones. Keep responsibility, shared resources,
separate recording and application, partial failure, status, version
constraints, and attributable runtime data explicit.

Before implementing milestone 1, settle its supported resource scope,
authority over shared resources, application success checks, retained
attempt history, and version-constraint support. Define what an explicit
update request may change; unattended update policy remains undecided.
Choose concrete demonstrations and their Arch baseline so that the
acceptance criteria can be checked without depending on production use.
