# Remaining execution work

The user requested this breakdown on 2026-11-07, starting with durable
attempts and supervised recovery. It records future work; it does not
implement these tasks or authorize system-administration commands.
The original [first-release contract](../docs/specs/2026-10-31-first-release-contract.md),
[storage and execution design](../docs/specs/2026-10-31-first-release-storage-and-execution.md)
and [A1-A12 acceptance scenarios](../docs/specs/2026-10-31-first-release-acceptance.md)
remain authoritative. This expands the unfinished execution sequence in
the [command/application plan](2026-11-02-manager-command-and-application-wave.md).

## Starting point and order

Recording, observation and comparison foundations are implemented. The
installed payload is staged; it has no application worker or apply verb.
Existing Sonarr proposals are permanently blocked, and Compose preflight
does not establish a full effective input bundle. See the
[current architecture](../ARCHITECTURE.md),
[proposal boundary](../docs/manager-effect-proposals.md) and
[helper boundary](../docs/manager-host-helper.md).

Start with `persist-attempt-journal`, then `supervise-attempt-workers`
and `recover-interrupted-attempts`. Journal-backed reporting and immutable
plan authorization can proceed after the journal interface lands.
`expose-execution-requests` joins those pieces before any concrete native
or Docker adapter becomes callable. Recording newer intent must preserve
old effects; it must not bypass an active worker or uncertain quiescence.

Independent input, verification, native preparation and file-publication
tasks may proceed alongside that sequence with disjoint ownership. The
queue's Ready/Waiting stages and dependency slugs control availability;
the order here is not permission to skip dependencies. New entries remain
Unprioritized; the first three tasks have the user's explicit sequencing
preference, not an invented urgency level.

## Ownership and delivery rules

- Each entry below is one bounded review scope and normally one draft
  PR. Its implementation, tests and behavior documentation stay together.
  If a scope proves too large, split it before claiming and retain every
  acceptance condition and dependency in the queue.
- Use one isolated worktree per author, a separate reviewer, at most
  four agents and two heavy runs. Authors fix findings; reviewers verify.
- The journal owner controls the first store/schema/migration interface.
  Plan and disposition schema changes follow serially; independent
  adapter authors do not edit the store concurrently.
- Shared CLI/protocol/status/payload edits have one integration owner at
  a time. Reporting lands its contract before execution requests;
  protected recording is coordinated with both. Adapter registration is
  serialized by that owner, not patched concurrently by every adapter.
- New module names are implementation choices. Starting points identify
  existing ownership and contracts rather than prescribing a second
  framework, generic action language or replacement native solver.
- Each PR runs Python 3.12 setup, `bash scripts/check.sh`, its focused
  regressions and independent review. Routine checks use owned temporary
  files/stores/processes and controlled native responses. No production
  package, account, service or Docker operations are validation steps.
- Installed/disposable system work, including diagnostics, requires the
  exact commands and any write contents to be shown and explicitly
  approved first. Acceptance tasks below retain that external blocker;
  past mechanism-run approval is not a new installation/run approval.
- A slice may be complete while release acceptance remains incomplete.
  Stubs, pure-library checks and the earlier
  [mechanism experiments](../docs/fixtures/2026-11-01-disposable-execution-evidence.md)
  never substitute for the actual native/Docker A1-A12 executions.
- Mark PRs ready only after their checks and independent review pass.
  Final review and landing remain with the user. No release publication,
  deployment, CI-policy or hook-policy change is authorized by this plan.

## Reviewable tasks

### persist-attempt-journal

**1. Persist durable attempts and action events.** Area: TOOLING.

**Prerequisites:** None; available for separate work.

**Ownership:** Own the next store schema, explicit migration, and a new
attempt-journal module; start with `mpkg_manager/store.py`,
`store_migration.py` and the storage design.

**Deliverable:** Add immutable attempt targets and append-only action events
with stable IDs, original decision/input/check bindings, trusted operator
and worker/boot identity, predecessor links, and separate
command/observation outcomes. Preserve planned, started, observed-complete,
failed, unverified and unknown states plus work not attempted. Define the
internal typed plan-reference contract for later authorization;
fixture-created records confer no execution authority. Keep production
attempt creation unavailable until the execution request boundary is wired.

**Acceptance:** Inject failures before start commit and after a simulated
effect; a start-commit failure permits no effect, while uncertain completion
retains the started record. Reopen stores, reject invalid
transitions/tampering, preserve history under newer intent, and test
migration backup/refusal and commit/cleanup uncertainty. Use temporary
stores and inert effects; no native adapter runs.

### supervise-attempt-workers

**2. Give attempts durable worker ownership.** Area: TOOLING.

**Prerequisites:** [`persist-attempt-journal`](#persist-attempt-journal)

**Ownership:** Own a fixed worker entrypoint, supervisor adapter and staged
worker payload; coordinate `packages/mpkg-manager/` with the
request-boundary owner.

**Deliverable:** Persist launch identity before dispatch and supervise a
fixed installed worker by attempt UUID. Use the selected systemd
service/cgroup semantics, one host application lock, bounded private child
output and no automatic restart. Close the launch/lock handoff race with a
durable reservation; recording and competing launches must respect it.
Reject requests for caller-selected commands, unit bodies, paths or
environment. Native/Docker execution remains unavailable in this slice.

**Acceptance:** Exercise launch failure, ambiguous launch response,
duplicate dispatch, competing workers, caller disconnect, child timeout and
secret-bearing errors with an owned worker and fake system-manager
transport. Verify lock lifetime and short database transactions. Record real
systemd/cgroup acceptance as outstanding until the installed-boundary task.

### recover-interrupted-attempts

**3. Recover uncertain attempts without overlapping work.** Area: TOOLING.

**Prerequisites:** [`supervise-attempt-workers`](#supervise-attempt-workers)

**Ownership:** Own recovery evidence and disposition logic plus the
unresolved-attempt gate; use the journal and supervisor APIs without
duplicating their storage.

**Deliverable:** Require evidence about unit/cgroup, boot identity, package
locking and affected engine/resources before resolving interrupted work. A
free advisory lock or dead worker alone never proves quiescence. Preserve
unknown effects and require a newly accepted plan/attempt for retries. Gate
every mutation that could overlap unresolved work, including authority
changes; allow explicit recording of newer intent only after
ownership/quiescence is established, preserving old attempt outcomes.

**Acceptance:** Simulate a live worker after caller death, continuing
child/daemon work after worker death, reboot, inaccessible observations,
corrupt/missing history and concurrent recovery. Assert no automatic lock
deletion, process killing, replay or success inference; unknown quiescence
blocks subsequent effects.

### report-attempt-outcomes

**4. Expose attempt history and partial outcomes in status.** Area: TOOLING.

**Prerequisites:** [`persist-attempt-journal`](#persist-attempt-journal)

**Ownership:** Own attempt projections and their CLI/status wire
integration; serialize edits to `cli.py`, `host_protocol.py`,
`host_helper.py` and `status_wire.py`.

**Deliverable:** Report exact historical targets,
completed/failed/unknown/not-attempted work, required checks and retry
ancestry independently of current intent and current file/service
observations. Keep reads non-mutating and redact private inputs,
paths/tokens and raw child errors. Paginate complete history explicitly
rather than silently truncating it.

**Acceptance:** Combine partial effects with newer intent and changed check
definitions, missing history, response bounds and concurrent journal writes.
Assert original attempts remain visible and status neither starts recovery
nor waits on the host application lock.

### authorize-execution-plans

**5. Bind accepted execution plans to exact authority and inputs.** Area:
TOOLING.

**Prerequisites:** [`persist-attempt-journal`](#persist-attempt-journal)

**Ownership:** Own execution-plan types and immutable persistence;
coordinate schema changes after the journal. Start with `effect_plans.py`,
protected bindings and the plan/action protocol.

**Deliverable:** Derive a closed set of versioned effect descriptors through
trusted installed adapters, binding host, revisions, original
consumers/checks, artifacts, before-evidence, interruption and disposition.
Persist explicit acceptance and invalidate stale prerequisites at each
action boundary. Define adapter prepare/revalidate/execute/observe contracts
without accepting arbitrary action graphs. Existing blocked Sonarr proposals
remain immutable and never become executable by clearing flags; executable
plans are newly derived records.

**Acceptance:** Reject forged or cross-host plans, reordered dependencies,
missing checks, stale authority/inputs and unsupported effects. Prove
changed facts require new acceptance, no-op verification has no mutation,
and failed required checks stop later effects. Use inert adapters until
concrete integration tasks land.

### expose-execution-requests

**6. Connect bounded plan, apply and recover requests.** Area: TOOLING.

**Prerequisites:**
[`recover-interrupted-attempts`](#recover-interrupted-attempts),
[`report-attempt-outcomes`](#report-attempt-outcomes),
[`authorize-execution-plans`](#authorize-execution-plans)

**Ownership:** Own shared `cli.py`, `host_client.py`, `host_protocol.py`,
`host_helper.py` and staged payload changes for execution.

**Deliverable:** Add closed requests for preparing supported proposals,
accepting exact plan IDs, applying and recovering attempts through the fixed
installed boundary. Bind operator identity from the trusted launcher, never
request JSON. Dispatch only registered reviewed adapters; unsupported kinds
remain blocked. Return a durable attempt ID across caller disconnects.
Retain explicit scopes, interruption decisions and mutation-boundary
freshness checks.

**Acceptance:** Exercise malformed/oversized input, forged operator or plan
IDs, lost responses, repeated requests, concurrent record/apply,
authorization denial and output secrecy. Test the full boundary with inert
integrations; no root installation or live host operation is part of routine
checks.

### prepare-native-transactions

**7. Prepare coherent native package transactions without live changes.**
Area: NATIVE.

**Prerequisites:** None; available for separate work.

**Ownership:** Own native preparation and artifact manifests; start with
`scripts/proofs/native_proof.py`, the frozen fixture inventory and native
execution design.

**Deliverable:** Use native resolution against a stable copied installed
inventory and isolated sync metadata. Bind sources, signature policy,
complete artifacts, provider/replacement/removal choices, package reasons
and coordinated upgrade scope. Expose exact/unrestricted requests and
unavailable pins without weakening intent. Preparation never refreshes the
live database or installs dependencies.

**Acceptance:** Use controlled bridge responses to cover unstable
inventories, missing/signature-invalid artifacts, incompatible pins,
provider changes and widened upgrade scope. Preserve the selected libalpm
ABI/transaction proof as an explicit gate for real acceptance; mocks and
prior prepare-only proofs do not establish a committed transaction.

### apply-native-transactions

**8. Commit only an exactly accepted native transaction.** Area: NATIVE.

**Prerequisites:**
[`prepare-native-transactions`](#prepare-native-transactions),
[`expose-execution-requests`](#expose-execution-requests)

**Ownership:** Own the installed libalpm bridge and native effect adapter;
register it through the execution-boundary owner.

**Deliverable:** Acquire native transaction locking, reprepare only accepted
artifacts/removals, and compare the complete prepared transaction and
installed reasons with the accepted plan before commit. Journal reason
changes separately and retain independent selections. Preserve native
signatures/hooks, report partial effects and re-observe them; forbid hidden
refresh/download, forced dependency bypasses and orphan sweeps.

**Acceptance:** Reject ABI mismatch, new providers/replacements, inventory
drift and additional effects before commit. Inject transaction/hook/journal
failure and verify unknown/partial outcomes and overlap refusal. Real
exact-set commit, dependency resolution and coordinated upgrades must pass
the native acceptance task before release.

### prepare-aur-recipes

**9. Capture reviewed AUR recipes and their dependency inputs.** Area:
NATIVE.

**Prerequisites:** None; available for separate work.

**Ownership:** Own AUR source/recipe manifests and trust decisions; use
frozen fixture recipes and the AUR boundary specification.

**Deliverable:** Acquire pinned recipes and sources with explicit provenance
and trust. Read untrusted `.SRCINFO` without evaluating PKGBUILD, retain
recursive AUR inputs where required, and distinguish repository/provider
dependencies from build outputs. Preparation has no dependency-install side
effect.

**Acceptance:** Exercise mismatched recipe/metadata, unavailable sources,
recursive cycles, unknown provenance and poisoned startup environments.
Demonstrate that inspection cannot run PKGBUILD, sudo or package
installation; secret/raw tool output stays private.

### build-aur-artifacts

**10. Build accepted AUR sources under an isolated unprivileged identity.**
Area: NATIVE.

**Prerequisites:** [`prepare-aur-recipes`](#prepare-aur-recipes),
[`apply-native-transactions`](#apply-native-transactions),
[`expose-execution-requests`](#expose-execution-requests)

**Ownership:** Own the AUR build worker adapter and protected artifact
import; use the shared supervisor, not a second execution engine.

**Deliverable:** Represent missing build dependencies as explicit accepted
native effects before build. Run source verification, metadata regeneration
and makepkg only under the dedicated build identity with no sudo or
self-installation. Compare generated metadata before proceeding; bind output
hashes, package metadata and provenance into a new installation proposal. Do
not automatically remove build dependencies.

**Acceptance:** Test privilege/credential refusal, missing prerequisites,
changed generated metadata, interrupted build, unsafe artifact paths and
bounded output. Building does not authorize installation of previously
unknown output bytes; the native acceptance task must exercise a genuinely
missing AUR dependency.

### install-aur-artifacts

**11. Require separate acceptance of built AUR package artifacts.** Area:
NATIVE.

**Prerequisites:** [`build-aur-artifacts`](#build-aur-artifacts)

**Ownership:** Own AUR artifact acceptance and the handoff to the native
transaction adapter.

**Deliverable:** Present newly built artifact bytes, resulting versions and
trust separately from recipe acceptance. Import only authenticated protected
artifacts and install through exact native transaction revalidation. Unknown
foreign provenance stays unknown; missing or changed outputs require a new
proposal.

**Acceptance:** Reject substituted artifacts, wrong metadata/version and
reuse of recipe approval as install authority. Verify interrupted
build/install history and satisfied-intent repetition without needless
rebuild or reinstall.

### record-protected-inputs

**12. Record protected configuration through the installed boundary.** Area:
TOOLING.

**Prerequisites:** None; available for separate work.

**Ownership:** Own authenticated capture preparation/consumption requests;
start with `protected_capture.py`, `protected_bindings.py` and the currently
unsupported protected recording path.

**Deliverable:** Expose bounded preparation and recording of policy-approved
protected inputs without accepting caller bytes as trusted captures. Bind
exact declarations, source identities, classifications and store revisions;
preserve capture-to-record freshness and original accepted checks. No
application or secret-bearing public response is added.

**Acceptance:** Test stale preparation, substitution, replay/cross-host
references, changed policy/source, interrupted recording and secret
sentinels in responses/errors/history. Adopt without effects and do not
invent missing legacy baselines.

### render-compose-execution-bundles

**13. Render a complete authenticated Compose input bundle.** Area: DOCKER.

**Prerequisites:** [`record-protected-inputs`](#record-protected-inputs)

**Ownership:** Own captured Compose closure and isolated rendering; extend
`compose_inputs.py` without mixing lifecycle execution into the parser.

**Deliverable:** Bind the selected fixture input syntax and tested Compose
version/schema, ordered sources, effective interpolation, base paths and all
referenced captures. Add the bounded YAML parsing needed by the actual
fixture explicitly; reject unsupported includes/builds/providers/hooks
before tool invocation. Preserve dollar/precedence semantics, durable bind
backing paths and exact native effective resources with no inherited
environment or implicit discovery.

**Acceptance:** Cover multiple sources, env precedence, dollars, secret
references, escaped paths, surplus/missing captures and stale inputs.
Compare fixed renderer fixtures locally; verify real pinned Compose
rendering in Docker acceptance. Existing JSON-only preflight cannot be
counted as complete YAML/effective input coverage.

### prepare-compose-images

**14. Bind explicitly acquired Docker images to digest and platform.** Area:
DOCKER.

**Prerequisites:**
[`render-compose-execution-bundles`](#render-compose-execution-bundles)

**Ownership:** Own image preparation and immutable deployment artifact
identities.

**Deliverable:** Resolve/acquire image content only through explicit
preparation or update scope, bind engine, digest/platform and complete
prospective deployment, and retain accepted content for configuration-only
work. Refuse missing pinned content rather than falling back to a tag.
Expose changed service/dependency scope before acceptance.

**Acceptance:** Test tag movement, platform mismatch, partial content, lost
acquisition responses and unrelated services. Status and configuration-only
proposals must not pull or update images; real image transition evidence
belongs to Docker acceptance.

### verify-container-application-health

**15. Verify the selected Sonarr and Radarr application predicates.** Area:
DOCKER.

**Prerequisites:** None; available for separate work.

**Ownership:** Own fixed version-bound application-check adapters; start
with endpoint attribution, retained check collection and the fixture
Sonarr/Radarr predicates.

**Deliverable:** Implement bounded Sonarr ping and authenticated Radarr
root-folder checks tied to original current/retained predicates. For bridge
networking, hold and verify the accepted container network namespace and
in-namespace listener before sending credentials; independently verify
published routes. Recheck runtime identity and keep functional results
distinct from HTTP reachability.

**Acceptance:** Use owned HTTP fixtures and synthetic engine/process
evidence for wrong listeners, container replacement, namespaces, stale
predicates, timeout, malformed responses and credential leakage. Never
create Radarr records as an observation; real application/namespace checks
remain Docker acceptance requirements.

### verify-native-application-health

**16. Verify the selected native service behavior.** Area: NATIVE.

**Prerequisites:** None; available for separate work.

**Ownership:** Own typed native application-check support; start with the
fixture OpenSSH verifier and native unit observation.

**Deliverable:** Bind the selected sshd configuration-validity and
authenticated loopback connection predicates to exact adopted context, with
bounded fixed operations and private credential delivery. Interpret systemd
service type correctly and distinguish active state from functional success;
do not expose arbitrary check commands.

**Acceptance:** Test wrong service identity, failed authentication, invalid
configuration, unavailable checks, cancellation and private output using
owned fixtures/stubs. Require a real isolated sshd connection during native
acceptance.

### verify-runtime-consumer-access

**17. Check access as the actual declared runtime consumer.** Area: TOOLING.

**Prerequisites:** None; available for separate work.

**Ownership:** Own runtime credential/namespace access evidence beyond
existing local-user read/list checks; start with `consumer_access.py` and
runtime attribution.

**Deliverable:** Bind real process/container credentials, supplementary
groups, capabilities, UID/GID maps and namespaces to accepted
consumer/resource identities. Perform only fixed bounded required operations
on declared fixture paths, including the selected shared-consumer predicate.
Unsupported access stays unavailable; mode bits, configured usernames and a
generic read are not substitutes for the required operation.

**Acceptance:** Cover identity/map/group changes, ancestor traversal denial,
namespace mismatch, changed targets, limits and retained consumers. Preserve
unprivileged local-user checks and prove private data does not escape. Real
container/native access evidence belongs to the acceptance tasks.

### publish-managed-file-content

**18. Publish authorized configuration bytes with safe file replacement.**
Area: TOOLING.

**Prerequisites:** None; available for separate work.

**Ownership:** Own a narrow trusted file-publication primitive, independent
of CLI and lifecycle adapters; start with capture/observation descriptor
handling and the file-write design.

**Deliverable:** Accept only trusted immutable candidate/input bindings from
an installed adapter. Require writer exclusion and fresh identity/content,
held parent descriptors, same-directory temporary files, preserved supported
metadata, content sync, replacement and directory sync. Refuse unsupported
alias/mount/ACL/xattr preservation; never imply rename excludes external
writers. The primitive alone grants no production apply authority.

**Acceptance:** Use owned temporary files to inject replacement races,
symlink/mount surprises, metadata changes and failures before/after
rename/sync. Preserve uncertain publication explicitly and prove failures do
not trigger automatic restart or rollback.

### apply-local-resource-properties

**19. Apply bounded local account and directory prerequisites.** Area:
NATIVE.

**Prerequisites:** [`expose-execution-requests`](#expose-execution-requests)

**Ownership:** Own closed account/membership and directory-property
adapters; reuse account and file observations.

**Deliverable:** Create explicitly authorized missing local identities, add
accepted memberships and change only declared directory properties through
separately journaled effects. Conflicting adopted numeric IDs or unresolved
external consumers block. Do not recursively rewrite ownership or delete
identities/directories; fixed operation scope must preserve unrelated state.

**Acceptance:** Test conflicting identities, stale NSS/metadata, shared
constraints, partial prerequisites, failure before durable start and
satisfied no-ops. All real account/directory operations are confined to
separately approved disposable acceptance.

### apply-native-service-configuration

**20. Apply the selected native configuration and service change.** Area:
NATIVE.

**Prerequisites:**
[`expose-execution-requests`](#expose-execution-requests),
[`verify-native-application-health`](#verify-native-application-health),
[`publish-managed-file-content`](#publish-managed-file-content),
[`apply-local-resource-properties`](#apply-local-resource-properties)

**Ownership:** Own the narrow sshd configuration adapter and fixed
service/startup-policy actions for the fixture.

**Deliverable:** Derive only supported native configuration changes,
preserve unrelated/private bytes, coordinate declared writers and publish
through the trusted file primitive. Journal configuration and service
operations separately, retain accepted package content, validate
configuration and verify the actual service outcome. Failure stops later
effects without fabricated rollback.

**Acceptance:** Inject a completed write followed by failed restart/check,
manual edits between plan and write, missing prerequisites, newer intent and
retry. Prove already-satisfied requests only verify. Real
partial-effect/recovery demonstrations belong to native acceptance.

### apply-sonarr-port-change

**21. Apply the accepted Sonarr port change to the same container.** Area:
DOCKER.

**Prerequisites:**
[`expose-execution-requests`](#expose-execution-requests),
[`render-compose-execution-bundles`](#render-compose-execution-bundles),
[`verify-container-application-health`](#verify-container-application-health),
[`verify-runtime-consumer-access`](#verify-runtime-consumer-access),
[`publish-managed-file-content`](#publish-managed-file-content)

**Ownership:** Own the Sonarr Port lifecycle adapter; reuse `sonarr_xml.py`
without promoting legacy blocked proposals.

**Deliverable:** Derive a new accepted plan, require a maintenance interval
excluding identified writers, stop the exact accepted container and verify
quiescence/restart policy. Re-read protected XML, publish only the supported
Port edit, then start that same container and verify
application/shared-consumer checks. Container replacement or input drift
requires new acceptance; no implicit recreation or image update.

**Acceptance:** Cover changed XML after stopping, unexpected
writers/restart, same-container identity loss, failed
publication/start/check and unknown daemon work. Verify no automatic restart
after failed write and no mutation for an already-satisfied verified target.

### apply-compose-recreation

**22. Apply an explicitly accepted Compose deployment change.** Area:
DOCKER.

**Prerequisites:**
[`expose-execution-requests`](#expose-execution-requests),
[`prepare-compose-images`](#prepare-compose-images),
[`verify-container-application-health`](#verify-container-application-health),
[`verify-runtime-consumer-access`](#verify-runtime-consumer-access),
[`apply-local-resource-properties`](#apply-local-resource-properties)

**Ownership:** Own the Compose deployment adapter and narrowly scoped
network/volume creation prerequisites.

**Deliverable:** Revalidate complete accepted resources and execute only
explicit engine/project/service/dependency scope with no implicit
pull/build. Keep accepted durable bind backing files, ordinary
project/external network and local-volume identities, and expose
interruption or recreation. Refuse unplanned affected resources and preserve
external consumers. Do not recreate matching deployments just to normalize
image references.

**Acceptance:** Test additional dependencies, changed engine/project,
missing images, shared/external objects, timeout with continuing daemon work
and failed postchecks. Real digest transition, network and volume behavior
is required in Docker acceptance.

### resolve-manual-configuration-drift

**23. Expose separate keep and restore decisions for manual edits.** Area:
TOOLING.

**Prerequisites:** [`record-protected-inputs`](#record-protected-inputs),
[`apply-native-service-configuration`](#apply-native-service-configuration),
[`apply-sonarr-port-change`](#apply-sonarr-port-change)

**Ownership:** Own bounded manual-drift decision requests and projections,
coordinating shared CLI/protocol edits.

**Deliverable:** Bind a keep decision to freshly observed bytes and record
them without restarting anything. Bind restore to the recorded input and
observed current target, then require a separate accepted application
through the native/Sonarr adapters. A second intervening edit invalidates
either decision; other pending work remains visible.

**Acceptance:** Exercise keep and restore independently for both native and
Docker configuration, changed content after decision, protected inputs,
unavailable observations and failed restoration. Assert status/keep never
invoke lifecycle effects.

### compare-package-file-baselines

**24. Explain package-supplied files and local configuration differences.**
Area: NATIVE.

**Prerequisites:** None; available for separate work.

**Ownership:** Own package-file baseline evidence and its bounded
accountability integration; start with `file_accountability.py` and accepted
package artifacts.

**Deliverable:** Distinguish authenticated supplied bytes, deliberate
configuration, expected runtime variation, unexplained additions/changes and
explicit unknowns. Keep configuration nested in runtime-data directories
visible and preserve scope/exclusion limits. Ownership alone or a clean
lostfiles report cannot establish agreement.

**Acceptance:** Use frozen artifact/inventory fixtures with unexpected
files, changed package-owned configuration, unreadable/unscanned paths,
changed package identity and runtime data. Restore access and verify newly
observed differences enter the report; never claim unavailable baselines as
clean.

### record-retirement-dispositions

**25. Require a fresh scoped data decision for every retirement.** Area:
TOOLING.

**Prerequisites:** [`authorize-execution-plans`](#authorize-execution-plans)

**Ownership:** Own disposition schema/migration and retirement plan
derivation; coordinate store changes and use retained consumer/authority
history.

**Deliverable:** Record fresh per-retirement keep/delete choices against
exact workload, data, path/mount/volume identities and current consumers.
Include empty or incomplete inventories explicitly. Declaration removal and
relinquishment do not authorize retirement; prior choices never answer a
later retirement. Preserve unfinished dispositions across new intent and
partial failures.

**Acceptance:** Test repeated retirements, changed inventory/consumers,
no-data and incomplete scans, lost responses, missing history and protected
shared resources. Verify choices cannot exceed accepted authority or
authorize unresolved deletion.

### retire-workloads-with-retained-data

**26. Stop and retire workloads while preserving usable retained data.**
Area: TOOLING.

**Prerequisites:**
[`record-retirement-dispositions`](#record-retirement-dispositions),
[`apply-native-service-configuration`](#apply-native-service-configuration),
[`apply-compose-recreation`](#apply-compose-recreation),
[`verify-runtime-consumer-access`](#verify-runtime-consumer-access)

**Ownership:** Own retention-oriented retirement orchestration using
reviewed native/Docker adapters; no recursive deletion in this task.

**Deliverable:** Disable only accepted startup/restart behavior, stop and
verify all identified writers including stopped container instances, then
remove only authorized workload resources. Preserve external/shared
networks, volumes, independent packages and identities. Give retained data
its own purpose, consumers and access requirements without keeping the
retired application wanted.

**Acceptance:** Test failed/incomplete stop, remaining users, auto-restart,
retained named volumes and bind data, lost responses and required access
failure. Repeated status/apply must not reinstall/restart the retired
workload; no blanket down --volumes or orphan sweep.

### delete-exclusive-retirement-data

**27. Delete only freshly authorized exclusive retirement data.** Area:
TOOLING.

**Prerequisites:**
[`retire-workloads-with-retained-data`](#retire-workloads-with-retained-data)

**Ownership:** Own bounded local-data deletion and separately journaled
native engine volume/network removals; reuse disposition and stopped-writer
evidence.

**Deliverable:** Require complete bounded inventory, fresh exclusive
ownership/consumer checks and verified stopped writers before deletion. Hold
root descriptors, recheck descendants/path/mount identities during
traversal, and stop on new or unvisited scope. Remove named volumes through
the engine, never its backing directory. Preserve partial deletion and
outstanding disposition on failure; shared media paths are never inferred as
deletion scope.

**Acceptance:** Exercise symlink/mount swaps, new descendants, aliases,
shared/stopped consumers, failed stopping, partial traversal/deletion and
volume-reference races. Keep local traversal and engine adapters
independently testable; real keep/delete cases remain separate acceptance
runs.

### export-and-recover-host-history

**28. Export complete redacted history and recover from verified backups.**
Area: TOOLING.

**Prerequisites:**
[`recover-interrupted-attempts`](#recover-interrupted-attempts),
[`record-retirement-dispositions`](#record-retirement-dispositions)

**Ownership:** Own complete history export and explicit backup/restore
maintenance interfaces; extend existing migration backup verification.

**Deliverable:** Export all nonsecret decisions, snapshots, attempts/actions
and dispositions without expiry or private tokens. Define and verify a
SQLite-consistent private backup inventory including host key/policy and
required artifacts; off-host encryption is an explicit operator
prerequisite. Restore under exclusive maintenance, preserve unknown external
outcomes and require re-observation/recovery before new effects. Application
data backups remain separate.

**Acceptance:** Test pagination/completeness, secret sentinels, incomplete
or corrupt backups, wrong host/key/policy, missing artifacts and effects
newer than the restored store. Restored history must never imply
packages/data/containers were rolled back.

### validate-installed-execution-boundary

**29. Validate the installed privilege and worker boundary in a disposable
guest.** Area: TOOLING.

**Prerequisites:**
[`expose-execution-requests`](#expose-execution-requests),
[`record-protected-inputs`](#record-protected-inputs),
[`export-and-recover-host-history`](#export-and-recover-host-history)

**External blocker:** explicit approval of exact system commands, write
contents and disposable target, plus verified fixture/tool prerequisites.

**Ownership:** Own repeatable installed-helper/worker acceptance tooling and
evidence; coordinate staged payload owners.

**Deliverable:** Prepare exact disposable-guest installation and diagnostic
commands for approval, then verify fixed trusted imports/paths, operator
identity, interactive authorization, systemd service/cgroup behavior, lock
provisioning and read-only denial. Kill caller and worker independently,
verify launch reservations and inspect terminal/journal/error/export
channels for fixture-secret leakage. Never install onto the production host.

**Acceptance:** Before execution, record the exact approved target/commands
and fixture revision. Require real installed systemd/sudo/process evidence,
including continuing work after disconnect, not transport mocks. Missing
approval or prerequisites keeps this acceptance task Waiting and its result
unverified.

### accept-recording-and-accountability

**30. Run first-release adoption and accountability scenarios.** Area:
TOOLING.

**Prerequisites:**
[`validate-installed-execution-boundary`](#validate-installed-execution-boundary),
[`record-protected-inputs`](#record-protected-inputs),
[`render-compose-execution-bundles`](#render-compose-execution-bundles),
[`compare-package-file-baselines`](#compare-package-file-baselines),
[`verify-container-application-health`](#verify-container-application-health),
[`verify-native-application-health`](#verify-native-application-health),
[`verify-runtime-consumer-access`](#verify-runtime-consumer-access)

**External blocker:** explicit approval of exact system commands, write
contents and disposable target, plus verified fixture/tool prerequisites.

**Ownership:** Own disposable A1-A3 evidence and independent before/after
observations for native and Docker fixtures.

**Deliverable:** Demonstrate non-disruptive adoption with no application
attempt, durable responsibility after uncommitted intent disappears,
explicit relinquishment/disposition and bounded file accountability.
Preserve independent requests, original checks and unmanaged consumers.
Freeze actual fixture inputs and starting states. Bind the complete captured
Compose input closure and compare its effective model with the observed
engine/project, containers and mounts before claiming verified adoption.

**Acceptance:** Require actual native/Docker state and functionality
before/after recording, plus unexpected files, nested configuration edits
and unreadable/unscanned scope. Capture implementation revision, restore
point, commands, results and limitations. No synthetic run counts as an
acceptance pass.

### accept-native-execution

**31. Run native package, configuration and recovery acceptance.** Area:
NATIVE.

**Prerequisites:**
[`validate-installed-execution-boundary`](#validate-installed-execution-boundary),
[`install-aur-artifacts`](#install-aur-artifacts),
[`apply-native-service-configuration`](#apply-native-service-configuration),
[`resolve-manual-configuration-drift`](#resolve-manual-configuration-drift),
[`report-attempt-outcomes`](#report-attempt-outcomes)

**External blocker:** explicit approval of exact system commands, write
contents and disposable target, plus verified fixture/tool prerequisites.

**Ownership:** Own the native side of A4-A9 and applicable A12 evidence in
the approved disposable guest.

**Deliverable:** Demonstrate repository and AUR additions each with their
own initially missing dependency, exact/coherent native transaction commits,
supported/incompatible pins and explicit updates. Exercise native config
keep/restore, real effects before failure, newer intent, caller/worker
death, continued native work, recovery and satisfied retries.

**Acceptance:** Record actual libalpm/tool outcomes and independent
package/reason/service/configuration observations. Inject pre-start journal
failure and post-effect completion loss. Preserve package hooks and prove no
overlapping retry; earlier prepare-only experiments and stubs do not pass
these gates.

### accept-docker-execution

**32. Run Docker configuration, update and recovery acceptance.** Area:
DOCKER.

**Prerequisites:**
[`validate-installed-execution-boundary`](#validate-installed-execution-boundary),
[`apply-sonarr-port-change`](#apply-sonarr-port-change),
[`apply-compose-recreation`](#apply-compose-recreation),
[`resolve-manual-configuration-drift`](#resolve-manual-configuration-drift),
[`report-attempt-outcomes`](#report-attempt-outcomes)

**External blocker:** explicit approval of exact system commands, write
contents and disposable target, plus verified fixture/tool prerequisites.

**Ownership:** Own the Docker side of A4-A9 and applicable A12 evidence in
the approved disposable guest.

**Deliverable:** Demonstrate the useful Sonarr change with the same
container when appropriate, effective captured inputs, protected
configuration keep/restore, explicit digest/platform update and unmanaged
Radarr consumer checks. Inject partial effects, worker death and continuing
daemon operations; retry only after evidence-backed recovery.

**Acceptance:** Verify actual container/image/network/mount identities and
functional/credential/access results across named restore points. Show drift
invalidates accepted plans, configuration-only work does not pull/recreate,
and satisfied work performs no unnecessary mutation.

### accept-retirement-and-release

**33. Verify retirement and reconcile every first-release acceptance gate.**
Area: TOOLING.

**Prerequisites:**
[`accept-recording-and-accountability`](#accept-recording-and-accountability),
[`accept-native-execution`](#accept-native-execution),
[`accept-docker-execution`](#accept-docker-execution),
[`delete-exclusive-retirement-data`](#delete-exclusive-retirement-data),
[`export-and-recover-host-history`](#export-and-recover-host-history)

**External blocker:** explicit approval of exact system commands, write
contents and disposable target, plus verified fixture/tool prerequisites.

**Ownership:** Own A10-A11, remaining cross-cutting A12 checks and the final
A1-A12 evidence index.

**Deliverable:** Run independent native and Docker keep/delete retirements,
including bind data, named volumes, shared unmanaged consumers and failure
cases. Verify retained access without a running workload, fresh
per-retirement decisions, complete stopping and partial deletion reporting.
Reconcile every original acceptance condition and unresolved review finding;
this task records readiness and does not publish or land a release.

**Acceptance:** Require real repeatable runs with exact
implementation/fixture identities, independent observers, approved commands
and explicit limits. Missing tests, unsupported scope, unverified outcomes
or unresolved correctness findings keep the release incomplete; no remainder
task waives an original criterion.

## Release coverage

| Original gate | Accountable execution/evidence scope |
| --- | --- |
| A1-A2: adoption and durable responsibility | Protected recording, retained history, retirement dispositions; `accept-recording-and-accountability` |
| A3: accountability and limits | Package file baselines plus existing bounded scanner; `accept-recording-and-accountability` |
| A4: real application and no-op verification | Native/AUR and Sonarr/Compose adapters; `accept-native-execution`, `accept-docker-execution` |
| A5: authority, consumers and freshness | Execution plans, authenticated inputs, runtime/access checks and every mutation boundary; native/Docker acceptance |
| A6-A7: partial effects, caller/worker loss and uncertain recovery | Journal, supervisor, recovery and attempt reporting; installed-boundary and independent native/Docker executions |
| A8: manual keep/restore | Protected recording and manual-drift decisions with native/Docker configuration adapters; both acceptance tracks |
| A9: versions and explicit updates | Native preparation/commit, separate AUR artifact acceptance and explicit image preparation/recreation; both acceptance tracks |
| A10-A11: retained/deleted data and incomplete retirement | Fresh dispositions, retained-data retirement and exclusive deletion; `accept-retirement-and-release` |
| A12: inspection, privilege and secrets | Installed boundary, all adapter error paths, complete redacted history and restored-state uncertainty; all acceptance tracks and final reconciliation |

The task list preserves repository/AUR installation, native configuration,
shared consumers, ordinary volume/network variants and accountable data
within the first release. Later whole-server coverage, replacement-host
recreation, reusable application knowledge and the Codeman stretch case
remain in their existing planning entries. Package visualization ideas
are independent of this execution sequence and retain their triage state.
