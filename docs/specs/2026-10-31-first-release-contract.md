# First-release resource contract

This is the proposed behavioral contract for
[milestone 1](../../plans/2026-10-31-server-environment-milestones.md).
It refines the [resource model](2026-10-31-server-environment-resources.md)
and [architecture](2026-10-31-server-environment-architecture.md).
The [Sonarr evidence](2026-10-31-compose-deployment-evidence.md) supplies
the selected deployment's source facts and a worked resource lifecycle.
The [runtime baseline](2026-10-31-sonarr-runtime-baseline.md) adds dated
engine, image, mount, credential and bounded probe observations.
The [storage and execution design](2026-10-31-first-release-storage-and-execution.md)
proposes concrete encoding and native operation boundaries.
It describes future work. The existing `mpkg` helper does not implement
these behaviors, and this specification does not authorize implementation
or operations on a live server.

The choices below are a design proposal for review. The mandate's
confirmed requirements still govern; the closing section distinguishes
remaining integration evidence and implementation decisions. The
[acceptance scenarios](2026-10-31-first-release-acceptance.md) define how
to challenge this contract without treating a paper example as proof.

## 1. Supported boundary

The first release manages a bounded selection on one Arch Linux host:
repository and AUR packages, system services, local accounts and groups,
paths, and an existing Compose application on a local Docker engine.
It uses native tools and their dependency/lifecycle semantics. There is
no user-defined task language, arbitrary execution recipe, scheduler,
or background reconciliation loop.

A component names a purpose and references resources. Resource identity
is host-local; a reference never grants management authority. Keep the
operator's package request distinct from the installed package/provider.

| Kind and identity | Initially managed facts | Required observation and success evidence |
| --- | --- | --- |
| Native package: installed name on the host | Requested presence/source, supported version intent, independent retention reasons | Installed name, version, reason, resolved provider, transaction outcome; source provenance when known, otherwise unknown |
| Compose deployment: accepted local engine and explicit project name | Ordered deployment inputs, enabled profiles/services, image intent, desired running/stopped state | Inventory including stopped containers, effective nonsecret configuration, resolved image identity/platform, mounts/networks, declared service and application checks |
| Docker volume: engine and volume name | Purpose, consumers, retention and authorized removal | Volume identity/driver, declared and observed consumers, access checks through its application; data is not a host path to rewrite |
| Docker network: engine and network name | Purpose, consumers, reference or deployment lifecycle authority | Effective Compose mapping, observed instance identity and endpoints; shared, external, or uncertain networks are retained |
| Native service: system systemd manager and unit name | Running/stopped and supported enablement state, references to configuration and identities | Relevant unit properties, actual process/service state and a declared functional check; unit types require appropriate checks |
| Local user: account name | Create a missing service account; declared home, shell, primary group and required supplementary memberships | Local account properties and resolved numeric identity; adopted UID changes are unsupported |
| Local group: group name | Create a missing group and satisfy declared membership requirements | Local group properties and numeric identity; adopted GID changes are unsupported |
| Path: absolute host path | Regular-file content, directory existence, symlink target, supported ownership and permission properties, purpose and retention | Type, identity, contents/target where declared, owner/group/mode and required access; directory contents have a separate inspection scope |

Required supplementary memberships are additive; unlisted memberships
are not automatically removed. Account/group deletion and numeric-ID
changes are outside the initial mutator scope. They remain attributable
retained resources after retirement, not unexplained leftovers. User
systemd managers, remote Docker engines, Swarm, application source/build
orchestration and arbitrary volume/network drivers are not initially
managed. Native AUR building remains required.

Unsupported properties, including ACLs or other access controls that
affect a required outcome, remain explicit inspection/management gaps.
They cannot be counted as satisfied by checking mode bits alone. If the
chosen deployment requires unsupported behavior, choose a supported
representative example or revise this contract before implementation;
do not silently exclude a required milestone outcome.

Compose networks extend the earlier minimum inventory because teardown
can remove them. Initial support covers an inspected application's
ordinary local networks; it does not introduce general host networking
management. Any creation/removal performed indirectly by Compose is
still part of the proposed effects and authority check.

## 2. Intent, adoption and authority

An intent revision describes components, resource references, desired
facts, authority per property, version requests, expected runtime-file
rules and required verification checks. It includes the actual
uncommitted input contents, not only a Git commit ID. Syntax and storage
encoding remain separate implementation decisions.

Each accepted resource record contains its stable identity, purpose,
known consumers, independent retention reasons, managed properties,
external/reference-only properties and unresolved questions. Resource
relationships and Unix ownership are separate facts.

Adoption is an explicit recording operation. It records that accepted
baseline in durable host history without installing, restarting,
changing package installation reasons, permissions or live files. It
does not manufacture an application attempt. Discovery alone cannot
adopt a resource, grant authority, or turn observed versions into pins.
An unavailable observation is recorded as unknown; adopting a known
scope is not a claim that all properties were verified.

When two components reference the same identity, combine their
requirements. Conflicting desired values for one property block the
affected plan; processing order cannot select a winner. Reference-only
use cannot be promoted to management by applying another component.

For shared resources, the plan identifies each affected property and
known consumer, including consumers outside management. A change needs
an explicit grant for that property and checks covering the known
effects on those consumers. An authority change is itself a deliberate
recording decision. Unknown use is never evidence of exclusive use.
Unresolved destructive impact blocks removal; unresolved required
verification prevents a successful outcome.

Directory authority applies to the directory itself. Descendants,
overlapping declarations, aliases, symlinks and mount boundaries must
be resolved separately before a write or deletion. No blanket recursive
ownership change follows from creating or adopting a directory.

Removing a declaration preserves its adopted baseline and presents a
pending disposition. The operator explicitly chooses retirement or
relinquishing management. Relinquishment records external responsibility
and leaves resources running/present; it is not a retirement. Temporary
stopping keeps the component and its resource requirements active.

## 3. Observation and status

Observation reads package, account, service, Docker and filesystem
state. It does not install inspection dependencies, refresh package
databases, pull images, restart services, adopt discoveries, or edit
intent. Missing tools, privilege, baselines or input files produce
specific unknowns. Status does not require a Git commit or an apply.

Every result reports the inspected host/resource, properties and path
scope, observation time, evidence source and limitations. A filesystem
scan declares its roots, mount/symlink policy, exclusions and any scan
limit or unreadable paths. Excluded or unvisited scope remains unchecked.
Concurrent runtime changes mean observations are time-bounded evidence,
not an atomic snapshot of the whole host.

Status presents separate, coexisting facts:

- Current agreement or difference for each inspected property.
- Pending actions from current intent, including required decisions.
- Unexplained differences and possible manual configuration changes.
- Each relevant attempt's target, completed/failed/not-attempted work,
  verification and unresolved or interrupted actions.
- Unknown or stale evidence and resources outside the inspected scope.

Do not infer who changed a file from its difference. A previous attempt
explains known effects, but is not a current observation. New intent
does not overwrite that attempt's target or erase its unresolved work.
The display can say that the current file matches while the earlier
restart failed and the current service state is unverified.

File accountability combines native ownership, an available baseline
for the installed package version, deliberate configuration, and narrow
runtime rules. Keep the package-supplied baseline distinct from the
operator's intended bytes. Package ownership alone proves neither
unchanged content nor intentional customization. Missing baselines
remain unknown. Report relevant `.pacnew`/`.pacsave` files separately.

A runtime rule states responsible component, root, permitted path/type
patterns and expected variation, with explicit exceptions for managed
configuration. Unmatched files stay unexplained. Runtime data need not
be copied or individually versioned; a broad directory label cannot
hide a declared configuration file or unsupported inspection scope.

## 4. Plan, apply and verify

Recording intent and preparing a description of effects are separate
from application. A plan binds the host, exact nonsecret intent/input
revision, adopted baseline revision, selected components, resolved
inputs, required authority, prerequisites, expected effects, known
consumer impact, interruption and data decisions, and verification.
An unresolved prerequisite is a visible block, not an executable plan.

Application is an explicit request for that scope. It acquires one
host-wide application lock for this tool and rechecks relevant live
state, inputs and authority before each mutating boundary. A material
change invalidates the affected plan and requires a revised explicit
application request. External tools are not controlled by this lock.

Use a bounded sequence of native operations with prerequisite edges;
native tools still solve package dependencies and Compose relationships.
First-release policy is to stop subsequent mutating work after any
action or required verification fails. Independent completed work stays
recorded; no automatic cross-resource rollback is promised. Post-failure
observation is allowed. A later request can plan still-needed work.

Durably record action start before invoking the tool. Record exit
status, structured/redacted errors and observed effects afterward.
An interrupted command without completion evidence has an unknown
outcome until re-observed. A native transaction or Compose invocation
can have partial effects internally; an action record must not invent
per-resource completion from a missing or nonzero exit status.

Retry observes the state already reached and uses the original attempt
as history, not as a command replay list. Repeating a satisfied request
verifies it without unnecessary writes, installation or restarts.
Reverting Git does not undo live effects or restore application data.
Before retrying, also establish whether an interrupted invocation is
still running: coordinator death need not stop its child or a daemon's
work. Do not overlap a new mutation with unresolved ongoing work. If
completion or quiescence cannot be established, report the block.

Success requires all planned effects and declared checks to pass. A
zero tool exit code is necessary command evidence, not service success.
Use concrete read-only checks selected during adoption: native service
properties, container state/health, a bounded local application probe,
and access/availability checks for affected known consumers. Each has
an expected result and timeout. An unsupported or unavailable required
check leaves the outcome unverified. Do not introduce arbitrary shell
check programs as a configuration language.

Service activity is interpreted by unit/service type. Compose's
running/healthy check alone does not establish application usefulness.
An already matching deployment must still pass its declared checks
before being described as verified. Status reports the precise checks
and their coverage, rather than an unqualified claim of host health.

## 5. Native packages and version intent

Collections preserve their named requests and purpose. Adopting
`vhata-cli`, for example, records its requested dependencies, not every
transitively installed package as an independent selection. Keep
pre-existing explicit reasons and external consumers. The eventual
representation may use metapackages, but acceptance does not require the
current CLI or PKGBUILD representation.

Use native resolution for constraints and virtual providers. Record
requested name/source separately from selected installed package names
and versions. A foreign package is not automatically an AUR package;
unknown provenance stays unknown until supplied or verified. Package
reason changes require an apply and must preserve independent reasons.
There is no sweep of every package absent from intent.

The initial version contract accepts:

| Source | Unrestricted choice | Exact choice |
| --- | --- | --- |
| Arch repositories | Accept a compatible installed version; install/update using a coherent native transaction when requested | Only an available artifact/version compatible with the selected coordinated package set; otherwise block |
| AUR | Accepted recipe/source and native dependency resolution; updates are explicit | Accepted recipe revision plus required resulting package version and available sources/artifacts; block when it cannot be reproduced or is incompatible |
| Docker image | An accepted image reference may resolve anew during install or an explicit update | Registry image digest and platform; tag text alone is not an immutable pin |

Version ranges and arbitrary portable constraint syntax are outside the
initial interface. Preserve unsupported imported constraints visibly
and block their application rather than dropping them. Native exact
pins remain conditional on compatibility and availability; the first
release must demonstrate a supported exact pin and honest rejection,
not promise arbitrary independent Arch downgrades.

Ordinary status never refreshes source metadata. Configuration-only
application keeps previously accepted resolved software content unless
the plan explicitly identifies and authorizes a necessary software
change. If required pinned/resolved artifacts are unavailable, block
instead of following a mutable tag or using another version.

An explicit update selects components and sources. Its proposed effects
include dependency/provider changes, package hooks and service
interruption where knowable. A wider coordinated Arch upgrade is a
separately exposed host-wide scope requiring acceptance; it cannot be
hidden inside a component update. Never use a refreshed package database
for an unsupported partial upgrade or treat `IgnorePkg` as proof of a
safe exact pin. Insufficient metadata makes effects unresolved.

Source acquisition and candidate preparation must be distinguishable
from observation and application. Where source refresh changes proposed
effects, present the revised plan before mutation. The native
integration must demonstrate this boundary with its selected tools;
this contract does not invent a replacement solver or assume every
transaction can be safely dry-run against the live package database.

AUR recipes are executable, reviewed inputs. Fetch/build as an
unprivileged build identity; dependency installation and final package
installation are explicit privileged effects. AUR handling must include
an initially missing dependency in real acceptance evidence. Do not
execute a PKGBUILD merely to discover whether it should be trusted.

There are no automatic update schedules in the first release. Allowing
updates in intent does not trigger acquisition or installation.

## 6. Compose inputs and privileges

Adoption binds the actual engine, explicit project name, ordered Compose
files/overrides, project directory, profiles, relevant interpolation
inputs, referenced files and resolved host paths. Preserve that identity
when declarations move. Validate the effective model against observed
containers/mounts; a basename or directory listing is insufficient.
Missing input closure prevents a fully verified adoption or application.

Record nonsecret input content and resolved image identities, including
platform, for each attempt. Keep secret values outside Git and ordinary
status/logs; declarations contain references and availability
requirements. Do not persist raw rendered Compose output or environment
dumps. An input change must invalidate a plan even when secret bytes
cannot be displayed: use protected comparison/version evidence. If such
evidence is unavailable, freshness is unknown and the plan cannot claim
to bind exact inputs. Raw secret hashes are not public identifiers.

The normal coordinator and recorder run unprivileged. Read-only checks
use only the privilege needed to inspect the selected facts; failure to
obtain it reports unknown. Apply requests privileged native operations
through a bounded boundary that validates resource identities, exact
effects and fresh prerequisites. Repository content cannot inject a
different privileged command. Storage of sensitive snapshots and
credentials needs access control separate from ordinary Git history.

Access to a rootful Docker socket is root-equivalent authority. Do not
grant Docker-group membership merely to make status work. The selected
deployment must explicitly identify the operator, build identity,
privileged executor and runtime service identities; these roles need
not be the same account. Choosing an executor/credential mechanism is
an implementation decision subject to these boundaries.

## 7. Manual edits and retirement

An unexplained live configuration edit blocks overwriting that file.
The operator chooses to keep its current bytes as intent, or to restore
the recorded bytes. Keeping is recording only; restoring becomes a
separate apply. Both choices bind the observed content so another edit
invalidates the decision. Other required changes can remain pending.

Every retirement presents persistent-data inventory and asks keep or
delete for that retirement, even after an earlier retirement of the
same component. A stored default cannot answer it. Report explicitly
when no persistent data was found and identify inspection gaps. A
removal of a declaration alone supplies no data disposition.

Shared, independently wanted, externally managed and unresolved
resources cannot be removed on the strength of one component retiring.
A deletion choice authorizes only the identified exclusively removable
data scope; it cannot override another consumer's requirement. New or
changed resources invalidate that scope. Inspect path identity, aliases,
mounts, volume references and known live consumers immediately before
deletion. Failure to establish a safe scope blocks that deletion.

First stop the intended workload and verify it cannot continue writing
the retiring data, including its managed restart/startup policy. Then
perform authorized data handling and verify it. Containers absent from
the running-only listing are not sufficient stopping evidence. Failed
stopping, failed deletion or missing checks leave retirement incomplete
or unverified. A subsequent apply must re-observe and retain the
unfinished disposition; it must not assume previous deletion completed.

Compose teardown can remove networks as well as containers. A blanket
`down --volumes` is not the retirement contract. Select operations that
preserve shared/external resources and approved retained data; targeted
container stopping/removal may be needed. Removing a named volume is a
separate authorized operation. Never edit its backing directory to
simulate removal. Anonymous/unresolved data identity is a blocker to
deletion and complete accountability, not disposable data by default.

Retained data receives its own continuing purpose, known consumers and
required access resources in intent/history. It does not retain a
running requirement on the retired application. Read/access checks must
establish it is usable by the declared remaining identity or consumer.
Account retention alone is insufficient evidence of accessibility.

## 8. History and recovery records

The logical records are independent of their eventual storage encoding:

| Record | Minimum retained information |
| --- | --- |
| Management decision | Host, monotonic revision, accepted resource identities/relationships/authority, adoption or relinquishment, purpose, unresolved scope, associated nonsecret input snapshot |
| Application attempt | Attempt ID, exact target and resolved inputs, management revision, selected effects and decisions, prerequisite observations, start/end state and verification results |
| Action | Stable ID within attempt, prerequisite IDs, start recorded durably, tool/integration and bounded effects, outcome/error, observations and uncertainty |
| Retirement disposition | Component/resource identities, keep/delete decision and its exact scope, retained access requirements, completed and outstanding effects |

First release retains all adoption decisions, attempt records and
nonsecret snapshots; there is no automatic expiry or truncation. Large
raw subprocess output is not the record: store bounded sanitized errors
and structured outcomes. Secret material is referenced or protected,
never included in ordinary exported history. Retention/backup of secret
inputs must be specified with the implementation, not achieved by
secret logging.

History survives uncommitted declaration removal, branch changes and
new intent. Journal failure before a mutation blocks it. A failure to
record a post-mutation result leaves an interrupted/unknown action that
the next inspection explains. Missing or corrupt history blocks unsafe
retirement/replay; rediscovery cannot silently reconstruct authority.
Recovery must explicitly reestablish management facts and unknowns.

## 9. Remaining design and evidence gates

This contract proposes the behavior; implementation remains gated on:

- Accept a complete current input bundle for the inspected Sonarr
  example and recheck it against live state at adoption. The runtime
  baseline supplies time-specific engine/project, image, mount,
  credential and bounded endpoint/root-access observations; it cannot
  reconstruct historical shell inputs or prove writes, descendant
  access and shared-consumer functionality. Raw secret-bearing inputs
  stay outside Git. Fresh fixture observations and full functional
  checks remain required before acceptance.
- A frozen disposable Arch fixture manifest with verified repository
  and AUR packages, a real missing dependency, native service/config
  checks and the selected Docker example. Candidate names are not
  acquisition evidence.
- The storage/execution proposal's focused mechanism proofs: journal
  durability and supervised recovery, exact native transaction
  revalidation, protected input replay, offline configuration edits
  and bounded retirement. These must substantiate the selected
  boundaries with actual tools before broader product implementation
  is authorized; paper design and source documentation are not passes.

The architecture remains direct native integration. These gates do not
reopen a framework comparison or move AUR handling, shared resources,
partial failure or accountable data beyond the first release.

## References

Tool facts inform the proposed policy; documentation is not evidence
that this product implements or has tested it.

- [Pacman manual](https://man.archlinux.org/man/pacman.8.en)
- [Arch coordinated upgrades](https://wiki.archlinux.org/title/System_maintenance#Partial_upgrades_are_unsupported)
- [Arch package builds](https://wiki.archlinux.org/title/Arch_User_Repository)
- [Compose project identity](https://docs.docker.com/compose/how-tos/project-name/)
- [Compose effective configuration](https://docs.docker.com/reference/cli/docker/compose/config/)
- [Compose container observation](https://docs.docker.com/reference/cli/docker/compose/ps/)
- [Compose application and waiting](https://docs.docker.com/reference/cli/docker/compose/up/)
- [Compose teardown](https://docs.docker.com/reference/cli/docker/compose/down/)
- [Docker daemon authority](https://docs.docker.com/engine/security/)
