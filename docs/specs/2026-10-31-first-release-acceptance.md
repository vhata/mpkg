# First-release acceptance scenarios

This plan tests the proposed
[resource contract](2026-10-31-first-release-contract.md) against every
[milestone-1 criterion](../../plans/2026-10-31-server-environment-milestones.md#1-first-useful-release-manage-an-existing-setup-end-to-end).
It is a demonstration design, not an execution report. No scenario has
been run and no passing product capability is claimed. Implementation
and disposable-environment execution require their own authorization.

## Fixture and evidence prerequisites

The [fixture design](2026-10-31-first-release-fixture.md) now binds an
official Arch ISO, one dated repository snapshot, complete native
package resolutions, Python 3.12 sources, pinned AUR recipes and
Sonarr/Radarr registry metadata. Its
[source inventory](../fixtures/2026-10-31-arch-native-inputs.json)
distinguishes published digests from verified downloaded metadata.
Archive/build verification, assembled input bundles and runtime checks
remain necessary before these scenarios are executable.

Use a disposable x86_64 Arch VM with a working systemd system manager,
independent console access, snapshots and a local Docker engine. Use
fixture-only data and credentials. Do not validate on the production
server. A normal container without the required host/service semantics
does not establish the native acceptance criteria.

Before executing, commit a nonsecret fixture manifest identifying:

- Arch installation image and checksum, architecture, repository
  snapshot/source, package database state, installed package inventory
  and versions, and relevant tool versions. The starting system must
  be coherently updated; record any unavailable historical inputs.
- Selected repository packages and hashes; AUR package base, reviewed
  recipe revision, source provenance/checksums, build/runtime dependency
  graph and built artifacts. Establish an initially missing repository
  package dependency and an initially missing build/runtime dependency
  of the selected AUR recipe before their application scenarios.
  Resolve recursive AUR dependencies with real evidence if the selected
  recipe needs them.
- Actual selected Compose definition provenance, ordered files,
  project name/directory, profiles, engine identity, resolved images
  and platforms, mounts, networks, volumes, identities and consumers.
  Distinguish configured users from measured application credentials,
  including supplementary groups, capabilities and namespace mappings.
  Record every adaptation made to run its shape with fixture data.
- Secret references and fixture credential delivery prerequisites,
  without values, rendered environment dumps or public secret hashes.
- Managed and unmanaged consumers, required functional/access checks,
  test paths, initial content/type/ownership/mode and relevant extra
  access controls. Identify a configuration file inside a runtime-data
  scope, and exclusive as well as shared persistent data.
- Named restore points, independent before/after observers, failure
  injection points, operation timeouts and the implementation revision
  under test. A result must be repeatable from its named restore point.

Freeze these inputs at execution time; current upstream metadata is a
candidate selection aid, not a promise that a rolling package source
will remain available. If a required source, check or environment
property is unavailable, mark the scenario blocked/unverified rather
than substituting a stub and counting it passed.

## Native example

The existing [vhata-cli collection](../../vhata-cli/PKGBUILD) provides
real request names and a purpose to preserve. Adoption must preserve
its exact selections without promoting every observed dependency or
version into independent intent. Its current text is evidence of
requests only; it is not an inventory of the server.

Use distinct restore points so adoption of a complete collection does
not conflict with the requirement to install something newly requested:

| Restore point | Starting condition and proposed evidence |
| --- | --- |
| Native adoption | All selected collection requests already satisfied; accepted service/configuration/data already present; capture provider and installation-reason facts separately |
| Native change | A fixture collection derived from those requests deliberately omits the additions; `tmux`, `ripgrep`, selected `gitstatus` and chosen missing dependencies are absent; remaining packages form a coherent system |
| Native retirement | Applied component has a real service, exclusive fixture data and a shared resource also used by an unmanaged consumer; independent retention reasons are recorded |

The frozen repository additions are `tmux` and `ripgrep`, both requested
by `vhata-cli`. Native resolution establishes `libutempter` as absent
from the change set and included by the applied set; `libevent` is
already a baseline dependency. Verify actual guest absence before
running the scenario. The selected AUR addition is `gitstatus`,
requested by [vhata-dev](../../vhata-dev/PKGBUILD), at the pinned recipe
in the fixture design. Its declared build prerequisites `cmake` and
`zsh` are absent from the resolved change set. Preserve those absences
until its real prerequisite-resolution operation.

Exact CLI adoption also needs AUR `ack` and `perl-file-next`. Their
recipes and source checksums are pinned. The fixture explicitly selects
a coherent ack revision preceding a HEAD whose PKGBUILD and metadata
disagree; it preserves the unrestricted collection request. Source
inspection is not evidence of a successful build. The `tmux` case
alone cannot satisfy the AUR dependency demonstration.

For a native service and package-owned configuration, `openssh` from
[vhata-system](../../vhata-system/PKGBUILD) supplies `sshd.service` and
`/etc/ssh/sshd_config`. In the disposable fixture only, use a dedicated
loopback test port and console access. Check configuration validity and
perform an actual authenticated local connection; service activity
alone is insufficient. A fixture SFTP user's test data can exercise
native persistent data and access. Declare these fixture-created
resources explicitly, with a separate unmanaged consumer of shared
data. Never treat these choices as observations of the user's server.

## Docker example prerequisite

Use Sonarr, selected after inspecting the six conventional applications'
actual Compose files and adjacent identity inputs. The
[evidence and resource walkthrough](2026-10-31-compose-deployment-evidence.md)
records nonsecret source facts, selected filesystem/configuration
observations and a proposed lifecycle. The
[runtime baseline](2026-10-31-sonarr-runtime-baseline.md) records actual
engine/project binding, local image identity/platform, mounts, process
credentials, Sonarr's HTTP 200/OK probe and credential-matched access to
the four applications' config/media roots. Those checks did not write
data, inspect descendants or exercise media workflows. Raw
secret-bearing inputs remain outside Git. Codeman is not the
first-release benchmark.

Reproduce the selected definition's relevant resource relationships in
the disposable VM with fixture data and credentials, then adopt that
already working deployment. Record differences from the supplied
definition, including paths and identities. Accept the complete current
input bundle and establish fixture engine/project identity and fresh
functional checks before calling it an executable scenario. Live
observations are inputs to that fixture, not its acceptance results.
A synthetic Compose application can add edge-case coverage;
it cannot replace this evidence-backed existing-deployment example.

Sonarr's declared relationships include configuration, runtime identity,
permissions, data and a media path also declared by Radarr, SABnzbd and
Plex. Their runtime attachments and root access are now observed;
establish functional shared-consumer checks and keep at least one such
consumer outside management in the fixture. The fixture design selects
an actual Radarr deployment with its own config and shared-media
operation; a synthetic process is insufficient for this variant.
Sonarr uses bind mounts and host networking; add supplemental fixtures for named volumes
and project networks. Preserve their retention coverage without claiming
those resources were observed in the existing deployment.

## Scenario matrix

Each scenario below specifies a starting point, action and pass/fail
oracle. Run the native and Docker variants where applicable. A missing
required variant prevents milestone completion.

| ID | Milestone criterion | Required variants |
| --- | --- | --- |
| A1 | 1. Adopt without disruption | Native collection/service; selected existing Compose deployment |
| A2 | 1, 7. Preserve adoption through declaration removal | Both; no prior application or Git commit |
| A3 | 2. Explain responsibility | Native package files and Docker/config/runtime paths |
| A4 | 3. Record separately, then apply | Repository and AUR additions, each with an initially missing dependency; Docker configuration |
| A5 | 3, 4. Shared authority and changing inputs | Both, including one unmanaged consumer |
| A6 | 4. Explain partial results and retry | Native and Docker failures after a real effect |
| A7 | 4. Recover uncertain attempts | Native and Docker interruption at a journal boundary |
| A8 | 5. Keep or restore manual changes | Native package-owned config and Docker application config; separate keep/restore runs |
| A9 | 6. Honor version intent and update scope | Native unrestricted, supported exact and incompatible/unavailable requests; Docker tag and digest |
| A10 | 7. Retire and retain data | Native data, Docker bind data and named volume; shared external consumer |
| A11 | 7. Retire and delete data | Native and Docker exclusive data; independent failed/incomplete cases |
| A12 | Cross-cutting: inspection, privilege and secrets | Both; denial, missing evidence and credential sentinels |

### A1: adopt without disruption

Start from the working adoption restore points. Capture package versions
and install reasons, service state/start evidence, container identities
and start times, configuration bytes, ownership/modes, data sentinels
and required functional checks. Record intent and explicitly adopt.

Pass only if those relevant live facts remain unchanged by recording,
no native or Docker mutating operation was issued, functional checks
still pass and the management baseline exists without an application
attempt. Incidental expected runtime data changes are compared under
their declared rules, not falsely required to be byte-identical.

### A2: remember adoption without applying

After A1, remove or replace the uncommitted declaration before any
apply. Status must still identify the formerly managed resources and
their accepted relationships separately from unrelated discoveries.
It must request a disposition and data decision instead of deleting
them. Exercise both retirement planning and explicit relinquishment;
relinquishment leaves the workload intact and records external use.

### A3: accountability and coverage

Introduce an unexpected file, modify a package-owned configuration,
and change expected runtime data. Put declared configuration within a
runtime-data directory. Make another scoped path unreadable and place a
file outside the chosen scan boundary.

Pass only if each in-scope item is classified with its supporting
evidence: supplied baseline, deliberate configuration, expected runtime
variation, unexplained difference or explicit unknown. Detect the
nested configuration change. Report unreadable/unscanned scope; do not
claim the out-of-scope file was inspected. Restore access and prove
newly observed differences enter the report. Ownership or a clean
`lostfiles` result alone cannot satisfy this oracle.

### A4: recording and real application

From the native-change restore point, record the chosen repository and
AUR additions. From the Docker restore point, record a useful
configuration change with a measurable application effect. Status and
recording must leave packages, services, configuration and containers
unchanged while describing pending work.

Apply the two changes separately. Capture actual native resolution,
AUR acquisition/build/installation and each initially missing dependency
becoming installed. Both the repository and AUR cases must demonstrate
their own prerequisite resolution; preinstalling the AUR recipe's
dependencies cannot satisfy that case. Show expected Docker
configuration and application behavior, plus shared-consumer checks.
No stubbed package or Docker
command counts as this evidence. Reapply satisfied intent: relevant
checks pass without needless rebuild, install, file rewrite or restart.

### A5: authority and fresh prerequisites

Give two components conflicting values for a shared property; require
the plan to identify the conflict before mutation. Separately reference
an external resource without granting management authority and attempt
to change it. Grant a bounded property explicitly, include the unmanaged
consumer's check, and demonstrate the accepted compatible change.

After planning, independently alter a relevant input or resource.
Application must detect the material change and require a revised
request before the affected mutation. Include a symlink/mount boundary
change before data deletion. Other consumers' requirements and unresolved
scope must not be overridden by the retiring component's data choice.

### A6: partial effects and newer intent

Write intended configuration, then force the subsequent native restart
or Docker application/verification to fail. Require evidence of at least
one real completed effect before failure. Status must show the exact
attempt target, completed action, error, work not attempted, current
file agreement and incomplete or unknown service outcome separately.

Record newer intent while that attempt remains incomplete. The old
effects and target must remain visible. Retry from fresh observation,
perform only still-needed authorized work and verify the new outcome.
Do not infer rollback from a failed exit code or reverted Git content.

### A7: interrupted action and journal failure

First terminate the initiating CLI while its durable attempt worker is
still running. The worker must continue owning the attempt and may
finish and durably record success; caller disconnection alone must not
invent an interrupted action or erase its result. Reconnecting status
must identify that same attempt and its actual outcome.

Separately terminate the durable worker after a real native/Docker
action takes effect but before its completion record is durable.
Restart inspection: the started action is uncertain, actual effects
are rediscovered and retry does not blindly replay it. Test this
independently for each integration; package transaction and Compose
failure surfaces differ. Include a case where the original child or
daemon operation continues after worker death; a new apply must wait
for verified completion or report a block rather than overlap it.

Separately deny durable recording before an action starts. No mutation
may begin. Remove/corrupt a copy of management history and verify that
the tool blocks unsafe retirement rather than guessing authority from
the live filesystem. Preserve the unaffected fixture history for reset.

### A8: resolve manual edits deliberately

In two fresh runs for each native/Docker configuration file, edit the
live file outside the tool. Status must report the difference without
overwriting anything. First keep those bytes as intent: recording alone
does not restart a service. Then, in the other run, choose restore:
nothing changes until a separate apply restores the intended bytes and
performs required service verification. A second intervening manual
edit must invalidate the first decision's content binding.

### A9: versions and explicit updates

Adopt unrestricted choices without generating pins from observed
versions. Demonstrate a supported exact native request against the
frozen coherent package set and a Docker digest/platform pin. Reject an
unavailable request and an incompatible native request without changing
their declared requirements or silently selecting another version.

Use the fixture's October 30 to October 31 coherent native sets and
bound Docker image transition in the isolated fixture. Status
and a configuration-only apply must not install/pull it merely because
updates are allowed. An explicit update records its resolved content
and verifies the selected change. If native installation/update needs
a wider coordinated system upgrade, show that scope and require its
acceptance; refusing leaves it unapplied. A missing required resolved
artifact must block, not fall back to a mutable image tag.

### A10: retain data after retirement

Retire from an applied restore point and choose keep for this attempt.
Verify workload stopping and the relevant restart/startup policy, then
verify retained data bytes/sentinels and access by the remaining declared
identity. Retained data, needed accounts/groups and independent package
reasons remain attributable without making the retired workload wanted.

Exercise bind data and a named volume, plus a shared directory or
network still used by an unmanaged consumer. That consumer's functional
check must pass after retirement. A new status/apply must not reinstall
or restart the retired component because its data or identity remains.

### A11: deletion and incomplete retirement

From a fresh restore point, require a fresh keep/delete decision and
choose deletion for identified exclusive data. An earlier choice must
not answer this retirement. Verify stopping before deletion, then
verify absence only for the approved scope. Shared/external/unresolved
data and known consumers must survive.

In separate runs, force stopping verification to fail, data deletion to
fail partway, and data identity/consumer inspection to be unavailable.
Report incomplete or unverified retirement and preserve its outstanding
disposition for a retry. Never mark success from an empty running-only
container listing. Unknown use cannot authorize deleting a volume or
Compose network. Cover an application with no discovered persistent
data and confirm the empty inventory and any observation gaps explicitly.

### A12: inspection limits, privilege and secrets

Deny access to a required observer, remove an inspection tool from the
fixture's tool environment, and withhold a required package baseline.
Status reports the precise unknowns without installing tools or making
live changes; no complete-success result is allowed for missing required
checks. Restore the prerequisite and require new evidence.

Use fixture credential sentinels in referenced files/interpolation and
fail a command that could echo them. Inspect Git changes, status,
ordinary attempt history and captured errors for leakage. Verify AUR
builds run unprivileged and that changing a repository-controlled input
cannot substitute an unrelated privileged operation. Docker observation
must not require adding a service account to the Docker group. Secret
freshness must be testable without exposing raw values or public hashes.

## Recording results and exit criteria

For each run retain fixture-manifest revision, product revision, restore
point, requested outcome, nonsecret before/after observations, native
operation evidence, attempt/action identities, functional-check results
and all inspection limits. Distinguish product assertions from independent
observations. Label every result passed, failed, blocked or unverified;
blank/missing evidence is not a pass.

Focused automated tests should exercise comparison, conflict detection,
record durability, interruption recovery and redaction. Real-tool
demonstrations above remain mandatory. The first release is complete
only when every milestone criterion and its applicable variants pass,
and independent review has no unresolved actionable findings.

Before this plan becomes an executable acceptance manifest, settle the
[remaining fixture gates](2026-10-31-first-release-fixture.md#gates-before-an-executable-manifest):
actual archive/build verification, assembled guest and accepted
Sonarr/Radarr inputs, supplemental resources and update candidates, and
exact probes/injection points bound to an implementation. Registry
metadata availability does not establish layer acquisition or runtime
compatibility. The runtime baseline does not establish historical input
provenance or replace fixture evidence. These remain explicit queue
work; no acceptance condition is waived by this document.

## Candidate-selection sources

Inspected on 2026-10-31; freeze exact inputs later rather than depending
on these rolling pages as a reproducible manifest.

- [tmux package metadata](https://archlinux.org/packages/extra/x86_64/tmux/)
- [ripgrep package metadata](https://archlinux.org/packages/extra/x86_64/ripgrep/)
- [OpenSSH package files](https://archlinux.org/packages/core/x86_64/openssh/files/)
- [Arch OpenSSH configuration](https://wiki.archlinux.org/title/OpenSSH)
- [Native package build behavior](https://man.archlinux.org/man/makepkg.8.en)
- [Compose project identity](https://docs.docker.com/compose/how-tos/project-name/)
- [Compose container observation](https://docs.docker.com/reference/cli/docker/compose/ps/)
- [Compose teardown effects](https://docs.docker.com/reference/cli/docker/compose/down/)
