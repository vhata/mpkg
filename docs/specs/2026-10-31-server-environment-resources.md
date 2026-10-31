# Server environment: minimum resource model

This proposal develops the selected
[architecture direction](2026-10-31-server-environment-architecture.md)
for [milestone 1](../../plans/2026-10-31-server-environment-milestones.md).
It defines the information and behavior we need, not a file format,
class hierarchy, plugin protocol, or implementation.

The [first-release contract](2026-10-31-first-release-contract.md)
now proposes the supported facts, authority, verification, history and
update policies. It adds explicit Compose-network accountability to the
minimum inventory below. Its
[acceptance scenarios](2026-10-31-first-release-acceptance.md) retain the
required demonstrations and identify missing fixture evidence.

## Keep the model small

A **component** explains why software and supporting resources belong
on the server: a software collection or an application. It has a name,
a purpose, and references to the resources it uses. It is not an ordered
script or a general workflow definition.

A **resource** identifies something concrete on the host. Several
components can reference one resource. Adding another reference does
not create a second copy or grant another component exclusive control.
Use straightforward integrations for the supported kinds; do not build
a general automation language or framework to describe their operations.

For milestone 1, use a conventional Compose application to exercise the
Docker resources. Codeman's apparent source/build layout is a stretch
case; do not add generic checkout, build, or installer machinery solely
to accommodate it now. Resources beyond supported management can still
be accounted for, with inspection limits made explicit. Native AUR
building and ordinary shared-resource, permission, and data handling
remain first-release requirements.

## Proposed resource kinds

| Resource | Identity on this host | Intended facts it can describe |
| --- | --- | --- |
| Native package | Installed package name | Whether it is wanted, source and supported version requirements, and independent reasons to retain it |
| Docker deployment | Local Docker engine and stable deployment identity, including the Compose project name where used | Deployment inputs, desired running state, version requirements, and resource references |
| Docker volume | Local Docker engine and volume name | Purpose, consumers, and the keep-or-delete decision on retirement; its contents remain application data |
| Native service | System manager or a particular user's service manager, plus service name | Intended running/startup state and required configuration or resources |
| Service user | User name | Declared account properties and required memberships; existing numeric identity remains relevant when adopting |
| Group | Group name | Declared group properties and relationships to users and paths |
| Path | Absolute path | File, directory, or symlink; declared content or target where appropriate; ownership, permissions, purpose, and retention expectations |

Package requests that name a virtual capability or include a version
constraint are resolved by native package tooling. Keep the request
and observed provider distinguishable; they do not create duplicate
installed-package resources. Conflicting constraints must be visible.

A recreated container ID does not identify a new intended deployment.
A named volume is independently accounted for because it can outlive
its deployment; it is not treated as an ordinary host directory to edit
through filesystem operations. Bind-mounted host data uses path
resources instead. Existing data with an unresolved identity is a
discovery gap, not permission to replace or discard it.
A path's purpose, such as configuration, persistent data, or generated
output, is a property rather than a separate resource kind. A directory
resource describes the directory itself; its expected contents need
their own declared scope and rules.

## Information associated with a resource

- **Intent:** The facts the operator wants, including whether the
  resource should remain present and any supported constraints.
- **Responsibility and use:** Why it exists, which components or other
  resources require it, and any independent or external consumer.
- **Management authority:** Whether this tool may change it, which
  properties it manages, and what is merely inspected or referenced.
- **Observation:** What was checked, when, what was found, and what
  remains unknown. This is not automatically copied into intent.
- **History:** Explicit adoption or management decisions and attempted
  changes, including incomplete work and its actual observed effects.

These are related facts, not competing ownership labels. A directory
can be managed, shared, and retained at the same time. Git keeps intent;
host management history remembers adoption and attempts independently
of Git commits. The precise storage remains undecided.

## Authority and sharing

Referencing a resource grants no permission to change or delete it.
An adoption records the accepted management scope. Properties outside
that scope are observed or left alone, with limitations visible.
Conflicting requested values for a managed property stop the affected
change; one component must not silently win by being processed last.

An application can use an account, package, or directory that another
application or an external consumer still needs. Retirement removes
the retiring application's requirement, not those other reasons for
retaining the resource. Unknown use cannot be treated as proof of
exclusive ownership. A path holding retained data can itself require
an account or group after the application has gone.

For overlapping paths, a broad runtime-data expectation cannot erase a
specific configuration declaration or conflicting responsibility.
Declare the boundaries and exceptions. If path aliases or symlinks
make the affected scope uncertain, report that limitation before any
destructive action. Do not infer that managing a parent grants control
over every descendant.

## Recording and application

Recording intent changes no live managed resource. Explicit adoption
also records the accepted management baseline even if everything
already matches. Merely discovering a resource does not adopt it.

Application compares current intent, fresh observations, and management
history. It identifies changes and checks their prerequisites before
using the appropriate native operations. Native dependencies remain
the native tools' responsibility; resource references explain ordering,
shared use, and authority without introducing another package solver.

An application attempt records its target intent and operations as they
start and finish. If execution stops partway through, re-observe before
retrying. Missing completion evidence is not proof that nothing changed.
An unexplained manual configuration edit still requires the operator's
choice to keep it as intended configuration or restore the recorded
version through a separate apply.

For retirement, preserve the previous management baseline even when
the component's declaration is removed. Ask whether to keep or delete
its persistent data on every retirement. Retained paths keep their
purpose and required access resources; they do not keep the retired
application running or cause its reinstallation. Shared or unresolved
resources are not silently swept into a deletion.

## One concrete example

The [Sonarr evidence and worked example](2026-10-31-compose-deployment-evidence.md)
now grounds these relationships in inspected Compose files, identity
inputs and selected path metadata. It records observed facts separately
from proposed behavior and outstanding runtime/fixture evidence. The
generic example below remains illustrative.

Suppose an adopted `media` component runs a Docker application. It uses
the `compose` account, a managed configuration file, an application-data
directory, and a media directory also used by a known external consumer.
These are illustrative resources, not an inventory of the actual server.

1. Adoption records the deployment identity and management scope.
   Matching resources require no apply, but the adoption remains known.
2. Editing the desired configuration produces pending work without
   altering the running application.
3. Applying writes the intended configuration, then the deployment
   restart fails. Status shows the file now matches, the deployment
   outcome is incomplete, and which checks or operations remain.
4. A retry checks the current file and deployment rather than assuming
   the earlier operation had no effects.
5. On retirement, the operator chooses to keep application data. Its
   attribution and required account remain; shared media remains
   separately accounted for. The deployment is verified stopped.

Status therefore presents current agreement, outstanding work, and
attempt outcomes separately. It does not reduce the component to one
last exit code, and it distinguishes unknown state from verified state.

## Design checks before implementation

- Adopt without applying, then remove the uncommitted declaration:
  history still identifies the former managed resources for retirement.
- Have two components require different values for a shared property:
  surface the conflict before mutation.
- Put managed configuration inside a runtime-data directory: a direct
  edit remains detectable, while expected data changes remain expected.
- Fail after a configuration update but before a successful service
  restart: status and retry distinguish completed and outstanding work.
- Retire while retaining data and sharing an account with an unmanaged
  consumer: keep attribution and required access without recreating the
  retired application.
- Retain a Docker volume after retirement: it stays attributable without
  keeping or recreating the deployment that previously used it.

The first-release contract develops these checks into proposed behavior
and logical records. The [storage and execution design](2026-10-31-first-release-storage-and-execution.md)
selects concrete encoding, persistence and native boundaries, with
focused mechanism proofs and fixture evidence still required. No
general task language, framework dependency or repository plugin system
is introduced by those choices.
