# Server environment: mandate and requirements

This is a planning document recording the agreed product direction. It
does not describe implemented behavior or select an architecture.

## Mandate

Maintain a versioned description of an Arch Linux server's intended software
environment and its supporting resources, make that environment
reproducible, and expose anything that differs from or falls outside
that description.

The existing command API, file formats, and implementation are open to
replacement. The design starts from the outcomes below.

The [milestone plan](../../plans/2026-10-31-server-environment-milestones.md)
defines the first useful release and the outcomes to demonstrate.
The [architecture direction](2026-10-31-server-environment-architecture.md)
uses native tools directly. Its detailed resource model remains proposed.

## Supported host

Arch Linux is the only supported host operating system. Supporting
other host operating systems is outside the product's scope.

The requirements cover native Arch software and Docker applications
running on an Arch host. Container images do not have to be based on
Arch Linux; their base distributions do not expand the supported host
scope.

## Intended outcomes

- Express which software belongs on the server and why, including
  meaningful collections of software.
- Manage native software from Arch repositories and the AUR, as well as
  software deployed through Docker, within the same repository.
- Describe the configuration and supporting resources that make that
  software useful on this server.
- Keep deliberate choices and customizations understandable in Git.
- Record intended changes separately from applying them to the server.
- Provide a system status view that explains unapplied work, application
  attempts and failures, and the server's observed agreement with intent.
- Compare the actual server with the recorded intent, exposing both
  missing resources and unexplained additions or changes.
- Bring an existing server under management incrementally.
- Reestablish the intended software and configuration without having to
  rediscover the original setup decisions.
- Retire software with an understanding of shared resources and data
  that should remain.

## Software and its supporting resources

The scope includes installed software, containerized applications,
operational configuration, service users and groups, required
directories and permissions, and responsibility for application data
and generated files.

For example, a service account named `compose`, its home at `/opt/docker`,
and the access it needs can be part of the intended environment.
Resources shared by several applications must remain identifiable as
shared when any one application is removed.

Knowledge about setting up common applications should be reusable and
shareable. Local choices and customizations must remain visible.
Software without dedicated community support must still be manageable.
Whether this uses plugins or another mechanism remains undecided.

## Recording, applying, and status

Recording the intended setup and applying it are separate actions.
Recording alone does not install software, change live configuration,
restart services, or otherwise apply the declared changes. Inspecting
system status also does not apply changes.

System status must make the following distinguishable. These are
different facts that can coexist, not a mutually exclusive set of
labels or a prescribed interface.

| Information | What the operator needs to understand |
| --- | --- |
| Agreement with intent | What has been checked and currently matches the recorded setup |
| Unapplied changes | What still needs to change to reach the recorded setup |
| Application attempts | What was attempted, against which intended setup, and whether the attempt completed |
| Failures and partial results | What took effect, what failed and why, and what was not attempted |
| Drift | Differences from expected live state beyond known unapplied work, without assuming their cause |
| Uncertainty | What could not be checked or is no longer supported by a sufficiently current observation |

Status must keep current observations distinct from the outcome of an
earlier attempt. An old success does not prove current agreement, and
an old failure does not prove that the server still differs. Recording
new intent must not make an unfinished attempt's effects disappear from
view. The operator must be able to understand what remains to be done.

Recording an existing setup that already matches the intent may require
no application work. A changed repository alone does not prove pending
work, and a successful recording operation does not prove agreement.

The precise presentation and history retention remain open. This
requirement does not select commands, storage, background monitoring,
or an implementation for applying changes.

## File accountability

The goal is to account for files and changes across the server. In this
context, responsibility explains why a resource exists and what needs
it; Unix ownership and permissions are related but separate facts.

| Category | Required understanding |
| --- | --- |
| Files supplied by software | Which installed software supplies them |
| Deliberate configuration and custom files | What is intended and whether the current contents match |
| Persistent application data | Which application is responsible and what should survive its removal |
| Generated files, caches, logs, and temporary files | Why they are expected and where they belong |
| Unexplained files or changes | What needs attention |

Accountability does not require recording every changing file
individually. Expected changes within an application's data should be
distinguishable from configuration drift. Treating a directory as
unconditionally invisible would not establish accountability for it.

A clean `lostfiles` result alone is insufficient: its report concerns
pacman ownership and excludes some paths. A package-owned file can also
contain a local modification. The requirements therefore cover both
additional files and changes to supplied or declared files.

An observed difference does not establish who made it or whether it was
intentional. Deliberate customizations must be distinguishable from
changes whose intent has not been recorded.

Resources explicitly recognized as outside management must remain
distinguishable from resources that have never been accounted for.

## Version intent

Version requirements belong to individual software choices. The
operator can leave a version unrestricted or constrain it, including
pinning a particular version, where the software source and installation
method can honor that requirement. This is not one choice for the whole
server.

Recreating the environment should satisfy those requirements. An
unrestricted choice may resolve to a newer version; an exact pin must
not silently resolve to another version. Observing which version is
installed does not itself make that version a requirement.

Permitting a newer version and deciding when to install it are separate
decisions. Upgrade timing and automation remain open.

Arch's compatibility constraints must remain visible. Arch does not
support partial system upgrades, so independent native package pins
cannot be promised without regard to the rest of the installed system.
Unavailable or incompatible requirements must be reported rather than
silently weakened. The supported forms of constraints remain a design
decision; no common version syntax or resolution mechanism is selected.

## Boundaries

- The unifying scope is software and its attributable footprint on the
  server. Managing every possible aspect of server administration is
  not an implicit requirement.
- Use native Arch, Docker, and host tools directly. Ansible and similar
  configuration-management frameworks are outside the chosen direction;
  avoid recreating a general automation framework within this project.
- Reestablishing software and configuration is distinct from restoring
  application data. Required data and secrets must be accounted for;
  their changing contents need not become repository configuration.
- Detecting a difference does not by itself authorize overwriting or
  removing it. Direct edits to managed configuration are reported; the
  operator chooses whether to keep the change as intended configuration
  or restore the recorded version.
- Every application retirement asks the operator whether to keep or
  delete its persistent data. The affected data and any shared use must
  be clear, and retained data remains accounted for.
- Reproducibility means satisfying the declared version requirements
  and configuration. It does not require freezing every version or
  promise a byte-for-byte reconstruction of the server.

## Acceptance scenarios for the eventual design

1. Explain why an installed package or containerized application exists
   and identify its declared configuration and supporting resources.
2. Identify both an unexpected custom file and an unexplained edit to a
   package-supplied configuration file.
3. Account for normal changes to application data without treating each
   change as configuration drift.
4. Adopt an existing application and its supporting resources while
   retaining visibility of resources not yet managed.
5. Retire one application while identifying shared accounts and
   directories, and distinguishing persistent data from disposable
   resources.
6. Reestablish the declared software and configuration on a suitable
   replacement Arch Linux server, honoring version requirements and
   identifying separately required data and secrets.
7. Record a change without changing the live setup, then see the
   unapplied work in system status and apply it as a separate action.
8. After a partly failed application, identify what took effect, what
   failed, what was not attempted, and what currently remains different
   from the intended setup. Inspection itself does not apply changes.

## Decisions still open

The [user journeys](2026-10-30-server-environment-journeys.md) explore
adoption, changes, and retirement, with proposed behaviors and more
specific open decisions. Handling direct configuration edits, asking
about persistent data on each retirement, and allowing software-specific
version requirements are confirmed directions. The supported host is
Arch Linux only. Recording and applying are separate actions, with
system status exposing unapplied work and application outcomes.

- The presentation of status, scope of application, and retained history
  of attempts and outcomes.
- Upgrade timing, automation, and supported version constraints for
  native Arch packages and Docker applications.
- Adoption, independent ownership, and removal policies.
- The relationship between reporting differences and correcting them.
- The role, if any, of native metapackages in the redesigned system.
- Command syntax, storage formats, application integrations, and all
  other implementation choices.

## References

- [lostfiles manual](https://man.archlinux.org/man/lostfiles.1.en)
- [ArchWiki: listing changed backup files](https://wiki.archlinux.org/title/Pacman/Tips_and_tricks#Listing_changed_backup_files)
- [ArchWiki: partial upgrades are unsupported](https://wiki.archlinux.org/title/System_maintenance#Partial_upgrades_are_unsupported)
