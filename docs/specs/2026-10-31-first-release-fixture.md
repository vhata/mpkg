# First-release disposable fixture design

This binds acquisition and assembly inputs for the
[acceptance scenarios](2026-10-31-first-release-acceptance.md). The
[source inventory](../fixtures/2026-10-31-arch-native-inputs.json)
records exact identities, package resolutions and evidence levels.
No acceptance scenario has run. Artifact acquisition, builds,
implementation and VM execution require their own authorization.

## Evidence obtained

Research on 2026-10-31 established the following inputs:

| Input | Evidence obtained | Evidence still required |
| --- | --- | --- |
| Arch ISO | Published SHA-256 and HTTP HEAD identifying the dated image | Downloaded bytes, digest and signature verification |
| Dated repositories | Downloaded core/extra databases, computed hashes and complete native dependency resolutions | Archive acquisition/signatures and actual installed inventory |
| AUR recipes | Canonical Git references checked against Arch's mirror; immutable recipe files read and hashed; sources/dependencies inspected | Source verification, isolated preparation, builds and artifact hashes |
| CPython 3.12 | Official source URL and published SHA-256 | Source verification, build and required-module checks |
| Sonarr/Radarr images | Registry index, amd64 manifest and config descriptor bytes/digests/platform checked | Image layers, trust decision, guest execution and functional checks |

The JSON distinguishes published archive digests from hashes computed
over downloaded metadata. Package hashes come from the frozen databases;
source checksums come from the pinned recipes. No ISO, package or source
archive was downloaded, no package recipe was executed, and no service,
container or VM was started for this design. Matching Git references
and metadata do not independently establish trust in executable code.

Native resolution used pacman 7.1.0 / libalpm 16.0.1 with an explicit
scratch configuration, empty scratch local database, downloaded sync
databases and scratch cache/log paths:

```text
pacman --config <scratch-config> --sync --print \
  --print-format '%r %n %v %l' <explicit-fixture-package-roots>
```

There was no refresh, archive download or installation, and the host's
installed-package database was not used. Exact roots and the resolved
names, versions, URLs, dependencies and database-published hashes are
retained in the source inventory. This is native resolution evidence;
runtime installation and compatibility remain unverified.

## Frozen Arch and Python sources

Use the official x86_64 installation media:

```text
https://archive.archlinux.org/iso/2026.10.01/archlinux-2026.10.01-x86_64.iso
SHA256 684ded26c63240ff4a41e8c25ee84ea6da233f557364821f13d12c2b0a9059a5
```

The digest comes from the official
[dated checksum manifest](https://archive.archlinux.org/iso/2026.10.01/sha256sums.txt).
HTTP HEAD reported 1,640,497,152 bytes. The ISO identifies installation
media, not a booted guest disk or its final package state.

All repository packages come from one coherent dated source, with only
`core` and `extra` enabled:

```text
https://archive.archlinux.org/repos/2026/10/30/$repo/os/x86_64
core.db SHA256 89d479c3a28ecd789ddc6ab44d77888b423339a606f470f0684eac81c0d8b1e8
extra.db SHA256 2ca123a980d89533a5306f60ef904fdc2d06f3e52c52f59ba951d50613358bb6
```

Refuse changed database bytes or missing artifacts rather than silently
using current, testing, staging or other dated repositories. Verify
package signatures under an accepted Arch signing-key policy during
assembly. Database hashes bind the resolution and do not replace
package signature checks.

The frozen system `python` is 3.14.8-1 and occurs in the toolchain's
dependency closure. It must not run the project checks or the proposed
Python 3.12 coordinator. Bind the separate official source release:

```text
https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz
SHA256 b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c
```

This digest is published on the
[Python 3.12.16 release page](https://www.python.org/downloads/release/python-31216/).
After authorized acquisition and verification, build as an unprivileged
fixture builder with prefix `/opt/mpkg-python/3.12.16` and
`--with-ensurepip=no`; a bounded administrator step installs the result.
Record configure/compiler inputs, linked libraries and installed-tree
identity. The baseline includes the compiler, make, pkgconf and library
prerequisites for SSL, SQLite, compression, ctypes, readline and GDBM;
verify those modules after building. Create each product worktree's
Python 3.12 `.venv` through `scripts/setup.sh` with `MPKG_PYTHON` naming
that interpreter. Verify the minor version and venv prefix explicitly.
No unrecorded interpreter or system-Python fallback is permitted.

## Repository sets and exact AUR selections

The source inventory contains two complete repository resolutions:

| Resolution | Packages | Purpose |
| --- | --- | --- |
| `native_change` | 207 | Boot/service/build baseline and all repository-supplied CLI requests except deliberately omitted additions |
| `native_applied` | 217 | The same roots plus `tmux`, `ripgrep`, `cmake`, `zsh` and their dependencies |

Counts exclude built AUR packages and the separately built Python
prefix. Roots include `base`, `linux`, `mkinitcpio`, filesystem tools,
OpenSSH, Docker/Compose, `base-devel`, Git and Python build libraries.
The `dbus-units` provider is explicitly `dbus-broker-units`. Every
resolved repository package is recorded with its source digest.

The change set excludes all of `tmux`, `ripgrep`, `libutempter`,
`gitstatus`, `cmake` and `zsh`. The applied set includes `tmux` 3.8-1,
`ripgrep` 15.2.0-1, `libutempter` 1.2.3-1, `cmake` 4.4.5-1 and `zsh`
5.9.2-1. `libevent` is already a baseline dependency and therefore
cannot serve as the missing-dependency oracle. Verify actual guest
absence of `libutempter` before the repository addition, and of
`cmake`/`zsh` before the AUR addition. Do not preinstall those AUR build
prerequisites merely to make its demonstration pass.

### gitstatus and its initially missing prerequisites

Select `gitstatus` 1.5.5-1, already requested by
[vhata-dev](../../vhata-dev/PKGBUILD), at canonical AUR commit:

```text
c9569422a0570f0f4cea4bef013a5026cdcfb3dc
```

The [pinned recipe](https://github.com/archlinux/aur/blob/c9569422a0570f0f4cea4bef013a5026cdcfb3dc/PKGBUILD)
and `.SRCINFO` agree: runtime dependency `glibc`; build dependencies
`git`, `cmake` and `zsh`. Its sources are gitstatus `v1.5.5` and bundled
libgit2 `tag-2ecf33948a4df9ef45a66c68b8ef24a5e60eaac6`; the source
inventory retains their published SHA-512 checksums and observed commit
identities. The recipe supplies the libgit2 archive and invokes
`./build` without automatic-install or download flags. Its install
script prints shell-integration instructions. This bounded static
inspection does not establish a successful or safe runtime build.

### Exact CLI adoption and recursive AUR dependencies

Preserve every request in [vhata-cli](../../vhata-cli/PKGBUILD), including
`ack`. The frozen repositories supply every other request; they contain
neither `ack` nor its runtime dependency `perl-file-next`.

| Package base | Selected canonical AUR recipe | Version and prerequisites |
| --- | --- | --- |
| `ack` | `1555404507ff0db4291d7f88c9a989b957ea1f48` | 3.10.0-1; runtime `perl-file-next`; checks `perl-yaml-pp` |
| `perl-file-next` | `18b5c5d120e1a3bb426831e4770a9971e4a488cf` | 1.18-7; runtime `perl` |

`perl` and `perl-yaml-pp` are bound repository inputs. This is a real
recursive AUR chain required by the exact collection; ordinary fixture
preparation must build and verify it before the complete adoption case.

The selected ack revision is the immediate parent of the observed
canonical HEAD, `03400c09bc0ee26be5ac939758db3b34b268e4b0`. HEAD's
`PKGBUILD` declares 3.10.0-2 while its `.SRCINFO` says 3.10.0-1. The
selected parent consistently declares 3.10.0-1 and uses the same
upstream 3.10.0 archive. This explicit fixture selection satisfies the
collection's unrestricted `ack` request without silently correcting
metadata, dropping the request or treating conflicting versions as
equivalent. Preserve that selection rationale in the source inventory.

Read-only canonical Git history established the ancestry and consistent
metadata. The selected recipe files are hashed. All AUR source archive
verification, isolated preparation, test results and built artifact
hashes remain to be obtained. No source declaration alone grants
privileged execution authority or selects an unbound AUR helper.

## Guest assembly and restore points

Use QEMU `qemu-system-x86` 11.1.3-1 and `edk2-ovmf` 202608-1 from
the frozen October 31 archive. The inventory binds their published
package hashes plus QEMU's common, firmware and disk-tool artifacts;
it does not claim a complete host dependency installation. Provisioning
that runner and recording its actual host inventory remain separate.

Select `q35`, `qemu64`, TCG acceleration, four vCPUs, 8 GiB RAM and a
40 GiB qcow2 virtio disk. Use a GPT disk with a 1 GiB FAT32 EFI system
partition and the remaining space as ext4 root, with systemd-boot from
the bound systemd package. Use virtio networking with QEMU user-mode
outbound networking and no inbound forwarding. Test clients run inside
the guest; serial console access is independent of SSH. Record the
expanded machine type, actual launch argv and firmware/disk identities.
The [QEMU invocation reference](https://www.qemu.org/docs/master/system/invocation.html)
describes machine/accelerator selection; the pinned binary must confirm
its available machine and CPU models during assembly.

Use `/usr/share/edk2/x64/OVMF_CODE.4m.fd` read-only and an independent
copy of `OVMF_VARS.4m.fd`, without Secure Boot. Those paths appear in
the [bound firmware package's file list](https://archlinux.org/packages/extra/any/edk2-ovmf/files/).
Hash the actual extracted firmware and per-restore-point variable state.
Attach no production disk, host directory or host Docker socket. All
data and credentials are fixture-only. This design creates no VM or
billable resource.

Use these observation limits: HTTP 10 seconds, SSH/SFTP 15 seconds,
status 30 seconds, service/container readiness 120 seconds, native or
Compose apply 900 seconds, source build 3,600 seconds per package,
acquisition 1,800 seconds per artifact and 7,200 seconds per scenario.
After worker death observe for 120 seconds before reporting a block.
A timeout fails or blocks that run; it never proves the action stopped,
releases uncertain ownership or authorizes replay/forced cleanup.

Assembly, when separately authorized, proceeds in this order:

1. Acquire and verify the bound ISO and packages. Install the full
   `native_change` repository set, checking its resolution against the
   manifest, and configure guest boot and console access.
2. Verify and prepare the pinned `perl-file-next`/`ack` recipes as an
   unprivileged builder. Record build/check results and artifact hashes
   before installing them. Fixture setup remains distinct from product
   adoption; preserve package installation reasons and independent use.
3. Build/verify Python 3.12.16, create the product environment and bind
   its implementation revision. Establish the native and Docker
   resources below using generated test credentials and synthetic data.
4. Verify initial absences, complete installed inventory, input bundles,
   runtime identities, sentinels and functional checks. Add actual
   artifact/disk identities to the assembled manifest and take snapshots.

| Restore point | Required initial state |
| --- | --- |
| `native-change` | Bound 207-package repository set and built ack chain; working native service/data; all six initial absences verified; fixture CLI intent omits `tmux`/`ripgrep`, and gitstatus is not wanted yet |
| `native-adoption` | Complete exact CLI requests already installed outside the product; accepted service/config/data working; no product adoption or attempt history |
| `native-applied` | Product's actual successful additions with missing-dependency resolution and bound attempt history; retirement cases reset here |
| `docker-adoption` | Working adapted Sonarr and actual unmanaged Radarr; accepted fixture inputs and checks; no product adoption/attempt history |
| `docker-applied` | Product's actual configuration application, verified behavior and attempt history; retirement cases reset here |

These are planned labels, not existing snapshots. Native adoption uses
a separate prepared snapshot so complete adoption cannot eliminate
A4's missing dependencies. The `native-applied` evidence must come
from A4; bootstrapping final packages cannot manufacture that evidence.
Every snapshot needs an actual identity and observed starting state.

## Native service, data and external consumer

Use the bound `openssh` 10.6p1-2 package from `vhata-system`,
`/etc/ssh/sshd_config` and `sshd.service`. Configure guest loopback port
22222, generated fixture keys and a dedicated account, with password
authentication disabled. Capture effective configuration and protected
key references during assembly. Private credentials and their public
hashes do not enter Git.

Success requires `sshd -t`, expected manager state, and authenticated
loopback SSH/SFTP reading a known sentinel. Keep independent console
access during failure injection. Compare the package-owned configuration
with both its package baseline and accepted intended content.

Declare exclusive native data at `/srv/mpkg-fixture/native-data` and
shared media at `/mnt/media/mpkg-fixture-shared`. Proposed guest-only
accounts are `fixture-native` (UID/GID 1500) and `fixture-external`
(UID/GID 1501), with supplementary GID 1001 (`media`). Record exact
memberships, modes, ACLs and sentinels. Confirm IDs are available before
creation; collisions require an explicit fixture revision instead of
renumbering an existing account.

The external native consumer uses a separate unmanaged SFTP service
instance on loopback port 22223, its own keys and startup policy. It
must authenticate and read the shared sentinel after managed-native
retirement. It does not depend on the managed service instance. Keep
`openssh` independently wanted; retiring the managed component cannot
uninstall it. Retained data and shared access retain their required
accounts/groups without recreating the retired service.

## Adapted Sonarr and actual unmanaged Radarr

Preserve the selected deployment relationships from the
[source evidence](2026-10-31-compose-deployment-evidence.md) and
[runtime baseline](2026-10-31-sonarr-runtime-baseline.md): published
LinuxServer images, host networking, separate `/config` and shared
`/mnt/media` binds, `unless-stopped`, and distinct deployment-owner and
application-group identities. Recreate them with fresh fixture data
and credentials. Keep an actual Radarr deployment outside management;
a synthetic process alone cannot substitute for this Docker consumer.

Sonarr registry metadata checked at 2026-10-31T23:28:57.919834Z binds:

```text
Repository: lscr.io/linuxserver/sonarr
OCI index: sha256:48e36b608b461273b9dae857725cd0561a127f2c694b687318f6d0c5ce63e5c9
linux/amd64 manifest: sha256:a674ae620ca7ce1246b377bcac13a7500567196cf2207059e68146fa4dc169f7
Image config: sha256:076be80fcab2bd0acdea4c8c5f604318f2feb61aeeaacd71cfcb1983a8fb50bf
```

Index and child returned HTTP 200; their response-header digests and
computed body SHA-256 values matched. The downloaded 9,202-byte config
matched its descriptor digest/size and declared `linux`/`amd64`. Nine
layer descriptors were present; layers were not requested. Index,
platform manifest and config are different identities. A runtime image
ID must not be substituted for a registry object digest.

Bind the fixture to the amd64 manifest and accepted index association.
Full layer acquisition, trust and compatibility remain gates. If an
artifact disappears, revise the manifest rather than falling back to
`latest`. Registry evidence came from the repository's
`/v2/linuxserver/sonarr/manifests/<digest>` endpoints and the identified
config blob; transient registry tokens were not persisted.

The actual unmanaged Radarr image is also bound from public registry
metadata checked at 2026-10-31T23:32:49.514068Z:

```text
Repository: lscr.io/linuxserver/radarr
OCI index: sha256:084b3b2ab1d0ef930660727259546a241f2bdf67c9ed085d54bf1486a6887c9b
linux/amd64 manifest: sha256:41fdc1672209c2ef31c5260015ec8b96e3c75513e60a667eb052e1ff54b4cfa9
Image config: sha256:a9b08c177649ae4e2c03f4ab375140ac8e633f87a781eeaa7a0e7f1e85b112a8
```

Its index and child returned HTTP 200 with matching header/computed
digests; the 9,053-byte config matched its descriptor and linux/amd64
platform. Nine layers were referenced but not fetched. Public config
labels identify Radarr `6.4.4.10685-ls324` and Sonarr `4.0.20.3014-ls1`.
These are metadata observations, not completed image acquisition.

Use Radarr project `mpkg-fixture-radarr`, service `radarr`, a separate
guest `/opt/docker/radarr/config:/config` bind, the same `/mnt/media`
bind and identity environment, and its own fixture listener on port
17878 after checking availability. Keep its definition, configuration,
data and lifecycle outside product management. It runs during Sonarr's
changes and retirement and cannot depend on Sonarr remaining present.

Generate and bind a complete fixture Compose input bundle with:

| Property | Fixture choice |
| --- | --- |
| Sonarr project/service | `mpkg-fixture-sonarr` / `sonarr`; absolute project directory and ordered files |
| Engine | Guest-local Unix engine; record actual engine and socket identity |
| Image/platform | Pinned amd64 manifest above; explicit `linux/amd64` |
| Network/restart | `host`; `unless-stopped`; no invented Sonarr project network |
| Binds | Guest `/opt/docker/sonarr/config:/config` and `/mnt/media:/mnt/media`, read-write, with fresh synthetic contents |
| Identity inputs | `PUID=963`, `PGID=1001`, `UMASK=002`, `TZ=America/Los_Angeles` |
| Deployment owner | Fixture `compose` UID 963, primary GID 962, home `/opt/docker`; `media` GID 1001 remains separate |
| Configuration | Fresh Sonarr data and generated credentials; selected nonsecret XML properties under management; other properties preserved |
| Managed change | Fixture HTTP port 18989 to 18990 after checking host-network availability |
| Checks | Measured application credentials, bind roots and descendant sentinels, attributed anonymous `/ping`, and unmanaged Radarr's functional shared-media check |

Fixture names/ports differ deliberately from production. Accept actual
bind address and URL base, and attribute the checked listener to the
intended process. Measure the application's full UID/GID slots,
supplementary groups, namespace mappings and capabilities; initialization
root processes and configured PUID/PGID alone do not establish access.
Preserve secrets and unrelated XML fields during the port change.

Prepare a legal synthetic media fixture and a separate Radarr config
bind. Before adoption, establish its application-level access to that
media using a version-matched operation, then repeat that same check
after Sonarr changes/retirement. Record the exact operation, result,
credential reference and affected fixture paths. A permission predicate
or merely a healthy Radarr process is insufficient. The final Radarr
image/input binding and functional operation are recorded before any
scenario that depends on them executes.

### Supplemental volume and network variants

Reuse the exact pinned Sonarr/Radarr amd64 images in separate fixture
projects. In `volume-keep` and `volume-delete`, replace only Sonarr's
config bind with the explicitly named volume `mpkg-fixture-sonarr-config`.
Initialize fresh application data and credentials through the normal
application startup, then run the same port-change and readiness checks.
After keep, inspect the volume and its accepted nonsecret config/data
sentinels without restarting the retired application. For delete, use a
fresh exclusive restore point, prove no other attachment/consumer, and
require the named volume's absence only after authorized deletion.
The ordinary mutable application database remains data inside the
volume; managing selected XML fields does not convert the whole volume
into configuration.

For `network-shared`, use a bridge named `mpkg-fixture-shared`, explicit
Sonarr and unmanaged Radarr attachments, and separate project names.
Create/adopt the network with sharing declared, use explicit external
references for the unmanaged project, and preserve it after managed
Sonarr retirement while Radarr remains attached. Publish fixture-only
listeners to guest loopback and use the same HTTP and media predicates.
For `network-exclusive-delete`, reset without Radarr or another
attachment and verify the independently authorized network cleanup.
Record actual network/volume IDs and attachment evidence at assembly.
These variants intentionally change networking/config storage; they
supplement the original binds/host-network Sonarr example.

### A9 coherent native update

The October 31 target uses only its own `core` and `extra` databases;
the source inventory binds both database hashes and all 217 resolved
package records. Its roots equal the October 30 applied roots. The real
version change is `gnupg` 2.4.9-3 to 2.4.9-4; the requested CLI versions
need not change for a coordinated system update to have wider effects.
Use the complete applied state as `native-update-before`, including
built AUR packages, then offer this dated target as update availability.
Status and configuration-only apply leave GnuPG at 2.4.9-3. Refusing the
coordinated scope leaves the installed state unchanged. Accepting it
allows the full native transaction, whose observed plan and result must
include GnuPG 2.4.9-4 and satisfy every collection request.

The empty-database target resolution binds inputs, not an actual
installed upgrade transaction. Resolve again against the assembled
local database and explicit package reasons; review any removals,
replacements or AUR compatibility requirements before execution. Never
mix individual newer packages into the October 30 repository state.
Demonstrate a supported exact request with `tmux=3.8-1`; an unavailable
`tmux=0` and incompatible `tmux=3.8-1` plus `tmux=0` must block before
mutation. Neither a failed request nor a wider-scope refusal may silently
relax intent.

## Gates before an executable manifest

The identified ISO, dated complete package resolution, coherent pinned
AUR chain and Python source close those earlier selection gaps. The
following remain gates, not acceptance passes:

1. Acquire archives and verify digests/signatures; prepare and build
   every AUR input and Python; retain actual artifacts and inventory.
2. Bind hypervisor/firmware, assembled disks, identities, nonsecret
   input bundles, credential references, product revision, snapshots,
   operation timeouts and failure injection controls.
3. Acquire the complete Sonarr/Radarr images, initialize fixture data,
   and establish measured identities and exact functional checks,
   including Radarr's media workflow and managed XML update inputs.
4. Assemble the named-volume/network variants and both update restore
   points; verify their observed transaction/input bindings and results.
5. Execute all A1-A12 variants after authorization. Caller disconnect,
   durable-worker death, continuing subprocess/daemon activity and
   journal failure require the implementation's actual boundaries.

Keep outstanding design inputs in the acceptance queue. Guest assembly
and product execution are separate work; this document establishes
neither a complete runtime manifest nor a working first release.
