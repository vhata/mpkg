# Disposable Arch fixture tools

These tools assemble the explicitly authorized disposable guest for the
[first-release fixture](../../docs/specs/2026-10-31-first-release-fixture.md).
They do not install packages on the host, invoke its service manager or
contact its Docker engine. Runtime state remains under ignored `.cache`.
Use the worktree's Python 3.12 environment.

## Acquisition and trust

`runner-inputs.json` binds the complete 117-package native resolution
for the private QEMU runner to the October 31 repository databases.
`runner.py acquire` downloads only the fixed official Arch archive URLs,
requires exact sizes and SHA-256 digests, and obtains detached signatures.
Transfers have a 1,800-second overall deadline plus socket timeouts.

The private GPG store imports the host's distro-provided Arch public
keyring. Fingerprints listed in `archlinux-trusted` are explicit ultimate
roots in this isolated store; other signing keys must obtain full GPG
validity from those roots. The store additionally rejects fingerprints
listed in `archlinux-revoked`, expired/revoked/bad signatures and unknown
or insufficiently trusted signers. It records the three keyring input
hashes and refuses changed inputs. It never uses ambient user trust,
auto-retrieves keys, starts an agent or disables package signatures.
This policy deliberately identifies its trust roots rather than treating
an unqualified successful `gpgv` result as sufficient.

`runner.py verify-iso` applies the same policy to the fixed downloaded ISO
and sidecar signature, after checking its frozen size and SHA-256.
`runner.py extract` rechecks every archive hash/signature, validates tar
paths/types and confines writes to a fresh private runner tree. It never
runs package scripts. Traversal, escaping links, special files, existing destination symlinks
and file collisions fail closed. Absolute package symlink targets are
converted to relative links under the private root; the final complete
link graph must remain confined there before execution is enabled.

`native.py acquire` obtains both frozen native sets with the same
hash/size/signature checks. `inputs.py` rechecks those artifacts and
builds an ext4 input disk as a fresh regular file using `mkfs.ext4 -d`;
it uses no host mount, loop or NBD device. The VM attaches the resulting
hash/UUID-bound image read-only. Its baseline list contains exactly the
207 selected packages; additional proof/update artifacts stay uninstalled.

## Private execution

`vm.py prepare` creates a new UUID-bound 40 GiB qcow2 disk and independent
firmware variables. It copies only the fixed kernel/initramfs members
from the verified ISO. `vm.py start-installer` starts the TCG guest;
`vm.py start-disk` starts the installed disk. The process remains in the
foreground with an exclusive operator lock.

Bubblewrap gives QEMU the verified runner tree as its read-only root,
a private writable VM directory, private temporary files and restricted
process/device views. Its loader, libraries and QEMU modules come from
that tree; host libraries and user configuration are not visible. No
host disk, host Docker socket, directory sharing or inbound forwarding
is passed into the guest. The guest can use user-mode outbound networking.

`vm.py status` verifies the QMP UUID before reporting state. The bounded
`console` operation observes the independent serial console; an optional
`--script` transfers a reviewed worktree shell script. The reviewed
`guest-bootstrap.sh` independently verifies DMI UUID, target disk serial,
40 GiB size and blank/unmounted state, plus input disk serial, manifest
identity and payload hashes, before partitioning. It installs the exact
baseline with required local package signatures, restores installation
reasons and verifies the six initial absences. A detected virtual machine
alone is insufficient authority.

`sources.py` acquires pinned Python and AUR recipe/source bytes without
executing them. `source_inputs.py --oci-snapshot <private-snapshot>` builds
a second read-only disk containing those bytes, verified OCI acquisition
inputs and the tracked proof scripts. `guest-install-sources.sh` binds the
installed root disk, DMI identity and source disk serial before checking
the complete payload and installing it into private guest input paths.
The Python source is placed at
`/opt/mpkg-proof-inputs/sources/python/Python-3.12.16.tar.xz`.

The initial ISO keyring must be initialized before package verification.
`guest-resume-bootstrap.sh` covers only the recorded formatted but empty
target state; it never repartitions or reformats a partially installed
disk. `guest-repair-public-permissions.sh` corrects the known bootstrap
umask defect only after a successful installation. Its fixed public
directory expectations come from `public-directory-modes.json`, extracted
from verified package metadata; private fixture permissions remain strict.
Fresh bootstrap runs use a public umask only for package/public config
creation. Status collection is read-only and requires an idle shell.

Each VM start retains a separate private serial log. Console transfer
requires successful complete decoding and an exact payload digest before
execution. `snapshot.py create <name>` and `restore <name>` require the
VM operator lock, so checkpoints cannot mutate a running disk. Restores
preserve the prior disk and firmware checkpoint; interrupted restore
markers block further snapshots and boot until explicitly reconciled.

After Python installation, `guest_aur.py` starts a bounded, durable
systemd build job for the pinned `perl-file-next` and `ack` recipes.
The builder uses UID 1502 and an isolated network namespace; it verifies
sources, compares generated `.SRCINFO`, and runs each recipe's checks.
Only the newly built, identity/hash-bound fixture artifacts use a separate
repository-free pacman configuration permitting unsigned local builds.
The guest's repository signature policy remains unchanged. Build records
include actual results, artifact hashes, configuration and worker hashes.
The pinned ack revision's `.SRCINFO` homepage uses `betterthangrep.com`
while its `PKGBUILD` generates `beyondgrep.com`. Only that exact pair of
metadata byte hashes and that one field change are reconciled, with
`generated_metadata_matches: false` and explicit old/new/hash evidence.
The pinned files remain intact; every other metadata difference fails.

Preserve `native-change` after the ack chain, Python and native service
fixture are complete. While stopped, `build_output.py prepare` creates a
128 MiB output disk bound to that checkpoint. `guest-build-gitstatus.sh`
uses it to authorize the separate build state, installs only the seven
signed build prerequisites and runs the pinned gitstatus recipe. After
shutdown, `build_output.py harvest` reads fixed members through the private
runner's `debugfs`, with the VM tree read-only and only a fresh export
directory writable. It validates the build provenance and archive bytes,
then creates a separate read-only return disk. Restore `native-change`
before running `guest_import_build.py`; this imports the artifact without
installing it or retaining build dependencies in the baseline.

The returned input disk also carries the host-validated `native-change`
checkpoint authorization. `guest_native_adoption.py` requires that record,
the exact native-change versions and functioning fixture SSH/data checks
before adding only frozen `tmux`, `ripgrep` and `libutempter` archives.
It retains every existing installation reason, marks the new runtime
dependency appropriately and verifies all ten exact `vhata-cli` requests.
Its durable result describes a separate bootstrap-only adoption baseline;
it creates no product state or product attempt. The ack build likewise
marks `perl-file-next` as the dependency of the explicit ack request.

`guest_native_update_before.py` starts from successful native adoption and
the completed gitstatus artifact import. It adds only the remaining seven
frozen repository prerequisites as dependencies and gitstatus as explicit,
preserving the previous 212 package reasons. It verifies all 217 October
30 repository packages plus the three actual AUR builds, including ack's
precise metadata reconciliation, and retains GnuPG 2.4.9-3. Its durable
220-package result is bootstrap-only `native-update-before` evidence;
it does not create or claim a product `native-applied` state.

Each build has durable `started`, `exit`, `complete` and private log
evidence. Manager timeouts can interrupt before an exit marker is written;
missing completion is not proof of success. A running build blocks another
heavy build, while a successful exited Python unit may retain its status.

`vm.py install-docker-ready`, `install-docker-baseline` and
`install-native-conflict` add only their fixed reviewed, digest-pinned
`docker_ready.py`, `docker_baseline.py` and `native_conflict.py` helpers
after Python is available. Each generates the installer payload
at runtime and uses the existing verified console transport.
The installed guest/root disk guard and root-protected directory checks
precede publication. An existing target is refused, and a private record
binds the added file's digest. The operation does not run the new helper
or modify the immutable source disk.

Relevant tool behavior is documented by the authoritative
[bubblewrap manual](https://man.archlinux.org/man/bwrap.1.en),
[QEMU invocation reference](https://www.qemu.org/docs/master/system/invocation.html)
and [pacstrap manual](https://man.archlinux.org/man/pacstrap.8.en).

The mocked host-boundary tests do not establish that the guest boots,
that acquisition succeeds or that any acceptance scenario passes. Record
those actual outcomes separately with their artifact/guest identities.
