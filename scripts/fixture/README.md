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
`install-native-conflict`, `install-service-environment`,
`install-account-defaults` and
`install-docker-resume` and `install-docker-diagnostic-resume` add only their fixed reviewed, digest-pinned helpers
after Python is available. Each generates the installer payload
at runtime and uses the existing verified console transport.
The installed guest/root disk guard and root-protected directory checks
precede publication. An existing target is refused, and a private record
binds the added file's digest. The operation does not run the new helper
or modify the immutable source disk.
Install `docker-resume` before the separate diagnostic activation helper;
the latter binds that dependency exactly and preserves the incomplete
image preparation history. Installing either helper does not activate it.

Install the shared service environment observer before Docker readiness,
and the account-defaults validator before corrected baseline helpers.
`vm.py replace-native-service` replaces
only the exact original `native_service.py` with its reviewed correction.
It requires untouched native fixture paths, accounts, packaged SSH unit
and configuration, no SSH listener, and an inactive disabled service.
It preserves the old helper bytes and a prepared receipt before atomic
publication, then records completion. An unexpected old digest or any
prior replacement evidence blocks replay; no replacement helper is run.

`vm.py replace-docker-baseline` separately corrects only the original
unused Docker baseline helper. It requires exact original/replacement
digests, the account-defaults validator, absent Compose account and fixed
application/state paths. It preserves old bytes and receipts before atomic
publication. It neither calls the helper nor contacts Docker. Neither
pristine replacement route can resume a partially created native fixture.

`vm.py install-native-service-recover` adds the separately guarded SSH
continuation only when its exact existing native helper and account
defaults dependency match. Installation neither replaces used code nor
executes recovery. The continuation separately checks the observed partial
state, preserves its prior unknown journal, and records its own attempt.

For the separately observed keyword-case mismatch, install the fixed
`native-service-observe` addition before `vm.py replace-native-verifier`.
This separate route accepts only the exact used helper, both expected
unknown journals, and the already running fixed SSH fixture. It preserves
old helper bytes and private copies of both journals before publication,
then verifies their bytes and service identities remain unchanged. It
performs no setup, service action or authenticated check. The separately
invoked observer records a new check without completing either prior
attempt.

The Docker resume addition only installs its helper. Its separate runtime
entrypoint requires the successful initial engine/import evidence and
exact image-only checkpoint bindings before starting that existing engine.

`guest_image_index_prepare.py` covers the observed archive whose root
entries point directly to the acquired amd64 child manifests. It requires
the completed but unverified original import and the exact image-only
engine. It verifies the original archive and every copied blob, then
creates a separate archive whose root descriptors point to the unchanged
original OCI indexes, with the same fixture annotations. No layer is
extracted, no blob is acquired, and no explicit tag command is used.
One `docker image load --platform linux/amd64` attempts the new archive;
actual original-index associations determine the result. Prior import
history remains intact, and known child image identities left by loading
are reported without cleanup. This preparation does not waive later
checkpoint, application or acceptance checks.

The [Docker load documentation](https://docs.docker.com/reference/cli/docker/image/load/)
describes explicit platform selection. The
[containerd 2.4.2 importer](https://github.com/containerd/containerd/blob/v2.4.2/client/import.go)
binds image records to the root index's descriptors and filters the content
walk by platform. These support testing this nested-index representation;
they do not establish the guest's resulting digest associations.

Relevant tool behavior is documented by the authoritative
[bubblewrap manual](https://man.archlinux.org/man/bwrap.1.en),
[QEMU invocation reference](https://www.qemu.org/docs/master/system/invocation.html)
and [pacstrap manual](https://man.archlinux.org/man/pacstrap.8.en).

The mocked host-boundary tests do not establish that the guest boots,
that acquisition succeeds or that any acceptance scenario passes. Record
those actual outcomes separately with their artifact/guest identities.

`guest_image_load_diagnose.py` performs one new local load after the
separate cold diagnostic activation. It binds that activation's completed
journal, the unchanged earlier unverified import and unknown preparation,
the running engine/process/socket identities, and the exact prepared
archive. Builds and other Docker clients must be quiescent. It never
restarts services, repacks bytes, pulls, tags, deletes or retries.

The new `image-index-load-diagnostic` directory retains private stdout and
stderr, limited to 1 MiB each, plus byte counts, hashes, the real client
exit code and closed error categories. The load has a 600-second timeout;
the whole helper has an 1800-second deadline. A timeout or output limit
leaves the new attempt unknown and makes no claim that daemon work
stopped. A completed client with a nonzero exit remains unverified even
if some image identities changed. Only actual successful loading and
original index/platform association checks can complete this new attempt;
all prior attempt records remain unchanged. Raw error text is never
printed on the console, and this diagnostic does not establish product
acceptance.

`guest_native_assembly_diagnose.py` reads the two fixed native assembly
jobs, defaulting to both; its optional `--state` accepts only
`native-adoption` or `native-update-before`. Completion requires the exact
212- or 220-package frozen inventory, original installation reasons,
old GnuPG, result/source/checkpoint and worker bindings, UUID/exit markers,
and zero manager or cgroup work. The update result also binds the actual
three AUR build records and prior adoption result. Output includes hashes
of the current version/reason inventories and bounded differences, rather
than dumping the full result files.

The collector performs current read-only account, configuration, service
and listener observations. Authenticated before/after checks are validated
from the completed jobs' results; it does not create another check, read
private keys, modify journals or run package/service mutations. A live
observation is not a stopped checkpoint.
