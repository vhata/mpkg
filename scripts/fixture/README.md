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

Relevant tool behavior is documented by the authoritative
[bubblewrap manual](https://man.archlinux.org/man/bwrap.1.en),
[QEMU invocation reference](https://www.qemu.org/docs/master/system/invocation.html)
and [pacstrap manual](https://man.archlinux.org/man/pacstrap.8.en).

The mocked host-boundary tests do not establish that the guest boots,
that acquisition succeeds or that any acceptance scenario passes. Record
those actual outcomes separately with their artifact/guest identities.
