# Disposable fixture execution evidence

This records actual work authorized on 2026-11-01 against the
[fixture design](../specs/2026-10-31-first-release-fixture.md) and
[focused mechanism proofs](../specs/2026-10-31-first-release-storage-and-execution.md#focused-proofs-before-product-implementation).
Package and service changes are confined to a local disposable guest.
Host effects are private acquisition/runner files and isolated QEMU
execution. The work does not implement the replacement manager or
establish any A1–A12 product acceptance result.

## Acquired inputs

| Input | Actual observation |
| --- | --- |
| Arch ISO 2026.10.01 | Downloaded 1,640,497,152 bytes; frozen SHA-256 matched; detached signature verified under explicit Arch master roots |
| Private QEMU runner | All 117 pinned archives passed size, digest and signature checks; confined extraction completed without package hooks |
| Native guest packages | All 218 distinct frozen archives passed size, digest and signature checks; these include the baseline, later additions and the GnuPG update |
| Python and AUR sources | All 12 selected source/recipe files matched their bound SHA-256 or SHA-512 digests; no source-signature verification is claimed |
| Container images | Complete selected linux/amd64 closures for observed Sonarr, observed Radarr and older Sonarr were downloaded and digest-verified; no publisher-signature verification is claimed |

The ISO SHA-256 is
`684ded26c63240ff4a41e8c25ee84ea6da233f557364821f13d12c2b0a9059a5`.
The OCI archive is 265,943,040 bytes with SHA-256
`b7971f3427b643acb69dbe1e792dd105b3e01b4aa6f2e46ec3d7b474a2423aa1`.
Other architectures named in the original image indexes were not acquired.
The image indexes, selected manifests, configs and every selected layer
remain bound by the acquisition record; digest identity does not assert
publisher signature trust.

Private acquisition evidence is retained in the assembly worktree's
ignored `.cache/fixture/` directory. OCI evidence and `images.oci.tar` are
under the checkout's ignored
`.cache/fixture-oci/snapshot-c37f5df672604499a7aedf2cdb1b93ff/`.
The source inventory remains
[the frozen input manifest](2026-10-31-arch-native-inputs.json).

## Actual guest boundary

- QEMU runs from the verified private filesystem under bubblewrap, using
  TCG, four virtual CPUs, 8 GiB RAM and private firmware variables.
  The actual binary reports version 11.1.3, maps `q35` to `pc-q35-11.1`,
  and advertises the selected `qemu64` CPU. The running loader/QEMU
  process was uniquely attributed by its UUID and its argv recorded.
- Guest UUID: `c81ea47f-3ca6-4966-ab55-1626068a4789`.
- Disposable OS disk: 40 GiB, serial `mpkgc81ea47f3ca64966`.
- Read-only native input disk: 2 GiB, 450 files, SHA-256
  `14e5535e2fde4033bdf68a8d9461ef0088c1b89a46eb236a9bb4492a557bc56e`.
- Read-only source/proof disk: 768 MiB, 31 files, SHA-256
  `6dda38da4c852d0ade16e51b62101174591394b0ede0e5a7427f148e7240ffe8`.
  Its per-file proof hashes bind revision
  `9cbb7a68779c1e0854c46cb121c99e809920e007`.
- No host disk, shared host directory, host Docker socket or inbound
  forwarding is exposed to the guest. Input disk construction used a
  private regular file, without host mounts, loop devices or NBD.
- The ISO booted, accepted root login over its private serial console,
  and reported the expected UUID, disk serials and sizes. The clock was
  observed at 2026-11-01T07:52:14+00:00.

The installed disk subsequently booted Linux 7.2.11-arch1-1 to an
automatic root serial login. Source installation verified every input
disk checksum, installed the reviewed proof files and rechecked the
Python source hash, then returned exit zero. Source builds, native
service checks, image import and mechanism results remain distinct
observations; a running QEMU process does not establish them.

## Diagnosed assembly failures

Private GPG initialization first exceeded Unix socket pathname limits.
The corrected short final and staging paths include the longest GPG
socket suffix in their length checks. A separate sandbox socket denial
required approved elevated execution. Failed stores and diagnostics were
preserved, and trust was published only after initialization succeeded.

Runner extraction initially refused absolute license symlinks in the
signed xz archive. The corrected extractor rebases such links within the
private root and checks the final resolved link graph before publishing
its completion marker. The failed extraction tree was preserved.

The first guest bootstrap formatted only its verified disposable disk,
then stopped before pacstrap because the ISO keyring was uninitialized.
A bounded continuation was added for that exact post-format, pre-install
state. Its first attempt refused padded `findmnt` display values. A
read-only diagnostic verified that raw device numbers matched, the root
contained only empty `boot` and `lost+found` directories, no package
database existed, and the transferred script hash matched exactly.
The corrected comparison uses raw output and preserves all state checks.

Console transport now requires successful base64 decoding and an exact
payload SHA-256 before invoking Bash or the fixed Python 3.12 interpreter.
Each transfer preserves previous
payloads and records its exit status. No malformed-transfer execution
was observed; the integrity gate was added after inspecting the original
transport's failure path.

## Execution results

The corrected bootstrap continuation completed with exit status zero and
its UUID-bound completion marker. Its exact 207-package inventory and six
required initial absences passed. An independent read-only status capture
confirmed the completion marker and exit status after the console returned
to an idle shell.

The restrictive bootstrap umask left
some public system directories and generated package metadata unreadable
to ordinary users. The first targeted repair restored fixed public paths
to their package-defined modes and passed the root inventory comparison,
but the unprivileged query still failed to open the package database.
The narrower diagnosis found only the database root mode and its
`ALPM_DB_VERSION` mode still wrong; all 207 package directories and 632
package metadata files already had their expected public modes. The
two-path correction then passed both root and unprivileged comparisons
against the complete frozen inventory and returned exit zero. Private
fixture and keyring permissions were not relaxed.

After orderly shutdown, an offline `repository-baseline` checkpoint was
created with internal snapshot ID `1`, no memory state, and firmware
variables SHA-256
`8f0774ade83915af4a570c390d6cbcac898c95ba0bbdbb1a233e5ca8d12af1e9`.
This label records the repository bootstrap only; it is not the complete
`native-change` fixture or an applied product restore point.

The supervised Python 3.12.16 job was launched successfully after the
installed boot and source checks. A subsequent observation found it
active/running in configure, with the OpenSSL compilation/link check
successful. Build completion, module verification and publication remain
pending at this checkpoint. The observed package inventory remains 207.

No source build, guest image import or mechanism result is recorded as
passed yet. Applied product restore points remain unavailable until
actual product operations create them.

## Verification and limits

The combined host-safe suite passed 43 tests after the first proof
integration. Subsequent edits require the final repository checks and
independent integration review. Host tests exercise isolated primitives
and refusal paths; they do not establish real guest behavior.

Independent review has covered acquisition, extraction, the private VM
boundary, bootstrap and its bounded continuation, console integrity, the
mechanism harness, and the fixed OCI importer. Runtime approval records,
exact reviewed hashes and private console captures remain under the
worktrees' ignored `.docket/` directories. No hosted PR or CI run exists
because this checkout has no configured remote.
