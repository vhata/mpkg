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

The first Docker readiness attempt refused a startup-property mismatch
before creating a journal, drop-ins, sockets, engine directories or daemon
processes. A read-only diagnostic verified the packaged commands and
found that `systemctl show` omitted empty `EnvironmentFiles` values even
with `--all`. Separate fixed D-Bus queries then returned the exact typed
empty list for Docker, containerd and SSH. The reviewed correction accepts
the omitted display only after that positive typed observation; nonempty,
conflicting, malformed or failed observations still block. Corrected
service startup remains a separate runtime gate.

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

The supervised Python 3.12.16 build completed with numeric exit zero,
the matching guest completion UUID, and manager result `success` with
`active/exited` state. Both manager PIDs were zero, its cgroup was absent,
and the dedicated builder UID/GID 967 had no surviving process. The
staged tree contained 8,380 entries and 8,027 regular files totaling
329,356,391 bytes. Publication retained root ownership and checked SSL,
SQLite, bz2, lzma, zlib, ctypes, readline and GDBM. The recorded compiler
was GCC 16.2.1; runtime libraries reported OpenSSL 3.6.5 and SQLite 3.54.0.
The installed-tree SHA-256 is
`d234281388c58ec427b11c66358a4c7fbdd8798f63777b20b2c59baa8b594683`;
the private result JSON SHA-256 is
`e660c3e8556869896ceb67dafbd601e7eaa6b21457c72c6f49b733c27596a3b1`.
The repository package inventory remains 207.

After clean shutdown, `python-ready` was saved as offline snapshot ID `2`,
with no memory state and firmware variables SHA-256
`07a4bc9434242842fe724a86bcf69b0212006a3385b10e384fab7dec8084dd72`.

The first five mechanism experiments returned observed results and the
combined entrypoint returned exit zero:

| Experiment | Actual observation and limit |
| --- | --- |
| Journal | Five start/effect/completion cases preserved not-started, unknown and observed-complete distinctions; process exits and SQLite query-only faults do not test power loss |
| Protected inputs | Exact replay succeeded, drift blocked, exports omitted the secret sentinel, failed capture published no reference, and restored history neither authorized recovery nor rolled back external effects |
| XML | Stale and intervening edits blocked while unrelated bytes survived; this used synthetic XML and still requires exclusive writer maintenance |
| Retirement | Changed consumers, new descendants and a same-filesystem bind mount blocked deletion; a fresh disposition removed two entries, the shared sentinel survived, and the injected partial outcome remained unverified |
| Supervision | Killing the controller left manager-owned work running; overlap was blocked for both supervised work and a surviving child; the orphan case remained unknown after its child effect |

These results do not establish real Sonarr editing, Docker daemon recovery,
or product retirement.

The separate frozen conflict proof reproduced the 167-package metadata
resolution, then libalpm 16.0.1 actually rejected preparation with result
`-1`, error `46` (conflicting dependencies), identifying the exact pair
`pulseaudio=17.0+r134+g77d25a1e6-1` and
`pipewire-pulse=1:1.6.10-1`. Its private local database was empty;
there were no fetch calls, removals or accepted questions. The proof
returned observed with console exit zero. It used the hash-bound
October 30 databases without acquiring conflict archives or importing
the installed package state, and never requested transaction commit.

The first offline AUR chain built `perl-file-next` 1.18-7 and passed its
recipe checks, producing a 14,697-byte archive with SHA-256
`16aed58ad66d473949975603458f880e625709612537466a36e041dc0d5b40d0`.
It installed that package, then refused to build `ack` because generated
metadata differed from the pinned `.SRCINFO`. The exact difference was
only `url`: the pinned metadata used `http://betterthangrep.com/`, while
the pinned PKGBUILD generated `http://beyondgrep.com/`. Every other
normalized field matched. The job exited one with no completion marker;
both manager PIDs were zero and no cgroup or builder process survived.
All 207 repository versions remained unchanged, with only the new
dependency installed as explicit because the later reason adjustment
had not run. This partial state was preserved in the stopped
`failed-ack-metadata` checkpoint before investigating a bounded fix.

After restoring `python-ready`, the corrected ack chain completed with
exit zero, the matching completion UUID, manager success and no remaining
manager, cgroup or builder process. The exact inventory is now 209:
all 207 repository versions unchanged, `ack` 3.10.0-1 explicit and
`perl-file-next` 1.18-7 recorded as its dependency. The successful run
produced these actual archives:

| Package | Bytes | SHA-256 |
| --- | --- | --- |
| `ack` | 76,354 | `afe240b17938cac7ee08d4ce0053cc96537b96b0c012f191c1d62d3929614e0b` |
| `perl-file-next` | 14,703 | `f6fe090774f472dc2bbb751750178aa6316a3b4fe7ceb0f833bc5ff28d16ab8b` |

The worker recorded the ack metadata mismatch and its exact URL/hash
reconciliation explicitly. It did not change the frozen recipe files.
Upstream test output reported PASS for 16 files/92 tests in File::Next
and for each of ack's classic and standalone passes at 70 files/847 tests.
Coverage exclusions remain visible: File::Next skipped its two POD checks
without Test::Pod/Test::Pod::Coverage; each ack pass skipped `ack-group`,
`ack-output-color`, `ack-pager` and `interactive` without IO::Pty. The
collector read the entire stable 18,106-byte log without omitting summary
lines. A successful recipe check does not claim those skipped tests ran.

Native service setup then stopped during `useradd` argument parsing after
native-group creation and before user creation. The observed state contained
no fixture users, homes, keys, data or service changes, and retained one unknown
bootstrap attempt. Dropped-privilege help probes reproduced exit three
for `-K CREATE_MAIL_SPOOL=no`, while plain help returned zero; account
metadata did not change. The actual package defaults already disable mail
spools. A separately reviewed continuation preserved that unknown attempt
and accepted only this exact partial state. It created the fixture accounts,
keys, data and service configuration, then exited 73 at the effective SSH
configuration check. Its own attempt also remains unknown.

A read-only diagnostic found both fixed configurations unchanged and both
services enabled and running. OpenSSH's effective-output keywords use
different capitalization: each of the 14 expected fields appeared exactly
once when compared without keyword case, with its value matching exactly
for both roles. No value normalization was needed. This identifies a parser
compatibility defect; it does not establish successful authenticated access
or retrospectively complete either interrupted attempt.

Corrected Docker readiness completed with exit zero on engine
`bb861e7c-3db2-4b9a-a865-6a2e04af426c`, Docker 29.9.2 and containerd 2.4.2-1.
Packaged unit, daemon process and Unix-socket identities passed, with zero
images, containers and volumes. Startup remained disabled.

The local OCI load completed, but its association check returned exit 75
and remained unverified for all three original index references. Read-only
inspection found exactly the three acquired amd64 manifest IDs, their
matching repository/child digest associations and the fixed fixture tags;
original index and config-digest lookups were unavailable. The acquisition
archive's top-level descriptors point to those children, although its
verified blobs also contain the original indexes. Any further preparation
must retain the original unverified result and independently establish the
required runtime association. No application container has been started.

The separate original-index preparation verified the existing blobs and
produced a 265,943,040-byte archive with SHA-256
`828001d7783098d69a87f84851883dc101da4023050a23c3d084614ca3a19bd3`.
It then exited 73 with `fixed_tool_failed`, without a final result. Its
attempt is unresolved; the archive's successful construction does not
establish a successful Docker load or association. The command wrapper
did not retain stderr, so the exact failing command's diagnostic is
unavailable. Further inspection must preserve this attempt as well as the
original unverified import.

The gitstatus build, native service fixture and complete image bindings
remain unverified. Applied product restore points remain unavailable until
actual product operations create them.

## Verification and limits

Repository setup selected Python 3.12. At checkpoint `6f015c1`, the
coordinator's combined checks passed 93 tests, syntax for 80 files, eight
queue entries and relative links. Subsequent edits require final checks and
independent integration review. Host tests exercise isolated primitives
and refusal paths; they do not establish real guest behavior.

Independent review has covered acquisition, extraction, the private VM
boundary, bootstrap and its bounded continuation, console integrity, the
mechanism harness, and the fixed OCI importer. Runtime approval records,
exact reviewed hashes and private console captures remain under the
worktrees' ignored `.docket/` directories. No hosted PR or CI run exists
because this checkout has no configured remote.
