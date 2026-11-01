# Disposable fixture execution evidence

This records actual work authorized on 2026-11-01 against the
[fixture design](../specs/2026-10-31-first-release-fixture.md) and
[focused mechanism proofs](../specs/2026-10-31-first-release-storage-and-execution.md#focused-proofs-before-product-implementation).
Package and service changes are confined to a local disposable guest.
Host effects are private acquisition/runner files and isolated QEMU
execution. The work does not implement the replacement manager or
establish any A1–A12 product acceptance result.

## Current evidence

| Scope | Observed result |
| --- | --- |
| Acquired inputs, guest bootstrap, Python and AUR builds | Completed; exact identities and upstream test limitations recorded below |
| Native service and starting states | Authenticated checks and separate 209-, 212- and 220-package states completed |
| Journal, protected replay, XML, supervision and bounded retirement | Focused experiments passed, including private Git-object and fixed child-error secrecy checks |
| Native transaction | Frozen prepare-only checks and conflict refusal passed; no package transaction commit inferred |
| Ordinary Docker fixture | Assembly, repeat check and separate restore/reboot check passed; final stopped state ID 41 saved |
| Compose mechanism experiment | All ten asserted checks passed, with the lifecycle limits below |
| Volume, network and image-policy variants | All six completed setup, repeat and reboot checks plus their selected mechanisms; four resource retirements passed; stopped baseline and final states preserved |
| Replacement manager and A1–A12 | Not implemented or executed by this work |

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

The reviewed keyword-only correction was subsequently installed with the
previous helper and both journals preserved. A separate observation
`2f1453f6-483f-4521-ad59-12d9f9edcdb8` then completed with exit zero:
both services passed attributed-listener and pinned-key SFTP reads of
their respective sentinels, with the intended accounts, groups, permissions
and protected keys. Both earlier attempts remain unknown; only this new
observation is complete. A fresh package check still found exactly 209
packages, unchanged repository versions and the intended ack-chain reasons,
with no build manager, cgroup or builder process remaining. Its complete
installed-inventory SHA-256 is
`1ac30726f3831fb0f4e1f182b9977027d656c8dfb7ad89ff5cab51d575350081`.

After orderly shutdown, `native-change` was saved as offline snapshot ID
`5`, with no memory state and firmware variables SHA-256
`116dd2297b2a8f791550bb7a1f653341222b736c29054da100a173aad95c8f31`.
Its checkpoint record SHA-256 is
`5f80c5d3673552ecac5b47e8b1bff11e68a0c22611add0301e22612905840803`.
The separate 128 MiB gitstatus output disk is bound to that record; its
initial SHA-256 is
`13c3cb10476232ef048754e6553227a42b432f7edd1cb119ec4cb29bc8df7c84`.
The snapshot also retains the incomplete image history described below;
it is not an image-ready or product-applied checkpoint.

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

The separate gitstatus build completed with exit zero and its matching
guest UUID. The manager was inactive/dead with success and zero PIDs;
its cgroup was absent and builder UID 1502 had no remaining processes.
The exact build-state inventory was 216 packages, adding only the seven
frozen prerequisites to the 209-package baseline. Source verification,
generated metadata comparison and the non-root build passed. The pinned
recipe defines no check function, so its recorded check status is
`not-defined`.

Gitstatus 1.5.5-1 produced a 1,524,392-byte archive with SHA-256
`d027ab2a60f26688d91ad3ee633baefc735086e4e31522a6f0e81e54b2e73c8b`.
The build record SHA-256 is
`a384abe46896c48aa7cbc091e8a24d312eb505d7f6a7c108e208c09dc229b972`.
The output disk contained matching artifact and record bytes, bound to
the preserved `native-change` checkpoint.

After clean shutdown, `gitstatus-build-complete` was saved as offline
snapshot ID `6`, with firmware variables SHA-256
`69fe94509c387f3b2cb1730e536c3a44a4b83d11f6208233af0bf9879039b29a`.
Offline harvest revalidated the actual artifact and provenance, then
created a read-only 128 MiB return disk with SHA-256
`aaa56edcc9bb459412080854e846c212fb2a3392ab236bd1bc5ef2aa2919e3ba`.
Restoring `native-change` also preserved the prior state as
`before-restore-b3ba14330a1d4cc0`.

The restored guest imported that exact artifact with exit zero and
`installed: false`. The native manifest then bound 218 artifacts, and
the real libalpm 16.0.1 preparation proof completed with exit zero. Its
five prepared additions matched between staged and live preparation;
the live local and sync databases remained unchanged. Missing dependency,
unavailable exact pin, synthetic conflict, partial coordinated upgrade
and scope mismatch all blocked. No installation, hook or upgrade commit
was performed. The earlier frozen audio-package conflict remains separate
from this explicitly synthetic conflict case.

Native adoption subsequently completed with exactly 212 packages and all
prior installation reasons preserved. Only `tmux` and `ripgrep` became new
explicit packages, with `libutempter` recorded as a dependency.
The job's authenticated SSH reads passed before and after installation;
a later read-only collector separately verified current account, data,
unit and listener metadata. Completion UUID and exit zero matched, both
manager PIDs were zero and its cgroup was absent. No product state existed.
The result SHA-256 is
`0d73e3b28258697d535f7a8bb8205f91ee1bfa38a94a0c3ebc01d27db8fc0b46`;
the 212-package inventory SHA-256 is
`bd1c456728854e3cabaab43d7d93249818d2fa7aa01c65f5b31e4eb3fe3ed60c`.
After orderly shutdown, `native-adoption` was saved as offline snapshot
ID `8`, with firmware variables SHA-256
`51d177a74e45bc0faa2c6433ec69813827e25a6092db039fdf4b5e5700c44a46`.

The separate native-update starting state then completed with 220 packages:
all 217 frozen repository packages and the three actual AUR builds. It
preserved the 212 prior reasons, marked the seven added repository packages
as dependencies and gitstatus as explicit, and retained GnuPG 2.4.9-3.
Its authenticated before/after checks, later metadata/listener observations,
completion UUID, exit zero and worker quiescence passed. Product state
remained absent. The result SHA-256 is
`a942120a3d61a8029b98074cab6a2f0e6f090378c1baaa522457d65476f4d642`;
the 220-package inventory SHA-256 is
`4b0663619c190f5de83823f6571707cfa5fa900f08a6ca321d65ef181a8f7b2e`.
After orderly shutdown, `native-update-before` was saved as offline snapshot
ID `9`, with firmware variables SHA-256
`36b4ee16785f54cc2424a9632ef217725a5cb2c5e172384f857be24444168361`.
Restoring `native-change` for the Docker work preserved this prior state
again as `before-restore-de247b4245a24884`.

On the restored native-change guest, a separate diagnostic activation
verified the same engine and three child images, with no containers or
volumes and startup still disabled. Its observation completed successfully;
its overall image state remained unverified. A separately journaled load
of the original-index archive then returned Docker client exit one and
wrapper exit 75. It preserved the prior records and retained the actual
182-byte diagnostic, whose SHA-256 is
`3c15efd23ab2fa788fd8aa890f35ea386e0118fb267e7abdbae7042099979350`.
Docker found the requested linux/amd64 platform but reported missing
content with digest
`4489f0c4579dc9b56b1fd13dc3d4c9aefb38493d1a234ed1cd33d19fd6bdfcdc`.

That digest belongs to the selected Sonarr child's attestation manifest
in the unchanged original index. The versioned Docker/containerd import
code includes selected-platform referrers after platform filtering. A
separate acquisition therefore collected the three selected children's
attestation manifests, configs and in-toto metadata, without acquiring
other architectures' runtime layers. Its completed report has SHA-256
`2e1ab12cc11766ecbde486cdadbc0ef2c51c10ff6547c17006eb6e891ca9cbd4`:
12 descriptor entries correspond to 11 unique blobs and 9,528,772 bytes.
Every blob's digest, size and JSON structure passed independent checking.
This establishes content identity, not publisher-signature verification.

The first supplemental acquisition preserved a partial cache when it
encountered OCI 1.1's inline empty config. The corrected parser accepts
only the exact empty-object descriptor tuple for that form; the later
complete acquisition remains separate from the failed cache.

A separate guest preparation attempted to obtain that exact metadata
closure over HTTPS before constructing and loading a supplemented archive.
It stopped at `acquire-exact-metadata` with `oci_request_deadline` and
wrapper exit 74. The complete serial records the failure and return to
an idle shell. No successful image load or completed preparation is
established by this attempt, and it must not be replayed over its history.

A read-only observation then found one unknown attempt with only its
start record and journal, no acquired blobs and no completed report.
The sampled client/build processes had stopped. DHCP, the default route
and resolver configuration were present; these facts did not establish
external reachability or identify the timeout's cause.

A separate offline preparation used the VM's existing private virtio
control port to receive the exact 11 metadata blobs. Both endpoints
checked their bound identities and content digests. It preserved the
failed HTTPS attempt, its empty metadata tree and all 17 earlier records.
The new archive retained every original index and runtime member, adding
only the selected attestation metadata. It measured 275,486,720 bytes
with SHA-256
`14444448bbaca0838278959a093394c2b2d5f7335272bab682480a8aff4fb9d6`.

Attempt `4fda59ff-a920-453e-b377-d923c5927d79` completed with Docker client
and wrapper exit zero. All three original index references resolved to
the expected linux/amd64 identities and version labels. The engine also
retained its three earlier child images, now without tags or repository
digest associations. No image cleanup was performed. The new result is
`observed-complete`, with result SHA-256
`4bddad8aa55415bd423f5c9d2aa8e289eb48a158f69464a943f2505c7f0c8165`
and closed-journal SHA-256
`0024131b28e8f07ed2baede69069cfa6e9d48fe87b147dfeb35ad32eef4f2285`.
Earlier unknown and unverified outcomes remain unchanged.

The separate manifest-only wrapper then completed with exit zero,
publishing current Sonarr/Radarr associations for the same engine and
guest. Its actual `compose.json` SHA-256 is
`6da996ed7da6d6db6cc92c87684f7c5214755e01d5225560e9a26d928b0b0548`.
Independent review matched these results to complete serial captures
and reconstructed the canonical result and manifest hashes.

The reviewed resume and four variant helpers were installed with exact
hashes and `executed: false` receipts. After orderly shutdown,
`image-ready` was saved as offline snapshot ID `11`, with no memory state
and firmware variables SHA-256
`51d177a74e45bc0faa2c6433ec69813827e25a6092db039fdf4b5e5700c44a46`.
Cold resumption then completed with exit zero: the same engine and all
six image views matched, all 27 recorded hashes remained unchanged, and
containers/volumes were absent with only default networks and disabled
startup. Independent review verified the complete capture and checkpoint.

The ordinary Sonarr/Radarr baseline subsequently completed with exit zero,
followed by a separate successful check. Both used the expected original
image references, application UID 963/GID 1001 and attributed listeners.
The checks verified configuration values, declared ownership/modes,
supplemental sentinel reads under copied credentials, and Radarr's actual
authenticated root-folder accessibility and sentinel-directory discovery.
Application serialization changed XML bytes while preserving the checked
protected and unmanaged values. These observations establish directory
discovery, not media-file reads or imports. Docker startup was enabled
for this application fixture.

After orderly shutdown, `docker-adoption` was saved as offline snapshot
ID `12`, with no memory state and firmware variables SHA-256
`36b4ee16785f54cc2424a9632ef217725a5cb2c5e172384f857be24444168361`.
The repeat check preceded shutdown. Restoring `image-ready` for the distinct
Compose proof preserved the application state again as
`before-restore-36e63e5d95ef4abe`.

A later independent restore of `docker-adoption` ID `12`, boot and
check-only run passed with exit zero. No assembly or image-resume helper
was replayed. Fresh attribution and readiness checks, configuration/data
checks, copied-credential sentinel reads and authenticated Radarr directory
discovery passed. After orderly shutdown,
`docker-adoption-reboot-verified` was saved as offline snapshot ID `41`,
with no memory state and firmware variables SHA-256
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.

The separate Compose proof then passed with exit zero on a fresh,
successfully resumed `image-ready` branch. Captured rendering, runtime
environment and dollar literals matched. The harness kept the container
by skipping mutation for satisfied state and for a tag-to-digest change
resolving to the same image; this does not establish Compose's own
reconciliation behavior if `up` is invoked after that string change.
Stopping Sonarr before its port edit preserved the container and checked
protected/unmanaged values after restart. Serialization did not change
after this edit/restart, unlike the initial ordinary-baseline observation.

The proof retained Sonarr data after retirement and verified Radarr's
actual shared-directory discovery. Intervening configuration and protected
input changes blocked. An actual daemon-owned container survived a killed
worker, and its unknown attempt blocked overlap. Scoped container cleanup
did not complete that attempt. All ten asserted mechanism checks passed;
independent review matched the source and complete serial evidence.

After orderly shutdown, `compose-mechanism` was saved as offline snapshot
ID `14`, with no memory state and firmware variables SHA-256
`36b4ee16785f54cc2424a9632ef217725a5cb2c5e172384f857be24444168361`.
Restoring `image-ready` for the first supplemental variant preserved it
again as `before-restore-1a33f6a4e0fd40e0`.

The first `volume-keep` assembly stopped with exit 73 at
`docker_variant_config_credential_check_failed`. A separate read-only
diagnostic reproduced `ENOENT` from the verifier's namespace lookup after
entering each container's mount namespace. A namespace directory held by
the child before entry still verified the intended namespace. Copied
credentials, sentinel contents/metadata, database metadata and empty
extended attributes passed for both applications. Radarr's bind-backed
config directory matched mode `2770`; Sonarr's named-volume root instead
had mode `0770`, exposing a second, independent unmet predicate.

The diagnostic preserved one unknown setup attempt, its sole start event,
ten protected records and the existing baseline bytes. It established
the observed metadata, rather than which initialization step omitted or
removed setgid. No successful volume assembly is claimed. After orderly
shutdown, this state was saved as `failed-volume-keep-credentials`,
offline snapshot ID `16`, with no memory state and firmware variables
SHA-256
`36b4ee16785f54cc2424a9632ef217725a5cb2c5e172384f857be24444168361`.
Independent review verified the diagnostic and preserved checkpoint.

The reviewed source correction holds the child's own namespace directory
before entering the container namespace and verifies the result through
that descriptor. Volume initialization now runs with the intended group
and requires actual owner/group/mode `963:1001:2770` before continuing.
It adds no capability and keeps the later mode check unchanged. These
changes address the observed failures without claiming which old
initialization step lost setgid.

The separate delivery procedure accepts only the pristine image state,
verifies the complete helper dependency set and preserves the original
helper with a durable receipt before replacement. Source and delivery
review remain distinct from guest execution.

The actual replacement then completed with exit zero and an idle prompt,
recording `executed: false` for the corrected helper. All 27 history/input
hashes matched, and supplemental resumption remained unused. After
orderly shutdown, `image-ready-variants-v2` was saved as offline snapshot
ID `18`, with no memory state and firmware variables SHA-256
`36b4ee16785f54cc2424a9632ef217725a5cb2c5e172384f857be24444168361`.
Independent review verified the exact serial interval, replacement
receipt and stopped checkpoint. The original image checkpoint and the
failed volume checkpoint remain preserved.

On a fresh branch of the corrected checkpoint, cold resumption passed
with the same image and history bindings. Its subsequent `volume-keep`
setup returned `unverified`, code `docker_variant_failed`, and exit 74.
Independent review verified the fresh serial interval and idle prompt.
The generic result establishes neither the cause nor successful assembly;
the running guest and failed attempt were retained for separate diagnosis.

A separate protected-output proof then completed with exit zero on that
idle guest. It used its own private journal and invoked no application
or lifecycle operations.
The new helper's exact installation receipt preceded its one-shot run.
Its private Git repository contained exactly one commit, tree and blob;
all objects were reachable, and neither the exported projection nor any
object contained the synthetic secret or protected reference material.
Fixed child processes actually emitted the sentinel on both output
streams before the failure, output-bound and timeout paths returned
their expected public codes without it. These checks cover the selected
projection and command boundaries, not arbitrary future product errors.
They spawn no descendants and establish no daemon-recovery guarantee.
The fresh completion interval has SHA-256
`7e1e69b2ec253beb2ede9249b7c2cdefc405dfd7c2fcc4a209209cf6dda6b5d5`.
Independent review verified the source, installation and actual result.

A separate stage diagnostic completed with exit zero and passed all 15
current engine, image, container, process, configuration-access, resource
and sentinel probes. Both assembled XML files existed, but `baseline.json`
was absent and Docker startup remained disabled. The journal still held
one unknown attempt, one start event and ten protected records, with
unchanged SHA-256
`45444ade45e2cf2e39c43012382c4759001a6022b0623cb3ccdfc200d8abb46f`.
The diagnostic made no application requests and did not read XML contents.
These current observations verify the corrected access predicates; they
do not reconstruct the original exception or complete the setup attempt.
Independent review verified the fresh interval and preserved records.

A separately reviewed diagnostic then issued only attributed Radarr GET
requests. Naming returned HTTP 200 with the expected object and format;
the root-folder list returned HTTP 200 and an empty array. Credential
bindings, listener attribution and the prior journal hash remained valid.
The observed absence of a current registration does not reveal the lost
POST response or establish its cause. No registration was replayed.
Independent review matched the result to its fresh serial interval,
exit zero and idle prompt.

After orderly shutdown, `failed-volume-keep-stage-v2` preserved this
failed setup, its diagnostics and the completed protected-output proof
as offline snapshot ID `20`, with no memory state. Its firmware variables
SHA-256 is
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.
Independent review verified shutdown, the checkpoint and saved firmware.

The next reviewed helper validates response status and object shape
before field access. Its failure report includes only a fixed setup
stage, bounded error category/errno and trusted source coordinates, plus
safe HTTP status/type when available. It retains no raw response or
exception message and adds no retry or lifecycle action. These changes
improve future observations without reclassifying the old failure.

On a fresh restore of original `image-ready`, the reviewed replacement
completed with exit zero, preserved all 27 history/input hashes and
recorded `executed: false` with supplemental resumption still unused.
After orderly shutdown, `image-ready-variants-v3` was saved as offline
snapshot ID `22`, with no memory state and firmware variables SHA-256
`36b4ee16785f54cc2424a9632ef217725a5cb2c5e172384f857be24444168361`.
Independent review verified the replacement receipt, serial interval,
shutdown and saved checkpoint before a fresh variant branch began.

The fresh `volume-keep` setup completed with exit zero. Its exact named
volume had only the recorded Sonarr consumer; both applications passed
image, process, configuration-access and shared-sentinel checks, including
the required configuration mode `2770`. Actual Radarr directory discovery
passed, and Docker startup was enabled. Independent review matched the
result to the fresh serial interval and source. This successful attempt
does not recover the cause of the earlier generic failure.

Its separate check also returned exit zero with the same complete result.
After orderly shutdown, the `volume-keep` assembly baseline was saved as
offline snapshot ID `24`, with no memory state and firmware variables
SHA-256
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.

The separate check-only reboot also passed. The same container, image,
volume, data and configuration bindings survived, with fresh process and
listener attribution and successful Radarr discovery. Independent review
verified the stopped checkpoint and the complete reboot-check interval.
No setup or supplemental resumption was replayed on this assembled state.

The separate port experiment then completed with exit zero. Sonarr
restarted in the same container on port `18990`; Radarr's complete
process/container observation remained unchanged. Volume identity,
configuration semantics, data/access checks and actual Radarr discovery
passed. The original assembly database and manifest stayed unchanged;
the experiment used a separate mechanism journal. Independent review
verified the source and fresh completion interval.

Keep-volume retirement then completed with exit zero. Sonarr was removed,
while the same named volume, protected configuration, sentinel and
readable database metadata were retained. Inspection used a fixed offline
helper without restarting Sonarr. Radarr's attribution and actual
directory discovery stayed valid, and the shared sentinel and earlier
assembly/port records were preserved. Independent review verified the
complete sequence through retirement.

After orderly shutdown, `volume-keep-mechanism` was saved as offline
snapshot ID `25`, with no memory state and firmware variables SHA-256
`4ba5f05f3fe1214089e691d3c9887bf67e4ebacb9e92ef0743ac6271d16beddd`.

On its own fresh branch, `volume-delete` setup and the separate check
both passed with identical complete observations, including its sole
Sonarr volume consumer and actual Radarr discovery. After orderly
shutdown, the `volume-delete` baseline was saved as offline snapshot
ID `27`, with no memory state and firmware variables SHA-256
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.
Independent review verified both checks, shutdown and the saved baseline.
Its check-only reboot then passed with the same container, image, volume
and configuration bindings, expected data metadata and sentinels, fresh
process/listener attribution and successful access and Radarr discovery.
The complete reboot interval was
independently verified before the port experiment.
That experiment also passed: the same Sonarr container restarted on
`18990`, Radarr's complete attribution remained unchanged, and resource,
configuration/access and discovery checks passed with unchanged assembly
history. Independent review verified its fresh completion interval.
Exclusive-volume retirement then passed. The recorded Sonarr container
and declared named volume were removed after consumer/identity checks,
with actual absence and final inventory verified. Radarr's attribution,
directory discovery, shared sentinel and prior history remained valid.
After orderly shutdown, `volume-delete-mechanism` was saved as offline
snapshot ID `28`, with no memory state and firmware variables SHA-256
`4ba5f05f3fe1214089e691d3c9887bf67e4ebacb9e92ef0743ac6271d16beddd`.

The independent `network-shared` branch passed setup and a separate
check with identical complete observations. Its bridge had exactly the
two expected consumers. Application namespace/listener attribution,
protected configuration/access and actual Radarr discovery passed.
Authenticated requests used held application network namespaces;
separate published-route checks carried no credential and verified the
declared loopback mappings. After orderly shutdown, the `network-shared`
baseline was saved as offline snapshot ID `30`, with no memory state
and firmware variables SHA-256
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.

The check-only reboot passed with the same network and two attachments,
image/configuration bindings and expected data checks. Fresh application
process, namespace and listener attribution passed, alongside protected
access, Radarr discovery and credential-free published routes. Independent
review verified the saved baseline and full reboot-check interval.
The port experiment also passed, recreating Sonarr for the `18990`
published mapping. The network identity, IPAM and options persisted with
the new Sonarr and unchanged Radarr attachments. Radarr's complete process
and listener observation remained unchanged. Configuration/data, attributed
requests, published routes and discovery passed, with the original
assembly history preserved. Independent review verified the result.
Shared-network retirement then passed: Sonarr was removed, while the
same bridge, IPAM and options remained with only the original Radarr
attachment. Radarr's attribution, actual directory discovery and
credential-free published route stayed valid, with shared data and prior
history preserved. After orderly shutdown, `network-shared-mechanism`
was saved as offline snapshot ID `31`, with no memory state and firmware
variables SHA-256
`4ba5f05f3fe1214089e691d3c9887bf67e4ebacb9e92ef0743ac6271d16beddd`.

The separate `network-exclusive-delete` branch passed setup and its
identical repeat check with Sonarr as the sole bridge consumer. Image,
process/namespace/listener attribution, configuration/access and the
credential-free published route passed. Radarr was deliberately absent;
no Radarr discovery result is claimed for this branch. After orderly
shutdown, `network-exclusive-delete` was saved as offline baseline ID
`33`, with no memory state and firmware variables SHA-256
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.

Its check-only reboot passed with the same bridge and sole consumer,
image/configuration bindings and data checks. Fresh process, namespace,
listener, access and published-route checks passed. Independent review
verified the saved baseline and complete reboot interval; Radarr remained
absent as declared.
Its port experiment passed, recreating Sonarr for `18990` while retaining
the bridge with only the replacement consumer. Image/configuration,
data/access and published-route checks passed, with the original assembly
history unchanged. Independent review verified the result.
Exclusive-network retirement passed after the final consumer check.
The exact Sonarr container and bridge were removed; actual absence,
default-network inventory and closed published routes were verified.
Shared native data, retained source/configuration and earlier history
remained valid. After orderly shutdown,
`network-exclusive-delete-mechanism` was saved as offline snapshot ID
`34`, with no memory state and firmware variables SHA-256
`4ba5f05f3fe1214089e691d3c9887bf67e4ebacb9e92ef0743ac6271d16beddd`.

The independent allowed-tag branch initialized fresh data under Sonarr
`4.0.19.2979-ls322`. Setup and its identical separate check passed with
the expected Radarr, configuration/access and discovery checks. The
wanted `latest` tag with updates allowed remained separate from the
frozen older execution digest and accepted newer candidate. This does
not establish live resolution of the current remote tag. After orderly
shutdown, `docker-update-allowed-tag-before` was saved as offline
baseline ID `36`, with no memory state and firmware variables SHA-256
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.

Its check-only reboot passed, retaining the older Sonarr identity,
expected Radarr, configuration/data checks and unchanged wanted policy,
with fresh process/listener attribution, access and discovery. Independent
review verified the saved baseline and full reboot interval before the
explicit forward-update experiment began.
The explicit update then passed, replacing Sonarr with the accepted
`4.0.20.3014-ls1` image while preserving the wanted `latest`/updates-allowed
policy. Radarr's complete attribution and discovery stayed valid, and
the original assembly history remained unchanged. XML bytes changed,
while the checked protected/unmanaged values and ownership/mode were
preserved. Database checks establish a nonempty regular file with expected
ownership and no world-write bit, plus application readiness. They do not
establish an internal migration
trace, full database-content integrity or downgrade safety.
Independent review verified the actual result and these limits.

After orderly shutdown, `docker-update-allowed-tag-mechanism` was saved
as offline snapshot ID `37`, with no memory state and firmware variables
SHA-256
`4ba5f05f3fe1214089e691d3c9887bf67e4ebacb9e92ef0743ac6271d16beddd`.
Independent review verified the saved result and checkpoint.

The first exact-digest branch passed its fresh cold resume, then setup
returned `unverified`/exit `74` at `radarr_naming_get`. The bounded failure
record identifies `FileNotFoundError`, errno `2`, while reading a symlink
from the application's enumerated `/proc/<pid>/fd` directory. This was
the second attribution check before constructing or dispatching the
naming request. No naming GET or root-folder POST was sent at that stage.
The record does not identify which descriptor disappeared or establish
its cause. Earlier assembly effects remain unresolved; setup was not
replayed and the failed state is preserved. This evidence does not explain
the earlier generic volume-keep failure.

After orderly shutdown, `failed-exact-digest-attribution` was saved as
offline snapshot ID `39`, with no memory state and firmware variables
SHA-256
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.

The reviewed correction skips only `ENOENT` from reading an individual
enumerated descriptor symlink. Missing directories/processes, other
errors and absent listener ownership still block. It additionally
rechecks process start time, namespaces, executable and listener set
after enumeration. No request, setup or lifecycle retry was added.
Focused regressions include an actual descriptor-symlink disappearance,
lost listeners, identity changes and refusal before HTTP dispatch.
This closes the observed enumeration boundary without identifying the
specific descriptor lost in the failed run.

On an independent restore of the original image-only ID `11`, the
code-only replacement passed with exit zero and `executed: false`.
It installed helper SHA-256
`1515a3b8ebd888c8bc1e555ed94c8c2606d64358e39230d5b80bf74e2589f447`,
preserving all 27 prior image-history hashes and the unused resume state.
After orderly shutdown, `image-ready-variants-v4` was saved as offline
snapshot ID `43`, with no memory state and firmware variables SHA-256
`36b4ee16785f54cc2424a9632ef217725a5cb2c5e172384f857be24444168361`.
The failed exact-digest state in ID `39` was not replayed.

The fresh ID `43` branch passed its cold resume, one-shot exact-digest
setup and identical separate check. It initialized independent older
Sonarr data under the declared exact digest, with updates disabled and
the newer candidate kept separate. Both application identity/readiness,
configuration/data checks and Radarr directory discovery passed.
After orderly shutdown, `docker-exact-digest-before` was saved as offline
baseline ID `45`, with no memory state and firmware variables SHA-256
`850fb33fbf7a3376a3f9acb5df8471c3906ed7b4ace6d9e02b889e99ff078f89`.
Its check-only reboot passed with the same exact image policy, resources,
data and configuration, fresh application attribution and working Radarr
directory discovery. Independent review verified the full sequence.

The candidate-refusal experiment then passed with exit zero. The declared
older exact digest with updates disabled blocked the newer candidate,
reporting `image_change_requested: false`. This branch issued no stop,
recreation or image-change operation. Before/after application and resource
observations matched, with original assembly database and manifest bytes
preserved. This proves the selected exact-digest/disabled-update policy;
it does not exercise every independent policy combination.

After orderly shutdown, `docker-exact-digest-mechanism` was saved as
offline snapshot ID `46`, with no memory state and firmware variables
SHA-256
`4ba5f05f3fe1214089e691d3c9887bf67e4ebacb9e92ef0743ac6271d16beddd`.
Independent review verified the refusal result, saved checkpoint and
firmware. The guest is stopped. All six selected variant sequences and
the separate ordinary-fixture reboot check are complete; earlier failed
attempts remain preserved under their original outcomes.

The supplemental runtime gates currently stand as follows:

| Variant | Assembly | Reboot check | Experiment | Retirement |
| --- | --- | --- | --- | --- |
| Volume keep | Setup and check passed; baseline ID 24 saved | Passed | Port change passed | Passed; final ID 25 saved |
| Volume delete | Setup and check passed; baseline ID 27 saved | Passed | Port change passed | Passed; final ID 28 saved |
| Shared network | Setup and check passed; baseline ID 30 saved | Passed | Published-port remapping passed | Passed; final ID 31 saved |
| Exclusive network deletion | Setup and check passed; baseline ID 33 saved | Passed | Published-port remapping passed | Passed; final ID 34 saved |
| Allowed-tag image update | Setup and check passed; baseline ID 36 saved | Passed | Forward update passed; final ID 37 saved | Not required |
| Exact-digest candidate refusal | Fresh setup and check passed; baseline ID 45 saved; earlier failure preserved | Passed | Candidate refused; final ID 46 saved | Not required |

Applied product restore points remain unavailable until actual product
operations create them.

## Verification and limits

Repository setup selected Python 3.12 and enabled the tracked hooks via
the authorized elevated Git configuration operation. At checkpoint
`e75d90c`, the combined checks passed 193 tests, syntax,
eight queue entries and relative links. Final integration checks and
independent review are recorded separately with the reviewed revision. Host tests
exercise isolated primitives and refusal paths; they do not establish
real guest behavior.

Independent review has covered acquisition, extraction, the private VM
boundary, bootstrap and its bounded continuation, console integrity, the
mechanism harness, and the fixed OCI importer. Runtime approval records,
exact reviewed hashes and private console captures remain under the
worktrees' ignored `.docket/` directories. No hosted PR or CI run exists
because this checkout has no configured remote.
