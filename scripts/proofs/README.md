# Disposable execution mechanism experiments

These are experiments for the
[storage and execution proposal](../../docs/specs/2026-10-31-first-release-storage-and-execution.md),
not the replacement manager or A1–A12 acceptance tests. Repository
checks exercise their local primitives with temporary files and SQLite.
Actual systemd, libalpm and Docker observations require the separately
assembled disposable Arch guest and independent review of this code.

## Execution boundary

The runner installs the reviewed files, owned by root and not writable
by other users, under `/opt/mpkg-proofs`. It supplies Python 3.12 at
`/opt/mpkg-python/3.12.16/bin/python3.12`. No script installs packages,
pulls images, fetches sources or creates a VM. There is no host fallback.

Every guest entrypoint requires root, Python 3.12, a regular root-owned `0600`
marker at `/etc/mpkg-fixture/identity.json`, and an independently supplied
expected UUID matching QEMU's DMI product UUID. The mounted root's actual
major/minor must identify `/dev/vda2`, whose parent disk has the bound
serial and 40 GiB capacity. This also refuses the live installer ISO.
The marker is exactly:

```json
{"schema":1,"guest_id":"<runner UUID>","fixture_id":"first-release-2026-10-31","disposable":true,"disk_serial":"mpkg<first 16 UUID hex digits>","disk_bytes":42949672960}
```

The runner sets QEMU's UUID; copying a marker onto another machine is
insufficient. This protects against accidental execution on the server,
not a malicious root who can replace the code or fabricate observations.
No host mounts, shared Docker socket or public inbound forwarding are
part of the runner interface. Transfer uses its private serial channel.

After review, invoke a single named experiment through that channel:

```text
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/run.py run --guest-id <runner UUID> --proof journal
```

The proof selector is closed: `journal`, `inputs`, `xml`, `retirement`,
`supervision`, `native`, or `compose`. Internal `worker` and `launch`
entrypoints accept only fixed cases and UUIDs. They cannot execute a
caller-provided command, unit body, module or script. The C probe also
checks the marker, DMI identity and a delegated pipe before libalpm use.

Each experiment requires its own unused directory beneath
`/var/lib/mpkg-proofs/<UUID>`. A repeated experiment requires an explicit
fresh guest restore point; the harness does not erase prior evidence.
Results are sanitized JSON with `product_acceptance: false`. Failure
does not authorize rollback, another attempt or cleanup of unknown work.

## Experiments and limits

| Experiment | Concrete observation | Limit |
| --- | --- | --- |
| Journal | Child exits before/after durable start and external file effect; rejected start/completion writes; unknown start blocks another attempt | Process death and SQLite query-only faults are not power-loss or filesystem durability certification |
| Inputs | Protected capture/replay, drift, private projection, SQLite `SQLITE_FULL`, quarantined history restoration that cannot authorize work or undo external effects | Plaintext private history; restoration uses an explicit helper, not arbitrary root replacement of database files |
| XML | Preserve all bytes outside the supported Port text, ownership/mode, comments and protected/unmanaged fields; reject stale or intervening edits | Only Port is implemented; exclusive writer maintenance is an explicit prerequisite |
| Retirement | Retained/shared and exclusive data, changed descendants/consumers, same-filesystem bind-mount refusal, partial deletion and a fresh remaining-scope disposition | Bounded directories and declared consumers, not every native or Docker resource kind |
| Supervision | Kill initiating CLI while its systemd service completes; kill worker while a child continues; unresolved work blocks another attempt | Real manager behavior is established only by guest execution |
| Native | Stage frozen metadata and a real coordinated upgrade; reprepare under the guest package lock; compare installed versions/reasons and prepared effects; reject exact-pin, dependency, conflict, omitted-upgrade and scope mismatches | Prepare-only: no commit, hook, installation-reason change or coordinated upgrade execution is claimed |
| Compose | Captured relative inputs retain canonical render and runtime env/dollar semantics; skip mutation for satisfied state; stop/edit/start same Sonarr container; actual Radarr shared-directory discovery after Sonarr retirement; daemon container survives killed worker | Exact preacquired images, host networking and bind paths only; no arbitrary Compose document support or volume/network coverage |

XML rejects DTDs, duplicate elements, nested structures, hardlinked files
and access metadata it cannot preserve. Same-directory replacement is
durable at the file/directory synchronization boundaries; it is not an
atomic compare-and-swap against an unrelated editor. The stopped Sonarr
experiment checks protected and unmanaged semantics after application
startup and reports serialization changes separately.

Radarr uses generated fixture-only API credentials and the fixed
root-folder API from version 6.4.4.10685. A request first attributes the
loopback listener to the container's actual application process. Root
folder setup is a separate write, including Radarr's temporary writable
file and database row. Subsequent GET checks require the exact synthetic
unmapped directory. They prove directory discovery, not media contents,
imports or downloads. Its server-side timeout does not cancel filesystem
work; a failed functional check stops the experiment.

Authenticated HTTP uses a private child with a whole-request deadline,
not only an inactivity timeout. All IPv4 listeners covering the target
must belong to the selected application; this IPv4 fixture refuses any
IPv6 listener on that port. Credentials never enter argv, output or
core dumps. Listener/process identity is checked around the request.

The Compose experiment intentionally retains Radarr and Sonarr's kept
configuration for inspection. The separate daemon uncertainty case
cleans up only its exact container and leaves its journal unresolved;
container cleanup does not invent a successful interrupted attempt.

## Bound inputs

### File-only image acquisition

`oci_acquire.py` is a separate host preparation tool. It uses anonymous
HTTPS to acquire only the three fixed Sonarr/Radarr image identities.
It has no Docker/socket call, archive extraction or executable payload
operation. Run it with Python 3.12 and an explicit ignored private cache:

```text
.venv/bin/python -I scripts/proofs/oci_acquire.py --cache /home/vhata/src/mpkg/.cache/fixture-oci
```

It verifies index/selected-manifest identity, config platform/version,
and every selected layer's exact size and SHA-256. Tokens and signed
redirect queries remain in memory; credential headers never cross
hostnames. Requests have byte and whole-request time bounds. Partial
downloads remain private and are never published as complete artifacts.
The tool does not automatically retry failed requests.

The cache contains immutable blob bytes and a new snapshot directory
with `images.oci.tar` and sanitized `acquisition.json`. The archive's
root index references only the selected amd64 images; original source
indexes are retained as provenance blobs, without acquiring their other
platforms. Only the bound closure is archived, even if the cache has
unrelated blobs. No downloaded archive is extracted on the host.

Digest identity does not establish publisher signature trust. Copy the
archive and acquisition report to `/opt/mpkg-proof-inputs` as root-owned
private files through the reviewed input disk or transfer interface.
`image_import.py --guest-id <UUID>` verifies the bound archive digest,
size and image identities, then journals a single fixed guest Docker
`image load --platform linux/amd64` using its held archive descriptor.
It never pulls, retags, starts a container or contacts an external
registry. Timeout leaves an unresolved attempt without automatic retry.

Guest Docker's OCI import and original RepoDigest association must be
observed; the acquisition report does not claim either. Import reports
an explicit unverified result if those associations are missing. A
guest-only offline registry would be a separately reviewed preparation
step, never an automatic fallback. After reviewed successful import,
`image_manifest.py --guest-id <UUID>` checks the guarded guest engine and
local image associations and records `compose.json`. If associations are
missing it refuses; it does not repair them by pulling or retagging.

### Guest proof manifests

The runner provides root-owned manifests under `/opt/mpkg-proof-inputs`.
They must be reviewed along with the acquisition/assembly evidence.

`compose.json` contains `schema: 1`, the exact `guest_id` and the guest
Docker `engine_id`. The code binds the observed Sonarr and Radarr index
digests and verifies local platform/config identities. It requests
`--pull never` and `--no-build`; missing images fail instead of fetching.
Ports 19891–19893 and the private project names must initially be unused.

`native.json` contains:

- `schema: 1`, `guest_id`, and the expected `libalpm_version`.
- `repository_databases`: exactly `core` and `extra`, each with `name`,
  confined `path` and `sha256`; optional `signature` uses the same
  path/digest record format.
- `artifacts`: exact `name`, `version`, confined `path`, `sha256`, and
  `source` (`repository` or explicitly trusted `fixture-build`).
- `targets`: package names including the agreed repository and AUR
  additions. The baseline must leave `libutempter` missing so omission
  of its artifact exercises a real unresolved dependency.
- `exact_versions`: the accepted exact version for each target.
- `coordinated_upgrade`: `name`, `from` and `to`, binding the real frozen
  `gnupg` 2.4.9-3 to 2.4.9-4 upgrade. The guest starts from October 30;
  staged metadata and artifacts use the October 31 target closure.

All artifact paths remain below `/opt/mpkg-proof-inputs`. Repository
archives must have usable signature sidecars and the guest keyring;
libalpm requires their signatures. Unsigned fixture-built artifacts have
an explicit different source classification and prior trust decision.
The conflict case adds a disclosed synthetic archive conflicting with
`filesystem`; it is prepared but never installed. No native transaction
commit or database-refresh function exists in the C probe.

`native_manifest.py --guest-id <UUID>` records this manifest only in the
bound guest. It requires the exact frozen `source-inventory.json`, actual
`native-acquisition.json`, target databases under `databases/2026-10-31`,
and archives/signatures under `artifacts/<sha256>.pkg.tar.zst[.sig]`.
It hashes bytes, reads archive package metadata without extracting files,
and binds acquisition signature evidence; libalpm rechecks signatures.
It also requires `gitstatus-build.json` with the actual non-root build
identity, pinned recipe/source digests, successful verification/build,
matching generated metadata, and resulting artifact identity. The pinned
recipe has no check function; this record must say `not-defined`, not
manufacture a passing check. Missing build evidence blocks publication.
This helper installs nothing and never refreshes a package database.

### Docker daemon readiness

Before importing images, `docker_ready.py --guest-id <UUID>` requires
inactive Docker/socket/containerd units, empty guest engine directories,
absent daemon configuration overrides and sockets, and no Docker-group
members. It binds installed versions and unit bytes to the actual signed
acquisition records and fixed archive digests. The helper adds only
fixed core-limit drop-ins, then starts `docker.service` and its packaged
dependencies. It does not enable startup, pull, build, import or create
containers. Default engine storage and guest network state are initialized
by daemon startup, as described in the
[Docker daemon documentation](https://docs.docker.com/engine/daemon/).

The observed result binds fixed startup arguments, empty environment
option sources, process identities and the owned local Unix socket.
Unexpected daemon TCP listeners refuse. Engine version/platform/data
root, inactive swarm and empty containers/images/volumes must match the
fresh baseline. The result and durable attempt are private under
`docker-readiness`; a start timeout leaves uncertainty without retry or
automatic stop. Image-store compatibility remains an import-time check.

### Console wrappers

The reviewed console transport may execute these fixed Bash files with
the independently supplied `MPKG_GUEST_ID`. They accept no operation
arguments and stop on the first failing command. Installed Python
entrypoints still enforce the marker, actual guest disk and code owner
before any system mutation.

- `guest-basics.sh`: journal, inputs, XML, retirement and supervision.
- `guest-docker-ready.sh`: fixed daemon readiness/start.
- `guest-native-service.sh`: native SSH baseline setup/check.
- `guest-image-import.sh`: archive import, then observed image manifest.
- `guest-native-proof.sh`: actual native manifest, then prepare-only proof.
- `guest-native-conflict.sh`: real frozen audio-package conflict preparation.
- `guest-compose-proof.sh`: fixed Sonarr/Radarr experiment.
- `guest-docker-baseline.sh`: assemble the separate running adoption fixture.
- `guest-docker-baseline-check.sh`: check that fixture after assembly/restore.

The wrappers do not transfer or install code. A newly added Python helper
must first be installed root-owned under `/opt/mpkg-proofs` through the
separately reviewed transport; the immutable source image is not modified.

### Running Docker adoption baseline

`docker_baseline.py setup --guest-id <UUID>` implements the ordinary
host-network/bind fixture from the
[fixture specification](../../docs/specs/2026-10-31-first-release-fixture.md).
Unlike the mechanism experiment, it keeps both applications running.
It requires verified image/engine bindings, Docker readiness, and the
native fixture's exact accounts/media group and shared sentinel first.
It refuses any collision with compose UID963/GID962 or the fresh
application paths, rather than reusing or renumbering another account.

Projects are `mpkg-fixture-sonarr` and `mpkg-fixture-radarr`; ports are
18989 and 17878, with 18990 checked for the later managed change. Source
and config directories are `/opt/docker/{sonarr,radarr}`; each config
root is 963:1001 with mode 2770. The existing native shared root is preserved;
new Radarr directories use the exact declared synthetic sentinel.
Both services use explicit preacquired digest/platform bindings, host
networking, `unless-stopped`, and the specified PUID/PGID/UMASK/timezone.
Setup enables only guest `docker.service` for later offline restoration.
The Compose execution reference is the immutable registry index digest
with explicit `linux/amd64`; acquisition and runtime checks separately
bind the selected amd64 manifest and image-config digests. The helper
does not invent or require a separate local child-reference alias.

The private assembly journal captures source inputs, rendered Compose,
generated-credential XML and accepted post-startup XML. It is separate
from product history. Checks bind actual containers/mounts, full process
UID/GID slots/groups, namespace mappings, capabilities and every covering
listener. Attributed anonymous ping and Radarr's authenticated root-folder
registration/discovery use the existing bounded HTTP helper. Supplemental
read-only file probes drop to the measured credentials; those probes are
reported separately from Radarr's actual application discovery.

`check` preserves all accepted XML values and checks source/render drift,
metadata, copied-credential sentinel reads and the live Radarr predicate.
It requires completed assembly history; an interrupted setup cannot
become an accepted baseline merely by running the check command. Setup
does not stop/retire applications, create snapshots, or claim product
adoption or A1–A12 success. The coordinator records an offline checkpoint
only after observed success. Volume/network variants remain separate.

### Real frozen native conflict

`native_conflict.py --guest-id <UUID>` is separate from the synthetic
conflict archive in the broader native experiment. It uses the exact
October 30 core/extra database hashes, an empty private root/local DB,
and the selected `pulseaudio=17.0+r134+g77d25a1e6-1` and
`pipewire-pulse=1:1.6.10-1` requests. It does not import installed state.

First, isolated print-only resolution must reproduce the recorded
167-package candidate bytes. That step is not counted as conflict
evidence: [pacman documents](https://man.archlinux.org/man/pacman.8.en)
that printing lists targets instead of performing the operation.
The helper then compiles its fixed C probe inside the guarded guest.
The probe rechecks machine/disk identity and a delegated pipe token,
adds exact database package objects, and requires libalpm's actual
conflicting-dependencies error naming both selected packages. Removal,
replacement and provider-selection questions are denied; both wanted
targets must remain in the candidate set with no removal. No commit,
refresh or download function is called. The
[libalpm transaction API](https://man.archlinux.org/man/libalpm_trans.3.en)
permits release after preparation without committing.

Both commands run in a separate network namespace; the C fetch callback
also refuses acquisition. Signature checks are disabled only for the
already hash-bound metadata; no archive trust, installation or product
acceptance is claimed. Results preserve actual question/error fields,
source/database/probe identities and empty-local-state limits. Failure
leaves the attempt unresolved, with no automatic retry.

### Native service baseline

`native_service.py setup --guest-id <UUID>` assembles only the fixed
guest SSH baseline, before the `native-change` snapshot. It requires
the acquired OpenSSH artifact and an unchanged package configuration,
inactive packaged `sshd.service`, unused ports 22/22222/22223, and free
fixture account/path identities. Setup preserves the package's original
`/etc/ssh/sshd_config`, then configures the managed service on loopback
22222. A separate unmanaged unit serves SFTP on loopback 22223 with
independent generated host/client keys and enablement. Both have core
dumps disabled. No package is installed or removed.

The accounts are exactly `fixture-native` 1500:1500 and
`fixture-external` 1501:1501, each also in `media` GID1001. Setup creates
the specified exclusive/shared synthetic data, modes and sentinels with
no extended ACLs. It unlocks accounts with unknown generated passwords
through bounded private stdin; the servers permit only public-key
authentication and force internal SFTP. Key material is captured in the
private journal and referred to by opaque IDs, never exported or hashed
into public results. This is disposable fixture setup, not adoption.

`check` validates `sshd -t`, effective configuration, exact memberships,
service state/enablement, protected inputs and metadata, then performs
authenticated SFTP reads with explicitly pinned generated host keys.
It binds the packaged/external unit and permitted drop-in bytes, exact
manager startup arguments and empty environment-option sources. The
main process must own every covering listener before and after the
probe. The pinned package unit has no `EnvironmentFile` or `SSHD_OPTS`;
introducing either blocks this closed fixture check.
The shared `service_environment.py` checks the fixed Docker, containerd,
managed SSH and external-consumer service objects through local
[typed systemd D-Bus properties](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).
An omitted `systemctl show` environment-file field is accepted only when
the separate `EnvironmentFiles` query returns the exact empty `a(sb)`
array. Nonempty, malformed, unsupported and failed reads refuse; no
environment paths or values are exported. Textual `Environment` and
`PassEnvironment` must still be present and empty.
`check-external` checks only the separate consumer and shared sentinel;
it does not require the retired managed service or exclusive directory.
These commands write private observations, without changing services.
Setup journals its boundary and refuses repeated setup after any partial
attempt; failures need explicit inspection or a separate guest restore.
The assembly owner still verifies the full package inventory, initial
absences and snapshot identity. These checks do not establish A1–A12.

OpenSSH documents the fixed server settings in
[sshd_config](https://man.openbsd.org/sshd_config), generated Ed25519 keys
in [ssh-keygen](https://man.openbsd.org/ssh-keygen), and batch retrieval
with abort-on-error semantics in [sftp](https://man.openbsd.org/sftp).
Actual package compatibility and authenticated behavior require the guest
run; host-safe configuration tests cannot establish either.

## Validation

Run `bash scripts/setup.sh` and `bash scripts/check.sh` from the worktree.
`tests/test_mechanism_proofs.py` uses temporary files/SQLite and confirms
the real CLI rejects a mismatched guest identity before an experiment.
It invokes no package, service, Docker, VM or guest-control operations.
Host C syntax-only checking uses available headers without linking or
executing libalpm. Guest linking, ABI/signatures and real integrations
remain prerequisites; syntax and mocked checks cannot establish them.
