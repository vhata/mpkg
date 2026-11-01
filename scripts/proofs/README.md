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

Every entrypoint requires root, Python 3.12, a regular root-owned `0600`
marker at `/etc/mpkg-fixture/identity.json`, and an independently supplied
expected UUID matching QEMU's DMI product UUID. The marker is exactly:

```json
{"schema":1,"guest_id":"<runner UUID>","fixture_id":"first-release-2026-10-31","disposable":true}
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
| Inputs | Protected byte capture/replay, full-byte/identity drift, private projection, actual SQLite `SQLITE_FULL` without publishing a reference | Plaintext private history; not a complete secret-leak audit |
| XML | Preserve all bytes outside the supported Port text, ownership/mode, comments and protected/unmanaged fields; reject stale or intervening edits | Only Port is implemented; exclusive writer maintenance is an explicit prerequisite |
| Retirement | Separate retained/shared and exclusive data, changed descendant refusal, partial deletion and a fresh remaining-scope disposition | Bounded directories and declared consumers, not every native or Docker resource kind |
| Supervision | Kill initiating CLI while its systemd service completes; kill worker while a child continues; unresolved work blocks another attempt | Real manager behavior is established only by guest execution |
| Native | Stage frozen metadata against a consistent installed DB copy; prepare again under the real guest package lock; compare full installed versions/reasons and prepared package/dependency/provider sets; reject missing dependencies/conflicts/mismatch | Prepare-only: no commit, hook, installation-reason change or coordinated upgrade execution is claimed |
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

The Compose experiment intentionally retains Radarr and Sonarr's kept
configuration for inspection. The separate daemon uncertainty case
cleans up only its exact container and leaves its journal unresolved;
container cleanup does not invent a successful interrupted attempt.

## Bound inputs

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

All artifact paths remain below `/opt/mpkg-proof-inputs`. Repository
archives must have usable signature sidecars and the guest keyring;
libalpm requires their signatures. Unsigned fixture-built artifacts have
an explicit different source classification and prior trust decision.
The conflict case adds a disclosed synthetic archive conflicting with
`filesystem`; it is prepared but never installed. No native transaction
commit or database-refresh function exists in the C probe.

## Validation

Run `bash scripts/setup.sh` and `bash scripts/check.sh` from the worktree.
`tests/test_mechanism_proofs.py` uses temporary files/SQLite and confirms
the real CLI rejects a mismatched guest identity before an experiment.
It invokes no package, service, Docker, VM or guest-control operations.
C compilation and real integrations are deliberately guest prerequisites;
Python syntax and mocked checks cannot establish them.
