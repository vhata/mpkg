# Sonarr runtime baseline

This records the explicitly authorized read-only runtime inspection
following the [Compose source inspection](2026-10-31-compose-deployment-evidence.md).
It supplies observed inputs for the proposed
[first-release contract](2026-10-31-first-release-contract.md) and
[acceptance scenarios](2026-10-31-first-release-acceptance.md).
It is not an implementation, adoption record or acceptance execution.

Docker/process metadata was collected on **2026-10-31 at 22:26:03 UTC**;
bounded access and application probes ran at **22:32:31–22:32:32 UTC**.
These are observations at those times, not a continuing health claim
or an atomic snapshot of all host resources.

## Method and scope

Queries targeted the explicit local Unix endpoint
`unix:///var/run/docker.sock`, with inherited context/host overrides
removed. The collector selected Sonarr, Radarr, SABnzbd and Plex. It
used Docker information, container/image inspection and process lists,
plus selected `/proc` identity fields. No registry lookup or image pull
was needed to inspect locally held image metadata.

Short `docker exec` probes ran under the observed application UIDs.
Each compared its real/effective/saved/filesystem UID/GID, supplementary
groups and effective capabilities with the application process before
performing any directory checks. A mismatch would leave access
unverified. The probe had a five-second timeout and emitted only
identity fields and booleans for fixed paths; it read no media names
or file contents and attempted no writes.

One anonymous Sonarr HTTP GET used a listener attributed to the observed
Sonarr process, a literal loopback address, no proxy or redirects, a
three-second socket timeout, six-second overall deadline and a 4096-byte
response cap. Only the HTTP code and recognized status token were saved.

Raw Docker inspect output, environment secrets, command arguments,
healthcheck logs, arbitrary labels, raw errors and HTTP response bodies
were not persisted. Application configuration was read only to select
the port and URL base; no API key was used. Independent review and
synthetic disclosure/attribution checks preceded live collection and
probes. Deployment definitions, permissions, accounts, images and service
lifecycle were not changed. Probe processes and normal observation
events are distinct from application or restart operations.

## Engine and Sonarr deployment identity

| Fact | Observation |
| --- | --- |
| Engine endpoint | `unix:///var/run/docker.sock` |
| Engine ID | `71b8a24c-86cd-4422-8d3b-64ae1ec2cfbb` |
| Engine server version | `29.9.2` |
| Engine OS / architecture | `linux` / `x86_64` |
| Image OS / architecture | `linux` / `amd64` |
| Compose project / service labels | `sonarr` / `sonarr` |
| Recorded project directory | `/opt/docker/sonarr` |
| Recorded Compose file | `/opt/docker/sonarr/compose.yaml` |
| Compose creator-version label | `5.6.1` |
| Container state | Running; neither paused nor restarting |
| Container start time | `2026-10-29T07:34:12.78955181Z` |
| Restart policy / reported restart count | `unless-stopped` / `0` |
| Network mode / privileged flag | `host` / `false` |
| Configured Docker user | Empty; this does not describe the application process's dropped credentials |
| Configured Docker healthcheck | Absent; no Docker health-status result |

Sonarr's observed container ID was:

```text
0030324693d4b8b4b7cb2b88908d1ca90d23009d391583a304a2dc72064ebc06
```

This instance ID identifies the observed container. The adopted
deployment identity must remain engine plus accepted project identity
when a later application recreates that container. The project and
source paths above come from runtime Compose labels, rather than being
inferred from the explicit container name.

The creator-version label is not evidence of the currently installed
Compose CLI version. The reported zero restart count is not a complete
history of starts or manual lifecycle operations.

## Image and input binding

The configured reference remains `lscr.io/linuxserver/sonarr:latest`.
The locally inspected image has version label `4.0.20.3014-ls1` and
recorded repository digest:

```text
lscr.io/linuxserver/sonarr@sha256:48e36b608b461273b9dae857725cd0561a127f2c694b687318f6d0c5ce63e5c9
```

Docker also reported the same hexadecimal digest for this image's local
ID. This observation does not establish a general equivalence between
image IDs and registry digests. No registry availability or independent
reproduction of this artifact was tested. Observing resolved content
does not turn the mutable reference into a user-requested pin.

The container's creation-time environment contains `PUID=963`,
`PGID=1001`, `UMASK=002` and `TZ=America/Los_Angeles`, matching the
previously inspected nonsecret declarations. The Compose labels name
the single source file above and contain no environment-file label.
That absence does not prove no `.env` or shell overrides were used.

Current values and labels cannot reconstruct the original invocation,
original source-file bytes or which environment source supplied a
particular value. Adoption must accept a complete current input bundle
and verify it against the live result, preserving uncertainties instead
of inventing historical provenance. Future attempts need their own
bound input snapshots and fresh observation.

## Actual mounts and application credentials

Sonarr's runtime mounts are both read-write bind mounts, with
`rprivate` propagation:

| Host source | Container destination |
| --- | --- |
| `/opt/docker/sonarr/config` | `/config` |
| `/mnt/media` | `/mnt/media` |

Radarr, SABnzbd and Plex are also running, each in its correspondingly
named Compose project, and each has a read-write `/mnt/media` bind at
that same container path. Each has its own app-specific config bind.
These are observed attachments, strengthening the earlier source-file
evidence of shared consumers. They do not prove that this is an
exhaustive consumer inventory or that every application workflow works.

| Container (short ID) | Selected process | Observed host PID | UID | GID | Supplementary groups |
| --- | --- | --- | --- | --- | --- |
| Sonarr `0030324693d4` | `Sonarr` | `175328` | `963` | `1001` | `1000`, `1001` |
| Radarr `8b734b32e8ad` | `Radarr` | `173789` | `963` | `1001` | `1000`, `1001` |
| SABnzbd `8538878b6ab8` | `python3` | `177854` | `967` | `1001` | `1000`, `1001` |
| Plex `2218fd57cefd` | `Plex Media Serv` | `179400` | `963` | `1001` | `100`, `983`, `987`, `1001` |

SABnzbd's selected process was the sole matching unprivileged `python3`
process in that container; command arguments were not collected. All
four UID and GID slots matched the displayed IDs for each selected
process, and effective capabilities were zero. The inspected namespace
maps were identity maps, supporting comparison of these numeric IDs
with the host for this run.

The image initialization processes include root processes. Neither an
empty configured Docker user nor the init PID alone establishes the
application's actual credentials. Conversely, the observed supplementary
groups are not automatically new intended host-account memberships.
They require deliberate interpretation when accepting management scope.

## Bounded probe results

For each of the four containers, the fresh probe's full UID/GID slots,
supplementary group set and effective capabilities matched the selected
application process. Every fixed-path check below succeeded:

| Path in each container | Checks that passed |
| --- | --- |
| `/config` | Directory existence; read/write/search permission predicates; actual directory traversal and opening for read |
| `/mnt/media` | Directory existence; read/write/search permission predicates; actual directory traversal and opening for read |

The write predicate checked permission only. There was no write trial,
directory enumeration, descendant scan or media-file read. These results
establish that a new process with the measured credentials could access
these directory roots in its container context. They do not prove a
media import, successful write, descendant access, application-specific
security context or continued access after future changes.

Sonarr owned the eligible IPv6 wildcard listener on port `8989`. The
probe selected IPv6 loopback, found no configured URL-base prefix, and
received **HTTP 200, status `OK`** from:

```text
GET http://[::1]:8989/ping
```

Ownership was checked on the listener serving that loopback address,
not merely any listener sharing the port number. The exact image-version
source for Sonarr `v4.0.20.3014` marks this route anonymous and uses a
configuration-repository read cached for five seconds. The response
supports point-in-time application/configuration-database responsiveness;
it does not verify indexers, download clients or media functionality.
[Versioned probe source](https://raw.githubusercontent.com/Sonarr/Sonarr/v4.0.20.3014/src/Sonarr.Http/Ping/PingController.cs)

Container IDs, image IDs, running state and start times matched the
earlier inventory when checked around the probes. Selected application
PID/parent/namespace-PID, identity and capability fields also matched
before and after. These checks reduce attribution races; they do not
make separate process and socket observations atomic or rule out every
possible transient change.

## Consequences for the design and remaining evidence

The selected example now has a concrete engine/project binding, locally
observed image identity/platform, actual mounts, measured application
credentials, an attributed bounded endpoint result and root-directory
access evidence for the known consumers. The source-file, process and
probe layers should remain separate in the proposed status model.

Before application or a reproducible acceptance demonstration:

- Re-observe current resources and accept the complete nonsecret and
  protected input bundle. Runtime labels do not recreate historical
  shell inputs; store future attempt inputs when the attempt is made.
- Freeze an obtainable image/platform and disposable Arch/package
  manifest. Current local content is not proof of future acquisition.
  Verify the selected AUR recipe and initially missing dependency.
- Finish configuration/data/secret classification and safe update
  boundaries. The prior XML/database evidence still requires a
  representation that preserves secret values and unmanaged fields.
- Identify exclusive data-retirement scope and any additional consumers.
  Root-directory access does not validate descendants or authorize
  deletion. Exercise real writes, shared-consumer functionality,
  interruptions, manual edits and retirement in the disposable fixture.
- Supply supplemental named-volume and project-network cases; the
  observed Sonarr definition uses bind mounts and host networking.

The read-only inventory task is complete with these limits explicit.
The first-release product and its acceptance demonstrations remain
unimplemented and unverified; the successful probes do not waive them.
