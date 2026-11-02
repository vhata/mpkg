# Read-only Compose observations

`mpkg_manager.observe_compose.observe_compose()` inspects one normalized
Compose resource using an actual engine ID already accepted by trusted
caller context. It never adopts the engine it discovers. Supply
`resource`, `host_id`, `accepted_engine_id` and optionally `observed_at`;
tests may inject a runner. A valid declaration with an unsupported project
name receives unknown facts without querying Docker.

The immutable `ComposeInventory` stores canonical bytes and exposes
`as_dict()` as a fresh nested projection. Its `observations` member is the
existing scalar `ObservationBatch` for status and planning. No nested
inventory is smuggled into a scalar fact as a JSON string.

## Identity and scope

The fixed endpoint is `unix:///run/docker.sock`, queried through
`/usr/bin/docker`. An accepted engine ID must match before and after
collection. No inherited context, host, proxy, TLS, loader or credential
environment controls execution. Explicit `--config /dev/null` prevents
loading the user's Docker configuration, including a home directory
found through account lookup. Configuration warnings remain private.
No Docker access or privileges are granted to make inspection work.

Each of two samples lists all containers carrying the exact project
label, including stopped containers. Each sample then inspects selected
container fields and each distinct image ID. Lists and metadata must
agree across samples. Stable repeated samples are time-bounded evidence,
not an atomic engine snapshot or proof that nothing changed between them.

Containers retain their full ID, service label, replica number, one-off
status, selected process state, start/finish times, image ID, mounts and
network attachments. A project or ID mismatch, duplicate container ID,
duplicate ordinary service/replica identity, missing attribution or
inconsistent attachment identity makes the inventory unknown.

The nested projection also groups observed bind sources, volume names
and drivers, and network names/IDs with their observed container IDs.
These are **only consumers in the selected labelled project**. External
consumers, host path aliases, actual filesystem objects, volume retention
authority and external network endpoints remain uninspected. The result
always says `consumers_exhaustive: false`; it cannot establish exclusive
use or authorize removal. Volume backing directories are not exported.

Only selected fields are requested. Queries do not request environment,
command arguments, arbitrary labels, health logs or raw daemon errors.
Image OS, architecture, optional variant and repository digest metadata
remain distinct from the local image ID. Registry metadata does not bind
a declared image reference to a verified registry manifest/platform, and
observed identities never become pins automatically.

## Scalar facts and unknowns

`present` means at least one container carrying this project label was
observed; it does not mean the deployment was adopted or its inputs were
verified. A successful stable empty listing establishes only that bounded
absence. `container_count` includes stopped and one-off containers.

`running` requires an explicit declared service list matching exactly
one ordinary container per service. All running containers establish
true; all created, exited or dead containers establish false. Missing
services, orphans, one-offs, multiple replicas, mixed states and
transitions leave it unknown. These state facts do not establish useful
application behavior or health. `input_closure`, image intent resolution
and `health` always remain unknown in this adapter.

Permission failures, missing tools or objects, malformed/incomplete
metadata, missing image platform, identity changes, bounds and timeouts
produce fixed unknown reasons with no partial inventory or raw output.
An empty nested inventory with `state: unknown` never establishes absence.
Snapshots currently stop at 64 containers, 64 mounts and 32 network
attachments per container. Each query has a ten-second timeout and a
256 KiB combined stdout/stderr limit; retained successful stdout is capped
at 8 MiB and collection at sixty seconds. Process-group cleanup permits a
bounded additional reap interval and preserves cancellation exceptions.

## Validation and limits

The Docker allowlist contains only engine identity, project container
listing, and selected-field container/image inspection. No lifecycle,
pull, build, Compose rendering, source loading or application probe exists
in this adapter. In particular, arbitrary YAML is never rendered through
`docker compose config`; input closure is separate work.

With the project's Python 3.12 environment prepared:

```sh
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m unittest discover \
  -s tests -p 'test_manager*observations.py' -v
```

Tests use synthetic Docker responses and local child processes. They
check identity races, attribution, stopped containers, unknown scope,
attachment consumers, malformed/private output, command rejection and
environment isolation. Shared subprocess mechanics retain the native
observer's cancellation and descendant tests. No live Docker, package or
service query is run, and these tests do not establish Arch acceptance
or compatibility with a particular installed Docker version.

The query forms follow Docker's
[container listing](https://docs.docker.com/reference/cli/docker/container/ls/)
and [selected-field formatting](https://docs.docker.com/engine/cli/formatting/)
interfaces. Docker's
[configuration loader](https://github.com/docker/cli/blob/master/cli/config/config.go)
documents the home-directory fallback and empty default configuration.
The [first-release contract](specs/2026-10-31-first-release-contract.md)
defines the additional adoption, input and application evidence required.
