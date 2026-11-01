# Read-only host observations

`mpkg_manager.observe_native.observe_resources()` observes validated
package and system-service declarations. It is a library boundary for
status and planning, separate from the legacy `mpkg` command. It neither
records adoption nor installs, restarts, refreshes sources or grants
authority. No privilege launcher is included.

Supply a host UUID and normalized resource dictionaries from
`Declaration.model["resources"]`. The result is an immutable
`ObservationBatch` with host identity, UTC observation time, facts,
coverage and limitations. `as_dict()` returns a fresh JSON-compatible
projection. Each `Observation` retains resource identity, property,
`known`, `absent` or `unknown` state, value, evidence source and limits.
Unknown facts have no value and carry a fixed diagnostic code.
`for_resource(id)` selects a resource's facts.

The timestamp marks the start of the observation batch. Coverage names
the requested resource IDs, including those whose inspection was
unavailable. No other resource or filesystem scope is claimed. Repeated
queries detect changed samples; they do not create an atomic host
snapshot or establish that no intervening change occurred.

## Packages

The adapter performs `pacman -Q` and `pacman -Qqe` twice, comparing the
complete inventories and explicit-reason sets. Duplicates, malformed
rows, missing reason identities or differing samples make the requested
package facts unknown. A failed query cannot establish absence.

The `present` property is whether the exact installed package name was
observed. `version` is the observed string and `install_reason` is
`explicit` or `dependency`; these facts are absent for a missing direct
name. Missing a direct name does **not** establish that a requested
dependency is unsatisfied: another package may provide it.

`source` and `provider` remain unknown. A foreign package is not inferred
to be an AUR package, and observed versions do not become exact intent.
This adapter does not solve dependency requirements or prepare native
transactions. Planning must retain those limitations as blockers where
the missing facts are required.

## System services

The adapter observes explicit `.service` units in the system manager.
It repeats a fixed `systemctl show` query, including invocation and
activation evidence, and requires stable, complete, recognized fields.
Missing fields are unknown even when systemd omitted an empty field.
It exports only allowlisted load, active, substate, unit-file-state,
service-type and main-PID properties.

`running` is true only for a supported long-running service type with
active/running state and a positive main PID. Inactive/dead or
failed/failed state with no main PID establishes false. A one-shot
active/exited unit, transition or ambiguous combination remains unknown.
`enabled` describes persistent enabled/disabled state; runtime-only,
static, masked and other enablement semantics remain unknown.
These observations do not establish application usefulness or functional
health. Required application and access checks remain separate.

Other resource kinds receive unknown facts for presence and declared
desired properties without invoking a tool. They do not acquire
management support merely because the declaration schema accepts them.

## Execution and verification boundary

The default runner uses only `/usr/bin/pacman` and
`/usr/bin/systemctl`, with exact query forms and validated unit names.
It accepts no mutating verbs, caller-selected program, shell or sudo
operation. Its environment excludes inherited loader, Docker, D-Bus,
proxy and credential settings. Standard input is closed.

One deadline and combined stdout/stderr byte cap bound each process.
Failure terminates its private process group, including children keeping
pipes open. Successful stdout is private parser input; stderr, raw
exceptions, failed output and partial output are never exported.
Public failures use fixed codes. Test-only runner injection does not add
an executable field to declarations or the future helper protocol.

Run the isolated tests with the prepared Python 3.12 environment:

```sh
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m unittest discover \
  -s tests -p test_manager_observations.py -v
```

The tests stub package/systemd queries and use short local child
processes for environment, output-limit and timeout behavior. They
perform no package, service, Docker or privileged host operations and
do not establish the real Arch acceptance scenarios.
