# Runtime-attributed loopback status

`mpkg_manager.runtime_endpoint.observe_attributed_endpoint` compares one
declared HTTP status after checking that every covering listener belongs
to a stable selected runtime. It returns a separate immutable
`AttributedEndpointObservation`. The existing route observer, collected
endpoint batches, planner and installed status command are unchanged.

An attributed status is still not authenticated application functionality.
Every result retains `functional_result: unverified`: no response body,
Sonarr/Radarr application predicate, shared-consumer operation or access
check is performed. Attribution grants no management or apply authority.

## Trusted interface

```python
evidence = observe_attributed_endpoint(
    endpoint_check,
    resource_definition,
    host_id=accepted_host_id,
    engine_aliases=accepted_engine_aliases,
)
summary = evidence.as_dict()
```

The embedding supplies trusted host/engine bindings and runs in the host
network and user namespaces. Shape-valid input cannot establish those
facts. Complete normalized endpoint predicates, physical target identity
and selected Compose services are frozen before the first external query.
`matches_context` checks that private binding, including changed service
selection, engine aliases, URL, timeout and expected status. A same-ID
replacement cannot reuse the result for another target.

The public projection exposes labels, collection-start time, fixed source
and reason codes, attribution and route outcomes, and explicit limitations.
It excludes URLs, PIDs, executable paths, cgroups, credentials, namespace
identifiers, container IDs, socket inodes and native replies. Private
process snapshots are discarded after comparison. Public JSON and Python
constructors are not authenticated evidence import interfaces.

`query_runner`, `proc_reader` and `probe_runner` are trusted library/test
seams. They are not declaration fields or privileged protocol options.
There is no caller-selected PID, command, executable, environment,
container process name or alternate Docker endpoint in this interface.

## Supported runtime scope

Native services use the fixed system manager. Minimal `systemctl show`
queries require a loaded, active, running long-lived service with a
nonzero main PID, invocation ID and normalized control-group path. The
main process must belong to that unified cgroup or a descendant and own
every covering listener. Cgroup-v1-only membership, worker-owned listeners
and nonempty `TriggeredBy` are unsupported; the last condition includes
socket activation and conservatively refuses other triggering units too.

Compose requires exactly one explicitly selected service and one matching
container, including stopped instances when checking ambiguity. Fixed
queries use the accepted local engine, project/service labels, a running
non-oneoff container and `network_mode: host`. `docker container top`
supplies bounded process membership, including the container's initial
PID. Every covering listener must belong to one or more of those
processes. Multiple replicas, implicit service selection, bridge networks,
one-off containers and unavailable membership remain unsupported.

Only IPv4 loopback is supported. The existing transport maps `localhost`
to `127.0.0.1`; explicit IPv6 requests are refused. The complete bounded
TCP tables are validated, and both wildcard and loopback listeners on the
port must be attributed, including multiple reuse-port sockets. Any IPv6
listener on the port is refused because its IPv4 coverage is not known.
Malformed, truncated, unreadable or over-budget tables cannot prove that
an unrelated listener is absent.

## Observation sequence and limits

Before the probe, runtime queries bracket a Linux process/listener
snapshot. Held PID-directory descriptors keep reads attached to the
original process if its numeric PID is reused. Within the snapshot,
process start times, numeric credentials, capabilities, ID maps,
executable identity, cgroups, and network/user/mount namespaces are
checked twice. Network and user namespaces must match the collector's.
Mount namespaces may differ but must stay stable. The complete covering
listener set and its ownership are also checked twice.

The fixed isolated [endpoint worker](manager-endpoint-observations.md)
then performs its bounded HTTP(S) status request. The observer repeats
runtime, process and listener collection afterward and requires an exact
match with the earlier snapshot. An observed change discards even a
successful route response. Missing attribution prevents the probe;
transport failure can coexist with verified runtime ownership and remains
an unavailable route result. Cancellation propagates without retry.

This is a time-bounded observation, not an atomic runtime snapshot or
proof against a change that occurs and reverses between observations.
It does not reserve a socket, stop processes or prevent another actor
from changing the host. Root and the native managers remain trusted.
It establishes that the selected runtime holds each covering socket;
it does not enumerate every other process which might share the same
socket descriptor. This is another reason ownership cannot authenticate
the responder or establish an application-specific functional predicate.

The default collection budget is 60 seconds; trusted callers may select
1–300 seconds. Each fixed native query gets at most five seconds and
64 KiB of output; the collection permits at most 32 queries and 1 MiB of
successful query output. Late query or probe results cannot be accepted.
The original full endpoint timeout must fit before a probe is scheduled.

Inspection permits at most 32 container processes, 1024 descriptors per
process, 1 MiB and 8192 rows per TCP table, and separate small bounds on
process metadata. Kernel proc reads have size/count bounds and deadline
checks around them, but an individual kernel read cannot be preempted by
this in-process collector. Unsupported or incomplete inspection remains
unknown, never a successful ownership inference.

## Validation and remaining integration

Focused checks use synthetic native replies, adversarial process/table
fixtures, and an owned Python HTTP child with the real proc reader and
isolated endpoint worker. They do not run real systemctl/Docker queries,
install helpers or change production services. They do not establish
real Arch/Docker acceptance, application authentication, filesystem
consumer access, or first-release completion.

The process-descriptor behavior follows the Linux
[proc documentation](https://docs.kernel.org/filesystems/proc.html).
Native runtime queries use the selected properties described by the
[systemd interface](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html)
and Docker's bounded
[process listing](https://docs.docker.com/reference/cli/docker/container/top/).
The repository's earlier
[mechanism proofs](../scripts/proofs/README.md) motivate the attribution
sequence; their disposable observations do not authenticate this API's
future callers or replace its acceptance requirements.
