# Bounded loopback endpoint observations

`mpkg_manager.observe_endpoint.observe_endpoint` probes the closed
`endpoint` check declarations and returns immutable route/status evidence.
It neither identifies the listener's owning service/container nor verifies
application health. Every result retains `functional_result: unverified`
and the limitations `listener_attribution_unavailable` and
`application_identity_unverified`, including a matching HTTP status.

## Trusted observation interface

```python
observation = observe_endpoint(
    check_definition,
    resource_definition,
    host_id=accepted_host_id,
    engine_aliases=accepted_engine_aliases,
)
summary = observation.as_dict()
```

The check and resource identity are revalidated against the declaration
schema. The result privately binds the complete normalized predicate and
physical target, including host and accepted Compose engine identity.
`matches_context(check, resource, host_id=..., engine_aliases=...)`
compares that binding. Same-ID replacement cannot reuse evidence for a
different expectation, URL, timeout or target. A caller comparing accepted
and current predicates must preserve both definitions independently.

`observed_at` is the collection-start UTC timestamp. A trusted caller may
supply it for deterministic collection/tests. The observer does not declare
its own freshness; consumers must enforce their time and identity rules.
An injected `runner(url, timeout_seconds)` is a trusted test/embedding seam,
not a declaration-selected command or transport. The supplied host and
engine bindings also come from the embedding's trusted boundary.

`EndpointObservation` is immutable and returns fresh public projections.
Public output contains check/resource labels, host, time, route result,
fixed reason/source codes and mandatory limitations. It exposes no URL,
physical target details, expected/observed status, response headers/body,
predicate digest, credential or arbitrary diagnostic. Private canonical
binding bytes are trusted-library state. Python objects and shape-valid
JSON cannot authenticate a remote host.
There is no JSON import or privileged dispatcher here.

## Transport and bounds

The default transport launches only a fixed Python worker in isolated
mode with a clean environment. A private stdin request of at most 8 KiB carries
the URL; process arguments contain no URL or declaration-selected command.
The parent limits combined stdout/stderr to 4096 bytes and retains only
fixed worker codes and a successful terminal status for comparison.
Worker errors and response content never enter public diagnostics.

The worker sends a fixed HTTP GET directly to a numeric loopback socket.
`localhost` deliberately maps to `127.0.0.1`; no DNS resolution occurs.
Explicit `127.0.0.1` and `::1` are supported. HTTP(S) uses an explicit port
from 1 through 65535. The bounded transport accepts ASCII URLs of at most
4096 bytes with no control characters, credentials, query or fragment.
The request has only fixed Host and Connection headers. No proxy settings,
redirects, authentication headers or arbitrary request content are used.
HTTPS uses Python's default certificate verification and hostname checks;
there is no declaration-selected CA or insecure mode.

Only complete terminal HTTP/1.0 or HTTP/1.1 status evidence is compared.
Parsing is limited to 16 KiB total headers, 4096 bytes per line, 64 header
fields and four informational responses. Protocol switching is unsupported.
The parser does not consume or retain the response body. Unsupported or
malformed responses and exhausted limits are unavailable evidence.
A 3xx terminal response is compared as received; its Location is never
followed. `match` or `mismatch` describe the declared terminal status
expectation only; request failure reports `unavailable`.

The parent rechecks completion time as well as readiness waits and enforces
the declared 1–60 second deadline across request
transport, worker execution and captured streams, then kills the worker
process group on failure or cancellation. Cleanup waits at most one second.
Kernel process launch/reaping and synchronous system calls cannot provide
a hard real-time guarantee. Interrupts propagate after bounded cleanup.
The worker also checks a monotonic deadline around socket operations.

## Limits and verification

This library does not read or update host records, grant authority, run
accepted checks automatically, or integrate evidence into comparison
reports. Listener attribution, authenticated application adapters and
planner consumption remain separate work. A reachable route may belong
to the wrong process or deployment, and response status does not prove
service usefulness. Anonymous GET may have endpoint-defined side effects;
trusted authors must select a read-only health route.

Tests use owned ephemeral HTTP/TLS listeners, synthetic protocol bytes and
private subprocess fixtures. They cover exact binding, output privacy,
certificate/hostname verification, inherited trust refusal, parser limits,
late completion, cancellation and closed-pipe descendant cleanup. They never probe a production endpoint or
perform package, service or Docker operations. They do not establish
installed privilege isolation or first-release acceptance.
