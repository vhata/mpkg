# Version-bound container application checks

`mpkg_manager.application_checks.observe_application` supplies a trusted
library observer for Sonarr 4.0.20.3014 and Radarr 6.4.4.10685. It pins the
runtime image configuration IDs selected in the
[first-release fixture](specs/2026-10-31-first-release-fixture.md).
An image configuration ID is not a registry manifest or index digest.
Other versions and image IDs remain unavailable pending an explicit
adapter update and acceptance evidence.

The Sonarr predicate requires HTTP 200 and JSON `status: "OK"` from
anonymous `GET /ping`. This establishes the selected ping behavior only,
including its documented cached configuration read. Radarr performs only
`GET /api/v3/rootfolder/{id}?timeout=true`, requiring HTTP 200, the exact
positive ID and path, `accessible: true`, and the exact expected sentinel
name and full path in `unmappedFolders`. It never registers a root folder,
creates movie records, or substitutes filesystem permission checks for
the application's directory discovery. Fixture assembly owns prior root
registration, naming configuration and sentinel creation.

## Trusted history binding

The caller supplies an independently obtained `RuntimeCheckManifest`, an
exact private original role from that manifest, and an
`ApplicationPredicate`. The complete binding includes host, revision,
source snapshot, selection, original current/accepted role and predicate,
physical resource, selected service, version, port, URL base and Radarr
root/sentinel expectations. Removed and relinquished accepted roles keep
their original scope. Changed IDs, predicates, adoption context or source
cannot reuse an observation. `matches` additionally refuses future or
stale evidence, with a default 60-second maximum age.

`context_guard(manifest, scope, predicate)` is mandatory. A trusted
embedding must independently reload live policy/history and the original
accepted application predicate, returning exactly `True` only for the
same context. It is checked before queries, before the worker and after
collection. A permissive test callback is not production authentication.
Python constructors, public JSON and imported reports cannot establish
accepted predicates or grant authority.

This library does not extend declaration syntax, store application
predicate acceptance, collect a complete application batch, or install a
CLI/helper request. The existing declaration endpoint URL records the
root-folder path without a query; the fixed Radarr worker appends its
version-bound `timeout=true` query. An embedding must retain the separate
application predicate alongside original accepted history rather than
infer it from a current same-ID endpoint or from observed runtime data.
The existing runtime and route reports keep their original unverified
functional meaning.

## Runtime, namespaces and credentials

Fixed read-only queries require the accepted engine, one running non-oneoff
container for the exact project/service, pinned image, stable start time
and bounded process membership. The observer holds its network namespace
file descriptor across both application and published-route checks. It
rechecks runtime inventory before and after each phase; changed evidence
invalidates the result. Bridge scope additionally requires nonempty
network and endpoint identities and the exact single IPv4 loopback port
mapping. Unknown or changed mappings cannot verify a published route.

Only the isolated fixed worker enters the held namespace. It checks its
identity after entry, then uses the existing bounded proc inspector to
require every covering IPv4 loopback/wildcard socket to belong to the
selected container processes, with stable process, credential, namespace,
executable and socket evidence. Inspection repeats after the request.
Unrelated listeners, namespace disagreement and unavailable process data
prevent sending the credential. IPv6 listeners, rootless user namespace
mappings, multiple replicas and incomplete proc visibility remain
unsupported. Socket ownership does not prove cryptographic responder
identity or exclude another process sharing the same socket descriptor.

The protected credential resolver returns a key only to private memory.
Delivery uses stdin, never argv, environment, URL or ordinary output. The
worker disables core dumps, sends `X-Api-Key` only to numeric loopback in
the verified namespace, and discards response bodies and exception text.
Direct HTTP connections use no proxies, redirects or retries. Each request
has the original timeout (at most 10 seconds) and a 64 KiB body limit.
The supervisor terminates the worker on deadline; a Radarr timeout does
not cancel the application's internal task. Callers must not overlap
retries after an uncertain request.

Published routes are independent and credential-free: anonymous Sonarr
ping status or a plain Radarr TCP connection. A successful route never
substitutes for the application predicate. Results expose only separate
functional/route outcomes, observation time and fixed reasons. They grant
no execution or management authority. Before/after observations are not
an atomic snapshot; kernel proc reads and engine queries retain the
existing bounds and limitations.

## Evidence

Owned HTTP listeners and synthetic engine/process evidence cover current
and retained binding, wrong versions/listeners, replacement, namespace
mismatch, bridge mapping, stale context, timeouts, redirects, malformed and
oversized bodies, exact Radarr sentinel checks and credential redaction.
No real Docker, application or namespace-entry acceptance is established.
Real version-pinned applications, bridge entry and shared-directory
behavior remain disposable Docker acceptance requirements.
