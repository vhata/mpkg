# Version-bound container application checks

`mpkg_manager.application_collection.observe_application` supplies a trusted
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

Endpoint checks may declare optional closed versioned `application`
metadata, as defined in the [declaration guide](manager-declarations.md).
It records the version, internal port, URL base and Radarr root ID, path
and sentinel in the immutable declaration snapshot. Existing adoption
history already retains full check definitions; no store schema migration
is needed. Later intent edits or relinquishment do not rewrite the last
explicitly adopted application predicates. History reopening reconstructs
them from the original adoption snapshot.

`application_check_manifest(readonly_store, loaded_policy, revision=...,
snapshot_id=...)` independently derives complete runtime roles, including
application metadata, from verified policy and actual current/accepted
history. Removed and relinquished resources retain their accepted roles;
component selection cannot suppress them. The manifest also retains
ordinary runtime roles so completeness cannot be asserted by dropping
unwanted definitions.

`observe_application` takes those trusted store/policy handles, the
expected manifest and one exact original scope. It derives the application
predicate from that stored role and constructs its own live history guard.
It accepts neither a caller predicate nor a guard callback. Complete
history, policy, source snapshot and selection are rechecked before queries,
before credential resolution, after resolution and after collection.
Changed or tampered context refuses the result; an imported or
caller-constructed manifest must exactly match independent live history
before it can cause any query or credential resolution.

`collect_application_checks` derives its manifest internally and collects
all application roles with explicit `check_applications=True`. The default
performs no application requests. Retained roles run first. Unselected,
disabled and unscheduled roles remain explicit unavailable rows.
`credential_resolver(scope)` receives the exact private role to resolve a
protected credential for its physical target. Credentials and credential
references never enter declarations, history or public results. The
resolver cannot override the stored predicate.

The default collection budget is 60 seconds and 64 attempts; trusted
callers may select up to 300 seconds and 256 attempts. Queries share a
1,024-query and 64 MiB reserved-output allowance. Each request keeps its
original timeout, and late results are discarded. Synchronous history,
policy and kernel reads retain their existing latency limitations. No
automatic retries occur. Collection rechecks history even for empty,
disabled or exhausted batches.

`ApplicationCheckBatch.matches_manifest` requires independently derived
complete scope and rejects future or stale evidence, with a default
60-second maximum age. Public results omit metadata values and are not
reusable evidence proofs. Python constructors and serialized reports do
not authenticate history or confer application authority.

No installed CLI/helper request is added. The existing endpoint URL
records the root-folder path without a query; the fixed Radarr worker
appends `timeout=true`. Ordinary endpoint and runtime reporting keeps its
unverified functional meaning even when the declaration includes metadata.
Functional evidence is supplied only by explicit trusted application
collection.

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

Real temporary stores and policies cover changed current predicates,
retained adoption history, removal/relinquishment, reopen, tampered
snapshots and manifests, stale evidence and denial before credentials.
A store-backed Radarr check also uses the real private worker and an
owned HTTP listener. Synthetic engine/process evidence covers current
and retained binding, wrong versions/listeners, replacement, namespace
mismatch, bridge mapping, stale context, timeouts, redirects, malformed and
oversized bodies, exact Radarr sentinel checks and credential redaction.
No real Docker, application or namespace-entry acceptance is established.
Real version-pinned applications, bridge entry and shared-directory
behavior remain disposable Docker acceptance requirements.
