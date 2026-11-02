# Inspecting host status

`status` collects bounded read-only observations through the
[installed host helper](manager-host-helper.md), then compares them with
recorded or working-tree intent. It does not record decisions, initialize
or recover a store, take the mutation lock, install inspection tools,
refresh package metadata, change files, or run lifecycle operations.
The existing `mpkg` package helper remains separate.

Run the unprivileged client after an administrator installs the helper
and provisions its private policy and store. Never invoke checkout code
with sudo. Status uses the same fixed authorization and transport as the
[recording client](manager-recording-cli.md#fixed-transport-and-failure-outcomes).
The staged payload and fixture checks do not establish real installation
or sudo acceptance.

```sh
.venv/bin/python -m mpkg_manager status
.venv/bin/python -m mpkg_manager status --json --expected-revision 7
.venv/bin/python -m mpkg_manager status --component media
.venv/bin/python -m mpkg_manager status environment.toml \
  --source-is-nonsecret --json
.venv/bin/python -m mpkg_manager status --probe-endpoints --json
.venv/bin/python -m mpkg_manager status --check-file-content --json
.venv/bin/python -m mpkg_manager status --attribute-endpoints --json
.venv/bin/python -m mpkg_manager status --check-consumer-access --json
```

## Target and selection

Without a pathname, status loads the exact current recorded declaration.
A missing store returns `store_missing`; an initialized store with no
recorded declaration returns `status_no_recorded_snapshot`. Neither case
creates intent or claims complete empty history.

A pathname selects an uncommitted working-tree declaration. The client
reads a bounded regular file and transfers its exact validated bytes.
`--source-is-nonsecret` explicitly classifies the complete source,
including comments, as nonsecret. It is required with a pathname and
refused without one. This acknowledgement is not secret detection and
does not authorize capturing referenced files. Protected references in
the TOML are permitted for inspection but remain private in output.

Working-tree status may inspect an initialized store at revision zero.
Its result explicitly says intent is unrecorded. Source comments and
line endings are part of exact recorded-target matching. Matching live
properties cannot make an edited declaration recorded or establish its
input freshness.

Repeat `--component ID` to select components. Their required resources
are included in the comparison; unselected and removed accepted resources
retain their original checks, input obligations, stable IDs and management
disposition. Selection does not hide retained responsibility or grant
authority. Invalid, repeated or unknown IDs are refused; source-based
selection errors fail before invoking the helper.

`--expected-revision N` optionally pins the reviewed history revision.
A stale revision is refused before host queries. Even without that flag,
the helper pins the collector to the revision used to choose its target,
then verifies policy and history again after collection. A detected race
returns an error instead of combining incompatible contexts. These checks
do not create an atomic snapshot of the entire host.

## Separate evidence

The [status collector](manager-status-collection.md) obtains native,
account, file metadata and Compose facts through its fixed adapters.
Unsupported, missing, stale, conflicting or unscheduled observations stay
unknown. It exports comparisons and fixed reasons, never raw native
output, private paths, desired values or physical identities.

Installed status opts into the
[complete recorded-input report](manager-recorded-input-reporting.md).
For an exact recorded declaration it constructs an independent history
manifest and compares current and retained declared files, including
original dependency and consumer-content obligations. It never mixes the
legacy protected-only evidence mode with this evidence. Source-file
freshness remains distinct from target-file content and property agreement.

Target-byte comparison requires `--check-file-content`. Its separate
[file-content report](manager-file-content-reporting.md) binds current
and retained desired/consumer roles to independently loaded history.
Only exact recorded intent can trigger target reads; edited intent keeps
the recorded obligations unavailable. The option neither captures missing
baselines nor grants overwrite, consumer-access or application authority.
Default status retains metadata and source-freshness behavior.

The recording CLI's explicit
[`--capture-inputs` option](manager-recording-capture.md) establishes
nonsecret file baselines. Ordinary declaration-only records retain
unavailable input baselines, and new protected recording declarations
remain unsupported through the CLI. Status never creates missing captures
or updates a baseline. Matching declared input files still leaves full
Compose input closure unverified.

For a working declaration that differs from the current record, status
does not read its input references or collect input freshness. The report
keeps the recorded history manifest and marks input evidence unavailable
with `intent_not_recorded`. Retained scope remains visible; it is not
silently replaced by the working declaration's smaller scope.

Route-only endpoint requests require `--probe-endpoints` and an exact recorded target.
The collector derives current and retained routes from actual history;
working-tree URL edits cannot cause requests. Ordinary status never probes.
A matching loopback response remains a route result, with listener and
application identity unverified. Recording and removing resources never
trigger status or probes automatically.

Separate [runtime and consumer checks](manager-runtime-check-reporting.md)
require `--attribute-endpoints` or `--check-consumer-access`. Attribution
performs its own HTTP status probe and socket-ownership inspection; it
does not imply the route-only option. Declared-user read/list results
can satisfy only that exact access predicate. Both preserve original
retained roles and leave application functionality unverified. Edited
intent keeps all recorded runtime roles unavailable without those reads.

## Output and bounds

Human output shows property comparisons, current and accepted checks,
retained and unselected resources, per-role input results and blockers.
Requested target-content results list current/accepted and desired/consumer
roles separately, without paths, bytes or content hashes.
`--json` returns `{"ok": true, "result": {"report": ..., "collection": ...}}`.
The report contains the full redacted comparison; collection states its
manifest coverage, query count, reserved output allowance and gaps.
Both remain `executable: false`, with application and attempt-history
limitations. A zero exit means a complete valid response, not that all
properties agree, checks pass, inputs match, or application is authorized.

The helper and client both validate a closed status-response schema.
Unknown nested fields, free-form diagnostics, mismatched contexts,
unexpected types and executable/verified-health claims are refused.
Snapshot hashes identify explicitly nonsecret declarations; input content
hashes, opaque protected references, URLs and file contents are omitted.
The response retains the existing 16 MiB transport cap; overflow is an
error, never a truncated report.

Installed collection has a fixed 45-second scheduling budget, 1,024
queries, 64 MiB reserved query output, 256 scheduled resource targets and
64 route-only endpoint probes and 64 runtime/access attempts. Native
queries across these phases share the same query count/output allowance;
new phases use remaining scheduling time. No request changes these limits or provides a runner,
program, policy/store path or environment override. Complete target and
input manifests have their own bounds and refuse overflow before reads.
Coverage means represented scope, not successful observation.

The existing client transport deadline is 60 seconds. Synchronous
filesystem, name-resolution, policy and history operations still have no
enforced latency deadline, so the helper may outlive the transport.
Status transport failure exits 5, without mutation-outcome uncertainty or
automatic retry. Explicit helper rejection exits 6; argument/source
errors retain exits 2 and 3, and authorization failure exits 4. No failed
status grants application authority or performs repair.

## Validation

Private fixtures drive the real CLI, protocol, helper, read-only store,
capture comparisons, collector and report with synthetic native/endpoint
replies. They check unchanged durable bytes, current/accepted baselines,
retained dependency and consumer roles, working-tree separation, selection,
revision races, unavailable input evidence, closed response validation and
redacted human/JSON output. Existing recording and collector checks remain
in force. No test invokes sudo, installs the root helper or performs real
package/account/service/Docker/endpoint operations. Installed usability and
A1–A12 product acceptance remain separate validation.
