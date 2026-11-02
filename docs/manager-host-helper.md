# Bounded host recording and observation protocol

The host helper exposes recording, history and read-only status through
closed JSON requests. It supplies a staged installed entrypoint; host
installation and complete-manager acceptance remain separate. Recording
and exports perform no live observation. Explicit status can query native
tools, Docker, file metadata and recorded input files; endpoint requests
require an additional explicit flag. No supported request applies host
changes. Preparation, executable planning, application and recovery are
unsupported.

## Installation and authorization boundary

The [payload stager](../packages/mpkg-manager/README.md) assembles only
files beneath a new package directory. It does not activate them.
The installed entrypoint is `/usr/lib/mpkg/host-helper.py`, with a fixed
`/usr/bin/python3.12 -I` shebang. It requires real and effective UID zero,
isolated Python 3.12 and that exact entrypoint path. It disables core
files, sets a private umask, clears inherited environment, changes to `/`
and verifies the installed source tree before importing product modules.
Symlinks, multiple hardlinks, writable code/ancestors, unexpected cache
files and oversized source inventories are refused. The interpreter,
standard library and administrator-owned installation are trusted;
this is not containment against a hostile administrator.

Enter the installed helper through explicit operator authorization, such
as interactive sudo. Never invoke repository code or a caller-selected
Python module as root. There is no passwordless sudo rule, Docker-group
grant or request-controlled operator identity. The existing store schema
does not yet record initiating-operator attribution.

Production construction fixes the private policy at
`/etc/mpkg/host-policy.toml`, the store at `/var/lib/mpkg`, and the host
mutation lock at `/run/mpkg/apply.lock`. Policy must already exist with
its required private ownership and modes. Administration separately
provisions the lock through the staged tmpfiles rule. Missing lock state
is refused for mutations rather than created during a request. Read-only
status and exports do not require or acquire that lock. The helper never
creates a default policy or repairs existing/partial state.

## Requests and responses

Each process handles one UTF-8 JSON object on stdin through EOF. Close the
input stream after writing the request. Duplicate keys, unexpected fields,
non-integer numbers, wrong scalar types, invalid UTF-8 and unsupported
versions are rejected. The wire input is limited to 20 MiB, including JSON
escaping; declaration source additionally retains its 16 MiB limit.
Both input receipt and output delivery have five-second deadlines. These
transport deadlines do not promise bounded filesystem/SQLite latency or
total execution time; validating retained store history grows with history.

Every request has exactly `version`, `verb` and `arguments`. For example:

```json
{"version":1,"verb":"export","arguments":{"operation":"current"}}
```

The supported operations are:

| Verb | Operation | Additional argument fields |
| --- | --- | --- |
| `record` | `initialize` | None |
| `record` | `intent` | `expected_revision`, `source`, `source_is_nonsecret` |
| `record` | `adopt` | The intent fields plus `resource_ids` |
| `record` | `relinquish` | `expected_revision`, `resource_ids` |
| `export` | `current` | None |
| `export` | `history` | None |
| `observe` | `status` | `expected_revision`, `source`, `source_is_nonsecret`, `selected_components`, `probe_endpoints`, optional `check_file_content` |

`initialize` creates the private store using the existing policy's host
and engine bindings. It refuses an existing destination. Ordinary reads
and recording requests never initialize the store as a side effect.

`source` is the exact TOML text, not a pathname. Source-bearing requests
require the literal boolean `source_is_nonsecret: true`, reflecting the
operator's explicit classification. This acknowledgement does not relax
declaration validation and cannot automatically detect secret content.
Protected recording declarations return `protected_recording_unsupported`; they
cannot be downgraded to generic unbound captures. Authenticated capture
preparation across helper requests remains separate work.

Intent and adoption additionally accept an optional boolean
`capture_inputs`, defaulting to false. When true, the helper captures all
declared nonsecret files through the verified host policy and publishes
them with the decision using the authenticated recorder. Other operations
reject this field. Protected declarations remain unsupported. Capture
failure returns `input_capture_rejected` without advancing the decision;
commit uncertainty retains its distinct outcome. See
[explicit input capture](manager-recording-capture.md).

`expected_revision` is an integer from zero through `2**63 - 2`.
Adoption selects one to 4096 distinct declaration resource IDs;
relinquishment selects distinct stable resource UUIDs from accepted host
history. Adoption records responsibility without claiming verification.
Relinquishment changes recorded responsibility without retiring software
or deleting data. No caller can provide a store/policy/lock path, owner
UID, executable, argv, environment, module, worker unit or raw capture.

Status uses `source: null` with `source_is_nonsecret: false` to inspect
the current recorded snapshot, or exact nonsecret source text with a true
acknowledgement for working-tree inspection. Protected references are
allowed for observation without creating captures. `expected_revision`
is null or a bounded integer, `selected_components` is null or a bounded
list of distinct IDs, and `probe_endpoints` is an explicit boolean.
The optional `check_file_content` boolean defaults to false; malformed
types are refused before dispatch. It opts into separately redacted
[recorded target comparisons](manager-file-content-reporting.md), never
arbitrary supplied paths or new baselines.
An empty component selection retains accepted obligations while selecting
no current components. Missing recorded intent is an explicit error.
See the [status guide](manager-status-cli.md) for evidence and latency
limits, retained scope and the closed public response.

The remaining fixed verbs `prepare`, `plan`, `apply` and
`recover` return `operation_unsupported`. Unknown verbs are malformed
requests; there is no generic command fallback.

Successful responses contain `version`, `ok: true` and `result`. Failure
responses contain `version`, `ok: false` and a fixed `error.code`. Output
is one JSON object plus newline and is limited to 16 MiB; overflow is an
explicit failure rather than truncated or apparently complete history.
Request failures, including input byte overflow, exit with status 2.
Input timeout, transport/bootstrap failures and failed output delivery
exit with 1; successful responses exit with 0. No raw parser, SQLite, path or exception
text is returned.

## Recording and output limits

Mutations take the pre-existing verified host lock nonblockingly, then
use the store's own revision/transaction checks. A competing mutation
returns `mutation_busy`; read-only status and exports do not take that host lock.
Store locking still applies. Policy is rechecked before recording and
afterward, and stored host/engine bindings must match it. This is not an
atomic lock against an administrator changing policy or external tools.
A detected policy change after recording returns an uncertain outcome.

`current` exports snapshot/revision metadata and resource identifiers,
kinds, managed-property names, management/disposition status and explicit
unknown observation state. It omits resource paths, desired values,
physical identities, consumer predicates and protected references.
`history` exports decision metadata only. Neither exposes raw TOML,
protected bytes or private capture tokens. Declared identifiers and
explicitly nonsecret snapshot hashes retain their existing meaning.

A lost response, `commit_outcome_unknown` or `record_outcome_unknown`
does not prove recording failed. Initialization errors after entering
store creation are also uncertain: the store may be committed or only
partially created. Existing destinations are still explicitly refused;
no failed initialization cleans up or silently retries those files. Inspect current revision and history
before deciding whether to retry. New requests still require an exact
expected revision; the helper does not replay recording automatically.
A missing/corrupt store or required recovery remains an error.

## Validation

Focused tests use real temporary policies, lock files and SQLite stores
under their fixture owner. They exercise initialization, exact source
recording, adoption, retained resources, relinquishment, stale revisions,
redaction, policy changes, unsafe paths and competing locks. Malformed
requests cannot activate the trusted Python fixture seams. No subprocess
or socket is needed for record/export dispatch.

Staging tests inspect the complete payload, code permissions and trust
checks. Owned subprocesses verify that a wrong-location launcher refuses
before importing product modules or attacker-controlled current-directory
modules. Pipes and regular files exercise request size, EOF/deadline and
blocked-output behavior. These checks do not install a root helper or
establish production installation, power-loss recovery or A1–A12 product
acceptance.
