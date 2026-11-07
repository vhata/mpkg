# Protected recording through the installed boundary

`prepare-inputs` captures the protected entries of an exact, explicitly
nonsecret TOML declaration under the installed host policy. It returns an
opaque preparation UUID without recording intent, adopting resources or
applying configuration. Then `record` or `adopt` consumes that preparation:

```sh
.venv/bin/python -m mpkg_manager prepare-inputs environment.toml \
  --source-is-nonsecret --expected-revision 0 --json
.venv/bin/python -m mpkg_manager record environment.toml \
  --source-is-nonsecret --expected-revision 0 --prepared-inputs UUID
```

Replace `UUID` with the preparation ID returned by the first command. Use
the actual reviewed revision. Preparing again replaces the host's previous
pending preparation, including one prepared by another operator. The host
has one pending slot, not a queue of outstanding captures.

The declaration's protected entries already contain canonical UUID
references. These are caller-selected identifiers, not evidence or access
credentials. Only the helper's policy-approved capture can authenticate a
new reference. Reusing an existing reference requires its original exact
authenticated snapshot. A changed source, including comments, needs new
references and a new preparation. Existing legacy unbound references never
gain a baseline merely by being submitted to preparation.

To adopt after recording, prepare the same declaration at the new revision
and use `adopt ... --prepared-inputs UUID --resource ID`. Existing capture
origins and original accepted predicates remain immutable. Add
[`--capture-inputs`](manager-recording-capture.md) when the decision should
also establish baselines for all declared nonsecret files.

## Exact scope and private staging

The closed helper request is `prepare` / `protected-inputs`, with exact
`source`, literal `source_is_nonsecret: true`, and `expected_revision`.
Intent/adoption requests additionally accept `preparation_id`. No request
accepts capture bytes, source identities, comparison tokens, alternate
staging paths or tool invocations. Preparation does not grant permission
to apply anything. The source classification is the operator's explicit
responsibility, not automatic secret detection.

The host mutation lock serializes preparation and recording. A private
authenticated receipt binds host/store identity, exact declaration source
and normalized snapshot, revision, loaded policy identity, every protected
slot and classification, source metadata and full content. Only the random
preparation ID, host UUID, revision and protected-entry count are public.
Source paths, input references, bytes and keyed comparison tokens remain
private and never appear in ordinary responses or decision history.

Staging uses fixed `protected-preparation.json` and unpublished
`protected-preparation.next` names inside the verified private store
directory. Each is bounded to 1 MiB, regular, owner-only and single-linked.
Descriptor-relative opens refuse symlinks and unsafe metadata. Publication
synchronizes the new file and directory. A later preparation can replace
the pending receipt and remove a valid leftover unpublished staging file;
these files carry no accepted authority. Neither contains captured bytes.

Preparation and consumption each read at most 64 protected files, 16 MiB
per file and 64 MiB in aggregate. The recorder performs its own final fresh
capture checks, with its existing combined protected/nonsecret limits.
File latency has no hard deadline and reads do not exclude application
writers. Freshness is evidence about these reads, not an atomic filesystem
snapshot or complete effective Compose input closure.

## Consumption, uncertainty and backup

Separate helper invocations reopen and verify policy and history. Before
recording, the helper authenticates the receipt, checks the exact source
and revision, and freshly captures every protected input. It then removes
the receipt and synchronizes the directory **before** entering the existing
SQLite recording transaction. The transaction atomically records accepted
snapshot, captures, authenticated references and adoption obligations.

Consuming a receipt is one-shot even if recording subsequently fails or the
caller loses its response. Failure or interruption after removal requires
a new explicit preparation. It never permits replay of old capture
evidence. Stale scope, changed source/policy or unavailable captures fail
without publishing a decision. A failure before receipt removal leaves
the pending receipt, but does not promise that it remains fresh.

`protected_preparation_required` rejects protected recording without an
explicit preparation before transport. Unavailable, invalid, consumed or
changed preparations return `input_capture_rejected`; stale revisions
remain `revision_conflict`. Commit/cleanup uncertainty preserves the
existing exit-7 outcome: inspect current/history before deciding whether
to retry. A failed preparation response does not imply that the previous
pending ID survived; explicitly prepare again when needed.

Accepted captures and history remain entirely in SQLite. Preparation
staging is unaccepted metadata, excluded from the store's authoritative
SQLite migration backup. Missing or stale staging requires a fresh
preparation; it is never restored as accepted history. Restoring a database
does not establish external-state freshness or authority to apply effects.

Tests use separate requests, fresh policy/store handles, private temporary
files and injected failures. They establish the staged boundary's behavior,
not real sudo/installed-helper acceptance, package effects or application
health. Installation and first-release acceptance remain separate work.
