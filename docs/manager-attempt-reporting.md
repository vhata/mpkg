# Historical attempt reporting

The installed helper exposes read-only attempt history through
`mpkg-manager attempts` and `mpkg-manager attempt UUID`. Default CLI
`status` also includes the first attempt page alongside its independent
current observations. These reads never dispatch a worker, capture inputs,
acquire the application lock, recover an attempt or authorize a retry.

Every entry identifies the original attempt and plan UUIDs, decision
revision, immutable snapshot, original adopted resource UUIDs and their
adoption revisions/snapshots. It retains desired property predicates,
consumer requirements, accepted check definitions and decision-time check
definitions. New intent and new observations do not rewrite these facts.
The predecessor UUID links retries; use `attempt UUID` to inspect each
predecessor independently.

Actions report command and observation outcomes separately, their derived
state and explicit `attempted`/`not_attempted` work. A successful command
without an observation stays unverified; a failed command remains failed
when an observation matches; unknown completion remains unknown. Individual
check outcomes are not stored by the current inert journal, so each
original check says `not_individually_recorded`. Reporting never invents
per-check success from the action's aggregate observation.

## Redaction and authority

Reports construct a closed set of public fields from authenticated private
history. Original snapshot IDs, resource/check/input IDs, input file indexes
and origin revisions identify exact historical records without exporting
source paths, capture UUIDs, keyed comparison tokens, content or raw errors.
Safe bounded scalar predicates are visible. Other values, including URLs
and file paths, have `redacted: true`; their immutable original snapshot
and record ID preserve the exact reference. Redacted placeholders are only
reporting data and can never become candidate configuration bytes.

Events expose only fixed kinds and outcomes. Private recovery evidence is
not a public event outcome. Recovery disposition and effects remain
separate: a quiescent disposition cannot turn an unknown effect into a
successful one. All current journal records are inert fixture records;
`authority: fixture_only` and `executable: false` remain explicit.

## Complete pagination

`attempts --limit N --after UUID` resumes after the last returned attempt
in immutable append order, not lexical UUID order. The default limit is 20,
with a maximum of 100. Responses expose `has_more`, `next_after` and
`observed_through_ordinal`. The next cursor remains available on a terminal
page so later inserted attempts can be polled. Older attempts can acquire
new events; revisit their detail endpoint rather than treating an advancing
attempt list as a live update stream.

`attempt UUID --limit N --after-event N` pages that attempt's events by
sequence. It exposes `has_more`, `next_event` and
`observed_through_sequence`, with the original target and current journal
summary on every page. A list entry includes an explicit event-detail
request reference. No complete event history is silently substituted by a
count or truncated event array.

Each page uses one verified read transaction. Pages across requests form an
advancing history feed, not a frozen snapshot. Concurrent appends may appear
on subsequent requests; each page retains its observed revision and bounds.
The encoded page budget is 1 MiB in addition to the item limit. A byte-bound
page returns a continuation cursor; a single oversized item fails with
`attempt_history_size_limit` instead of dropping targets or checks.

A missing store, corrupt history, missing attempt/cursor and pre-journal
schema have distinct fixed refusals. None is presented as an empty history.
No read migrates or repairs history. Store verification has existing
filesystem/SQLite latency and complete-history verification costs; reporting
adds no hard latency guarantee and never waits on the application lock.

The wire uses closed `export/attempts` and `export/attempt` operations.
`observe/status` supports `include_attempts: true`, which the CLI supplies
by default. Older direct status requests without that flag retain their
explicit history-unavailable projection. Pure library status collection
still has no journal report unless the installed boundary attaches it.

## Validation limits

Owned temporary-store tests cover partial effects, newer intent and changed
checks, retry ancestry, missing/corrupt history, item/byte cursors,
concurrent journal append, redaction, strict response validation and reads
while an application lock is held. Existing status and recording tests
exercise the integrated boundary. No real installed privilege, package,
service, Docker or A1-A12 acceptance operation runs in these checks.
