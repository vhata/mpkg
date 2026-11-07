# Recording intent from the manager CLI

The unprivileged manager exposes explicit host-store initialization,
recording, adoption, relinquishment and sanitized exports through the
[installed host helper](manager-host-helper.md). These commands record
responsibility and intent. They do not observe live resources, install
packages, apply configuration, start services, contact Docker or verify
application behavior. The existing `mpkg` package helper is separate.

The [declaration validation command](manager-declarations.md) keeps its
existing local behavior. The new commands require the installed helper,
Python 3.12, an administratively provisioned private host policy and
mutation lock, and explicit operator authorization through sudo. The
[payload stager](../packages/mpkg-manager/README.md) assembles files only;
it does not perform that installation or provisioning.

## Commands and explicit revisions

Run the client as the ordinary operator. Its root entrypoint is always
installed code; never run this checkout or its Python modules with sudo.

```sh
.venv/bin/python -m mpkg_manager validate environment.toml --json
.venv/bin/python -m mpkg_manager init
.venv/bin/python -m mpkg_manager current --json
.venv/bin/python -m mpkg_manager record environment.toml \
  --source-is-nonsecret --expected-revision 0
.venv/bin/python -m mpkg_manager adopt environment.toml \
  --source-is-nonsecret --expected-revision 1 --resource config
.venv/bin/python -m mpkg_manager current
.venv/bin/python -m mpkg_manager history --json
```

`init` explicitly creates the store at revision zero using the installed
policy. It refuses any existing destination. Other commands never
initialize or repair the store as a side effect.

`record` records the exact validated source without accepting resource
responsibility. `adopt` records the source and deliberately accepts the
selected declaration resource IDs. Repeat `--resource ID` to select
multiple resources. Adoption records an unknown observation baseline;
it does not claim those resources exist or have been verified.

Add `--capture-inputs` to either command to capture every declared
nonsecret file under the installed host policy. The helper records those
private baselines atomically with the decision, so subsequent status can
compare input freshness. The flag is optional; ordinary recording retains
its declaration-only behavior. See [explicit input capture](manager-recording-capture.md)
for bounds, failure semantics and the separate protected-input boundary.

`relinquish` selects stable resource UUIDs shown by `current`, rather
than declaration IDs. For example, after inspecting current revision 2:

```sh
.venv/bin/python -m mpkg_manager relinquish \
  --expected-revision 2 \
  --resource 12345678-1234-4234-8234-123456789abc
```

Replace the example UUID with the actual selected stable UUID. This
records external responsibility without stopping or deleting anything.
Removing a resource from a later declaration preserves its accepted
history and reports a pending disposition. The
[store guide](manager-store.md) defines retained responsibility and
consumer constraints.

Every `record`, `adopt` and `relinquish` requires `--expected-revision N`,
using the revision the operator reviewed through `current` or `history`.
An empty history means revision zero. The helper checks that revision
inside the write transaction and rejects stale requests. The client
never fetches a replacement revision, silently updates a decision, or
retries recording. A revision ranges from zero through `2**63 - 2`.

## Source classification and local validation

Source-bearing commands require `--source-is-nonsecret`: the operator
explicitly classifies the complete TOML source, including comments, as
nonsecret. This is a declaration by the operator, not automatic secret
detection or a promise that secrets have been removed. There is no
classification prompt or default for noninteractive commands.

The client reads a bounded regular source file without following its
final symlink, validates it locally, and sends the exact UTF-8 bytes as
JSON text. Comments and line endings are preserved. It does not read
referenced input files. Malformed declarations, invalid selections and
protected recording without preparation fail before invoking sudo.
Protected inputs require the explicit
[`prepare-inputs` / `--prepared-inputs` flow](manager-protected-recording.md).
The helper captures inputs privately and consumes the exact preparation
once; a reference in TOML alone never authenticates captured content.

## Fixed transport and failure outcomes

The client first runs fixed `/usr/bin/sudo -v -u root` authorization
with stdin disconnected. Sudo may use the controlling terminal for
authentication; a session without available credentials or a usable
terminal fails. The declaration is never authentication input. Askpass
and inherited executable/environment overrides are unavailable.

After authorization, the client makes one noninteractive invocation:

```text
/usr/bin/sudo -n -u root -- /usr/lib/mpkg/host-helper.py
```

The installed launcher uses its fixed `/usr/bin/python3.12 -I` shebang.
Both invocations use `/` as working directory and only fixed `PATH`,
`LANG` and `LC_ALL` environment entries. There is no shell, program/path
flag, store/policy override, UID option, or environment-based test mode.
The helper request is sent on stdin through EOF; stderr is discarded.
Only a closed, type-checked response can become ordinary output.

Authentication has a 120-second client deadline. Helper transport has
a 60-second client deadline and a 16 MiB response limit. The helper has
its own input/output limits. Its store-history validation can grow with
history, so a client deadline is not evidence that recording failed.
Stopping the unprivileged transport cannot guarantee that an already
privileged helper stopped. It may still finish after the client exits.

| Exit | Meaning |
| --- | --- |
| 0 | Validated declaration or successful recording/export response |
| 2 | Invalid arguments, declaration, selection or unsupported protected source |
| 3 | Declaration source file unavailable |
| 4 | Authentication failed or was interrupted before helper invocation |
| 5 | Transport unavailable before dispatch, failed export transport, or explicit helper input-transport failure |
| 6 | A well-formed helper response explicitly rejected the request |
| 7 | Recording outcome uncertain after invocation or reported by the helper |

A partial request write, timeout, interruption, lost/malformed response,
or inconsistent process exit after a mutation starts is conservatively
uncertain. `commit_outcome_unknown` and `record_outcome_unknown` also
exit 7. Inspect `current` and `history` before deciding whether to retry;
the client performs neither inspection nor retry automatically. A missing
or corrupt store and required recovery remain explicit errors.

All commands accept `--json`. Successful host commands return
`{"ok": true, "result": ...}` with only the helper's sanitized projection.
Host failures return a fixed error code and category; uncertain results
also carry a fixed next-step label. Human output uses validated IDs,
revision numbers and fixed labels. Raw source, paths, desired values,
predicates, protected references, process diagnostics and exception text
are never printed. Argument errors retain the validation command's
fixed JSON diagnostic format regardless of output mode.

`current` reports recorded responsibility and unknown observation state;
it is not live status. `history` reports decision metadata. The separate
[`status` command](manager-status-cli.md) explicitly collects read-only
observations and compares current and retained obligations. Neither
output grants authority for applying changes. Prepare, plan, apply and
recover commands remain unavailable.

## Validation limits

Focused tests drive these command flows through real private policy,
lock and SQLite fixtures via an internal sender seam. They exercise
exact source preservation, explicit selection/revision checks, retained
resources, stale conflicts, output redaction and uncertain outcomes.
Owned Python subprocesses test EOF, bounded output, timeout, interruption
and partial write failure while inspecting fixed production controls.
An owned PTY checks that substituted authorization stays in the foreground
and the helper retains the controlling session in a separate process
group. These probes do not establish actual sudo authentication behavior.
No test invokes sudo, executes an installed root helper, or performs a
real package/service/Docker operation. Sudo configuration, installed
helper usability and A1–A12 product acceptance remain unverified here.
