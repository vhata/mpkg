# Durable attempt ownership and supervision

`mpkg_manager.attempt_supervisor` and `attempt_worker` add a fixed launch
adapter, durable launch reservations and a worker that holds the host
application lock through an attempt. Their executable test assembly accepts
only inert fixture attempts. The installed [request boundary](manager-execution-requests.md) recognizes
apply requests, while production construction rejects fixture authority
before dispatch or execution. Native and Docker effects remain unavailable.

## Reservation and lock handoff

The immutable [journal target](manager-attempt-journal.md) already contains
the attempt UUID, operator UID, worker UID/UUID, boot UUID and derived
`mpkg-attempt-<UUID>.service` identity. Dispatch verifies that identity and
the original decision revision, takes `/run/mpkg/apply.lock`, and commits a
`launch_reserved` event before contacting the system manager.

Dispatch releases that host lock before launching the worker. The durable
reservation closes this handoff gap: the helper refuses recording or capture
before reading its inputs, and ordinary store write transactions independently
refuse intent, adoption, relinquishment, new attempts and proposal writes.
Both gates return `attempt_recovery_required`. A second launch also refuses
an unresolved reservation. Inactive, never-dispatched fixture records do
not block recording.

A failed start commit or lock-cleanup return never invokes the transport.
A committed reservation whose response was lost remains blocking. A repeated
dispatch never relaunches the service, even after a previous attempt finished.
Only journal-event appends have the internal exemption needed to advance
ownership and outcomes; this exemption is not a host request field.

Launch results are accepted, rejected or unknown. Startup acknowledgement
is not action success. Client timeout, nonzero exit, output overflow and
unknown errors are ambiguous; unavailable client executables or a refused
process start are rejected. Neither state clears the reservation. A caller
can disappear after dispatch while the separately owned worker continues.

## Fixed service and private transport

A `LaunchSpec` accepts only one canonical UUID. The installed adapter builds
this fixed service command with `/usr/bin/systemd-run`:

- `--system --quiet --no-ask-password` and the derived unit name.
- `Type=exec`, `ExitType=cgroup`, `KillMode=control-group`, `Restart=no`,
  `RemainAfterExit=yes` and `TimeoutStartSec=30s`.
- Null stdin/stdout/stderr, `LimitCORE=0`, `UMask=0077` and working
  directory `/`.
- `/usr/lib/mpkg/attempt-worker.py` followed only by the attempt UUID.

There is no caller-selected unit body, shell command, executable, path or
environment, and no scope, terminal, pipe, wait or automatic-restart mode.
The client has a fixed minimal environment, a 10-second deadline and at
most 64 KiB of private combined output. It returns only a fixed outcome;
raw stdout/stderr and errors are never journal fields. These choices follow
[systemd-run's service ownership and startup semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html).
The exact installed systemd version and real service/cgroup behavior still
require the separate disposable installed-boundary acceptance task.

The [payload stager](../packages/mpkg-manager/README.md) installs the worker
and helper from one hardened bootstrap source. The worker accepts exactly
one canonical UUID. Both require fixed installed paths, isolated Python
3.12, UID zero, verified code ownership and no writable/symlinked source
inventory. They clear inherited environment and disable core dumps before
importing product code. The worker entrypoint emits no raw exception text.
No service is started by staging or importing either module.

## Worker ownership, completion and uncertainty

The worker takes the same host lock for its entire attempt, checks boot,
worker UID, policy/store bindings and original revision, and durably appends
`worker_started` before any action. Duplicate workers cannot claim an owned
or completed attempt. SQLite/store transactions are short; no database lock
is held while a child runs. Read-only status/export does not wait for the
host application lock.

The trusted fixture runner starts a fixed inert Python child with bounded
private pipes. Each action retains the journal's committed-start ordering
and separate command/observation outcomes. Missing or malformed runner
results, interruption, timeout and output overflow preserve uncertainty.
A failed or unverified action stops the remainder. Raw child errors and
output never enter ordinary history.

Only a complete, verified inert run appends `worker_completed` with
`verified_complete` and releases its durable reservation. The host lock
continues to be held until the worker leaves its context. Startup results
may arrive after worker completion; they remain separate append-only launch
metadata and cannot replay actions.

Worker failure appends `unresolved` when it can; interrupted journal writes
may leave the earlier ownership event instead. Either remains blocking even
when the worker has exited and the advisory lock is free. This slice does
not delete locks, kill existing workers, infer daemon quiescence, roll back
external effects or automatically retry. The separate
[recovery boundary](manager-attempt-recovery.md) requires complete trusted
evidence before releasing ownership without rewriting action outcomes.
Production adapter completion rules remain separate work. The fixture runner
is not evidence that a real package transaction or application is healthy.

## Evidence and limits

Temporary fixtures cover the reservation handoff race, failed/ambiguous
launch, duplicate and competing launches, wrong-boot workers, caller-process
exit with an independently owned sibling worker, action timeouts, output
bounds and secret-bearing errors. Tests verify recording refusal across the
handoff, host-lock lifetime, available SQLite transactions during children,
nonblocking exports, replay refusal and staged worker trust checks.

The tests never invoke real systemd, package tools, Docker lifecycle
operations or a root-installed worker. Real cgroup/boot behavior, privilege
acceptance, system crashes and A1–A12 remain unverified. The explicit private
fixture constructors and fake transport are trusted test seams, never
wire-protocol options or production execution authorization.
