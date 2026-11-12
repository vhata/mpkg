# Execution requests

The installed helper recognizes bounded preparation, exact plan acceptance,
apply and evidence-backed recovery requests. The CLI uses the existing
fixed sudo transport; it cannot select commands, adapters, worker paths,
environment, output destinations or operator identity.

The installed adapter registry is empty. All production execution requests
return `execution_adapter_unavailable`; this interface does not enable native,
AUR, Docker, service or filesystem effects. Trusted inert test assembly
exercises the complete client, parser, helper, plan, journal, launch and
recovery path. No JSON field or installed option enables that assembly.
Existing blocked Sonarr proposals cannot become executable plans.

Commands are `prepare-execution --expected-revision N --resource UUID
--interruption stop_and_require_recovery`, `inspect-plan UUID`,
`accept-plan UUID`, `apply UUID`, and `recover UUID --expected-sequence N`.
Repeat `--resource` to select multiple stable resources. The trusted planner
closes dependencies and retains original consumers/checks. The supported
interruption policy stops subsequent work and requires recovery; it never
permits automatic replay. Plan responses expose only bounded action scope,
check/artifact counts and opaque IDs, excluding private evidence.

The fixed launcher captures sudo's operator UID before clearing its
inherited environment. Direct root invocation uses UID zero. JSON cannot
supply identity. Acceptance and apply require the same trusted operator;
recovery records its requesting operator separately from the worker owner.

Apply takes the existing host application lock, validates durable acceptance
and fresh prerequisites, creates one attempt, then commits its reservation
before dispatch. Recording cannot slip between these writes. The lock is
released before transport; durable reservation protects the worker handoff.
The fixed launch descriptor contains only the attempt UUID. Tests execute
accepted inert plans with freshness checks at every action boundary.

The plan ID is the durable apply idempotency key. Repeating apply returns
the original attempt ID, including after a lost response or changed facts;
it never launches a second worker. A failure between attempt creation and
reservation leaves an inspectable, never-dispatched attempt; repeating does
not launch it. Unknown launch outcomes retain reservations and require
recovery. Client transport loss is reported as uncertain, not as rollback.
Inspect plan and attempt history before further action. Preparation creates
a new proposal on each invocation; only acceptance/apply have exact-plan
repeat semantics.

Before creating a different attempt, apply derives retry ancestry from the
complete authenticated history under the host lock. Overlap includes every
derived prerequisite, not only explicitly selected roots. Both preparation
and acceptance must postdate every overlapping recovery or failed/unverified
completion. Accepting an old proposal after recovery is insufficient; a later
successful retry cannot make an older acceptance valid again.

A fresh retry links to the single latest unresolved lineage. Successful
linked descendants resolve only the resources they actually verified;
partial success preserves the remaining ancestor scope. Disjoint attempts
do not create retry ancestry. Multiple unrelated overlapping lineages, or an
overlapping attempt without a qualifying terminal disposition, block new
dispatch. The current single-predecessor schema cannot represent a lineage
merge, so the helper does not choose one branch or discard the others.
There is no caller-supplied predecessor or bypass field. Same-plan repeats
still return the original attempt before these new-attempt checks.

Recovery uses the existing lock, exact journal sequence and complete fresh
quiescence evidence. It does not infer successful effects, kill workers,
delete locks or replay actions. Unknown evidence keeps mutations blocked.
The installed recovery collector is unavailable until concrete integrations
are reviewed. Production worker and real sudo/systemd/cgroup acceptance,
power-loss behavior and A1–A12 remain unverified.
