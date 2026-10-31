# Server environment: user journeys

These proposed journeys develop the [agreed mandate](2026-10-30-server-environment.md).
They describe desired experiences and outcomes, not commands, storage
formats, or implementation. Detailed policies remain proposals; the
confirmed behaviors below record subsequent decisions, while open
decisions must not be treated as settled defaults.

The example is an already working Plex deployment through Docker on
an Arch Linux host, using a shared `compose` account and an existing
media directory. This is an illustrative scenario, not an inventory of
the actual server. All journeys target Arch Linux hosts only; Docker
images may use other base distributions.
The same questions apply to native software and its supporting
configuration and resources.

## 1. Adopt an existing service

**Starting point:** The service works, but its setup decisions are only
partly recorded. Some resources may also serve other applications.

**Desired experience:**

1. Identify what runs, what supplies it, its configuration, the identity
   it runs under, the access it needs, and where its persistent data and
   generated files belong. Identify required secrets separately from
   ordinary configuration.
2. Distinguish supplied defaults, deliberate local choices, normal
   runtime state, and unexplained differences. Discovery reports
   uncertainty instead of treating everything observed as intentional.
3. Choose what to manage, what to recognize as externally managed or
   deliberately outside management, and what still needs investigation.
   Requiring a shared account or media directory does not automatically
   grant authority to change or delete it.
4. Record the intended setup and the reasons for local choices. Bring
   one service into scope without first accounting for the whole server.
   Inspect status to distinguish verified agreement, unapplied changes,
   and gaps in what could be checked. Matching existing state does not
   require a redundant application step.

**Success:** The service remains operational without changes caused by
inspection or recording alone. Its declared setup can be explained,
and remaining gaps are visible. Adoption does not silently restart,
upgrade, relocate data, change permissions, or replace configuration.

For native software, adoption must also distinguish a package required
by this application from one independently wanted by the operator or
another consumer.

## 2. Change a managed service

**Starting point:** The service is accounted for. The operator wants it
to access another media directory with specified access permissions.

**Desired experience:**

1. Record the desired outcome without changing the live server. Inspect
   how it differs from the actual setup, including unapplied work and
   intervening manual changes. Surface uncertainty before acting on an
   outdated understanding.
2. Understand which configuration, identities, permissions, and running
   services would change, including known effects on other consumers of
   shared resources and any expected interruption. Unknown effects must
   remain visible as uncertainty.
3. Separately request application of the chosen change, without silently
   including unrelated software updates, permission changes, or data
   relocation.
4. Check whether the intended outcome was achieved, including known
   affected consumers. Distinguish verified results from conditions
   that could not be checked.
5. If only part of the change succeeds, see what changed, what remains
   running, what failed or was not attempted, and what still differs
   from the intent in system status. Retrying should account for the
   actual state already reached.

**Success:** The desired access works, the deliberate change is
understandable in history, and any remaining discrepancies are visible.
Rechecking an already satisfied intent does not cause unnecessary
installation or restarts.

An edit to a managed file made outside this system is another entry
point into this journey. The difference is reported, and the operator
chooses whether to keep it as intended configuration or restore the
recorded version. Observing a difference does not establish the
operator's intention.

Reverting a recorded configuration choice must not be presented as
proof that software updates, application data changes, or other live
effects have also been undone.

## 3. Retire a service

**Starting point:** The operator no longer wants the service running.
Other applications may use the same account, directories, software, or
data. Some of those consumers may not yet be managed by this system.

**Desired experience:**

1. Distinguish stopping the service temporarily, retiring it, and
   leaving it running while relinquishing management. These are
   different intended outcomes. Recording the chosen outcome does not
   itself stop or remove anything; status makes unapplied work visible.
2. Identify resources used only by this service, resources known to be
   shared or independently wanted, and resources whose use is uncertain.
   Absence of a recorded consumer is not proof that a resource is unused.
3. Understand what would stop, what could be removed, and what would
   remain. For every retirement, ask the operator whether to keep or
   delete persistent application data, with its scope and any shared
   use made clear. Retiring the service does not imply a data choice.
4. Separately request application of the retirement and the chosen data
   disposition.
5. If data remains, preserve its attribution and explain what keeps it
   accessible. Accounts, groups, or permissions needed by retained data
   still have a purpose even after the application stops running.
6. Verify the retirement outcome and expose any remaining activity or
   incomplete cleanup in system status. Retained data must not imply
   that the service should be reinstalled.

**Success:** The service is no longer intended to run and has been
verified to have stopped, and the chosen data disposition has been
completed. Remaining activity or unfinished data handling means
retirement is incomplete; inability to check means it is unverified.
Shared and independently wanted resources retain their declared
purpose. Any retained data and supporting resources remain accounted
for; incomplete work and uncertain ownership remain visible.

There is no implicit keep-or-delete choice for persistent data.
Choosing to delete data, where appropriate, is a distinct outcome whose
scope must be understandable before it occurs.

## Requirements exposed by these journeys

- Keep intended setup, observed state, and unresolved differences
  distinguishable, including after a partially completed change.
- Distinguish responsibility, use, and authority to modify a resource.
  Several applications can require the same resource.
- Recognize independently wanted and externally managed resources.
  Incomplete discovery must not become a claim of exclusive ownership.
- Describe expected runtime variation sufficiently to make the
  attribution meaningful. A directory's existence alone does not
  explain every possible new file or modification beneath it.
- Preserve accountability through retirement, including responsibility
  for retained data and the resources still required to access it.
- Make the limits of inspection and verification visible. Reporting
  incomplete knowledge is preferable to asserting the server matches
  its intended state without evidence.

## Confirmed behaviors

1. **Direct configuration edits:** Report the difference. The operator
   chooses whether to keep it as intended configuration or restore the
   recorded version.
2. **Persistent data on retirement:** Ask the operator to choose whether
   to keep or delete it on every retirement. Kept data retains its
   attribution and any supporting resources it still requires.
3. **Version intent:** Software choices may allow newer versions or
   constrain them, including exact pins where the source and
   installation method can honor them. Recreation honors those
   requirements; permitting an upgrade does not decide when it happens.
   See the mandate's
   [version requirements](2026-10-30-server-environment.md#version-intent).
4. **Supported host:** Arch Linux only. Native Arch software and Docker
   applications are in scope; other host operating systems are not.
5. **Recording and applying:** Separate actions. A system status view
   makes unapplied changes and attempted applications, including
   failures and partial results, clear. See the mandate's
   [status requirements](2026-10-30-server-environment.md#recording-applying-and-status).

## Decisions to resolve next

1. **Shared resources:** How explicitly should the operator grant
   authority to modify resources used by more than one application?
2. **Service success:** What must be checked before declaring a change
   successful, and how should limited verification be presented?
3. **History:** Which deliberate decisions and observed outcomes must
   be preserved, without recording routine runtime changes as intent?

Updating software and recreating a server need further journey detail
as their milestones are designed. The
[milestone plan](../../plans/2026-10-31-server-environment-milestones.md)
sets the first-release scope and the remaining design questions, using
the confirmed direction on version intent above.
