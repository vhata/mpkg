# Compose deployment evidence and Sonarr resource example

This records a read-only inspection of the user's actual files under
`/opt/docker` on 2026-10-31 and grounds the
[minimum resource model](2026-10-31-server-environment-resources.md) in
one selected application. It supports the
[first-release milestone](../../plans/2026-10-31-server-environment-milestones.md).
The worked lifecycle below is proposed behavior, not an executed
adoption, application or retirement.

## Inspection boundary

Inspected the six conventional applications' `compose.yaml` files and
adjacent `.env` inputs, selected Sonarr path metadata and nonsecret
`config.xml` fields, account/group mappings, and the ACL entries on the
Sonarr config directory and `/mnt/media`. YAML was parsed as source,
not rendered by Compose. No Docker daemon or application was queried.
No package, container, service, account, group or permission was changed.

The account database includes `vhata` in `compose`, but inherited
process groups were stale. An approved `newgrp compose` subshell
enabled directory traversal. Five Compose files and Sonarr's `.env`
are owner-only, so approved noninteractive reads as their owner,
`compose`, were used. This did not broaden file permissions.

Extraction retained resource facts, environment-variable names,
numeric identities, timezone, ports, log level and credential presence.
Other environment values, commands, labels and raw parser diagnostics
were withheld; interpolated resource values were withheld rather than
partially redacted. Source files, secret values and database contents
were not copied into Git. Source contents and runtime state can change;
these observations are not a frozen deployment manifest.

Uninspected scope includes other application configuration, directory
contents outside the bounded checks, media descendants, Codeman's
source/build lifecycle, the live engine, Compose invocation and
overrides, resolved images, running credentials, effective access and
application availability. Unreadable `.cache` and `.local` directories
under `/opt/docker` were outside this inspection.

## Candidate comparison

Each source is `/opt/docker/<application>/compose.yaml`, with adjacent
`.env`. All six have a single declared service and a matching explicit
`container_name`, use a published image, and declare
`restart: unless-stopped`. None of these files declares a build,
Compose project `name`, or a Compose healthcheck. An image could still
supply its own healthcheck. No named volume is declared in these files.

| Application | Declared image | Declared mounts and networking | UID/GID from adjacent input |
| --- | --- | --- | --- |
| homepage | `ghcr.io/gethomepage/homepage:latest` | `./config:/app/config`; `3000:3000`; no explicit network mode | `HOMEPAGE_UID=963`, `HOMEPAGE_GID=962` referenced by `PUID`/`PGID` |
| plex | `lscr.io/linuxserver/plex:latest` | `./config:/config`, `/mnt/media:/mnt/media`, host network, `/dev/dri` device mapping | `PUID=963`, `PGID=1001` |
| prowlarr | `lscr.io/linuxserver/prowlarr:latest` | `./config:/config`, host network | `PUID=963`, `PGID=962` |
| radarr | `lscr.io/linuxserver/radarr:latest` | `./config:/config`, `/mnt/media:/mnt/media`, host network | `PUID=963`, `PGID=1001` |
| sabnzbd | `lscr.io/linuxserver/sabnzbd:latest` | `./config:/config`, `/mnt/media:/mnt/media`, host network | `PUID=967`, `PGID=1001` |
| sonarr | `lscr.io/linuxserver/sonarr:latest` | `./config:/config`, `/mnt/media:/mnt/media`, host network | `PUID=963`, `PGID=1001` |

These are file declarations, not resolved invocation or runtime
credentials. A caller's environment, additional files or invocation
options may affect the effective model. Matching container names do
not establish Compose project identity. `latest` is a mutable image
reference, not a digest or evidence of deployed content/platform.

Radarr, SABnzbd and Sonarr also declare `UMASK=002`. Plex has an
additional `VERSION` environment field and device mapping; Plex and
SABnzbd set a stop-grace-period field. Homepage references a credential
through an environment variable; its value was withheld. Absence of a
credential in another Compose environment list does not establish that
the application's mounted configuration or database is secret-free.

The six source files were owned by UID 963/GID 962. Homepage's mode was
`0644`; the other five were `0600`. Ownership of deployment definitions
is distinct from an application's declared runtime identity.

## Selected example: Sonarr

Use Sonarr as the primary conventional Compose example. Radarr is a
similarly suitable alternative. Sonarr has the required configuration,
data, shared-media and identity relationships without Plex's device
passthrough or Codeman's source/build concerns. Keep Radarr, SABnzbd and
Plex outside management in the first fixture while retaining their
declared interests in `/mnt/media` and the shared group.

Their definitions establish declared shared consumers, not proof that
those workloads are currently running or that these are all consumers.
Do not infer exclusive authority over any portion of the shared tree.

### Observed identity and path facts

Account records map UID 963 to `compose`, primary GID 962 (`compose`),
with home `/opt/docker`; UID 967 maps to `sabnzbd`. GID 1001 is `media`.
The group database also contains application-named members, but their
names do not override Sonarr's declared PUID. A container's requested
GID 1001 is not an instruction to change the host account's primary
GID from 962.

| Observed path | Type | UID:GID | Mode |
| --- | --- | --- | --- |
| `/opt/docker` | directory | `963:962` | `0750` |
| `/opt/docker/sonarr` | directory | `963:962` | `0755` |
| `/opt/docker/sonarr/compose.yaml` | file | `963:962` | `0600` |
| `/opt/docker/sonarr/.env` | file | `963:962` | `0600` |
| `/opt/docker/sonarr/config` | directory | `963:1001` | `0755` |
| `/opt/docker/sonarr/config/config.xml` | file | `963:1001` | `0664` |
| `/opt/docker/sonarr/config/sonarr.db` | file | `963:1001` | `0644` |
| `/opt/docker/sonarr/config/logs.db` | file | `963:1001` | `0644` |
| `/opt/docker/sonarr/config/logs` | directory | `963:1001` | `0755` |
| `/mnt/media` | directory | `0:1001` | `02775` |

These exact inspected paths were not symlinks. This is not proof that
all path components, descendants or mount boundaries are resolved.
ACL output for the config directory and media root showed only the
basic user/group/other entries; it says nothing about descendant ACLs
or effective container access. Observed modes are facts to adopt or
question deliberately, not permission to normalize an entire tree.

Selected XML facts were `Port=8989`, `SslPort=9898` and `LogLevel=info`.
API-key, authentication-method, bind-address and URL-base elements were
present; their values were not retained. No endpoint, TLS behavior or
actual bind address was verified. Database contents were not read.

### Resource and authority proposal

| Resource | Evidence and proposed responsibility | Initial authority boundary |
| --- | --- | --- |
| Sonarr deployment | Declared service/container `sonarr`, published image and restart behavior | Adopt only after identifying actual engine/project and complete effective inputs; do not derive identity from container name alone |
| Compose input and `.env` | Deployment choices and identity references | Version deliberate nonsecret choices; preserve secret references and bind exact accepted inputs; do not replace unrelated settings |
| `compose` account and `media` group | Declared UID/GID map to existing host identities; other definitions share them | Reference existing identity and required access; no renumbering, primary-group rewrite or exclusive deletion authority |
| Config directory itself | Existing app-data/config parent with observed ownership and mode | Adopt directory properties separately from contents; no automatic recursive ownership or permission changes |
| `config.xml` | Mixed operational configuration and credential material | Manage explicitly selected nonsecret properties and preserve protected secret inputs; no raw secret-bearing copy in Git and no replacement with redacted placeholders |
| `sonarr.db` | Existing persistent application data | Attribute to Sonarr and retain by explicit retirement choice; no desired byte-level snapshot in ordinary intent |
| `logs.db` and `logs/` | Existing runtime-output candidates | Verify their purpose and bound expected variation; unclassified files stay visible rather than hiding the whole directory |
| `/mnt/media` | Bind source also declared by Radarr, SABnzbd and Plex | Shared reference; keep other consumers' requirements and unknown use visible; no blanket deletion or recursive mode change |
| Host network | Declared `network_mode: host` | Refer to shared host networking and verify proposed listener conflicts; do not manage/delete a project bridge network for this source definition |

LinuxServer documents `/config` as containing database and configuration.
The actual `config.xml` and database files reinforce that distinction.
The directory cannot be treated as homogeneous versioned configuration,
nor as a runtime exclusion that hides deliberate configuration edits.
[Image volume documentation](https://docs.linuxserver.io/images/docker-sonarr/#volume-mappings-v)

Managing selected nonsecret XML properties still needs a concrete input
representation and safe update strategy: preserve secret values,
unmanaged fields and intervening application writes. The table does not
select a templating language or authorize rewriting the live XML.

## Worked lifecycle in a disposable fixture

This walkthrough uses the observed resource relationships. The proposed
changes, failures and results below have not occurred on the server.
Use fixture data/credentials and record adaptations from the real
definition; preserve UID/GID distinctions and shared-consumer checks.

1. **Adopt without applying.** Establish actual engine/project identity,
   effective inputs, image content/platform, mounts and running
   credentials. Accept only the desired management properties and
   account for the shared media consumers. Record this baseline without
   restarting, pulling an image, changing permissions or copying data.
   Remove an uncommitted declaration afterward: its previous baseline
   must still identify retirement scope without a preceding apply.
2. **Record a bounded change.** In the isolated fixture, propose changing
   Sonarr's configured HTTP port from its fixture baseline to a chosen
   free test port. Record intent and expected interruption; preserve the
   API key and unrelated settings. Live bytes/listeners must stay intact
   until application. Confirm the actual bind address, URL base and port
   availability before approving effects in the shared host network.
3. **Apply and observe a partial failure.** Write the intended supported
   configuration, then inject a failure before successful service
   verification. Status should distinguish matching file content,
   incomplete service behavior, work not attempted and the exact target
   of that attempt. Newer intent must not erase those effects. A retry
   rechecks live state and outstanding operations before mutating again.
4. **Resolve a manual edit.** Edit a managed nonsecret property outside
   the tool. Status detects the difference even though the file lives
   beside changing databases and logs. Demonstrate keeping the edit as
   intent and, in a separate reset, restoring it through a later apply.
   Neither status nor recording itself overwrites the file or restarts
   the workload. Intervening edits invalidate an earlier overwrite plan.
5. **Retire with a fresh data decision.** Ask whether to retain or delete
   Sonarr's identified private persistent data; that choice cannot
   include `/mnt/media` or shared identities merely because Sonarr used
   them. Verify stopping and restart policy before handling data. Kept
   configuration/database data stays attributable and accessible through
   the required retained identities without re-creating the workload.
   Demonstrate deletion separately on disposable exclusive data, with
   shared consumers still functioning. Unknown descendants or data
   consumers block destructive scope, and failed verification keeps the
   outcome incomplete/unverified.

An illustrative status after step 3 would report these facts separately:

| Subject | Current evidence | Pending work / history |
| --- | --- | --- |
| Managed port property | Intended fixture value now present | Configuration action completed for the recorded attempt |
| Sonarr service | Required endpoint check failed or unavailable | Service outcome incomplete/unverified; re-observation required before retry |
| Shared media consumers | Their declared checks and any gaps reported separately | Preserve their interests; do not infer success from Sonarr's file content |
| Newer intent | Compared against fresh observations | Previous attempt retains its own target and outstanding effects |

This is an information example, not a committed CLI or storage format.

## Verification and remaining evidence

Sonarr's upstream `/ping` implementation is a candidate bounded
application probe. It checks configuration-database responsiveness with
a five-second cache; it does not establish media access or external
integration health. Match the probe to the deployed version and effective
port/URL base before relying on it. No request was made during this
inspection. Separate access checks are needed for the application and
the known shared consumers.
[Upstream probe implementation](https://raw.githubusercontent.com/Sonarr/Sonarr/main/src/Sonarr.Http/Ping/PingController.cs)

Before an executable adoption or acceptance manifest, establish:

- Actual local Docker engine/project identity, invocation and all
  override/interpolation sources. The adjacent `.env` is not proof of
  effective values, and the configured container name is not a project
  name. Confirm the actual resolved bind sources and boundaries.
- Running image digest/platform, image-provided health checks, process
  credentials, observed restart behavior, listeners and application
  checks. Source-file inspection provides none of these runtime facts.
- The complete managed/nonmanaged file classification and protected
  secret input mechanism for `config.xml` and other relevant inputs;
  data and credentials must remain outside ordinary versioned intent.
- Actual shared-consumer/access evidence and a named, bounded exclusive
  data-retirement scope. Shared declarations establish reasons to
  preserve resources without proving current access or exhaustiveness.
- The reproducible disposable Arch fixture and real native/AUR package
  evidence required by the milestone. Sonarr uses bind mounts and host
  networking, so supplemental fixtures must exercise named-volume and
  project-network retention without pretending they exist here.

File access and primary application selection are now established.
These runtime and fixture gaps remain separate evidence requirements;
they do not justify treating the server as verified or running live
changes as a documentation check.
