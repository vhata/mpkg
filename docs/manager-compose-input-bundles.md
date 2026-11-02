# Captured Compose input preflight

`mpkg_manager.compose_inputs.validate_compose_bundle` validates a bounded,
closed subset of already captured Compose inputs. It is a pure library:
it reads no files, environment variables, stores or host policy, invokes
no native tool, and changes no host or recorded state.

This is an intermediate input preflight, not full first-release Compose
closure. The [execution design](specs/2026-10-31-first-release-storage-and-execution.md#compose-and-configuration-boundaries)
still requires effective interpolation, isolated native rendering,
effective-model comparison and immutable attempt storage. The existing
disposable proof uses JSON source documents, but its interpolation,
quoted runtime environment and short mount syntax exceed this subset.

## Private API and trust

```python
from mpkg_manager.compose_inputs import (
    CapturedComposeFile, ComposeInputBundle, validate_compose_bundle,
)

bundle = ComposeInputBundle(
    engine="accepted-engine-id",
    project="media",
    base_directory="/srv/media-inputs",
    source_paths=("/srv/media-inputs/compose.yaml",),
    services=("sonarr",),
    profiles=(),
    files=(CapturedComposeFile(
        path="/srv/media-inputs/compose.yaml",
        classification="protected",
        raw=b'{"services":{"sonarr":{"image":"sonarr:accepted"}}}',
    ),),
    interpolation_environment=(),
)
preflight = validate_compose_bundle(bundle)
summary = preflight.as_dict()
```

The input and returned records use frozen dataclasses, exact tuples and
immutable bytes. The returned `bundle` retains original source order,
engine/project, base directory, explicit service/profile selections,
classifications and original bytes. `references` is a tuple of private
occurrences: source-file index, role, owner, per-field position and
absolute lexical path. Role values are `env`, `config`, `secret` and
`bind`. An owner is the service or top-level config/secret name.

Constructing these Python values does not authenticate capture origin,
host policy, stored revision, freshness, engine identity or permissions.
The caller must supply already authenticated captures through its trusted
boundary. Raw JSON is not accepted as a bundle and cannot substitute for
[authenticated recorded input evidence](manager-recorded-input-evidence.md).
This module does not collect or authenticate captures itself, and does
not integrate with the recorder, planner or CLI.

Keep all input bytes and reference metadata private regardless of their
declared classification. Classification remains an explicit operator
decision, not secret detection. A file used by a Compose secret must be
classified `protected`; source, runtime environment and config inputs may
use either `protected` or `nonsecret`. All remain private in this API.

Representations omit private names, paths, identities and content.
`as_dict()` returns counts and fixed capability statements only:

```json
{
  "subset": "compose_json_no_interpolation_v1",
  "source_count": 1,
  "captured_file_count": 1,
  "reference_count": 0,
  "supported_reference_closure": "complete",
  "capture_authentication": "caller_required",
  "effective_model": "unverified",
  "full_input_closure": "unverified",
  "apply_authorized": false
}
```

`supported_reference_closure` means only that every file reference in the
accepted source subset has exactly one supplied classified capture.
It does not claim capture authentication or effective/native closure.
Neither public summaries nor directly constructed result objects grant
authority. Failures expose fixed `ComposeInputError.code` values without
source excerpts, paths, values or content digests.

## Versioned supported subset

The subset identifier versions this library's closed source schema; it
does not identify a tested or pinned native Compose version. No renderer
is provided. Source filenames may end in `.yaml`, but contents must be
UTF-8 JSON objects. YAML, duplicate JSON keys, nonstandard constants,
floating-point numbers and unknown fields at every accepted level fail.
Every document has a nonempty `services` object. Override documents may
omit an image; native image requirements and merge semantics are not
validated here.

| Location | Accepted fields and forms |
| --- | --- |
| Document | `services`, `volumes`, `networks`, `configs`, `secrets` |
| Service | `image`, `platform`, `restart`, `network_mode`, `environment`, `env_file`, `profiles`, `volumes`, `networks`, `configs`, `secrets`, `command`, `entrypoint` |
| Service environment | Map of valid environment names to explicit strings, including empty strings |
| Runtime environment files | String path or ordered list of string paths |
| Command and entrypoint | String or list of strings |
| Profiles and service network/config/secret references | Lists of unique names; long reference forms are unsupported |
| Service mounts | Long form with `type`, `source`, `target` and optional Boolean `read_only`; type is `bind` or `volume` |
| Top-level configs and secrets | Exactly one local `file` field |
| Top-level volumes and networks | Empty object or null, or object containing optional `name` and Boolean `external` |

`restart` accepts `no`, `always`, `on-failure` and `unless-stopped`.
`network_mode` accepts `host` and `none`; the same service document cannot
also declare `networks`. Local volumes use native defaults. Driver,
driver-option, plugin and network-driver settings are unsupported.
Names and paths have conservative bounded syntax; otherwise valid Compose
features outside the table fail explicitly. This includes ports,
healthchecks, dependencies, include, extends, builds, remote file inputs,
providers, lifecycle hooks, label files and extension fields.

Every source document is checked, including unselected services and
disabled profiles. Selected service/profile names and named resource
references must exist in the union of ordered document declarations.
That conservative reference check does not compute merged definitions,
active services, profile activation, dependency scope or prospective
resources. Native merging remains mandatory before any effective-model
claim. Source order and all original bytes are retained without merging.

## Environment and path boundaries

`interpolation_environment` is explicit and must be an empty tuple.
Interpolated source values such as `$NAME` or `${NAME:-default}` fail.
Paired `$$` escapes are retained byte-for-byte without replacement; an
unpaired dollar fails. Paths containing any dollar are unsupported.
There is no inherited shell, Docker or Compose environment, and no
automatic `.env` discovery. Supplying an otherwise unreferenced `.env`
capture fails as surplus input. A service may explicitly use `.env` as a
runtime `env_file`; that says nothing about interpolation inputs.

Runtime env-file bytes use a deliberately narrow grammar: ASCII lines
of `NAME=value`, with blank lines allowed. Names follow shell-variable
syntax and cannot repeat within one file. Values allow letters, digits,
spaces within a value, and `_./:@%+,=-`; leading/trailing whitespace is
refused. Empty values are accepted. Quotes, escapes, comments, carriage
returns, inherited bare names, dollar syntax and other characters fail.
This grammar avoids approximating general dotenv behavior. Config and
secret payload bytes are opaque and may contain arbitrary binary data.

The order of runtime env files within each source/service is preserved.
Repeated variables across different env files and explicit environment
maps remain separate original inputs. The validator never flattens them
or invents effective precedence. Docker documents runtime environment
and file-reference forms in its
[service reference](https://docs.docker.com/reference/compose-file/services/).
Native rendering must eventually verify their effective behavior.

All source and captured file paths are canonical absolute paths beneath
the explicit original base/project directory. Relative references resolve
against that directory even when an override source lives in a nested
directory. One initial `./` is allowed; empty, dot, parent, backslash,
URI/drive-prefix and home-expansion components are refused. Referenced
files outside the base directory fail. Captured paths and source paths
cannot repeat; one file cannot serve conflicting source/env/config/secret
roles. Reusing an env file across different services or source documents
is allowed, but duplicate resolved env paths within one service document
and duplicate mount targets there fail. Surplus captures fail.

Bind sources can be relative beneath the base or canonical absolute
paths elsewhere. These are lexical references only. They do not establish
existence, symlink resolution, inode identity, host-policy permission,
mount containment or captured bind contents. Named mounts and networks
also do not establish actual engine objects, ownership or lifecycle
authority. A future renderer must not copy lexical input paths into live
execution without the remaining checks.

## Bounds and remaining work

The validator accepts at most 16 ordered source files and 64 captured
files, at most 16 MiB per captured file and 64 MiB in total. JSON source
documents are limited to 1 MiB, 16 levels, 16,384 value nodes and 256
members per object/list. A bundle permits 1,024 reference occurrences,
256 selected services and 256 selected profiles. Paths are limited to
4,096 characters. Strings are limited to 65,536 characters. Runtime env
files permit 256 distinct keys. These are memory/structure bounds, not a
wall-clock guarantee.

The next rendering slice must bind this subset to a tested, pinned
Compose schema/version; authenticate all captures against exact recorded
context; explicitly capture effective interpolation inputs and precedence;
and prevent implicit environment or source discovery. It must preserve
dollar semantics while mapping every accepted reference into an isolated
immutable workspace, retain durable bind backing paths, and compare the
native merged/effective model with accepted resources. Unsupported YAML
and other features require an explicit future parser/schema decision.
Freshness, engine identity, actual bind resolution, accepted image
digest/platform and application authorization remain separate gates.

Focused tests exercise source/ref ordering, classification, missing and
surplus captures, conflicting roles, duplicate keys, path escapes,
environment inheritance and precedence preservation, unsupported features,
bounded inputs and private output. They patch file/process APIs to refuse
use and poison inherited Compose/Docker variables. They perform no native
rendering, production operation or full first-release acceptance check.
