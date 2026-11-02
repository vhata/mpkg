# Manager declarations

The replacement manager has a Python 3.12 declaration-validation entrypoint.
The existing `mpkg` executable remains the package helper. Validation is an
implemented foundation; host recording, observation, planning, application
and the [A1–A12 acceptance scenarios](specs/2026-10-31-first-release-acceptance.md)
are not implemented by this command.

```sh
bash scripts/setup.sh
.venv/bin/python -m mpkg_manager validate environment.toml --json
```

The command reads only the explicitly named regular file, without following
a symlink. It refuses FIFOs, device files, inputs larger than 16 MiB, and
files observed changing during the read. It does not read referenced inputs,
discover host state, create a management store, run package tools or contact
Docker. Success means the declaration has a supported shape, not that its
resources exist, its checks pass, or any proposed effects are authorized.

Success exits zero. Invalid declarations or arguments exit two. Unavailable
input files exit three. Failure output is JSON with a fixed error `code` and
a structural `path`; it contains no offending values or source excerpts.
Parser conversion and nesting limits also produce fixed errors, without
tracebacks or parser diagnostic text.
`--json` returns schema and normalization versions, the normalized model's
SHA-256, counts and `application: "not_implemented"`. Human output gives the
same limited validation claim.

## Root and components

The root requires `schema = 1`, a `components` array and a `resources` array.
The optional `inputs`, `checks` and `runtime_rules` arrays default to empty.
Unknown keys, duplicate IDs, floating-point numbers, TOML dates/times, values
outside signed 64-bit integers and invalid Unicode are rejected. Booleans
are distinct from integers. Meaningful array order is retained.

Logical IDs begin with an ASCII letter or digit and may contain ASCII
letters, digits, `_`, `.`, `:`, and `-`; their maximum length is 128. The
`external:` prefix is reserved for named consumers outside management.
Component IDs cannot use that prefix.

A component requires `id`, nonempty `purpose`, and an ordered `resources`
array of resource IDs. Optional `requirements` entries have exactly
`resource`, `property` and `value`. Each requirement addresses a resource
the component references and uses that kind's property type. Conflicting
consumer requirements, or disagreement with the resource's desired value,
are errors. Requirements describe use; they grant no management authority.
Kind-specific property relationships and input references are validated
against the combined desired properties and consumer requirements.

```toml
schema = 1

[[components]]
id = "tools"
purpose = "Interactive command-line tools"
resources = ["git", "workspace"]

[[resources]]
id = "git"
kind = "package"
identity = { name = "git" }
manage = ["present"]
desired = { present = true, source = "repository", version = { policy = "any" } }

[[resources]]
id = "workspace"
kind = "directory"
identity = { path = "/srv/workspace" }
manage = ["mode"]
desired = { mode = 0o750 }
consumers = ["external:backup"]
```

## Resources and identity

A resource requires `id`, `kind` and `identity`. `desired` defaults to an
empty table; `manage`, `consumers`, `checks` and `requires` default to empty
arrays. Optional `purpose` is nonempty text. Every managed property must
have a desired value. A desired value without a management grant cannot
authorize a mutation.

`consumers` names components or nonempty `external:<name>` references.
Component resource references also contribute consumers in the normalized
model. An explicit component consumer must reference the resource itself.
`requires` names other resource IDs and must form an acyclic graph; these
are resource relationships, not executable commands or an action program.
`checks` contains IDs of checks scoped to that resource. Optional
`input = { bundle = "id" }` references a declared input bundle.

All identities and properties below are closed tables: a new property
requires code implementing its validation. Path identities are absolute,
lexically normalized POSIX paths; no filesystem or symlink resolution is
performed. Leading `//` is unsupported. File, directory, symlink and XML
identities share one path namespace, so aliases such as `/srv/child/../data`
cannot declare a second resource at `/srv/data`.

Names in physical identities and account properties are bounded ASCII
tokens containing letters, digits, `_`, `.`, `@`, `+` and `-`; they cannot
contain whitespace or slashes. Host and accepted engine IDs are bound later
by the host store. A declaration's package name remains the request;
validation does not claim to have selected an installed provider. Different
engine aliases may require further duplicate-identity checks after binding
to actual accepted engine IDs.

| Kind | Required identity fields | Supported desired properties |
| --- | --- | --- |
| `package` | `name` | `present` boolean; `source` (`repository`, `aur`, `unknown`); `version` table below |
| `compose` | `engine`, `project` | `running` boolean; `profiles` and `services` arrays of names; `images` array below |
| `volume`, `network` | `engine`, `name` | `present` boolean |
| `service` | `manager = "system"`, `unit` | `running`, `enabled` booleans |
| `user` | `name` | `present` boolean; absolute `home`, `shell`; `primary_group` name; additive `groups` array |
| `group` | `name` | `present` boolean; additive `members` array of names |
| `file` | `path` | `present` boolean; `owner`, `group` names; integer `mode` from `0` to `0o7777`; either nonsecret UTF-8 `content` text or `content_input` bundle ID |
| `directory` | `path` | `present`, `owner`, `group`, `mode` as above |
| `symlink` | `path` | `present`, `owner`, `group`, `mode` as above; nonempty `target` text |
| `sonarr_xml` | `path` | Integer `port` from `1024` to `65535` |

These types record intent. They do not imply every effect is supported by
an installed adapter. For example, the first-release contract does not
authorize account deletion, numeric-ID changes, arbitrary volume drivers
or modifying symlink permissions. Unsupported effects must remain blocked
when a planner is added, even if their desired facts can be represented.

A package version is `{ policy = "any" }` or
`{ policy = "exact", value = "1:2.3-1" }`. Exact AUR intent additionally
requires `recipe_revision`, a complete 40- or 64-character lowercase hex
commit ID. A recipe revision is not accepted for a non-AUR source. `any`
does not accept an observed version as a hidden pin. Availability and Arch
transaction compatibility remain native integration prerequisites.
These rules apply to the combined source and version constraints from
desired properties and all consumer requirements, after conflict checks.
Combining constraints does not add desired properties or grant management
authority.

Each Compose image entry requires `service`, `reference` and `policy`
(`any` or `exact`). Exact intent also requires a lowercase `sha256:` digest
with 64 hex digits and a nonempty `platform`. Optional `updates_allowed`
is a boolean and never schedules anything. Service entries are unique;
mutable policy cannot carry a purported immutable digest. Registry
resolution, platform availability and full Compose input semantics remain
separate preparation and observation work.

## Input bundles

An input has `id`, absolute `base_directory`, and a nonempty ordered
`files` array. Each file has a normalized relative `path` and explicit
`classification` of `nonsecret` or `protected`. Paths cannot escape the
base through `..`; duplicate normalized paths are errors. Protected files
also require a canonical UUID `reference` from the
[protected recorder](manager-protected-bindings.md); nonsecret
files cannot carry such a reference. Literal secret values are not fields
in this schema. The validator never reads or compares referenced bytes.

```toml
[[inputs]]
id = "sonarr-inputs"
base_directory = "/srv/sonarr"
files = [
  { path = "compose.yaml", classification = "nonsecret" },
  { path = ".env", classification = "protected", reference = "0a89debe-8e38-4e24-a27f-b3763ad252a8" },
]
```

File `content_input` refers to a bundle containing exactly one file. A
file cannot combine literal `content` and `content_input`, including when
different consumers or desired properties supply the two constraints. A
protected reference identifies required content without exposing it; its
availability, source identity and freshness need authenticated recording
and a current-policy comparison. A syntactically valid UUID alone is not
a binding or read capability.
Classifying data as nonsecret is an explicit responsibility. Validation
does not promise automatic secret detection in source declarations.

## Checks

Every check requires `id`, a closed `kind`, `resource`, and integer
`timeout_seconds` from 1 through 60. Unknown keys and executables are
rejected. These are check declarations; `validate` executes none of them.

| Kind | Additional required fields | Resource kinds |
| --- | --- | --- |
| `package` | Nonempty `expected` table with boolean `present`, text `version`, and/or `reason` (`explicit`, `dependency`) | `package` |
| `service` | Nonempty `expected` table with boolean `running` and/or `enabled` | `service` |
| `endpoint` | `url` and integer `expected_status` from 100 through 599 | `service`, `compose` |
| `access` | `as_user` name, `operation` (`read`, `list`), and a declared `consumer` | `file`, `directory`, `symlink`, `volume` |

Endpoint URLs use HTTP or HTTPS, an explicit port, and `localhost`,
`127.0.0.1` or `::1`. User information, query strings, fragments, whitespace
and literal ASCII controls (C0 and DEL) are unsupported. The
original URL is checked before parsing; percent-encoded path data stays
encoded and unchanged. Stored declarations containing literal controls
also fail when their contents are revalidated; no rewrite is performed.
Authenticated application checks, response
content checks and write-access verification require a further bounded
schema and implementation; they cannot be represented as arbitrary
commands, headers or secret arguments.

## Runtime scope

A runtime rule requires `id`, an existing `component`, absolute `root`,
nonempty `patterns` and `types` arrays, and an `exceptions` array. Patterns
are relative path patterns without `..`; supported entry types are `file`,
`directory` and `symlink`. Exceptions are normalized absolute paths within
the rule's root. Every declared file or `sonarr_xml` path under that root
must be an explicit exception, so a broad runtime rule cannot hide known
configuration. No traversal, mount crossing or file classification occurs
during validation; those need a bounded observer.

## Python interface and snapshots

`mpkg_manager.declarations.load_declaration(raw_bytes)` returns an immutable
`Declaration` with `source_bytes`, `canonical_bytes`, `sha256`,
`schema_version` and `normalization_version`. Its `model` property returns a
fresh decoded projection; mutating that projection does not alter the
snapshot. Canonical JSON uses UTF-8, sorted object keys, fixed scalar types
and meaningful array order. Original TOML bytes remain separate, and a Git
commit is never substituted for them.

`validate_model(value)` validates a decoded declaration dictionary through
the same fixed-type, root, reference and contextual rules used by the TOML
loader. It returns a fresh normalized dictionary without modifying or
retaining caller objects. This supports validation of stored records and
combined consumer constraints without a TOML round trip. Malformed values,
cycles and excessive nesting fail through `DeclarationError`.

`canonical_json(value)` is the shared fixed-type encoding operation.
`physical_key(resource, host_id, engine_aliases)` binds an already validated
resource to accepted host/engine context without inspecting the host.
`DeclarationError.code` and `.path` are bounded diagnostics; its string
representation is the code alone.
