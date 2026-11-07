# Native transaction preparation

`mpkg_manager.native_preparation.prepare_native_transaction()` prepares a
private, immutable repository-package proposal. It copies a stable local
package database, preacquired repository metadata, a public trust keyring,
and offered signed package archives into a new private staging directory.
The fixed `/usr/lib/mpkg/native-prepare` bridge resolves the transaction
with libalpm 16.0.1. The function does not refresh the live package database,
download packages, install dependencies, or expose an apply request.

This is a trusted library boundary. Paths, source fingerprints and the
optional test runner come from installed integration code; they are not
accepted fields in the public helper protocol. Constructing a preparation
object or comparing its scope never grants execution authority.

## Inputs and native resolution

Supply a host UUID, the local package database directory, a keyring
directory containing exactly `pubring.gpg` and `trustdb.gpg`, an existing
private `0700` staging root, and ordered typed input tuples:

- `NativeRepository` binds the repository name, ordered HTTPS servers,
  database SHA-256, optional detached database signature and its SHA-256,
  and whether the database signature is required. Package signatures are
  always required and trusted. Optional database signatures are still
  verified when present; this is explicit policy, not an automatic fallback.
- `NativeArtifact` binds a concrete package name, version and repository to
  archive and detached signature paths and hashes. Every selected archive
  must match the native sync metadata digest and pass libalpm's signature
  validation. Offered archives outside the selected closure grant no scope.
- `NativeRequest` expresses an unrestricted package dependency name or an
  exact version. libalpm interprets versioned virtual dependencies using
  its own provider semantics; an exact provided version can differ from
  the provider package's version. Unsupported operators are refused.

The bridge opens only the staged database under an empty staged root. It
performs native system-upgrade selection before additional requests. A
request already satisfied by the proposed final package inventory causes
no redundant archive reinstall. Existing dependency packages explicitly
requested by the caller have a separate dependency-to-explicit reason
change in the manifest. Pre-existing independent explicit reasons remain
explicit; newly selected dependencies remain dependencies.

Repository ordering controls native selection. If native resolution asks
for a provider, the bridge proposes its first native candidate and records
that choice. Replacement questions propose and record the old/new package
pair and complete removal set. Other questions, including key import,
conflict removal and skipping unresolvable packages, block preparation.
Nothing in those proposals authorizes an effect. Dependency rows identify
a native satisfier in the resulting inventory, not a uniquely necessary
provider where multiple installed packages could satisfy the same edge.

libalpm performs all dependency/version resolution. The Python boundary
validates its closed result, request coverage, exact concrete versions,
artifact closure and removal explanations; it does not implement a second
package solver or use `pacman --print` as a fallback.

## Stable inputs and retained manifest

Descriptor traversal refuses symlinks, special files, hard-linked regular
files, writable input files and changed identities. Nonblocking opens
prevent a FIFO substitution from hanging capture. Local metadata is copied
between repeated complete identity/content observations, and checked again
after native preparation. Source and staged keyring changes also refuse the
result, including automatic trustdb changes by native verification. A
keyring needing such maintenance must be prepared explicitly before this
operation; a changed trust result is never bound to the original keyring.
This detects observed changes; it is not an atomic snapshot or reservation
against an independently operating package manager.

Metadata/keyring captures are bounded to 40,000 entries and 256 MiB each.
Repository database/signature files are bounded to 256 MiB each. Package
archives are bounded to 2 GiB each, with a 16 GiB aggregate archive/signature
budget. Artifact fingerprints stream bytes without retaining archive
contents in memory. The bridge has a 30-second deadline, private bounded
output and a fixed minimal environment. Failed commands and exceptions
produce fixed codes, never raw tool errors or source paths.

The successful manifest retains:

- Host, architecture, libalpm version, copied installed inventory and
  installation reasons, and installed/keyring fingerprints.
- Ordered source servers, metadata/signature fingerprints and signature
  policy.
- Original exact/unrestricted requests, their native satisfiers, complete
  additions/removals, separately proposed reason changes, dependencies,
  provides, and provider/replacement choices.
- Archive/signature fingerprints for the complete selected artifact
  closure, coordinated-upgrade scope, and native transaction flags.

The manifest is written under the private stage; successful preparations
retain their copies. Failed preparations may leave private orphan stages
for explicit inspection/removal. No stage is reused as a new preparation.
The returned object's `manifest` is a fresh private projection, while
`as_dict()` exposes only counts, a preparation UUID and explicit acceptance
limits. It omits paths, servers, hashes, native output and credentials.
`require_same_native_scope()` refuses changed providers, widened upgrades,
reasons, sources, inputs or other bound scope; it cannot authorize commit.

## Building the staged bridge

The existing package staging script copies Python modules. The native
bridge is an explicit additional build step on an Arch build environment
with a compiler and libalpm development files. For an existing empty package
directory, the complete inert payload can be assembled with:

```bash
bash packages/mpkg-manager/stage.sh /absolute/empty/package-directory
bash native/build.sh /absolute/empty/package-directory/usr/lib/mpkg/native-prepare
```

`native/build.sh` compiles the bridge and refuses an existing output. It
does not install, activate or execute it. The fixed runtime path matches
the Python caller. The bridge requires libalpm `16.0.1`; another ABI/version
is a blocking result, not permission to use a different native path.
Installing that payload or running preparation against a real host is a
separate approved operation. The public recording/status helper has no
preparation handler in this change.

The implementation uses libalpm's
[prepare/release transaction APIs](https://man.archlinux.org/man/libalpm_trans.3.en),
[native package and signature loading](https://man.archlinux.org/man/libalpm_packages.3.en),
and [repository validation](https://man.archlinux.org/man/libalpm_databases.3.en).
The bridge contains no transaction commit or database-refresh call, refuses
fetch callbacks, and imports no configuration from the caller's environment.

## Validation and remaining acceptance

`tests/test_manager_native_preparation.py` uses temporary input trees and
controlled bridge responses. It covers unstable inventories, file races,
signature failure, missing/substituted artifacts, unavailable pins, native
choices, reason preservation, no-op and reason-only requests, source policy,
widened upgrade scopes, malformed responses, timeouts and output secrecy.
It runs no live package or service operation.

C warning-clean compilation and linking verify build compatibility only.
They do not prove real signature validation, dependency/provider behavior,
libalpm ABI compatibility in an installed payload, hooks or native commit.
The original
[native execution acceptance task](../plans/2026-11-07-execution-work-breakdown.md#accept-native-execution)
must exercise the selected ABI, full upgrade solution and exact accepted
artifact transaction. The earlier
[prepare-only experiment](fixtures/2026-11-01-disposable-execution-evidence.md)
does not establish a committed transaction or waive those gates.
