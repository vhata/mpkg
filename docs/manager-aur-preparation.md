# Pinned AUR recipe preparation

`mpkg_manager.aur_recipes.prepare_recipes` acquires explicitly accepted
recipe and source bytes and retains their recursive AUR input closure.
It performs no shell evaluation, PKGBUILD metadata generation, dependency
installation, source extraction or package build. It is a trusted library
boundary; no installed request or CLI exposes this preparation yet.

## Exact pins and trust

Each immutable `RecipePin` names an AUR package base, canonical 40-character
commit, expected version and output package names. It lists every accepted
recipe file and upstream source with exact SHA-256 and/or SHA-512 hashes.
Recipe URLs must identify the same commit in the official Arch AUR GitHub
mirror. `PKGBUILD` and `.SRCINFO` are mandatory. Declared install/changelog
files and local source files must be present in the accepted recipe set.

`RecipeTrust` explicitly accepts the complete pin's identity and binds a
trusted operator UID and decision UUID. Missing trust, a changed pin,
unknown provenance or different expected metadata fails before acquisition
can produce a preparation. The trust object is trusted embedding data,
not a request credential or permission to execute arbitrary recipe code.
The caller must establish that the operator actually reviewed the bytes
identified by these pins. A transport hash does not certify benign code.

Acquisition uses fixed Python HTTPS transport, certificate validation and
the accepted hashes. It accepts only the source hosts used by the frozen
fixture: the official raw mirror, GitHub/codeload and CPAN. URLs carrying
credentials, queries, fragments, encoded/traversal paths or unsupported
schemes are refused. Redirects use the same host/scheme restrictions.
Ambient proxy settings do not select a transport. No subprocess, package
helper, shell startup file or PKGBUILD entrypoint is invoked.

Both original metadata and each acquired source must match the accepted
pins. Source names, URLs and strong checksums must also match `.SRCINFO`;
all accompanying declared checksums are verified. Local patch sources use
their accepted recipe-file bytes. Weak-only checksums, `SKIP`, VCS sources,
unknown metadata keywords and unsupported source syntax fail explicitly.
There is no mutable-branch or unchecked-download fallback.

## Metadata and recursive dependency boundaries

The text parser follows the section, override and architecture rules in
[Arch's SRCINFO specification](https://man.archlinux.org/man/SRCINFO.5.en).
It retains build/test dependencies at package-base scope and resolves each
split package's runtime dependency overrides for the selected architecture.
Version expressions are preserved; only the native solver can establish
their satisfaction. Optional dependencies and other accepted metadata remain
private metadata and never become automatic installation requests.

The accepted expected version and output names must match the pinned text.
This does **not** establish that arbitrary PKGBUILD code generates that
metadata. `generated_metadata` remains `unverified` in every public result.
Regeneration, source verification and comparison must happen in the later
isolated build stage. The frozen ack recipe illustrates the distinction:
its source-generated homepage differed from its checked-in `.SRCINFO`.
Preparation preserves those inputs rather than silently reconciling them.

Every required dependency name has an explicit `DependencyChoice`:

- `native` retains the exact request and phase for native resolution,
  including provider selection. It does not claim a repository package
  exists, is installed or satisfies a version constraint.
- `aur` names a pinned recipe and one of its output packages. The output
  must advertise the requested package name or provision. Its version
  constraint still requires native validation.

Preparation recursively acquires all selected AUR recipes, deduplicating
shared inputs. It records runtime/build/check edges separately and returns
a recipe build order. Recursive cycles and dependencies on the same
recipe's unbuilt output during build/check are refused. Runtime edges
between distinct split outputs remain valid; they need no second recipe
build. Missing routes, wrong providers and unused recipe pins are refused.
This is explicit input routing, not a replacement dependency solver.

## Private result, limits and validation

`PreparedRecipes` retains immutable private manifest bytes and acquired
files for trusted downstream embedding. The manifest binds the exact
recipe/source pins, accepted trust decisions, text metadata and acquired
file identities. Ordinary `as_dict()` output contains package/version and
dependency summaries without URLs, recipe bytes, arbitrary descriptions,
source digests or raw transport errors. Exceptions expose fixed codes.
It always reports `build_authorized: false`, `installation_authorized:
false`, unverified generated metadata/signatures and required native
resolution. Constructing or copying this object conveys no authority.

There are at most 32 recipes, 128 acquired files, 1 MiB per recipe file,
32 MiB per upstream source and 128 MiB total. Exceeding a limit refuses the
whole preparation; bytes are never truncated into a usable result. No
partially acquired object is returned. Acquisition stays in memory and
does not publish artifacts or accepted host history.

Transport checks a 120-second budget between operations and single-read
body chunks, with socket timeouts capped at 30 seconds. These are not a hard
supervised wall-clock deadline: DNS, response headers, HTTP framing and a
blocking read can delay the next budget check. Hostile or unavailable
sources still cannot bypass byte/hash bounds or cause recipe execution.

Tests use controlled acquisitions, pinned historical `.SRCINFO` fixtures,
recursive/shared/cyclic dependencies, malformed metadata, substitutions,
missing sources, hostile startup environments, bounded transport doubles
and private error sentinels. Only the three pinned metadata fixtures were
downloaded during development. No recipe/source build, real native solver,
dependency installation or AUR artifact acceptance was performed. Those
remain required by the build/install tasks and first-release acceptance.
