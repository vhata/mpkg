# Native package request satisfaction

`mpkg_manager.observe_packages.observe_package_requests()` collects positive
unversioned dependency satisfaction for package declarations. It complements
the [direct installed-package inventory](manager-observations.md#packages):
an installed provider may satisfy a request whose literal package name is
absent from that inventory. This library performs no installation, source
refresh, adoption or transaction preparation.

Pass a list or tuple of at most 256 normalized package resources, a host UUID
and optionally a UTC collection-start timestamp. Only package resources are
accepted. Logical IDs remain distinct while duplicate requested names share
a query target. Names retain the declaration schema's bounded ASCII syntax;
version expressions, options, alternate roots and commands are not accepted.

The immutable `ObservationBatch` covers every requested resource and contains
only `present` facts with evidence source `pacman_dependency_satisfaction`.
Satisfaction produces `known` / `true`. An unmet request produces `unknown`
with `package_request_unsatisfied_or_database_unavailable`, never `false`.
No provider identity, installed version, installation reason, repository/AUR
provenance or management authority is inferred. Source-specific facts must
not be relabelled as direct installed-package inventory.

The [pure planner](manager-planning.md) accepts this source only for positive
`present` comparisons after its usual host, coverage, identity and freshness
checks. It rejects stronger property claims and fabricated false, integer or
other non-true presence values. Positive request evidence cannot satisfy the
direct inventory prerequisite for version or installation-reason comparison.
Reports remain non-executable and retain native transaction and application
blockers. Supplying the wire projection does not authenticate its origin.

## Native protocol and limits

The closed query is `/usr/bin/pacman -T --` followed by deduplicated names.
The [pacman manual](https://man.archlinux.org/man/pacman.8.en) describes
dependency testing against installed packages. The
[pacman 7.1.0 implementation](https://gitlab.archlinux.org/pacman/pacman/-/blob/v7.1.0/src/pacman/deptest.c)
checks direct names and native satisfiers, returning zero with empty output
when all requests are satisfied or 127 with unmet targets on separate lines.
The adapter requires those exact status/output combinations, complete
newline-terminated rows, unique rows and membership in the requested set.
Any diagnostic on stderr invalidates the query; neither diagnostics nor
malformed stdout becomes a public error message.

Two queries must produce identical unmet sets. A failure, malformed response
or changed set invalidates the entire batch. Empty selections run no query.
Each query has a ten-second deadline and a combined stdout/stderr limit of
128 KiB. Stdin is closed and the environment contains only a fixed PATH and
C locale. There is no shell, sudo, inherited loader setting or caller-selected
executable. Failure and cancellation terminate the private process group;
accepted nonzero exits also terminate any remaining descendants before
returning private stdout. Leader cleanup allows at most one extra second.
The internal runner's default zero-only policy remains unchanged for other
adapters. Injected test runners are trusted and must honor these boundaries.

Repeated samples detect differences, not an atomic package-database snapshot.
The normal host pacman configuration remains trusted, as with the direct
inventory adapter. This is observational evidence, not a native transaction
plan or proof of complete database integrity.

## Why unmet requests stay unknown

Native dependency testing does not reliably distinguish every incomplete
database read from absence. In the
[local database reader](https://gitlab.archlinux.org/pacman/pacman/-/blob/v7.1.0/lib/libalpm/be_local.c),
some package-cache failures have no printed diagnostic, and directory
iteration does not check the final `errno`. The dependency-test operation
does not check the resulting libalpm error. A partial cache can therefore
omit a package or provider while still producing the expected 127 response.

A fixed installed-package sentinel cannot prove complete iteration, and
[the native consistency checker](https://gitlab.archlinux.org/pacman/pacman/-/blob/v7.1.0/src/pacman/database.c)
has similar iteration/error limits. The adapter consequently retains positive
satisfaction and leaves every unmet request unknown. It does not install a
dependency solver or inspect the database itself to invent stronger evidence.

## Validation scope

Focused tests use synthetic native responses and private short-lived Python
children. They cover direct/provider-style satisfaction, unmet and changed
sets, malformed protocols, resource limits, immutable identity binding,
environment isolation, accepted nonzero cleanup, stderr rejection, output
limits and late completion. They do not run pacman on the host or establish
real Arch package acceptance, provider identity or application readiness.
