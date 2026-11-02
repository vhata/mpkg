# Sonarr XML Port transformation

`mpkg_manager.sonarr_xml` implements a pure transformation of protected
configuration bytes. It changes only the existing `Port` value, the field
supported by the [declaration schema](manager-declarations.md). It does not
read or write files, inspect containers, stop writers, restart Sonarr,
record a plan, or authorize application. `UrlBase` and `LogLevel` remain
outside this adapter's interface.

## Protected interface

```python
from mpkg_manager.sonarr_xml import transform_port

candidate = transform_port(
    freshly_captured_bytes,
    8990,
    expected_original=accepted_protected_bytes,
)
public_summary = candidate.as_dict()
# candidate.candidate_bytes stays inside the protected caller boundary.
```

Both inputs must be immutable `bytes`, each at most 16 MiB. They must match
exactly, including whitespace and unrelated values. A mismatch raises
`SonarrXmlError` with code `original_changed`. This comparison is a stale
input check inside the library, not an atomic file protection mechanism.

The result is a frozen `SonarrPortCandidate`. `candidate_bytes` is excluded
from its representation. `original_port`, `port` and `unchanged` describe
the selected property; `as_dict()` returns a fresh dictionary with those
fields and fixed adapter/capability metadata. It reports
`serialization_changed: false` and `apply_authorized: false`. No whole-file
hash, XML field name, source excerpt or secret value appears in that public
projection or in errors. `SonarrXmlError.code`, its string representation
and exception arguments contain only a fixed diagnostic code.

The explicit candidate byte field still contains secrets. It must not be
logged, exported, or passed to generic dataclass serializers. The public
projection is `as_dict()`; this module is not a general secret container.

## Supported XML subset

The input must be XML 1.0 encoded as UTF-8, optionally with a UTF-8 byte
order mark. An XML encoding declaration, when present, must name UTF-8.
The parser requires Expat 2.6.0 or newer and retains its normal large-token
protections. DTD declarations, custom entities and external entity access
are refused; parameter entity processing is disabled. Standard XML escapes
and numeric character references in unrelated text or attributes are
preserved as their original bytes. These limits follow the
[Python XML security guidance](https://docs.python.org/3.12/library/xml.html#xml-vulnerabilities)
and [Expat interface](https://docs.python.org/3.12/library/pyexpat.html).

The root must be `Config`, with at most 256 uniquely named direct child
elements and no nested elements. Unknown flat fields are preserved; this
does not claim knowledge of Sonarr's entire configuration grammar. Element
and attribute names are ASCII letters, digits, `_`, `.`, or `-`, beginning
with a letter or `_`, and at most 128 characters. Each element may have at
most 64 attributes. Namespaces, duplicate fields, non-whitespace text
between fields, CDATA and processing instructions are unsupported.

Exactly one direct child must be named `Port`. Its content must consist of
one to ten ASCII decimal digits, optionally surrounded by XML whitespace
(`space`, `tab`, `CR`, `LF`). Comments, character references, nested markup,
signs, Unicode digits and other forms of Port content are rejected. The
observed port may be any valid TCP port from 1 through 65535. Requested
intent must be an integer from 1024 through 65535, matching the declaration
schema; booleans are rejected. An existing privileged port can therefore
be transformed to an allowed target, but this library does not authorize
that change or permit requesting a privileged target.

## Preservation and application boundaries

Parser byte offsets identify the actual Port text; apparent Port tags in
comments or attribute values cannot select a replacement. The transformer
replaces only the decimal digit span. All bytes outside it remain exact,
including whitespace, comments, attribute quoting, declarations, unknown
fields, XML escapes and protected values. A numerically matching target
returns the original bytes unchanged, including leading zeros. A changed
candidate must also fit within 16 MiB. There is no XML reserialization.

Before any future publication, a trusted caller must bind the accepted
protected input and source identity, establish a maintenance interval
excluding other editors, stop all identified writers, and reread the file.
It must recheck identity and content immediately before a supported atomic
publication, preserve required metadata, and verify effective properties
after restarting the same accepted workload. This pure module implements
none of those operations. Exact byte comparison alone cannot prevent an
intervening editor from overwriting or being overwritten.

The [storage and execution design](specs/2026-10-31-first-release-storage-and-execution.md)
defines those requirements. Existing disposable evidence showed that
Sonarr can change XML serialization during startup while preserving the
checked values; see the
[execution record](fixtures/2026-11-01-disposable-execution-evidence.md).
Library byte preservation is not a claim about application restart
behavior or completed product acceptance.

## Validation

```sh
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m unittest discover \
  -s tests -p 'test_manager_sonarr_xml.py' -v
```

The focused tests cover exact preservation with decoy comments, escaped
secret text and attribute delimiters; no-op bytes; both port ranges;
stale inputs; immutable results; fixed diagnostics and public projections;
malformed, duplicate, nested and namespaced documents; DTD/entity attacks;
encoded Port values; encoding limits; input/candidate sizes; and parser
structure limits. Tests forbid file, subprocess and network entrypoints
around pure transformation and external-reference rejection. No host
configuration or service lifecycle operations run.
