# Frozen AUR text metadata

These three `.SRCINFO` files are the exact bytes referenced by
[`2026-10-31-arch-native-inputs.json`](../../../docs/fixtures/2026-10-31-arch-native-inputs.json).
Their recorded SHA-256 digests are verified by the parser regressions.
They describe ack `3.10.0-1`, perl-file-next `1.18-7` and gitstatus `1.5.5-1`.
No PKGBUILD was executed to create or test these copies.

They were downloaded from the official Arch AUR mirror at the manifest's
pinned commits, without following moving branch heads. The private
acquisition implementation tests use synthetic recipe/source bytes; these
files separately establish compatibility with the selected fixture's real
metadata and source/checksum syntax.
