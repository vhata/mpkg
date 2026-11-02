# Public endpoint TLS test material

The self-signed localhost certificate and matching private key are public,
nonproduction test fixtures. They are intentionally committed and confer
no trust outside these tests. The certificate covers DNS localhost only;
this permits an explicit hostname-mismatch regression for 127.0.0.1.

The isolated worker uses its default verified trust store and must reject
this certificate, including when the parent environment tries to trust it.
A direct private-worker test explicitly trusts this fixture in its own
Python SSLContext to verify the successful TLS path without changing the
host trust store or public observer interface.
