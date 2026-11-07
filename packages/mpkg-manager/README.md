# Host-helper payload

`bash packages/mpkg-manager/stage.sh EMPTY_PACKAGE_DIRECTORY` assembles an
inert file tree for packaging. It performs no installation, policy setup,
store initialization, tmpfiles activation or host lifecycle operation.
The helper requires `/usr/bin/python3.12`; substituting another Python
minor is unsupported. A release package and real installation validation
remain separate work.

The resulting files belong to root. `/usr/lib/mpkg/host-helper.py` serves
requests under explicit operator authorization. The fixed
`/usr/lib/mpkg/attempt-worker.py` accepts only one attempt UUID. Both use
the same hardened bootstrap source and isolated Python shebang. Never run a checkout or
caller-supplied Python module with sudo. The launcher refuses another
entrypoint path, non-root invocation, non-isolated Python, writable or
symlinked code, and any Python minor other than 3.12. The installed
module directory contains source files only, without bytecode caches.

An administrator must separately provision the private host policy and
activate the included tmpfiles rule for the mutation lock. No default
policy, sudo rule or Docker group grant is installed. Store creation is
an explicit `record/initialize` request and refuses existing state.

See the [host-helper protocol](../../docs/manager-host-helper.md) for
supported requests, output redaction, transport limits and validation.

The [attempt supervisor](../../docs/manager-attempt-supervision.md) owns
the fixed service specification and durable reservation handoff. Staging
does not launch workers; production execution remains unavailable.
