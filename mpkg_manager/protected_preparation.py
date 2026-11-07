"""Private, single-use staging for protected recording across helper requests.

Only authenticated metadata is staged. Captured bytes enter accepted history
only in the recorder's existing atomic decision transaction. Callers own the
host mutation lock for the complete prepare or consume operation.
"""
import hmac
import os
import uuid

from .protected_bindings import (BindingError, PreparedProtectedInput,
                                 MAX_PROTECTED_BYTES, MAX_PROTECTED_ENTRIES,
                                 _PURPOSE)
from .store import (MAX_INPUT_BYTES, StoreError, _PREPARATION_DOMAIN, _decode,
                    _declared_protected, _file_info, _framed_mac, _json)


MAX_PENDING_BYTES = 1024 * 1024
_PENDING = "protected-preparation.json"
_NEXT = "protected-preparation.next"
_MANIFEST_DOMAIN = b"mpkg/protected-recording-manifest/v1"
_CAPTURE_DOMAIN = b"mpkg/protected-recording-capture/v1"


def _context(recorder, declaration, revision):
    with recorder._store._read():
        recorder._revision(revision)
        recorder._store._check_bound_identities(declaration)
        return {"version": 1, "host_id": recorder._store.host_id,
                "revision": revision,
                "snapshot_id": recorder._store._snapshot_id(declaration),
                "policy": recorder._policy_context()}


def _captures(recorder, declaration, context):
    entries = _declared_protected(declaration)
    if (not entries or len(entries) > MAX_PROTECTED_ENTRIES
            or len({entry["reference"] for entry in entries}) != len(entries)):
        raise BindingError("invalid_preparation")
    prepared, evidence, total = [], [], 0
    for entry in entries:
        with recorder._store._read():
            recorder._revision(context["revision"])
            exists = recorder._store._db.execute(
                "SELECT 1 FROM protected_inputs WHERE id=?", (entry["reference"],)).fetchone()
            if exists and recorder._store._bound_capture(
                    entry["reference"], context["snapshot_id"], context["revision"]) is None:
                # An explicit preparation cannot promote a legacy or other
                # snapshot's reference into an authenticated baseline.
                raise BindingError("invalid_preparation")
            key = recorder._key()
        captured = recorder._capture(entry, max_bytes=min(MAX_INPUT_BYTES, MAX_PROTECTED_BYTES - total))
        total += len(captured.raw)
        metadata = {"entry": entry, "source_identity": captured.source_identity}
        evidence.append({**metadata, "token": _framed_mac(
            key, _CAPTURE_DOMAIN, {**context, **metadata}, captured.raw).hex()})
        if not exists:
            # Source UUIDs are identifiers, never capture credentials. Only
            # this trusted capture path can authenticate a new reference.
            binding = {"version": 1, "host_id": recorder._store.host_id,
                       "expected_revision": context["revision"],
                       "recorder_nonce": recorder._nonce, "policy": context["policy"],
                       "purpose": _PURPOSE, "source_identity": captured.source_identity,
                       **entry}
            prepared.append(PreparedProtectedInput(
                _json(binding), captured.raw,
                _framed_mac(key, _PREPARATION_DOMAIN, binding, captured.raw), recorder._policy))
    if _context(recorder, declaration, context["revision"]) != context:
        raise BindingError("invalid_preparation")
    return prepared, evidence


def _read(store, name):
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=store._dirfd)
        before = os.fstat(fd)
        try:
            _file_info(before, store.owner_uid)
        except StoreError:
            raise BindingError("invalid_preparation") from None
        if before.st_size > MAX_PENDING_BYTES:
            raise BindingError("invalid_preparation")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_PENDING_BYTES + 1)
        after = os.fstat(fd)
        linked = os.stat(name, dir_fd=store._dirfd, follow_symlinks=False)
        fingerprint = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (len(raw) > MAX_PENDING_BYTES or fingerprint(before) != fingerprint(after)
                or fingerprint(after) != fingerprint(linked)):
            raise BindingError("invalid_preparation")
        return raw
    finally:
        if fd is not None:
            os.close(fd)


def _remove(store, name):
    try:
        _read(store, name)
    except FileNotFoundError:
        return
    os.unlink(name, dir_fd=store._dirfd)


def prepare_recording(recorder, declaration, revision):
    """Replace the one pending preparation; return only its opaque identifier."""
    context = _context(recorder, declaration, revision)
    _, evidence = _captures(recorder, declaration, context)
    identifier = str(uuid.uuid4())
    manifest = {**context, "preparation_id": identifier, "entries": evidence}
    store = recorder._store
    with store._locked(exclusive=True):
        recorder._revision(revision)
        if recorder._policy_context() != context["policy"]:
            raise BindingError("invalid_preparation")
        encoded = _json({"manifest": manifest, "seal": _framed_mac(
            recorder._key(), _MANIFEST_DOMAIN, manifest, b"").hex()})
        if len(encoded) > MAX_PENDING_BYTES:
            raise BindingError("protected_input_limit")
        # Fixed names plus the host mutation lock bound staging to two files.
        # A leftover unpublished next file carries no accepted authority.
        _remove(store, _NEXT)
        fd = os.open(_NEXT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=store._dirfd)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(encoded)
                stream.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        # Validate any existing destination before replacing private staging.
        try:
            _read(store, _PENDING)
        except FileNotFoundError:
            pass
        os.replace(_NEXT, _PENDING, src_dir_fd=store._dirfd, dst_dir_fd=store._dirfd)
        os.fsync(store._dirfd)
    return {"host_id": store.host_id, "revision": revision,
            "preparation_id": identifier, "protected_count": len(evidence)}


def consume_recording(recorder, declaration, revision, identifier):
    """Verify fresh captures, durably burn the receipt, then return private inputs.

    The caller records immediately while retaining the host mutation lock.
    Burning before the decision prevents replay even after uncertain commit
    or cleanup. Failure needs a new preparation, never automatic retry.
    """
    context = _context(recorder, declaration, revision)
    store = recorder._store
    with store._locked():
        raw = _read(store, _PENDING)
        try:
            value = _decode(raw)
        except StoreError:
            raise BindingError("invalid_preparation") from None
        if type(value) is not dict or set(value) != {"manifest", "seal"}:
            raise BindingError("invalid_preparation")
        manifest = value["manifest"]
        seal = _framed_mac(recorder._key(), _MANIFEST_DOMAIN, manifest, b"").hex()
        if (type(value["seal"]) is not str or not hmac.compare_digest(seal, value["seal"])
                or type(manifest) is not dict
                or set(manifest) != set(context) | {"preparation_id", "entries"}
                or any(manifest[name] != item for name, item in context.items())
                or manifest["preparation_id"] != identifier):
            raise BindingError("invalid_preparation")
    prepared, evidence = _captures(recorder, declaration, context)
    if not hmac.compare_digest(_json(evidence), _json(manifest["entries"])):
        raise BindingError("protected_input_changed")
    with store._locked(exclusive=True):
        recorder._revision(revision)
        if recorder._policy_context() != context["policy"] or _read(store, _PENDING) != raw:
            raise BindingError("invalid_preparation")
        os.unlink(_PENDING, dir_fd=store._dirfd)
        os.fsync(store._dirfd)
    return prepared
