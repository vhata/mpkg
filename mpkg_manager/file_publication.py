"""Trusted, bounded configuration replacement; never an apply authorization.

Installed adapters own durable authority/input checks and writer exclusion.
This primitive has no public protocol and accepts no serialized write request.
"""
from dataclasses import dataclass, field
import hmac
import os
from pathlib import Path
import stat
import uuid

from .host_policy import LoadedHostPolicy, _OPEN_DIRECTORY, _OPEN_FILE, _fingerprint


MAX_BYTES = 16 * 1024 * 1024
MAX_PATH_PARTS = 128


class PublicationError(RuntimeError):
    """Fixed diagnostics retain publication uncertainty without private data."""

    def __init__(self, code, *, outcome="not_published", cleanup_complete=True):
        self.code = code
        self.outcome = outcome
        self.cleanup_complete = cleanup_complete
        super().__init__(code)

    def as_dict(self):
        return {"code": self.code, "outcome": self.outcome,
                "cleanup_complete": self.cleanup_complete, "retry_authorized": False}


@dataclass(frozen=True, slots=True)
class PublicationInput:
    """Private observed input; this does not authenticate accepted intent."""
    host_id: str = field(repr=False)
    root: str = field(repr=False)
    relative_path: str = field(repr=False)
    identity: tuple[int, ...] = field(repr=False)
    mount_id: int = field(repr=False)
    raw: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class PublicationBinding:
    """Immutable candidate/input pairing supplied only by trusted adapters."""
    publication_id: str
    adapter: str
    input_reference: str = field(repr=False)
    original: PublicationInput = field(repr=False)
    candidate: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class PublicationReadiness:
    """Trusted adapter evidence, not a claim accepted from public JSON."""
    publication_id: str
    authority_current: bool
    input_current: bool
    identified_writers_stopped: bool
    maintenance_interval_active: bool


@dataclass(frozen=True, slots=True)
class PublicationResult:
    publication_id: str
    outcome: str

    def as_dict(self):
        return {"publication_id": self.publication_id, "outcome": self.outcome,
                "application_verified": False, "apply_authorized": False}


def _require(condition, code):
    if not condition:
        raise PublicationError(code)


def _close_checked(fd):
    try:
        os.close(fd)
    except BaseException:
        raise PublicationError("publication_cleanup_failed", cleanup_complete=False) from None


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _arguments(root, relative_path):
    _require(type(root) is str and type(relative_path) is str
             and 0 < len(root) + len(relative_path) <= 4096,
             "invalid_publication_input")
    _require(root.startswith("/") and root != "/" and not root.startswith("//")
             and os.path.normpath(root) == root and "\0" not in root
             and "\0" not in relative_path, "invalid_publication_input")
    parts = relative_path.split("/")
    _require(0 < len(parts) <= MAX_PATH_PARTS
             and all(part not in ("", ".", "..") for part in parts),
             "invalid_publication_input")
    _require(len(Path(root).parts) + len(parts) <= MAX_PATH_PARTS,
             "invalid_publication_input")
    try:
        root.encode("utf-8")
        relative_path.encode("utf-8")
    except UnicodeError:
        raise PublicationError("invalid_publication_input") from None


def _mount_id(fd):
    # Linux's descriptor mount ID distinguishes same-device bind mounts.
    descriptor = os.open("/proc/self/fdinfo/" + str(fd), os.O_RDONLY | os.O_CLOEXEC)
    try:
        raw = os.read(descriptor, 16385)
    finally:
        _close_checked(descriptor)
    _require(len(raw) <= 16384, "mount_identity_unavailable")
    rows = [line[7:].strip() for line in raw.splitlines() if line.startswith(b"mnt_id:")]
    _require(len(rows) == 1 and rows[0].isdigit() and 0 < len(rows[0]) <= 20,
             "mount_identity_unavailable")
    return int(rows[0])


def _directory_identity(fd):
    info = os.fstat(fd)
    _require(stat.S_ISDIR(info.st_mode), "publication_path_changed")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, _mount_id(fd))


class _HeldPath:
    def __init__(self, root, relative):
        self.fds, self.parts, self.identities = [], [], []
        self.root_index = len(Path(root).parts) - 1
        self.leaf = relative.split("/")[-1]
        try:
            self.fds.append(os.open("/", _OPEN_DIRECTORY))
            self.identities.append(_directory_identity(self.fds[0]))
            components = (*Path(root).parts[1:], *relative.split("/")[:-1])
            for part in components:
                child = os.open(part, _OPEN_DIRECTORY, dir_fd=self.fds[-1])
                self.fds.append(child)
                self.parts.append(part)
                self.identities.append(_directory_identity(child))
            self.mount_id = self.identities[self.root_index][-1]
            self.device = self.identities[self.root_index][0]
            _require(all(item[-1] == self.mount_id and item[0] == self.device
                         for item in self.identities[self.root_index:]),
                     "publication_mount_unsupported")
        except BaseException:
            if not self.close():
                raise PublicationError("publication_cleanup_failed", cleanup_complete=False) from None
            raise

    @property
    def parent(self):
        return self.fds[-1]

    def verify(self):
        _require(_directory_identity(self.fds[0]) == self.identities[0],
                 "publication_path_changed")
        for index, part in enumerate(self.parts):
            _require(_directory_identity(self.fds[index + 1]) == self.identities[index + 1],
                     "publication_path_changed")
            fresh = os.open(part, _OPEN_DIRECTORY, dir_fd=self.fds[index])
            try:
                _require(_directory_identity(fresh) == self.identities[index + 1],
                         "publication_path_changed")
            finally:
                _close_checked(fresh)

    def close(self):
        complete = True
        while self.fds:
            try:
                os.close(self.fds.pop())
            except BaseException:
                complete = False
        return complete


def _policy(policy, root, host_id=None):
    _require(type(policy) is LoadedHostPolicy, "publication_policy_unavailable")
    policy._verify()
    value = policy.policy
    _require(root in value.allowed_input_roots and (host_id is None or value.host_id == host_id),
             "publication_root_not_allowed")
    return value.host_id


def _regular(fd, path):
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
             "publication_alias_or_type_unsupported")
    _require(info.st_dev == path.device and _mount_id(fd) == path.mount_id,
             "publication_mount_unsupported")
    _require(0 <= info.st_size <= MAX_BYTES and not info.st_mode & 0o7000,
             "publication_metadata_unsupported")
    _require(not os.listxattr(fd), "publication_access_metadata_unsupported")
    identity = _fingerprint(info)
    _require(all(type(item) is int and 0 <= item < 2**63 for item in identity),
             "publication_metadata_unsupported")
    return identity


def _read(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    chunks, size = [], 0
    while chunk := os.read(fd, min(65536, MAX_BYTES + 1 - size)):
        size += len(chunk)
        _require(size <= MAX_BYTES, "publication_input_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _read_leaf(path):
    fd = os.open(path.leaf, _OPEN_FILE, dir_fd=path.parent)
    try:
        before = _regular(fd, path)
        raw = _read(fd)
        _require(_regular(fd, path) == before and len(raw) == before[6],
                 "publication_input_changed")
        linked = os.stat(path.leaf, dir_fd=path.parent, follow_symlinks=False)
        _require(_fingerprint(linked) == before, "publication_input_changed")
        # Stat alone cannot detect a same-inode bind mount over this name.
        fresh = os.open(path.leaf, _OPEN_FILE, dir_fd=path.parent)
        try:
            _require(_regular(fresh, path) == before, "publication_input_changed")
        finally:
            _close_checked(fresh)
        path.verify()
        return raw, before
    finally:
        _close_checked(fd)


def capture_publication_input(policy, *, root, relative_path):
    """Read one policy-approved regular target for a trusted adapter.

    This observation is not authority, a stored-input authentication, or proof
    of writer exclusion. The adapter must establish those before publishing.
    """
    _arguments(root, relative_path)
    path = None
    try:
        host_id = _policy(policy, root)
        path = _HeldPath(root, relative_path)
        raw, identity = _read_leaf(path)
        _policy(policy, root, host_id)
        result = PublicationInput(host_id, root, relative_path, identity, path.mount_id, raw)
    except PublicationError:
        raise
    except BaseException:
        raise PublicationError("publication_input_unavailable") from None
    finally:
        if path is not None and not path.close():
            raise PublicationError("publication_cleanup_failed", cleanup_complete=False) from None
    return result


def bind_publication(original, candidate, *, adapter, input_reference):
    """Pair private values; the mandatory adapter callback authenticates them.

    Neither this factory nor the returned value grants write authority.
    """
    _require(type(original) is PublicationInput and type(candidate) is bytes
             and len(candidate) <= MAX_BYTES and _uuid(input_reference)
             and type(adapter) is str and 0 < len(adapter) <= 128
             and all(char.isascii() and (char.isalnum() or char in "_.-") for char in adapter),
             "invalid_publication_binding")
    return PublicationBinding(str(uuid.uuid4()), adapter, input_reference, original, candidate)


def _revalidate(binding, callback):
    value = callback(binding)
    _require(type(value) is PublicationReadiness and value.publication_id == binding.publication_id
             and value.authority_current is True and value.input_current is True
             and value.identified_writers_stopped is True and value.maintenance_interval_active is True,
             "publication_authority_or_exclusion_unavailable")


def _fresh(path, original):
    raw, identity = _read_leaf(path)
    _require(identity == original.identity and path.mount_id == original.mount_id
             and hmac.compare_digest(raw, original.raw), "publication_input_changed")


def _verify_temporary(path, name, fd, expected):
    try:
        _require(_regular(fd, path) == expected
                 and _fingerprint(os.stat(name, dir_fd=path.parent,
                                          follow_symlinks=False)) == expected,
                 "publication_temporary_changed")
        fresh = os.open(name, _OPEN_FILE, dir_fd=path.parent)
        try:
            _require(_regular(fresh, path) == expected, "publication_temporary_changed")
        finally:
            _close_checked(fresh)
    except PublicationError as error:
        if not error.cleanup_complete:
            raise
        raise PublicationError("publication_temporary_changed") from None
    except BaseException:
        raise PublicationError("publication_temporary_changed") from None


def publish_file(policy, binding, *, revalidate):
    """Replace one file while a trusted adapter maintains writer exclusion.

    The callback must authenticate this exact candidate/input binding and
    current accepted authority, and prove stopped identified writers plus a
    maintained maintenance interval. It is trusted installed Python code,
    never a caller-supplied Boolean or command. Rename cannot exclude an
    unrelated administrator; this function is not atomic compare-and-replace.
    """
    _require(type(binding) is PublicationBinding and _uuid(binding.publication_id)
             and type(binding.original) is PublicationInput and type(binding.candidate) is bytes
             and len(binding.candidate) <= MAX_BYTES and callable(revalidate),
             "invalid_publication_binding")
    original = binding.original
    _arguments(original.root, original.relative_path)
    _require(type(original.raw) is bytes and len(original.raw) <= MAX_BYTES
             and type(original.identity) is tuple and len(original.identity) == 9,
             "invalid_publication_binding")
    path, temporary_fd, temporary_name, temporary_identity = None, None, None, None
    attempted, completed, cleanup_complete, failure = False, False, True, None
    outcome = "not_published"
    try:
        _policy(policy, original.root, original.host_id)
        _revalidate(binding, revalidate)
        path = _HeldPath(original.root, original.relative_path)
        _fresh(path, original)
        if hmac.compare_digest(original.raw, binding.candidate):
            _revalidate(binding, revalidate)
            _fresh(path, original)
            _policy(policy, original.root, original.host_id)
            outcome = "unchanged"
        else:
            _revalidate(binding, revalidate)
            temporary_name = ".mpkg-publication-" + uuid.uuid4().hex
            temporary_fd = os.open(temporary_name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                                   | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   0o600, dir_fd=path.parent)
            temporary_identity = _fingerprint(os.fstat(temporary_fd))
            _regular(temporary_fd, path)
            position = 0
            while position < len(binding.candidate):
                written = os.write(temporary_fd, binding.candidate[position:position + 65536])
                _require(written > 0, "publication_write_failed")
                position += written
            os.fchown(temporary_fd, original.identity[3], original.identity[4])
            os.fchmod(temporary_fd, stat.S_IMODE(original.identity[2]))
            staged = _regular(temporary_fd, path)
            _require(staged[2:5] == original.identity[2:5]
                     and hmac.compare_digest(_read(temporary_fd), binding.candidate),
                     "publication_metadata_unsupported")
            os.fsync(temporary_fd)
            _policy(policy, original.root, original.host_id)
            _revalidate(binding, revalidate)
            _fresh(path, original)
            _verify_temporary(path, temporary_name, temporary_fd, staged)
            # The maintained exclusion must span this unavoidable syscall gap.
            attempted = True
            os.replace(temporary_name, path.leaf, src_dir_fd=path.parent, dst_dir_fd=path.parent)
            completed = True
            os.fsync(path.parent)
            raw, identity = _read_leaf(path)
            _require(identity[:7] == staged[:7] and hmac.compare_digest(raw, binding.candidate),
                     "publication_result_changed")
            _policy(policy, original.root, original.host_id)
            _revalidate(binding, revalidate)
            outcome = "published"
    except BaseException as error:
        failure = error.code if type(error) is PublicationError else "publication_operation_failed"
        if type(error) is PublicationError:
            cleanup_complete = cleanup_complete and error.cleanup_complete
        outcome = "unknown" if attempted else "not_published"
    finally:
        if temporary_name is not None and path is not None and not completed:
            try:
                linked = os.stat(temporary_name, dir_fd=path.parent, follow_symlinks=False)
                _require(temporary_identity is not None
                         and (linked.st_dev, linked.st_ino) == temporary_identity[:2],
                         "publication_cleanup_failed")
                os.unlink(temporary_name, dir_fd=path.parent)
                os.fsync(path.parent)
            except FileNotFoundError:
                pass
            except BaseException:
                cleanup_complete = False
        if temporary_fd is not None:
            try:
                os.close(temporary_fd)
            except BaseException:
                cleanup_complete = False
        if path is not None:
            cleanup_complete = path.close() and cleanup_complete
    if not cleanup_complete:
        failure = failure or "publication_cleanup_failed"
        if attempted:
            outcome = "unknown"
    if failure is not None:
        raise PublicationError(failure, outcome=outcome,
                               cleanup_complete=cleanup_complete) from None
    return PublicationResult(binding.publication_id, outcome)
