"""Bounded host-policy parsing and verified loading for a future recorder."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import posixpath
import re
import stat
import tomllib
import uuid


POLICY_PATH = Path("/etc/mpkg/host-policy.toml")
MAX_POLICY_BYTES = 64 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OPEN_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_OPEN_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class PolicyError(RuntimeError):
    """Fixed diagnostics, without raw policy contents or filesystem paths."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class HostPolicy:
    """Parsed values are immutable data, not authorization to read inputs."""
    host_id: str = field(repr=False)
    allowed_input_roots: tuple = field(repr=False)
    _aliases: tuple = field(repr=False)
    schema_version: int = 1

    @property
    def engine_aliases(self):
        return dict(self._aliases)


def _absolute(value, *, allow_root=False):
    if type(value) is not str or not 0 < len(value) <= 4096:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return ("\0" not in value
            and value.startswith("/") and not value.startswith("//")
            and posixpath.normpath(value) == value and (allow_root or value != "/"))


def parse_host_policy(raw):
    """Parse a closed v1 policy without establishing filesystem trust."""
    if type(raw) is not bytes or len(raw) > MAX_POLICY_BYTES:
        raise PolicyError("invalid_policy")
    try:
        value = tomllib.loads(raw.decode("utf-8"))
        if set(value) != {"schema", "host_id", "engine_aliases", "allowed_input_roots"}:
            raise ValueError
        if type(value["schema"]) is not int or value["schema"] != 1:
            raise PolicyError("policy_schema_unsupported")
        host = value["host_id"]
        if type(host) is not str or str(uuid.UUID(host)) != host:
            raise ValueError
        aliases = value["engine_aliases"]
        if type(aliases) is not dict or len(aliases) > 64:
            raise ValueError
        if any(type(key) is not str or not _NAME.fullmatch(key)
               or type(item) is not str or not _NAME.fullmatch(item)
               for key, item in aliases.items()):
            raise ValueError
        roots = value["allowed_input_roots"]
        if (type(roots) is not list or not 1 <= len(roots) <= 64
                or any(not _absolute(root) for root in roots) or len(set(roots)) != len(roots)):
            raise ValueError
        return HostPolicy(host, tuple(roots), tuple(sorted(aliases.items())))
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise PolicyError("invalid_policy") from None


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_permission(info, owner_uid):
    sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner_uid)
            or (info.st_mode & 0o022 and not sticky_root)):
        raise PolicyError("unsafe_policy_ancestor")


class _DirectoryChain:
    """Hold and recheck directory links; caller decides ownership policy."""

    def __init__(self, path, *, owner_uid=None, start_fd=None, device=None):
        self.fds = []
        self.parts = []
        self.owner_uid, self.device = owner_uid, device
        try:
            first = os.open("/", _OPEN_DIRECTORY) if start_fd is None else os.dup(start_fd)
            self.fds.append(first)
            self._check(os.fstat(first))
            parts = Path(path).parts[1:] if start_fd is None else path
            for part in parts:
                child = os.open(part, _OPEN_DIRECTORY, dir_fd=self.fd)
                self.fds.append(child)
                self.parts.append(part)
                self._check(os.fstat(child))
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.fds[-1]

    def _check(self, info):
        if not stat.S_ISDIR(info.st_mode):
            raise PolicyError("input_path_changed")
        if self.owner_uid is not None:
            _directory_permission(info, self.owner_uid)
        if self.device is not None and info.st_dev != self.device:
            raise PolicyError("input_device_changed")

    def verify(self):
        self._check(os.fstat(self.fds[0]))
        for parent, part, child in zip(self.fds, self.parts, self.fds[1:]):
            linked = os.stat(part, dir_fd=parent, follow_symlinks=False)
            opened = os.fstat(child)
            self._check(linked)
            self._check(opened)
            if (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino):
                raise PolicyError("input_path_changed")

    def close(self):
        while self.fds:
            os.close(self.fds.pop())


def _policy_file(info, owner_uid):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise PolicyError("policy_permissions")
    if info.st_size > MAX_POLICY_BYTES:
        raise PolicyError("invalid_policy")


def _read_bounded(fd, maximum):
    chunks, size = [], 0
    while True:
        chunk = os.read(fd, min(65536, maximum + 1 - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > maximum:
            raise PolicyError("input_too_large")


class LoadedHostPolicy:
    """A verified open policy handle, not an installed privilege boundary.

    Construct handles through load_host_policy. Trusted Python embedding is
    responsible for fixture overrides; declarations cannot provide a handle.
    """

    def __init__(self):
        self._fd = None
        self._chain = None
        self._closed = True

    @property
    def policy(self):
        self._verify()
        return self._policy

    def _verify(self):
        if self._closed:
            raise PolicyError("policy_closed")
        try:
            self._chain.verify()
            directory = os.fstat(self._chain.fd)
            if directory.st_uid != self._owner_uid or stat.S_IMODE(directory.st_mode) != 0o700:
                raise PolicyError("policy_permissions")
            linked = os.stat(self._name, dir_fd=self._chain.fd, follow_symlinks=False)
            opened = os.fstat(self._fd)
            _policy_file(linked, self._owner_uid)
            _policy_file(opened, self._owner_uid)
            if _fingerprint(linked) != self._identity or _fingerprint(opened) != self._identity:
                raise PolicyError("policy_changed")
        except OSError:
            raise PolicyError("policy_unavailable") from None

    def close(self):
        self._closed = True
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._chain is not None:
            self._chain.close()
            self._chain = None

    def __enter__(self):
        self._verify()
        return self

    def __exit__(self, *args):
        self.close()


def load_host_policy(*, path=POLICY_PATH, owner_uid=0):
    """Load a private trusted policy; alternate path/UID are fixture seams."""
    if (type(owner_uid) is not int or owner_uid < 0 or owner_uid != os.geteuid()):
        raise PolicyError("policy_owner_required")
    if not isinstance(path, (str, Path)) or not _absolute(str(path)):
        raise PolicyError("invalid_policy_path")
    path = Path(path)
    result = LoadedHostPolicy()
    try:
        result._owner_uid = owner_uid
        result._name = path.name
        result._chain = _DirectoryChain(path.parent, owner_uid=owner_uid)
        directory = os.fstat(result._chain.fd)
        if directory.st_uid != owner_uid or stat.S_IMODE(directory.st_mode) != 0o700:
            raise PolicyError("policy_permissions")
        before = os.stat(path.name, dir_fd=result._chain.fd, follow_symlinks=False)
        _policy_file(before, owner_uid)
        result._fd = os.open(path.name, _OPEN_FILE, dir_fd=result._chain.fd)
        opened = os.fstat(result._fd)
        _policy_file(opened, owner_uid)
        if _fingerprint(opened) != _fingerprint(before):
            raise PolicyError("policy_changed")
        raw = _read_bounded(result._fd, MAX_POLICY_BYTES)
        result._policy = parse_host_policy(raw)
        result._identity = _fingerprint(opened)
        result._closed = False
        result._verify()
        if len(raw) != opened.st_size:
            raise PolicyError("policy_changed")
        return result
    except OSError:
        result.close()
        raise PolicyError("policy_unavailable") from None
    except BaseException:
        result.close()
        raise
