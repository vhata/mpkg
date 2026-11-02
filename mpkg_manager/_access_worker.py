"""Private Linux read/list worker; all target traversal follows credential drop.

Only the fixed supervisor invokes this standard-library-only isolated script.
The numeric request is trusted internal input, never a privileged public API.
"""
import ctypes
import errno
import json
import os
import posixpath
import resource
import stat
import sys


MAX_REQUEST = 16 * 1024
MAX_READ = 1024 * 1024
MAX_ENTRIES = 1024
MAX_GROUPS = 256
MAX_DEPTH = 64
_CODES = {"ok", "denied", "invalid_request", "credentials_unavailable",
          "credentials_changed", "namespace_unsupported", "namespace_changed",
          "target_unavailable", "target_unsupported", "target_changed",
          "read_limit", "entry_limit", "probe_failed"}


class AccessFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def validate_request(value):
    try:
        if (type(value) is not dict or set(value) != {"path", "kind", "operation", "uid", "gid", "groups"}
                or value["kind"] not in ("file", "directory")
                or value["operation"] != {"file": "read", "directory": "list"}[value["kind"]]
                or type(value["path"]) is not str or not value["path"].startswith("/")
                or value["path"].startswith("//") or posixpath.normpath(value["path"]) != value["path"]
                or len(value["path"].encode("utf-8")) > 4096
                or any(ord(char) < 32 or ord(char) == 127 for char in value["path"])
                or len([part for part in value["path"].split("/") if part]) > MAX_DEPTH
                or any(type(value[name]) is not int or not 0 < value[name] < 2**32 - 1 for name in ("uid", "gid"))
                or type(value["groups"]) is not list or not 1 <= len(value["groups"]) <= MAX_GROUPS
                or any(type(item) is not int or not 0 <= item < 2**32 - 1 for item in value["groups"])
                or value["groups"] != sorted(set(value["groups"])) or value["gid"] not in value["groups"]):
            raise ValueError
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
        raise AccessFailure("invalid_request") from None


def _read_proc(name, limit=16 * 1024):
    with open('/proc/self/' + name, 'rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise AccessFailure("credentials_unavailable")
    return data


def _namespaces():
    result = []
    for name in ("user", "mnt"):
        info = os.stat('/proc/self/ns/' + name)
        result.append((info.st_dev, info.st_ino))
    for name in ("uid_map", "gid_map"):
        rows = [line.split() for line in _read_proc(name, 4096).splitlines()]
        if rows != [[b'0', b'0', b'4294967295']]:
            raise AccessFailure("namespace_unsupported")
        result.append(tuple(tuple(row) for row in rows))
    return tuple(result)


def _credentials(value):
    wanted = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
    fields = {}
    for line in _read_proc('status').splitlines():
        name, separator, raw = line.partition(b':')
        key = name.decode('ascii')
        if key in wanted:
            if not separator or key in fields:
                raise AccessFailure("credentials_unavailable")
            fields[key] = raw.split()
    if set(fields) != wanted:
        raise AccessFailure("credentials_unavailable")
    try:
        for name, expected in (("Uid", value["uid"]), ("Gid", value["gid"])):
            if [int(item) for item in fields[name]] != [expected] * 4:
                raise ValueError
        if sorted(int(item) for item in fields['Groups']) != value['groups']:
            raise ValueError
        for name in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
            if len(fields[name]) != 1 or int(fields[name][0], 16) != 0:
                raise ValueError
        if len(fields['CapBnd']) != 1 or int(fields['CapBnd'][0], 16) < 0:
            raise ValueError
        if fields['NoNewPrivs'] != [b'1']:
            raise ValueError
        if (os.getresuid() != (value['uid'],) * 3 or os.getresgid() != (value['gid'],) * 3
                or sorted(os.getgroups()) != value['groups']):
            raise ValueError
    except (ValueError, OverflowError):
        raise AccessFailure("credentials_unavailable") from None
    return tuple((key, tuple(fields[key])) for key in sorted(fields))


def _drop(value):
    # This runs only in the isolated child. No target descriptor is open yet.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise AccessFailure("credentials_unavailable")
    if os.geteuid() == 0:
        os.setgroups(value['groups'])
        os.setresgid(value['gid'], value['gid'], value['gid'])
        os.setresuid(value['uid'], value['uid'], value['uid'])
    # The unprivileged path must already have the exact complete credentials.
    return _credentials(value)


def _identity(info, *, target=False):
    base = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    return base + (info.st_size, info.st_mtime_ns, info.st_ctime_ns) if target else base


def _walk(path):
    descriptors = []
    try:
        descriptors.append(os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC))
        parts = [part for part in path.split('/') if part]
        for index, part in enumerate(parts):
            flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
            if index < len(parts) - 1:
                flags |= os.O_DIRECTORY
            descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
        return descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def _path_snapshot(descriptors):
    return tuple(_identity(os.fstat(fd), target=index == len(descriptors) - 1)
                 for index, fd in enumerate(descriptors))


def _access(value):
    descriptors = []
    read_fd = None
    initial = None
    try:
        descriptors = _walk(value['path'])
        initial = _path_snapshot(descriptors)
        info = os.fstat(descriptors[-1])
        predicate = stat.S_ISREG if value['kind'] == 'file' else stat.S_ISDIR
        if not predicate(info.st_mode):
            raise AccessFailure('target_unsupported')
        if value['kind'] == 'file' and info.st_size > MAX_READ:
            raise AccessFailure('read_limit')
        # Reopen the held regular object, never a raced path that could now be
        # a device/FIFO. The earlier dropped-credential walk checked ancestors.
        read_fd = os.open('/proc/self/fd/' + str(descriptors[-1]),
                          os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        if _identity(os.fstat(read_fd), target=True) != initial[-1]:
            raise AccessFailure('target_changed')
        if value['operation'] == 'read':
            total = 0
            while True:
                raw = os.read(read_fd, min(65536, MAX_READ - total + 1))
                if not raw:
                    break
                total += len(raw)
                if total > MAX_READ:
                    raise AccessFailure('read_limit')
        else:
            with os.scandir(read_fd) as entries:
                for count, _ in enumerate(entries, 1):
                    if count > MAX_ENTRIES:
                        raise AccessFailure('entry_limit')
    finally:
        again = []
        try:
            # A denied open or a bounded read failure must not hide replacement
            # of a path that was already resolved to a particular object.
            if initial is not None:
                try:
                    if (_path_snapshot(descriptors) != initial
                            or (read_fd is not None and _identity(os.fstat(read_fd), target=True) != initial[-1])):
                        raise AccessFailure('target_changed')
                    again = _walk(value['path'])
                    if _path_snapshot(again) != initial:
                        raise AccessFailure('target_changed')
                except OSError:
                    raise AccessFailure('target_changed') from None
        finally:
            for descriptor in descriptors + again + ([] if read_fd is None else [read_fd]):
                os.close(descriptor)


def probe(value):
    """Attempt bounded actual access, retaining no contents or names."""
    try:
        validate_request(value)
        namespaces = _namespaces()
        credentials = _drop(value)
        # Credential failures, including setgroups/setresuid, are not denials
        # of the requested target operation.
    except AccessFailure as error:
        return {'code': error.code}
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        return {'code': 'credentials_unavailable'}
    outcome = 'ok'
    try:
        _access(value)
    except AccessFailure as error:
        outcome = error.code
    except OSError as error:
        outcome = ('denied' if error.errno in (errno.EACCES, errno.EPERM)
                   else 'target_unsupported' if error.errno in (errno.ELOOP, errno.ENOTDIR)
                   else 'target_unavailable')
    except (ValueError, TypeError, AttributeError, OverflowError):
        outcome = 'probe_failed'
    # Failures and empty files/directories still cross the final live checks.
    try:
        if _namespaces() != namespaces:
            return {'code': 'namespace_changed'}
        if _credentials(value) != credentials:
            return {'code': 'credentials_changed'}
    except (AccessFailure, OSError, ValueError, TypeError, AttributeError, OverflowError):
        return {'code': 'credentials_changed'}
    return {'code': outcome}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise ValueError
        value = json.loads(raw)
        result = probe(value)
    except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
        result = {'code': 'invalid_request'}
    sys.stdout.write(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
