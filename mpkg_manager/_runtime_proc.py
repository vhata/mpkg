"""Bounded Linux process/listener snapshots for trusted runtime attribution."""
import os
from pathlib import Path
import re
import stat


MAX_PROCESSES = 32
MAX_FDS = 1024
MAX_TABLE = 1024 * 1024
MAX_ROWS = 8192
_DECIMAL = re.compile(r"[0-9]{1,20}\Z")
_SOCKET = re.compile(r"socket:\[([1-9][0-9]{0,19})\]\Z")


class ProcUnavailable(ValueError):
    def __init__(self, code="runtime_process_unavailable"):
        self.code = code
        super().__init__(code)


def _number(value, maximum=2**64 - 1):
    if not _DECIMAL.fullmatch(value) or int(value) > maximum:
        raise ProcUnavailable("runtime_process_malformed")
    return int(value)


def covering_listeners(raw, raw6, port):
    """Validate complete tables before selecting every IPv4 covering socket."""
    result = set()
    for family, source in ((4, raw), (6, raw6)):
        if type(source) is not bytes or len(source) > MAX_TABLE or not source.endswith(b"\n"):
            raise ProcUnavailable("runtime_listener_table_unavailable")
        try:
            rows = source.decode("ascii").splitlines()
        except UnicodeError:
            raise ProcUnavailable("runtime_listener_table_malformed") from None
        header = ["sl", "local_address", "rem_address" if family == 4 else "remote_address", "st"]
        if not rows or rows[0].split()[:4] != header:
            raise ProcUnavailable("runtime_listener_table_malformed")
        if len(rows) > MAX_ROWS + 1:
            raise ProcUnavailable("runtime_inspection_limit")
        indexes = set()
        for row in rows[1:]:
            fields = row.split()
            width = 8 if family == 4 else 32
            endpoint = re.compile(r"[0-9A-F]{" + str(width) + r"}:[0-9A-F]{4}\Z")
            if (len(fields) < 12 or not re.fullmatch(r"[0-9]+:", fields[0])
                    or fields[0] in indexes or not endpoint.fullmatch(fields[1])
                    or not endpoint.fullmatch(fields[2])
                    or not re.fullmatch(r"[0-9A-F]{2}", fields[3])
                    or not re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{8}", fields[4])
                    or not re.fullmatch(r"[0-9A-F]{2}:[0-9A-F]{8}", fields[5])
                    or not re.fullmatch(r"[0-9A-F]{8}", fields[6])
                    or any(not _DECIMAL.fullmatch(fields[index]) for index in (7, 8, 9))):
                raise ProcUnavailable("runtime_listener_table_malformed")
            indexes.add(fields[0])
            address, encoded_port = fields[1].split(":")
            if int(encoded_port, 16) != port or fields[3] != "0A":
                continue
            if family == 6:
                raise ProcUnavailable("runtime_ipv6_listener_unsupported")
            if address in ("00000000", "0100007F"):
                inode = _number(fields[9])
                if inode == 0 or inode in result:
                    raise ProcUnavailable("runtime_listener_table_malformed")
                result.add(inode)
    if not result:
        raise ProcUnavailable("runtime_listener_unavailable")
    return tuple(sorted(result))


class ProcReader:
    """Fixed /proc reader; a private alternate root is only a fixture seam.

    Held PID-directory descriptors never switch to a reused PID. All reads
    have size/count bounds; a kernel read itself cannot be preempted here.
    """
    def __init__(self, root="/proc"):
        self.root = Path(root)

    @staticmethod
    def _read(parent, name, limit):
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ProcUnavailable()
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, min(65536, limit - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ProcUnavailable("runtime_inspection_limit")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    @staticmethod
    def _namespace(parent, name):
        info = os.stat("ns/" + name, dir_fd=parent)
        return info.st_dev, info.st_ino

    def _identity(self, parent, pid):
        raw = self._read(parent, "stat", 8192)
        prefix, separator, rest = raw.rpartition(b") ")
        values = rest.split()
        if (not separator or not prefix.startswith(str(pid).encode() + b" (")
                or len(values) < 20 or values[0] not in (b"R", b"S", b"D", b"I")):
            raise ProcUnavailable("runtime_process_malformed")
        start = _number(values[19].decode("ascii"))
        if not start:
            raise ProcUnavailable("runtime_process_malformed")
        fields = {}
        for line in self._read(parent, "status", 65536).decode("ascii").splitlines():
            key, separator, value = line.partition(":")
            if not separator or key in fields:
                raise ProcUnavailable("runtime_process_malformed")
            fields[key] = value.strip()
        if any(fields.get(key) != str(pid) for key in ("Pid", "Tgid")):
            raise ProcUnavailable("runtime_process_malformed")
        credentials = []
        for key in ("Uid", "Gid", "Groups"):
            if key not in fields:
                raise ProcUnavailable("runtime_process_malformed")
            values = fields[key].split()
            if (key != "Groups" and len(values) != 4) or len(values) > 256:
                raise ProcUnavailable("runtime_process_malformed")
            credentials.append(tuple(_number(value, 2**32 - 1) for value in values))
        caps = tuple(fields.get(key, "") for key in
                     ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        if any(not re.fullmatch(r"[0-9a-fA-F]{1,16}", value) for value in caps):
            raise ProcUnavailable("runtime_process_malformed")
        maps = []
        for name in ("uid_map", "gid_map"):
            rows = self._read(parent, name, 4096).decode("ascii").splitlines()
            if not 1 <= len(rows) <= 32:
                raise ProcUnavailable("runtime_process_malformed")
            normalized = []
            for row in rows:
                values = row.split()
                if len(values) != 3:
                    raise ProcUnavailable("runtime_process_malformed")
                normalized.append(tuple(_number(value, 2**32 - 1) for value in values))
            maps.append(tuple(normalized))
        namespaces = tuple(self._namespace(parent, name) for name in ("net", "user", "mnt"))
        executable = os.readlink("exe", dir_fd=parent)
        if (not executable.startswith("/") or len(executable) > 4096
                or executable.endswith(" (deleted)") or any(ord(c) < 32 for c in executable)):
            raise ProcUnavailable("runtime_process_malformed")
        exe = os.stat("exe", dir_fd=parent)
        if not stat.S_ISREG(exe.st_mode):
            raise ProcUnavailable("runtime_process_malformed")
        cgroup = self._read(parent, "cgroup", 16384)
        if not cgroup or not cgroup.endswith(b"\n") or len(cgroup.splitlines()) > 64:
            raise ProcUnavailable("runtime_process_malformed")
        for row in cgroup.decode("ascii").splitlines():
            pieces = row.split(":", 2)
            if len(pieces) != 3 or not pieces[0].isdigit() or not pieces[2].startswith("/"):
                raise ProcUnavailable("runtime_process_malformed")
        return (pid, start, tuple(credentials), caps, tuple(maps), namespaces,
                executable, (exe.st_dev, exe.st_ino, exe.st_mode), cgroup)

    @staticmethod
    def _owned(parent, listeners):
        fd = os.open("fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                     dir_fd=parent)
        try:
            result = set()
            with os.scandir(fd) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > MAX_FDS:
                        raise ProcUnavailable("runtime_inspection_limit")
                    if not entry.name.isdecimal():
                        raise ProcUnavailable("runtime_process_malformed")
                    value = os.readlink(entry.name, dir_fd=fd)
                    if len(value) > 4096:
                        raise ProcUnavailable("runtime_inspection_limit")
                    match = _SOCKET.fullmatch(value)
                    if match and int(match[1]) in listeners:
                        result.add(int(match[1]))
            return tuple(sorted(result))
        finally:
            os.close(fd)

    def capture(self, pids, port, guard):
        handles = []
        try:
            root = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            handles.append(root)
            own = os.open(str(os.getpid()), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                          dir_fd=root)
            handles.append(own)
            own_namespaces = tuple(self._namespace(own, name) for name in ("net", "user"))
            # Numeric own PID avoids proc's magic self/net symlinks.
            net = os.open("net", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                          dir_fd=own)
            handles.append(net)

            def listeners():
                guard()
                return covering_listeners(self._read(net, "tcp", MAX_TABLE),
                                          self._read(net, "tcp6", MAX_TABLE), port)

            expected = listeners()
            records = []
            for pid in pids:
                guard()
                process = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                  dir_fd=root)
                handles.append(process)
                identity = self._identity(process, pid)
                if identity[5][:2] != own_namespaces:
                    raise ProcUnavailable("runtime_namespace_unsupported")
                records.append((process, identity, self._owned(process, expected)))
            if set(expected) != {inode for _, _, owned in records for inode in owned}:
                raise ProcUnavailable("runtime_listener_unattributed")
            for process, identity, owned in records:
                guard()
                if self._identity(process, identity[0]) != identity or self._owned(process, expected) != owned:
                    raise ProcUnavailable("runtime_changed")
            if (listeners() != expected
                    or tuple(self._namespace(own, name) for name in ("net", "user")) != own_namespaces):
                raise ProcUnavailable("runtime_changed")
            return tuple((identity, owned) for _, identity, owned in records), expected, own_namespaces
        except (OSError, UnicodeError, ValueError) as error:
            if isinstance(error, ProcUnavailable):
                raise
            raise ProcUnavailable() from None
        finally:
            for fd in reversed(handles):
                os.close(fd)
