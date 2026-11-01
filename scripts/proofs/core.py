"""Small mechanisms under test, not a product API or privileged dispatcher."""
import hashlib
import ctypes
import errno
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import uuid
import xml.etree.ElementTree as ET


MARKER = Path('/etc/mpkg-fixture/identity.json')
LIMIT = 16 * 1024 * 1024


class Refused(Exception):
    """Only fixed codes from this module are exported; raw errors stay private."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def validate_guest(expected, marker, metadata, dmi_uuid, vendor,
                   root_device, disk_root_device, disk_serial, disk_bytes):
    try:
        expected = str(uuid.UUID(expected))
        actual = str(uuid.UUID(dmi_uuid.strip()))
    except (ValueError, AttributeError):
        raise Refused('guest_identity_invalid') from None
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1):
        raise Refused('guest_marker_permissions')
    if marker != {'schema': 1, 'guest_id': expected,
                  'fixture_id': 'first-release-2026-10-31',
                  'disposable': True,
                  'disk_serial': 'mpkg' + expected.replace('-', '')[:16],
                  'disk_bytes': 42949672960}:
        raise Refused('guest_marker_mismatch')
    if actual != expected or vendor.strip() != 'QEMU':
        raise Refused('guest_machine_mismatch')
    if (root_device != disk_root_device or disk_serial.strip() != marker['disk_serial']
            or disk_bytes != marker['disk_bytes']):
        raise Refused('guest_root_disk_mismatch')
    return expected


def require_guest(expected):
    if sys.version_info[:2] != (3, 12) or os.geteuid() != 0:
        raise Refused('guest_runtime_required')
    try:
        parent = MARKER.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                or parent.st_mode & 0o022):
            raise Refused('guest_marker_directory')
        fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            raw = os.read(fd, 4097)
            if len(raw) > 4096:
                raise Refused('guest_marker_size')
            marker = json.loads(raw)
        finally:
            os.close(fd)
        root_device = os.stat('/').st_dev
        return validate_guest(
            expected, marker, metadata,
            Path('/sys/class/dmi/id/product_uuid').read_text(),
            Path('/sys/class/dmi/id/sys_vendor').read_text(),
            (os.major(root_device), os.minor(root_device)),
            tuple(int(part) for part in Path('/sys/class/block/vda2/dev').read_text().strip().split(':')),
            Path('/sys/class/block/vda/serial').read_text(),
            int(Path('/sys/class/block/vda/size').read_text()) * 512,
        )
    except (OSError, ValueError, TypeError):
        raise Refused('guest_identity_unavailable') from None


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise Refused('private_directory_required')
    return path


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def identity(metadata):
    return [metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_uid, metadata.st_gid,
            metadata.st_mode, metadata.st_nlink]


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > LIMIT):
            raise Refused('input_shape_unsupported')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT or identity(before) != identity(os.fstat(fd)):
            raise Refused('input_changed_during_read')
        return raw, identity(before)
    finally:
        os.close(fd)


class Journal:
    def __init__(self, directory):
        self.directory = private_directory(directory)
        self.path = self.directory / 'state.sqlite3'
        try:
            write_new(self.path, b'')
        except FileExistsError:
            metadata = self.path.lstat()
            if (not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600):
                raise Refused('journal_permissions')
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=1)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=EXTRA')
        self.db.execute('PRAGMA foreign_keys=ON')
        actual = tuple(self.db.execute('PRAGMA ' + name).fetchone()[0]
                       for name in ('journal_mode', 'synchronous', 'foreign_keys'))
        if actual != ('delete', 3, 1):
            raise Refused('journal_settings_unavailable')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS attempts(
                id TEXT PRIMARY KEY, terminal TEXT);
            CREATE TABLE IF NOT EXISTS events(
                seq INTEGER PRIMARY KEY, attempt TEXT NOT NULL
                    REFERENCES attempts(id), kind TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS protected(
                id TEXT PRIMARY KEY, bytes BLOB NOT NULL,
                identity BLOB NOT NULL, token BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS private_key(key BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS store_guard(recovery_required INTEGER NOT NULL);
        ''')
        if not self.db.execute('SELECT 1 FROM private_key').fetchone():
            self.db.execute('INSERT INTO private_key VALUES(?)',
                            (os.urandom(32),))
        if not self.db.execute('SELECT 1 FROM store_guard').fetchone():
            self.db.execute('INSERT INTO store_guard VALUES(0)')

    def close(self):
        self.db.close()

    def transaction(self, callback):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            result = callback()
            self.db.execute('COMMIT')
            return result
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise

    def begin(self, attempt):
        if str(uuid.UUID(attempt)) != attempt:
            raise Refused('attempt_identity_invalid')

        def record():
            if self.db.execute('SELECT recovery_required FROM store_guard').fetchone()[0]:
                raise Refused('history_recovery_required')
            if self.db.execute(
                    'SELECT 1 FROM attempts WHERE terminal IS NULL').fetchone():
                raise Refused('unresolved_attempt')
            self.db.execute('INSERT INTO attempts VALUES(?, NULL)', (attempt,))
            self.db.execute('INSERT INTO events(attempt,kind) VALUES(?,?)',
                            (attempt, 'started'))
        self.transaction(record)

    def backup(self, destination):
        directory = private_directory(destination)
        path = directory / 'state.sqlite3'
        write_new(path, b'')
        target = sqlite3.connect(path)
        try:
            self.db.backup(target)
        finally:
            target.close()
        with path.open('rb') as stream:
            os.fsync(stream.fileno())

    @classmethod
    def restore(cls, source, destination, *, before_publish=None):
        destination = Path(destination)
        if destination.exists() or destination.is_symlink():
            raise Refused('restore_destination_exists')
        parent = private_directory(destination.parent)
        staging = parent / ('.mpkg-restore-' + uuid.uuid4().hex)
        restored = cls(staging)
        snapshot = sqlite3.connect((Path(source) / 'state.sqlite3').as_uri() + '?mode=ro',
                                   uri=True)
        try:
            snapshot.backup(restored.db)
            restored.transaction(lambda: restored.db.execute(
                'UPDATE store_guard SET recovery_required=1'))
        finally:
            snapshot.close()
            restored.close()
        with (staging / 'state.sqlite3').open('rb') as stream:
            os.fsync(stream.fileno())
        if before_publish:
            before_publish()
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            rename = getattr(libc, 'renameat2', None)
            if rename is None:
                raise Refused('atomic_restore_publication_unavailable')
            rename.argtypes = [ctypes.c_int, ctypes.c_char_p,
                               ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            rename.restype = ctypes.c_int
            if rename(descriptor, os.fsencode(staging.name), descriptor,
                      os.fsencode(destination.name), 1):
                code = ctypes.get_errno()
                if code == errno.EEXIST:
                    raise Refused('restore_destination_exists')
                raise Refused('atomic_restore_publication_failed')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return cls(destination)

    def finish(self, attempt, outcome):
        if outcome not in ('observed-complete', 'failed', 'unverified'):
            raise Refused('outcome_invalid')

        def record():
            changed = self.db.execute(
                'UPDATE attempts SET terminal=? WHERE id=? AND terminal IS NULL',
                (outcome, attempt)).rowcount
            if changed != 1:
                raise Refused('attempt_not_started')
            self.db.execute('INSERT INTO events(attempt,kind) VALUES(?,?)',
                            (attempt, outcome))
        self.transaction(record)

    def export(self):
        return [{'id': row[0], 'state': row[1] or 'unknown',
                 'events': [event[0] for event in self.db.execute(
                     'SELECT kind FROM events WHERE attempt=? ORDER BY seq',
                     (row[0],))]}
                for row in self.db.execute('SELECT id,terminal FROM attempts')]

    def capture(self, path):
        raw, evidence = read_regular(path)
        key = self.db.execute('SELECT key FROM private_key').fetchone()[0]
        token = hmac.digest(key, canonical(evidence) + raw, 'sha256')
        reference = str(uuid.uuid4())
        self.transaction(lambda: self.db.execute(
            'INSERT INTO protected VALUES(?,?,?,?)',
            (reference, raw, canonical(evidence), token)))
        return reference

    def unchanged(self, reference, path):
        row = self.db.execute('SELECT token FROM protected WHERE id=?',
                              (reference,)).fetchone()
        if row is None:
            raise Refused('protected_reference_missing')
        raw, evidence = read_regular(path)
        key = self.db.execute('SELECT key FROM private_key').fetchone()[0]
        return hmac.compare_digest(
            row[0], hmac.digest(key, canonical(evidence) + raw, 'sha256'))

    def replay(self, reference, path):
        row = self.db.execute('SELECT bytes FROM protected WHERE id=?',
                              (reference,)).fetchone()
        if row is None:
            raise Refused('protected_reference_missing')
        write_new(path, row[0])


def change_xml_port(raw, port):
    if not 1024 <= port <= 65535:
        raise Refused('port_outside_fixture_range')
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise Refused('xml_declaration_unsupported')
    if b'<![CDATA[' in raw:
        raise Refused('xml_structure_unsupported')
    try:
        text = raw.decode('utf-8')
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError):
        raise Refused('xml_invalid') from None
    children = list(root)
    names = [child.tag for child in children]
    if (root.tag != 'Config' or len(set(names)) != len(names)
            or any(list(child) for child in children)
            or names.count('Port') != 1):
        raise Refused('xml_structure_unsupported')
    matches = list(re.finditer(r'(<Port(?:\s+[^<>]*?)?>)([^<]*)(</Port>)', text))
    actual_port = root.findtext('Port')
    if (len(matches) != 1 or not actual_port or not actual_port.strip().isdigit()
            or matches[0].group(2).strip() != actual_port.strip()):
        raise Refused('xml_port_unsupported')
    match = matches[0]
    replacement = (text[:match.start(2)] + str(port) + text[match.end(2):]).encode()
    if ET.fromstring(replacement).findtext('Port') != str(port):
        raise Refused('xml_port_unsupported')
    return replacement


def replace_xml(path, expected_raw, expected_identity, port, *, before_publish=None):
    """Caller must establish stopped writers; tests can inject a final drift."""
    raw, observed = read_regular(path)
    if observed != expected_identity or raw != expected_raw:
        raise Refused('config_changed')
    replacement = change_xml_port(raw, port)
    parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.mpkg-proof-' + uuid.uuid4().hex
    fd = None
    try:
        if os.listxattr(path, follow_symlinks=False):
            raise Refused('config_access_metadata_unsupported')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(replacement)
            stream.flush()
        os.fchown(fd, observed[4], observed[5])
        os.fchmod(fd, stat.S_IMODE(observed[6]))
        os.fsync(fd)
        if before_publish:
            before_publish()
        now, evidence = read_regular(path)
        if evidence != observed or now != raw:
            raise Refused('config_changed')
        os.rename(temporary, Path(path).name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)
    return replacement


def mount_identity(descriptor):
    for line in Path('/proc/self/fdinfo/' + str(descriptor)).read_text().splitlines():
        if line.startswith('mnt_id:'):
            return int(line.split(':', 1)[1])
    raise Refused('mount_identity_unavailable')


def ping_ok(raw):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return False
    if not isinstance(value, dict):
        return False
    statuses = [value[key] for key in ('status', 'Status') if key in value]
    return statuses == ['OK']


def inventory_tree(path):
    result = []
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    device = os.fstat(root).st_dev
    mount = mount_identity(root)
    visited = 0

    def walk(directory, prefix, depth):
        nonlocal visited
        if depth > 12:
            raise Refused('data_inventory_bound')
        before = identity(os.fstat(directory))
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                if visited + len(names) >= 1000:
                    raise Refused('data_inventory_bound')
                names.append(entry.name)
        for name in sorted(names):
            visited += 1
            if visited > 1000:
                raise Refused('data_inventory_bound')
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            relative = prefix + [name]
            if info.st_dev != device:
                raise Refused('data_mount_changed')
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                try:
                    if mount_identity(child) != mount:
                        raise Refused('data_mount_changed')
                    walk(child, relative, depth + 1)
                finally:
                    os.close(child)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Refused('data_alias_unsupported')
            else:
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    if mount_identity(child) != mount:
                        raise Refused('data_mount_changed')
                    if identity(os.fstat(child)) != identity(info):
                        raise Refused('data_inventory_changed')
                finally:
                    os.close(child)
            result.append({'parts': relative, 'identity': identity(info),
                           'directory': stat.S_ISDIR(info.st_mode)})
        if identity(os.fstat(directory)) != before:
            raise Refused('data_inventory_changed')
    try:
        walk(root, [], 0)
        return {'root': identity(os.fstat(root)), 'mount_id': mount, 'entries': result}
    finally:
        os.close(root)


def delete_inventory(path, accepted, consumers, *, fail_after=None):
    if consumers:
        raise Refused('data_shared')
    if inventory_tree(path) != accepted:
        raise Refused('data_inventory_changed')
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    removed = 0
    try:
        for entry in accepted['entries']:
            directory = os.dup(root)
            try:
                for part in entry['parts'][:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory)
                    os.close(directory)
                    directory = child
                name = entry['parts'][-1]
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                # A directory's mtime changes as its accepted children disappear.
                evidence = identity(current)
                expected = entry['identity'][:]
                if entry['directory']:
                    expected[2:4] = evidence[2:4]
                if evidence != expected:
                    raise Refused('data_inventory_changed')
                if fail_after is not None and removed == fail_after:
                    raise Refused('injected_partial_delete')
                if entry['directory']:
                    os.rmdir(name, dir_fd=directory)
                else:
                    os.unlink(name, dir_fd=directory)
                os.fsync(directory)
                removed += 1
            finally:
                os.close(directory)
        if os.listdir(root):
            raise Refused('data_new_descendant')
    finally:
        os.close(root)
    return removed
