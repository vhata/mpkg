"""Explicit store maintenance with a verified backup before schema changes.

Paths and ownership overrides are trusted embedding parameters, never host
request fields. This is not restoration, policy backup or effect rollback.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
import uuid

from .store import (HostStore, StoreError, _SCHEMAS, _TRIGGERS,
                    _directory, _file_info, _host_id, _json, _store_path)


MAX_BACKUP_BYTES = 1024 * 1024 * 1024
BACKUP_SECONDS = 60
_ORDER = {"host": "singleton", "snapshots": "id", "decisions": "revision",
          "resources": "stable_id,revision", "protected_inputs": "id",
          "decision_inputs": "revision,name", "schema_migrations": "to_version",
          "sonarr_port_proposals": "id"}
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class MigrationError(RuntimeError):
    """Fixed diagnostics; private backup paths, bytes and digests stay private."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MigrationReceipt:
    host_id: str
    migration_id: str
    backup_id: str
    revision: int
    from_version: int = 1
    to_version: int = 2

    def as_dict(self):
        return {"host_id": self.host_id, "migration_id": self.migration_id,
                "backup_id": self.backup_id, "revision": self.revision,
                "from_version": self.from_version, "to_version": self.to_version, "state": "completed",
                "backup_verified": True, "external_policy_backed_up": False,
                "host_effects_rolled_back": False}


def _fail(code):
    raise MigrationError(code)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _verify_connection(db, host_id):
    # Borrow the already opened connection only for schema/history validation.
    # This object acquires no descriptors and never becomes a public handle.
    check = HostStore()
    check._db, check.host_id = db, host_id
    check._verify_schema()
    return check._schema_version


def _logical_digest(db):
    version = db.execute("PRAGMA user_version").fetchone()[0]
    digest = hashlib.sha256()

    def append(value):
        if value is None:
            kind, raw = b"N", b""
        elif type(value) is int:
            kind, raw = b"I", str(value).encode("ascii")
        elif type(value) is bytes:
            kind, raw = b"B", value
        elif type(value) is str:
            kind, raw = b"T", value.encode("utf-8")
        else:
            _fail("backup_verification_failed")
        digest.update(kind + len(raw).to_bytes(8, "big") + raw)

    append(db.execute("PRAGMA application_id").fetchone()[0])
    append(version)
    for name, sql in sorted(_SCHEMAS[version].items()):
        append(name)
        append(sql)
        if name in _ORDER:
            for row in db.execute(f"SELECT * FROM {name} ORDER BY {_ORDER[name]}"):
                append(len(row))
                for value in row:
                    append(value)
            append(None)
    return digest.hexdigest()


def _source_paths(store):
    fd = _directory(store.directory, store.owner_uid)
    try:
        info = os.fstat(fd)
        if ((info.st_dev, info.st_ino) != store._directory_key
                or info.st_uid != store.owner_uid or stat.S_IMODE(info.st_mode) != 0o700):
            _fail("migration_source_changed")
        for name, key in (("state.sqlite3", store._database_key), ("state.lock", store._lock_key)):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            _file_info(info, store.owner_uid)
            if (info.st_dev, info.st_ino) != key:
                _fail("migration_source_changed")
    finally:
        os.close(fd)


class _Backup:
    def __init__(self, path, owner_uid):
        self.path, self.owner_uid = path, owner_uid
        self.parentfd = self.dirfd = None
        self.files = {}

    def __enter__(self):
        try:
            self.parentfd = _directory(self.path.parent, self.owner_uid)
            os.mkdir(self.path.name, 0o700, dir_fd=self.parentfd)
            self.dirfd = os.open(self.path.name, _DIRECTORY, dir_fd=self.parentfd)
            os.fchmod(self.dirfd, 0o700)
            self.directory_key = (os.fstat(self.dirfd).st_dev, os.fstat(self.dirfd).st_ino)
            for name in ("state.sqlite3", "state.lock"):
                self.write_new(name, b"")
            os.fsync(self.dirfd)
            os.fsync(self.parentfd)
            self.check_paths()
            return self
        except FileExistsError:
            self.__exit__(*sys.exc_info())
            _fail("backup_destination_exists")
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, *args):
        error = None
        for name in ("dirfd", "parentfd"):
            fd = getattr(self, name)
            if fd is not None:
                setattr(self, name, None)
                try:
                    os.close(fd)
                except OSError as failure:
                    error = failure
        if error is not None and (not args or args[0] is None):
            raise error

    def write_new(self, name, raw):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.dirfd)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                if count <= 0:
                    _fail("backup_write_failed")
                offset += count
            os.fsync(fd)
            self.files[name] = _identity(os.fstat(fd))
        finally:
            os.close(fd)

    def check_paths(self):
        fd = _directory(self.path, self.owner_uid)
        try:
            info = os.fstat(fd)
            if ((info.st_dev, info.st_ino) != self.directory_key or info.st_uid != self.owner_uid
                    or stat.S_IMODE(info.st_mode) != 0o700):
                _fail("backup_identity_changed")
            for name, identity in self.files.items():
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                _file_info(info, self.owner_uid)
                if _identity(info) != identity:
                    _fail("backup_identity_changed")
            for name in ("state.sqlite3-journal", "state.sqlite3-wal", "state.sqlite3-shm"):
                try:
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _fail("backup_verification_failed")
        finally:
            os.close(fd)

    def capture(self, store, revision):
        self.check_paths()
        _source_paths(store)
        deadline = time.monotonic() + BACKUP_SECONDS
        version = store._schema_version
        page_size = store._db.execute("PRAGMA page_size").fetchone()[0]
        page_count = store._db.execute("PRAGMA page_count").fetchone()[0]
        if page_size * page_count > MAX_BACKUP_BYTES:
            _fail("backup_size_limit")
        source = sqlite3.connect((store.directory / "state.sqlite3").as_uri() + "?mode=ro",
                                 uri=True, timeout=1, isolation_level=None)
        target = None
        try:
            source.execute("PRAGMA query_only=ON")
            source.execute("PRAGMA trusted_schema=OFF")
            source.execute("PRAGMA foreign_keys=ON")
            source.execute("PRAGMA temp_store=MEMORY")
            source.execute("BEGIN")
            if _verify_connection(source, store.host_id) != version:
                _fail("migration_source_changed")
            original = _logical_digest(store._db)
            if _logical_digest(source) != original:
                _fail("migration_source_changed")
            target = sqlite3.connect((self.path / "state.sqlite3").as_uri() + "?mode=rw",
                                     uri=True, timeout=1, isolation_level=None)
            target.execute("PRAGMA synchronous=EXTRA")
            target.execute("PRAGMA journal_mode=DELETE")

            def progress(status, remaining, total):
                if total * page_size > MAX_BACKUP_BYTES:
                    _fail("backup_size_limit")
                if time.monotonic() >= deadline:
                    _fail("backup_timeout")

            # The write-reserving connection is deliberately not the source:
            # backing up a connection's active write transaction can deadlock.
            source.backup(target, pages=128, progress=progress, sleep=0.01)
            if (_verify_connection(target, store.host_id) != version
                    or _logical_digest(target) != original or _logical_digest(store._db) != original):
                _fail("backup_verification_failed")
        finally:
            if target is not None:
                target.close()
            source.close()
        _source_paths(store)
        fd = os.open("state.sqlite3", _READ, dir_fd=self.dirfd)
        try:
            info = os.fstat(fd)
            _file_info(info, self.owner_uid)
            if (info.st_dev, info.st_ino) != self.files["state.sqlite3"][:2]:
                _fail("backup_identity_changed")
            if not 0 < info.st_size <= MAX_BACKUP_BYTES:
                _fail("backup_size_limit")
            digest, total = hashlib.sha256(), 0
            while chunk := os.read(fd, 1024 * 1024):
                total += len(chunk)
                if total > MAX_BACKUP_BYTES:
                    _fail("backup_size_limit")
                digest.update(chunk)
            if total != info.st_size or _identity(os.fstat(fd)) != _identity(info):
                _fail("backup_identity_changed")
            os.fsync(fd)
            self.files["state.sqlite3"] = _identity(os.fstat(fd))
        finally:
            os.close(fd)
        metadata = {"backup_id": str(uuid.uuid4()), "host_id": store.host_id,
                    "schema_version": version, "revision": revision, "directory": str(self.path),
                    "database_size": total, "database_sha256": digest.hexdigest(),
                    "logical_sha256": original}
        self.write_new("backup.json", _json(metadata) + b"\n")
        os.fsync(self.dirfd)
        os.fsync(self.parentfd)
        self.check_paths()
        if time.monotonic() >= deadline:
            _fail("backup_timeout")
        return metadata


def _upgrade(store, revision, backup):
    db = store._db
    before = backup["schema_version"]
    after = before + 1
    for name, statement in _SCHEMAS[after].items():
        if name not in _SCHEMAS[before]:
            db.execute(statement)
    db.execute("DROP TRIGGER host_update")
    db.execute("UPDATE host SET schema_version=? WHERE singleton=1", (after,))
    db.execute(_TRIGGERS["host_update"])
    db.execute(f"PRAGMA user_version={after}")
    identity = store._save_schema_receipt("migrated", before, after, revision, backup)
    store._verify_schema()
    return identity


def migrate_store(directory, host_id, *, expected_revision, backup_directory, owner_uid=0):
    """Upgrade exactly v1 to v2 after an exclusive, verified private backup.

    All paths are administratively supplied trusted-library arguments. The
    backup preserves database/key/captures, not external policy or host state.
    Existing or partial backup destinations are never overwritten or deleted.
    """
    return _migrate_store(directory, host_id, expected_revision=expected_revision,
                          backup_directory=backup_directory, owner_uid=owner_uid, before=1)


def migrate_store_to_v3(directory, host_id, *, expected_revision, backup_directory, owner_uid=0):
    """Upgrade exactly v2 to v3 with the same verified-backup requirements."""
    return _migrate_store(directory, host_id, expected_revision=expected_revision,
                          backup_directory=backup_directory, owner_uid=owner_uid, before=2)


def _migrate_store(directory, host_id, *, expected_revision, backup_directory, owner_uid, before):
    if type(expected_revision) is not int or not 0 <= expected_revision < 2**63 - 1:
        _fail("invalid_migration_request")
    _host_id(host_id)
    source_path, backup_path = _store_path(directory), _store_path(backup_directory)
    if (len(str(backup_path)) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in str(backup_path))
            or backup_path == source_path or source_path in backup_path.parents):
        _fail("invalid_backup_path")
    store, committing = None, False
    try:
        store = HostStore._open(source_path, host_id, owner_uid, False, allow_legacy=True)
        with store._locked(exclusive=True):
            store._db.execute("BEGIN IMMEDIATE")
            try:
                store._verify_schema()
                if store._schema_version != before:
                    _fail("migration_not_required")
                if store._revision() != expected_revision:
                    raise StoreError("revision_conflict")
                with _Backup(backup_path, owner_uid) as backup:
                    metadata = backup.capture(store, expected_revision)
                    _source_paths(store)
                    identity = _upgrade(store, expected_revision, metadata)
                    backup.check_paths()
                    _source_paths(store)
                    committing = True
                    store._commit()
                    os.fsync(store._dirfd)
                    store._verify_schema()
                    return MigrationReceipt(host_id, identity, metadata["backup_id"], expected_revision,
                                             before, before + 1)
            except BaseException:
                if committing:
                    store._closed = True
                    try:
                        store._db.close()
                        store._db = None
                    except (OSError, sqlite3.Error):
                        pass  # Preserve the original failure; final cleanup retries.
                elif store._db.in_transaction:
                    try:
                        store._db.execute("ROLLBACK")
                    except (OSError, sqlite3.Error):
                        store._closed = True
                        try:
                            store._db.close()
                            store._db = None
                        except (OSError, sqlite3.Error):
                            pass
                raise
    except Exception as error:
        if committing:
            raise MigrationError("migration_outcome_unknown") from None
        if isinstance(error, (MigrationError, StoreError)):
            raise
        raise MigrationError("migration_failed") from None
    finally:
        if store is not None:
            active = sys.exception()
            try:
                store.close()
            except Exception:
                if active is None:
                    raise MigrationError("migration_outcome_unknown" if committing
                                         else "migration_failed") from None
