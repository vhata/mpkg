"""Private, durable recording primitives; not an installed privileged helper.

The owner defaults to root. A trusted embedding may explicitly use another
owner for an isolated fixture; declarations cannot select that owner or path.
Nothing in this module installs, starts, stops, or otherwise applies resources.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from .declarations import Declaration, DeclarationError, canonical_json, load_declaration, physical_key


SCHEMA_VERSION = 1
APPLICATION_ID = 0x4D504B47
MAX_INPUT_BYTES = 16 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SIDEFILES = ("state.sqlite3-journal", "state.sqlite3-wal", "state.sqlite3-shm")
_TABLES = {
    "host": """CREATE TABLE host(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        host_id TEXT NOT NULL, schema_version INTEGER NOT NULL,
        engine_aliases BLOB NOT NULL, private_key BLOB NOT NULL) STRICT""",
    "snapshots": """CREATE TABLE snapshots(
        id TEXT PRIMARY KEY, source BLOB NOT NULL, canonical BLOB NOT NULL,
        digest TEXT NOT NULL, schema_version INTEGER NOT NULL,
        normalization_version INTEGER NOT NULL) STRICT""",
    "decisions": """CREATE TABLE decisions(
        revision INTEGER PRIMARY KEY, parent_revision INTEGER REFERENCES decisions(revision),
        kind TEXT NOT NULL CHECK(kind IN ('intent','adopt','relinquish')),
        snapshot_id TEXT NOT NULL REFERENCES snapshots(id), created_at TEXT NOT NULL) STRICT""",
    "resources": """CREATE TABLE resources(
        stable_id TEXT NOT NULL, revision INTEGER NOT NULL REFERENCES decisions(revision),
        logical_id TEXT NOT NULL, physical_key BLOB NOT NULL, definition BLOB NOT NULL,
        requirements BLOB NOT NULL,
        active INTEGER NOT NULL CHECK(active IN (0,1)),
        PRIMARY KEY(stable_id, revision)) STRICT""",
    "protected_inputs": """CREATE TABLE protected_inputs(
        id TEXT PRIMARY KEY, raw BLOB NOT NULL, source_identity BLOB NOT NULL,
        purpose TEXT NOT NULL, token BLOB NOT NULL) STRICT""",
    "decision_inputs": """CREATE TABLE decision_inputs(
        revision INTEGER NOT NULL REFERENCES decisions(revision), name TEXT NOT NULL,
        protected_id TEXT NOT NULL REFERENCES protected_inputs(id),
        PRIMARY KEY(revision, name)) STRICT""",
}
_TRIGGERS = {
    f"{table}_{operation.lower()}": (
        f"CREATE TRIGGER {table}_{operation.lower()} BEFORE {operation} ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable_record'); END")
    for table in _TABLES for operation in ("UPDATE", "DELETE")
}


class StoreError(RuntimeError):
    """A fixed public error code without paths, values, or SQLite diagnostics."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProtectedInput:
    """Already captured bytes and identity from a trusted, bounded reader.

    The recorder must enforce allowed input roots and read stability. This
    store deliberately does not read arbitrary caller-specified live files.
    """
    name: str
    raw: bytes = field(repr=False)
    source_identity: dict = field(repr=False)
    purpose: str = field(repr=False)


def _fail(code):
    raise StoreError(code)


def _json(value):
    try:
        return canonical_json(value)
    except (DeclarationError, RecursionError):
        raise StoreError("invalid_record") from None


def _decode(raw):
    try:
        value = json.loads(raw)
        if _json(value) != raw:
            _fail("invalid_store_record")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise StoreError("invalid_store_record") from None


def _host_id(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            _fail("invalid_host_id")
    except (ValueError, AttributeError):
        raise StoreError("invalid_host_id") from None
    return value


def _aliases(value):
    if type(value) is not dict:
        _fail("invalid_engine_aliases")
    for alias, engine in value.items():
        if (type(alias) is not str or not _NAME.fullmatch(alias)
                or type(engine) is not str or not _NAME.fullmatch(engine)):
            _fail("invalid_engine_aliases")
    return _decode(_json(value))


def _declaration(value):
    if type(value) is not Declaration:
        _fail("invalid_declaration")
    try:
        checked = load_declaration(value.source_bytes)
    except (DeclarationError, TypeError, ValueError, RecursionError):
        raise StoreError("invalid_declaration") from None
    if value != checked:
        _fail("invalid_declaration")
    return checked


def _source_identity(value, raw):
    keys = {"path", "device", "inode", "size", "mtime_ns", "uid", "gid", "mode", "links"}
    if type(value) is not dict or set(value) != keys:
        _fail("invalid_protected_input")
    path = value["path"]
    if (type(path) is not str or len(path) > 4096 or not path.startswith("/") or path.startswith("//")
            or os.path.normpath(path) != path or "\0" in path):
        _fail("invalid_protected_input")
    if any(type(value[key]) is not int or value[key] < 0 for key in keys - {"path"}):
        _fail("invalid_protected_input")
    if value["size"] != len(raw) or value["links"] != 1 or not stat.S_ISREG(value["mode"]):
        _fail("invalid_protected_input")
    return _json(value)


def _captures(values):
    result = []
    names = set()
    if type(values) not in (tuple, list):
        _fail("invalid_protected_input")
    for item in values:
        if (type(item) is not ProtectedInput or type(item.name) is not str
                or not _NAME.fullmatch(item.name) or item.name in names
                or type(item.raw) is not bytes or len(item.raw) > MAX_INPUT_BYTES
                or type(item.purpose) is not str or not item.purpose):
            _fail("invalid_protected_input")
        try:
            if len(item.purpose.encode("utf-8")) > 1024:
                _fail("invalid_protected_input")
        except UnicodeError:
            raise StoreError("invalid_protected_input") from None
        names.add(item.name)
        result.append((item.name, item.raw, _source_identity(item.source_identity, item.raw), item.purpose))
    return result


def _directory(path, owner_uid):
    """Open every directory without following symlinks or unsafe ancestors."""
    path = Path(path)
    if (not path.is_absolute() or "\0" in str(path) or str(path) != os.path.normpath(path)
            or type(owner_uid) is not int or owner_uid < 0):
        _fail("invalid_store_path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in (0, owner_uid)
                    or (info.st_mode & 0o022 and not sticky_root)):
                _fail("unsafe_store_ancestor")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _store_path(value):
    if not isinstance(value, (str, Path)):
        _fail("invalid_store_path")
    path = Path(value)
    if (not path.is_absolute() or not path.name or "\0" in str(path)
            or str(path) != os.path.normpath(path)):
        _fail("invalid_store_path")
    return path


def _file_info(info, owner_uid):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        _fail("store_permissions")


class HostStore:
    """Explicitly created private host records with no external effects.

    Connections are private implementation details. Public read methods return
    sanitized projections; callers never receive a raw SQLite connection.
    """

    def __init__(self):
        self._db = None
        self._dirfd = self._lockfd = None
        self._closed = False

    @classmethod
    def create(cls, directory, host_id, *, engine_aliases=None, owner_uid=0):
        """Create a new private directory; never replace or repair an old one."""
        _host_id(host_id)
        aliases = _aliases({} if engine_aliases is None else engine_aliases)
        if owner_uid != os.geteuid():
            _fail("store_owner_required")
        path = _store_path(directory)
        parentfd = None
        store = cls()
        try:
            parentfd = _directory(path.parent, owner_uid)
            os.mkdir(path.name, mode=0o700, dir_fd=parentfd)
            os.fsync(parentfd)
            for name in ("state.lock", "state.sqlite3"):
                dirfd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
                try:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=dirfd)
                    try:
                        os.fchmod(fd, 0o600)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.fsync(dirfd)
                finally:
                    os.close(dirfd)
            store._attach(path, host_id, owner_uid, readonly=False, initializing=True)
            with store._locked(exclusive=True):
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    for statement in (*_TABLES.values(), *_TRIGGERS.values()):
                        db.execute(statement)
                    db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    db.execute("INSERT INTO host VALUES(1,?,?,?,?)",
                               (host_id, SCHEMA_VERSION, _json(aliases), os.urandom(32)))
                    store._commit()
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
                os.fsync(store._dirfd)
                store._verify_schema()
                store._engine_aliases = aliases
            return store
        except FileExistsError:
            store.close()
            raise StoreError("store_exists") from None
        except StoreError:
            store.close()
            raise
        except (OSError, sqlite3.Error):
            store.close()
            raise StoreError("store_creation_failed") from None
        finally:
            if parentfd is not None:
                os.close(parentfd)

    @classmethod
    def open_existing(cls, directory, host_id, *, owner_uid=0):
        return cls._open(directory, host_id, owner_uid, readonly=False)

    @classmethod
    def open_readonly(cls, directory, host_id, *, owner_uid=0):
        return cls._open(directory, host_id, owner_uid, readonly=True)

    @classmethod
    def _open(cls, directory, host_id, owner_uid, readonly):
        _host_id(host_id)
        store = cls()
        try:
            store._attach(_store_path(directory), host_id, owner_uid, readonly)
            return store
        except StoreError:
            store.close()
            raise
        except FileNotFoundError:
            store.close()
            raise StoreError("store_missing") from None
        except (OSError, sqlite3.Error):
            store.close()
            raise StoreError("store_unavailable") from None

    def _attach(self, path, host_id, owner_uid, readonly, initializing=False):
        if owner_uid != os.geteuid():
            _fail("store_owner_required")
        if sqlite3.sqlite_version_info < (3, 37, 0):
            _fail("sqlite_version_unsupported")
        self.directory, self.host_id = path, host_id
        self.owner_uid, self.readonly = owner_uid, readonly
        self._dirfd = _directory(path, owner_uid)
        info = os.fstat(self._dirfd)
        if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
            _fail("store_permissions")
        self._directory_key = (info.st_dev, info.st_ino)
        self._lockfd = os.open("state.lock", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._dirfd)
        _file_info(os.fstat(self._lockfd), owner_uid)
        lock_info = os.fstat(self._lockfd)
        self._lock_key = (lock_info.st_dev, lock_info.st_ino)
        with self._locked(exclusive=not readonly):
            info = os.stat("state.sqlite3", dir_fd=self._dirfd, follow_symlinks=False)
            _file_info(info, owner_uid)
            self._database_key = (info.st_dev, info.st_ino)
            mode = "ro" if readonly else "rw"
            self._db = sqlite3.connect((path / "state.sqlite3").as_uri() + f"?mode={mode}",
                                       uri=True, timeout=1, isolation_level=None)
            self._db.execute("PRAGMA synchronous=EXTRA")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA trusted_schema=OFF")
            self._db.execute("PRAGMA temp_store=MEMORY")
            if initializing:
                self._db.execute("PRAGMA journal_mode=DELETE")
            if readonly:
                self._db.execute("PRAGMA query_only=ON")
            actual = tuple(self._db.execute("PRAGMA " + name).fetchone()[0]
                           for name in ("journal_mode", "synchronous", "foreign_keys", "trusted_schema"))
            if actual != ("delete", 3, 1, 0):
                _fail("sqlite_settings_unsupported")
            if not initializing:
                self._verify_schema()

    def _verify_schema(self):
        db = self._db
        if (db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                or db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION):
            _fail("store_schema_unsupported")
        actual = {name: sql for name, sql in db.execute(
            "SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL")}
        if actual != _TABLES | _TRIGGERS:
            _fail("store_schema_unsupported")
        if db.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
            _fail("store_corrupt")
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            _fail("store_corrupt")
        rows = db.execute("SELECT host_id,schema_version,engine_aliases,length(private_key) FROM host").fetchall()
        if len(rows) != 1 or rows[0][0] != self.host_id:
            _fail("store_host_mismatch")
        if rows[0][1] != SCHEMA_VERSION or rows[0][3] != 32:
            _fail("store_corrupt")
        self._engine_aliases = _aliases(_decode(rows[0][2]))

    @property
    def engine_aliases(self):
        """Return a copy of accepted bindings, never mutable authority state."""
        return dict(self._engine_aliases)

    @contextmanager
    def _locked(self, *, exclusive=False):
        if self._closed:
            _fail("store_closed")
        if exclusive and self.readonly:
            _fail("store_readonly")
        try:
            fcntl.flock(self._lockfd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StoreError("store_busy") from None
        try:
            checkfd = _directory(self.directory, self.owner_uid)
            try:
                info = os.fstat(checkfd)
                if ((info.st_dev, info.st_ino) != self._directory_key
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    _fail("store_identity_changed")
            finally:
                os.close(checkfd)
            info = os.stat("state.lock", dir_fd=self._dirfd, follow_symlinks=False)
            _file_info(info, self.owner_uid)
            if (info.st_dev, info.st_ino) != self._lock_key:
                _fail("store_identity_changed")
            for name in _SIDEFILES:
                try:
                    os.stat(name, dir_fd=self._dirfd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _fail("store_recovery_required")
            if hasattr(self, "_database_key"):
                info = os.stat("state.sqlite3", dir_fd=self._dirfd, follow_symlinks=False)
                _file_info(info, self.owner_uid)
                if (info.st_dev, info.st_ino) != self._database_key:
                    _fail("store_identity_changed")
            yield
        finally:
            fcntl.flock(self._lockfd, fcntl.LOCK_UN)

    def _commit(self):
        self._db.execute("COMMIT")

    def _revision(self):
        return self._db.execute("SELECT coalesce(max(revision),0) FROM decisions").fetchone()[0]

    @contextmanager
    def _write(self, expected_revision):
        if type(expected_revision) is not int or not 0 <= expected_revision < 2**63 - 1:
            _fail("invalid_revision")
        uncertain = False
        try:
            with self._locked(exclusive=True):
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    if self._revision() != expected_revision:
                        _fail("revision_conflict")
                    yield
                except BaseException:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    raise
                try:
                    self._commit()
                except (OSError, sqlite3.Error):
                    uncertain = True
                    raise StoreError("commit_outcome_unknown") from None
        except StoreError:
            raise
        except (OSError, sqlite3.Error):
            raise StoreError("store_write_failed") from None
        except (TypeError, ValueError, KeyError, OverflowError, RecursionError):
            raise StoreError("invalid_store_record") from None
        finally:
            if uncertain:
                # COMMIT may have persisted before an error reached the caller.
                # Closing never returns an accepted revision; reopen and inspect.
                self.close()

    @contextmanager
    def _read(self):
        try:
            with self._locked():
                self._db.execute("BEGIN")
                try:
                    yield
                finally:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
        except StoreError:
            raise
        except (OSError, sqlite3.Error):
            raise StoreError("store_read_failed") from None
        except (TypeError, ValueError, KeyError, OverflowError, RecursionError):
            raise StoreError("invalid_store_record") from None

    def _snapshot_id(self, declaration):
        envelope = _json({"source": hashlib.sha256(declaration.source_bytes).hexdigest(),
                          "canonical": declaration.sha256,
                          "schema": declaration.schema_version,
                          "normalization": declaration.normalization_version})
        return hashlib.sha256(envelope).hexdigest()

    def _save_snapshot(self, declaration):
        identity = self._snapshot_id(declaration)
        self._db.execute("INSERT OR IGNORE INTO snapshots VALUES(?,?,?,?,?,?)",
                         (identity, declaration.source_bytes, declaration.canonical_bytes,
                          declaration.sha256, declaration.schema_version,
                          declaration.normalization_version))
        if self._load_snapshot(identity) != declaration:
            _fail("snapshot_identity_conflict")
        return identity

    def _load_snapshot(self, identity):
        row = self._db.execute("SELECT source,canonical,digest,schema_version,normalization_version "
                               "FROM snapshots WHERE id=?", (identity,)).fetchone()
        if row is None:
            _fail("snapshot_missing")
        declaration = _declaration(Declaration(*row))
        if self._snapshot_id(declaration) != identity:
            _fail("invalid_store_record")
        return declaration

    def _decision(self, kind, declaration, revision, captures):
        snapshot_id = self._save_snapshot(declaration)
        self._db.execute("INSERT INTO decisions VALUES(?,?,?,?,?)",
                         (revision, revision - 1 if revision > 1 else None, kind,
                          snapshot_id, datetime.now(timezone.utc).isoformat(timespec="microseconds")))
        key = self._db.execute("SELECT private_key FROM host").fetchone()[0]
        for name, raw, identity, purpose in captures:
            reference = str(uuid.uuid4())
            token = hmac.digest(key, identity + b"\0" + raw, "sha256")
            self._db.execute("INSERT INTO protected_inputs VALUES(?,?,?,?,?)",
                             (reference, raw, identity, purpose, token))
            self._db.execute("INSERT INTO decision_inputs VALUES(?,?,?)", (revision, name, reference))
        return {"revision": revision, "kind": kind, "snapshot_id": snapshot_id}

    def record_intent(self, declaration, expected_revision, *, protected_inputs=()):
        """Record validated intent without accepting authority or applying it."""
        declaration, captures = _declaration(declaration), _captures(protected_inputs)
        self._check_bound_identities(declaration)
        with self._write(expected_revision):
            result = self._decision("intent", declaration, expected_revision + 1, captures)
        return result

    def _current_resources(self):
        rows = self._db.execute("""SELECT r.stable_id,r.logical_id,r.physical_key,r.definition,r.requirements,r.active
            FROM resources r JOIN (SELECT stable_id,max(revision) revision FROM resources GROUP BY stable_id) x
            ON r.stable_id=x.stable_id AND r.revision=x.revision ORDER BY r.stable_id""").fetchall()
        return [{"stable_id": row[0], "logical_id": row[1], "physical_key": _decode(row[2]),
                 "definition": _decode(row[3]), "requirements": _decode(row[4]),
                 "active": bool(row[5])} for row in rows]

    def _physical(self, resource):
        try:
            return list(physical_key(resource, self.host_id, self.engine_aliases))
        except DeclarationError:
            raise StoreError("resource_identity_unbound") from None

    def _check_bound_identities(self, declaration):
        keys = set()
        for resource in declaration.model["resources"]:
            try:
                key = _json(self._physical(resource))
            except StoreError:
                continue  # Unbound intent is not adoption or execution authority.
            if key in keys:
                _fail("resource_identity_conflict")
            keys.add(key)

    def adopt(self, declaration, expected_revision, resource_ids, *, protected_inputs=()):
        """Explicitly accept selected identities/authority; observations stay unknown."""
        declaration, captures = _declaration(declaration), _captures(protected_inputs)
        self._check_bound_identities(declaration)
        if (type(resource_ids) not in (list, tuple) or not resource_ids
                or any(type(item) is not str for item in resource_ids)
                or len(set(resource_ids)) != len(resource_ids)):
            _fail("invalid_resource_selection")
        model = declaration.model
        resources = {item["id"]: item for item in model["resources"]}
        if not set(resource_ids) <= set(resources):
            _fail("resource_missing")
        selected = [(resources[item], self._physical(resources[item])) for item in resource_ids]
        with self._write(expected_revision):
            existing = self._current_resources()
            result = self._decision("adopt", declaration, expected_revision + 1, captures)
            for resource, key in selected:
                matching = next((item for item in existing if item["physical_key"] == key), None)
                logical = next((item for item in existing if item["logical_id"] == resource["id"] and item["active"]), None)
                if logical and logical["physical_key"] != key:
                    _fail("resource_identity_conflict")
                if matching and matching["definition"]["kind"] != resource["kind"]:
                    _fail("resource_identity_conflict")
                if (matching and matching["active"]
                        and set(matching["definition"]["manage"]) != set(resource["manage"])):
                    _fail("authority_change_requires_decision")
                requirements = matching["requirements"][:] if matching else []
                known = {(item["consumer"], item["property"]): item for item in requirements}
                for component in model["components"]:
                    for requirement in component["requirements"]:
                        if requirement["resource"] != resource["id"]:
                            continue
                        requirement = {"consumer": component["id"], "property": requirement["property"],
                                       "value": requirement["value"]}
                        at = (requirement["consumer"], requirement["property"])
                        if at in known and _json(known[at]["value"]) != _json(requirement["value"]):
                            _fail("consumer_requirement_conflict")
                        if at not in known:
                            known[at] = requirement
                            requirements.append(requirement)
                values = {}
                for requirement in requirements:
                    prop, value = requirement["property"], _json(requirement["value"])
                    if ((prop in values and values[prop] != value)
                            or (prop in resource["desired"] and _json(resource["desired"][prop]) != value)):
                        _fail("consumer_requirement_conflict")
                    values[prop] = value
                if matching:
                    resource = resource | {"consumers": list(dict.fromkeys(
                        matching["definition"]["consumers"] + resource["consumers"]))}
                stable_id = matching["stable_id"] if matching else str(uuid.uuid4())
                self._db.execute("INSERT INTO resources VALUES(?,?,?,?,?,?,1)",
                                 (stable_id, result["revision"], resource["id"], _json(key),
                                  _json(resource), _json(requirements)))
        return result

    def relinquish(self, resource_ids, expected_revision):
        """Record external responsibility; do not retire or change live resources."""
        if (type(resource_ids) not in (list, tuple) or not resource_ids
                or any(type(item) is not str for item in resource_ids)
                or len(set(resource_ids)) != len(resource_ids)):
            _fail("invalid_resource_selection")
        with self._write(expected_revision):
            current = {item["stable_id"]: item for item in self._current_resources()}
            if not set(resource_ids) <= set(current) or any(not current[item]["active"] for item in resource_ids):
                _fail("resource_missing")
            row = self._db.execute("SELECT snapshot_id FROM decisions ORDER BY revision DESC LIMIT 1").fetchone()
            if row is None:
                _fail("snapshot_missing")
            result = self._decision("relinquish", self._load_snapshot(row[0]), expected_revision + 1, ())
            for identity in resource_ids:
                item = current[identity]
                self._db.execute("INSERT INTO resources VALUES(?,?,?,?,?,?,0)",
                                 (identity, result["revision"], item["logical_id"],
                                  _json(item["physical_key"]), _json(item["definition"]),
                                  _json(item["requirements"])))
        return result

    def current(self):
        """Project retained management facts, not observations of current effects."""
        with self._read():
            revision = self._revision()
            row = self._db.execute("SELECT snapshot_id FROM decisions ORDER BY revision DESC LIMIT 1").fetchone()
            snapshot_id = row[0] if row else None
            snapshot = None
            declared = []
            unresolved_engine = False
            if snapshot_id:
                declaration = self._load_snapshot(snapshot_id)
                snapshot = {"id": snapshot_id,
                            "source_sha256": hashlib.sha256(declaration.source_bytes).hexdigest(),
                            "canonical_sha256": declaration.sha256,
                            "schema_version": declaration.schema_version,
                            "normalization_version": declaration.normalization_version}
                for resource in declaration.model["resources"]:
                    try:
                        declared.append(self._physical(resource))
                    except StoreError:
                        unresolved_engine = True
            resources = []
            for item in self._current_resources():
                definition = item["definition"]
                state = "present" if item["physical_key"] in declared else "absent"
                if state == "absent" and "engine" in definition["identity"] and unresolved_engine:
                    state = "unknown"
                resources.append({"stable_id": item["stable_id"], "logical_id": item["logical_id"],
                                  "physical_key": item["physical_key"], "definition": definition,
                                  "requirements": item["requirements"],
                                  "management": "accepted" if item["active"] else "relinquished",
                                  "declaration_state": state,
                                  "pending_disposition": item["active"] and state == "absent",
                                  "observation": {"state": "unknown", "reason": "not_observed"}})
            return {"host_id": self.host_id, "revision": revision,
                    "snapshot_id": snapshot_id, "snapshot": snapshot, "resources": resources}

    def history(self):
        """Sanitized decision history excludes protected references and content."""
        with self._read():
            return [{"revision": row[0], "parent_revision": row[1], "kind": row[2],
                     "snapshot_id": row[3], "created_at": row[4]}
                    for row in self._db.execute("SELECT * FROM decisions ORDER BY revision")]

    def snapshot(self, identity):
        """Trusted nonsecret-source retrieval, not an ordinary public projection.

        Exact source can contain explicitly declared opaque references. Do not
        expose this method through ordinary status/history output.
        """
        with self._read():
            return self._load_snapshot(identity)

    def compare_protected(self, revision, name, raw, source_identity):
        """Return same/changed/unavailable without disclosing protected tokens."""
        if (type(revision) is not int or not 1 <= revision < 2**63
                or type(name) is not str or not _NAME.fullmatch(name)
                or raw is None or source_identity is None):
            return "unavailable"
        if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
            return "unavailable"
        try:
            identity = _source_identity(source_identity, raw)
        except StoreError:
            return "unavailable"
        with self._read():
            row = self._db.execute("""SELECT p.token,h.private_key FROM protected_inputs p
                JOIN decision_inputs d ON d.protected_id=p.id CROSS JOIN host h
                WHERE d.revision=? AND d.name=?""", (revision, name)).fetchone()
            if row is None:
                return "unavailable"
            return "same" if hmac.compare_digest(row[0], hmac.digest(row[1], identity + b"\0" + raw, "sha256")) else "changed"

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None
        for name in ("_lockfd", "_dirfd"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
        self._closed = True

    def __enter__(self):
        if self._closed:
            _fail("store_closed")
        return self

    def __exit__(self, *args):
        self.close()
