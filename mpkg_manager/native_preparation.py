"""Offline native preparation using copied inputs and a fixed libalpm bridge.

This trusted library is not a public request handler or execution authority.
Only the bridge resolves dependencies. Acquiring inputs and applying a prepared
transaction are separate operations; neither occurs here.
"""
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from .query_process import QueryResult, run_bounded


BRIDGE = "/usr/lib/mpkg/native-prepare"
LIBALPM_VERSION = "16.0.1"
MAX_OUTPUT = 8 * 1024 * 1024
MAX_FILES = 40000
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARTIFACT_TOTAL = 16 * 1024 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ENV = {"PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C"}


class NativePreparationError(ValueError):
    """Fixed diagnostic only; private paths and native output stay private."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class NativeRequest:
    name: str
    version: str | None = None


@dataclass(frozen=True, slots=True)
class NativeRepository:
    name: str
    servers: tuple[str, ...] = field(repr=False)
    database: Path = field(repr=False)
    sha256: str = field(repr=False)
    signature: Path | None = field(default=None, repr=False)
    signature_sha256: str | None = field(default=None, repr=False)
    require_database_signature: bool = True


@dataclass(frozen=True, slots=True)
class NativeArtifact:
    name: str
    version: str
    repository: str
    path: Path = field(repr=False)
    sha256: str = field(repr=False)
    signature: Path = field(repr=False)
    signature_sha256: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class NativePreparation:
    """Private immutable proposal. Construction grants no apply authority."""
    preparation_id: str
    scope_bytes: bytes = field(repr=False)
    stage: Path = field(repr=False)

    @property
    def manifest(self):
        return json.loads(self.scope_bytes)

    @property
    def scope_sha256(self):
        return hashlib.sha256(self.scope_bytes).hexdigest()

    def as_dict(self):
        manifest = self.manifest
        return {"preparation_id": self.preparation_id,
                "installed_count": len(manifest["installed"]),
                "add_count": len(manifest["add"]),
                "remove_count": len(manifest["remove"]),
                "coordinated_upgrade": True,
                "apply_authorized": False,
                "acceptance": "libalpm_abi_and_exact_commit_unverified"}


def _require(value, code="invalid_native_preparation"):
    if not value:
        raise NativePreparationError(code)


def _text(value):
    return (type(value) is str and 0 < len(value) <= 4096
            and all(32 <= ord(c) < 127 for c in value)
            and not any(c.isspace() for c in value))


def _name(value):
    return type(value) is str and _NAME.fullmatch(value) is not None


def _hash(value):
    return type(value) is str and _HASH.fullmatch(value) is not None


def _path(value):
    _require(isinstance(value, Path) and value.is_absolute()
             and str(value) == os.path.normpath(value)
             and ".." not in value.parts and _text(str(value)))
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_directory(path):
    """Reject symlinks in every path component, including ancestors."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in _path(path).parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _tree(path, *, capture=True, limit=MAX_TREE_BYTES):
    """Capture a bounded regular-file tree, retaining directory identities."""
    entries, identities = [], []
    total = 0

    def visit(fd, prefix):
        nonlocal total
        before = os.fstat(fd)
        identities.append((prefix, _identity(before)))
        names = sorted(os.listdir(fd))
        _require(len(entries) + len(identities) + len(names) <= MAX_FILES,
                 "native_input_limit")
        for name in names:
            _require(_text(name) and name not in (".", ".."), "native_input_shape")
            rel = prefix + "/" + name if prefix else name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            _require(not info.st_mode & 0o022, "native_input_permissions")
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=fd)
                try:
                    _require(_identity(os.fstat(child)) == _identity(info),
                             "native_input_changed")
                    visit(child, rel)
                finally:
                    os.close(child)
            else:
                _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                         "native_input_shape")
                child = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
                try:
                    _require(_identity(os.fstat(child)) == _identity(info),
                             "native_input_changed")
                    raw = bytearray() if capture else None
                    file_digest = hashlib.sha256()
                    while chunk := os.read(child, 65536):
                        total += len(chunk)
                        _require(total <= limit, "native_input_limit")
                        file_digest.update(chunk)
                        if capture:
                            raw.extend(chunk)
                    _require(_identity(os.fstat(child)) == _identity(info),
                             "native_input_changed")
                finally:
                    os.close(child)
                entries.append((rel, bytes(raw) if capture else file_digest.hexdigest()))
                identities.append((rel, _identity(info)))
        _require(sorted(os.listdir(fd)) == names
                 and _identity(os.fstat(fd)) == _identity(before),
                 "native_input_changed")

    fd = _open_directory(path)
    try:
        _require(not os.fstat(fd).st_mode & 0o022, "native_input_permissions")
        visit(fd, "")
    finally:
        os.close(fd)
    digest = hashlib.sha256()
    for name, raw in entries:
        encoded = name.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big") + encoded)
        digest.update(hashlib.sha256(raw).digest() if capture else bytes.fromhex(raw))
    return tuple(entries), tuple(identities), digest.hexdigest()


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _copy_tree(captured, destination):
    destination.mkdir(mode=0o700)
    for name, raw in captured[0]:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _write(target, raw)


def _copy_file(source, destination, digest, limit):
    _path(source)
    _require(_hash(digest))
    parent = _open_directory(source.parent)
    try:
        fd = os.open(source.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and not before.st_mode & 0o022 and before.st_size <= limit,
                 "native_input_shape")
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                      | os.O_CLOEXEC, 0o600)
        try:
            actual, total = hashlib.sha256(), 0
            with os.fdopen(out, "wb", closefd=False) as stream:
                while chunk := os.read(fd, 1024 * 1024):
                    total += len(chunk)
                    _require(total <= limit, "native_input_limit")
                    actual.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(out)
            _require(_identity(os.fstat(fd)) == _identity(before),
                     "native_input_changed")
            _require(actual.hexdigest() == digest, "native_input_digest_mismatch")
            return total
        finally:
            os.close(out)
    finally:
        os.close(fd)


def _validate_inputs(host_id, repositories, artifacts, requests, architecture):
    try:
        _require(type(host_id) is str and str(uuid.UUID(host_id)) == host_id)
    except (ValueError, AttributeError):
        raise NativePreparationError("invalid_native_preparation") from None
    _require(architecture == "x86_64")
    for values, cls, limit in ((repositories, NativeRepository, 32),
                               (artifacts, NativeArtifact, 4096),
                               (requests, NativeRequest, 256)):
        _require(type(values) is tuple and (0 if cls is NativeArtifact else 1) <= len(values) <= limit)
        _require(all(type(item) is cls and _name(item.name) for item in values))
        _require(len({item.name for item in values}) == len(values))
    for repository in repositories:
        _require(type(repository.require_database_signature) is bool
                 and type(repository.servers) is tuple and repository.servers
                 and len(repository.servers) <= 16
                 and all(_text(url) and url.startswith("https://")
                         for url in repository.servers)
                 and _hash(repository.sha256))
        _path(repository.database)
        _require((repository.signature is None) == (repository.signature_sha256 is None))
        if repository.signature is not None:
            _path(repository.signature)
            _require(_hash(repository.signature_sha256))
        _require(not repository.require_database_signature or repository.signature is not None,
                 "database_signature_missing")
    names = {item.name for item in repositories}
    for artifact in artifacts:
        _require(_text(artifact.version) and artifact.repository in names
                 and _hash(artifact.sha256) and _hash(artifact.signature_sha256))
        _path(artifact.path)
        _path(artifact.signature)
    for request in requests:
        _require(request.version is None or (_text(request.version)
                 and not any(c in request.version for c in "<>=")))


def _bridge(stage):
    return run_bounded((BRIDGE, str(stage)), environment=_ENV, timeout=30,
                       max_output=MAX_OUTPUT, require_empty_stderr=True)


def _parse(raw, requests, artifacts, repositories):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT
             and raw.endswith(b"\n"), "invalid_native_bridge_result")
    try:
        rows = [tuple(line.split("\t")) for line in raw.decode("ascii").splitlines()]
    except UnicodeError:
        raise NativePreparationError("invalid_native_bridge_result") from None
    _require(len(rows) <= MAX_FILES and len(set(rows)) == len(rows)
             and all(all(_text(field) for field in row) for row in rows),
             "invalid_native_bridge_result")
    if len(rows) == 1 and rows[0][0] == "BLOCK":
        _require(len(rows[0]) == 2 and rows[0][1] in {
            "dependency", "conflict", "choice", "pin", "artifact", "signature",
            "database", "abi", "input"}, "invalid_native_bridge_result")
        raise NativePreparationError("native_" + rows[0][1] + "_unavailable")
    versions = [row for row in rows if row[0] == "V"]
    _require(versions == [("V", LIBALPM_VERSION)], "native_abi_unavailable")
    groups = {kind: [] for kind in ("I", "A", "R", "D", "P", "Q", "T")}
    widths = {"I": 4, "A": 5, "R": 4, "D": 4, "P": 3, "Q": 4, "T": 4}
    for row in rows:
        if row[0] == "V":
            continue
        _require(row[0] in groups and len(row) == widths[row[0]],
                 "invalid_native_bridge_result")
        groups[row[0]].append(row[1:])
    installed = {}
    for name, version, reason in groups["I"]:
        _require(_name(name) and name not in installed and reason in ("0", "1"),
                 "invalid_native_bridge_result")
        installed[name] = {"name": name, "version": version,
                           "reason": "explicit" if reason == "0" else "dependency"}
    removed = {}
    for name, version, reason in groups["R"]:
        _require(name not in removed and name in installed
                 and installed[name]["version"] == version
                 and reason in ("0", "1")
                 and installed[name]["reason"] == ("explicit" if reason == "0" else "dependency"),
                 "invalid_native_bridge_result")
        removed[name] = installed[name]
    by_artifact = {item.name: item for item in artifacts}
    artifact_indexes = {item.name: index for index, item in enumerate(artifacts)}
    added = {}
    for name, version, repository, digest in groups["A"]:
        _require(name not in added and name in by_artifact, "native_artifact_unavailable")
        artifact = by_artifact[name]
        _require((version, repository, digest) ==
                 (artifact.version, artifact.repository, artifact.sha256),
                 "native_artifact_mismatch")
        added[name] = {"name": name, "version": version, "repository": repository,
                       "sha256": digest, "signature_sha256": artifact.signature_sha256,
                       "archive": "artifacts/" + str(artifact_indexes[name]) + ".pkg",
                       "signature": "artifacts/" + str(artifact_indexes[name]) + ".pkg.sig"}
    final = {name: value for name, value in installed.items() if name not in removed}
    final.update(added)
    mapped = {}
    for name, provider, version in groups["T"]:
        _require(name not in mapped and _name(name) and provider in final
                 and final[provider]["version"] == version,
                 "invalid_native_bridge_result")
        mapped[name] = {"name": name, "provider": provider, "version": version}
    _require(set(mapped) == {request.name for request in requests},
             "invalid_native_bridge_result")
    for request in requests:
        _require(request.version is None or mapped[request.name]["provider"] != request.name
                 or mapped[request.name]["version"] == request.version,
                 "native_pin_unavailable")
    requested_providers = {item["provider"] for item in mapped.values()}
    reason_changes = [{"name": name, "from": "dependency", "to": "explicit"}
                      for name in sorted(requested_providers)
                      if installed.get(name, {}).get("reason") == "dependency"]
    for name, value in added.items():
        value["reason"] = ("explicit" if name in requested_providers
                           or installed.get(name, {}).get("reason") == "explicit"
                           else "dependency")
    for parent, dependency, provider in groups["D"]:
        _require(parent in added and provider in final, "invalid_native_bridge_result")
    for parent, provided in groups["P"]:
        _require(parent in added, "invalid_native_bridge_result")
    for kind, source, target in groups["Q"]:
        _require(kind in ("provider", "replacement"), "invalid_native_bridge_result")
        if kind == "replacement":
            _require(source in removed and target in added, "invalid_native_bridge_result")
        else:
            _require(target in final, "invalid_native_bridge_result")
    _require(all(any(kind == "replacement" and source == name
                     for kind, source, _ in groups["Q"]) for name in removed),
             "unexplained_native_removal")
    return {"installed": sorted(installed.values(), key=lambda item: item["name"]),
            "add": sorted(added.values(), key=lambda item: item["name"]),
            "remove": sorted(removed.values(), key=lambda item: item["name"]),
            "requests": [{"name": item.name, "version": item.version,
                          "provider": mapped[item.name]["provider"]} for item in requests],
            "reason_changes": reason_changes,
            "dependencies": sorted(groups["D"]), "provides": sorted(groups["P"]),
            "choices": sorted(groups["Q"])}


def prepare_native_transaction(*, host_id, installed_database, keyring,
                               repositories, artifacts, requests, staging_root,
                               architecture="x86_64", runner=None):
    """Prepare against a stable copied inventory and preacquired signed inputs.

    Paths/runners come from trusted installed integration code, never a public
    request. A supplied runner receives only the newly created staging path and
    must obey the fixed bridge protocol. Failures leave a private orphan stage;
    a result retains its copies for later explicit import/revalidation.
    """
    _validate_inputs(host_id, repositories, artifacts, requests, architecture)
    for path in (installed_database, keyring, staging_root):
        _path(path)
    _require(runner is None or callable(runner))
    try:
        rootfd = _open_directory(staging_root)
        try:
            info = os.fstat(rootfd)
            _require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                     "native_staging_not_private")
        finally:
            os.close(rootfd)
        # Keep staging out of every source tree, including the live local DB.
        _require(not staging_root.is_relative_to(installed_database)
                 and not staging_root.is_relative_to(keyring), "native_staging_overlap")
        inventory = _tree(installed_database)
        keys = _tree(keyring)
        _require({name for name, _ in keys[0]} == {"pubring.gpg", "trustdb.gpg"},
                 "unsupported_native_keyring")
        stage = Path(tempfile.mkdtemp(prefix="native-", dir=staging_root))
        (stage / "root").mkdir(mode=0o700)
        (stage / "db").mkdir(mode=0o700)
        (stage / "db/sync").mkdir(mode=0o700)
        (stage / "artifacts").mkdir(mode=0o700)
        _copy_tree(inventory, stage / "db/local")
        _copy_tree(keys, stage / "gpg")
        _require(_tree(installed_database) == inventory, "installed_snapshot_unstable")
        repo_lines, source_manifest = [], []
        for repository in repositories:
            _copy_file(repository.database, stage / "db/sync" / (repository.name + ".db"),
                       repository.sha256, MAX_TREE_BYTES)
            if repository.signature is not None:
                _copy_file(repository.signature, stage / "db/sync" / (repository.name + ".db.sig"),
                           repository.signature_sha256, MAX_TREE_BYTES)
            repo_lines.append(repository.name + "\t" + str(int(repository.require_database_signature)))
            source_manifest.append({"name": repository.name, "servers": repository.servers,
                                    "database_sha256": repository.sha256,
                                    "signature_sha256": repository.signature_sha256,
                                    "package_signature": "required_trusted",
                                    "database_signature": ("required_trusted" if
                                        repository.require_database_signature else "optional_trusted")})
        artifact_lines, total = [], 0
        for index, artifact in enumerate(artifacts):
            name = str(index) + ".pkg"
            total += _copy_file(artifact.path, stage / "artifacts" / name,
                                artifact.sha256, MAX_ARTIFACT_BYTES)
            total += _copy_file(artifact.signature, stage / "artifacts" / (name + ".sig"),
                                artifact.signature_sha256, MAX_TREE_BYTES)
            _require(total <= MAX_ARTIFACT_TOTAL, "native_input_limit")
            artifact_lines.append("\t".join((artifact.name, artifact.version,
                                             artifact.repository, name, artifact.sha256)))
        _write(stage / "repositories", ("\n".join(repo_lines) + "\n").encode("ascii"))
        _write(stage / "artifacts.list", ("\n".join(artifact_lines)
                                         + ("\n" if artifact_lines else "")).encode("ascii"))
        _write(stage / "requests", ("\n".join(item.name + "\t" + (item.version or "-")
                                             for item in requests) + "\n").encode("ascii"))
        _write(stage / "protocol", ("1\t" + LIBALPM_VERSION + "\t" + architecture + "\n").encode())
        before_stage = _tree(stage / "db/local")[2]
        before_sync = _tree(stage / "db/sync")[2]
        before_keys = _tree(stage / "gpg")[2]
        before_artifacts = _tree(stage / "artifacts", capture=False,
                                 limit=MAX_ARTIFACT_TOTAL)[2]
        result = (_bridge if runner is None else runner)(stage)
        _require(type(result) is QueryResult and result.code == "ok"
                 and result.returncode == 0, "native_bridge_unavailable")
        transaction = _parse(result.output, requests, artifacts, repositories)
        _require(_tree(installed_database) == inventory, "installed_snapshot_unstable")
        _require(_tree(keyring) == keys, "native_keyring_changed")
        _require(_tree(stage / "gpg")[2] == before_keys, "native_staged_keyring_changed")
        _require(_tree(stage / "db/local")[2] == before_stage
                 and _tree(stage / "db/sync")[2] == before_sync
                 and _tree(stage / "artifacts", capture=False,
                           limit=MAX_ARTIFACT_TOTAL)[2] == before_artifacts,
                 "native_staged_input_changed")
        manifest = {"schema": 1, "host_id": host_id, "architecture": architecture,
                    "libalpm_version": LIBALPM_VERSION,
                    "installed_fingerprint": inventory[2], "keyring_fingerprint": keys[2],
                    "sources": source_manifest, "coordinated_upgrade": True,
                    "native_flags": 0, **transaction}
        raw = _canonical(manifest)
        _write(stage / "manifest.json", raw)
        # Copies and manifest are synchronized before exposing references.
        for directory, _, _ in os.walk(stage, topdown=False, followlinks=False):
            fd = _open_directory(Path(directory))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        fd = _open_directory(staging_root)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return NativePreparation(str(uuid.uuid4()), raw, stage)
    except NativePreparationError:
        raise
    except Exception:
        raise NativePreparationError("native_preparation_unavailable") from None


def require_same_native_scope(accepted, fresh):
    """Reject all changed bindings; this comparison is not apply authority."""
    _require(type(accepted) is NativePreparation and type(fresh) is NativePreparation)
    _require(accepted.scope_bytes == fresh.scope_bytes, "native_prepared_scope_changed")
