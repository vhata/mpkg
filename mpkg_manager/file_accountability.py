"""Bounded metadata enumeration and classification; no content or authority."""
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import errno
import hashlib
import os
import posixpath
import re
import stat

from .declarations import Declaration, DeclarationError, load_declaration
from .observations import utc_now, validate_context


MAX_SCOPES = 8
MAX_PATH_BYTES = 4096
MAX_COMPONENTS = 128
MAX_RULES = 128
MAX_PATTERNS = 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_PATH_OPEN = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORY_OPEN = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
SOURCE = "bounded_filesystem_accountability"
LIMITATIONS = (
    "metadata_not_content_or_package_baseline",
    "classification_not_management_authority",
    "time_bounded_observation_not_atomic_snapshot",
    "same_device_mount_aliases_may_be_traversed",
    "synchronous_filesystem_calls_have_no_deadline",
    "paths_outside_requested_scopes_not_inspected",
)


def _invalid():
    raise ValueError("invalid_file_accountability_request")


def _within(path, root):
    return root == "/" or path == root or path.startswith(root + "/")


def _path(value):
    try:
        valid = (type(value) is str and value.startswith("/") and not value.startswith("//")
                 and posixpath.normpath(value) == value and "\0" not in value
                 and len(value.encode("utf-8")) <= MAX_PATH_BYTES
                 and len(value.split("/")) - 1 <= MAX_COMPONENTS)
    except UnicodeError:
        valid = False
    if not valid:
        _invalid()
    return value


@dataclass(frozen=True)
class ScanScope:
    """A trusted embedding selects these paths, never an imported report."""
    id: str
    root: str = field(repr=False)
    exclusions: tuple = field(default=(), repr=False)

    def __post_init__(self):
        if type(self.id) is not str or not _ID.fullmatch(self.id):
            _invalid()
        _path(self.root)
        if type(self.exclusions) not in (list, tuple) or len(self.exclusions) > 128:
            _invalid()
        values = tuple(_path(value) for value in self.exclusions)
        if len(set(values)) != len(values) or any(not _within(value, self.root) for value in values):
            _invalid()
        object.__setattr__(self, "exclusions", values)


@dataclass(frozen=True)
class ScanLimits:
    max_entries: int = 4096
    max_directories: int = 256
    max_depth: int = 32
    max_path_bytes: int = 1024 * 1024

    def __post_init__(self):
        for name, maximum in (("max_entries", 4096), ("max_directories", 256),
                              ("max_depth", 64), ("max_path_bytes", 1024 * 1024)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                _invalid()


@dataclass(frozen=True)
class ScanEntry:
    scope_id: str
    relative_path: str = field(repr=False)
    kind: str
    classification: str
    reason: str
    resource_ids: tuple = ()
    rule_ids: tuple = ()
    component_ids: tuple = ()


@dataclass(frozen=True)
class ScanGap:
    relative_path: str = field(repr=False)
    reason: str


@dataclass(frozen=True)
class ScopeResult:
    scope: ScanScope
    state: str
    entries: tuple = field(repr=False)
    gaps: tuple = field(repr=False)


@dataclass(frozen=True)
class AccountabilityScan:
    host_id: str
    observed_at: str
    declaration_sha256: str
    source_sha256: str
    scopes: tuple = field(repr=False)
    limits: ScanLimits
    source: str = SOURCE
    limitations: tuple = LIMITATIONS

    def summary(self):
        """A fresh redacted projection; private paths never leave this API."""
        scopes = []
        for result in self.scopes:
            counts = {}
            for entry in result.entries:
                counts[entry.classification] = counts.get(entry.classification, 0) + 1
            gaps = {}
            for gap in result.gaps:
                gaps[gap.reason] = gaps.get(gap.reason, 0) + 1
            scopes.append({"id": result.scope.id, "state": result.state,
                           "entries_observed": len(result.entries),
                           "classifications": counts, "gaps": gaps,
                           "exclusions_requested": len(result.scope.exclusions)})
        return {"host_id": self.host_id, "observed_at": self.observed_at,
                "source": self.source, "declaration_sha256": self.declaration_sha256,
                "source_sha256": self.source_sha256, "scopes": scopes,
                "policy": {"symlinks": "never_follow", "mounts": "same_device",
                           "file_contents": "never_read"},
                "limits": {key: getattr(self.limits, key) for key in
                           ("max_entries", "max_directories", "max_depth", "max_path_bytes")},
                "limitations": list(self.limitations)}


def _pattern(value):
    # Do not invent semantics for repeated separators, escapes, malformed
    # brackets, or embedded recursive globs. Validate all rules before I/O.
    try:
        if len(value.encode("utf-8")) > 256 or "\\" in value:
            _invalid()
    except UnicodeError:
        _invalid()
    parts = value.split("/")
    if len(parts) > 32 or any(part in ("", ".", "..") for part in parts):
        _invalid()
    for part in parts:
        if "**" in part and part != "**":
            _invalid()
        position = 0
        while position < len(part):
            if part[position] == "[":
                end = part.find("]", position + 1)
                if end < 0 or part[position + 1:end] in ("", "!") or "[" in part[position + 1:end]:
                    _invalid()
                position = end
            elif part[position] == "]":
                _invalid()
            position += 1
    return tuple(parts)


def _matches(parts, pattern):
    # Bounded dynamic programming avoids recursive '**' backtracking.
    reachable = {0}
    for segment in pattern:
        if segment == "**":
            reachable = set(range(min(reachable), len(parts) + 1)) if reachable else set()
        else:
            reachable = {index + 1 for index in reachable
                         if index < len(parts) and fnmatchcase(parts[index], segment)}
    return len(parts) in reachable


def _kind(info):
    for name, predicate in (("file", stat.S_ISREG), ("directory", stat.S_ISDIR),
                            ("symlink", stat.S_ISLNK)):
        if predicate(info.st_mode):
            return name
    return "special"


def _classify(scope_id, relative, path, kind, resources, rules):
    declared = resources.get(path, ())
    if declared:
        ids = tuple(item["id"] for item in declared)
        expected = {"file" if item["kind"] == "sonarr_xml" else item["kind"] for item in declared}
        if expected != {kind}:
            return ScanEntry(scope_id, relative, kind, "unknown", "declared_kind_mismatch", ids)
        label = "declared_configuration" if kind == "file" else "declared_resource"
        return ScanEntry(scope_id, relative, kind, label, "content_and_properties_not_compared", ids)
    # These files need package-aware comparison even under a runtime rule.
    if path.endswith((".pacnew", ".pacsave")):
        return ScanEntry(scope_id, relative, kind, "package_side_file", "package_baseline_unavailable")
    matches = []
    for rule, patterns in rules:
        if (path == rule["root"] or not _within(path, rule["root"]) or kind not in rule["types"]
                or any(_within(path, value) for value in rule["exceptions"])):
            continue
        local = path[len(rule["root"]):].lstrip("/").split("/")
        if any(_matches(local, pattern) for pattern in patterns):
            matches.append(rule)
    if matches:
        components = tuple(sorted({rule["component"] for rule in matches}))
        ids = tuple(sorted(rule["id"] for rule in matches))
        if len(components) != 1:
            return ScanEntry(scope_id, relative, kind, "unknown", "ambiguous_runtime_responsibility",
                             rule_ids=ids, component_ids=components)
        return ScanEntry(scope_id, relative, kind, "runtime_rule_match", "declared_pattern_not_content_proof",
                         rule_ids=ids, component_ids=components)
    return ScanEntry(scope_id, relative, kind, "unexplained", "no_supported_classification")


def _key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _fingerprint(info):
    return (*_key(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Changed(Exception):
    pass


class _Budget:
    def __init__(self, limits):
        self.limits = limits
        self.entries = self.directories = self.path_bytes = 0

    def reserve(self, relative):
        try:
            count = len(relative.encode("utf-8"))
        except UnicodeError:
            return "path_encoding_unsupported"
        if count > MAX_PATH_BYTES:
            return "path_length_limit"
        if self.entries >= self.limits.max_entries:
            return "entry_limit"
        if self.path_bytes + count > self.limits.max_path_bytes:
            return "path_bytes_limit"
        self.entries += 1
        self.path_bytes += count
        return None


def _scan(scope, budget, resources, rules):
    entries, gaps, ancestors, frames = [], [], [], []
    root_fd = None

    def gap(relative, reason):
        gaps.append(ScanGap(relative, reason))

    def verify_frame(frame):
        fd, parent, name, original, _, _ = frame
        if (_fingerprint(os.fstat(fd)) != original
                or _fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) != original):
            raise _Changed

    def push(parent, name, relative, expected, depth):
        if budget.directories >= budget.limits.max_directories:
            gap(relative, "directory_limit")
            return
        budget.directories += 1
        fd = None
        try:
            fd = os.open(name, _DIRECTORY_OPEN, dir_fd=parent)
            info = os.fstat(fd)
            if _fingerprint(info) != _fingerprint(expected):
                raise _Changed
            iterator = os.scandir(fd)
            frames.append((fd, parent, name, _fingerprint(info), iterator, (relative, depth)))
            fd = None
        except PermissionError:
            gap(relative, "directory_permission_denied")
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                # A directory was already observed at this exact parent/name.
                # Missing/non-directory/no-follow failure detects replacement,
                # including a root whose frame could never be opened.
                raise _Changed from None
            gap(relative, "directory_unavailable")
        finally:
            if fd is not None:
                os.close(fd)

    try:
        if any(_within(scope.root, excluded) for excluded in scope.exclusions):
            return ScopeResult(scope, "unavailable", (), (ScanGap(".", "excluded"),))
        error = budget.reserve(".")
        if error:
            return ScopeResult(scope, "unavailable", (), (ScanGap(".", error),))
        root_fd = os.open("/", _PATH_OPEN | os.O_DIRECTORY)
        root_key = _key(os.fstat(root_fd))
        parent = root_fd
        parts = scope.root.split("/")[1:] if scope.root != "/" else []
        for name in parts[:-1]:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                return ScopeResult(scope, "unavailable", (), (ScanGap(".", "parent_not_directory"),))
            fd = os.open(name, _PATH_OPEN | os.O_DIRECTORY, dir_fd=parent)
            ancestors.append((parent, name, fd, _key(before)))
            if _key(os.fstat(fd)) != _key(before):
                raise _Changed
            parent = fd
        leaf = parts[-1] if parts else "."
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            return ScopeResult(scope, "unavailable", (), (ScanGap(".", "root_not_directory"),))
        device = before.st_dev
        entries.append(_classify(scope.id, ".", scope.root, "directory", resources, rules))
        push(parent, leaf, ".", before, 0)
        while frames:
            frame = frames[-1]
            fd, _, _, _, iterator, (relative, depth) = frame
            try:
                item = next(iterator)
            except StopIteration:
                verify_frame(frame)
                iterator.close()
                os.close(fd)
                frames.pop()
                continue
            except OSError:
                gap(relative, "directory_enumeration_unavailable")
                verify_frame(frame)
                iterator.close()
                os.close(fd)
                frames.pop()
                continue
            name = item.name
            child_relative = name if relative == "." else relative + "/" + name
            error = budget.reserve(child_relative)
            if error:
                # Stopping a nested frame also leaves ancestor siblings unseen.
                # The gap covers the whole stopped scope, not just this frame.
                gap(".", error)
                # Bounds apply to directory enumeration, not just emitted rows.
                # Stop the whole scope rather than reading unbounded skipped names.
                break
            path = posixpath.join(scope.root, child_relative)
            if any(_within(path, excluded) for excluded in scope.exclusions):
                gap(child_relative, "excluded")
                continue
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                kind = _kind(info)
                entry = _classify(scope.id, child_relative, path, kind, resources, rules)
                if _fingerprint(os.stat(name, dir_fd=fd, follow_symlinks=False)) != _fingerprint(info):
                    raise _Changed
                entries.append(entry)
                if kind == "directory":
                    if info.st_dev != device:
                        gap(child_relative, "device_boundary")
                    elif depth + 1 >= budget.limits.max_depth:
                        gap(child_relative, "depth_limit")
                    else:
                        push(fd, name, child_relative, info, depth + 1)
            except PermissionError:
                gap(child_relative, "entry_permission_denied")
            except FileNotFoundError:
                raise _Changed from None
            except OSError:
                gap(child_relative, "entry_metadata_unavailable")
        for frame in frames:
            verify_frame(frame)
        if _key(os.fstat(root_fd)) != root_key:
            raise _Changed
        for parent, name, fd, original in ancestors:
            if (_key(os.fstat(fd)) != original
                    or _key(os.stat(name, dir_fd=parent, follow_symlinks=False)) != original):
                raise _Changed
        return ScopeResult(scope, "partial" if gaps else "complete", tuple(entries), tuple(gaps))
    except _Changed:
        return ScopeResult(scope, "unavailable", (), (ScanGap(".", "path_changed"),))
    except PermissionError:
        return ScopeResult(scope, "unavailable", (), (ScanGap(".", "path_permission_denied"),))
    except FileNotFoundError:
        return ScopeResult(scope, "unavailable", (), (ScanGap(".", "path_missing_or_changed"),))
    except OSError:
        return ScopeResult(scope, "unavailable", (), (ScanGap(".", "path_unavailable"),))
    finally:
        while frames:
            fd, _, _, _, iterator, _ = frames.pop()
            iterator.close()
            os.close(fd)
        for _, _, fd, _ in reversed(ancestors):
            os.close(fd)
        if root_fd is not None:
            os.close(root_fd)


def scan_files(declaration, scopes, *, host_id, observed_at=None, limits=None):
    """Enumerate trusted scopes without content reads, adoption or effects.

    Paths and matching evidence are private Python records. ``summary()`` is
    the redacted projection. The caller must supply host and scope authority;
    this library neither authenticates imported JSON nor authorizes scanning.
    """
    when = utc_now() if observed_at is None else observed_at
    validate_context(host_id, when)
    try:
        if type(declaration) is not Declaration:
            _invalid()
        checked = load_declaration(declaration.source_bytes)
        if checked != declaration:
            _invalid()
        if type(scopes) not in (list, tuple) or not 1 <= len(scopes) <= MAX_SCOPES:
            _invalid()
        if any(type(item) is not ScanScope for item in scopes):
            _invalid()
        scopes = tuple(ScanScope(item.id, item.root, item.exclusions) for item in scopes)
        if not scopes or len({item.id for item in scopes}) != len(scopes):
            _invalid()
        for index, item in enumerate(scopes):
            if any(_within(item.root, previous.root) or _within(previous.root, item.root)
                   for previous in scopes[:index]):
                _invalid()
        limits = ScanLimits() if limits is None else limits
        if type(limits) is not ScanLimits:
            _invalid()
        limits = ScanLimits(limits.max_entries, limits.max_directories, limits.max_depth, limits.max_path_bytes)
        model = checked.model
        if len(model["runtime_rules"]) > MAX_RULES or len(model["resources"]) > 4096:
            _invalid()
        rules = []
        total_patterns = 0
        for rule in model["runtime_rules"]:
            _path(rule["root"])
            if len(rule["exceptions"]) > 128:
                _invalid()
            for value in rule["exceptions"]:
                _path(value)
            total_patterns += len(rule["patterns"])
            if total_patterns > MAX_PATTERNS:
                _invalid()
            rules.append((rule, tuple(_pattern(value) for value in rule["patterns"])))
        resources = {}
        for resource in model["resources"]:
            if resource["kind"] in ("file", "directory", "symlink", "sonarr_xml"):
                path = _path(resource["identity"]["path"])
                resources.setdefault(path, []).append(resource)
    except (ValueError, TypeError, AttributeError, KeyError, DeclarationError, RecursionError):
        _invalid()
    budget = _Budget(limits)
    results = tuple(_scan(scope, budget, resources, rules) for scope in scopes)
    return AccountabilityScan(host_id, when, checked.sha256,
                              hashlib.sha256(checked.source_bytes).hexdigest(), results, limits)
