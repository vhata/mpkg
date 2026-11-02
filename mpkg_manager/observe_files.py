"""Read-only Linux path metadata; no content reads or application authority."""
import errno
import grp
import os
import pwd
import re
import stat

from .declarations import DeclarationError, validate_model
from .observations import Observation, ObservationBatch, utc_now, validate_context


MAX_RESOURCES = 256
MAX_PATH_BYTES = 4096
MAX_COMPONENTS = 128
SOURCE = "filesystem_metadata"
_KINDS = {"file": stat.S_ISREG, "directory": stat.S_ISDIR, "symlink": stat.S_ISLNK}
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}\Z")
_PROPERTIES = ("present", "mode", "owner", "group")
_OPEN = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC


class _Unavailable(Exception):
    def __init__(self, code):
        self.code = code


class SystemIdentities:
    """At most two NSS calls per name, without account enumeration.

    Reverse and forward records must agree with the observed numeric ID.
    Synchronous NSS has no wall-clock deadline in this adapter.
    """
    def user(self, uid):
        reverse = pwd.getpwuid(uid)
        name = reverse.pw_name
        if type(reverse.pw_uid) is not int or reverse.pw_uid != uid or type(name) is not str or not _NAME.fullmatch(name):
            raise ValueError
        forward = pwd.getpwnam(name)
        if type(forward.pw_uid) is not int or forward.pw_uid != uid or forward.pw_name != name:
            raise ValueError
        return name

    def group(self, gid):
        reverse = grp.getgrgid(gid)
        name = reverse.gr_name
        if type(reverse.gr_gid) is not int or reverse.gr_gid != gid or type(name) is not str or not _NAME.fullmatch(name):
            raise ValueError
        forward = grp.getgrnam(name)
        if type(forward.gr_gid) is not int or forward.gr_gid != gid or forward.gr_name != name:
            raise ValueError
        return name


def _name(resolver, numeric):
    try:
        if type(numeric) is not int or not 0 <= numeric < 2**32:
            raise ValueError
        name = resolver(numeric)
        if type(name) is not str or not _NAME.fullmatch(name):
            raise ValueError
        return name
    except Exception:
        # Resolver failures contain no public diagnostics. Cancellation still
        # propagates because KeyboardInterrupt/SystemExit are BaseExceptions.
        return None


def _parent_key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _fingerprint(info):
    return (*_parent_key(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Path:
    def __init__(self):
        self.fds = []
        self.links = []

    def open(self, path):
        fd = os.open("/", _OPEN | os.O_DIRECTORY)
        self.fds.append(fd)
        self.root_key = _parent_key(os.fstat(fd))
        parts = path.split("/")[1:] if path != "/" else []
        for part in parts[:-1]:
            parent = self.fds[-1]
            try:
                before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                self.missing(parent, part)
                return None, None
            if stat.S_ISLNK(before.st_mode):
                raise _Unavailable("parent_symlink_not_followed")
            if not stat.S_ISDIR(before.st_mode):
                raise _Unavailable("parent_not_directory")
            child = os.open(part, _OPEN | os.O_DIRECTORY, dir_fd=parent)
            self.fds.append(child)
            if _parent_key(before) != _parent_key(os.fstat(child)):
                raise _Unavailable("path_changed")
            self.links.append((parent, part, child, _parent_key(before)))
        return self.fds[-1], parts[-1] if parts else "."

    def verify(self):
        if _parent_key(os.fstat(self.fds[0])) != self.root_key:
            raise _Unavailable("path_changed")
        for parent, name, child, original in self.links:
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _parent_key(linked) != original or _parent_key(os.fstat(child)) != original:
                raise _Unavailable("path_changed")

    def missing(self, parent, name):
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            self.verify()
            return
        raise _Unavailable("path_changed")

    def close(self):
        while self.fds:
            os.close(self.fds.pop())


def _snapshot(resource, identities):
    path = _Path()
    descriptor = None
    try:
        parent, name = path.open(resource["identity"]["path"])
        if parent is None:
            return {}, "absent"
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            path.missing(parent, name)
            return {}, "absent"
        descriptor = os.open(name, _OPEN, dir_fd=parent)
        info = os.fstat(descriptor)
        if _fingerprint(before) != _fingerprint(info):
            raise _Unavailable("path_changed")
        if not _KINDS[resource["kind"]](info.st_mode):
            raise _Unavailable("path_kind_mismatch")
        values = {"present": True, "mode": stat.S_IMODE(info.st_mode),
                  "owner": _name(identities.user, info.st_uid),
                  "group": _name(identities.group, info.st_gid)}
        if resource["kind"] == "symlink":
            # Linux readlinkat with an empty name reads this O_PATH symlink,
            # including a dangling target, without opening its destination.
            target = os.readlink("", dir_fd=descriptor)
            try:
                if not target or len(target.encode("utf-8")) > MAX_PATH_BYTES or "\0" in target:
                    raise ValueError
            except (UnicodeError, ValueError):
                target = None
            values["target"] = target
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _fingerprint(info) != _fingerprint(os.fstat(descriptor)) or _fingerprint(info) != _fingerprint(linked):
            raise _Unavailable("path_changed")
        path.verify()
        return values, None
    except _Unavailable as error:
        return {}, error.code
    except PermissionError:
        return {}, "path_permission_denied"
    except FileNotFoundError:
        return {}, "path_changed"
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            return {}, "path_changed"
        return {}, "path_metadata_unavailable"
    except (OverflowError, ValueError):
        return {}, "path_metadata_unavailable"
    finally:
        if descriptor is not None:
            os.close(descriptor)
        path.close()


def observe_files(resources, *, host_id, observed_at=None, identities=None):
    """Observe a bounded list of declared paths without reading their contents.

    Identity resolvers are trusted Python embedding seams, not declarations.
    Raw facts contain paths/targets; public comparison reports redact values.
    """
    when = utc_now() if observed_at is None else observed_at
    validate_context(host_id, when)
    try:
        if type(resources) not in (list, tuple) or len(resources) > MAX_RESOURCES:
            raise ValueError
        checked, seen = [], set()
        for resource in resources:
            if type(resource) is not dict or resource.get("kind") not in _KINDS:
                raise ValueError
            minimal = {key: resource[key] for key in ("id", "kind", "identity")}
            validated = validate_model({"schema": 1, "components": [], "resources": [minimal]})["resources"][0]
            if validated["identity"] != resource["identity"] or validated["id"] in seen:
                raise ValueError
            name = validated["identity"]["path"]
            if len(name.encode("utf-8")) > MAX_PATH_BYTES or len(name.split("/")) - 1 > MAX_COMPONENTS:
                raise ValueError
            seen.add(validated["id"])
            checked.append(validated)
        identities = SystemIdentities() if identities is None else identities
        if not callable(identities.user) or not callable(identities.group):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, DeclarationError, RecursionError):
        raise ValueError("invalid_file_observation_request") from None
    facts = []
    for resource in checked:
        values, error = _snapshot(resource, identities)
        properties = _PROPERTIES + (("target",) if resource["kind"] == "symlink" else ())
        if resource["kind"] == "file":
            properties += ("content", "content_input")
        for prop in properties:
            value = values.get(prop)
            if error == "absent":
                state, value, reason = ("known", False, None) if prop == "present" else ("absent", None, None)
            elif error:
                state, value, reason = "unknown", None, error
            elif prop in ("content", "content_input"):
                state, value, reason = "unknown", None, "file_content_not_observed"
            elif value is None:
                state, reason = "unknown", "identity_name_unavailable" if prop in ("owner", "group") else "symlink_target_unavailable"
            else:
                state, reason = "known", None
            facts.append(Observation(host_id, resource["id"], resource["kind"], resource["identity"],
                prop, state, value, when, SOURCE, (reason,) if reason else ()))
    return ObservationBatch(host_id, when, tuple(facts), tuple(item["id"] for item in checked),
        ("time_bounded_observation_not_atomic_host_snapshot", "metadata_not_content_or_access_check",
         "filesystem_and_identity_resolution_have_no_deadline", "mount_aliases_not_excluded",
         "no_management_authority_inferred"))
