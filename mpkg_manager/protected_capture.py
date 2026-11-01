"""Read-only bounded capture beneath roots from a verified host-policy handle."""
import os
import re
import stat

from .host_policy import (LoadedHostPolicy, PolicyError, _DirectoryChain,
                          _fingerprint, _OPEN_FILE, _read_bounded)
from .store import MAX_INPUT_BYTES, ProtectedInput


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class CaptureError(RuntimeError):
    """Fixed diagnostics that never include input bytes, paths or digests."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _arguments(root, relative_path, name, purpose):
    if (type(root) is not str or type(relative_path) is not str
            or not 0 < len(relative_path) <= 4096 or "\0" in relative_path
            or len(root) + 1 + len(relative_path) > 4096
            or any(part in ("", ".", "..") for part in relative_path.split("/"))
            or type(name) is not str or not _NAME.fullmatch(name)
            or type(purpose) is not str or not 0 < len(purpose) <= 1024):
        raise CaptureError("invalid_capture_request")
    try:
        relative_path.encode("utf-8")
        if len(purpose.encode("utf-8")) > 1024:
            raise CaptureError("invalid_capture_request")
    except UnicodeError:
        raise CaptureError("invalid_capture_request") from None


def _regular(info, device):
    if type(info.st_mode) is not int or not 0 <= info.st_mode < 2**63:
        raise CaptureError("input_metadata_unsupported")
    if not stat.S_ISREG(info.st_mode):
        raise CaptureError("input_not_regular")
    if info.st_nlink != 1:
        raise CaptureError("input_hardlinked")
    if info.st_dev != device:
        raise CaptureError("input_device_changed")
    if info.st_size > MAX_INPUT_BYTES:
        raise CaptureError("input_too_large")


def _source_identity(info, path):
    identity = {"path": path, "device": info.st_dev, "inode": info.st_ino,
                "size": info.st_size, "mtime_ns": info.st_mtime_ns,
                "uid": info.st_uid, "gid": info.st_gid, "mode": info.st_mode,
                "links": info.st_nlink}
    # The durable store accepts nonnegative signed-64-bit JSON integers.
    # Do not return an apparently usable capture that cannot be recorded,
    # and never clamp or otherwise substitute its observed source identity.
    if any(type(value) is not int or not 0 <= value < 2**63
           for key, value in identity.items() if key != "path"):
        raise CaptureError("input_metadata_unsupported")
    return identity


def capture_protected(policy, *, root, relative_path, name, purpose):
    """Capture one regular file without following links or changing the host.

    Before/after identity checks detect observed replacement and writes; they
    do not exclude concurrent writers or detect same-device bind mounts.
    """
    _arguments(root, relative_path, name, purpose)
    if type(policy) is not LoadedHostPolicy:
        raise CaptureError("policy_unavailable")
    try:
        policy._verify()
        if root not in policy.policy.allowed_input_roots:
            raise CaptureError("input_root_not_allowed")
    except PolicyError:
        raise CaptureError("policy_unavailable") from None
    roots = parents = None
    descriptor = None
    try:
        roots = _DirectoryChain(root)
        device = os.fstat(roots.fd).st_dev
        parts = relative_path.split("/")
        path = root + "/" + relative_path
        parents = _DirectoryChain(parts[:-1], start_fd=roots.fd, device=device)
        before = os.stat(parts[-1], dir_fd=parents.fd, follow_symlinks=False)
        _regular(before, device)
        _source_identity(before, path)
        descriptor = os.open(parts[-1], _OPEN_FILE, dir_fd=parents.fd)
        opened = os.fstat(descriptor)
        _regular(opened, device)
        identity = _source_identity(opened, path)
        if _fingerprint(opened) != _fingerprint(before):
            raise CaptureError("input_changed")
        raw = _read_bounded(descriptor, MAX_INPUT_BYTES)
        after = os.fstat(descriptor)
        linked = os.stat(parts[-1], dir_fd=parents.fd, follow_symlinks=False)
        _regular(after, device)
        _regular(linked, device)
        if (_fingerprint(opened) != _fingerprint(after)
                or _fingerprint(opened) != _fingerprint(linked) or len(raw) != opened.st_size):
            raise CaptureError("input_changed")
        parents.verify()
        roots.verify()
        try:
            policy._verify()
        except PolicyError:
            raise CaptureError("policy_unavailable") from None
        return ProtectedInput(name, raw, identity, purpose)
    except PolicyError as error:
        code = error.code if error.code in ("input_device_changed", "input_path_changed", "input_too_large") else "input_unavailable"
        raise CaptureError(code) from None
    except OSError:
        raise CaptureError("input_unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parents is not None:
            parents.close()
        if roots is not None:
            roots.close()
