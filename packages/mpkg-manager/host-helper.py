#!/usr/bin/python3.12 -I
"""Fixed privileged entrypoint; install this file, never sudo a checkout."""
import os
import resource
import stat
import sys
import uuid


INSTALL_ROOT = "/usr/lib/mpkg"
ENTRYPOINT = INSTALL_ROOT + "/host-helper.py"
WORKER_ENTRYPOINT = INSTALL_ROOT + "/attempt-worker.py"
_FAILURE = b'{"error":{"code":"installed_helper_unavailable"},"ok":false,"version":1}\n'


def _permission(info, owner_uid, *, directory=False):
    if ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid not in ((0, owner_uid) if directory else (owner_uid,))
            or info.st_mode & 0o022 or (not directory and info.st_nlink != 1)):
        raise ValueError


def _verified_installation(root, *, owner_uid=0):
    """Check installed Python sources before importing any product module.

    Alternate root/owner arguments are available only to trusted fixture code.
    The command entrypoint always supplies fixed paths and UID zero.
    """
    if (type(root) is not str or not root.startswith("/") or root == "/"
            or root != os.path.normpath(root)):
        raise ValueError
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    package = None
    try:
        _permission(os.fstat(directory), owner_uid, directory=True)
        for part in root.split("/")[1:]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
            _permission(os.fstat(directory), owner_uid, directory=True)
        for entrypoint in ("host-helper.py", "attempt-worker.py"):
            _permission(os.stat(entrypoint, dir_fd=directory, follow_symlinks=False), owner_uid)
        package = os.open("mpkg_manager", flags, dir_fd=directory)
        _permission(os.fstat(package), owner_uid, directory=True)
        names = os.listdir(package)
        if not {"__init__.py", "host_helper.py", "host_protocol.py", "attempt_worker.py"} <= set(names) or len(names) > 128:
            raise ValueError
        total = 0
        for name in names:
            if not name.endswith(".py"):
                raise ValueError
            info = os.stat(name, dir_fd=package, follow_symlinks=False)
            _permission(info, owner_uid)
            if info.st_size > 2 * 1024 * 1024:
                raise ValueError
            total += info.st_size
        if total > 64 * 1024 * 1024:
            raise ValueError
    finally:
        if package is not None:
            os.close(package)
        os.close(directory)


def main():
    try:
        worker = __file__ == WORKER_ENTRYPOINT
        if (sys.version_info[:2] != (3, 12) or not sys.flags.isolated
                or os.geteuid() != 0 or os.getuid() != 0
                or __file__ not in (ENTRYPOINT, WORKER_ENTRYPOINT)
                or len(sys.argv) != (2 if worker else 1)):
            raise ValueError
        if worker and str(uuid.UUID(sys.argv[1])) != sys.argv[1]:
            raise ValueError
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        # sudo sets SUDO_UID; root is trusted when invoking directly. Capture
        # it before clearing the environment, never from request JSON.
        operator = os.environ.get("SUDO_UID", "0")
        if not operator.isascii() or not operator.isdecimal() or len(operator) > 10:
            raise ValueError
        operator_uid = int(operator)
        if not 0 <= operator_uid < 2**32 - 1:
            raise ValueError
        os.environ.clear()
        os.environ.update({"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        os.chdir("/")
        _verified_installation(INSTALL_ROOT)
        sys.dont_write_bytecode = True
        sys.path.insert(0, INSTALL_ROOT)
        if worker:
            from mpkg_manager.attempt_worker import main as dispatch_worker
            return dispatch_worker(sys.argv[1])
        from mpkg_manager.host_helper import main as dispatch
        return dispatch(operator_uid=operator_uid)
    except BaseException:
        # Never emit a traceback, import error, source path or request value.
        # A nonblocking write also avoids an unresponsive caller retaining root.
        try:
            os.set_blocking(1, False)
            os.write(1, _FAILURE)
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
