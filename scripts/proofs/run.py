#!/usr/bin/env python3
"""Run only reviewed, fixed experiments inside the identified disposable VM."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import selectors
import resource
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

# Isolated Python excludes even the script directory. Add this explicit path,
# never the caller's working directory or a path obtained from its environment.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, private_directory, require_guest, write_new


INSTALL = Path('/opt/mpkg-proofs')
CASES = ('before-start', 'after-start', 'after-effect', 'completion-failure',
         'complete', 'supervised', 'orphan', 'daemon')
PROOFS = ('journal', 'inputs', 'xml', 'retirement', 'supervision', 'compose', 'native')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'}


def command(argv, timeout=30, *, cwd=None, env=None, pass_fds=()):
    """Keep raw tool diagnostics private and never inherit stdout/stderr."""
    child = subprocess.Popen(argv, cwd=cwd, env=env or ENV, pass_fds=pass_fds,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = bytearray()
    total = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, True)
            selector.register(child.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refused('tool_timeout_external_work_unknown')
                for key, _ in selector.select(min(remaining, 0.5)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > 4 * 1024 * 1024:
                        raise Refused('tool_output_bound_external_work_unknown')
                    if key.data:
                        output.extend(chunk)
        child.wait(timeout=max(0.01, deadline - time.monotonic()))
        if child.returncode:
            raise Refused('fixed_tool_failed')
        return bytes(output)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


def trusted_install():
    if Path(__file__).resolve() != INSTALL / 'run.py':
        raise Refused('installed_guest_copy_required')
    for path in [INSTALL, *INSTALL.glob('*.py')]:
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise Refused('installed_code_not_trusted')


def case_root(root, case):
    if case not in CASES:
        raise Refused('case_unsupported')
    return private_directory(root / case)


def worker(root, case, attempt):
    directory = case_root(root, case)
    lock = os.open(directory / 'apply.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                   0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused('execution_locked') from None
        journal = Journal(directory)
        try:
            if case == 'before-start':
                journal.db.execute('PRAGMA query_only=ON')
            journal.begin(attempt)
            if case == 'daemon':
                from compose_proof import SONARR
                client = private_directory(directory / 'docker-client')
                command(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock',
                         'run', '--detach', '--pull=never', '--network=none',
                         '--name', 'mpkg-proof-' + root.name[:8] + '-daemon',
                         '--label', 'mpkg.proof=' + root.name,
                         '--entrypoint=/bin/sleep', SONARR, '60'],
                        env=dict(ENV, DOCKER_CONFIG=str(client)))
                os.kill(os.getpid(), signal.SIGKILL)
            if case == 'after-start':
                os._exit(71)
            if case in ('supervised', 'orphan'):
                write_new(directory / 'worker-started', b'started')
                if case == 'orphan':
                    child = os.fork()
                    if child == 0:
                        # Keep the worker's lock while this native child survives.
                        time.sleep(8)
                        write_new(directory / 'child-effect', b'completed')
                        os._exit(0)
                    write_new(directory / 'child-pid', str(child).encode())
                    os.kill(os.getpid(), signal.SIGKILL)
                deadline = time.monotonic() + 45
                while not (directory / 'release').exists():
                    if time.monotonic() >= deadline:
                        raise Refused('worker_release_timeout')
                    time.sleep(0.1)
            write_new(directory / 'effect', b'effect')
            if case == 'after-effect':
                os._exit(72)
            if case == 'completion-failure':
                journal.db.execute('PRAGMA query_only=ON')
            journal.finish(attempt, 'observed-complete')
        finally:
            journal.close()
    finally:
        os.close(lock)


def launch(guest, root, case, attempt):
    if case not in ('supervised', 'orphan'):
        raise Refused('supervision_case_required')
    unit = 'mpkg-proof-' + str(uuid.UUID(attempt)) + '.service'
    command([
        '/usr/bin/systemd-run', '--quiet', '--unit=' + unit,
        '--service-type=exec', '--property=ExitType=cgroup',
        '--property=KillMode=control-group', '--property=Restart=no',
        '--property=RemainAfterExit=yes', '--property=LimitCORE=0',
        '--property=StandardOutput=null', '--property=StandardError=null',
        sys.executable, '-I', str(INSTALL / 'run.py'), 'worker',
        '--guest-id', guest, '--case', case, '--attempt', attempt,
    ])
    # The proof kills this initiating CLI while the manager-owned unit continues.
    time.sleep(60)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('verb', choices=('run', 'worker', 'launch'))
    parser.add_argument('--guest-id', required=True)
    parser.add_argument('--proof', choices=PROOFS)
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--attempt')
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    root = private_directory(Path('/var/lib/mpkg-proofs') / guest)
    if args.verb in ('worker', 'launch'):
        if not args.case or not args.attempt:
            raise Refused('worker_arguments_required')
        if str(uuid.UUID(args.attempt)) != args.attempt:
            raise Refused('attempt_identity_invalid')
        if args.verb == 'worker':
            worker(root, args.case, args.attempt)
        else:
            launch(guest, root, args.case, args.attempt)
        return
    if not args.proof:
        raise Refused('proof_required')
    import experiments
    result = getattr(experiments, 'prove_' + args.proof)(guest, root)
    result.update({'schema': 1, 'proof': args.proof,
                   'guest_id': guest, 'product_acceptance': False})
    write_new(root / (args.proof + '-result.json'),
              json.dumps(result, sort_keys=True).encode() + b'\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error),
                          'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'operation_failed',
                          'product_acceptance': False}))
        sys.exit(74)
