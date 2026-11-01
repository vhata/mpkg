#!/usr/bin/env bash
# Argument parsing only, without a login operand and with privileges dropped.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I - <<'PY'
import json
import os
from pathlib import Path
import resource
import selectors
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, read_regular, require_guest
from native_service import trusted_path
from run import ENV, command, trusted_install


def parse_probe(arguments):
    # No login operand, no default-changing -D, and no privilege to create
    # accounts. Upstream 4.20.0 processes -K/--help before account mutation.
    child = subprocess.Popen(['/usr/bin/useradd', *arguments], cwd='/', env=ENV,
                             user=65534, group=65534, extra_groups=[],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outputs = {True: bytearray(), False: bytearray()}
    total = 0
    deadline = time.monotonic() + 10
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, True)
            selector.register(child.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise Refused('diagnostic_useradd_timeout')
                for key, _ in selector.select(0.2):
                    part = os.read(key.fileobj.fileno(), 4096)
                    if not part:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(part)
                    if total > 65536:
                        raise Refused('diagnostic_useradd_output_bound')
                    outputs[key.data].extend(part)
        code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        return {'exit_code': code,
                'help_usage_seen': b'Usage: useradd' in outputs[True],
                'unknown_mail_spool_item': b"configuration error - unknown item 'CREATE_MAIL_SPOOL'" in outputs[False],
                'stderr_present': bool(outputs[False])}
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
guest = require_guest(os.environ['MPKG_GUEST_ID'])
trusted_install()
if command(['/usr/bin/pacman', '-Q', 'shadow']).strip() != b'shadow 4.20.0.arch1-1':
    raise Refused('diagnostic_shadow_version_changed')
binary = Path('/usr/bin/useradd')
info = trusted_path(binary)
if info.st_mode & (stat.S_ISUID | stat.S_ISGID) or 'security.capability' in os.listxattr(binary):
    raise Refused('diagnostic_useradd_privileged_binary')
account_paths = [Path('/etc') / name for name in ('passwd', 'group', 'shadow', 'gshadow', 'subuid', 'subgid')]
def account_metadata():
    return {str(path): (path.lstat().st_ino, path.lstat().st_size, path.lstat().st_mtime_ns)
            if path.exists() else None for path in account_paths}
before = account_metadata()
plain = parse_probe(['--help'])
override = parse_probe(['-K', 'CREATE_MAIL_SPOOL=no', '--help'])
defaults = Path('/etc/default/useradd')
trusted_path(defaults)
raw, _ = read_regular(defaults)
mail = [line.split(b'=', 1)[1].strip() for line in raw.splitlines()
        if line.strip().startswith(b'CREATE_MAIL_SPOOL=')]
print(json.dumps({'schema': 1, 'guest_id': guest, 'diagnostic_only': True,
                  'plain_help': plain, 'mail_spool_override_help': override,
                  'mail_spool_default_present': bool(mail), 'mail_spool_default_exact_no': mail == [b'no'],
                  'account_file_metadata_unchanged': before == account_metadata(),
                  'probe_uid': 65534, 'probe_gid': 65534, 'probe_supplementary_groups': [],
                  'login_operand_supplied': False, 'account_mutation_requested': False}, sort_keys=True))
PY
