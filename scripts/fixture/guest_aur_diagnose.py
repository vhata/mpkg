#!/usr/bin/env python3
"""Read bounded public build, test and process evidence from the AUR fixture job."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, require_guest

STATE = Path('/var/lib/mpkg-fixture/aur-ack')
INPUTS = Path('/opt/mpkg-proof-inputs')
ENV = {'PATH': '/usr/bin', 'LC_ALL': 'C', 'HOME': '/root',
       'SYSTEMD_PAGER': 'cat', 'SYSTEMD_COLORS': '0'}


def read(path, maximum=65536, tail=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise Refused('untrusted_diagnostic_file')
        if tail:
            stream.seek(max(0, info.st_size-maximum))
        elif info.st_size > maximum:
            raise Refused('diagnostic_file_bound')
        return stream.read(maximum)


def command(arguments, allow_empty=False):
    result = subprocess.run(arguments, env=ENV, timeout=15, capture_output=True)
    if result.returncode not in ((0, 1) if allow_empty else (0,)) or len(result.stdout) > 65536:
        raise Refused('diagnostic_command_failed_or_exceeded_bound')
    return result.stdout.decode(errors='replace')


def test_lines(raw, prefix_omitted=False):
    lines = raw.decode(errors='replace').splitlines()
    if prefix_omitted:
        lines = lines[1:]  # The first line may start in the middle of a record.
    summary = re.compile(r'^(?:All tests successful[.]|Files=\d+, Tests=\d+,.*|Result: (?:PASS|FAIL|NOTESTS))$')
    skipped = re.compile(r'^\S+\.t\s+.*\bskipped\b.*$', re.IGNORECASE)
    matches = [{'window_line': number, 'text': line[:256], 'line_truncated': len(line) > 256}
               for number, line in enumerate(lines, 1) if summary.fullmatch(line) or skipped.fullmatch(line)]
    retained = []
    size = 0
    for item in reversed(matches[-24:]):
        if size + len(item['text'].encode()) > 4096:
            break
        retained.insert(0, item)
        size += len(item['text'].encode())
    return {'matched_lines_in_window': len(matches), 'lines': retained,
            'matching_lines_omitted': len(matches) - len(retained),
            'claim': 'observed upstream output; skipped tests are not covered'}


def build_log_evidence():
    fd = os.open(STATE/'build.log', os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or before.st_mode & 0o022):
            raise Refused('untrusted_diagnostic_log')
        offset = max(0, before.st_size - 1024*1024)
        stream.seek(offset)
        raw = stream.read(min(before.st_size, 1024*1024))
        after = os.fstat(stream.fileno())
    evidence = test_lines(raw, prefix_omitted=bool(offset))
    evidence.update({'file_bytes_at_open': before.st_size, 'read_bytes': len(raw),
                     'prefix_omitted_bytes': offset,
                     'changed_during_read': (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                     != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)})
    return evidence, raw[-4096:].decode(errors='replace').splitlines()[-35:]


def main():
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    source_bytes = read(INPUTS/'source-inventory.json', maximum=1024*1024)
    if hashlib.sha256(source_bytes).hexdigest() != 'c4713eff10cd435487a043a093e02bc596e88a10853e2d6e8ae7d3e384418c30':
        raise Refused('frozen_source_inventory_changed')
    source = json.loads(source_bytes)
    raw = command(['/usr/bin/systemctl', '--no-pager', '--plain', 'show',
                   '--property=ActiveState,SubState,Result,ExecMainStatus,MainPID,ControlPID,ControlGroup,TasksCurrent',
                   'mpkg-fixture-aur-ack.service'])
    manager = dict(line.split('=', 1) for line in raw.splitlines())
    metadata = {}
    builds = {}
    for name in ('perl-file-next', 'ack'):
        recipe = next(p for p in source['aur_packages'] if p['package_base'] == name)
        pinned = read(INPUTS/'sources'/name/'.SRCINFO')
        if hashlib.sha256(pinned).hexdigest() != recipe['recipe_files']['.SRCINFO']['sha256_computed']:
            raise Refused('pinned_srcinfo_changed')
        generated_path = STATE/(name+'-generated.SRCINFO')
        if generated_path.exists():
            generated = read(generated_path)
            normalized = lambda value: sorted(line.strip() for line in value.decode().splitlines()
                                             if line.strip() and not line.lstrip().startswith('#'))
            left, right = normalized(pinned), normalized(generated)
            metadata[name] = {'pinned_sha256': hashlib.sha256(pinned).hexdigest(),
                              'generated_sha256': hashlib.sha256(generated).hexdigest(),
                              'normalized_equal': left == right,
                              'only_in_pinned': sorted(set(left)-set(right)),
                              'only_in_generated': sorted(set(right)-set(left)),
                              'unified_diff': ''.join(difflib.unified_diff(
                                  pinned.decode().splitlines(True), generated.decode().splitlines(True),
                                  fromfile=name+'/.SRCINFO', tofile=name+'-generated.SRCINFO'))}
        else:
            metadata[name] = {'generated': 'absent'}
        record_path = INPUTS/(name+'-build.json')
        if record_path.exists():
            record = read(record_path)
            builds[name] = {'sha256': hashlib.sha256(record).hexdigest(), 'record': json.loads(record)}
        else:
            builds[name] = {'record': 'absent'}
    inventory_raw = command(['/usr/bin/pacman', '-Q'])
    inventory = dict(line.split() for line in inventory_raw.splitlines())
    explicit = set(command(['/usr/bin/pacman', '-Qqe']).splitlines())
    baseline_names = set(source['resolutions']['native_change']['resolved_package_names'])
    baseline = {p['name']: p['version'] for p in source['repository_packages'] if p['name'] in baseline_names}
    cgroup = Path('/sys/fs/cgroup/system.slice/mpkg-fixture-aur-ack.service')
    tasks = []
    if (cgroup/'cgroup.procs').exists():
        with (cgroup/'cgroup.procs').open() as stream:
            pids = stream.read(4096).splitlines()[:32]
        for pid in pids:
            if not pid.isdecimal():
                raise Refused('unexpected_cgroup_pid')
            try:
                tasks.append({'pid': int(pid), 'comm': Path('/proc', pid, 'comm').read_text()[:64].strip(),
                              'wchan': Path('/proc', pid, 'wchan').read_text()[:64].strip()})
            except FileNotFoundError:
                continue
    test_evidence, log_tail = build_log_evidence()
    result = {'schema': 1, 'guest_id': guest, 'read_only': True, 'manager': manager,
              'cgroup_tasks': tasks, 'builder_processes_pid_comm_wchan': command(
                  ['/usr/bin/ps', '-u', '1502', '-o', 'pid=,comm=,wchan='], allow_empty=True).splitlines()[:32],
              'metadata': metadata, 'completed_build_records': builds,
              'installed_package_count': len(inventory),
              'installed_inventory_sha256': hashlib.sha256(inventory_raw.encode()).hexdigest(),
              'missing_baseline_packages': sorted(baseline.keys()-inventory.keys()),
              'changed_baseline_versions': {n: inventory[n] for n in baseline.keys() & inventory.keys() if baseline[n] != inventory[n]},
              'extra_installed_packages': {n: {'version': inventory[n], 'reason': 'explicit' if n in explicit else 'dependency'}
                                           for n in inventory.keys()-baseline.keys()},
              'exit': read(STATE/'exit', maximum=16).decode().strip() if (STATE/'exit').exists() else 'absent',
              'complete': read(STATE/'complete', maximum=128).decode().strip() if (STATE/'complete').exists() else 'absent',
              'upstream_test_output': test_evidence, 'build_log_tail': log_tail}
    output = json.dumps(result, indent=2, sort_keys=True)
    if len(output.encode()) > 15000:
        raise Refused('combined_diagnostic_output_bound')
    print(output)


if __name__ == '__main__':
    main()
