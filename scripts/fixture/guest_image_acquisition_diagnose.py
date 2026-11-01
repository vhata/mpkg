#!/usr/bin/env python3
"""Observe the failed metadata acquisition and network state without retrying."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import sqlite3
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, identity, require_guest
from native_service import trusted_path
from run import ENV, command, trusted_install

REPORT_SHA = '2e1ab12cc11766ecbde486cdadbc0ef2c51c10ff6547c17006eb6e891ca9cbd4'
RESOLVERS = ('/etc/resolv.conf', '/run/systemd/resolve/stub-resolv.conf',
             '/run/systemd/resolve/resolv.conf')


def bounded_file(path, maximum=65536, *, trusted=True):
    if trusted:
        trusted_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise Refused('acquisition_diagnostic_file_bound')
        raw = stream.read(maximum + 1)
        if len(raw) > maximum or identity(before) != identity(os.fstat(fd)):
            raise Refused('acquisition_diagnostic_file_changed')
    return raw


def resolver_fields(raw):
    if len(raw) > 16384:
        raise Refused('acquisition_diagnostic_resolver_bound')
    nameservers, other = [], {}
    for line in raw.decode('ascii', errors='strict').splitlines():
        words = line.split('#', 1)[0].split(';', 1)[0].split()
        if not words:
            continue
        if words[0] == 'nameserver' and len(words) == 2:
            nameservers.append(str(ipaddress.ip_address(words[1].split('%', 1)[0])))
        else:
            # Do not emit search domains, comments, or arbitrary file contents.
            key = words[0] if words[0] in {'search', 'domain', 'options', 'sortlist'} else 'other'
            other[key] = other.get(key, 0) + 1
    if len(nameservers) > 16:
        raise Refused('acquisition_diagnostic_resolver_count')
    return {'nameservers': nameservers, 'other_directive_counts': other}


def resolver_observation():
    path = Path('/etc/resolv.conf')
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'present': False, 'status': 'missing'}
    target = os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
    result = {'present': True, 'symlink': target is not None, 'uid': info.st_uid,
              'mode': oct(stat.S_IMODE(info.st_mode))}
    try:
        resolved = str(path.resolve(strict=True))
    except FileNotFoundError:
        return dict(result, status='dangling')
    except (RuntimeError, OSError):
        return dict(result, status='unresolvable')
    result.update(status='observed', allowed_target=resolved in RESOLVERS)
    if resolved not in RESOLVERS:
        return result
    result['resolved_path'] = resolved
    result['files'] = {}
    for candidate in set((resolved, *RESOLVERS[1:])):
        file = Path(candidate)
        if file.exists() and not file.is_symlink():
            raw = bounded_file(file, 16384, trusted=False)
            result['files'][candidate] = dict(resolver_fields(raw), sha256=hashlib.sha256(raw).hexdigest())
    return result


def record_observation(directory, guest):
    trusted_path(directory, directory=True)
    entries = list(directory.iterdir())
    allowed = {'started.json', 'prepared.json', 'capture.json', 'result.json', 'state.sqlite3',
               'stdout.private', 'stderr.private', 'images.attestations.oci.tar'}
    if len(entries) > 16 or any(item.name not in allowed for item in entries):
        raise Refused('acquisition_diagnostic_attempt_shape')
    result = {'present_files': sorted(item.name for item in entries), 'records': {}}
    for name in ('started.json', 'prepared.json', 'capture.json', 'result.json'):
        path = directory/name
        if not path.exists():
            result['records'][name] = {'present': False}
            continue
        raw = bounded_file(path)
        value = json.loads(raw)
        if name != 'capture.json' and (value.get('schema') != 1 or value.get('guest_id') != guest):
            raise Refused('acquisition_diagnostic_record_identity')
        fields = ('attempt', 'engine_id', 'status', 'attempt_terminal', 'platform',
                  'supplement_acquisition_sha256', 'guest_metadata_blob_count',
                  'command_completed', 'capture_status', 'client_exit_code')
        result['records'][name] = {'present': True, 'sha256': hashlib.sha256(raw).hexdigest(),
                                  'bytes': len(raw), 'fields': {key: value[key] for key in fields if key in value}}
    started = json.loads(bounded_file(directory/'started.json'))
    if started.get('supplement_acquisition_sha256') != REPORT_SHA:
        raise Refused('acquisition_diagnostic_report_binding')
    db = directory/'state.sqlite3'
    before = bounded_file(db, 1048576)
    connection = sqlite3.connect(db.as_uri()+'?mode=ro&immutable=1', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        result['journal'] = {
            'sha256': hashlib.sha256(before).hexdigest(),
            'attempt_counts': dict(connection.execute("SELECT COALESCE(terminal,'unknown'),COUNT(*) FROM attempts GROUP BY terminal")),
            'event_counts': dict(connection.execute('SELECT kind,COUNT(*) FROM events GROUP BY kind')),
            'protected_count': connection.execute('SELECT COUNT(*) FROM protected').fetchone()[0],
            'recovery_required': [r[0] for r in connection.execute('SELECT recovery_required FROM store_guard')],
        }
    finally:
        connection.close()
    if bounded_file(db, 1048576) != before:
        raise Refused('acquisition_diagnostic_journal_changed')
    return result


def partial_metadata():
    directory = Path('/opt/mpkg-proof-inputs/oci-supplement')
    result = {'present': directory.exists(), 'files': {}}
    if not result['present']:
        return result
    trusted_path(directory, directory=True)
    if any(p.name not in {'acquisition.json', 'blobs'} for p in directory.iterdir()):
        raise Refused('acquisition_diagnostic_input_shape')
    report = directory/'acquisition.json'
    result['report_present'] = report.exists()
    if report.exists():
        result['report_sha256'] = hashlib.sha256(bounded_file(report)).hexdigest()
    blobs = directory/'blobs/sha256'
    if blobs.exists():
        trusted_path(blobs, directory=True)
        entries = list(blobs.iterdir())
        if len(entries) > 16:
            raise Refused('acquisition_diagnostic_blob_count')
        total = 0
        for path in sorted(entries):
            if not re.fullmatch('[0-9a-f]{64}', path.name):
                raise Refused('acquisition_diagnostic_blob_name')
            raw = bounded_file(path, 16*1024**2)
            total += len(raw)
            if total > 32*1024**2:
                raise Refused('acquisition_diagnostic_total_blob_bound')
            result['files'][path.name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    return result


def fixed_observations():
    env = dict(ENV, SYSTEMD_PAGER='cat', PAGER='cat', SYSTEMD_COLORS='0')
    result = {'units': {}, 'processes': []}
    for unit in ('systemd-networkd.service', 'systemd-resolved.service', 'docker.service',
                 'containerd.service', 'mpkg-fixture-python-build.service',
                 'mpkg-fixture-aur-ack.service', 'mpkg-fixture-aur-gitstatus.service'):
        raw = command(['/usr/bin/systemctl', '--no-pager', '--plain', 'show', unit,
                       '--property=ActiveState,SubState,Result,MainPID,ControlPID'], env=env, timeout=10)
        if len(raw) > 4096:
            raise Refused('acquisition_diagnostic_unit_bound')
        result['units'][unit] = dict(line.split('=', 1) for line in raw.decode().splitlines())
    paths = list(Path('/proc').iterdir())
    if len(paths) > 8192:
        raise Refused('acquisition_diagnostic_process_bound')
    for process in paths:
        if not process.name.isdecimal():
            continue
        try:
            comm = (process/'comm').read_text()[:64].strip()
            if comm in {'docker', 'python3.12', 'curl', 'wget'} or process.stat().st_uid == 1502:
                result['processes'].append({'pid': int(process.name), 'comm': comm,
                                             'is_this_collector': int(process.name) == os.getpid()})
        except (FileNotFoundError, ProcessLookupError):
            continue
    if len(result['processes']) > 64:
        raise Refused('acquisition_diagnostic_process_output_bound')
    for kind, argv in (('addresses', ['address', 'show']), ('routes', ['route', 'show'])):
        raw = command(['/usr/bin/ip', '-j', *argv], env=env, timeout=10)
        if len(raw) > 32768:
            raise Refused('acquisition_diagnostic_network_bound')
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) > 32:
            raise Refused('acquisition_diagnostic_network_count')
        if kind == 'routes':
            result[kind] = [{key: item[key] for key in ('dst', 'gateway', 'dev', 'protocol', 'scope', 'prefsrc') if key in item}
                            for item in values]
        else:
            result[kind] = [{'ifname': item.get('ifname'), 'operstate': item.get('operstate'),
                             'addresses': [{key: addr[key] for key in ('family', 'local', 'prefixlen', 'scope') if key in addr}
                                           for addr in item.get('addr_info', [])]} for item in values]
    # Effective DNS servers only: no network request, domain/search output, or secret settings.
    raw = command(['/usr/bin/resolvectl', '--no-pager', 'dns'], env=env, timeout=10)
    if len(raw) > 16384:
        raise Refused('acquisition_diagnostic_dns_bound')
    servers = []
    for line in raw.decode().splitlines():
        if ': ' not in line:
            continue
        for word in line.split(': ', 1)[1].split():
            try:
                servers.append(str(ipaddress.ip_address(word.split('%', 1)[0])))
            except ValueError:
                continue
    result['effective_dns_servers'] = sorted(set(servers))
    return result


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    result = {'schema': 1, 'guest_id': guest, 'read_only': True, 'network_requests': False,
              'attempt': record_observation(Path('/var/lib/mpkg-proofs')/guest/'image-attestation-preparation', guest),
              'partial_metadata': partial_metadata(), 'resolver': resolver_observation(),
              'live': fixed_observations(),
              'limits': ['A request deadline alone does not identify DNS as its cause.',
                         'No acquisition, load, resolver change, retry, or service action was requested.']}
    output = json.dumps(result, sort_keys=True)
    if len(output.encode()) > 15000:
        raise Refused('acquisition_diagnostic_combined_bound')
    print(output)


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, sqlite3.Error) as error:
        print(json.dumps({'status': 'unverified', 'code': str(error) if isinstance(error, Refused)
                          else 'acquisition_diagnostic_failed', 'exception': type(error).__name__}))
        raise SystemExit(74)
