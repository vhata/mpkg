#!/usr/bin/env bash
# Read-only diagnosis of the fixed failed volume-keep credential check.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I - "$MPKG_GUEST_ID" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import sqlite3
import stat
import sys
import time

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, read_regular, require_guest
from docker_diagnostic_resume import ENGINE
from docker_variant_plan import VOLUME, variant_plan
from native_manifest import trusted_json
from native_service import trusted_path
from run import ENV, command, trusted_install

FORMAT = ('{"Id":{{json .Id}},"Image":{{json .Image}},"ConfiguredImage":{{json .Config.Image}},'
          '"Project":{{json (index .Config.Labels "com.docker.compose.project")}},'
          '"Service":{{json (index .Config.Labels "com.docker.compose.service")}},'
          '"Running":{{json .State.Running}},"Pid":{{json .State.Pid}},'
          '"StartedAt":{{json .State.StartedAt}},"Mounts":{{json .Mounts}}}')


def metadata(info):
    return {'directory': stat.S_ISDIR(info.st_mode), 'regular': stat.S_ISREG(info.st_mode),
            'symlink': stat.S_ISLNK(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': oct(stat.S_IMODE(info.st_mode)), 'links': info.st_nlink,
            'size': info.st_size, 'device': info.st_dev, 'inode': info.st_ino}


def predicates(config, sentinel, database, *, xattr_count, sentinel_matches):
    return {'config_metadata': config['directory'] and (config['uid'], config['gid'], config['mode']) == (963, 1001, '0o2770'),
            'config_xattrs_empty': xattr_count == 0,
            'sentinel_metadata': sentinel['regular'] and sentinel['links'] == 1
                and (sentinel['uid'], sentinel['gid'], sentinel['mode']) == (963, 1001, '0o640'),
            'sentinel_content_matches': sentinel_matches,
            'database_metadata': database['regular'] and database['links'] == 1
                and (database['uid'], database['gid']) == (963, 1001)
                and database['size'] > 0 and not int(database['mode'], 8) & 0o002}


def child_probe(root_fd, namespace_fd, namespace_inode, credentials, expected, role):
    stage, result = 'open_own_namespace_directory', {}
    try:
        own_namespaces = os.open('/proc/self/ns', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        stage = 'enter_mount_namespace'
        os.setns(namespace_fd, os.CLONE_NEWNS)
        stage = 'verify_entered_mount_namespace'
        try:
            result['original_namespace_check'] = {'query_succeeded': True,
                'matches': os.stat('/proc/self/ns/mnt').st_ino == namespace_inode}
        except OSError as error:
            result['original_namespace_check'] = {'query_succeeded': False, 'errno': error.errno}
        # Hold the host procfs view before entering the target mount namespace.
        # This remains read-only even when the target /proc hides this PID.
        result['mount_namespace_matches'] = os.stat('mnt', dir_fd=own_namespaces).st_ino == namespace_inode
        if not result['mount_namespace_matches']:
            raise Refused('namespace_changed')
        stage = 'enter_held_root'
        os.fchdir(root_fd)
        os.chroot('.')
        os.chdir('/')
        stage = 'drop_credentials'
        os.setgroups(credentials['groups'])
        os.setgid(1001)
        os.setuid(963)
        result['copied_credentials'] = {'uids': os.getresuid(), 'gids': os.getresgid(), 'groups': os.getgroups()}
        stage = 'open_config_directory'
        config_fd = os.open('/config', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        result['config'] = metadata(os.fstat(config_fd))
        stage = 'config_xattrs'
        names = os.listxattr('/config')
        result['xattrs'] = {'count': len(names), 'posix_access_acl': 'system.posix_acl_access' in names,
                           'posix_default_acl': 'system.posix_acl_default' in names,
                           'selinux': 'security.selinux' in names}
        stage = 'stat_xml_metadata_only'
        result['xml'] = metadata(os.stat('config.xml', dir_fd=config_fd, follow_symlinks=False))
        stage = 'open_synthetic_sentinel'
        sentinel_fd = os.open('mpkg-fixture-sentinel', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=config_fd)
        result['sentinel'] = metadata(os.fstat(sentinel_fd))
        stage = 'read_synthetic_sentinel'
        result['sentinel_content_matches'] = (result['sentinel']['regular'] and result['sentinel']['links'] == 1
            and result['sentinel']['size'] <= 4096 and os.read(sentinel_fd, 4097) == expected)
        stage = 'stat_database_metadata_only'
        result['database'] = metadata(os.stat(role + '.db', dir_fd=config_fd, follow_symlinks=False))
        result['predicates'] = predicates(result['config'], result['sentinel'], result['database'],
                                         xattr_count=len(names), sentinel_matches=result['sentinel_content_matches'])
        result['first_false_predicate'] = next((name for name, value in result['predicates'].items() if not value), None)
        result['original_check_would_stop'] = (result['first_false_predicate']
            if result['original_namespace_check'].get('matches') is True else 'mount_namespace_observation')
        result['stage'] = 'complete'
    except Exception as error:
        result.update(stage=stage, failed=True, error_kind='os_error' if isinstance(error, OSError) else 'refused_or_unverified',
                      errno=error.errno if isinstance(error, OSError) else None)
    return result


def copied_probe(root_fd, namespace_fd, namespace_inode, credentials, expected, role):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        result = child_probe(root_fd, namespace_fd, namespace_inode, credentials, expected, role)
        raw = json.dumps(result, sort_keys=True).encode()
        if len(raw) <= 16384:
            while raw:
                raw = raw[os.write(write_fd, raw):]
        os._exit(0)
    os.close(write_fd)
    deadline, output, waited = time.monotonic() + 5, bytearray(), False
    try:
        os.set_blocking(read_fd, False)
        with selectors.DefaultSelector() as selector:
            selector.register(read_fd, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                for _, _ in selector.select(min(0.05, deadline - time.monotonic())):
                    raw = os.read(read_fd, 16385)
                    output.extend(raw)
                    if len(output) > 16384:
                        raise Refused('volume_diagnostic_child_output_bound')
                finished, status = os.waitpid(child, os.WNOHANG)
                if finished:
                    waited = True
                    while True:
                        raw = os.read(read_fd, 16385)
                        if not raw:
                            break
                        output.extend(raw)
                        if len(output) > 16384:
                            raise Refused('volume_diagnostic_child_output_bound')
                    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                        raise Refused('volume_diagnostic_child_failed')
                    return json.loads(output)
        raise Refused('volume_diagnostic_child_timeout')
    finally:
        os.close(read_fd)
        if not waited:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)


def process_facts(pid):
    root = Path('/proc') / str(pid)
    raw = (root / 'status').read_bytes()
    if len(raw) > 65536:
        raise Refused('volume_diagnostic_process_bound')
    values = dict((key, value.strip()) for line in raw.decode().splitlines()
                  for key, separator, value in [line.partition(':')] if separator)
    result = {'pid': pid, 'uids': [int(item) for item in values['Uid'].split()],
              'gids': [int(item) for item in values['Gid'].split()],
              'groups': [int(item) for item in values['Groups'].split()],
              'capabilities': {key: values[key] for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')},
              'namespaces': {name: os.stat(root / 'ns' / name).st_ino for name in ('mnt', 'net', 'user')},
              'start_ticks': (root / 'stat').read_bytes().rsplit(b')', 1)[1].split()[19].decode(),
              'identity_maps': {name: [[int(item) for item in line.split()] for line in (root / name).read_text().splitlines()]
                                for name in ('uid_map', 'gid_map')}}
    if (len(result['groups']) > 128 or any(not re.fullmatch('[0-9a-f]{16}', item) for item in result['capabilities'].values())
            or any(len(value) != 4 for value in (result['uids'], result['gids']))):
        raise Refused('volume_diagnostic_process_shape')
    return result


def journal_summary(root):
    path = root / 'state.sqlite3'
    trusted_path(path)
    if any(Path(str(path) + suffix).exists() for suffix in ('-wal', '-journal', '-shm')):
        raise Refused('volume_diagnostic_journal_sidecar_present')
    before = read_regular(path)[0]
    database = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True, timeout=1)
    try:
        database.execute('PRAGMA query_only=ON')
        attempts = database.execute('SELECT terminal,COUNT(*) FROM attempts GROUP BY terminal').fetchall()
        events = database.execute('SELECT kind,COUNT(*) FROM events GROUP BY kind').fetchall()
        if any(name not in (None, 'observed-complete', 'failed', 'unverified') for name, _ in attempts) or any(
                name not in ('started', 'observed-complete', 'failed', 'unverified') for name, _ in events):
            raise Refused('volume_diagnostic_journal_shape')
        recovery = database.execute('SELECT recovery_required FROM store_guard').fetchall()
        if recovery not in ([(0,)], [(1,)]):
            raise Refused('volume_diagnostic_recovery_guard_shape')
        result = {'attempts': {name or 'unknown': count for name, count in attempts}, 'events': dict(events),
                  'protected_count': database.execute('SELECT COUNT(*) FROM protected').fetchone()[0],
                  'recovery_required': recovery[0][0],
                  'sha256': hashlib.sha256(before).hexdigest()}
    finally:
        database.close()
    return result, before


def main():
    guest = require_guest(sys.argv[1])
    trusted_install()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Refused('volume_diagnostic_deadline')))
    signal.alarm(120)
    root = Path('/var/lib/mpkg-proofs') / guest / 'docker-variant-volume-keep'
    trusted_path(root, directory=True)
    client = root / 'docker-client'
    trusted_path(client, directory=True)
    environment = dict(ENV, DOCKER_CONFIG=str(client))
    def docker(*arguments):
        return command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments], env=environment, timeout=15)
    if docker('info', '--format', '{{.ID}}').decode().strip() != ENGINE:
        raise Refused('volume_diagnostic_engine_changed')
    manifest, _ = trusted_json('compose.json')
    if manifest.get('guest_id') != guest or manifest.get('engine_id') != ENGINE:
        raise Refused('volume_diagnostic_manifest_changed')
    images = {item['reference']: item['image_id'] for item in manifest['images']}
    journal, before_database = journal_summary(root)
    protected_paths = ('baseline.json', 'sonarr-assembled.xml', 'radarr-assembled.xml')
    before_files = {}
    stages = {}
    for name in protected_paths:
        path = root / name
        if path.is_symlink():
            raise Refused('volume_diagnostic_state_symlink')
        if path.exists():
            trusted_path(path)
            stages[name] = metadata(path.lstat())
            if name == 'baseline.json':
                raw, _ = read_regular(path)
                before_files[path] = raw
                stages[name]['sha256'] = hashlib.sha256(raw).hexdigest()
        else:
            stages[name] = {'present': False}
    plan, applications = variant_plan('volume-keep'), {}
    for role, spec in plan['applications'].items():
        identifiers = docker('ps', '--all', '--quiet', '--no-trunc', '--filter',
                             'label=com.docker.compose.project=' + spec['project']).decode().splitlines()
        if len(identifiers) != 1 or not re.fullmatch('[0-9a-f]{64}', identifiers[0]):
            raise Refused('volume_diagnostic_container_scope')
        value = json.loads(docker('inspect', '--format', FORMAT, identifiers[0]))
        if (value['Id'] != identifiers[0] or value['Image'] != images[spec['image']]
                or value['ConfiguredImage'] != spec['image'] or value['Project'] != spec['project'] or value['Service'] != role):
            raise Refused('volume_diagnostic_container_binding_changed')
        mounts = value.pop('Mounts')
        config = [item for item in mounts if item.get('Destination') == '/config']
        if len(mounts) != 2 or len(config) != 1:
            raise Refused('volume_diagnostic_mount_scope')
        config = config[0]
        expected_mount = (config.get('Type') == 'volume' and config.get('Name') == VOLUME and config.get('Driver') == 'local'
                          if role == 'sonarr' else config.get('Type') == 'bind' and config.get('Source') == '/opt/docker/radarr/config')
        value['config_mount'] = {'matches_declared': expected_mount, 'rw': config.get('RW') is True}
        if not expected_mount or not value['config_mount']['rw'] or value['Running'] is not True:
            raise Refused('volume_diagnostic_config_mount_changed')
        rows = docker('top', value['Id'], '-eo', 'pid,comm').decode().splitlines()[1:]
        pids = [int(row.split()[0]) for row in rows if len(row.split()) == 2
                and row.split()[0].isdigit() and row.split()[1] == spec['process']]
        if len(pids) != 1:
            raise Refused('volume_diagnostic_application_process_scope')
        facts = process_facts(pids[0])
        value['process'] = facts
        eligible = facts['uids'] == [963] * 4 and facts['gids'] == [1001] * 4 and int(facts['capabilities']['CapEff'], 16) == 0
        eligible = eligible and all(item == [[0, 0, 4294967295]] for item in facts['identity_maps'].values())
        value['copied_probe_eligible'] = eligible
        if eligible:
            namespace = os.open('/proc/' + str(pids[0]) + '/ns/mnt', os.O_RDONLY | os.O_CLOEXEC)
            descriptor = os.open('/proc/' + str(pids[0]) + '/root', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                held = os.fstat(descriptor)
                if os.fstat(namespace).st_ino != facts['namespaces']['mnt'] or process_facts(pids[0]) != facts:
                    raise Refused('volume_diagnostic_process_changed_before_probe')
                value['copied_probe'] = copied_probe(descriptor, namespace, facts['namespaces']['mnt'], facts,
                    ('mpkg fixture ' + guest + ' ' + role + ' config\n').encode(), role)
                if process_facts(pids[0]) != facts or (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (held.st_dev, held.st_ino):
                    raise Refused('volume_diagnostic_process_changed_during_probe')
            finally:
                os.close(descriptor)
                os.close(namespace)
        after = json.loads(docker('inspect', '--format', FORMAT, value['Id']))
        if any(after[key] != value[key] for key in ('Id', 'Image', 'Running', 'Pid', 'StartedAt')):
            raise Refused('volume_diagnostic_container_changed')
        applications[role] = value
    volumes = docker('volume', 'ls', '--quiet').decode().splitlines()
    containers = docker('ps', '--all', '--quiet', '--no-trunc').decode().splitlines()
    if (docker('info', '--format', '{{.ID}}').decode().strip() != ENGINE
            or read_regular(root / 'state.sqlite3')[0] != before_database
            or any(read_regular(path)[0] != raw for path, raw in before_files.items())):
        raise Refused('volume_diagnostic_prior_state_changed')
    print(json.dumps({'schema': 1, 'guest_id': guest, 'status': 'observed', 'diagnostic_only': True,
        'engine_id': ENGINE, 'journal': journal, 'stages': stages, 'applications': applications,
        'only_declared_containers': set(containers) == {value['Id'] for value in applications.values()},
        'only_declared_volume': volumes == [VOLUME], 'prior_records_unchanged': True,
        'product_acceptance': False, 'xml_files_opened': False, 'credential_values_emitted': False,
        'application_requests': False}, sort_keys=True))


try:
    main()
except Exception:
    print('{"status":"unverified","code":"volume_keep_diagnostic_failed","product_acceptance":false}')
    sys.exit(73)
PY
