#!/usr/bin/env python3
"""Assemble/check the running Docker adoption fixture, without product history."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import socket
import stat
import sys
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compose_proof import (CONFIG_DIGESTS, RADARR, SONARR, NoRedirect, bounded_request,
                           config_xml, covering_listeners)
from core import Journal, Refused, canonical, ping_ok, private_directory, read_regular, require_guest, write_new
from docker_ready import assert_unit, process_identity, properties, socket_identity
from image_import import validate_acquisition
from native_manifest import trusted_json
from native_service import identity as native_identity, trusted_path
from run import ENV, command, trusted_install
from account_defaults import require_mail_defaults, useradd_arguments


BASE = Path('/opt/docker')
MEDIA = Path('/mnt/media')
SHARED = MEDIA / 'mpkg-fixture-shared'
RADARR_ROOT = SHARED / 'radarr-root'
SENTINEL = RADARR_ROOT / 'Mpkg Sentinel (2000)'
SPECS = {'sonarr': {'project': 'mpkg-fixture-sonarr', 'port': 18989, 'process': 'Sonarr', 'image': SONARR},
         'radarr': {'project': 'mpkg-fixture-radarr', 'port': 17878, 'process': 'Radarr', 'image': RADARR}}


def metadata(path, uid, gid, mode, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != mode or os.listxattr(path)
            or (not directory and info.st_nlink != 1)):
        raise Refused('docker_fixture_metadata_mismatch')
    return {'path': str(path), 'uid': uid, 'gid': gid, 'mode': oct(mode), 'xattrs': []}


def make_directory(path, uid, gid, mode):
    path.mkdir(mode=0o700)
    os.chown(path, uid, gid)
    path.chmod(mode)


def make_file(path, raw, uid, gid, mode):
    write_new(path, raw)
    os.chown(path, uid, gid)
    path.chmod(mode)


def assert_compose_account():
    user, group = pwd.getpwnam('compose'), grp.getgrnam('compose')
    if (user.pw_uid != 963 or user.pw_gid != 962 or group.gr_gid != 962
            or user.pw_dir != str(BASE) or sorted(os.getgrouplist('compose', 962)) != [962, 1001]
            or grp.getgrnam('media').gr_gid != 1001):
        raise Refused('docker_fixture_owner_mismatch')


def xml_values(raw):
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise Refused('docker_fixture_xml_declaration')
    root = ET.fromstring(raw)
    if root.tag != 'Config' or len({child.tag for child in root}) != len(root):
        raise Refused('docker_fixture_xml_structure')
    if any(list(child) for child in root):
        raise Refused('docker_fixture_xml_structure')
    return {child.tag: child.text or '' for child in root}


def preserve_initial_values(initial, current):
    expected, observed = xml_values(initial), xml_values(current)
    if any(observed.get(key) != value for key, value in expected.items()):
        raise Refused('docker_fixture_protected_or_unmanaged_xml_changed')
    return observed


def validate_shared_response(code, data, root_id):
    if (code != 200 or data.get('id') != root_id or data.get('path') != str(RADARR_ROOT)
            or data.get('accessible') is not True
            or not any(item.get('name') == SENTINEL.name and item.get('path') == str(SENTINEL)
                       for item in (data.get('unmappedFolders') or []))):
        raise Refused('docker_fixture_unmanaged_shared_check_failed')


def read_as_application(path, expected, credentials):
    """A copied-credential read is supplemental; Radarr supplies the real app check."""
    child = os.fork()
    if child == 0:
        try:
            os.setgroups(credentials['groups'])
            os.setgid(1001)
            os.setuid(963)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                raw = os.read(fd, 4097)
            finally:
                os.close(fd)
            os._exit(0 if raw == expected else 1)
        except Exception:
            os._exit(1)
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline:
            finished, status = os.waitpid(child, os.WNOHANG)
            if finished:
                child = None
                if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                    raise Refused('docker_fixture_credential_read_failed')
                return
            time.sleep(0.01)
        raise Refused('docker_fixture_credential_read_timeout')
    finally:
        if child is not None:
            os.kill(child, 9)
            os.waitpid(child, 0)


class Baseline:
    def __init__(self, guest, setup=False):
        self.guest = guest
        self.root = Path('/var/lib/mpkg-proofs') / guest / 'docker-baseline'
        if setup and self.root.exists():
            raise Refused('docker_baseline_requires_fresh_attempt')
        if not setup and not self.root.is_dir():
            raise Refused('docker_baseline_not_assembled')
        private_directory(self.root)
        self.client = private_directory(self.root / 'docker-client')
        self.environment = dict(ENV, DOCKER_CONFIG=str(self.client))
        self.journal = Journal(self.root)
        self.image_manifest, _ = trusted_json('compose.json')
        if (self.image_manifest.get('schema') != 1 or self.image_manifest.get('guest_id') != guest):
            raise Refused('docker_baseline_engine_binding_missing')
        acquisition, _ = trusted_json('acquisition.json')
        validate_acquisition(acquisition)
        # Acquisition includes two Sonarr versions. Select by the actual fixed
        # index rather than by list order or an assumed fixture-name spelling.
        self.acquired = {spec['image'].split('@')[0]: next(
            item for item in acquisition['images'] if item['repository'] == spec['image'].split('@')[0]
            and item['index_digest'] == spec['image'].split('@')[1]) for spec in SPECS.values()}

    def docker(self, *arguments, timeout=30):
        return command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments],
                       env=self.environment, timeout=timeout)

    def engine(self, enabled):
        raw, _ = read_regular(self.root.parent / 'docker-readiness' / 'result.json')
        readiness = json.loads(raw)
        if (readiness.get('status') != 'observed' or readiness.get('guest_id') != self.guest
                or readiness.get('engine_id') != self.image_manifest.get('engine_id')
                or set(readiness.get('packages_and_units', {})) != {'docker.service', 'docker.socket', 'containerd.service'}):
            raise Refused('docker_baseline_readiness_binding_missing')
        for unit, record in readiness['packages_and_units'].items():
            raw, _ = read_regular(Path('/usr/lib/systemd/system') / unit)
            if hashlib.sha256(raw).hexdigest() != record['unit_sha256']:
                raise Refused('docker_baseline_unit_drift')
        manager = properties('docker.service')
        containerd = properties('containerd.service')
        assert_unit('containerd.service', containerd, started=True)
        assert_unit('docker.socket', properties('docker.socket'), started=True)
        process_identity(containerd, '/usr/bin/containerd')
        expected_start = '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock'
        if (manager.get('ActiveState') != 'active' or manager.get('SubState') != 'running'
                or manager.get('UnitFileState') != ('enabled' if enabled else 'disabled')
                or manager.get('FragmentPath') != '/usr/lib/systemd/system/docker.service'
                or manager.get('DropInPaths') != '/etc/systemd/system/docker.service.d/50-mpkg-fixture.conf'
                or manager.get('LimitCORE') != '0'
                or any(manager.get(key) != '' for key in ('Environment', 'EnvironmentFiles', 'PassEnvironment'))
                or not manager.get('ExecStart', '').startswith(
                    '{ path=/usr/bin/dockerd ; argv[]=' + expected_start + ' ; ignore_errors=no ;')
                or manager.get('ExecStart', '').count('{') != 1):
            raise Refused('docker_baseline_daemon_startup_drift')
        for name in ('/etc/docker/daemon.json', '/etc/containerd/config.toml'):
            if Path(name).exists() or Path(name).is_symlink():
                raise Refused('docker_baseline_daemon_configuration_drift')
        process = process_identity(manager, '/usr/bin/dockerd')
        socket_fact = socket_identity(grp.getgrnam('docker').gr_gid, process)
        engine = self.docker('info', '--format', '{{.ID}}').decode().strip()
        if engine != self.image_manifest['engine_id']:
            raise Refused('docker_baseline_engine_identity_changed')
        return {'engine_id': engine, 'process': process, 'socket': socket_fact, 'startup_enabled': enabled}

    def images(self):
        result = {}
        bound = {item['reference']: item for item in self.image_manifest['images']}
        for role, spec in SPECS.items():
            image = spec['image']
            value = json.loads(self.docker('image', 'inspect', image))[0]
            if (image not in value.get('RepoDigests', []) or value.get('Os') != 'linux'
                    or value.get('Architecture') != 'amd64' or value.get('Id') != bound[image]['image_id']
                    or value.get('Id') not in (CONFIG_DIGESTS[image], image.split('@')[1])):
                raise Refused('docker_baseline_image_binding_changed')
            acquired = self.acquired[image.split('@')[0]]
            result[role] = {'reference': image, 'image_id': value['Id'], 'platform': 'linux/amd64',
                            'index_digest': acquired['index_digest'], 'manifest_digest': acquired['manifest_digest'],
                            'config_digest': acquired['config_digest'], 'version_label': acquired['version_label']}
        return result

    def compose(self, role, *arguments):
        directory = BASE / role
        return self.docker('compose', '--project-name', SPECS[role]['project'],
                           '--project-directory', str(directory), '--env-file', str(directory / '.env'),
                           '-f', str(directory / 'compose.yaml'), *arguments, timeout=900)

    def container(self, role):
        spec = SPECS[role]
        ids = self.docker('ps', '--all', '--quiet', '--filter',
                          'label=com.docker.compose.project=' + spec['project']).decode().splitlines()
        if len(ids) != 1:
            raise Refused('docker_baseline_container_scope')
        value = json.loads(self.docker('inspect', ids[0]))[0]
        labels = value['Config'].get('Labels') or {}
        binds = {item['Destination']: item for item in value['Mounts']}
        expected = {'/config': str(BASE / role / 'config'), '/mnt/media': str(MEDIA)}
        if (value['Image'] != self.image_ids[role]['image_id']
                or value['Config']['Image'] != spec['image']
                or labels.get('com.docker.compose.project') != spec['project']
                or labels.get('com.docker.compose.service') != role
                or labels.get('com.docker.compose.project.working_dir') != str(BASE / role)
                or labels.get('com.docker.compose.project.config_files') != str(BASE / role / 'compose.yaml')
                or value['HostConfig']['NetworkMode'] != 'host'
                or value['HostConfig']['RestartPolicy']['Name'] != 'unless-stopped'
                or set(binds) != set(expected) or len(value['Mounts']) != 2
                or any(binds[name]['Type'] != 'bind' or binds[name]['Source'] != path
                       or binds[name].get('RW') is not True for name, path in expected.items())):
            raise Refused('docker_baseline_container_resources_changed')
        environment = dict(item.split('=', 1) for item in value['Config']['Env'])
        if any(environment.get(key) != expected for key, expected in
               {'PUID': '963', 'PGID': '1001', 'UMASK': '002', 'TZ': 'America/Los_Angeles'}.items()):
            raise Refused('docker_baseline_identity_environment_changed')
        return value

    def attribution(self, role):
        container = self.container(role)
        if not container['State']['Running']:
            raise Refused('docker_baseline_application_not_running')
        rows = self.docker('top', container['Id'], '-eo', 'pid,comm').decode().splitlines()[1:]
        pids = [int(row.split()[0]) for row in rows if len(row.split()) == 2
                and row.split()[1] == SPECS[role]['process']]
        if len(pids) != 1:
            raise Refused('docker_baseline_application_process_pending')
        pid = pids[0]
        process = Path('/proc') / str(pid)
        values = dict((key, value.strip()) for line in (process / 'status').read_text().splitlines()
                      for key, separator, value in [line.partition(':')] if separator)
        uids, gids = [int(item) for item in values['Uid'].split()], [int(item) for item in values['Gid'].split()]
        groups = [int(item) for item in values['Groups'].split()]
        capabilities = {name: values[name] for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}
        maps = {name: [[int(value) for value in row.split()] for row in (process / name).read_text().splitlines()]
                for name in ('uid_map', 'gid_map')}
        namespaces = {name: os.stat(process / 'ns' / name).st_ino for name in ('user', 'mnt', 'net')}
        if (uids != [963] * 4 or gids != [1001] * 4 or int(capabilities['CapEff'], 16) != 0
                or any(value != [[0, 0, 4294967295]] for value in maps.values())
                or namespaces['net'] != os.stat('/proc/self/ns/net').st_ino):
            raise Refused('docker_baseline_application_credentials_mismatch')
        start = (process / 'stat').read_bytes().rsplit(b')', 1)[1].split()[19].decode()
        inodes = covering_listeners(Path('/proc/net/tcp').read_text(), Path('/proc/net/tcp6').read_text(), SPECS[role]['port'])
        owned = {os.readlink(path) for path in (process / 'fd').iterdir()}
        if not inodes or not inodes <= owned:
            raise Refused('docker_baseline_listener_pending')
        return {'container_id': container['Id'], 'started_at': container['State']['StartedAt'],
                'pid': pid, 'start_ticks': start, 'uid_slots': uids, 'gid_slots': gids, 'groups': groups,
                'capabilities': capabilities, 'id_maps': maps, 'namespaces': namespaces,
                'executable': os.readlink(process / 'exe'), 'umask': values.get('Umask'),
                'listener_inodes': sorted(inodes)}

    def request(self, role, route, key=None, body=None):
        before = self.attribution(role)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        headers = {'Accept': 'application/json'}
        if key is not None:
            headers['X-Api-Key'] = key
        payload = None
        if body is not None:
            payload = canonical(body)
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request('http://127.0.0.1:' + str(SPECS[role]['port']) + route,
                                         data=payload, headers=headers)
        result = bounded_request(opener, request, seconds=10)
        if self.attribution(role) != before:
            raise Refused('docker_baseline_application_changed_during_request')
        return result

    def wait_ready(self, role):
        deadline = time.monotonic() + 120
        while True:
            try:
                self.attribution(role)
                break
            except Refused as error:
                if str(error) not in ('docker_baseline_application_not_running',
                                      'docker_baseline_application_process_pending', 'docker_baseline_listener_pending'):
                    raise
            except (FileNotFoundError, ProcessLookupError):
                pass
            if time.monotonic() >= deadline:
                raise Refused('docker_baseline_readiness_timeout')
            time.sleep(0.2)
        code, raw = self.request(role, '/ping')
        if code != 200 or not ping_ok(raw):
            raise Refused('docker_baseline_ping_failed')

    def protected(self, reference):
        row = self.journal.db.execute('SELECT bytes FROM protected WHERE id=?', (reference,)).fetchone()
        if row is None:
            raise Refused('docker_baseline_protected_reference_missing')
        return row[0]

    def inspect(self, manifest):
        engine = self.engine(enabled=True)
        self.image_ids = self.images()
        assert_compose_account()
        data = [metadata(BASE, 963, 962, 0o750, True), metadata(MEDIA, 0, 0, 0o755, True),
                metadata(SHARED, 1500, 1001, 0o2770, True), metadata(SHARED / 'sentinel', 1500, 1001, 0o640),
                metadata(RADARR_ROOT, 963, 1001, 0o2770, True), metadata(SENTINEL, 963, 1001, 0o2770, True)]
        data.append(metadata(SENTINEL / 'sentinel', 963, 1001, 0o640))
        shared_bytes = ('mpkg fixture ' + self.guest + ' shared\n').encode()
        if read_regular(SHARED / 'sentinel')[0] != shared_bytes:
            raise Refused('docker_baseline_existing_shared_sentinel_changed')
        observations = {}
        for role in SPECS:
            directory, references = BASE / role, manifest['inputs'][role]
            for filename in ('compose.yaml', '.env'):
                if not self.journal.unchanged(references[filename], directory / filename):
                    raise Refused('docker_baseline_compose_input_drift')
            rendered = self.compose(role, 'config', '--format', 'json')
            if json.loads(rendered) != json.loads(self.protected(references['rendered'])):
                raise Refused('docker_baseline_effective_inputs_drift')
            data.append(metadata(directory, 963, 962, 0o750, True))
            data.append(metadata(directory / 'config', 963, 1001, 0o2770, True))
            data.append(metadata(directory / 'config' / 'config.xml', 963, 1001, 0o600))
            current, _ = read_regular(directory / 'config' / 'config.xml')
            preserve_initial_values(self.protected(references['initial_xml']), current)
            preserve_initial_values(self.protected(references['assembled_xml']), current)
            self.wait_ready(role)
            credentials = self.attribution(role)
            sentinel = directory / 'config' / 'mpkg-fixture-sentinel'
            sentinel_bytes = ('mpkg fixture ' + self.guest + ' ' + role + ' config\n').encode()
            data.append(metadata(sentinel, 963, 1001, 0o640))
            read_as_application(sentinel, sentinel_bytes, credentials)
            read_as_application(SHARED / 'sentinel', shared_bytes, credentials)
            read_as_application(SENTINEL / 'sentinel', ('mpkg fixture ' + self.guest + ' media\n').encode(), credentials)
            observations[role] = {'project': SPECS[role]['project'], 'service': role,
                                   'image': self.image_ids[role], 'attribution': credentials,
                                   'configuration_semantics_preserved': True,
                                   'serialization_changed_from_initial': current != self.protected(references['initial_xml']),
                                   'anonymous_ping': True, 'copied_credential_sentinel_reads': True}
        key = xml_values(self.protected(manifest['inputs']['radarr']['initial_xml']))['ApiKey']
        code, raw = self.request('radarr', '/api/v3/rootfolder/' + str(manifest['radarr_root_id']) + '?timeout=true', key=key)
        validate_shared_response(code, json.loads(raw), manifest['radarr_root_id'])
        result = {'schema': 1, 'guest_id': self.guest, 'status': 'observed', 'fixture': 'docker-adoption-candidate',
                  'engine': engine, 'applications': observations, 'data': data,
                  'unmanaged_radarr_directory_discovery': True, 'product_acceptance': False,
                  'limits': ['Assembly evidence only; no product adoption, attempt history or applied snapshot.',
                             'Sonarr and unmanaged Radarr remain running; the coordinator owns offline snapshots.',
                             'Copied-credential file reads are supplemental, not application behavior.',
                             'Radarr proves live directory discovery, not media import or media-file reads.',
                             'Host-network binds only; supplemental volume/network variants are not assembled.']}
        write_new(self.root / ('check-' + str(uuid.uuid4()) + '.json'), canonical(result) + b'\n')
        return result

    def setup(self):
        require_mail_defaults()
        self.engine(enabled=False)
        self.image_ids = self.images()
        native_identity('native')
        native_identity('external')
        metadata(MEDIA, 0, 0, 0o755, True)
        metadata(SHARED, 1500, 1001, 0o2770, True)
        metadata(SHARED / 'sentinel', 1500, 1001, 0o640)
        if ({item.name for item in MEDIA.iterdir()} != {SHARED.name}
                or {item.name for item in SHARED.iterdir()} != {'sentinel'}
                or read_regular(SHARED / 'sentinel')[0] != ('mpkg fixture ' + self.guest + ' shared\n').encode()):
            raise Refused('docker_fixture_shared_baseline_not_fresh')
        for lookup, value in ((pwd.getpwnam, 'compose'), (pwd.getpwuid, 963),
                              (grp.getgrnam, 'compose'), (grp.getgrgid, 962)):
            try:
                lookup(value)
            except KeyError:
                continue
            raise Refused('docker_fixture_owner_collision')
        for path in (BASE, RADARR_ROOT):
            if path.exists() or path.is_symlink():
                raise Refused('docker_fixture_path_collision')
        trusted_path(BASE.parent, directory=True)
        for port in (18989, 18990, 17878):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', port))
        for spec in SPECS.values():
            if self.docker('ps', '--all', '--quiet', '--filter',
                           'label=com.docker.compose.project=' + spec['project']).strip():
                raise Refused('docker_fixture_project_collision')
        attempt = str(uuid.uuid4())
        self.journal.begin(attempt)
        command(['/usr/bin/groupadd', '--gid', '962', 'compose'])
        command(useradd_arguments('compose'))
        make_directory(BASE, 963, 962, 0o750)
        assert_compose_account()
        for path in (RADARR_ROOT, SENTINEL):
            make_directory(path, 963, 1001, 0o2770)
        make_file(SENTINEL / 'sentinel', ('mpkg fixture ' + self.guest + ' media\n').encode(), 963, 1001, 0o640)
        manifest = {'schema': 1, 'guest_id': self.guest, 'inputs': {}, 'radarr_root_id': None}
        for role, spec in SPECS.items():
            directory = BASE / role
            make_directory(directory, 963, 962, 0o750)
            make_directory(directory / 'config', 963, 1001, 0o2770)
            make_file(directory / 'config' / 'config.xml', config_xml(spec['port'], uuid.uuid4().hex), 963, 1001, 0o600)
            make_file(directory / 'config' / 'mpkg-fixture-sentinel',
                      ('mpkg fixture ' + self.guest + ' ' + role + ' config\n').encode(), 963, 1001, 0o640)
            source = {'services': {role: {'image': '${FIXTURE_IMAGE}', 'platform': 'linux/amd64',
                'network_mode': 'host', 'restart': 'unless-stopped',
                'environment': {key: '${' + key + '}' for key in ('PUID', 'PGID', 'UMASK', 'TZ')},
                'volumes': [{'type': 'bind', 'source': './config', 'target': '/config', 'read_only': False,
                             'bind': {'create_host_path': False}},
                            {'type': 'bind', 'source': str(MEDIA), 'target': '/mnt/media', 'read_only': False,
                             'bind': {'create_host_path': False}}]}}}
            make_file(directory / 'compose.yaml', canonical(source) + b'\n', 963, 962, 0o640)
            make_file(directory / '.env', ('FIXTURE_IMAGE=' + spec['image'] +
                      '\nPUID=963\nPGID=1001\nUMASK=002\nTZ=America/Los_Angeles\n').encode(), 963, 962, 0o640)
            rendered = self.compose(role, 'config', '--format', 'json')
            effective = json.loads(rendered)
            if (set(effective['services']) != {role} or effective['services'][role]['image'] != spec['image']
                    or effective['services'][role].get('build') or effective.get('networks') or effective.get('volumes')):
                raise Refused('docker_fixture_effective_scope_changed')
            rendered_path = self.root / (role + '-rendered.json')
            write_new(rendered_path, rendered)
            manifest['inputs'][role] = {name: self.journal.capture(directory / name) for name in ('compose.yaml', '.env')}
            manifest['inputs'][role]['rendered'] = self.journal.capture(rendered_path)
            manifest['inputs'][role]['initial_xml'] = self.journal.capture(directory / 'config' / 'config.xml')
            self.compose(role, 'up', '--detach', '--no-build', '--pull', 'never')
            self.wait_ready(role)
            current, _ = read_regular(directory / 'config' / 'config.xml')
            preserve_initial_values(self.protected(manifest['inputs'][role]['initial_xml']), current)
            manifest['inputs'][role]['assembled_xml'] = self.journal.capture(directory / 'config' / 'config.xml')
        key = xml_values(self.protected(manifest['inputs']['radarr']['initial_xml']))['ApiKey']
        code, raw = self.request('radarr', '/api/v3/config/naming', key=key)
        if code != 200 or json.loads(raw).get('movieFolderFormat') != '{Movie Title} ({Release Year})':
            raise Refused('docker_fixture_radarr_naming_changed')
        code, raw = self.request('radarr', '/api/v3/rootfolder', key=key, body={'path': str(RADARR_ROOT)})
        root_id = json.loads(raw).get('id')
        if code != 201 or type(root_id) is not int or root_id <= 0:
            raise Refused('docker_fixture_radarr_registration_unverified')
        manifest['radarr_root_id'] = root_id
        write_new(self.root / 'baseline.json', canonical(manifest) + b'\n')
        command(['/usr/bin/systemctl', 'enable', 'docker.service'])
        result = self.inspect(manifest)
        self.journal.finish(attempt, 'observed-complete')
        return result


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'check'))
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    baseline = Baseline(guest, setup=args.action == 'setup')
    try:
        if args.action == 'setup':
            result = baseline.setup()
        else:
            attempts = baseline.journal.export()
            if len(attempts) != 1 or attempts[0]['state'] != 'observed-complete':
                raise Refused('docker_baseline_setup_incomplete')
            raw, _ = read_regular(baseline.root / 'baseline.json')
            manifest = json.loads(raw)
            if manifest.get('schema') != 1 or manifest.get('guest_id') != guest:
                raise Refused('docker_baseline_manifest_identity')
            result = baseline.inspect(manifest)
        print(json.dumps(result, sort_keys=True))
    finally:
        baseline.journal.close()


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'docker_baseline_failed', 'product_acceptance': False}))
        sys.exit(74)
