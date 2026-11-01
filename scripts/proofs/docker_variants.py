#!/usr/bin/env python3
"""Assemble isolated Docker resource/update fixtures without product history."""
import argparse
import grp
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from account_defaults import require_mail_defaults, useradd_arguments
from compose_proof import NoRedirect, bounded_request, config_xml, covering_listeners
from core import Journal, Refused, canonical, ping_ok, private_directory, read_regular, require_guest, write_new
from docker_baseline import (BASE, MEDIA, SHARED, RADARR_ROOT, SENTINEL, Baseline,
                             assert_compose_account, make_directory, make_file, metadata,
                             preserve_initial_values, read_as_application, validate_shared_response, xml_values)
from docker_variant_plan import (NETWORK, VOLUME, VARIANTS, NamespaceOpener, compose_document,
                                 read_config_archive, variant_plan)
from image_import import validate_acquisition
from native_manifest import trusted_json
from native_service import identity as native_identity, trusted_path
from run import ENV, command, trusted_install


def reserve(path):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise Refused('docker_variant_fresh_restore_required') from None
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return private_directory(path)


def config_credential_check(root_descriptor, namespace_descriptor, namespace_inode, credentials, sentinel, role):
    """Inspect only the fixed config root/sentinel with the app's full credentials."""
    child = os.fork()
    if child == 0:
        try:
            # The target procfs may not expose this child from the host PID
            # namespace. Hold this child's own proc view before setns.
            own_namespaces = os.open('/proc/self/ns', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            os.setns(namespace_descriptor, os.CLONE_NEWNS)
            if os.stat('mnt', dir_fd=own_namespaces).st_ino != namespace_inode:
                os._exit(1)
            os.close(own_namespaces)
            os.fchdir(root_descriptor)
            os.chroot('.')
            os.chdir('/')
            os.setgroups(credentials['groups'])
            os.setgid(1001)
            os.setuid(963)
            descriptor = os.open('/config', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(descriptor)
            if ((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (963, 1001, 0o2770)
                    or os.listxattr('/config')):
                os._exit(1)
            file = os.open('mpkg-fixture-sentinel', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            info = os.fstat(file)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (963, 1001, 0o640)
                    or os.read(file, 4097) != sentinel):
                os._exit(1)
            info = os.stat(role + '.db', dir_fd=descriptor, follow_symlinks=False)
            if (role not in ('sonarr', 'radarr') or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_uid, info.st_gid) != (963, 1001) or info.st_size <= 0 or info.st_mode & 0o002):
                os._exit(1)
            os._exit(0)
        except Exception:
            os._exit(1)
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline:
            finished, status = os.waitpid(child, os.WNOHANG)
            if finished:
                child = None
                if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                    raise Refused('docker_variant_config_credential_check_failed')
                return
            time.sleep(0.01)
        raise Refused('docker_variant_config_credential_check_timeout')
    finally:
        if child is not None:
            os.kill(child, 9)
            os.waitpid(child, 0)


class Variant(Baseline):
    def __init__(self, guest, variant, setup=False):
        self.guest, self.plan = guest, variant_plan(variant)
        self.specs = self.plan['applications']
        self.root = Path('/var/lib/mpkg-proofs') / guest / ('docker-variant-' + variant)
        if setup:
            reserve(self.root)
        else:
            trusted_path(self.root, directory=True)
        self.client = private_directory(self.root / 'docker-client')
        self.environment = dict(ENV, DOCKER_CONFIG=str(self.client))
        self.journal = Journal(self.root)
        self.image_manifest, _ = trusted_json('compose.json')
        if self.image_manifest.get('schema') != 1 or self.image_manifest.get('guest_id') != guest:
            raise Refused('docker_variant_engine_binding_missing')
        acquired, _ = trusted_json('acquisition.json')
        validate_acquisition(acquired)
        self.acquired = {item['repository'] + '@' + item['index_digest']: item for item in acquired['images']}
        self.network_id = None
        self.image_ids = {}
        self.enabled = not setup

    def compose(self, role, *arguments):
        spec = self.specs[role]
        directory = BASE / role
        return self.docker('compose', '--project-name', spec['project'], '--project-directory', str(directory),
                           '--env-file', str(directory / '.env'), '-f', str(directory / 'compose.yaml'),
                           *arguments, timeout=900)

    def images(self):
        result = {}
        for role, spec in self.specs.items():
            image = spec['image']
            acquired = self.acquired[image]
            value = json.loads(self.docker('image', 'inspect', image))[0]
            if (image not in value.get('RepoDigests', []) or value.get('Os') != 'linux'
                    or value.get('Architecture') != 'amd64'
                    or value.get('Id') not in (acquired['config_digest'], acquired['index_digest'])
                    or (value.get('Config', {}).get('Labels') or {}).get('org.opencontainers.image.version') != acquired['version_label']):
                raise Refused('docker_variant_image_binding_changed')
            result[role] = {'reference': image, 'image_id': value['Id'], 'platform': 'linux/amd64',
                            'index_digest': acquired['index_digest'], 'manifest_digest': acquired['manifest_digest'],
                            'config_digest': acquired['config_digest'], 'version_label': acquired['version_label']}
        return result

    def container(self, role):
        spec = self.specs[role]
        identifiers = self.docker('ps', '--all', '--quiet', '--no-trunc', '--filter',
                                   'label=com.docker.compose.project=' + spec['project']).decode().splitlines()
        if len(identifiers) != 1:
            raise Refused('docker_variant_container_scope')
        value = json.loads(self.docker('inspect', identifiers[0]))[0]
        labels = value['Config'].get('Labels') or {}
        mounts = {item['Destination']: item for item in value['Mounts']}
        if (value['Image'] != self.image_ids[role]['image_id'] or value['Config']['Image'] != spec['image']
                or labels.get('com.docker.compose.project') != spec['project']
                or labels.get('com.docker.compose.service') != role
                or labels.get('com.docker.compose.project.working_dir') != str(BASE / role)
                or labels.get('com.docker.compose.project.config_files') != str(BASE / role / 'compose.yaml')
                or value['HostConfig']['RestartPolicy']['Name'] != 'unless-stopped'
                or set(mounts) != {'/config', '/mnt/media'} or len(value['Mounts']) != 2
                or mounts['/mnt/media']['Type'] != 'bind' or mounts['/mnt/media']['Source'] != str(MEDIA)
                or any(item.get('RW') is not True for item in mounts.values())):
            raise Refused('docker_variant_container_resources_changed')
        config = mounts['/config']
        if spec['config_volume']:
            if config.get('Type') != 'volume' or config.get('Name') != VOLUME or config.get('Driver') != 'local':
                raise Refused('docker_variant_volume_mount_changed')
        elif config.get('Type') != 'bind' or config.get('Source') != str(BASE / role / 'config'):
            raise Refused('docker_variant_config_bind_changed')
        environment = dict(item.split('=', 1) for item in value['Config']['Env'])
        if any(environment.get(key) != expected for key, expected in
               {'PUID': '963', 'PGID': '1001', 'UMASK': '002', 'TZ': 'America/Los_Angeles'}.items()):
            raise Refused('docker_variant_identity_environment_changed')
        if self.plan['bridge']:
            networks = value['NetworkSettings']['Networks']
            mapping = {str(spec['port']) + '/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(spec['port'])}]}
            if (set(networks) != {NETWORK} or networks[NETWORK].get('NetworkID') != self.network_id
                    or value['HostConfig']['NetworkMode'] not in (NETWORK, self.network_id)
                    or value['HostConfig'].get('PortBindings') != mapping):
                raise Refused('docker_variant_network_binding_changed')
            published = {key: item for key, item in (value['NetworkSettings'].get('Ports') or {}).items() if item}
            if value['State']['Running'] and published != mapping:
                raise Refused('docker_variant_published_mapping_changed')
        elif value['HostConfig']['NetworkMode'] != 'host' or value['HostConfig'].get('PortBindings'):
            raise Refused('docker_variant_host_network_changed')
        return value

    def attribution(self, role):
        container = self.container(role)
        if not container['State']['Running']:
            raise Refused('docker_baseline_application_not_running')
        rows = self.docker('top', container['Id'], '-eo', 'pid,comm').decode().splitlines()[1:]
        pids = [int(row.split()[0]) for row in rows if len(row.split()) == 2 and row.split()[1] == self.specs[role]['process']]
        if len(pids) != 1:
            raise Refused('docker_baseline_application_process_pending')
        process = Path('/proc') / str(pids[0])
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
                or (namespaces['net'] != os.stat('/proc/self/ns/net').st_ino) != self.plan['bridge']):
            raise Refused('docker_variant_application_credentials_mismatch')
        start = (process / 'stat').read_bytes().rsplit(b')', 1)[1].split()[19].decode()
        inodes = covering_listeners((process / 'net/tcp').read_text(), (process / 'net/tcp6').read_text(), self.specs[role]['port'])
        owned = {os.readlink(path) for path in (process / 'fd').iterdir()}
        if not inodes or not inodes <= owned:
            raise Refused('docker_baseline_listener_pending')
        return {'container_id': container['Id'], 'started_at': container['State']['StartedAt'],
                'pid': pids[0], 'start_ticks': start, 'uid_slots': uids, 'gid_slots': gids, 'groups': groups,
                'capabilities': capabilities, 'id_maps': maps, 'namespaces': namespaces,
                'executable': os.readlink(process / 'exe'), 'umask': values.get('Umask'), 'listener_inodes': sorted(inodes)}

    def request(self, role, route, key=None, body=None):
        allowed = ('/ping', '/api/v3/config/naming', '/api/v3/rootfolder')
        if route not in allowed and not (route.startswith('/api/v3/rootfolder/')
                                        and route.removeprefix('/api/v3/rootfolder/').removesuffix('?timeout=true').isdigit()
                                        and route.endswith('?timeout=true')):
            raise Refused('docker_variant_request_route_unsupported')
        engine = self.engine(self.enabled)
        before = self.attribution(role)
        descriptor = (os.open('/proc/' + str(before['pid']) + '/ns/net', os.O_RDONLY | os.O_CLOEXEC)
                      if self.plan['bridge'] else None)
        try:
            info = os.fstat(descriptor) if descriptor is not None else None
            if (info is not None and info.st_ino != before['namespaces']['net']) or self.attribution(role) != before:
                raise Refused('docker_variant_namespace_changed_before_request')
            headers = {'Accept': 'application/json'}
            if key is not None:
                headers['X-Api-Key'] = key
            payload = None
            if body is not None:
                payload = canonical(body)
                headers['Content-Type'] = 'application/json'
            request = urllib.request.Request('http://127.0.0.1:' + str(self.specs[role]['port']) + route,
                                             data=payload, headers=headers)
            opener = (NamespaceOpener(descriptor, (info.st_dev, info.st_ino)) if info is not None else
                      urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect))
            response = bounded_request(opener, request, seconds=10)
            if (self.attribution(role) != before or self.engine(self.enabled) != engine
                    or (descriptor is not None and os.fstat(descriptor).st_ino != before['namespaces']['net'])):
                raise Refused('docker_variant_namespace_changed_during_request')
            return response
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def published_ping(self, role):
        before = self.container(role)
        if not self.plan['bridge']:
            return
        request = urllib.request.Request('http://127.0.0.1:' + str(self.specs[role]['port']) + '/ping',
                                         headers={'Accept': 'application/json'})
        code, raw = bounded_request(urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect), request, seconds=10)
        after = self.container(role)
        if code != 200 or not ping_ok(raw) or (before['Id'], before['State']['StartedAt']) != (after['Id'], after['State']['StartedAt']):
            raise Refused('docker_variant_credential_free_route_failed')

    def config_file(self, role, name):
        if name not in ('config.xml', 'mpkg-fixture-sentinel'):
            raise Refused('docker_variant_config_file_unsupported')
        container = self.container(role)
        raw = self.docker('cp', container['Id'] + ':/config/' + name, '-')
        data, info = read_config_archive(raw, name)
        expected_mode = '0o600' if name == 'config.xml' else '0o640'
        if info['uid'] != 963 or info['gid'] != 1001 or info['mode'] != expected_mode:
            raise Refused('docker_variant_config_metadata_changed')
        if self.container(role)['Id'] != container['Id']:
            raise Refused('docker_variant_container_changed_during_copy')
        return data, info

    def capture_config(self, role, label):
        raw, info = self.config_file(role, 'config.xml')
        path = self.root / (role + '-' + label + '.xml')
        write_new(path, raw)
        return self.journal.capture(path), info

    def config_access(self, role):
        before = self.attribution(role)
        namespace = os.open('/proc/' + str(before['pid']) + '/ns/mnt', os.O_RDONLY | os.O_CLOEXEC)
        root = os.open('/proc/' + str(before['pid']) + '/root', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            identity = os.fstat(root)
            if os.fstat(namespace).st_ino != before['namespaces']['mnt'] or self.attribution(role) != before:
                raise Refused('docker_variant_config_namespace_changed')
            config_credential_check(root, namespace, before['namespaces']['mnt'], before,
                                    ('mpkg fixture ' + self.guest + ' ' + role + ' config\n').encode(), role)
            after = os.fstat(root)
            if (self.attribution(role) != before or os.fstat(namespace).st_ino != before['namespaces']['mnt']
                    or (after.st_dev, after.st_ino) != (identity.st_dev, identity.st_ino)):
                raise Refused('docker_variant_config_namespace_changed')
        finally:
            os.close(root)
            os.close(namespace)

    def objects(self):
        containers = {role: self.container(role) for role in self.specs}
        expected_ids = {item['Id'] for item in containers.values()}
        actual_ids = set(self.docker('ps', '--all', '--quiet', '--no-trunc').decode().splitlines())
        if actual_ids != expected_ids:
            raise Refused('docker_variant_other_container_present')
        result = {'container_ids': {role: value['Id'] for role, value in containers.items()}}
        if self.plan['volume']:
            value = json.loads(self.docker('volume', 'inspect', VOLUME))[0]
            if (value.get('Name') != VOLUME or value.get('Driver') != 'local' or value.get('Options') not in (None, {})
                    or value.get('Scope') != 'local' or value.get('Labels') != self.labels()
                    or set(self.docker('volume', 'ls', '--quiet').decode().splitlines()) != {VOLUME}):
                raise Refused('docker_variant_volume_identity_changed')
            consumers = [role for role, container in containers.items()
                         if any(item.get('Name') == VOLUME for item in container['Mounts'])]
            config_mount = next(item for item in containers['sonarr']['Mounts'] if item['Destination'] == '/config')
            if consumers != ['sonarr'] or config_mount.get('Source') != value.get('Mountpoint'):
                raise Refused('docker_variant_volume_consumers_changed')
            result['volume'] = {key: value.get(key) for key in ('Name', 'Driver', 'Mountpoint', 'Labels', 'Options', 'Scope', 'CreatedAt')}
            result['volume']['consumers'] = [containers['sonarr']['Id']]
        elif self.docker('volume', 'ls', '--quiet').strip():
            raise Refused('docker_variant_unexpected_volume')
        if self.plan['bridge']:
            value = json.loads(self.docker('network', 'inspect', NETWORK))[0]
            if (value.get('Id') != self.network_id or value.get('Name') != NETWORK or value.get('Driver') != 'bridge'
                    or value.get('Scope') != 'local' or value.get('Labels') != self.labels()
                    or value.get('Internal') is not False or value.get('EnableIPv6') is not False
                    or value.get('Options') not in (None, {}) or set(value.get('Containers', {})) != expected_ids):
                raise Refused('docker_variant_network_identity_or_consumers_changed')
            result['network'] = {key: value.get(key) for key in ('Id', 'Name', 'Driver', 'Scope', 'Labels', 'Options', 'IPAM')}
            result['network']['consumers'] = sorted(expected_ids)
        names = set(self.docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines())
        if names != {'bridge', 'host', 'none'} | ({NETWORK} if self.plan['bridge'] else set()):
            raise Refused('docker_variant_unexpected_network')
        return result

    def labels(self):
        return {'mpkg.fixture': self.guest, 'mpkg.variant': self.plan['variant']}

    def prepare_volume(self):
        self.docker('volume', 'create', '--driver', 'local', '--label', 'mpkg.fixture=' + self.guest,
                    '--label', 'mpkg.variant=' + self.plan['variant'], VOLUME)
        name = 'mpkg-fixture-' + self.plan['variant'] + '-volume-init'
        identifier = self.docker('create', '--pull', 'never', '--platform', 'linux/amd64', '--name', name,
                                  '--network', 'none', '--read-only', '--user', '0:1001', '--cap-drop', 'ALL',
                                  '--cap-add', 'CHOWN', '--cap-add', 'FOWNER', '--security-opt', 'no-new-privileges',
                                  '--mount', 'type=volume,source=' + VOLUME + ',target=/config,volume-nocopy',
                                  '--entrypoint', '/bin/sh', self.specs['sonarr']['image'], '-c',
                                  "chown 963:1001 /config && chmod 2770 /config && stat -c '%u:%g:%a' /config").decode().strip()
        if len(identifier) != 64 or any(char not in '0123456789abcdef' for char in identifier):
            raise Refused('docker_variant_initializer_identity_invalid')
        self.docker('start', identifier)
        if self.docker('wait', identifier, timeout=30).strip() != b'0':
            raise Refused('docker_variant_volume_initialization_failed')
        # chmod can silently clear SGID without a matching process group or
        # CAP_FSETID. Require actual metadata before any application starts.
        if self.docker('logs', identifier) != b'963:1001:2770\n':
            raise Refused('docker_variant_volume_initialization_metadata_mismatch')
        value = json.loads(self.docker('inspect', identifier))[0]
        mounts = value.get('Mounts', [])
        if (value.get('Id') != identifier or value.get('Image') != self.image_ids['sonarr']['image_id']
                or value['Config']['User'] != '0:1001'
                or value['State']['Running'] or value['State']['ExitCode'] != 0
                or value['HostConfig']['NetworkMode'] != 'none' or len(mounts) != 1
                or mounts[0].get('Name') != VOLUME or mounts[0].get('Destination') != '/config'):
            raise Refused('docker_variant_initializer_scope_changed')
        self.docker('rm', identifier)

    def fresh(self):
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
            raise Refused('docker_variant_shared_baseline_not_fresh')
        for lookup, value in ((pwd.getpwnam, 'compose'), (pwd.getpwuid, 963),
                              (grp.getgrnam, 'compose'), (grp.getgrgid, 962)):
            try:
                lookup(value)
            except KeyError:
                continue
            raise Refused('docker_variant_owner_collision')
        for path in (BASE, RADARR_ROOT, self.root.parent / 'docker-baseline', self.root.parent / 'compose'):
            if path.exists() or path.is_symlink():
                raise Refused('docker_variant_path_collision')
        trusted_path(BASE.parent, directory=True)
        for port in (18989, 18990, 17878):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', port))
        if self.docker('ps', '--all', '--quiet').strip() or self.docker('volume', 'ls', '--quiet').strip():
            raise Refused('docker_variant_engine_not_empty')
        if set(self.docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines()) != {'bridge', 'host', 'none'}:
            raise Refused('docker_variant_networks_not_fresh')
        if any(path != self.root for path in self.root.parent.glob('docker-variant-*')):
            raise Refused('docker_variant_other_attempt_present')

    def seed(self, role):
        spec, directory = self.specs[role], BASE / role
        make_directory(directory, 963, 962, 0o750)
        seed = private_directory(self.root / (role + '-seed')) if spec['config_volume'] else directory / 'config'
        if not spec['config_volume']:
            make_directory(seed, 963, 1001, 0o2770)
        raw = config_xml(spec['port'], uuid.uuid4().hex)
        if self.plan['bridge']:
            raw = raw.replace(b'<BindAddress>127.0.0.1</BindAddress>', b'<BindAddress>0.0.0.0</BindAddress>')
            if xml_values(raw)['BindAddress'] != '0.0.0.0':
                raise Refused('docker_variant_bridge_bind_configuration')
        make_file(seed / 'config.xml', raw, 963, 1001, 0o600)
        make_file(seed / 'mpkg-fixture-sentinel',
                  ('mpkg fixture ' + self.guest + ' ' + role + ' config\n').encode(), 963, 1001, 0o640)
        make_file(directory / 'compose.yaml', canonical(compose_document(self.plan, role)) + b'\n', 963, 962, 0o640)
        make_file(directory / '.env', ('FIXTURE_IMAGE=' + spec['image'] +
                  '\nPUID=963\nPGID=1001\nUMASK=002\nTZ=America/Los_Angeles\n').encode(), 963, 962, 0o640)
        rendered = self.compose(role, 'config', '--format', 'json')
        effective = json.loads(rendered)
        if (set(effective.get('services', {})) != {role} or effective['services'][role]['image'] != spec['image']
                or effective['services'][role].get('build')
                or bool(effective.get('networks')) != self.plan['bridge']
                or bool(effective.get('volumes')) != bool(spec['config_volume'])):
            raise Refused('docker_variant_effective_scope_changed')
        rendered_path = self.root / (role + '-rendered.json')
        write_new(rendered_path, rendered)
        references = {name: self.journal.capture(directory / name) for name in ('compose.yaml', '.env')}
        references['rendered'] = self.journal.capture(rendered_path)
        references['initial_xml'] = self.journal.capture(seed / 'config.xml')
        if spec['config_volume']:
            self.compose(role, 'create', '--no-build', '--pull', 'never')
            container = self.container(role)
            if container['State']['Running'] or container['State']['Status'] != 'created':
                raise Refused('docker_variant_seed_requires_unstarted_container')
            for name in ('config.xml', 'mpkg-fixture-sentinel'):
                self.docker('cp', '--archive', str(seed / name), container['Id'] + ':/config/' + name)
            if self.config_file(role, 'config.xml')[0] != raw:
                raise Refused('docker_variant_seed_copy_changed')
        self.compose(role, 'up', '--detach', '--no-build', '--pull', 'never')
        self.wait_ready(role)
        current, _ = self.config_file(role, 'config.xml')
        preserve_initial_values(raw, current)
        references['assembled_xml'], _ = self.capture_config(role, 'assembled')
        return references

    def shared_check(self, manifest):
        if 'radarr' not in self.specs:
            return False
        key = xml_values(self.protected(manifest['inputs']['radarr']['initial_xml']))['ApiKey']
        identifier = manifest['radarr_root_id']
        if type(identifier) is not int or identifier <= 0:
            raise Refused('docker_variant_root_folder_identity')
        code, raw = self.request('radarr', '/api/v3/rootfolder/' + str(identifier) + '?timeout=true', key=key)
        validate_shared_response(code, json.loads(raw), identifier)
        return True

    def inspect(self, manifest):
        if (manifest.get('schema') != 1 or manifest.get('guest_id') != self.guest
                or manifest.get('plan') != self.plan or set(manifest.get('inputs', {})) != set(self.specs)):
            raise Refused('docker_variant_manifest_changed')
        self.network_id = manifest['network_id']
        engine = self.engine(enabled=True)
        self.image_ids = self.images()
        if self.image_ids != manifest['images']:
            raise Refused('docker_variant_image_identity_changed')
        assert_compose_account()
        native_identity('native')
        native_identity('external')
        data = [metadata(BASE, 963, 962, 0o750, True), metadata(MEDIA, 0, 0, 0o755, True),
                metadata(SHARED, 1500, 1001, 0o2770, True), metadata(SHARED / 'sentinel', 1500, 1001, 0o640)]
        shared = ('mpkg fixture ' + self.guest + ' shared\n').encode()
        if read_regular(SHARED / 'sentinel')[0] != shared:
            raise Refused('docker_variant_shared_sentinel_changed')
        if 'radarr' in self.specs:
            data.extend([metadata(RADARR_ROOT, 963, 1001, 0o2770, True), metadata(SENTINEL, 963, 1001, 0o2770, True),
                         metadata(SENTINEL / 'sentinel', 963, 1001, 0o640)])
        elif RADARR_ROOT.exists() or RADARR_ROOT.is_symlink():
            raise Refused('docker_variant_exclusive_fixture_has_radarr_data')
        observations = {}
        for role, spec in self.specs.items():
            directory, references = BASE / role, manifest['inputs'][role]
            data.append(metadata(directory, 963, 962, 0o750, True))
            for name in ('compose.yaml', '.env'):
                data.append(metadata(directory / name, 963, 962, 0o640))
                if not self.journal.unchanged(references[name], directory / name):
                    raise Refused('docker_variant_compose_input_drift')
            if json.loads(self.compose(role, 'config', '--format', 'json')) != json.loads(self.protected(references['rendered'])):
                raise Refused('docker_variant_effective_input_drift')
            current, config_metadata = self.config_file(role, 'config.xml')
            preserve_initial_values(self.protected(references['initial_xml']), current)
            preserve_initial_values(self.protected(references['assembled_xml']), current)
            self.wait_ready(role)
            credentials = self.attribution(role)
            self.config_access(role)
            read_as_application(SHARED / 'sentinel', shared, credentials)
            if 'radarr' in self.specs:
                read_as_application(SENTINEL / 'sentinel', ('mpkg fixture ' + self.guest + ' media\n').encode(), credentials)
            self.published_ping(role)
            observations[role] = {'project': spec['project'], 'service': role, 'image': self.image_ids[role],
                                  'attribution': credentials, 'configuration_metadata': config_metadata,
                                  'configuration_semantics_preserved': True, 'anonymous_ping': True,
                                  'published_route_checked': self.plan['bridge'], 'copied_credential_reads': True,
                                  'application_database_metadata_observed': True}
        resources = self.objects()
        if resources != manifest['resources']:
            raise Refused('docker_variant_recorded_resources_changed')
        discovered = self.shared_check(manifest)
        result = {'schema': 1, 'guest_id': self.guest, 'status': 'observed', 'variant': self.plan['variant'],
                  'fixture': 'docker-supplemental-assembly', 'plan': self.plan, 'engine': engine,
                  'applications': observations, 'resources': resources, 'data': data,
                  'unmanaged_radarr_directory_discovery': discovered, 'product_acceptance': False,
                  'limits': ['Assembly only; no product history, adoption, applied state, update or retirement.',
                             'Copied-credential reads supplement the real Radarr directory-discovery check.',
                             'Authenticated bridge checks enter the held application namespace; published checks carry no key.',
                             'The coordinator owns stopped checkpoints and separate mutation attempts.']}
        write_new(self.root / ('check-' + str(uuid.uuid4()) + '.json'), canonical(result) + b'\n')
        return result

    def setup(self):
        self.fresh()
        attempt = str(uuid.uuid4())
        self.journal.begin(attempt)
        command(['/usr/bin/groupadd', '--gid', '962', 'compose'])
        command(useradd_arguments('compose'))
        make_directory(BASE, 963, 962, 0o750)
        assert_compose_account()
        if 'radarr' in self.specs:
            for path in (RADARR_ROOT, SENTINEL):
                make_directory(path, 963, 1001, 0o2770)
            make_file(SENTINEL / 'sentinel', ('mpkg fixture ' + self.guest + ' media\n').encode(), 963, 1001, 0o640)
        if self.plan['bridge']:
            self.network_id = self.docker('network', 'create', '--driver', 'bridge', '--label', 'mpkg.fixture=' + self.guest,
                                           '--label', 'mpkg.variant=' + self.plan['variant'], NETWORK).decode().strip()
            if len(self.network_id) != 64 or any(char not in '0123456789abcdef' for char in self.network_id):
                raise Refused('docker_variant_network_identity_invalid')
        if self.plan['volume']:
            self.prepare_volume()
        manifest = {'schema': 1, 'guest_id': self.guest, 'plan': self.plan, 'images': self.image_ids,
                    'network_id': self.network_id, 'inputs': {}, 'radarr_root_id': None}
        for role in self.specs:
            manifest['inputs'][role] = self.seed(role)
        manifest['resources'] = self.objects()
        if 'radarr' in self.specs:
            key = xml_values(self.protected(manifest['inputs']['radarr']['initial_xml']))['ApiKey']
            code, raw = self.request('radarr', '/api/v3/config/naming', key=key)
            if code != 200 or json.loads(raw).get('movieFolderFormat') != '{Movie Title} ({Release Year})':
                raise Refused('docker_variant_radarr_naming_changed')
            code, raw = self.request('radarr', '/api/v3/rootfolder', key=key, body={'path': str(RADARR_ROOT)})
            root_id = json.loads(raw).get('id')
            if code != 201 or type(root_id) is not int or root_id <= 0:
                raise Refused('docker_variant_radarr_registration_unverified')
            manifest['radarr_root_id'] = root_id
        write_new(self.root / 'baseline.json', canonical(manifest) + b'\n')
        command(['/usr/bin/systemctl', 'enable', 'docker.service'])
        self.enabled = True
        result = self.inspect(manifest)
        self.journal.finish(attempt, 'observed-complete')
        return result


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'check'))
    parser.add_argument('--variant', choices=VARIANTS, required=True)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    fixture = Variant(guest, args.variant, setup=args.action == 'setup')
    try:
        if args.action == 'setup':
            result = fixture.setup()
        else:
            attempts = fixture.journal.export()
            if len(attempts) != 1 or attempts[0]['state'] != 'observed-complete':
                raise Refused('docker_variant_setup_incomplete')
            raw, _ = read_regular(fixture.root / 'baseline.json')
            result = fixture.inspect(json.loads(raw))
        print(json.dumps(result, sort_keys=True))
    finally:
        fixture.journal.close()


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'docker_variant_failed', 'product_acceptance': False}))
        sys.exit(74)
