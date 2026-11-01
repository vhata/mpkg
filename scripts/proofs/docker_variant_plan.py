"""Closed fixture variants and private namespace/file observation primitives."""
import io
import os
from pathlib import Path
import re
import tarfile
import urllib.request

from compose_proof import NoRedirect, RADARR, SONARR
from core import Refused
from oci_acquire import IMAGES


VARIANTS = ('volume-keep', 'volume-delete', 'network-shared', 'network-exclusive-delete',
            'docker-update-allowed-tag', 'docker-exact-digest')
VOLUME = 'mpkg-fixture-sonarr-config'
NETWORK = 'mpkg-fixture-shared'
OLDER = next('lscr.io/' + repository + '@sha256:' + index
             for name, repository, index, _, _, _ in IMAGES if name == 'sonarr-older')
BASE = Path('/opt/docker')


def variant_plan(name):
    if name not in VARIANTS:
        raise Refused('docker_variant_unsupported')
    bridge = name.startswith('network-')
    volume = name.startswith('volume-')
    older = name.startswith('docker-')
    roles = ('sonarr',) if name == 'network-exclusive-delete' else ('sonarr', 'radarr')
    applications = {}
    for role in roles:
        port = 18989 if role == 'sonarr' else 17878
        applications[role] = {
            'project': 'mpkg-fixture-' + name + '-' + role, 'service': role,
            'process': 'Sonarr' if role == 'sonarr' else 'Radarr', 'port': port,
            'image': OLDER if older and role == 'sonarr' else SONARR if role == 'sonarr' else RADARR,
            'directory': str(BASE / role), 'config_volume': VOLUME if volume and role == 'sonarr' else None,
            'network': NETWORK if bridge else None,
        }
    wanted = {'image': applications['sonarr']['image'], 'platform': 'linux/amd64',
              'exact_image': True, 'updates_allowed': False}
    if name == 'docker-update-allowed-tag':
        wanted = {'image': 'lscr.io/linuxserver/sonarr:latest', 'platform': 'linux/amd64',
                  'exact_image': False, 'updates_allowed': True}
    return {'variant': name, 'applications': applications, 'bridge': bridge,
            'volume': VOLUME if volume else None, 'network': NETWORK if bridge else None,
            'wanted_declaration': wanted,
            'resolved_sonarr_execution': applications['sonarr']['image'],
            'accepted_update_candidate': SONARR if older else None,
            'fresh_older_database_required': older,
            'retirement_declaration': ('keep-volume' if name == 'volume-keep' else
                                       'delete-exclusive-volume' if name == 'volume-delete' else
                                       'retain-shared-network' if name == 'network-shared' else
                                       'delete-exclusive-network' if name == 'network-exclusive-delete' else None)}


def compose_document(plan, role):
    spec = plan['applications'][role]
    config = ({'type': 'volume', 'source': 'configuration', 'target': '/config', 'read_only': False,
               'volume': {'nocopy': True}} if spec['config_volume'] else
              {'type': 'bind', 'source': './config', 'target': '/config', 'read_only': False,
               'bind': {'create_host_path': False}})
    service = {'image': '${FIXTURE_IMAGE}', 'platform': 'linux/amd64', 'restart': 'unless-stopped',
               'environment': {key: '${' + key + '}' for key in ('PUID', 'PGID', 'UMASK', 'TZ')},
               'volumes': [config, {'type': 'bind', 'source': '/mnt/media', 'target': '/mnt/media',
                                    'read_only': False, 'bind': {'create_host_path': False}}]}
    result = {'services': {role: service}}
    if spec['network']:
        service['networks'] = ['fixture']
        service['ports'] = [{'target': spec['port'], 'published': str(spec['port']),
                             'host_ip': '127.0.0.1', 'protocol': 'tcp'}]
        result['networks'] = {'fixture': {'external': True, 'name': NETWORK}}
    else:
        service['network_mode'] = 'host'
    if spec['config_volume']:
        result['volumes'] = {'configuration': {'external': True, 'name': VOLUME}}
    return result


def read_config_archive(raw, expected_name):
    """Read one bounded regular Docker-cp member in memory, never extract it."""
    if expected_name not in ('config.xml', 'mpkg-fixture-sentinel') or len(raw) > 1048576:
        raise Refused('docker_variant_config_archive_bound')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        member = archive.next()
        if (member is None or member.name != expected_name or not member.isfile()
                or member.issparse() or member.linkname or not 0 < member.size <= 65536
                or any(key not in ('mtime', 'atime', 'ctime') or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value)
                       for key, value in member.pax_headers.items())):
            raise Refused('docker_variant_config_archive_shape')
        stream = archive.extractfile(member)
        with stream:
            data = stream.read(65537)
        if len(data) != member.size or archive.next() is not None:
            raise Refused('docker_variant_config_archive_scope')
        return data, {'uid': member.uid, 'gid': member.gid, 'mode': oct(member.mode), 'bytes': member.size}


class NamespaceOpener:
    """Enter a held application namespace only in bounded_request's child."""
    def __init__(self, descriptor, identity):
        self.descriptor = descriptor
        self.identity = identity
        self.parent = os.getpid()

    def open(self, request, timeout):
        if os.getpid() == self.parent:
            raise Refused('docker_variant_namespace_requires_private_child')
        before = os.fstat(self.descriptor)
        if (before.st_dev, before.st_ino) != self.identity:
            raise Refused('docker_variant_namespace_handle_changed')
        os.setns(self.descriptor, os.CLONE_NEWNET)
        current = os.stat('/proc/self/ns/net')
        if (current.st_dev, current.st_ino) != self.identity:
            raise Refused('docker_variant_namespace_entry_failed')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        return opener.open(request, timeout=timeout)
