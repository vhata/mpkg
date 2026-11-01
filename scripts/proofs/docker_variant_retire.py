#!/usr/bin/env python3
"""Exercise declared keep/delete boundaries after a disposable port experiment."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, read_regular, require_guest, write_new
from docker_baseline import BASE, MEDIA, SHARED, RADARR_ROOT, SENTINEL, metadata, preserve_initial_values, read_as_application
from docker_variant_experiment import Experiment, JournalView
from docker_variant_plan import NETWORK, VOLUME, read_config_archive
from docker_variants import reserve
from run import trusted_install


CASES = ('volume-keep', 'volume-delete', 'network-shared', 'network-exclusive-delete')


class Retirement(Experiment):
    def __init__(self, guest, variant):
        super().__init__(guest, variant)
        self.prior_directory = self.directory
        self.prior_records = {name: read_regular(self.prior_directory / name)[0]
                              for name in ('state.sqlite3', 'after.json', 'result.json')}
        self.changes = Journal(self.prior_directory)
        attempts = self.changes.export()
        result = json.loads(self.prior_records['result.json'])
        if (len(attempts) != 1 or attempts[0]['state'] != 'observed-complete'
                or result.get('guest_id') != guest or result.get('variant') != variant
                or result.get('status') != 'observed' or result.get('mechanism_only') is not True
                or result.get('assembly_database_sha256') != hashlib.sha256(self.original_database).hexdigest()
                or result.get('assembly_manifest_sha256') != hashlib.sha256(self.original_manifest).hexdigest()):
            raise Refused('docker_retirement_requires_complete_port_experiment')
        self.journal = JournalView(self.baseline_journal, self.changes)
        self.manifest = json.loads(self.prior_records['after.json'])
        expected = self.plan
        expected['applications']['sonarr']['port'] = 18990
        if (self.manifest.get('plan') != expected or self.manifest.get('guest_id') != guest
                or self.manifest.get('schema') != 1):
            raise Refused('docker_retirement_post_port_intent_changed')
        self.plan = self.manifest['plan']
        self.specs = self.plan['applications']
        self.network_id = self.manifest['network_id']
        self.image_ids = self.manifest['images']
        self.directory = self.root.parent / ('docker-retirement-' + variant)
        self.retirement = None

    def histories_unchanged(self):
        super().histories_unchanged()
        if any(read_regular(self.prior_directory / name)[0] != raw for name, raw in self.prior_records.items()):
            raise Refused('docker_retirement_prior_experiment_changed')

    def remaining(self):
        expected = ({self.manifest['resources']['container_ids']['radarr']} if 'radarr' in self.specs else set())
        actual = set(self.docker('ps', '--all', '--quiet', '--no-trunc').decode().splitlines())
        if actual != expected:
            raise Refused('docker_retirement_remaining_consumer_scope_changed')
        if 'radarr' in self.specs:
            container = self.container('radarr')
            if container['Id'] not in expected or not container['State']['Running']:
                raise Refused('docker_retirement_unmanaged_consumer_changed')
        return expected

    def volume_identity(self):
        self.remaining()
        value = json.loads(self.docker('volume', 'inspect', VOLUME))[0]
        fields = ('Name', 'Driver', 'Mountpoint', 'Labels', 'Options', 'Scope', 'CreatedAt')
        expected = {key: self.manifest['resources']['volume'][key] for key in fields}
        if ({key: value.get(key) for key in fields} != expected
                or set(self.docker('volume', 'ls', '--quiet').decode().splitlines()) != {VOLUME}):
            raise Refused('docker_retirement_volume_identity_changed')
        for role in self.specs:
            if role == 'sonarr':
                continue
            if any(item.get('Name') == VOLUME for item in self.container(role)['Mounts']):
                raise Refused('docker_retirement_volume_still_consumed')
        return expected

    def network_identity(self):
        expected_consumers = self.remaining()
        value = json.loads(self.docker('network', 'inspect', NETWORK))[0]
        fields = ('Id', 'Name', 'Driver', 'Scope', 'Labels', 'Options', 'IPAM')
        expected = {key: self.manifest['resources']['network'][key] for key in fields}
        if ({key: value.get(key) for key in fields} != expected
                or value.get('Internal') is not False or value.get('EnableIPv6') is not False
                or set(value.get('Containers', {})) != expected_consumers
                or set(self.docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines())
                != {'bridge', 'host', 'none', NETWORK}):
            raise Refused('docker_retirement_network_identity_or_consumers_changed')
        return dict(expected, consumers=sorted(expected_consumers))

    def keep_volume(self):
        before = self.volume_identity()
        helper = self.offline_volume_helper('keep')
        self.run_helper(helper)
        # Only the fixed metadata/readability shell ran, never Sonarr's entrypoint.
        raw, info = read_config_archive(self.docker('cp', helper + ':/config/config.xml', '-'), 'config.xml')
        if (info['uid'], info['gid'], info['mode']) != (963, 1001, '0o600'):
            raise Refused('docker_retirement_kept_config_metadata_changed')
        preserve_initial_values(self.protected(self.manifest['inputs']['sonarr']['assembled_xml']), raw)
        sentinel, info = read_config_archive(self.docker('cp', helper + ':/config/mpkg-fixture-sentinel', '-'),
                                            'mpkg-fixture-sentinel')
        if ((info['uid'], info['gid'], info['mode']) != (963, 1001, '0o640')
                or sentinel != ('mpkg fixture ' + self.guest + ' sonarr config\n').encode()):
            raise Refused('docker_retirement_kept_sentinel_changed')
        private = self.directory / 'kept-config.xml'
        write_new(private, raw)
        reference = self.retirement.capture(private)
        self.docker('rm', helper)
        if self.volume_identity() != before:
            raise Refused('docker_retirement_kept_volume_changed')
        return {'disposition': 'kept', 'identity': before, 'protected_config_reference': reference,
                'sentinel_unchanged': True, 'database_readable_metadata_check': True,
                'application_restarted_for_inspection': False}

    def source_and_data(self):
        metadata(MEDIA, 0, 0, 0o755, True)
        metadata(SHARED, 1500, 1001, 0o2770, True)
        metadata(SHARED / 'sentinel', 1500, 1001, 0o640)
        shared = ('mpkg fixture ' + self.guest + ' shared\n').encode()
        if read_regular(SHARED / 'sentinel')[0] != shared:
            raise Refused('docker_retirement_shared_data_changed')
        for role, references in self.manifest['inputs'].items():
            for name in ('compose.yaml', '.env'):
                metadata(BASE / role / name, 963, 962, 0o640)
                if not self.journal.unchanged(references[name], BASE / role / name):
                    raise Refused('docker_retirement_source_changed')
        if not self.plan['volume']:
            path = BASE / 'sonarr/config'
            metadata(path, 963, 1001, 0o2770, True)
            metadata(path / 'config.xml', 963, 1001, 0o600)
            preserve_initial_values(self.protected(self.manifest['inputs']['sonarr']['assembled_xml']),
                                    read_regular(path / 'config.xml')[0])
            metadata(path / 'mpkg-fixture-sentinel', 963, 1001, 0o640)
            if read_regular(path / 'mpkg-fixture-sentinel')[0] != ('mpkg fixture ' + self.guest + ' sonarr config\n').encode():
                raise Refused('docker_retirement_kept_bind_sentinel_changed')
        return shared

    def execute(self):
        if self.directory.exists() or self.directory.is_symlink():
            raise Refused('docker_retirement_fresh_attempt_required')
        before = self.inspect(self.manifest)
        self.histories_unchanged()
        reserve(self.directory)
        for name, raw in self.prior_records.items():
            write_new(self.directory / ('prior-' + name), raw)
        self.retirement = Journal(self.directory)
        attempt = str(uuid.uuid4())
        self.retirement.begin(attempt)
        stopped = self.stop_sonarr()
        self.docker('rm', stopped['Id'])
        self.remaining()
        disposition = None
        if self.plan['volume']:
            if self.plan['variant'] == 'volume-keep':
                disposition = self.keep_volume()
            else:
                identity = self.volume_identity()
                self.docker('volume', 'rm', VOLUME)
                if self.docker('volume', 'ls', '--quiet').strip():
                    raise Refused('docker_retirement_volume_absence_unverified')
                disposition = {'disposition': 'deleted', 'previous_identity': identity, 'remaining_consumers': []}
        else:
            identity = self.network_identity()
            if self.plan['variant'] == 'network-exclusive-delete':
                if identity['consumers']:
                    raise Refused('docker_retirement_network_still_shared')
                self.docker('network', 'rm', identity['Id'])
                if set(self.docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines()) != {'bridge', 'host', 'none'}:
                    raise Refused('docker_retirement_network_absence_unverified')
                disposition = {'disposition': 'deleted', 'previous_identity': identity}
            else:
                disposition = {'disposition': 'retained-shared', 'identity': identity}
        self.remaining()
        shared = self.source_and_data()
        unmanaged = None
        if 'radarr' in self.specs:
            metadata(RADARR_ROOT, 963, 1001, 0o2770, True)
            metadata(SENTINEL, 963, 1001, 0o2770, True)
            metadata(SENTINEL / 'sentinel', 963, 1001, 0o640)
            self.wait_ready('radarr')
            actual = self.attribution('radarr')
            if actual != before['applications']['radarr']['attribution']:
                raise Refused('docker_retirement_unmanaged_process_changed')
            self.config_access('radarr')
            read_as_application(SHARED / 'sentinel', shared, actual)
            read_as_application(SENTINEL / 'sentinel', ('mpkg fixture ' + self.guest + ' media\n').encode(), actual)
            if not self.shared_check(self.manifest):
                raise Refused('docker_retirement_shared_discovery_missing')
            self.published_ping('radarr')
            unmanaged = {'attribution': actual, 'directory_discovery': True,
                         'credential_free_published_route': self.plan['bridge']}
        for port in (18989, 18990):
            with socket.socket() as connection:
                connection.settimeout(2)
                if connection.connect_ex(('127.0.0.1', port)) != errno.ECONNREFUSED:
                    raise Refused('docker_retirement_sonarr_route_not_closed')
        self.engine(enabled=True)
        networks = {'bridge', 'host', 'none'} | ({NETWORK} if self.plan['variant'] == 'network-shared' else set())
        if set(self.docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines()) != networks:
            raise Refused('docker_retirement_final_network_scope_changed')
        volumes = {VOLUME} if self.plan['variant'] == 'volume-keep' else set()
        if set(self.docker('volume', 'ls', '--quiet').decode().splitlines()) != volumes:
            raise Refused('docker_retirement_final_volume_scope_changed')
        if self.plan['variant'] == 'network-shared' and self.network_identity() != disposition['identity']:
            raise Refused('docker_retirement_retained_network_changed')
        self.remaining()
        self.histories_unchanged()
        result = {'schema': 1, 'guest_id': self.guest, 'variant': self.plan['variant'], 'status': 'observed',
                  'mechanism_only': True, 'product_acceptance': False, 'removed_container': stopped['Id'],
                  'resource': disposition, 'unmanaged_radarr': unmanaged, 'shared_sentinel_unchanged': True,
                  'prior_histories_unchanged': True,
                  'prior_record_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in self.prior_records.items()},
                  'limits': ['Resource-only disposable retirement, not product removal or A1-A12 acceptance.',
                             'Compose source, accounts and shared native data are explicitly retained.',
                             'Kept-volume inspection starts only a fixed offline metadata helper, never the application.',
                             'No cleanup or retry follows an unresolved operation.']}
        write_new(self.directory / 'result.json', canonical(result) + b'\n')
        self.retirement.finish(attempt, 'observed-complete')
        return result


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', choices=CASES, required=True)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    fixture = Retirement(guest, args.variant)
    try:
        print(json.dumps(fixture.execute(), sort_keys=True))
    finally:
        fixture.baseline_journal.close()
        fixture.changes.close()
        if fixture.retirement is not None:
            fixture.retirement.close()


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'mechanism_only': True}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'docker_retirement_failed', 'mechanism_only': True}))
        sys.exit(74)
