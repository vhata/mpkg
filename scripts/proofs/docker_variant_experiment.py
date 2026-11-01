#!/usr/bin/env python3
"""Run fixed disposable port/retirement or version-intent mechanism experiments."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, change_xml_port, read_regular, require_guest, write_new
from docker_baseline import BASE, make_file, preserve_initial_values
from docker_variant_plan import NETWORK, VOLUME, VARIANTS, compose_document, read_config_archive
from docker_variants import Variant, reserve
from run import trusted_install


def atomic_bytes(path, expected_raw, expected_identity, replacement):
    """Publish only after the fixed caller has stopped the accepted writer."""
    raw, evidence = read_regular(path)
    if raw != expected_raw or evidence != expected_identity or os.listxattr(path):
        raise Refused('docker_experiment_file_drift')
    temporary = path.parent / ('.mpkg-fixture-' + uuid.uuid4().hex)
    write_new(temporary, replacement)
    try:
        os.chown(temporary, evidence[4], evidence[5])
        temporary.chmod(stat.S_IMODE(evidence[6]))
        descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if read_regular(path) != (raw, evidence):
            raise Refused('docker_experiment_file_drift')
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def preserved_resources(before, after, *, replacement):
    """Only the selected Sonarr container may change during the fixed action."""
    if set(before) != set(after) or set(before['container_ids']) != set(after['container_ids']):
        raise Refused('docker_experiment_resource_scope_changed')
    for role, identifier in before['container_ids'].items():
        if role != 'sonarr' or not replacement:
            if after['container_ids'][role] != identifier:
                raise Refused('docker_experiment_unselected_container_changed')
    for kind in ('volume', 'network'):
        if kind in before:
            original = {key: value for key, value in before[kind].items() if key != 'consumers'}
            current = {key: value for key, value in after[kind].items() if key != 'consumers'}
            if original != current:
                raise Refused('docker_experiment_resource_identity_changed')


class JournalView:
    def __init__(self, baseline, changes):
        self.baseline, self.changes = baseline, changes

    def resolve(self, reference):
        if type(reference) is dict and set(reference) == {'experiment'}:
            return self.changes, reference['experiment']
        if type(reference) is str:
            return self.baseline, reference
        raise Refused('docker_experiment_protected_reference_shape')

    def unchanged(self, reference, path):
        journal, reference = self.resolve(reference)
        return journal.unchanged(reference, path)


class Experiment(Variant):
    def __init__(self, guest, variant):
        super().__init__(guest, variant)
        self.baseline_journal = self.journal
        self.changes = None
        self.directory = self.root.parent / ('docker-experiment-' + variant)
        self.original_database = read_regular(self.root / 'state.sqlite3')[0]
        self.original_manifest = read_regular(self.root / 'baseline.json')[0]
        attempts = self.baseline_journal.export()
        if len(attempts) != 1 or attempts[0]['state'] != 'observed-complete':
            raise Refused('docker_experiment_requires_complete_assembly')
        self.manifest = json.loads(self.original_manifest)

    def protected(self, reference):
        if self.changes is None:
            return super().protected(reference)
        journal, key = self.journal.resolve(reference)
        row = journal.db.execute('SELECT bytes FROM protected WHERE id=?', (key,)).fetchone()
        if row is None:
            raise Refused('docker_experiment_protected_reference_missing')
        return row[0]

    def capture_bytes(self, name, raw):
        path = self.directory / name
        write_new(path, raw)
        return {'experiment': self.changes.capture(path)}

    def capture_path(self, path):
        return {'experiment': self.changes.capture(path)}

    def histories_unchanged(self):
        if (read_regular(self.root / 'state.sqlite3')[0] != self.original_database
                or read_regular(self.root / 'baseline.json')[0] != self.original_manifest):
            raise Refused('docker_experiment_original_assembly_changed')

    def start(self):
        if self.directory.exists() or self.directory.is_symlink():
            raise Refused('docker_experiment_fresh_attempt_required')
        before = self.inspect(self.manifest)
        reserve(self.directory)
        write_new(self.directory / 'assembly-before.sqlite3', self.original_database)
        write_new(self.directory / 'assembly-before.json', self.original_manifest)
        self.changes = Journal(self.directory)
        self.journal = JournalView(self.baseline_journal, self.changes)
        self.before = before
        self.original_radarr = before['applications'].get('radarr', {}).get('attribution')
        return before

    def stop_sonarr(self):
        process = self.attribution('sonarr')
        container = self.container('sonarr')
        if not container['State']['Running']:
            raise Refused('docker_experiment_requires_running_sonarr')
        self.docker('stop', '--time', '30', container['Id'], timeout=45)
        stopped = self.container('sonarr')
        if (stopped['Id'] != container['Id'] or stopped['State']['Running'] or stopped['State']['Pid'] != 0
                or stopped['State']['Status'] != 'exited'):
            raise Refused('docker_experiment_sonarr_stop_unverified')
        path = Path('/proc') / str(process['pid']) / 'stat'
        try:
            start = path.read_bytes().rsplit(b')', 1)[1].split()[19].decode()
        except FileNotFoundError:
            start = None
        if start == process['start_ticks']:
            raise Refused('docker_experiment_application_writer_still_present')
        if self.objects() != self.manifest['resources']:
            raise Refused('docker_experiment_stopped_resource_drift')
        return stopped

    def objects(self):
        if not self.plan['bridge']:
            return super().objects()
        containers = {role: self.container(role) for role in self.specs}
        if all(item['State']['Running'] for item in containers.values()):
            return super().objects()
        expected = {value['Id'] for value in containers.values()}
        if set(self.docker('ps', '--all', '--quiet', '--no-trunc').decode().splitlines()) != expected:
            raise Refused('docker_experiment_stopped_consumer_scope_changed')
        if self.docker('volume', 'ls', '--quiet').strip():
            raise Refused('docker_experiment_unexpected_volume')
        if set(self.docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines()) != {'bridge', 'host', 'none', NETWORK}:
            raise Refused('docker_experiment_network_scope_changed')
        value = json.loads(self.docker('network', 'inspect', NETWORK))[0]
        active = {item['Id'] for item in containers.values() if item['State']['Running']}
        if (value.get('Id') != self.network_id or value.get('Name') != NETWORK or value.get('Driver') != 'bridge'
                or value.get('Scope') != 'local' or value.get('Labels') != self.labels()
                or value.get('Internal') is not False or value.get('EnableIPv6') is not False
                or value.get('Options') not in (None, {}) or set(value.get('Containers', {})) != active):
            raise Refused('docker_experiment_stopped_network_changed')
        network = {key: value.get(key) for key in ('Id', 'Name', 'Driver', 'Scope', 'Labels', 'Options', 'IPAM')}
        # Docker's live endpoint list omits stopped containers. Their accepted
        # attachment configuration is independently checked by container().
        network['consumers'] = sorted(expected)
        return {'container_ids': {role: item['Id'] for role, item in containers.items()}, 'network': network}

    def offline_volume_helper(self, purpose, *, input_directory=None):
        if purpose not in ('port', 'keep'):
            raise Refused('docker_experiment_helper_scope')
        name = 'mpkg-fixture-' + self.plan['variant'] + '-' + purpose
        readonly = purpose == 'keep'
        mount = 'type=volume,source=' + VOLUME + ',target=/config,volume-nocopy' + (',readonly' if readonly else '')
        arguments = ['create', '--pull', 'never', '--platform', 'linux/amd64', '--name', name,
                     '--network', 'none', '--read-only', '--user', '963:1001', '--cap-drop', 'ALL',
                     '--security-opt', 'no-new-privileges', '--mount', mount]
        script = 'test -f /config/sonarr.db && test -s /config/sonarr.db && test -r /config/sonarr.db'
        if purpose == 'port':
            if input_directory != self.directory / 'offline-port-input':
                raise Refused('docker_experiment_helper_input_scope')
            arguments += ['--mount', 'type=bind,source=' + str(input_directory) + ',target=/input,readonly']
            script = ('umask 077; set -C; cat /input/next.xml > /config/mpkg-fixture-port-next.xml && '
                      'sync /config/mpkg-fixture-port-next.xml && cmp /input/before.xml /config/config.xml && '
                      'mv /config/mpkg-fixture-port-next.xml /config/config.xml && sync /config/config.xml && sync /config')
        arguments += ['--entrypoint', '/bin/sh', self.specs['sonarr']['image'], '-c', script]
        identifier = self.docker(*arguments).decode().strip()
        if len(identifier) != 64 or any(char not in '0123456789abcdef' for char in identifier):
            raise Refused('docker_experiment_helper_identity')
        value = json.loads(self.docker('inspect', identifier))[0]
        mounts = {item['Destination']: item for item in value['Mounts']}
        if (value['Id'] != identifier or value['Image'] != self.image_ids['sonarr']['image_id']
                or value['State']['Running'] or value['State']['Status'] != 'created'
                or value['Config'].get('User') != '963:1001' or value['Config'].get('Entrypoint') != ['/bin/sh']
                or value['Config'].get('Cmd') != ['-c', script] or value['HostConfig']['NetworkMode'] != 'none'
                or not value['HostConfig']['ReadonlyRootfs'] or value['HostConfig']['Privileged']
                or set(mounts) != ({'/config', '/input'} if purpose == 'port' else {'/config'})
                or mounts['/config'].get('Name') != VOLUME or mounts['/config'].get('RW') != (not readonly)
                or (purpose == 'port' and (mounts['/input'].get('Source') != str(input_directory)
                                          or mounts['/input'].get('RW') is not False))):
            raise Refused('docker_experiment_helper_configuration_changed')
        return identifier

    def run_helper(self, identifier):
        self.docker('start', identifier)
        if self.docker('wait', identifier, timeout=30).strip() != b'0':
            raise Refused('docker_experiment_helper_failed')
        value = json.loads(self.docker('inspect', identifier))[0]
        if value['Id'] != identifier or value['State']['Running'] or value['State']['ExitCode'] != 0:
            raise Refused('docker_experiment_helper_completion_unknown')

    def volume_port(self, stopped, raw, updated):
        inputs = reserve(self.directory / 'offline-port-input')
        os.chown(inputs, 963, 1001)
        make_file(inputs / 'before.xml', raw, 963, 1001, 0o400)
        make_file(inputs / 'next.xml', updated, 963, 1001, 0o400)
        helper = self.offline_volume_helper('port', input_directory=inputs)
        # Every other accepted consumer is stopped. The private read-only
        # comparison input detects intervening bytes immediately before mv.
        current, _ = self.config_file('sonarr', 'config.xml')
        if current != raw or self.container('sonarr')['Id'] != stopped['Id']:
            raise Refused('docker_experiment_prepublication_xml_drift')
        self.run_helper(helper)
        if self.config_file('sonarr', 'config.xml')[0] != updated:
            raise Refused('docker_experiment_volume_xml_publish_unverified')
        self.docker('rm', helper)

    def checked_after(self, *, replacement):
        resources = self.objects()
        preserved_resources(self.manifest['resources'], resources, replacement=replacement)
        self.manifest['resources'] = resources
        self.manifest['plan'] = copy.deepcopy(self.plan)
        self.manifest['images'] = self.images()
        self.image_ids = self.manifest['images']
        after = self.inspect(self.manifest)
        if self.original_radarr is not None and after['applications']['radarr']['attribution'] != self.original_radarr:
            raise Refused('docker_experiment_unmanaged_radarr_restarted')
        self.histories_unchanged()
        return after

    def port_change(self):
        attempt = str(uuid.uuid4())
        self.changes.begin(attempt)
        self.attempt = attempt
        with socket.socket() as port:
            port.bind(('127.0.0.1', 18990))
        stopped = self.stop_sonarr()
        raw, _ = self.config_file('sonarr', 'config.xml')
        references = self.manifest['inputs']['sonarr']
        preserve_initial_values(self.protected(references['assembled_xml']), raw)
        updated = change_xml_port(raw, 18990)
        self.capture_bytes('port-before.xml', raw)
        if self.plan['volume']:
            self.volume_port(stopped, raw, updated)
        else:
            path = BASE / 'sonarr/config/config.xml'
            local, evidence = read_regular(path)
            if local != raw:
                raise Refused('docker_experiment_bind_xml_drift')
            atomic_bytes(path, raw, evidence, updated)
        references['initial_xml'] = self.capture_bytes('port-initial.xml', change_xml_port(self.protected(references['initial_xml']), 18990))
        references['assembled_xml'] = self.capture_bytes('port-assembled.xml', updated)
        self.specs['sonarr']['port'] = 18990
        if self.plan['bridge']:
            path = BASE / 'sonarr/compose.yaml'
            raw, evidence = read_regular(path)
            if not self.journal.unchanged(references['compose.yaml'], path):
                raise Refused('docker_experiment_compose_preedit_drift')
            atomic_bytes(path, raw, evidence, canonical(compose_document(self.plan, 'sonarr')) + b'\n')
            references['compose.yaml'] = self.capture_path(path)
            references['rendered'] = self.capture_bytes('port-rendered.json', self.compose('sonarr', 'config', '--format', 'json'))
        self.compose('sonarr', 'up', '--detach', '--no-build', '--pull', 'never')
        self.wait_ready('sonarr')
        after = self.checked_after(replacement=self.plan['bridge'])
        write_new(self.directory / 'port-result.json', canonical(after) + b'\n')
        return after

    def update(self):
        previous = self.specs['sonarr']['image']
        candidate = self.plan['accepted_update_candidate']
        self.specs['sonarr']['image'] = candidate
        try:
            candidate_images = self.images()
        finally:
            self.specs['sonarr']['image'] = previous
        attempt = str(uuid.uuid4())
        self.changes.begin(attempt)
        self.attempt = attempt
        wanted = self.plan['wanted_declaration']
        if wanted['exact_image'] or not wanted['updates_allowed']:
            self.histories_unchanged()
            after = self.inspect(self.manifest)
            if after['applications'] != self.before['applications'] or after['resources'] != self.before['resources']:
                raise Refused('docker_experiment_exact_pin_changed')
            result = {'candidate_blocked_by_exact_intent': True, 'image_change_requested': False,
                      'wanted': wanted, 'candidate': self.plan['accepted_update_candidate']}
        else:
            self.stop_sonarr()
            path = BASE / 'sonarr/.env'
            raw, evidence = read_regular(path)
            references = self.manifest['inputs']['sonarr']
            if not self.journal.unchanged(references['.env'], path):
                raise Refused('docker_experiment_update_input_drift')
            expected = ('FIXTURE_IMAGE=' + previous + '\nPUID=963\nPGID=1001\nUMASK=002\nTZ=America/Los_Angeles\n').encode()
            if raw != expected:
                raise Refused('docker_experiment_update_input_shape')
            atomic_bytes(path, raw, evidence, raw.replace(previous.encode(), candidate.encode(), 1))
            self.specs['sonarr']['image'] = candidate
            self.plan['resolved_sonarr_execution'] = candidate
            references['.env'] = self.capture_path(path)
            references['rendered'] = self.capture_bytes('update-rendered.json', self.compose('sonarr', 'config', '--format', 'json'))
            self.image_ids = self.images()
            if self.image_ids != candidate_images:
                raise Refused('docker_experiment_candidate_changed_after_planning')
            self.compose('sonarr', 'up', '--detach', '--no-build', '--pull', 'never')
            self.wait_ready('sonarr')
            after = self.checked_after(replacement=True)
            result = {'candidate_blocked_by_exact_intent': False, 'image_change_requested': True,
                      'wanted': wanted, 'previous': previous, 'accepted_candidate': candidate, 'observation': after}
        self.histories_unchanged()
        write_new(self.directory / 'update-result.json', canonical(result) + b'\n')
        return result

    def execute(self):
        self.start()
        if self.plan['fresh_older_database_required']:
            result = self.update()
        else:
            result = self.port_change()
        result = {'schema': 1, 'guest_id': self.guest, 'variant': self.plan['variant'],
                  'status': 'observed', 'mechanism_only': True, 'product_acceptance': False,
                  'assembly_database_unchanged': True, 'observation': result,
                  'assembly_database_sha256': hashlib.sha256(self.original_database).hexdigest(),
                  'assembly_manifest_sha256': hashlib.sha256(self.original_manifest).hexdigest(),
                  'limits': ['Disposable mechanism experiment, not product adoption or A1-A12 acceptance.',
                             'No automatic retry, rollback or cleanup after an unresolved operation.',
                             'Retirement is a separate experiment and remains unexecuted here.']}
        write_new(self.directory / 'after.json', canonical(self.manifest) + b'\n')
        write_new(self.directory / 'result.json', canonical(result) + b'\n')
        self.changes.finish(self.attempt, 'observed-complete')
        return result


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', choices=VARIANTS, required=True)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    experiment = Experiment(guest, args.variant)
    try:
        print(json.dumps(experiment.execute(), sort_keys=True))
    finally:
        experiment.baseline_journal.close()
        if experiment.changes is not None:
            experiment.changes.close()


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'mechanism_only': True}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'docker_experiment_failed', 'mechanism_only': True}))
        sys.exit(74)
