#!/usr/bin/env python3
"""Resume only the initialized, image-only Docker checkpoint in the bound VM."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import sqlite3
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, private_directory, read_regular, require_guest, write_new
from docker_ready import (DROPIN, UNITS, assert_unit, check_absent_configuration,
                          package_units, process_identity, properties, socket_identity)
from image_import import validate_acquisition
from native_manifest import trusted_json
from native_service import trusted_path
from oci_acquire import IMAGES
from run import ENV, command, trusted_install


def state_root(guest):
    return Path('/var/lib/mpkg-proofs') / guest


def reserve_attempt(root):
    directory = root / 'docker-resume'
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise Refused('docker_resume_fresh_restore_required') from None
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return private_directory(directory)


def completed_result(directory, guest):
    """Read prior evidence without opening it as a writable Journal."""
    trusted_path(directory, directory=True)
    result_path, database = directory / 'result.json', directory / 'state.sqlite3'
    trusted_path(result_path)
    trusted_path(database)
    raw, _ = read_regular(result_path)
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        if (connection.execute('SELECT recovery_required FROM store_guard').fetchall() != [(0,)]
                or connection.execute('SELECT terminal FROM attempts').fetchall() != [('observed-complete',)]
                or connection.execute('SELECT kind FROM events ORDER BY seq').fetchall()
                != [('started',), ('observed-complete',)]):
            raise Refused('docker_resume_prior_attempt_not_complete')
    finally:
        connection.close()
    value = json.loads(raw)
    if value.get('schema') != 1 or value.get('guest_id') != guest or value.get('status') != 'observed':
        raise Refused('docker_resume_prior_result_not_observed')
    return value, hashlib.sha256(raw).hexdigest()


def image_bindings(imported, acquisition, engine):
    archive = validate_acquisition(acquisition)
    if (imported.get('engine_id') != engine or imported.get('archive_sha256') != archive['sha256']
            or imported.get('load_command_completed') is not True
            or imported.get('unverified_associations') != []):
        raise Refused('docker_resume_import_not_bound')
    observed = imported.get('verified_associations', [])
    bindings = {item['reference']: item['image_id'] for item in observed}
    expected = {'lscr.io/' + repository + '@sha256:' + index: {'sha256:' + index, 'sha256:' + config}
                for _, repository, index, _, config, _ in IMAGES}
    if (len(observed) != len(expected) or set(bindings) != set(expected)
            or any(bindings[reference] not in allowed for reference, allowed in expected.items())):
        raise Refused('docker_resume_three_image_bindings_required')
    return bindings


def unit_state(unit, value, active):
    if active:
        assert_unit(unit, value, started=True)
        return
    executable = UNITS[unit][1]
    expected_dropin = '/etc/systemd/system/' + unit + '.d/50-mpkg-fixture.conf' if executable else ''
    if (value.get('DropInPaths') != expected_dropin
            or (executable and value.get('LimitCORE') != '0')
            or value.get('SubState') != 'dead'):
        raise Refused('docker_resume_inactive_unit_mismatch')
    # The initial-readiness validator expects no drop-in before startup.
    # Validate the existing fixed drop-in above and its bytes separately.
    assert_unit(unit, dict(value, DropInPaths=''), started=False)


def units(provenance, active):
    values = {}
    for unit in UNITS:
        path = Path('/usr/lib/systemd/system') / unit
        trusted_path(path)
        if hashlib.sha256(read_regular(path)[0]).hexdigest() != provenance[unit]['unit_sha256']:
            raise Refused('docker_resume_package_unit_drift')
        if UNITS[unit][1]:
            path = Path('/etc/systemd/system') / (unit + '.d') / '50-mpkg-fixture.conf'
            trusted_path(path)
            if read_regular(path)[0] != DROPIN:
                raise Refused('docker_resume_dropin_drift')
        values[unit] = properties(unit)
        unit_state(unit, values[unit], active)
    check_absent_configuration()
    return values


def offline_empty_containers():
    # Docker must not restart a container before we can inspect the API.
    # This is an additional pre-start check of its fixed default data root,
    # not a general parser or repair of arbitrary Docker storage versions.
    path = Path('/var/lib/docker/containers')
    trusted_path(path, directory=True)
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            raise Refused('docker_resume_offline_containers_present')


def quiescent():
    for name in ('/run/docker.sock', '/run/containerd/containerd.sock', '/run/docker.pid'):
        path = Path(name)
        if path.exists() or path.is_symlink():
            raise Refused('docker_resume_runtime_state_present')
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            name = (process / 'comm').read_text().strip()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if name in ('dockerd', 'containerd') or name.startswith('containerd-shim'):
            raise Refused('docker_resume_daemon_process_present')
    jobs = command(['/usr/bin/systemctl', 'list-jobs', '--no-legend', '--no-pager', '--all'])
    if any(unit in line.split() for line in jobs.decode().splitlines() for unit in UNITS):
        raise Refused('docker_resume_unit_job_pending')
    offline_empty_containers()


def verify_engine(value, engine, bindings):
    if (value.get('ID') != engine or value.get('ServerVersion') != '29.9.2'
            or value.get('OSType') != 'linux' or value.get('Architecture') != 'x86_64'
            or value.get('DockerRootDir') != '/var/lib/docker'
            or value.get('Containers') != 0 or value.get('Images') != len(set(bindings.values()))
            or value.get('Swarm', {}).get('LocalNodeState') != 'inactive'):
        raise Refused('docker_resume_engine_mismatch')


def verify_image(value, reference, image_id, version):
    if (value.get('Id') != image_id or reference not in value.get('RepoDigests', [])
            or value.get('Os') != 'linux' or value.get('Architecture') != 'amd64'
            or value.get('Config', {}).get('Labels', {}).get('org.opencontainers.image.version') != version):
        raise Refused('docker_resume_image_association_changed')


def no_application_state(root):
    for path in (Path('/opt/docker'), root / 'docker-baseline', root / 'compose', root / 'daemon'):
        if path.exists() or path.is_symlink():
            raise Refused('docker_resume_application_state_present')


def resume(guest):
    root = state_root(guest)
    no_application_state(root)
    readiness, readiness_hash = completed_result(root / 'docker-readiness', guest)
    imported, import_hash = completed_result(root / 'image-import', guest)
    engine = readiness.get('engine_id')
    if not isinstance(engine, str) or not engine or len(engine) > 256 or readiness.get('enabled_services') is not False:
        raise Refused('docker_resume_readiness_binding_missing')
    acquisition, acquisition_hash = trusted_json('acquisition.json')
    bindings = image_bindings(imported, acquisition, engine)
    compose, compose_hash = trusted_json('compose.json')
    current = {'lscr.io/' + repository + '@sha256:' + index: bindings['lscr.io/' + repository + '@sha256:' + index]
               for name, repository, index, _, _, _ in IMAGES if name != 'sonarr-older'}
    recorded = compose.get('images', [])
    if (compose.get('schema') != 1 or compose.get('guest_id') != guest or compose.get('engine_id') != engine
            or len(recorded) != len(current)
            or {item['reference']: item['image_id'] for item in recorded} != current
            or any(item.get('platform') != 'linux/amd64' for item in recorded)):
        raise Refused('docker_resume_compose_binding_changed')
    provenance = package_units()
    if provenance != readiness.get('packages_and_units'):
        raise Refused('docker_resume_unit_provenance_changed')
    group = grp.getgrnam('docker')
    if group.gr_mem or any(user.pw_gid == group.gr_gid for user in pwd.getpwall()):
        raise Refused('docker_resume_group_not_empty')
    units(provenance, active=False)
    quiescent()
    directory = reserve_attempt(root)
    client = private_directory(directory / 'docker-client')
    environment = dict(ENV, DOCKER_CONFIG=str(client))
    journal = Journal(directory)
    try:
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        # A timeout or later mismatch leaves the durable start unresolved.
        # Never stop, retry, reload units, import images or enable startup.
        command(['/usr/bin/systemctl', 'start', 'docker.service'], timeout=90)
        observed = units(provenance, active=True)
        processes = {unit: process_identity(observed[unit], UNITS[unit][1].split()[0])
                     for unit in ('docker.service', 'containerd.service')}
        socket = socket_identity(group.gr_gid, processes['docker.service'])

        def docker(*arguments):
            return command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments], env=environment)

        verify_engine(json.loads(docker('info', '--format', '{{json .}}')), engine, bindings)
        if docker('container', 'ls', '--all', '--quiet').strip() or docker('volume', 'ls', '--quiet').strip():
            raise Refused('docker_resume_not_image_only')
        actual_ids = set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines())
        if actual_ids != set(bindings.values()):
            raise Refused('docker_resume_extra_or_missing_image')
        images = []
        for name, repository, index, manifest, config, version in IMAGES:
            reference = 'lscr.io/' + repository + '@sha256:' + index
            value = json.loads(docker('image', 'inspect', reference))[0]
            verify_image(value, reference, bindings[reference], version)
            images.append({'reference': reference, 'image_id': value['Id'], 'platform': 'linux/amd64',
                           'index_digest': 'sha256:' + index, 'manifest_digest': 'sha256:' + manifest,
                           'config_digest': 'sha256:' + config, 'version_label': version})
        networks = [json.loads(line) for line in docker('network', 'ls', '--format', '{{json .}}').splitlines()]
        if (len(networks) != 3 or {(item.get('Name'), item.get('Driver'), item.get('Scope')) for item in networks}
                != {('bridge', 'bridge', 'local'), ('host', 'host', 'local'), ('none', 'null', 'local')}):
            raise Refused('docker_resume_nondefault_network')
        verify_engine(json.loads(docker('info', '--format', '{{json .}}')), engine, bindings)
        observed = units(provenance, active=True)
        for unit, original in processes.items():
            if process_identity(observed[unit], original['executable']) != original:
                raise Refused('docker_resume_process_changed_during_check')
        if socket_identity(group.gr_gid, processes['docker.service']) != socket:
            raise Refused('docker_resume_socket_changed_during_check')
        result = {'schema': 1, 'guest_id': guest, 'status': 'observed', 'engine_id': engine,
                  'source_evidence_sha256': {'readiness': readiness_hash, 'import': import_hash,
                                             'acquisition': acquisition_hash, 'compose': compose_hash},
                  'images': images, 'containers': 0, 'volumes': 0, 'default_networks_only': True,
                  'enabled_services': False, 'processes': processes, 'socket': socket,
                  'product_acceptance': False,
                  'limits': ['Resume of the independently restored image-only fixture; no product history.',
                             'Only fixed Docker service startup was requested; no image or application mutation.',
                             'Offline empty container metadata is checked before daemon startup.',
                             'No stop, retry or cleanup is authorized by an incomplete resume attempt.']}
        write_new(directory / 'result.json', canonical(result) + b'\n')
        journal.finish(attempt, 'observed-complete')
        return result
    finally:
        journal.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    print(json.dumps(resume(guest), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'docker_resume_failed', 'product_acceptance': False}))
        sys.exit(74)
