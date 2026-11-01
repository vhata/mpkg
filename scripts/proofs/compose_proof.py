"""Real Compose/Sonarr experiment using only preacquired immutable images."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET

from core import (Journal, Refused, canonical, private_directory, read_regular,
                  replace_xml, write_new)
from experiments import expect_refusal, fresh, wait_for, worker_argv
from run import ENV, command


SONARR = 'lscr.io/linuxserver/sonarr@sha256:48e36b608b461273b9dae857725cd0561a127f2c694b687318f6d0c5ce63e5c9'
RADARR = 'lscr.io/linuxserver/radarr@sha256:084b3b2ab1d0ef930660727259546a241f2bdf67c9ed085d54bf1486a6887c9b'
CONFIG_DIGESTS = {
    SONARR: 'sha256:076be80fcab2bd0acdea4c8c5f604318f2feb61aeeaacd71cfcb1983a8fb50bf',
    RADARR: 'sha256:a9b08c177649ae4e2c03f4ab375140ac8e633f87a781eeaa7a0e7f1e85b112a8',
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


def config_xml(port, secret):
    return ('<Config><Port>' + str(port) + '</Port><BindAddress>127.0.0.1</BindAddress>'
            '<UrlBase></UrlBase><ApiKey>' + secret + '</ApiKey>'
            '<AuthenticationMethod>External</AuthenticationMethod>'
            '<InstanceName>mpkg proof unmanaged value</InstanceName>'
            '<LogLevel>info</LogLevel><UpdateMechanism>Docker</UpdateMechanism>'
            '</Config>').encode()


def run(guest, root):
    raw, info = read_regular(Path('/opt/mpkg-proof-inputs/compose.json'))
    manifest = json.loads(raw)
    if (info[4] != 0 or info[6] & 0o022 or manifest.get('schema') != 1
            or manifest.get('guest_id') != guest):
        raise Refused('compose_manifest_identity')
    directory = fresh(root, 'compose')
    client_config = private_directory(directory / 'docker-client')
    environment = dict(ENV, DOCKER_CONFIG=str(client_config), CHOICE='shell-choice',
                       PROOF_IMAGE=SONARR)

    def docker(*arguments, timeout=30):
        return command(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock',
                        *arguments], timeout=timeout, env=environment)

    if docker('info', '--format', '{{.ID}}').decode().strip() != manifest['engine_id']:
        raise Refused('engine_identity_changed')
    for image in (SONARR, RADARR):
        data = json.loads(docker('image', 'inspect', image))[0]
        if (data.get('Os') != 'linux' or data.get('Architecture') != 'amd64'
                or image not in data.get('RepoDigests', [])
                or data.get('Id') not in (CONFIG_DIGESTS[image], image.split('@')[1])):
            raise Refused('preacquired_image_identity_mismatch')
    for port in (19891, 19892, 19893):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', port))
    source = private_directory(directory / 'source')
    staged = private_directory(directory / 'captured')
    media = private_directory(directory / 'media')
    media_root = private_directory(media / 'probe')
    sentinel = private_directory(media_root / 'Mpkg Sentinel (2000)')
    for path in (media, media_root, sentinel):
        os.chown(path, 963, 1001)
        path.chmod(0o2770)
    config = private_directory(source / 'config')
    sonarr_key = uuid.uuid4().hex
    radarr_key = uuid.uuid4().hex
    write_new(config / 'config.xml', config_xml(19891, sonarr_key))
    runtime_secret = uuid.uuid4().hex
    write_new(source / '.env', b'CHOICE=file-choice\n')
    write_new(source / 'runtime.env',
              ('TOKEN=' + runtime_secret + "\nFIXTURE_LITERAL='kept$dollar'\n").encode())
    model = {'services': {'sonarr': {
        'image': '${PROOF_IMAGE}', 'platform': 'linux/amd64',
        'network_mode': 'host', 'restart': 'no',
        'environment': {'PUID': '963', 'PGID': '1001', 'UMASK': '002', 'TZ': 'UTC',
                        'PROOF_PRECEDENCE': '${CHOICE}', 'PROOF_DOLLAR': '$$HOME'},
        'env_file': ['./runtime.env'],
        'volumes': ['./config:/config', str(media) + ':/mnt/media'],
    }}}
    write_new(source / 'compose.yaml', canonical(model))
    project = 'mpkg-proof-' + guest[:8] + '-sonarr'
    radarr_project = 'mpkg-proof-' + guest[:8] + '-radarr'
    for name in (project, radarr_project):
        if docker('ps', '--all', '--quiet', '--filter',
                  'label=com.docker.compose.project=' + name).strip():
            raise Refused('fixture_project_already_exists')
    journal = Journal(directory)

    def action(operation):
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        value = operation()
        journal.finish(attempt, 'observed-complete')
        return value

    def compose(base, name, *arguments):
        return docker('compose', '--project-name', name,
                      '--project-directory', str(base), '--env-file', str(base / '.env'),
                      '-f', str(base / 'compose.yaml'), *arguments, timeout=120)

    captured = {}
    for filename in ('.env', 'runtime.env', 'compose.yaml'):
        captured[filename] = journal.capture(source / filename)
        journal.replay(captured[filename], staged / filename)
    frozen = json.loads((staged / 'compose.yaml').read_bytes())
    frozen['services']['sonarr']['volumes'][0] = str(config) + ':/config'
    frozen['services']['sonarr']['env_file'] = [str(staged / 'runtime.env')]
    (staged / 'compose.yaml').write_bytes(canonical(frozen))
    original = json.loads(compose(source, project, 'config', '--format', 'json'))
    replayed = json.loads(compose(staged, project, 'config', '--format', 'json'))
    if original != replayed:
        raise Refused('compose_replay_semantics_changed')
    if original['services']['sonarr']['environment']['PROOF_PRECEDENCE'] != 'shell-choice':
        raise Refused('compose_environment_precedence_changed')
    action(lambda: compose(staged, project, 'up', '--detach', '--no-build', '--pull', 'never'))

    def container(name):
        ids = docker('ps', '--all', '--quiet', '--filter',
                     'label=com.docker.compose.project=' + name).decode().splitlines()
        if len(ids) != 1:
            raise Refused('container_scope_changed')
        return json.loads(docker('inspect', ids[0]))[0]

    def attributed_request(name, process_name, port, route, *, key=None, body=None):
        before = container(name)
        if not before['State']['Running']:
            raise Refused('application_not_running')
        rows = docker('top', before['Id'], '-eo', 'pid,comm').decode().splitlines()[1:]
        pids = [int(row.split()[0]) for row in rows
                if len(row.split()) == 2 and row.split()[1] == process_name]
        if len(pids) != 1:
            raise Refused('application_process_ambiguous')
        pid = pids[0]
        process_start = Path('/proc/' + str(pid) + '/stat').read_bytes()
        status = Path('/proc/' + str(pid) + '/status').read_text().splitlines()
        values = {line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                  for line in status if ':' in line}
        if (set(values['Uid'].split()) != {'963'}
                or set(values['Gid'].split()) != {'1001'}
                or int(values['CapEff'], 16) != 0):
            raise Refused('application_credentials_changed')
        inodes = set()
        for row in Path('/proc/net/tcp').read_text().splitlines()[1:]:
            fields = row.split()
            if fields[1] == '0100007F:' + format(port, '04X') and fields[3] == '0A':
                inodes.add('socket:[' + fields[9] + ']')
        owned = {os.readlink(path) for path in Path('/proc/' + str(pid) + '/fd').iterdir()}
        if len(inodes & owned) != 1:
            raise Refused('listener_not_attributed')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        headers = {'Accept': 'application/json'}
        payload = None
        if key:
            headers['X-Api-Key'] = key
        if body is not None:
            payload = canonical(body)
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request('http://127.0.0.1:' + str(port) + route,
                                         data=payload, headers=headers)
        with opener.open(request, timeout=10) as response:
            raw = response.read(65537)
            code = response.status
        if len(raw) > 65536:
            raise Refused('application_response_bound')
        after = container(name)
        if (before['Id'] != after['Id'] or before['State']['StartedAt'] != after['State']['StartedAt']
                or process_start.split(b') ', 1)[1].split()[19] !=
                Path('/proc/' + str(pid) + '/stat').read_bytes().split(b') ', 1)[1].split()[19]):
            raise Refused('application_changed_during_probe')
        return code, raw

    def ready(name, process, port):
        def check():
            try:
                code, raw = attributed_request(name, process, port, '/ping')
                return code == 200 and raw.strip() == b'OK'
            except (Refused, OSError):
                return False
        wait_for(check, 120)

    ready(project, 'Sonarr', 19891)
    before = container(project)
    environment_values = dict(item.split('=', 1) for item in before['Config']['Env'])
    if (environment_values.get('PROOF_DOLLAR') != '$HOME'
            or environment_values.get('FIXTURE_LITERAL') != 'kept$dollar'
            or environment_values.get('TOKEN') != runtime_secret):
        raise Refused('compose_runtime_literal_changed')
    # Already-satisfied desired state intentionally dispatches no up/start call.
    ready(project, 'Sonarr', 19891)
    after = container(project)
    if before['Id'] != after['Id'] or before['State']['StartedAt'] != after['State']['StartedAt']:
        raise Refused('no_op_recreated_container')

    radarr_source = private_directory(directory / 'radarr')
    radarr_config = private_directory(radarr_source / 'config')
    write_new(radarr_config / 'config.xml', config_xml(19893, radarr_key))
    write_new(radarr_source / '.env', b'')
    write_new(radarr_source / 'compose.yaml', canonical({'services': {'radarr': {
        'image': RADARR, 'platform': 'linux/amd64', 'network_mode': 'host', 'restart': 'no',
        'environment': {'PUID': '963', 'PGID': '1001', 'UMASK': '002', 'TZ': 'UTC'},
        'volumes': [str(radarr_config) + ':/config', str(media) + ':/mnt/media'],
    }}}))
    action(lambda: compose(radarr_source, radarr_project, 'up', '--detach', '--no-build', '--pull', 'never'))
    ready(radarr_project, 'Radarr', 19893)
    code, raw = attributed_request(radarr_project, 'Radarr', 19893,
                                   '/api/v3/config/naming', key=radarr_key)
    if code != 200 or json.loads(raw)['movieFolderFormat'] != '{Movie Title} ({Release Year})':
        raise Refused('radarr_naming_fixture_changed')
    code, raw = action(lambda: attributed_request(
        radarr_project, 'Radarr', 19893, '/api/v3/rootfolder', key=radarr_key,
        body={'path': '/mnt/media/probe'}))
    if code != 201:
        raise Refused('radarr_create_status_unexpected')
    root_id = json.loads(raw)['id']
    if not isinstance(root_id, int) or root_id <= 0:
        raise Refused('radarr_root_identity_invalid')

    def shared_probe():
        code, raw = attributed_request(radarr_project, 'Radarr', 19893,
                                       '/api/v3/rootfolder/' + str(root_id) + '?timeout=true',
                                       key=radarr_key)
        data = json.loads(raw)
        if (code != 200 or data.get('id') != root_id or data.get('path') != '/mnt/media/probe'
                or data.get('accessible') is not True
                or not any(item.get('name') == 'Mpkg Sentinel (2000)' and
                           item.get('path') == '/mnt/media/probe/Mpkg Sentinel (2000)'
                           for item in (data.get('unmappedFolders') or []))):
            raise Refused('unmanaged_shared_consumer_failed')
    shared_probe()
    accepted, evidence = read_regular(config / 'config.xml')
    container_id = container(project)['Id']
    action(lambda: docker('stop', '--time', '10', container_id))
    stopped = container(project)
    if stopped['State']['Running'] or stopped['State']['Pid'] or stopped['HostConfig']['RestartPolicy']['Name'] != 'no':
        raise Refused('writer_exclusion_unverified')
    replacement = action(lambda: replace_xml(config / 'config.xml', accepted, evidence, 19892))
    action(lambda: docker('start', container_id))
    ready(project, 'Sonarr', 19892)
    if container(project)['Id'] != container_id:
        raise Refused('xml_change_recreated_container')
    active_xml = ET.fromstring((config / 'config.xml').read_bytes())
    if (active_xml.findtext('ApiKey') != sonarr_key or
            active_xml.findtext('InstanceName') != 'mpkg proof unmanaged value'):
        raise Refused('application_normalized_protected_value')
    normalized = (config / 'config.xml').read_bytes() != replacement
    shared_probe()
    action(lambda: docker('stop', '--time', '10', container_id))
    kept, evidence = read_regular(config / 'config.xml')
    action(lambda: docker('rm', container_id))
    if read_regular(config / 'config.xml') != (kept, evidence):
        raise Refused('kept_configuration_changed')
    shared_probe()
    # A genuine pre-edit drift on the retained, quiescent application file.
    (config / 'config.xml').write_bytes(kept + b'\n')
    expect_refusal('config_changed', lambda: replace_xml(
        config / 'config.xml', kept, evidence, 19891))
    (source / 'runtime.env').write_bytes(b'changed fixture input\n')
    if journal.unchanged(captured['runtime.env'], source / 'runtime.env'):
        raise Refused('compose_protected_drift_not_detected')
    journal.close()

    # A killed client leaves an actual daemon-owned container and unknown start.
    daemon_root = fresh(root, 'daemon')
    attempt = str(uuid.uuid4())
    process = subprocess.run(worker_argv(guest, 'daemon', attempt), env=environment,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if process.returncode != -9:
        raise Refused('daemon_worker_not_killed')
    daemon_name = 'mpkg-proof-' + guest[:8] + '-daemon'
    daemon = json.loads(docker('inspect', daemon_name))[0]
    if not daemon['State']['Running']:
        raise Refused('daemon_work_did_not_survive')
    unresolved = Journal(daemon_root)
    expect_refusal('unresolved_attempt', lambda: unresolved.begin(str(uuid.uuid4())))
    unresolved.close()
    docker('stop', '--time', '1', daemon['Id'])
    docker('rm', daemon['Id'])
    return {'status': 'observed', 'captured_render_equivalent': True,
            'runtime_env_and_dollars_preserved': True, 'satisfied_no_op_keeps_container': True,
            'offline_port_change_keeps_container': True, 'protected_unmanaged_values_kept': True,
            'application_serialization_changed': normalized,
            'kept_data_and_unmanaged_radarr_discovery': True,
            'preedit_and_secret_drift_blocked': True, 'daemon_outlives_worker': True,
            'unknown_daemon_attempt_blocks_overlap': True,
            'limits': ['No image acquisition, unplanned pull or build is permitted.',
                       'Radarr proves directory discovery, not media import or file contents.',
                       'Radarr and retained Sonarr data intentionally remain for inspection.',
                       'Daemon cleanup does not mark its interrupted attempt complete.',
                       'No A1-A12 product acceptance is established.']}
