#!/usr/bin/env python3
"""Acquire fixed public OCI bytes into private files; never contact Docker."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Refused, canonical, private_directory, write_new


IMAGES = (
    ('sonarr-observed', 'linuxserver/sonarr',
     '48e36b608b461273b9dae857725cd0561a127f2c694b687318f6d0c5ce63e5c9',
     'a674ae620ca7ce1246b377bcac13a7500567196cf2207059e68146fa4dc169f7',
     '076be80fcab2bd0acdea4c8c5f604318f2feb61aeeaacd71cfcb1983a8fb50bf',
     '4.0.20.3014-ls1'),
    ('radarr-observed', 'linuxserver/radarr',
     '084b3b2ab1d0ef930660727259546a241f2bdf67c9ed085d54bf1486a6887c9b',
     '41fdc1672209c2ef31c5260015ec8b96e3c75513e60a667eb052e1ff54b4cfa9',
     'a9b08c177649ae4e2c03f4ab375140ac8e633f87a781eeaa7a0e7f1e85b112a8',
     '6.4.4.10685-ls324'),
    ('sonarr-older', 'linuxserver/sonarr',
     'c19aa4ecdf03d73e1d5c901da33744cb7eb4d921f89bafed1ca264601d7fa224',
     '6b06eac65225627173c12f049d8b5c55c588cdb0b3faa667553559cbb51e1474',
     '8df16ac7fd59767b1fc4f15243578695ea6f8de7d4f2873a091364535e752aa3',
     '4.0.19.2979-ls322'),
)
ACCEPT = 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json'
LAYERS = {'application/vnd.oci.image.layer.v1.tar',
          'application/vnd.oci.image.layer.v1.tar+gzip',
          'application/vnd.oci.image.layer.v1.tar+zstd',
          'application/vnd.docker.image.rootfs.diff.tar.gzip'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


def digest_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024 ** 2:
            raise Refused('oci_blob_shape')
        digest = hashlib.sha256()
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise Refused('oci_blob_changed')
        return 'sha256:' + digest.hexdigest(), before.st_size
    finally:
        os.close(descriptor)


def descriptor(record, media_types, limit):
    if (not isinstance(record, dict) or record.get('mediaType') not in media_types
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(record.get('digest', '')))
            or type(record.get('size')) is not int or not 0 < record['size'] <= limit):
        raise Refused('oci_descriptor_unsupported')
    return record['digest'], record['size']


class Registry:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        self.tokens = {}

    def transfer(self, url, headers, sink, limit, seconds):
        def deadline(signum, frame):
            raise Refused('oci_request_deadline')
        previous = signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            for _ in range(4):
                try:
                    response = self.opener.open(urllib.request.Request(url, headers=headers), timeout=20)
                except urllib.error.HTTPError as error:
                    response = error
                if response.status in (301, 302, 303, 307, 308):
                    target = urllib.parse.urljoin(url, response.headers['Location'])
                    parsed = urllib.parse.urlsplit(target)
                    response.close()
                    if (parsed.scheme != 'https' or parsed.username or parsed.password
                            or parsed.hostname not in ('lscr.io', 'ghcr.io', 'pkg-containers.githubusercontent.com')):
                        raise Refused('oci_redirect_refused')
                    if parsed.hostname != urllib.parse.urlsplit(url).hostname:
                        headers = {key: value for key, value in headers.items()
                                   if key.lower() != 'authorization'}
                    url = target
                    continue
                if response.status != 200:
                    response.close()
                    raise Refused('oci_registry_request_failed')
                metadata = {'media_type': response.headers.get('Content-Type'),
                            'digest': response.headers.get('Docker-Content-Digest')}
                size = 0
                try:
                    while chunk := response.read1(65536):
                        size += len(chunk)
                        if size > limit:
                            raise Refused('oci_response_bound')
                        sink.write(chunk)
                finally:
                    response.close()
                return metadata
            raise Refused('oci_redirect_limit')
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    def small(self, url, headers, limit=1048576):
        import io
        sink = io.BytesIO()
        metadata = self.transfer(url, headers, sink, limit, 30)
        return sink.getvalue(), metadata

    def headers(self, repository):
        if repository not in self.tokens:
            query = urllib.parse.urlencode({'service': 'ghcr.io',
                                           'scope': 'repository:' + repository + ':pull'})
            raw, _ = self.small('https://ghcr.io/token?' + query,
                                {'Accept': 'application/json'}, 65536)
            data = json.loads(raw)
            token = data.get('token') or data.get('access_token')
            if not isinstance(token, str) or not 0 < len(token) <= 16384:
                raise Refused('oci_anonymous_token_unavailable')
            self.tokens[repository] = token
        return {'Accept': ACCEPT, 'Authorization': 'Bearer ' + self.tokens[repository]}

    def manifest(self, repository, digest):
        url = 'https://lscr.io/v2/' + repository + '/manifests/' + digest
        raw, metadata = self.small(url, self.headers(repository))
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest or metadata['digest'] != digest:
            raise Refused('oci_manifest_digest_mismatch')
        value = json.loads(raw)
        if value.get('schemaVersion') != 2 or metadata['media_type'] != value.get('mediaType'):
            raise Refused('oci_manifest_schema_mismatch')
        return raw, value


def publish_bytes(blobs, digest, raw):
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
        raise Refused('oci_content_digest_mismatch')
    path = blobs / digest.split(':')[1]
    if path.exists():
        if digest_file(path) != (digest, len(raw)):
            raise Refused('oci_existing_blob_mismatch')
    else:
        write_new(path, raw, 0o400)
    return path


def acquire_blob(registry, repository, record, blobs):
    digest, size = descriptor(record, LAYERS | {'application/vnd.oci.image.config.v1+json'},
                              512 * 1024 ** 2)
    path = blobs / digest.split(':')[1]
    if path.exists():
        if digest_file(path) != (digest, size):
            raise Refused('oci_existing_blob_mismatch')
        return
    temporary = blobs / ('.partial-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            registry.transfer('https://lscr.io/v2/' + repository + '/blobs/' + digest,
                              registry.headers(repository), stream, size, 900)
            stream.flush()
            os.fsync(fd)
        if digest_file(temporary) != (digest, size):
            raise Refused('oci_download_digest_mismatch')
        os.fchmod(fd, 0o400)
        # The acquisition process owns an exclusive cache lock throughout.
        os.rename(temporary, path)
        parent = os.open(blobs, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(fd)
    print(json.dumps({'event': 'blob-verified', 'digest': digest, 'bytes': size}), flush=True)


def acquire(cache):
    cache = private_directory(cache)
    lock = os.open(cache / 'acquire.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        layout = private_directory(cache / 'layout')
        blobs = private_directory(layout / 'blobs' / 'sha256')
        registry = Registry()
        report = {'schema': 1, 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'images': [], 'registry_signatures_verified': False,
                  'docker_or_runtime_operations': False,
                  'scope': 'Only the selected linux/amd64 closures; other index platforms are not acquired.'}
        selected_descriptors = []
        total = 0
        required_blobs = {}
        for name, repository, index_hex, child_hex, config_hex, version in IMAGES:
            index_digest = 'sha256:' + index_hex
            child_digest = 'sha256:' + child_hex
            config_digest = 'sha256:' + config_hex
            raw, index = registry.manifest(repository, index_digest)
            if index.get('mediaType') != 'application/vnd.oci.image.index.v1+json':
                raise Refused('oci_index_required')
            publish_bytes(blobs, index_digest, raw)
            required_blobs[index_digest] = len(raw)
            choices = [item for item in index.get('manifests', [])
                       if item.get('platform', {}).get('os') == 'linux'
                       and item.get('platform', {}).get('architecture') == 'amd64']
            if len(choices) != 1 or choices[0].get('digest') != child_digest:
                raise Refused('oci_platform_selection_mismatch')
            descriptor(choices[0], {'application/vnd.oci.image.manifest.v1+json'}, 1048576)
            raw, manifest = registry.manifest(repository, child_digest)
            if len(raw) != choices[0]['size']:
                raise Refused('oci_manifest_size_mismatch')
            publish_bytes(blobs, child_digest, raw)
            required_blobs[child_digest] = len(raw)
            configuration = manifest['config']
            descriptor(configuration, {'application/vnd.oci.image.config.v1+json'}, 1048576)
            if configuration['digest'] != config_digest or len(manifest.get('layers', [])) > 64:
                raise Refused('oci_configuration_mismatch')
            records = [configuration, *manifest['layers']]
            for record in records:
                _, size = descriptor(record, LAYERS | {'application/vnd.oci.image.config.v1+json'}, 512 * 1024 ** 2)
                if record['digest'] not in required_blobs:
                    total += size
                required_blobs[record['digest']] = size
                if total > 3 * 1024 ** 3:
                    raise Refused('oci_acquisition_total_bound')
                acquire_blob(registry, repository, record, blobs)
            configuration_data = json.loads((blobs / config_hex).read_bytes())
            if (configuration_data.get('os') != 'linux'
                    or configuration_data.get('architecture') != 'amd64'
                    or configuration_data.get('config', {}).get('Labels', {}).get('org.opencontainers.image.version') != version):
                raise Refused('oci_platform_or_version_mismatch')
            selected = dict(choices[0])
            selected['annotations'] = {
                'org.opencontainers.image.ref.name': 'lscr.io/' + repository + ':mpkg-fixture-' + name,
                'io.mpkg.source.index.digest': index_digest,
            }
            selected_descriptors.append(selected)
            report['images'].append({'fixture_name': name, 'repository': 'lscr.io/' + repository,
                                     'index_digest': index_digest, 'manifest_digest': child_digest,
                                     'config_digest': config_digest, 'platform': 'linux/amd64',
                                     'version_label': version,
                                     'blobs': [{'digest': item['digest'], 'size': item['size'],
                                                'media_type': item['mediaType']} for item in records]})
        # Snapshot metadata is immutable per acquisition run, not an overwrite of
        # the previous run's evidence. The shared blob cache remains reusable.
        snapshot = private_directory(cache / ('snapshot-' + uuid.uuid4().hex))
        write_new(snapshot / 'oci-layout', canonical({'imageLayoutVersion': '1.0.0'}))
        write_new(snapshot / 'index.json', canonical({'schemaVersion': 2,
                  'mediaType': 'application/vnd.oci.image.index.v1+json',
                  'manifests': selected_descriptors}))
        archive = snapshot / 'images.oci.tar'
        with tarfile.open(archive, 'x') as output:
            def add_file(path, name):
                info = output.gettarinfo(str(path), arcname=name)
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = 0
                info.mode = 0o444
                with path.open('rb') as stream:
                    output.addfile(info, stream)
            for filename in ('oci-layout', 'index.json'):
                add_file(snapshot / filename, filename)
            for digest, expected_size in sorted(required_blobs.items()):
                path = blobs / digest.split(':')[1]
                if digest_file(path) != (digest, expected_size):
                    raise Refused('oci_cached_blob_changed')
                add_file(path, 'blobs/sha256/' + path.name)
        with archive.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            os.fsync(stream.fileno())
        report['archive'] = {'filename': 'images.oci.tar', 'sha256': digest,
                             'bytes': archive.stat().st_size}
        report['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report['limits'] = ['Digest identity is not publisher signature trust.',
                            'Guest Docker OCI import and RepoDigest association remain unverified.',
                            'No layer archive is extracted or executed by this helper.']
        write_new(snapshot / 'acquisition.json', canonical(report) + b'\n')
        print(json.dumps({'status': 'acquired', 'evidence': str(snapshot / 'acquisition.json'),
                          'archive': str(archive), 'images': len(report['images'])}), flush=True)
    finally:
        os.close(lock)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.version_info[:2] != (3, 12):
        raise Refused('python_312_required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    acquire(args.cache.absolute())


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error)}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'failed', 'code': 'oci_acquisition_failed'}))
        sys.exit(74)
