#!/usr/bin/env python3
"""Acquire only index-bound amd64 attestation metadata; never contact Docker."""
import datetime
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import re
import sys
import tarfile
import uuid

import runner
sys.path.insert(0, str(runner.PROJECT/'scripts/proofs'))
from core import Refused, canonical, private_directory, write_new
from oci_acquire import IMAGES, Registry, descriptor, digest_file, publish_bytes

SOURCE = Path('/home/vhata/src/mpkg/.cache/fixture-oci/snapshot-c37f5df672604499a7aedf2cdb1b93ff/images.oci.tar')
SOURCE_SHA256 = 'b7971f3427b643acb69dbe1e792dd105b3e01b4aa6f2e46ec3d7b474a2423aa1'
SOURCE_BYTES = 265943040
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
EMPTY = 'application/vnd.oci.empty.v1+json'
STAGE = {'stage': 'not-started'}
ATTESTATION = 'application/vnd.in-toto+json'
MAX_BLOB = 16*1024**2
MAX_TOTAL = 32*1024**2


def selected_attestation(index, child):
    matches = [item for item in index.get('manifests', [])
               if item.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest'
               and item.get('annotations', {}).get('vnd.docker.reference.digest') == 'sha256:'+child]
    if len(matches) != 1 or matches[0].get('platform') != {'architecture': 'unknown', 'os': 'unknown'}:
        raise Refused('oci_supplement_attestation_scope')
    descriptor(matches[0], {MANIFEST}, 65536)
    return matches[0]


def auxiliary_records(manifest):
    if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') != MANIFEST:
        raise Refused('oci_supplement_manifest_shape')
    config = manifest.get('config')
    descriptor(config, {CONFIG, EMPTY}, 65536)
    if config.get('mediaType') == EMPTY and (manifest.get('artifactType') != 'application/vnd.docker.attestation.manifest.v1+json'
            or config.get('size') != 2
            or config.get('digest') != 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'
            or config.get('data') != 'e30='):
        raise Refused('oci_supplement_empty_config_changed')
    layers = manifest.get('layers', [])
    if not isinstance(layers, list) or not 1 <= len(layers) <= 8:
        raise Refused('oci_supplement_layer_count')
    for layer in layers:
        descriptor(layer, {ATTESTATION}, MAX_BLOB)
    records = [config, *layers]
    if sum(item['size'] for item in records) > MAX_TOTAL:
        raise Refused('oci_supplement_metadata_total')
    return records


def source_indexes():
    runner.regular_file(SOURCE)
    if digest_file(SOURCE) != ('sha256:'+SOURCE_SHA256, SOURCE_BYTES):
        raise Refused('oci_supplement_source_archive_changed')
    with tarfile.open(SOURCE, 'r:') as archive:
        entries = {}
        for member in archive:
            if member.name in entries:
                raise Refused('oci_supplement_duplicate_archive_member')
            entries[member.name] = member
        result = {}
        for name, _, index, child, _, _ in IMAGES:
            member = entries.get('blobs/sha256/'+index)
            if (member is None or not member.isfile() or member.issparse() or member.pax_headers
                    or not 0 < member.size <= 65536):
                raise Refused('oci_supplement_original_index_shape')
            with archive.extractfile(member) as stream:
                raw = stream.read(65537)
            if len(raw) != member.size or hashlib.sha256(raw).hexdigest() != index:
                raise Refused('oci_supplement_original_index_digest')
            result[name] = selected_attestation(json.loads(raw), child)
        return result


def acquire():
    STAGE.update(stage='source-indexes')
    indexes = source_indexes()
    cache = private_directory(runner.CACHE/'oci-supplements')
    directory = private_directory(cache/('acquisition-'+uuid.uuid4().hex))
    blobs = private_directory(directory/'blobs/sha256')
    registry = Registry()
    report = {'schema': 1, 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_archive_sha256': SOURCE_SHA256, 'source_archive_bytes': SOURCE_BYTES,
              'images': [], 'docker_or_runtime_operations': False, 'registry_signatures_verified': False,
              'scope': 'Only selected amd64 attestation manifests, their config and in-toto JSON blobs; no arm64 or filesystem layers.'}
    total = 0
    for name, repository, index, child, _, _ in IMAGES:
        selected = indexes[name]
        digest, size = descriptor(selected, {MANIFEST}, 65536)
        STAGE.update(stage='attestation-manifest', fixture_name=name, digest=digest)
        raw, manifest = registry.manifest(repository, digest)
        if len(raw) != size:
            raise Refused('oci_supplement_manifest_size')
        publish_bytes(blobs, digest, raw)
        total += len(raw)
        STAGE.update(stage='attestation-descriptors')
        records = auxiliary_records(manifest)
        acquired = [{'digest': digest, 'size': size, 'mediaType': MANIFEST}]
        for record in records:
            digest, size = descriptor(record, {CONFIG, EMPTY, ATTESTATION}, MAX_BLOB)
            STAGE.update(stage='auxiliary-json', digest=digest)
            total += size
            if total > MAX_TOTAL:
                raise Refused('oci_supplement_complete_size_bound')
            if record['mediaType'] == EMPTY:
                data = base64.b64decode(record['data'], validate=True)
            else:
                sink = io.BytesIO()
                registry.transfer('https://lscr.io/v2/'+repository+'/blobs/'+digest,
                                  registry.headers(repository), sink, size, 120)
                data = sink.getvalue()
            if len(data) != size or 'sha256:'+hashlib.sha256(data).hexdigest() != digest:
                raise Refused('oci_supplement_blob_digest_or_size')
            if not isinstance(json.loads(data), dict):
                raise Refused('oci_supplement_auxiliary_json_shape')
            publish_bytes(blobs, digest, data)
            acquired.append({'digest': digest, 'size': size, 'mediaType': record['mediaType']})
        report['images'].append({'fixture_name': name, 'repository': repository,
                                'original_index_digest': 'sha256:'+index,
                                'selected_child_digest': 'sha256:'+child,
                                'attestation_descriptor': selected, 'blobs': acquired})
        print(json.dumps({'event': 'attestation-metadata-verified', 'fixture_name': name,
                          'blob_count': len(acquired), 'bytes': sum(item['size'] for item in acquired)}), flush=True)
    report['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['descriptor_bytes_total'] = total
    STAGE.update(stage='publish-report')
    write_new(directory/'acquisition.json', canonical(report)+b'\n')
    print(json.dumps({'status': 'acquired', 'directory': str(directory), 'bytes': total,
                      'report_sha256': digest_file(directory/'acquisition.json')[0],
                      'docker_or_runtime_operations': False}), flush=True)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    try:
        acquire()
    except Exception as error:
        code = str(error) if isinstance(error, Refused) else 'oci_attestation_metadata_acquisition_failed'
        if not re.fullmatch('[a-z0-9_]{1,96}', code):
            code = 'unexpected_refusal'
        failure = {'status': 'unverified', 'code': code, 'exception_type': type(error).__name__, **STAGE}
        if type(getattr(error, 'code', None)) is int:
            failure['http_status'] = error.code
        print(json.dumps(failure))
        sys.exit(74)
