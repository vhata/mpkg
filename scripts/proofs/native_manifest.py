#!/usr/bin/env python3
"""Bind acquired native inputs and an actual guest build to prepare-only proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Refused, canonical, private_directory, read_regular, require_guest, write_new
from native_proof import INPUTS, artifact_path
from run import command, trusted_install


SOURCE_SHA256 = 'c4713eff10cd435487a043a093e02bc596e88a10853e2d6e8ae7d3e384418c30'
TRUST = 'Arch master roots; full GPG validity'


def trusted_json(name):
    raw, metadata = read_regular(INPUTS / name)
    if metadata[4] != 0 or stat.S_IMODE(metadata[6]) & 0o022:
        raise Refused('native_evidence_not_trusted')
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def validate_build(record, source, guest):
    recipe = next(item for item in source['aur_packages']
                  if item['package_base'] == 'gitstatus')
    expected_files = {name: item['sha256_computed']
                      for name, item in recipe['recipe_files'].items()}
    expected_sources = sorted((item['filename'], algorithm, digest)
                              for item in recipe['sources']
                              for algorithm, digest in item['digests_published_in_recipe'].items())
    actual_sources = sorted((item['filename'], item['algorithm'], item['digest'])
                            for item in record['sources'] if item.get('verified') is True)
    if (record.get('schema') != 1 or record.get('guest_id') != guest
            or record.get('package_base') != 'gitstatus'
            or record.get('recipe_commit') != recipe['recipe_commit']
            or record.get('recipe_files') != expected_files
            or actual_sources != expected_sources
            or len(record['sources']) != len(expected_sources)
            or type(record.get('build_uid')) is not int or record['build_uid'] <= 0
            or record.get('source_verification_exit_code') != 0
            or record.get('generated_metadata_matches') is not True
            or record.get('build_exit_code') != 0
            or record.get('check_status') != 'not-defined'):
        raise Refused('actual_gitstatus_build_required')
    artifact = record['artifact']
    if (artifact.get('name') != 'gitstatus'
            or artifact.get('version') != recipe['srcinfo_version']
            or not re.fullmatch(r'[0-9a-f]{64}', artifact.get('sha256', ''))
            or type(artifact.get('size')) is not int or not 0 < artifact['size'] <= 2 * 1024 ** 3):
        raise Refused('gitstatus_artifact_invalid')
    return artifact


def validate_acquisition(record, planned, allowed_urls):
    digest = planned['package_sha256_published_in_database']
    if (record.get('name') != planned['name'] or record.get('version') != planned['version']
            or record.get('sha256') != digest or record.get('url') not in allowed_urls
            or record.get('trust') != TRUST
            or type(record.get('size')) is not int or not 0 < record['size'] <= 2 * 1024 ** 3
            or not re.fullmatch(r'[0-9a-f]{64}', record.get('signature_sha256', ''))
            or any(not re.fullmatch(r'[0-9A-F]{40}', record.get(field, ''))
                   for field in ('signing_fingerprint', 'primary_fingerprint'))):
        raise Refused('verified_native_acquisition_required')


def check_archive(record, source):
    path = INPUTS / 'artifacts' / (record['sha256'] + '.pkg.tar.zst')
    artifact_path({'path': str(path), 'sha256': record['sha256']})
    info = path.lstat()
    if info.st_nlink != 1 or info.st_size != record['size']:
        raise Refused('native_archive_identity')
    fields = {}
    raw = command(['/usr/bin/bsdtar', '-xOf', str(path), '.PKGINFO'])
    for line in raw.decode().splitlines():
        key, separator, value = line.partition(' = ')
        if separator and key in ('pkgname', 'pkgver', 'arch'):
            if key in fields:
                raise Refused('native_archive_metadata_ambiguous')
            fields[key] = value
    if (fields.get('pkgname') != record['name'] or fields.get('pkgver') != record['version']
            or fields.get('arch') not in ('x86_64', 'any') or path.lstat() != info):
        raise Refused('native_archive_metadata_mismatch')
    return {'name': record['name'], 'version': record['version'], 'path': str(path),
            'sha256': record['sha256'], 'source': source}


def assemble(guest):
    private_directory(INPUTS)
    if (INPUTS / 'native.json').exists():
        raise Refused('native_manifest_already_exists')
    source, source_hash = trusted_json('source-inventory.json')
    if source_hash != SOURCE_SHA256:
        raise Refused('frozen_source_inventory_mismatch')
    acquisition, acquisition_hash = trusted_json('native-acquisition.json')
    build, build_hash = trusted_json('gitstatus-build.json')
    built = validate_build(build, source, guest)
    target = source['native_update_target']
    acquired = {item['sha256']: item for item in acquisition}
    if len(acquired) != len(acquisition):
        raise Refused('duplicate_native_acquisition')
    allowed = {}
    for item in source['repository_packages'] + target['repository_packages']:
        identity = (item['name'], item['version'], item['package_sha256_published_in_database'])
        allowed.setdefault(identity, set()).add(item['url'])
    artifacts = []
    for item in target['repository_packages']:
        identity = (item['name'], item['version'], item['package_sha256_published_in_database'])
        record = acquired.get(identity[2])
        if record is None:
            raise Refused('target_archive_not_acquired')
        validate_acquisition(record, item, allowed[identity])
        artifacts.append(check_archive(record, 'repository'))
        signature = Path(artifacts[-1]['path'] + '.sig')
        artifact_path({'path': str(signature), 'sha256': record['signature_sha256']})
        if signature.lstat().st_nlink != 1 or not 0 < signature.stat().st_size <= 65536:
            raise Refused('native_signature_shape')
    artifacts.append(check_archive(built, 'fixture-build'))
    databases = []
    for item in target['repository_databases']:
        name = item['repository']
        if name not in ('core', 'extra'):
            raise Refused('native_repository_unsupported')
        record = {'name': name, 'path': str(INPUTS / 'databases' / '2026-10-31' / (name + '.db')),
                  'sha256': item['sha256_computed']}
        artifact_path(record)
        databases.append(record)
    versions = {item['name']: item['version'] for item in artifacts}
    observed = command(['/usr/bin/pacman', '--version']).decode()
    library = re.search(r'libalpm v([0-9.]+)', observed)
    if library is None or library[1] != source['resolver']['libalpm_version_observed']:
        raise Refused('native_library_version_mismatch')
    return {'schema': 1, 'guest_id': guest, 'libalpm_version': library[1],
            'repository_databases': databases, 'artifacts': artifacts,
            'targets': ['tmux', 'ripgrep', 'gitstatus'],
            'exact_versions': {name: versions[name] for name in ('tmux', 'ripgrep', 'gitstatus')},
            'coordinated_upgrade': {'name': 'gnupg', 'from': '2.4.9-3', 'to': '2.4.9-4'},
            'evidence': {'source_sha256': source_hash, 'acquisition_sha256': acquisition_hash,
                         'gitstatus_build_sha256': build_hash},
            'limits': ['Acquisition signature trust is bound prior evidence; libalpm rechecks signatures.',
                       'Build evidence is bound to bytes; reproducible-build equivalence is not claimed.',
                       'No package installation or repository refresh is performed.']}


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    manifest = assemble(guest)
    write_new(INPUTS / 'native.json', canonical(manifest) + b'\n')
    print(json.dumps({'status': 'recorded', 'guest_id': guest,
                      'artifact_count': len(manifest['artifacts'])}))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error)}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'failed', 'code': 'native_manifest_failed'}))
        sys.exit(74)
