#!/usr/bin/env python3
"""Acquire the frozen native fixture inputs; never install host packages."""
import argparse
import json
import os
import sys
from pathlib import Path
import tarfile

import runner

MANIFEST = runner.PROJECT / 'docs/fixtures/2026-10-31-arch-native-inputs.json'


def database_records(item):
    destination = runner.CACHE / 'native-metadata' / (item['sha256_computed'] + '.db')
    runner.download(item['url'], destination, 20 * 1024**2, item['sha256_computed'])
    records = {}
    with tarfile.open(destination) as archive:
        for member in archive:
            if not member.isfile() or not member.name.endswith('/desc'):
                continue
            if member.size > 1024**2:
                raise ValueError('oversized package metadata entry')
            fields = {}
            for block in archive.extractfile(member).read().decode().strip().split('\n\n'):
                lines = block.splitlines()
                fields[lines[0].strip('%')] = lines[1:]
            records[fields['NAME'][0]] = fields
    return records


def native_inputs():
    manifest = json.loads(MANIFEST.read_text())
    groups = [(manifest['repository_databases'], manifest['repository_packages']),
              (manifest['native_update_target']['repository_databases'],
               manifest['native_update_target']['repository_packages'])]
    selected = {}
    for databases, packages in groups:
        records = {item['repository']: database_records(item) for item in databases}
        for package in packages:
            record = records[package['repository']][package['name']]
            digest = package['package_sha256_published_in_database']
            if (record['VERSION'][0] != package['version']
                    or record['FILENAME'][0] != package['filename']
                    or record['SHA256SUM'][0] != digest):
                raise ValueError('frozen package record does not match its database')
            size = int(record['CSIZE'][0])
            if not 0 < size < 1024**3:
                raise ValueError('native archive size outside bounds')
            selected[digest] = {'name':package['name'], 'version':package['version'],
                                'sha256':digest, 'size':size, 'url':package['url']}
    return list(selected.values())


def acquire():
    cache = runner.private_directory(runner.CACHE)
    os.chmod(cache,0o700)
    home = runner.trust_home(cache)
    evidence = []
    for package in native_inputs():
        path = cache/'archives'/(package['sha256']+'.pkg.tar.zst')
        runner.download(package['url'],path,package['size'],package['sha256'],package['size'])
        signature=path.with_name(path.name+'.sig')
        runner.download(package['url']+'.sig',signature,16384)
        proof=runner.verify_signature(home,path,signature)
        evidence.append({**package,**proof})
        print(f"verified native {package['name']} {package['version']}",flush=True)
    runner.write_new(cache/'native-acquisition.json',(json.dumps(evidence,indent=2)+'\n').encode())


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['acquire'])
    parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error('Python 3.12 is required')
    os.umask(0o077)
    acquire()
