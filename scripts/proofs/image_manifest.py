#!/usr/bin/env python3
"""Record observed local guest image/engine identities after reviewed import."""
import argparse
import json
import os
from pathlib import Path
import resource
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Refused, canonical, private_directory, require_guest, write_new
from compose_proof import CONFIG_DIGESTS, RADARR, SONARR
from run import ENV, command, trusted_install


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    inputs = private_directory(Path('/opt/mpkg-proof-inputs'))
    client = private_directory(inputs / 'docker-client')
    environment = dict(ENV, DOCKER_CONFIG=str(client))
    def docker(*args):
        return command(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *args],
                       env=environment)
    engine = docker('info', '--format', '{{.ID}}').decode().strip()
    if not engine or len(engine) > 256:
        raise Refused('engine_identity_unavailable')
    images = []
    for image in (SONARR, RADARR):
        value = json.loads(docker('image', 'inspect', image))[0]
        if (image not in value.get('RepoDigests', [])
                or value.get('Os') != 'linux' or value.get('Architecture') != 'amd64'
                or value.get('Id') not in (CONFIG_DIGESTS[image], image.split('@')[1])):
            raise Refused('imported_digest_association_unverified')
        images.append({'reference': image, 'image_id': value['Id'], 'platform': 'linux/amd64'})
    result = {'schema': 1, 'guest_id': guest, 'engine_id': engine, 'images': images}
    write_new(inputs / 'compose.json', canonical(result) + b'\n')
    print(json.dumps({'status': 'recorded', 'guest_id': guest, 'engine_id': engine}))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error)}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'failed', 'code': 'image_observation_failed'}))
        sys.exit(74)
