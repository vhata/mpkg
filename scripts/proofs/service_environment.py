"""Verify empty environment-file lists on the fixed guest service objects."""
from core import Refused
from run import command


OBJECTS = {
    'docker.service': 'docker_2eservice',
    'containerd.service': 'containerd_2eservice',
    'sshd.service': 'sshd_2eservice',
    'mpkg-fixture-external.service': 'mpkg_2dfixture_2dexternal_2eservice',
}


def verified_environment_files(unit, properties):
    """Normalize an omitted display field only after a typed empty-list read.

    Callers must have established the guest/install guards and loaded the
    fixed unit through systemctl show. Text output can omit an empty array;
    missing, unsupported or failed typed reads cannot establish emptiness.
    """
    if unit not in OBJECTS:
        raise Refused('service_environment_unit_unsupported')
    if 'EnvironmentFiles' in properties and properties['EnvironmentFiles'] != '':
        raise Refused('service_environment_files_not_empty')
    try:
        raw = command([
            '/usr/bin/busctl', '--system', '--no-pager', '--timeout=10s',
            'get-property', 'org.freedesktop.systemd1',
            '/org/freedesktop/systemd1/unit/' + OBJECTS[unit],
            'org.freedesktop.systemd1.Service', 'EnvironmentFiles',
        ], timeout=15)
    except Refused:
        raise Refused('service_environment_files_not_verified') from None
    if raw.strip() != b'a(sb) 0':
        raise Refused('service_environment_files_not_verified')
    return dict(properties, EnvironmentFiles='')
