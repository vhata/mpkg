#!/usr/bin/env python3
"""Prepare the real frozen audio conflict in an empty isolated guest database."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, private_directory, read_regular, require_guest, write_new
from experiments import fresh
from native_manifest import SOURCE_SHA256, trusted_json
from native_proof import artifact_path
from run import command, trusted_install


TARGETS = {'pulseaudio': '17.0+r134+g77d25a1e6-1', 'pipewire-pulse': '1:1.6.10-1'}
DATABASES = {'core': '89d479c3a28ecd789ddc6ab44d77888b423339a606f470f0684eac81c0d8b1e8',
             'extra': '2ca123a980d89533a5306f60ef904fdc2d06f3e52c52f59ba951d50613358bb6'}
RESOLUTION_SHA256 = '8d244c01ded92845bca5ffd757b77377d1cd182c6f2434ca0a4118cc54bcff26'

C_SOURCE = r'''
#define _GNU_SOURCE
#include <alpm.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int questions, question_mask, fetches;
static void fail(void) { fputs("real-conflict-refused\n", stderr); exit(74); }
static void question(void *context, alpm_question_t *value) {
    (void)context;
    questions++;
    question_mask |= value->type;
    value->any.answer = 0;
    if (value->type == ALPM_QUESTION_SELECT_PROVIDER) value->select_provider.use_index = -1;
}
static int fetch(void *context, const char *url, const char *path, int force) {
    (void)context; (void)url; (void)path; (void)force;
    fetches++;
    return -1;
}
static void guard(const char *guest, const char *fd_text) {
    struct stat info;
    char actual[128] = {0}, vendor[128] = {0}, delegated[128] = {0}, expected[128];
    if (geteuid() || strlen(guest) != 36) fail();
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (guest[i] != '-') fail();
        } else if (!isdigit((unsigned char)guest[i]) && !(guest[i] >= 'a' && guest[i] <= 'f')) fail();
    }
    if (lstat("/etc/mpkg-fixture/identity.json", &info) || !S_ISREG(info.st_mode) ||
        info.st_uid || info.st_gid || (info.st_mode & 0777) != 0600 || info.st_nlink != 1) fail();
    FILE *file = fopen("/sys/class/dmi/id/product_uuid", "r");
    if (!file || !fgets(actual, sizeof actual, file)) fail();
    fclose(file); actual[strcspn(actual, "\r\n")] = 0;
    if (strcasecmp(actual, guest)) fail();
    file = fopen("/sys/class/dmi/id/sys_vendor", "r");
    if (!file || !fgets(vendor, sizeof vendor, file)) fail();
    fclose(file);
    if (strcmp(vendor, "QEMU\n")) fail();
    unsigned int device_major, device_minor;
    file = fopen("/sys/class/block/vda2/dev", "r");
    if (!file || fscanf(file, "%u:%u", &device_major, &device_minor) != 2) fail();
    fclose(file);
    if (stat("/", &info) || major(info.st_dev) != device_major || minor(info.st_dev) != device_minor) fail();
    char serial[32] = "mpkg", observed_serial[128];
    size_t position = 4;
    for (size_t i = 0; guest[i] && position < 20; i++) if (guest[i] != '-') serial[position++] = guest[i];
    serial[position] = 0;
    file = fopen("/sys/class/block/vda/serial", "r");
    if (!file || !fgets(observed_serial, sizeof observed_serial, file)) fail();
    fclose(file); observed_serial[strcspn(observed_serial, "\r\n")] = 0;
    if (strcmp(serial, observed_serial)) fail();
    unsigned long long sectors;
    file = fopen("/sys/class/block/vda/size", "r");
    if (!file || fscanf(file, "%llu", &sectors) != 1 || sectors != 83886080ULL) fail();
    fclose(file);
    char *end;
    long descriptor = strtol(fd_text, &end, 10);
    if (*end || descriptor < 3 || descriptor > 1024 || fstat((int)descriptor, &info) || !S_ISFIFO(info.st_mode)) fail();
    snprintf(expected, sizeof expected, "MPKG-REAL-CONFLICT:%s\n", guest);
    if (read((int)descriptor, delegated, sizeof delegated - 1) < 0 || strcmp(delegated, expected)) fail();
    close((int)descriptor);
}
static int target(alpm_pkg_t *pkg) {
    const char *name = alpm_pkg_get_name(pkg), *version = alpm_pkg_get_version(pkg);
    if (!strcmp(name, "pulseaudio")) {
        if (strcmp(version, "17.0+r134+g77d25a1e6-1")) fail();
        return 1;
    }
    if (!strcmp(name, "pipewire-pulse")) {
        if (strcmp(version, "1:1.6.10-1")) fail();
        return 2;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) fail();
    guard(argv[1], argv[2]);
    if (strcmp(alpm_version(), "16.0.1")) fail();
    char base[256], root[512], database[512], path[512];
    snprintf(base, sizeof base, "/var/lib/mpkg-proofs/%s/native-real-conflict", argv[1]);
    snprintf(root, sizeof root, "%s/root/", base);
    snprintf(database, sizeof database, "%s/database/", base);
    alpm_errno_t error;
    alpm_handle_t *handle = alpm_initialize(root, database, &error);
    if (!handle || alpm_option_add_architecture(handle, "x86_64") ||
        alpm_option_set_questioncb(handle, question, NULL) || alpm_option_set_fetchcb(handle, fetch, NULL)) fail();
    alpm_db_t *core = alpm_register_syncdb(handle, "core", 0);
    alpm_db_t *extra = alpm_register_syncdb(handle, "extra", 0);
    if (!core || !extra || alpm_list_count(alpm_db_get_pkgcache(alpm_get_localdb(handle))) != 0) fail();
    if (alpm_trans_init(handle, 0)) fail();
    snprintf(path, sizeof path, "%s/candidates.tsv", base);
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid ||
        (info.st_mode & 0022) || info.st_nlink != 1 || info.st_size > 65536) fail();
    FILE *file = fdopen(fd, "r");
    if (!file) fail();
    char line[2048];
    int count = 0, selected = 0;
    while (fgets(line, sizeof line, file)) {
        if (!strchr(line, '\n')) fail();
        line[strcspn(line, "\n")] = 0;
        char *save, *repo = strtok_r(line, "\t", &save), *name = strtok_r(NULL, "\t", &save);
        char *version = strtok_r(NULL, "\t", &save);
        if (!repo || !name || !version || strtok_r(NULL, "\t", &save)) fail();
        alpm_db_t *db = !strcmp(repo, "core") ? core : !strcmp(repo, "extra") ? extra : NULL;
        alpm_pkg_t *pkg = db ? alpm_db_get_pkg(db, name) : NULL;
        if (!pkg || strcmp(alpm_pkg_get_version(pkg), version)) fail();
        selected |= target(pkg);
        if (alpm_add_pkg(handle, pkg)) fail();
        count++;
    }
    fclose(file);
    if (count != 167 || selected != 3) fail();
    alpm_list_t *errors = NULL;
    int prepared = alpm_trans_prepare(handle, &errors);
    error = alpm_errno(handle);
    if (prepared != -1 || error != ALPM_ERR_CONFLICTING_DEPS || fetches ||
        alpm_list_count(alpm_trans_get_remove(handle)) != 0 ||
        alpm_list_count(alpm_db_get_pkgcache(alpm_get_localdb(handle))) != 0) fail();
    int exact_pair = 0;
    for (alpm_list_t *item = errors; item; item = item->next) {
        alpm_conflict_t *conflict = item->data;
        int a = target(conflict->package1), b = target(conflict->package2);
        if ((a == 1 && b == 2) || (a == 2 && b == 1)) exact_pair = 1;
    }
    selected = 0;
    for (alpm_list_t *item = alpm_trans_get_add(handle); item; item = item->next) selected |= target(item->data);
    if (!exact_pair || selected != 3) fail();
    printf("{\"libalpm_version\":\"16.0.1\",\"prepare_result\":-1,\"error_number\":%d,"
           "\"exact_pair\":true,\"candidate_count\":167,\"removal_count\":0,\"local_package_count\":0,"
           "\"question_count\":%d,\"question_mask\":%d,\"all_questions_denied\":true,\"fetch_calls\":0}\n",
           error, questions, question_mask);
    alpm_list_free_inner(errors, (alpm_list_fn_free)alpm_conflict_free);
    alpm_list_free(errors);
    if (alpm_trans_release(handle) || alpm_release(handle)) fail();
    return 0;
}
'''


def parse_candidates(raw):
    if hashlib.sha256(raw).hexdigest() != RESOLUTION_SHA256:
        raise Refused('frozen_conflict_resolution_changed')
    rows = []
    names = set()
    for line in raw.decode().splitlines():
        fields = line.split()
        if len(fields) != 4:
            raise Refused('conflict_candidate_shape')
        repo, name, version, url = fields
        if (repo not in DATABASES or not re.fullmatch(r'[a-z0-9@._+-]+', name)
                or name in names or not url.startswith('https://archive.archlinux.org/repos/2026/10/30/' + repo + '/os/x86_64/')
                or not version or any(character in version for character in '\t\r\n')):
            raise Refused('conflict_candidate_identity')
        rows.append((repo, name, version))
        names.add(name)
    versions = {name: version for _, name, version in rows}
    if len(rows) != 167 or any(versions.get(name) != version for name, version in TARGETS.items()):
        raise Refused('real_frozen_conflict_targets_required')
    return rows


def validate_result(value):
    expected = {'libalpm_version': '16.0.1', 'prepare_result': -1, 'error_number': 46,
                'exact_pair': True, 'candidate_count': 167, 'removal_count': 0,
                'local_package_count': 0, 'all_questions_denied': True, 'fetch_calls': 0}
    if (any(value.get(key) != result for key, result in expected.items())
            or type(value.get('question_count')) is not int or value['question_count'] < 0
            or type(value.get('question_mask')) is not int or value['question_mask'] < 0):
        raise Refused('real_native_conflict_not_observed')


def run(guest):
    source, source_hash = trusted_json('source-inventory.json')
    if source_hash != SOURCE_SHA256:
        raise Refused('frozen_source_inventory_mismatch')
    selected = source['native_incompatible_requests']
    if (selected['independently_wanted_exact_requests'] != [name + '=' + version for name, version in TARGETS.items()]
            or selected['readonly_native_resolution']['stdout_sha256_computed'] != RESOLUTION_SHA256):
        raise Refused('frozen_conflict_declaration_mismatch')
    inputs = []
    for name, digest in DATABASES.items():
        record = {'name': name, 'path': '/opt/mpkg-proof-inputs/databases/2026-10-30/' + name + '.db', 'sha256': digest}
        artifact_path(record)
        inputs.append(record)
    directory = fresh(private_directory(Path('/var/lib/mpkg-proofs') / guest), 'native-real-conflict')
    root = private_directory(directory / 'root')
    database = private_directory(directory / 'database')
    private_directory(database / 'local')
    sync = private_directory(database / 'sync')
    for record in inputs:
        raw, _ = read_regular(Path(record['path']))
        if hashlib.sha256(raw).hexdigest() != record['sha256']:
            raise Refused('frozen_conflict_database_changed')
        write_new(sync / (record['name'] + '.db'), raw)
    cache = private_directory(directory / 'cache')
    keys = private_directory(directory / 'empty-keyring')
    config = directory / 'pacman.conf'
    content = ('[options]\nRootDir = ' + str(root) + '\nDBPath = ' + str(database) +
               '\nCacheDir = ' + str(cache) + '\nLogFile = ' + str(directory / 'pacman.log') +
               '\nGPGDir = ' + str(keys) + '\nArchitecture = x86_64\nSigLevel = Never\n' +
               ''.join('[' + name + ']\nServer = https://archive.archlinux.org/repos/2026/10/30/' + name + '/os/x86_64\n'
                       for name in DATABASES))
    write_new(config, content.encode())
    journal = Journal(directory)
    attempt = str(uuid.uuid4())
    journal.begin(attempt)
    try:
        # Print-only resolution selects the previously frozen dependency closure.
        # A network namespace additionally prevents outbound acquisition. This
        # candidate list is not itself evidence that the conflict was rejected.
        raw = command(['/usr/bin/unshare', '--net', '--', '/usr/bin/pacman', '--config', str(config),
                       '--sync', '--print', '--noconfirm', '--print-format', '%r %n %v %l',
                       *[name + '=' + version for name, version in TARGETS.items()]], timeout=90)
        candidates = parse_candidates(raw)
        write_new(directory / 'resolution.txt', raw)
        write_new(directory / 'candidates.tsv', ''.join('\t'.join(row) + '\n' for row in candidates).encode())
        c_path = directory / 'real-conflict.c'
        write_new(c_path, C_SOURCE.encode())
        binary = directory / 'real-conflict'
        command(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                 str(c_path), '-lalpm', '-o', str(binary)], timeout=90)
        binary.chmod(0o700)
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, ('MPKG-REAL-CONFLICT:' + guest + '\n').encode())
            os.close(write_fd)
            write_fd = None
            result = json.loads(command(['/usr/bin/unshare', '--net', '--', str(binary), guest, str(read_fd)],
                                        pass_fds=(read_fd,), timeout=90))
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
        validate_result(result)
        for record in inputs:
            artifact_path(record)
            if hashlib.sha256(read_regular(sync / (record['name'] + '.db'))[0]).hexdigest() != record['sha256']:
                raise Refused('private_conflict_metadata_changed')
        if list(cache.iterdir()):
            raise Refused('unexpected_conflict_download')
        result.update({'schema': 1, 'guest_id': guest, 'status': 'observed',
                       'case': 'frozen-pulseaudio-pipewire-pulse', 'metadata_only': True,
                       'exact_requests': TARGETS, 'repository_databases': inputs,
                       'source_inventory_sha256': source_hash, 'resolution_sha256': RESOLUTION_SHA256,
                       'c_probe_sha256': hashlib.sha256(C_SOURCE.encode()).hexdigest(),
                       'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                       'product_acceptance': False,
                       'limits': ['Empty private root/local database; no live package state imported.',
                                  'Frozen metadata only: no archive acquisition or artifact-signature claim.',
                                  'Actual prepare rejection is distinct from print-only resolution and synthetic conflict.',
                                  'No commit, refresh, download or package installation is requested.']})
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
    print(json.dumps(run(guest), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'native_real_conflict_failed', 'product_acceptance': False}))
        sys.exit(74)
