/* Prepare only. There is deliberately no commit, fetch, or DB refresh API. */
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

static int questions;
static char *rows[40000];
static size_t count;

static void fail(void) { fputs("probe-refused\n", stderr); exit(74); }

static void question(void *context, alpm_question_t *value) {
    (void)context;
    questions = 1;
    value->any.answer = 0;
}

static void safe(const char *value) {
    if (!value || strlen(value) > 4096 || strpbrk(value, "\t\r\n")) fail();
}

static void row(const char *kind, const char *a, const char *b, int reason) {
    safe(a); safe(b);
    if (count == 40000 || asprintf(&rows[count], "%s\t%s\t%s\t%d\n",
                                  kind, a, b, reason) < 0) fail();
    count++;
}

static int compare(const void *a, const void *b) {
    return strcmp(*(char * const *)a, *(char * const *)b);
}

static void package_rows(alpm_pkg_t *pkg, const char *kind) {
    const char *name = alpm_pkg_get_name(pkg);
    row(kind, name, alpm_pkg_get_version(pkg),
        !strcmp(kind, "I") ? alpm_pkg_get_reason(pkg) : 0);
    if (strcmp(kind, "A")) return;
    for (alpm_list_t *p = alpm_pkg_get_depends(pkg); p; p = p->next) {
        char *text = alpm_dep_compute_string(p->data);
        row("D", name, text, 0); free(text);
    }
    for (alpm_list_t *p = alpm_pkg_get_provides(pkg); p; p = p->next) {
        char *text = alpm_dep_compute_string(p->data);
        row("P", name, text, 0); free(text);
    }
}

static void guard(const char *guest, const char *fd_text) {
    struct stat info;
    char actual[128] = {0}, vendor[128] = {0}, delegated[128] = {0};
    char expected[128];
    if (geteuid() || strlen(guest) != 36) fail();
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (guest[i] != '-') fail();
        } else if (!isdigit((unsigned char)guest[i]) &&
                   !(guest[i] >= 'a' && guest[i] <= 'f')) fail();
    }
    if (lstat("/etc/mpkg-fixture/identity.json", &info) ||
        !S_ISREG(info.st_mode) || info.st_uid || info.st_gid ||
        (info.st_mode & 0777) != 0600 || info.st_nlink != 1) fail();
    FILE *file = fopen("/sys/class/dmi/id/product_uuid", "r");
    if (!file || !fgets(actual, sizeof actual, file)) fail();
    fclose(file);
    actual[strcspn(actual, "\r\n")] = 0;
    if (strcasecmp(actual, guest)) fail();
    file = fopen("/sys/class/dmi/id/sys_vendor", "r");
    if (!file || !fgets(vendor, sizeof vendor, file)) fail();
    fclose(file);
    if (strcmp(vendor, "QEMU\n")) fail();
    unsigned int device_major, device_minor;
    file = fopen("/sys/class/block/vda2/dev", "r");
    if (!file || fscanf(file, "%u:%u", &device_major, &device_minor) != 2) fail();
    fclose(file);
    if (stat("/", &info) || major(info.st_dev) != device_major ||
        minor(info.st_dev) != device_minor) fail();
    char serial[32] = "mpkg", observed_serial[128];
    size_t position = 4;
    for (size_t i = 0; guest[i] && position < 20; i++)
        if (guest[i] != '-') serial[position++] = guest[i];
    serial[position] = 0;
    file = fopen("/sys/class/block/vda/serial", "r");
    if (!file || !fgets(observed_serial, sizeof observed_serial, file)) fail();
    fclose(file);
    observed_serial[strcspn(observed_serial, "\r\n")] = 0;
    if (strcmp(serial, observed_serial)) fail();
    unsigned long long sectors;
    file = fopen("/sys/class/block/vda/size", "r");
    if (!file || fscanf(file, "%llu", &sectors) != 1 || sectors != 83886080ULL) fail();
    fclose(file);
    char *end;
    long descriptor = strtol(fd_text, &end, 10);
    if (*end || descriptor < 3 || descriptor > 1024 ||
        fstat((int)descriptor, &info) || !S_ISFIFO(info.st_mode)) fail();
    snprintf(expected, sizeof expected, "MPKG-PROOF:%s\n", guest);
    ssize_t length = read((int)descriptor, delegated, sizeof delegated - 1);
    if (length < 0 || strcmp(delegated, expected)) fail();
    close((int)descriptor);
}

static FILE *private_file(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid ||
        (info.st_mode & 0022) || info.st_nlink != 1 || info.st_size > 8 * 1024 * 1024)
        fail();
    FILE *file = fdopen(fd, "r");
    if (!file) fail();
    return file;
}

int main(int argc, char **argv) {
    if (argc != 4) fail();
    guard(argv[2], argv[3]);
    int staged = !strcmp(argv[1], "stage");
    if (!staged && strcmp(argv[1], "compare")) fail();
    char base[256], path[512], database[512];
    snprintf(base, sizeof base, "/var/lib/mpkg-proofs/%s/native", argv[2]);
    snprintf(database, sizeof database, "%s/staged-db/", base);
    alpm_errno_t error;
    alpm_handle_t *handle = alpm_initialize("/", staged ? database : "/var/lib/pacman/", &error);
    if (!handle) fail();
    if (alpm_option_set_gpgdir(handle, "/etc/pacman.d/gnupg/") ||
        alpm_option_add_architecture(handle, "x86_64") ||
        alpm_option_set_questioncb(handle, question, NULL)) fail();
    if (staged) {
        const char *names[] = {"core", "extra"};
        for (size_t i = 0; i < 2; i++) {
            if (!alpm_register_syncdb(handle, names[i],
                    ALPM_SIG_PACKAGE | ALPM_SIG_DATABASE | ALPM_SIG_DATABASE_OPTIONAL)) fail();
        }
    }
    if (alpm_trans_init(handle, 0)) fail();
    if (staged && alpm_sync_sysupgrade(handle, 0)) fail();
    snprintf(path, sizeof path, "%s/targets.list", base);
    FILE *targets = private_file(path);
    char target[256];
    while (fgets(target, sizeof target, targets)) {
        target[strcspn(target, "\n")] = 0;
        if (!*target || strspn(target, "abcdefghijklmnopqrstuvwxyz0123456789@._+-") != strlen(target)) fail();
        if (!staged) continue;
        alpm_pkg_t *found = NULL;
        for (alpm_list_t *db = alpm_get_syncdbs(handle); db && !found; db = db->next)
            found = alpm_db_get_pkg(db->data, target);
        if (found && alpm_add_pkg(handle, found)) fail();
        /* File-backed AUR targets are added below. */
    }
    fclose(targets);
    snprintf(path, sizeof path, "%s/packages.list", base);
    FILE *packages = private_file(path);
    char line[8192];
    while (fgets(line, sizeof line, packages)) {
        line[strcspn(line, "\n")] = 0;
        char *save;
        char *source = strtok_r(line, "\t", &save);
        char *name = strtok_r(NULL, "\t", &save);
        char *version = strtok_r(NULL, "\t", &save);
        char *artifact = strtok_r(NULL, "\t", &save);
        if (!source || !name || !version || !artifact || strtok_r(NULL, "\t", &save)) fail();
        int repository = !strcmp(source, "repository");
        if (!repository && strcmp(source, "fixture-build")) fail();
        if (strncmp(artifact, "/opt/mpkg-proof-inputs/", 23) &&
            (strncmp(artifact, base, strlen(base)) || artifact[strlen(base)] != '/')) fail();
        if (strstr(artifact, "/../") || strstr(artifact, "/./")) fail();
        if (staged && repository) continue;
        if (staged) {
            snprintf(path, sizeof path, "%s/targets.list", base);
            targets = private_file(path);
            int wanted = 0;
            while (fgets(target, sizeof target, targets)) {
                target[strcspn(target, "\n")] = 0;
                if (!strcmp(target, name)) wanted = 1;
            }
            fclose(targets);
            if (!wanted) continue;
        }
        alpm_pkg_t *pkg = NULL;
        if (alpm_pkg_load(handle, artifact, 1,
                          repository ? ALPM_SIG_PACKAGE : 0, &pkg)) fail();
        if (strcmp(alpm_pkg_get_name(pkg), name) ||
            strcmp(alpm_pkg_get_version(pkg), version) || alpm_add_pkg(handle, pkg)) fail();
    }
    fclose(packages);
    alpm_list_t *errors = NULL;
    if (alpm_trans_prepare(handle, &errors)) {
        error = alpm_errno(handle);
        if (error == ALPM_ERR_UNSATISFIED_DEPS) puts("BLOCK missing-dependency");
        else if (error == ALPM_ERR_CONFLICTING_DEPS) puts("BLOCK conflict");
        else fail();
        alpm_trans_release(handle); alpm_release(handle);
        return 0;
    }
    if (questions) {
        puts("BLOCK native-question");
        alpm_trans_release(handle); alpm_release(handle);
        return 0;
    }
    row("V", alpm_version(), "libalpm", 0);
    for (alpm_list_t *p = alpm_db_get_pkgcache(alpm_get_localdb(handle)); p; p = p->next)
        package_rows(p->data, "I");
    for (alpm_list_t *p = alpm_trans_get_add(handle); p; p = p->next)
        package_rows(p->data, "A");
    for (alpm_list_t *p = alpm_trans_get_remove(handle); p; p = p->next)
        package_rows(p->data, "R");
    qsort(rows, count, sizeof *rows, compare);
    if (staged) {
        for (size_t i = 0; i < count; i++) fputs(rows[i], stdout);
    } else {
        snprintf(path, sizeof path, "%s/accepted.plan", base);
        FILE *accepted = private_file(path);
        int matched = 1;
        for (size_t i = 0; i < count; i++) {
            if (!fgets(line, sizeof line, accepted) || strcmp(line, rows[i])) matched = 0;
        }
        if (fgetc(accepted) != EOF) matched = 0;
        fclose(accepted);
        puts(matched ? "MATCH" : "BLOCK prepared-set-mismatch");
    }
    alpm_trans_release(handle);
    alpm_release(handle);
    for (size_t i = 0; i < count; i++) free(rows[i]);
    return 0;
}
