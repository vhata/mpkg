/* Closed offline preparation protocol. Never commits, refreshes or fetches. */
#define _GNU_SOURCE
#include <alpm.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define VERSION "16.0.1"
#define LIMIT 40000
static char *rows[LIMIT];
static size_t row_count;
static int unsupported_question;
static const char *base;

static void fail(const char *code) {
    printf("BLOCK\t%s\n", code);
    exit(0);
}

static int safe(const char *value) {
    if (!value || !*value || strlen(value) > 4096) return 0;
    for (; *value; value++) if ((unsigned char)*value <= 32 ||
                               (unsigned char)*value >= 127) return 0;
    return 1;
}

static void emit(const char *format, ...) {
    if (row_count == LIMIT) fail("input");
    va_list args;
    va_start(args, format);
    if (vasprintf(&rows[row_count], format, args) < 0) fail("input");
    va_end(args);
    row_count++;
}

static void package_name(alpm_pkg_t *pkg) {
    if (!safe(alpm_pkg_get_name(pkg)) || !safe(alpm_pkg_get_version(pkg))) fail("input");
}

static void question(void *ctx, alpm_question_t *q) {
    (void)ctx;
    q->any.answer = 0;
    if (q->type == ALPM_QUESTION_REPLACE_PKG) {
        package_name(q->replace.oldpkg);
        package_name(q->replace.newpkg);
        emit("Q\treplacement\t%s\t%s\n", alpm_pkg_get_name(q->replace.oldpkg),
             alpm_pkg_get_name(q->replace.newpkg));
        q->replace.replace = 1; /* A proposed removal, never a live action. */
    } else if (q->type == ALPM_QUESTION_SELECT_PROVIDER) {
        if (!q->select_provider.providers) fail("choice");
        char *dep = alpm_dep_compute_string(q->select_provider.depend);
        alpm_pkg_t *pkg = q->select_provider.providers->data;
        package_name(pkg);
        if (!safe(dep)) fail("input");
        /* Native repository order selects the first candidate. Bind it. */
        emit("Q\tprovider\t%s\t%s\n", dep, alpm_pkg_get_name(pkg));
        free(dep);
        q->select_provider.use_index = 0;
    } else {
        unsupported_question = 1;
    }
}

static int no_fetch(void *ctx, const char *url, const char *path, int force) {
    (void)ctx; (void)url; (void)path; (void)force;
    return -1;
}

static void no_log(void *ctx, alpm_loglevel_t level, const char *fmt, va_list args) {
    (void)ctx; (void)level; (void)fmt; (void)args;
}

static void path(char *buffer, size_t size, const char *relative) {
    if (snprintf(buffer, size, "%s/%s", base, relative) >= (int)size) fail("input");
}

static FILE *input(const char *relative) {
    char buffer[8192]; path(buffer, sizeof buffer, relative);
    int fd = open(buffer, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077) || st.st_nlink != 1 ||
        st.st_size > 8 * 1024 * 1024) fail("input");
    FILE *file = fdopen(fd, "r");
    if (!file) fail("input");
    return file;
}

static size_t fields(char *line, char **parts, size_t expected) {
    size_t n = 0;
    size_t length = strlen(line);
    if (!length || line[length - 1] != '\n') fail("input");
    line[length - 1] = 0;
    char *next = line;
    while (next) {
        if (n == expected) fail("input");
        parts[n] = strsep(&next, "\t");
        if (!safe(parts[n++])) fail("input");
    }
    if (n != expected) fail("input");
    return n;
}

static void directory(const char *relative) {
    char buffer[8192]; path(buffer, sizeof buffer, relative);
    struct stat st;
    if (lstat(buffer, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) fail("input");
}

static int package_member(alpm_list_t *list, const char *name) {
    return alpm_pkg_find(list, name) != NULL;
}

static int compare_rows(const void *left, const void *right) {
    return strcmp(*(char * const *)left, *(char * const *)right);
}

static void package_row(alpm_pkg_t *pkg, const char *kind) {
    package_name(pkg);
    int reason = alpm_pkg_get_reason(pkg);
    if (reason != 0 && reason != 1) fail("input");
    emit("%s\t%s\t%s\t%d\n", kind, alpm_pkg_get_name(pkg),
         alpm_pkg_get_version(pkg), reason);
}

static void verify_artifact(alpm_handle_t *handle, alpm_pkg_t *pkg) {
    char line[16384], *part[5], buffer[8192];
    const char *name = alpm_pkg_get_name(pkg), *version = alpm_pkg_get_version(pkg);
    const char *digest = alpm_pkg_get_sha256sum(pkg);
    const char *repo = alpm_db_get_name(alpm_pkg_get_db(pkg));
    if (!safe(repo) || !safe(digest)) fail("artifact");
    FILE *file = input("artifacts.list");
    int found = 0;
    while (fgets(line, sizeof line, file)) {
        fields(line, part, 5);
        if (strcmp(part[0], name)) continue;
        if (found++ || strcmp(part[1], version) || strcmp(part[2], repo) ||
            strcmp(part[4], digest) || strspn(part[3], "0123456789.pkg") != strlen(part[3]) ||
            strstr(part[3], "..") || !strstr(part[3], ".pkg")) fail("artifact");
        char relative[512];
        if (snprintf(relative, sizeof relative, "artifacts/%s", part[3]) >= (int)sizeof relative)
            fail("input");
        path(buffer, sizeof buffer, relative);
        alpm_pkg_t *loaded = NULL;
        if (alpm_pkg_load(handle, buffer, 1, ALPM_SIG_PACKAGE, &loaded)) fail("signature");
        if (strcmp(alpm_pkg_get_name(loaded), name) ||
            strcmp(alpm_pkg_get_version(loaded), version)) fail("artifact");
        alpm_pkg_free(loaded);
    }
    if (ferror(file)) fail("input");
    fclose(file);
    if (!found) fail("artifact");
    emit("A\t%s\t%s\t%s\t%s\n", name, version, repo, digest);
}

int main(int argc, char **argv) {
    if (argc != 2 || !safe(argv[1]) || argv[1][0] != '/') fail("input");
    base = argv[1];
    char *resolved = realpath(base, NULL);
    if (!resolved || strcmp(resolved, base)) fail("input");
    free(resolved);
    directory("."); directory("root"); directory("db"); directory("db/local");
    directory("db/sync"); directory("gpg"); directory("artifacts");
    FILE *file = input("protocol");
    char line[16384], *part[5];
    if (!fgets(line, sizeof line, file)) fail("input");
    fields(line, part, 3);
    if (strcmp(part[0], "1") || strcmp(part[1], VERSION) || strcmp(part[2], "x86_64") ||
        fgetc(file) != EOF || strcmp(alpm_version(), VERSION)) fail("abi");
    fclose(file);
    char root[8192], db[8192], gpg[8192];
    path(root, sizeof root, "root/"); path(db, sizeof db, "db/"); path(gpg, sizeof gpg, "gpg/");
    alpm_errno_t error;
    alpm_handle_t *handle = alpm_initialize(root, db, &error);
    if (!handle || alpm_option_set_gpgdir(handle, gpg) ||
        alpm_option_add_architecture(handle, "x86_64") ||
        alpm_option_set_questioncb(handle, question, NULL) ||
        alpm_option_set_fetchcb(handle, no_fetch, NULL) ||
        alpm_option_set_logcb(handle, no_log, NULL)) fail("input");
    file = input("repositories");
    size_t count = 0;
    while (fgets(line, sizeof line, file)) {
        fields(line, part, 2);
        if (++count > 32 || (strcmp(part[1], "0") && strcmp(part[1], "1"))) fail("input");
        int level = ALPM_SIG_PACKAGE | ALPM_SIG_DATABASE;
        if (!strcmp(part[1], "0")) level |= ALPM_SIG_DATABASE_OPTIONAL;
        alpm_db_t *repository = alpm_register_syncdb(handle, part[0], level);
        if (!repository || alpm_db_get_valid(repository)) fail("database");
    }
    if (!count || ferror(file)) fail("input");
    fclose(file);
    if (alpm_trans_init(handle, 0) || alpm_sync_sysupgrade(handle, 0)) fail("dependency");
    file = input("requests");
    char *wanted[256], *versions[256];
    count = 0;
    while (fgets(line, sizeof line, file)) {
        fields(line, part, 2);
        if (count == 256) fail("input");
        wanted[count] = strdup(part[0]); versions[count] = strdup(part[1]);
        if (!wanted[count] || !versions[count]) fail("input");
        char expression[8192];
        if (snprintf(expression, sizeof expression, !strcmp(part[1], "-") ? "%s" : "%s=%s",
                     part[0], part[1]) >= (int)sizeof expression) fail("input");
        alpm_pkg_t *selected = alpm_find_satisfier(alpm_trans_get_add(handle), expression);
        alpm_pkg_t *installed = alpm_find_satisfier(
            alpm_db_get_pkgcache(alpm_get_localdb(handle)), expression);
        int satisfied = selected || (installed &&
            !package_member(alpm_trans_get_add(handle), alpm_pkg_get_name(installed)) &&
            !package_member(alpm_trans_get_remove(handle), alpm_pkg_get_name(installed)));
        if (!satisfied) {
            selected = alpm_find_dbs_satisfier(handle, alpm_get_syncdbs(handle), expression);
            if (!selected) fail("pin");
            if (!package_member(alpm_trans_get_add(handle), alpm_pkg_get_name(selected)) &&
                alpm_add_pkg(handle, selected)) fail("dependency");
        }
        count++;
    }
    if (!count || ferror(file)) fail("input");
    fclose(file);
    alpm_list_t *errors = NULL;
    if (alpm_trans_prepare(handle, &errors)) {
        error = alpm_errno(handle);
        fail(error == ALPM_ERR_CONFLICTING_DEPS ? "conflict" : "dependency");
    }
    if (unsupported_question) fail("choice");
    emit("V\t%s\n", alpm_version());
    alpm_list_t *added = alpm_trans_get_add(handle), *removed = alpm_trans_get_remove(handle);
    alpm_list_t *final = NULL;
    for (alpm_list_t *p = alpm_db_get_pkgcache(alpm_get_localdb(handle)); p; p = p->next) {
        package_row(p->data, "I");
        if (!package_member(added, alpm_pkg_get_name(p->data)) &&
            !package_member(removed, alpm_pkg_get_name(p->data))) final = alpm_list_add(final, p->data);
    }
    for (alpm_list_t *p = added; p; p = p->next) final = alpm_list_add(final, p->data);
    for (alpm_list_t *p = removed; p; p = p->next) package_row(p->data, "R");
    for (alpm_list_t *p = added; p; p = p->next) {
        alpm_pkg_t *pkg = p->data;
        package_name(pkg);
        verify_artifact(handle, pkg);
        for (alpm_list_t *d = alpm_pkg_get_depends(pkg); d; d = d->next) {
            char *expression = alpm_dep_compute_string(d->data);
            if (!safe(expression)) fail("input");
            alpm_pkg_t *provider = alpm_find_satisfier(final, expression);
            if (!provider) fail("dependency");
            package_name(provider);
            emit("D\t%s\t%s\t%s\n", alpm_pkg_get_name(pkg), expression, alpm_pkg_get_name(provider));
            free(expression);
        }
        for (alpm_list_t *d = alpm_pkg_get_provides(pkg); d; d = d->next) {
            char *expression = alpm_dep_compute_string(d->data);
            if (!safe(expression)) fail("input");
            emit("P\t%s\t%s\n", alpm_pkg_get_name(pkg), expression);
            free(expression);
        }
    }
    for (size_t i = 0; i < count; i++) {
        char expression[8192];
        if (snprintf(expression, sizeof expression, !strcmp(versions[i], "-") ? "%s" : "%s=%s",
                     wanted[i], versions[i]) >= (int)sizeof expression) fail("input");
        alpm_pkg_t *provider = alpm_find_satisfier(final, expression);
        if (!provider) fail("pin");
        package_name(provider);
        emit("T\t%s\t%s\t%s\n", wanted[i], alpm_pkg_get_name(provider), alpm_pkg_get_version(provider));
        free(wanted[i]); free(versions[i]);
    }
    /* No partial response is emitted on a release/cleanup failure. */
    alpm_list_free(final);
    if (alpm_trans_release(handle) || alpm_release(handle)) fail("input");
    qsort(rows, row_count, sizeof rows[0], compare_rows);
    for (size_t i = 0; i < row_count; i++)
        if (!i || strcmp(rows[i - 1], rows[i])) fputs(rows[i], stdout);
    for (size_t i = 0; i < row_count; i++) free(rows[i]);
    return 0;
}
