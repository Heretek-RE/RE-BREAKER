/* RE-BREAKER decrypt-dump writer (v0.4.0: cross-platform mkdir fix). */
#include "decrypt_dump.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#ifdef _WIN32
#  include <direct.h>      /* for _mkdir on Windows (mingw) */
#endif

#ifndef _WIN32
#  include <pwd.h>
#endif

static const char *get_home_dir(void) {
#ifdef _WIN32
    const char *home = getenv("USERPROFILE");
    return home ? home : "C:\\Users\\Default";
#else
    const char *home = getenv("HOME");
    if (home) return home;
    struct passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_dir : "/tmp";
#endif
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return 0;
#ifdef _WIN32
    if (_mkdir(path) == 0) return 0;        /* mingw: 1-arg _mkdir */
#else
    if (mkdir(path, 0755) == 0) return 0;   /* POSIX: 2-arg mkdir */
#endif
    return -1;
}

int re_breaker_write_decrypted_region(const char *name, const uint8_t *buf, size_t size) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/.re-breaker/dumps", get_home_dir());
    if (ensure_dir(path) != 0) return -1;
    char out_path[1024];
    snprintf(out_path, sizeof(out_path), "%s/%s.bin", path, name);
    FILE *f = fopen(out_path, "wb");
    if (!f) return -1;
    fwrite(buf, 1, size, f);
    fclose(f);
    fprintf(stderr, "[re-breaker] v0.3.0 wrote %zu bytes to %s\n", size, out_path);
    return 0;
}

int re_breaker_write_event(const char *event_name, const char *payload) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/.re-breaker/events.log", get_home_dir());
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    fprintf(f, "{\"event\": \"%s\", \"payload\": \"%s\"}\n", event_name, payload);
    fclose(f);
    return 0;
}
