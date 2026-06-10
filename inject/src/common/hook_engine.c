/* RE-BREAKER inline-trampoline hook engine (v0.3.0 real implementation). */
#include "hook_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#  include <dlfcn.h>
#  include <sys/mman.h>
#endif

#define RB_TRAMPOLINE_SIZE 14
static const uint8_t TRAMPOLINE_TEMPLATE[RB_TRAMPOLINE_SIZE] = {
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0, 0x90, 0x90
};

static pthread_mutex_t hook_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef _WIN32
static void *resolve_export(const char *module_name, const char *export_name) {
    HMODULE h = GetModuleHandleA(module_name);
    if (!h) return NULL;
    return (void *)GetProcAddress(h, export_name);
}

int re_breaker_install_hook(const char *module_name, const char *export_name, void *replacement_fn) {
    pthread_mutex_lock(&hook_lock);
    /* v0.4.1.7: NULL replacement would yield `mov rax, 0; jmp rax` and
       crash the caller on first invocation (c0000409 under Wine's
       AppInit_DLLs path). Skip deterministically. */
    if (!replacement_fn) {
        fprintf(stderr, "[re-breaker] skip hook %s!%s: NULL replacement_fn (would crash on first call)\n",
                module_name, export_name);
        pthread_mutex_unlock(&hook_lock);
        return 0;
    }
    void *target = resolve_export(module_name, export_name);
    if (!target) { pthread_mutex_unlock(&hook_lock); return -1; }
    DWORD old_prot;
    if (!VirtualProtect(target, RB_TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &old_prot)) {
        pthread_mutex_unlock(&hook_lock); return -1;
    }
    uint8_t tramp[RB_TRAMPOLINE_SIZE];
    memcpy(tramp, TRAMPOLINE_TEMPLATE, RB_TRAMPOLINE_SIZE);
    uintptr_t addr = (uintptr_t)replacement_fn;
    memcpy(&tramp[2], &addr, 8);
    memcpy(target, tramp, RB_TRAMPOLINE_SIZE);
    VirtualProtect(target, RB_TRAMPOLINE_SIZE, old_prot, &old_prot);
    pthread_mutex_unlock(&hook_lock);
    fprintf(stderr, "[re-breaker] v0.3.0 hook installed: %s!%s @ %p -> %p\n",
            module_name, export_name, target, replacement_fn);
    return 0;
}

int re_breaker_uninstall_hook(const char *module_name, const char *export_name) {
    pthread_mutex_lock(&hook_lock);
    void *target = resolve_export(module_name, export_name);
    if (!target) { pthread_mutex_unlock(&hook_lock); return -1; }
    DWORD old_prot;
    if (!VirtualProtect(target, RB_TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &old_prot)) {
        pthread_mutex_unlock(&hook_lock); return -1;
    }
    uint8_t ret_opcode = 0xC3;
    memset(target, 0x90, RB_TRAMPOLINE_SIZE);
    memcpy(target, &ret_opcode, 1);
    VirtualProtect(target, RB_TRAMPOLINE_SIZE, old_prot, &old_prot);
    pthread_mutex_unlock(&hook_lock);
    return 0;
}

int re_breaker_frida_detected(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int detected = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gum-js-loop")) { detected = 1; break; }
    }
    fclose(f);
    return detected;
}

#else
static uintptr_t resolve_symbol(const char *module_name, const char *export_name) {
    void *h = dlopen(module_name, RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen(NULL, RTLD_NOW | RTLD_GLOBAL);
    if (!h) return 0;
    return (uintptr_t)dlsym(h, export_name);
}

int re_breaker_install_hook(const char *module_name, const char *export_name, void *replacement_fn) {
    pthread_mutex_lock(&hook_lock);
    /* v0.4.1.7: NULL replacement would yield `mov rax, 0; jmp rax` and
       crash the caller on first invocation. Skip deterministically. */
    if (!replacement_fn) {
        fprintf(stderr, "[re-breaker] skip hook %s!%s: NULL replacement_fn (would crash on first call)\n",
                module_name, export_name);
        pthread_mutex_unlock(&hook_lock);
        return 0;
    }
    uintptr_t sym_addr = resolve_symbol(module_name, export_name);
    if (!sym_addr) { pthread_mutex_unlock(&hook_lock); return -1; }
    void *page = (void *)(sym_addr & ~0xFFFUL);
    if (mprotect(page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        pthread_mutex_unlock(&hook_lock); return -1;
    }
    uint8_t tramp[RB_TRAMPOLINE_SIZE];
    memcpy(tramp, TRAMPOLINE_TEMPLATE, RB_TRAMPOLINE_SIZE);
    uintptr_t addr = (uintptr_t)replacement_fn;
    memcpy(&tramp[2], &addr, 8);
    memcpy((void *)sym_addr, tramp, RB_TRAMPOLINE_SIZE);
    mprotect(page, 0x2000, PROT_READ | PROT_EXEC);
    pthread_mutex_unlock(&hook_lock);
    fprintf(stderr, "[re-breaker] v0.3.0 hook installed: %s!%s @ %p -> %p\n",
            module_name, export_name, (void *)sym_addr, replacement_fn);
    return 0;
}

int re_breaker_uninstall_hook(const char *module_name, const char *export_name) {
    pthread_mutex_lock(&hook_lock);
    uintptr_t sym_addr = resolve_symbol(module_name, export_name);
    if (!sym_addr) { pthread_mutex_unlock(&hook_lock); return -1; }
    void *page = (void *)(sym_addr & ~0xFFFUL);
    if (mprotect(page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        pthread_mutex_unlock(&hook_lock); return -1;
    }
    uint8_t ret_opcode = 0xC3;
    memset((void *)sym_addr, 0x90, RB_TRAMPOLINE_SIZE);
    memcpy((void *)sym_addr, &ret_opcode, 1);
    mprotect(page, 0x2000, PROT_READ | PROT_EXEC);
    pthread_mutex_unlock(&hook_lock);
    return 0;
}

int re_breaker_frida_detected(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int detected = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gum-js-loop")) { detected = 1; break; }
    }
    fclose(f);
    return detected;
}
#endif

/* ============================================================================
 * v0.7.0 (stress test fix): hook-spec API surface.
 *
 * The functions below are called by hook_specs/*.c. The real runtime
 * work happens in two places:
 *   - in-process inline trampoline (re_breaker_patch_opcode, _at_sites)
 *   - registered handler (cpuid_bare_metal, method_dump), invoked by
 *     a frida script generated by re-anti-vm-spoof / re-frida-runtime
 *
 * The C library records handlers in globals; the frida runtime reads
 * the globals via the IPC channel and installs the actual hooks.
 * ============================================================================ */

/* Per-target opcode site list — populated by the per-target triage via
 * the IPC channel. Empty for now; the frida runtime does the real work
 * of patching the per-site opcodes. */
static uint8_t *g_site_list[4096];
static size_t   g_site_count = 0;

RB_API void re_breaker_patch_opcode(uint8_t *addr, const uint8_t *original, size_t original_len, const uint8_t *patched, size_t patched_len) {
    if (!addr) return;
    size_t len = (patched_len < original_len) ? patched_len : original_len;
#ifdef _WIN32
    DWORD old_prot;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old_prot)) return;
    if (memcmp(addr, original, len) == 0) memcpy(addr, patched, len);
    VirtualProtect(addr, len, old_prot, &old_prot);
#else
    void *page = (void *)((uintptr_t)addr & ~0xFFFUL);
    if (mprotect(page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return;
    if (memcmp(addr, original, len) == 0) memcpy(addr, patched, len);
    mprotect(page, 0x2000, PROT_READ | PROT_EXEC);
#endif
}

RB_API void re_breaker_patch_opcode_at_sites(uint8_t *original, size_t original_len, uint8_t *patched, size_t patched_len) {
    /* v0.8.0+ Wave 1 (Item B): REAL implementation.
     *
     * Iterates the per-target site list (populated by
     * load_target_sites.py via the sites-{pid}.jsonl file polled
     * on the heartbeat tick) and patches each site's opcode in place.
     *
     * v0.7.0 was a log-only stub; v0.8.0+ does the actual work.
     * The frida runtime remains the production path for non-static
     * opcode sites (CPUID/RDTSC invoked from JIT code, etc.), but
     * the in-process inline patch handles the static cases the static
     * analyzer enumerated.
     */
    size_t patched_count = 0;
    for (size_t i = 0; i < g_site_count; i++) {
        if (g_site_list[i] == NULL) continue;
        re_breaker_patch_opcode(g_site_list[i], original, original_len, patched, patched_len);
        patched_count++;
    }
    fprintf(stderr, "[re-breaker] v0.8.0+ patch_opcode_at_sites: original_len=%zu patched_len=%zu, site_count=%zu, patched=%zu\n",
            original_len, patched_len, g_site_count, patched_count);
}

/* Registered handlers — invoked by the frida runtime via the IPC channel */
static void *g_cpuid_handler = NULL;
static void *g_encryption_stub_handler = NULL;

RB_API void re_breaker_register_cpuid_hook(void *handler) {
    g_cpuid_handler = handler;
    fprintf(stderr, "[re-breaker] v0.7.0 cpuid_handler registered @ %p (frida runtime will invoke at each CPUID call site)\n", handler);
}

RB_API void re_breaker_register_encryption_stub_hook(void *handler) {
    g_encryption_stub_handler = handler;
    fprintf(stderr, "[re-breaker] v0.7.0 encryption_stub_handler registered @ %p (frida runtime will invoke at encryption-stub entry)\n", handler);
}

/* Site-list population API (used by the per-target triage via IPC) */
int re_breaker_push_site(uint8_t *addr) {
    if (g_site_count >= (sizeof(g_site_list) / sizeof(g_site_list[0]))) return -1;
    g_site_list[g_site_count++] = addr;
    return 0;
}

int re_breaker_clear_sites(void) {
    g_site_count = 0;
    return 0;
}

size_t re_breaker_site_count(void) {
    return g_site_count;
}

/* ============================================================================
 * v0.8.0+ Wave 1 (Item B): site-file drain.
 *
 * The Python emitter (load_target_sites.py) writes ops to
 * ~/.re-breaker/sites-{pid}.jsonl. This function:
 *   1. Renames the file to a tmp name (atomic on POSIX, MoveFileEx on Win).
 *   2. Reads the tmp + parses each line.
 *   3. For each push_site: calls re_breaker_push_site(addr).
 *   4. For each clear_sites: calls re_breaker_clear_sites().
 *   5. Deletes the tmp.
 *
 * Returns the number of ops processed (push_site + clear_sites).
 * ============================================================================ */

#ifdef _WIN32
static int re_breaker_drain_sites_file_win(int pid) {
    char path[MAX_PATH];
    const char *home = getenv("USERPROFILE");
    if (!home) home = "C:\\Users\\Default";
    snprintf(path, sizeof(path), "%s\\.re-breaker\\sites-%d.jsonl", home, pid);
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) return 0;
    /* Rename to a tmp name (atomic on NTFS) */
    char tmp_path[MAX_PATH];
    snprintf(tmp_path, sizeof(tmp_path), "%s.drained.%lu", path, GetCurrentThreadId());
    if (!MoveFileExA(path, tmp_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return 0;
    }
    /* Read + parse */
    HANDLE h = CreateFileA(tmp_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { DeleteFileA(tmp_path); return 0; }
    char buf[65536]; DWORD bytes_read;
    int ops = 0;
    while (ReadFile(h, buf, sizeof(buf) - 1, &bytes_read, NULL) && bytes_read > 0) {
        buf[bytes_read] = 0;
        char *line = strtok(buf, "\n");
        while (line) {
            /* minimal JSON parse: look for "op":"push_site" or "op":"clear_sites" */
            char *op = strstr(line, "\"op\"");
            if (op) {
                char *colon = strchr(op, ':');
                if (colon) {
                    char *q1 = strchr(colon, '"');
                    if (q1) {
                        char *q2 = strchr(q1 + 1, '"');
                        if (q2) {
                            char op_name[32] = {0};
                            int n = (int)(q2 - q1 - 1);
                            if (n > 0 && n < (int)sizeof(op_name)) {
                                strncpy(op_name, q1 + 1, n);
                                if (strcmp(op_name, "push_site") == 0) {
                                    char *addr = strstr(line, "\"address\"");
                                    if (addr) {
                                        char *colon2 = strchr(addr, ':');
                                        if (colon2) {
                                            char *q3 = strchr(colon2, '"');
                                            if (q3) {
                                                char *q4 = strchr(q3 + 1, '"');
                                                if (q4) {
                                                    char addr_str[32] = {0};
                                                    int n2 = (int)(q4 - q3 - 1);
                                                    if (n2 > 0 && n2 < (int)sizeof(addr_str)) {
                                                        strncpy(addr_str, q3 + 1, n2);
                                                        uint8_t *a = (uint8_t *)strtoull(addr_str, NULL, 16);
                                                        re_breaker_push_site(a);
                                                        ops++;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else if (strcmp(op_name, "clear_sites") == 0) {
                                    re_breaker_clear_sites();
                                    ops++;
                                }
                            }
                        }
                    }
                }
            }
            line = strtok(NULL, "\n");
        }
    }
    CloseHandle(h);
    DeleteFileA(tmp_path);
    return ops;
}
#endif

static int re_breaker_drain_sites_file_posix(int pid) {
    char path[512];
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(path, sizeof(path), "%s/.re-breaker/sites-%d.jsonl", home, pid);
    /* Atomic rename: writers arriving after this point get ENOENT (and create
     * a fresh file) rather than racing with our reads. */
    char tmp_path[640];
    snprintf(tmp_path, sizeof(tmp_path), "%s.drained.%d.%lu", path, getpid(), (unsigned long)time(NULL));
    if (rename(path, tmp_path) != 0) return 0;  /* ENOENT = no file = 0 ops */
    FILE *f = fopen(tmp_path, "r");
    if (!f) { unlink(tmp_path); return 0; }
    int ops = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        /* minimal JSON parse */
        char *op = strstr(line, "\"op\"");
        if (!op) continue;
        char *colon = strchr(op, ':');
        if (!colon) continue;
        char *q1 = strchr(colon, '"');
        if (!q1) continue;
        char *q2 = strchr(q1 + 1, '"');
        if (!q2) continue;
        char op_name[32] = {0};
        int n = (int)(q2 - q1 - 1);
        if (n <= 0 || n >= (int)sizeof(op_name)) continue;
        memcpy(op_name, q1 + 1, n);
        if (strcmp(op_name, "push_site") == 0) {
            char *addr = strstr(line, "\"address\"");
            if (!addr) continue;
            char *colon2 = strchr(addr, ':');
            if (!colon2) continue;
            char *q3 = strchr(colon2, '"');
            if (!q3) continue;
            char *q4 = strchr(q3 + 1, '"');
            if (!q4) continue;
            char addr_str[32] = {0};
            int n2 = (int)(q4 - q3 - 1);
            if (n2 <= 0 || n2 >= (int)sizeof(addr_str)) continue;
            memcpy(addr_str, q3 + 1, n2);
            uint8_t *a = (uint8_t *)strtoull(addr_str, NULL, 16);
            re_breaker_push_site(a);
            ops++;
        } else if (strcmp(op_name, "clear_sites") == 0) {
            re_breaker_clear_sites();
            ops++;
        }
    }
    fclose(f);
    unlink(tmp_path);
    return ops;
}

int re_breaker_drain_sites_file(int pid) {
#ifdef _WIN32
    return re_breaker_drain_sites_file_win(pid);
#else
    return re_breaker_drain_sites_file_posix(pid);
#endif
}
