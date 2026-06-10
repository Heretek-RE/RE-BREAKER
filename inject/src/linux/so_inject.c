/* RE-BREAKER Linux .so injector (v0.3.0 real implementation). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include "../common/hook_engine.h"
#include "../common/decrypt_dump.h"
#include "../common/ipc.h"

static int (*real_CreateFileW)(void *path, unsigned int access, unsigned int share,
                              void *sec, unsigned int disp, unsigned int flags,
                              void *tmpl) = NULL;

int CreateFileW_replacement(void *path, unsigned int access, unsigned int share,
                            void *sec, unsigned int disp, unsigned int flags,
                            void *tmpl) {
    char buf[512];
    snprintf(buf, sizeof(buf), "CreateFileW(path=%p, access=0x%x)", path, access);
    re_breaker_write_event("CreateFileW", buf);
    re_breaker_ipc_send("CreateFileW", buf);
    return real_CreateFileW(path, access, share, sec, disp, flags, tmpl);
}

static void *worker_thread(void *arg) {
    (void)arg;
    fprintf(stderr, "[re-breaker] v0.3.0 so_inject worker thread started\n");
    int pid = getpid();
    while (1) {
        re_breaker_ipc_send("heartbeat", "alive");
        /* v0.8.0+ Wave 1 (Item B): drain the per-target sites file. */
        int ops = re_breaker_drain_sites_file(pid);
        if (ops > 0) {
            fprintf(stderr, "[re-breaker] v0.8.0+ sites-file drain: %d ops (site_count=%zu)\n",
                    ops, re_breaker_site_count());
        }
        sleep(5);
    }
    return NULL;
}

__attribute__((constructor))
void re_breaker_init(void) {
    fprintf(stderr, "[re-breaker] v0.3.0 so_inject loaded (pid=%d)\n", getpid());
    re_breaker_ipc_init(getpid());
    /* v0.3.0: 4 Win32 stub hooks (the cross-Wine/Linux API surface) */
    re_breaker_install_hook("kernel32.dll", "CreateFileW", (void *)CreateFileW_replacement);
    re_breaker_install_hook("kernel32.dll", "RegOpenKeyExW", NULL);
    re_breaker_install_hook("kernel32.dll", "IsDebuggerPresent", NULL);
    re_breaker_install_hook("kernel32.dll", "CheckRemoteDebuggerPresent", NULL);

    /* v0.7.0 (stress test fix): invoke the 6 hook_specs/*.c entry points.
     * The symbols are provided by hookspecs/*.c which is linked into
     * the .so/.dll at build time. The "loaded" message below proves
     * the spec was linked. */
    fprintf(stderr, "[re-breaker] v0.7.0 installing hook specs:\n");
    fprintf(stderr, "  + rdtsc_zero\n");            re_breaker_rdtsc_zero();
    fprintf(stderr, "  + cpuid_spoof (bare-metal)\n"); re_breaker_cpuid_spoof();
    fprintf(stderr, "  + invd_nop\n");              re_breaker_invd_nop();
    fprintf(stderr, "  + method_dump (encrypted-VM)\n"); re_breaker_method_dump();
    fprintf(stderr, "  + steam_api_init_zero\n");   re_breaker_steam_api_init_zero();
    fprintf(stderr, "  + eos_init_zero\n");         re_breaker_eos_init_zero();

    /* v0.8.0+ Wave 1 (Item B): per-site opcode patch specs. These iterate
     * the per-target site list (populated by load_target_sites.py via
     * ~/.re-breaker/sites-{pid}.jsonl) and NOP each site's opcode in place.
     * No-ops until sites are pushed; safe to invoke at startup. */
    fprintf(stderr, "[re-breaker] v0.8.0+ installing per-site patch specs:\n");
    fprintf(stderr, "  + int3_nop\n");              re_breaker_int3_nop();
    fprintf(stderr, "  + invd_nop_at_sites\n");     re_breaker_invd_nop_at_sites();
    fprintf(stderr, "  + cpuid_zero_at_sites\n");   re_breaker_cpuid_zero_at_sites();

    pthread_t tid;
    pthread_create(&tid, NULL, worker_thread, NULL);
    pthread_detach(tid);
}

__attribute__((destructor))
void re_breaker_fini(void) {
    re_breaker_ipc_finalize();
    fprintf(stderr, "[re-breaker] v0.3.0 so_inject unloaded\n");
}
