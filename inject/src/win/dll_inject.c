/* RE-BREAKER Windows DLL injector (v0.3.0 real implementation). */
#include <windows.h>
#include <stdio.h>
#include "../common/hook_engine.h"
#include "../common/decrypt_dump.h"
#include "../common/ipc.h"

static HANDLE g_worker_thread = NULL;
static HANDLE g_lazy_hook_thread = NULL;

/* v0.4.1.7: the 4 install_hook() calls below were running synchronously
   inside DllMain during AppInit_DLLs injection. Wine's loader-side code
   (LdrpCallInitRoutine / thread-local init helper) was still running when
   DllMain returned, and one of the just-hooked kernel32 exports was
   invoked by the loader, which crashed with c0000409 (the trampoline's
   NULL replacement_fn → mov rax,0; jmp rax; first call lands on 0x0).
   Defer the installs to a worker thread that sleeps 250ms first so Wine's
   loader init has time to complete. Fix A (NULL-skip in hook_engine.c)
   is the second half of the fix. */
static DWORD WINAPI lazy_hook_installer(LPVOID arg) {
    (void)arg;
    Sleep(250);  /* let Wine's loader init finish */
    fprintf(stderr, "[re-breaker] v0.4.1.7 lazy_hook_installer starting\n");
    re_breaker_install_hook("kernel32.dll", "CreateFileW", NULL);
    re_breaker_install_hook("kernel32.dll", "RegOpenKeyExW", NULL);
    re_breaker_install_hook("kernel32.dll", "IsDebuggerPresent", NULL);
    re_breaker_install_hook("kernel32.dll", "CheckRemoteDebuggerPresent", NULL);

    /* v0.7.0 (stress test fix): invoke the 6 hook_specs/*.c entry points.
     * The symbols are provided by hookspecs/*.c which is linked into
     * the .so/.dll at build time. */
    fprintf(stderr, "[re-breaker] v0.7.0 installing hook specs:\n");
    fprintf(stderr, "  + rdtsc_zero\n");            re_breaker_rdtsc_zero();
    fprintf(stderr, "  + cpuid_spoof (bare-metal)\n"); re_breaker_cpuid_spoof();
    fprintf(stderr, "  + invd_nop\n");              re_breaker_invd_nop();
    fprintf(stderr, "  + method_dump (encrypted-VM)\n"); re_breaker_method_dump();
    fprintf(stderr, "  + steam_api_init_zero\n");   re_breaker_steam_api_init_zero();
    fprintf(stderr, "  + eos_init_zero\n");         re_breaker_eos_init_zero();

    /* v0.8.0+ Wave 1 (Item B): per-site opcode patch specs. */
    fprintf(stderr, "[re-breaker] v0.8.0+ installing per-site patch specs:\n");
    fprintf(stderr, "  + int3_nop\n");              re_breaker_int3_nop();
    fprintf(stderr, "  + invd_nop_at_sites\n");     re_breaker_invd_nop_at_sites();
    fprintf(stderr, "  + cpuid_zero_at_sites\n");   re_breaker_cpuid_zero_at_sites();

    fprintf(stderr, "[re-breaker] v0.4.1.7 lazy_hook_installer done\n");
    return 0;
}

static DWORD WINAPI worker_thread(LPVOID arg) {
    (void)arg;
    fprintf(stderr, "[re-breaker] v0.3.0 dll_inject worker thread started\n");
    DWORD pid = GetCurrentProcessId();
    while (1) {
        re_breaker_ipc_send("heartbeat", "alive");
        /* v0.8.0+ Wave 1 (Item B): drain the per-target sites file. */
        int ops = re_breaker_drain_sites_file((int)pid);
        if (ops > 0) {
            fprintf(stderr, "[re-breaker] v0.8.0+ sites-file drain: %d ops (site_count=%zu)\n",
                    ops, re_breaker_site_count());
        }
        Sleep(5000);
    }
    return 0;
}

/* v0.4.1.2: helper to load the in-process frida-gadget.
   Exported so the host (or AppInit_DLLs-injected launcher) can call
   this AFTER DllMain returns — critical because LoadLibraryA from
   inside DllMain deadlocks on the loader_section critical section. */
__declspec(dllexport) HMODULE WINAPI re_breaker_load_frida_gadget(void) {
    HMODULE g = LoadLibraryA("frida-gadget.dll");
    if (g) {
        fprintf(stderr, "[re-breaker] frida-gadget loaded at %p\n", (void *)g);
    } else {
        DWORD err = GetLastError();
        fprintf(stderr, "[re-breaker] frida-gadget LoadLibraryA failed (err=%lu)\n", err);
    }
    return g;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    (void)hModule; (void)lpReserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        fprintf(stderr, "[re-breaker] v0.3.0 dll_inject loaded (pid=%lu)\n", GetCurrentProcessId());
        re_breaker_ipc_init(GetCurrentProcessId());
        /* v0.4.1.7: defer install_hook() to a worker thread. See
           lazy_hook_installer above for rationale. */
        g_lazy_hook_thread = CreateThread(NULL, 0, lazy_hook_installer, NULL, 0, NULL);
        /* v0.4.1.2: do NOT LoadLibraryA("frida-gadget.dll") here.
           Recursive loader_section lock would deadlock the gadget's
           V8 worker. Caller (host.exe or AppInit_DLLs launcher) should
           call re_breaker_load_frida_gadget() from outside any DllMain. */
        g_worker_thread = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        if (g_worker_thread) CloseHandle(g_worker_thread);
        if (g_lazy_hook_thread) CloseHandle(g_lazy_hook_thread);
        re_breaker_ipc_finalize();
        fprintf(stderr, "[re-breaker] v0.3.0 dll_inject unloaded\n");
        break;
    }
    return TRUE;
}
