/* RE-BREAKER inline-trampoline hook engine (v0.3.0 real implementation). */
#ifndef RE_BREAKER_HOOK_ENGINE_H
#define RE_BREAKER_HOOK_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  define RB_API __declspec(dllexport)
#else
#  define RB_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

RB_API int re_breaker_install_hook(const char *module_name,
                                  const char *export_name,
                                  void *replacement_fn);

RB_API int re_breaker_uninstall_hook(const char *module_name,
                                    const char *export_name);

RB_API int re_breaker_frida_detected(void);

/* v0.7.0 (stress test fix): hook-spec API surface.
 *
 * The hook_specs/*.c files (rdtsc_zero, cpuid_bare_metal, invd_nop,
 * method_dump, steam_api_init_zero, eos_init_zero) call these to
 * install their bypass implementations. The real runtime behavior is
 * either:
 *   (a) an in-process inline trampoline (rdtsc, invd, method_dump), or
 *   (b) a registered handler invoked by a runtime hook (CPUID via
 *       re-anti-vm-spoof's frida script, Steam API via re-frida-runtime).
 *
 * v0.7.0 ships (a) as a real inline-trampoline implementation and
 * (b) as a registration stub (the handler is recorded; the frida
 * runtime invokes it at the real CPUID/Steam API call site).
 */
RB_API void re_breaker_patch_opcode(uint8_t *addr, const uint8_t *original, size_t original_len, const uint8_t *patched, size_t patched_len);

RB_API void re_breaker_patch_opcode_at_sites(uint8_t *original, size_t original_len, uint8_t *patched, size_t patched_len);

/* Handler signatures. The cpuid_bare_metal handler receives a register
 * context (EAX/EBX/ECX/EDX in ctx[0..3]) and may modify ECX/EDX in
 * place. The encryption-stub handler receives (input_ptr, input_size,
 * output_ptr); the output buffer is the decrypted method body.
 *
 * The hookspecs/*.c files declare the registration functions as
 * `void (void *)` — we use `void*` here to match. The actual handler
 * signature is enforced at the call site in each hookspec. */
RB_API void re_breaker_register_cpuid_hook(void *handler);

RB_API void re_breaker_register_encryption_stub_hook(void *handler);

/* Hook spec entry points (v0.8.0: NOT weak).
 *
 * v0.7.0 declared these as `__attribute__((weak))` to allow
 * "build without hookspecs". The MinGW weak-symbol mechanism
 * routes the call through `.rdata$.refptr.X` which resolves
 * to NULL on Wine + some linker configurations, causing a
 * page fault on first spec invocation.
 *
 * v0.8.0 drops the weak attribute. The hookspecs/*.c are
 * canonical and always linked; building without them is no
 * longer supported. The constructor in so_inject.c /
 * dll_inject.c invokes them after the 4 Win32 stub hooks.
 */
void re_breaker_rdtsc_zero(void);
void re_breaker_cpuid_spoof(void);
void re_breaker_invd_nop(void);
void re_breaker_method_dump(void);
void re_breaker_steam_api_init_zero(void);
void re_breaker_eos_init_zero(void);

/* v0.8.0+ Wave 1 (Item B): per-site opcode patch specs. */
void re_breaker_int3_nop(void);
void re_breaker_invd_nop_at_sites(void);
void re_breaker_cpuid_zero_at_sites(void);

/* v0.8.0+ Wave 1 (Item B): drain the per-target sites file.
 *
 * The Python emitter (load_target_sites.py) writes push_site / clear_sites
 * ops to ~/.re-breaker/sites-{pid}.jsonl. The C-side worker thread calls
 * this on its 5s heartbeat tick. Returns the number of ops processed.
 * Atomic-rename semantics in the Python side make this safe to call
 * concurrently with writers (the writer either sees the original inode
 * pre-rename or a fresh one post-rename, never a half-truncated file).
 */
int re_breaker_drain_sites_file(int pid);

/* v0.8.0+ Wave 1 (Item B): site-list stats (for the verify step + tests). */
size_t re_breaker_site_count(void);

/* v0.8.0+ Wave 1 (Item B): direct push/clear API (used by the
 * re_breaker_drain_sites_file() impl; exposed for tests + advanced
 * callers that already have addresses in hand and don't need the
 * JSON file round-trip). */
int re_breaker_push_site(uint8_t *addr);
int re_breaker_clear_sites(void);

#ifdef __cplusplus
}
#endif

#endif
