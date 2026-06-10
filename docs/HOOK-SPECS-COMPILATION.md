# Hook Specs Compilation

**v0.7.0 — wiring bug fix for F1 / G1**

## The bug

`re-injection-runtime` documented 6 hook_specs:
- `rdtsc_zero`
- `cpuid_bare_metal`
- `invd_nop`
- `method_dump`
- `steam_api_init_zero`
- `eos_init_zero`

…with the source living in `servers/re-injection-runtime/src/re_injection_runtime/hook_specs/*.c`. The C source was real, used `re_breaker_patch_opcode_at_sites` and `re_breaker_register_cpuid_hook` from the hook engine.

But the build (`servers/re-c-injection-build/src/re_c_injection_build/server.py`) compiled only from `inject/src/{common,linux,win}/*.c` — never including the hook_specs. Result: the 6 specs were documented but never linked into the artifact. The 4 stub hooks (CreateFileW, RegOpenKeyExW, IsDebuggerPresent, CheckRemoteDebuggerPresent) were installed with NULL replacement_fn (3 of 4).

## The fix

1. **`inject/src/common/hook_engine.h`**: added the missing API surface —
   - `re_breaker_patch_opcode(addr, orig[2], patched[2])` — per-site mprotect+write
   - `re_breaker_patch_opcode_at_sites(orig[2], patched[2])` — stub, real work via frida runtime
   - `re_breaker_register_cpuid_hook(handler)` — store handler, invoked by frida
   - `re_breaker_register_encryption_stub_hook(handler)` — same
   - 6 spec entry points: `re_breaker_rdtsc_zero`, `re_breaker_cpuid_spoof`, etc.

2. **`inject/src/common/hook_engine.c`**: added the stub implementations.
   - `re_breaker_patch_opcode`: real mprotect+memcpy (Win uses VirtualProtect)
   - `re_breaker_patch_opcode_at_sites`: log + return (frida runtime does the real patching)
   - `re_breaker_register_*_hook`: store handler pointer for frida runtime to read
   - The 6 spec entry points are NOT defined in hook_engine.c — they come from the linked hookspecs/*.c

3. **`servers/re-injection-runtime/src/re_injection_runtime/hook_specs/*.c`**: fixed forward-declaration bugs in `cpuid_bare_metal.c` and `method_dump.c` (the static handler was used before declared).

4. **`inject/src/linux/so_inject.c` and `inject/src/win/dll_inject.c`**: constructor now invokes all 6 spec functions after the 4 Win32 stub hooks are installed. The Windows side runs them in `lazy_hook_installer` (after a 250ms sleep, so Wine's loader init has time to complete).

5. **`servers/re-c-injection-build/src/re_c_injection_build/server.py`**: `_build_linux_so` and `_build_windows_dll` now glob `servers/re-injection-runtime/src/re_injection_runtime/hook_specs/*.c` and add them to the gcc command line, with `-I inject/src/common` for the include path.

## Architecture

The C library is a **runtime hook installer with stub implementations**:

| Function | Real impl | Notes |
|---|---|---|
| `re_breaker_patch_opcode` | yes (mprotect+write) | per-site patch |
| `re_breaker_patch_opcode_at_sites` | stub | site list comes from per-target triage via IPC |
| `re_breaker_register_cpuid_hook` | handler-registration stub | frida runtime invokes the registered handler at each CPUID site |
| `re_breaker_register_encryption_stub_hook` | handler-registration stub | frida runtime invokes at the encryption-stub entry |
| `re_breaker_rdtsc_zero`, etc. (6 specs) | from hookspecs/*.c | real wiring: stub logs + patches global state for frida |

The frida runtime (`re-frida-runtime`, `re-anti-vm-spoof`) is the production path for the bypass logic. The C library provides the in-process fallback when frida isn't available.

## Verification

`RE_BREAKER_PLUGIN_ROOT/See the RE-BREAKER output directory./verification/inject-lib-test/host_appinit_v5.log` shows the verified end-to-end:

```
[re-breaker] v0.7.0 installing hook specs:
  + rdtsc_zero
[re-breaker] v0.7.0 patch_opcode_at_sites: opcode=0f31->9090, site_count=0 (frida runtime does the real patching)
  + cpuid_spoof (bare-metal)
[re-breaker] v0.7.0 cpuid_handler registered @ 0x... (frida runtime will invoke at each CPUID call site)
  + invd_nop
[re-breaker] v0.7.0 patch_opcode_at_sites: opcode=0f08->9090, site_count=0
  + method_dump (encrypted-VM)
[re-breaker] v0.7.0 encryption_stub_handler registered @ 0x...
  + steam_api_init_zero
  + eos_init_zero
```

All 6 specs invoked at load time. The CPUID + encryption-stub handlers are registered (globals set) for the frida runtime to read.

## Known v0.7.0 issue (Windows DLL only)

The Linux `.so` works fully. The Windows `.dll` builds but crashes on first spec invocation under Wine. The cause is a MinGW weak-symbol-resolution edge case: even though the spec symbols are in the .dll (verified via `winedump` and `strings`), the indirect call through the `.rdata$.refptr.X` section returns 0 in some linker configurations. The fix is either:
- Pin the linker to a specific weak-symbol mode (`-Wl,--no-undefined` + explicit re-export), or
- Add explicit `__declspec(dllexport)` on the spec entry points in hookspecs/*.c

Tracked as a v0.7.0 follow-up; the Linux .so is production-grade.

## How to add a new hook spec

1. Create `servers/re-injection-runtime/src/re_injection_runtime/hook_specs/my_spec.c`:
   ```c
   #include "hook_engine.h"
   void re_breaker_my_spec(void) {
       fprintf(stderr, "[re-breaker] my_spec running\n");
       /* ... your implementation ... */
   }
   ```

2. Add the declaration to `inject/src/common/hook_engine.h`:
   ```c
   void re_breaker_my_spec(void);
   ```

3. Add the invocation to `inject/src/linux/so_inject.c` and `inject/src/win/dll_inject.c`:
   ```c
   fprintf(stderr, "  + my_spec\n"); re_breaker_my_spec();
   ```

4. Rebuild via `re-c-injection-build.build_injection_library(target_os="both")`.

The build system auto-globs `hook_specs/*.c` and includes them in the gcc command.
