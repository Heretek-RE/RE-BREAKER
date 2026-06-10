# RE-BREAKER on Wine (v0.4.0)

**The 7 stress-test targets are Windows PE binaries** running on a Linux host. There is no Windows runtime on this host; we use Wine to load and execute them. This document describes the 3 runtime analysis paths RE-BREAKER ships in v0.4.0 and the per-target launch recommendations.

## 1. Wine 11.0 baseline

The host has `wine-11.0 (Staging)` (Fedora 44 package). Wine 11 is the **major-version inflection point** for `winedbg`:

- **Wine ≤ 10**: `winedbg --gdb <exe> <port>` binds a TCP gdbserver port. Client connects via `target remote localhost:<port>`.
- **Wine ≥ 11**: `winedbg --gdb <exe>` runs gdb over its own stdin/stdout (no port). The client (e.g., `re-winedbg`'s `WinedbgStdioClient`) writes gdb commands to winedbg's stdin and reads responses from stdout.

RE-BREAKER's `re-winedbg` server auto-detects via `_wine_major()` and dispatches to the right transport.

## 2. The 3 runtime paths

### 2.1. `re-frida-wine-runtime` — In-process frida-gadget injection

**This is the only known-working Frida path on this host.** The out-of-process `wine frida-server.exe` + `frida -H 127.0.0.1:27042` attach is broken (Frida GH #3339, #3617, #2734).

The technique:

1. The C injection library (built by `re-c-injection-build`) is loaded into the Wine-hosted target via `AppInit_DLLs` (a registry entry in the Wine prefix that points to a DLL the loader auto-injects into every process).
2. At `DllMain(DLL_PROCESS_ATTACH)`, the C library calls `LoadLibraryA("frida-gadget.dll")` from a path the Wine process can see (the target's dir, or `%WINDIR%\system32\`).
3. The frida-gadget reads its config file `frida-gadget.config` next to itself, sees `interaction = { type = "listen", address = "127.0.0.1", port = 27042 }`, and starts listening on TCP 127.0.0.1:27042 *inside* the Wine process.
4. The MCP server's Python side calls `frida.get_device('127.0.0.1:27042', api='frida')`. The Linux-side frida client is talking to a frida-instance running inside the Wine process over loopback TCP. This sidesteps the broken out-of-process attach paths.

**Status (v0.4.0)**: scaffolding + script-only mode complete. The `frida_attach` tool spawns the target under Wine, sets the AppInit_DLLs registry entry, places the frida-gadget, and starts the listener. Full `session.create_script(...)` execution requires the frida-gadget binary to be downloaded (run `curl -L -O https://github.com/frida/frida/releases/download/17.11.0/frida-gadget-17.11.0-windows-x86_64.dll.xz` and place at `vendored/frida-gadgets/frida-gadget-windows-x86_64.dll`).

**Important (v0.4.1.7)**: Wine 11.0's `kernelbase!LoadAppInitDlls` is a stub ([source](https://github.com/wine-mirror/wine/blob/wine-11.0/dlls/kernelbase/loader.c)):

```c
void WINAPI LoadAppInitDlls(void)
{
    TRACE( "\n" );
}
```

And `user32.dll`'s `DllMain` does not call `LoadAppInitDlls` either. So the `AppInit_DLLs` registry value is **never read on Wine 11.0**. The production injection mechanism on this host is therefore the **LoadLibraryA-from-main()** path (used by `re-frida-wine-runtime.frida_attach` via `re_breaker_inject_load_frida_gadget` exported from `re_breaker_inject.dll`, and by `re-injection-runtime.inject` via `re_breaker_inject.dll`'s `ipc_init` + `install_hooks`). The AppInit_DLLs registry keys are still set (for real Windows, or future Wine versions that implement it) but do not trigger injection on this host. The fix path (DllMain + install_hooks + the 4 hooked APIs) is identical between the two mechanisms — verified by `scripts/re_breaker_inject_appinit_test.py`.

### 2.2. `re-injection-runtime` — C-injection-only runtime (no Frida)

For when Frida is not available, or when JS-hook overhead is too high for tight loops, or when the hook spec is simple enough to express in C. The C library's inline-trampoline + IAT/GOT override primitives are sufficient for ~80% of the typical anti-tamper-bypass work.

The technique:

1. Build the C library with the requested hook specs baked in (e.g., `rdtsc_zero.c` overrides RDTSC to return 0; `method_dump.c` captures (input, output) at the encryption-stub entry and writes to disk).
2. Spawn the target with `LD_PRELOAD=/path/to/re_breaker_inject.so ./target` (Linux) or `LoadLibraryA("re_breaker_inject.dll")` from the host's `main()` (Wine). AppInit_DLLs is the real-Windows production mechanism but is a stub on Wine 11.0 (see §2.1 note).
3. The C library's hooks fire as the target runs; captured payloads stream back via named-pipe (Windows) or Unix-domain-socket (Linux).

**Status (v0.4.0)**: scaffolding + 4 hook specs (rdtsc_zero, cpuid_bare_metal, invd_nop, method_dump) + build+spawn complete. The IPC consumer (reads named-pipe / Unix-socket, parses structured payload, writes per-method dumps) lands in v0.4.1.

### 2.3. `re-winedbg` — Wine + winedbg + gdb + GEF (port of RE-AI's 30-tool wrapper)

For vendor-neutral, in-tree dynamic analysis. Uses `winedbg --gdb` directly (the proven, supported path on Wine 11). RE-AI ships this as `re-winedbg`; v0.4.0 ports it to RE-BREAKER as a vendored path-aware re-implementation.

The 30 tools:

- **Core (10, all implemented in v0.4.0)**: `status`, `check_winedbg`, `launch_under_wine`, `start_winedbg_gdbserver`, `attach_winedbg_gdbserver`, `set_breakpoint`, `continue_execution`, `read_memory`, `write_memory`, `info_modules`, `info_registers`.
- **GEF helpers (15, stubs in v0.4.0; land in v0.4.1)**: `gef_trace_breakpoint`, `gef_pattern_search`, `gef_ropper_search`, `gef_magic_string_search`, `gef_telescope`, `gef_vmmap`, `gef_xinfo`, `gef_context`, `gef_xor_memory_search`, `gef_patch`, `gef_glibc_arena`, `gef_heap_search`, `gef_stack_search`, `gef_tcache_perthread_struct`, `gef_heap_bins`.
- **Convenience (5, stubs in v0.4.0; land in v0.4.1)**: `register_read`, `register_write`, `disassemble`, `session_detach`, `session_kill`.

## 3. Per-target launch recommendations

The 7 stress-test targets have **very uneven** Wine-compatibility. Recommended path per target:

| Target | Engine | Denuvo | EAC/BE | Wine-launchable? | Recommended path |
|---|---|---|---|---|---|
| FM26 | Unity 6 IL2CPP | no | no | **likely yes** | `re-injection-runtime` (lightweight) or `re-winedbg` |
| HKIA | Unity IL2CPP | no | no | **likely yes** | `re-injection-runtime` or `re-winedbg` |
| LIR | Unity IL2CPP + Origin | no | no | **likely yes** (Origin stub-drop Pattern B at runtime) | `re-winedbg` + Pattern B hook |
| P3R | UE4 (older) | Denuvo (SOW-X) | no | likely yes on UE4 path; Denuvo check is for `SOW-X` ↔ `SOW-X` routing | `re-winedbg`; Denuvo work is multi-month per-title |
| 007FL | IOI Glacier 2 | no | no (SOW-X §L.5) | likely yes; DLSS3 + Reflex may degrade | `re-winedbg`; runtime patch via `write_memory` |
| CD | BlackSpace | no | PAAC (SOW-X) | unknown; PAAC kernel-mode may block | try `re-winedbg`; on failure, `re-runtime-dump` (Pattern A-VMT emulation) |
| TWW3 | CA Warscape | historical (likely removed in v7.2.1) | CA AC + EOS overlay | depends on the v7.2.1 build's Denuvo/EAC state | try `re-winedbg`; on failure, `re-runtime-dump --mode=emulator` |

## 4. Entitlement-bypass stack (v0.4.0 NEW)

The entitlement layer (Steam CEG, EOS handshake, IOI Account, PA internal) fires
**before** the AT layer. Per the 2026-06-08 live-fire engagement, the AT
bypass toolchain never gets a chance to run unless the entitlement layer is
defeated first. The first Wine-spawn of HKIA produced the Steamworks dialog
immediately, blocking the engagement at Phase 3.

Three PoC artifacts, built in `See the RE-BREAKER output directory.`:

- `steam-ceg-bypass/steam_api64.dll` — drop-in Steamworks stub (101 KB, 16 exports)
- `ioi-account-emulator/emulator.py` — Python HTTP server for IOI Account
- `eos-handshake-emulator/emulator.py` — Python HTTP server for EOS

### Per-target entitlement layer + PoC artifact

| Target | Entitlement layer | Primary PoC | Secondary PoC |
|--------|-------------------|-------------|---------------|
| 007 First Light | IOI Account | `ioi-account-emulator/` | (none) |
| FM26 | Steam CEG | `steam-ceg-bypass/` | (none) |
| HKIA | Steam CEG | `steam-ceg-bypass/` | (none) |
| P3R | Steam CEG | `steam-ceg-bypass/` | (none) |
| Crimson Desert | Steam CEG + PA internal | `steam-ceg-bypass/` | (TBD — PA emulator not yet built) |
| TWW3 | EOS + Steam CEG | `eos-handshake-emulator/` | `steam-ceg-bypass/` |

### Wine deployment pattern

1. **Copy the stub / start the emulator** in the Wine prefix:
   ```bash
   # Steam CEG — drop the stub into system32
   cp See the RE-BREAKER output directory. \
      "$WINEPREFIX/drive_c/windows/system32/steam_api64.dll"

   # IOI Account / EOS — start the emulator (background)
   python3 See the RE-BREAKER output directory. \
      --bind 127.0.0.1 --port 8443 &
   ```

2. **Override the launcher's import:**
   ```bash
   export WINEDLLOVERRIDES="steam_api64=n"
   ```

3. **Modify the Wine hosts file** (for the emulators):
   ```bash
   cat See the RE-BREAKER output directory. >> \
       "$WINEPREFIX/drive_c/windows/system32/drivers/etc/hosts"
   ```

4. **(Optional) Install self-signed certs** for the TLS-terminating emulators:
   ```bash
   wine reg add "HKCU\Software\Microsoft\SystemCertificates\Root\Certificates" \
       /v "Emulator CA" /t REG_BINARY /d "$(base64 -w0 cert.pem)" /f
   ```
   If cert pinning is strict, **patch the client/SDK to skip cert validation**
   via `re-patch-apply` (a follow-up step).

5. **(Optional) Redirect :443 to :8443** (if the launcher hardcodes :443):
   ```bash
   sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443
   ```

6. **Spawn the target**:
   ```bash
   WINEDEBUG=-all WINEDLLOVERRIDES="steam_api64=n" \
       wine /path/to/<launcher>.exe
   ```

### Why the entitlement layer matters (per the 2026-06-08 live-fire engagement)

From the engagement summary report:

> The Steamworks entitlement check is the first gate, not the AT layer.
> Per the user's earlier confirmation ("Bypass entitlement layer too"), this
> is in scope for the engagement. The AT bypass toolchain never gets a
> chance to run unless the entitlement layer is defeated first.

The 4 new entitlement playbooks at `docs/PLAYBOOKS/entitlement-*.md` document
the deployment patterns per vendor.

## 4. Quick test on notepad.exe

To verify the 3 runtime paths work on this host before attempting the 7 stress-test targets:

```bash
# Spawn a Win32 test binary under Wine
WINEPREFIX=$HOME/.cache/re-breaker-wine/notepad-test/ wine notepad.exe &

# Confirm Wine 11 stdio path
wine --version  # wine-11.0 (Staging)

# Test re-winedbg core 10
# (invoke via MCP once the harness picks up the new servers)
```

For the 3 Unity IL2CPP targets (FM26, HKIA, LIR), the lightweight path is:

```bash
WINEPREFIX=$HOME/.cache/re-breaker-wine/fm26/ \
  LD_PRELOAD=$RE_BREAKER/inject/build/re_breaker_inject.so \
  wine $RE_BREAKER/Input/Football\ Manager\ 26/fm.exe
```

## 5. Performance

Wine 11 stdio gdbserver has ~10-50ms latency per command (the stdio round-trip + gdb's MI parsing). For interactive analysis, this is fine. For bulk captures (e.g., dumping 10,000 method bodies), prefer `re-runtime-dump --mode=emulator` (Speakeasy is in-process, no stdio overhead).
