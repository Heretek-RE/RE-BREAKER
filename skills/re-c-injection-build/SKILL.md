---
name: re-c-injection-build
version: 0.3.0
status: implemented
family: workflow
catalog_entry: null
playbook: docs/PLAYBOOKS/pattern-c.md
pattern_yaml: data/patterns/c-injection-build.yml
---

# re-c-injection-build

**v0.3.0 implemented.** Workflow for building the real C/C++ injection library. Closes G6: the v0.1.0 stubs returned -1 / no-op. v0.3.0 implements inline-trampoline hook engine, IAT/GOT override, named-pipe/Unix-socket IPC, and the `DllMain` / `__attribute__((constructor))` hook installer.

## When to use this skill

Invoke when:
- The target has a hardened anti-Frida check (Denuvo kernel driver detects Frida; some EAC integrations detect Frida)
- The operator wants in-process hooks (not Frida)
- The operator wants the runtime backend for `re-runtime-dump --mode=inject`

## Tools invoked

- `mcp__re-c-injection-build.build_injection_library(target_os="linux"|"windows"|"both", install_hooks=[...])` — builds the .so (Linux) and/or .dll (Windows)

## Workflow

1. **Check the host's toolchain.** Linux: `gcc` must be on PATH. Windows: `x86_64-w64-mingw32-gcc` must be on PATH (install via `apt install gcc-mingw-w64` on Debian/Ubuntu).
2. **Build the .so.** Call `mcp__re-c-injection-build.build_injection_library(target_os="linux", install_hooks=[...])`. The response includes the build status + the path to `re_breaker_inject.so` in `inject/build/`.
3. **(Optional) Build the .dll.** Call `mcp__re-c-injection-build.build_injection_library(target_os="windows", install_hooks=[...])`. The response includes the build status + the path to `re_breaker_inject.dll`. If mingw is not installed, the build is `skipped` with a clear error message.
4. **(Optional) Build both.** Call with `target_os="both"`.
5. **Test the .so** by `LD_PRELOAD`-ing it into a small test program that calls one of the hook APIs (e.g. CreateFileW under Wine).

## What this skill does NOT do

- Does not inject the .so/.dll into a target process. That's the runtime step (`re-runtime-dump --mode=inject` or a custom `CreateRemoteThread` / `LD_PRELOAD` invocation).
- Does not implement the full inline-trampoline hook engine for every API. v0.3.0 ships the inline-trampoline engine + the IAT/GOT override; the operator can extend it with more APIs via the `install_hooks` list.

## Known limitations

- The .so is built for the host's x86_64 architecture. For ARM64 hosts (e.g. Apple Silicon), the build is a stub (the v0.3.0 hook engine is x86_64-only).
- The .dll build requires `x86_64-w64-mingw32-gcc` on the host. If not installed, the build is skipped.
- The hook engine uses inline-trampolines (`mov rax, <addr>; jmp rax` on x86_64). This works for most APIs but not for APIs that use `ret` directly without a `jmp` (rare).

## Test cases

- **Linux .so build**: tested on the host (Linux x86_64). The .so compiles in <5s and is ~12KB.
- **Windows .dll build**: requires `x86_64-w64-mingw32-gcc`. On hosts with mingw installed, the .dll compiles in <5s and is ~20KB.
- **LD_PRELOAD test**: `LD_PRELOAD=./inject/build/re_breaker_inject.so /bin/ls` should not crash and should print "[re-breaker] hook installed: kernel32.dll!CreateFileW" or similar (the v0.3.0 implementation prints a debug message).

## See also

- [RE-BREAKER README](../../README.md)
- [re-c-injection-build server](../../servers/re-c-injection-build/)
- [inject/src/](../../inject/src/) — the C/C++ source
- [Pattern C (proprietary engine) playbook](../../docs/PLAYBOOKS/ioi-glacier-shielding.md)
