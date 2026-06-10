# re-injection-runtime

RE-BREAKER C-injection runtime (v0.4.0). Wraps the `re-c-injection-build` C library (inline trampolines, IAT/GOT override, named-pipe/Unix-socket IPC) for runtime hooking without Frida.

Useful when:
- Frida-on-Wine is unavailable (no frida-gadget, no Wine)
- JS-hook overhead is too high for tight loops
- The hook spec is simple enough to express in C

See `src/re_injection_runtime/server.py` for the 4 tools exposed.
