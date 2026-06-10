# re-winedbg

RE-BREAKER Wine + winedbg + gdb + GEF wrapper (v0.4.0). Port of RE-AI's 30-tool dynamic-analysis server. Uses `winedbg --gdb` over stdio (the Wine 11+ path) and gdb's MI interface.

Exposes 30 tools: launch_under_wine, start_winedbg_gdbserver, attach_winedbg_gdbserver, set_breakpoint, read_memory, write_memory, info_modules, gef_trace_breakpoint, gef_pattern_search, gef_ropper_search, etc.

See `src/re_winedbg/server.py` for the full tool list. v0.4.0 implements the core 10 tools; GEF helpers + convenience methods are stubs.
