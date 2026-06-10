# re-speakeasy

MCP server for [Speakeasy](https://github.com/mandiant/speakeasy) (Mandiant, Apache-2.0) — Windows API emulation for binary analysis. The "run a .exe in a Wine-like sandbox and tell me what it did" tool.

## Why

The other RE-AI MCP servers analyze binaries **statically** (no execution): `re-lief` reads headers, `re-rizin` disassembles, `re-triton` symbolically executes individual functions. None of them can answer "what APIs does this .exe call, with what arguments, in what order, when I run it?"

`re-speakeasy` fills that gap. Speakeasy is a Windows API emulator — it loads the .exe / .dll in-process and serves the same Win32 surface that Windows would, but in pure Python. The output is a per-API trace that complements the static analysis: "the static strings say this binary calls `CreateFileW`" + "the dynamic trace confirms it calls `CreateFileW("C:\\Users\\...", GENERIC_READ, ...)`".

## Architecture

The Python MCP server is a thin wrapper around a `speakeasy-cli` Python helper installed by install.sh:

```
Claude Code (MCP stdio)
  │
  ▼
re-speakeasy server (Python, this directory)
  │  subprocess.run(...)
  ▼
speakeasy-cli (small Python script, wraps the Speakeasy API)
  │
  └─ speakeasy-emulator (pip-installed, the actual emulator)
```

The subprocess boundary is intentional: Speakeasy is a heavy Python package with rich in-process APIs. The subprocess wrapper keeps the MCP server's memory footprint small and lets Claude Code load the plugin in degraded mode if Speakeasy isn't installed.

## Tools

| Tool | What it does |
|---|---|
| `check_speakeasy` | Health check — return Speakeasy version + API count |
| `emulate_binary` | Run a .exe / .dll under Speakeasy, return per-API trace |
| `list_emulated_apis` | Return the count + sample of the Win32 API catalog Speakeasy emulates |

## Install

`./install.sh` installs `speakeasy-emulator` from PyPI.

To install standalone:

```bash
pip install speakeasy-emulator
```

## Requirements

- Python 3.11+
- `speakeasy-emulator` (Apache-2.0, on PyPI)
- No system dependencies

## Degraded mode

If `speakeasy-cli` is not installed, every tool returns `{"status": "WARN", "error": "speakeasy-cli not installed; run install.sh", ...}`. The Python MCP server itself always loads so Claude Code can surface the install hint.

## Pairing with `re-winedbg`

`re-winedbg` runs a Windows .exe under Wine (the full Windows compatibility layer, including x86_64 emulation) and exposes a gdbserver for interactive debugging. `re-speakeasy` runs the .exe under Speakeasy (the pure-Python emulator, no real CPU) and returns a structured API trace.

- Use `re-speakeasy.emulate_binary` for "what did this binary do, end-to-end, with a structured trace?" — fast, no x86 emulation, can be retried safely.
- Use `re-winedbg.start_winedbg_gdbserver` for "I want to step through this binary interactively, with breakpoints" — slower (full Wine + gdbserver), but gives the analyst control.

For the encrypted-VM bytecode family: `re-speakeasy.emulate_binary` is the right first call (let the encrypted stub decrypt, watch the dispatcher fire, see which handlers execute); `re-winedbg` is the right follow-up when the analyst wants to break at a specific handler entry.

## Pairing with `re-leak-scan`

The Speakeasy trace includes network calls (`WinHttpOpen`, `WSAConnect`, `InternetOpenUrl`, ...). Cross-reference against `re-leak-scan.find_secrets` to confirm whether the dynamic calls match the static string-table leaks. The Sentry DSN or Logstash URL in the strings is a credential; the same URL appearing in the Speakeasy trace is the actual call site.
