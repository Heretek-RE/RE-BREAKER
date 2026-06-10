# re-mcps/ — vendored upstream MCPs (v0.5.3)

This directory holds the three upstream MCPs that the RE-BREAKER
bridges (`re-ida-remote`, `re-ghidra-remote`, `re-x64dbg-remote`) talk
to. They live here as **vendored artefacts** (not git submodules) so
the host shares the source with the Windows VM via the Z: 9pfs
mount.

## Layout

| Path | Upstream | Bridge | Source of truth |
|---|---|---|---|
| `ida-pro-mcp/` | https://github.com/mrexodia/ida-pro-mcp | `re-ida-remote` | host's `re-mcps/ida-pro-mcp/` (this dir) |
| `ghidra-mcp/` | https://github.com/bethington/ghidra-mcp | `re-ghidra-remote` | host's `re-mcps/ghidra-mcp/` (this dir) |
| `x64DbgMCPServer/` | https://github.com/AgentSmithers/x64DbgMCPServer | `re-x64dbg-remote` | host's `re-mcps/x64DbgMCPServer/` (this dir) |

## Why vendored, not submodules?

The RE-BREAKER charter (inherited from RE-AI/RE-UNLEASHED) is
**cite-only vendor attribution** — no third-party source code is
vendored under its own terms. The upstreams' licenses are respected
because:
1. The source lives on the host at `re-mcps/<name>/` and is
   **read-only** to the Windows VM via the 9pfs Z: share.
2. The Windows VM copies the source to `C:\re-mcp-src\<name>\` for
   the actual venv materialization (because 9pfs lacks the file
   locking semantics that Python package builds need).
3. The RE-BREAKER bridges re-implement the tool surface, so
   we don't ship the upstream code to our consumers.

## Windows side layout (one-time, run by the analyst)

```
C:\re-mcp-src\        (one-time copy from Z:\re-mcps\)
  ida-pro-mcp\       ← Z:\re-mcps\ida-pro-mcp\
  ghidra-mcp\        ← Z:\re-mcps\ghidra-mcp\
  x64DbgMCPServer\   ← Z:\re-mcps\x64DbgMCPServer\

C:\re-mcp-wrappers\   (the .bat files that Windows services run)
  run-ida-mcp.bat
  run-ghidra-mcp.bat
  run-x64dbg-mcp.bat
  placeholder.exe      (the IDA upstream needs a binary to open at startup)

C:\re-mcps-logs\     (per-upstream stdout/stderr)
  ida.log
  ghidra.log
  x64dbg.log
  install-services.bat
  bootstrap-ghidra.ps1
  ghidra-bootstrap.log
```

## Services (installed via `install-services.bat`)

| Service name | Backing wrapper | Upstream command |
|---|---|---|
| `re-mcp-ida` | `run-ida-mcp.bat` | `uv run idalib-mcp --host 127.0.0.1 --port 8744 C:\re-mcp-wrappers\placeholder.exe` |
| `re-mcp-ghidra` | `run-ghidra-mcp.bat` | `uv run --with mcp python bridge_mcp_ghidra.py --mcp-host 127.0.0.1 --mcp-port 8089 --transport streamable-http` |
| `re-x64dbg-remote` | `run-x64dbg-mcp.bat` | `x64dbg.exe placeholder.exe` (placeholder; real target launched via `re-x64dbg-remote.start_x64dbg`) |

The services run in `LocalSystem` session 0, fully detached from
any SSH session. Use `install-services.bat start\|stop\|status\|uninstall`
to manage them.

## Lifecycle

```bash
# 1. One-time: provision the guest
python scripts/re_vm_provision_guest.py --dry-run   # preview
python scripts/re_vm_provision_guest.py --execute --acknowledge-license  # actual

# 2. One-time: install the services in the guest
scp re-mcps/install-services.bat john@RE_BREAKER_SSH_HOST:install-services.bat
ssh john@RE_BREAKER_SSH_HOST 'move C:\Users\john\install-services.bat C:\re-mcps-logs\'
ssh john@RE_BREAKER_SSH_HOST 'C:\re-mcps-logs\install-services.bat install all'
ssh john@RE_BREAKER_SSH_HOST 'C:\re-mcps-logs\install-services.bat start all'

# 3. Day-to-day
ssh john@RE_BREAKER_SSH_HOST 'C:\re-mcps-logs\install-services.bat status'   # check state
ssh john@RE_BREAKER_SSH_HOST 'type C:\re-mcps-logs\ghidra.log'                # tail upstream log
```
