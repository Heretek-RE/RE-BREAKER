---
name: re-vm-native-toolchain
description: Play-by-play of when to use which server in the RE-BREAKER native-Windows-VM toolchain. Use this when the analyst wants to RE a binary that ships with native Windows tools (IDA Pro 9, Ghidra, x64dbg) inside the libvirt KVM win11 guest, when Wine isn't appropriate, or when kernel-mode / hypervisor-level debug is needed. The VM toolchain is at v0.5.3 of itself (ships in project v0.5.6); re-vm-launch/memory are at v0.5.1, the 3 bridges are at v0.5.2, re-vm-debug is at v0.5.3.
---

# re-vm-native-toolchain

The v0.4.x RE-BREAKER stack runs against **Wine + winedbg** for dynamic
RE. v0.5.x (project) adds a parallel stack against a real **libvirt KVM
Windows 11 guest** (`win11`, libvirt id 9) with **IDA Pro 9**, **Ghidra**,
and **x64dbg** installed natively. The host talks to the guest over
SSH with the existing ed25519 key + a 9pfs Z:\\ mount of the host
checkout at `\\home\\john\\Desktop\\RE\\RE-BREAKER`.

## Server map (as of project v0.5.6)

| Server | VM-toolchain ver | impl | Tools | Notes |
|---|---|---|---|---|
| `re-vm-control` | v0.5.0 (full) | 15/15 real | libvirt + QEMU + snapshots + SPICE + NMI + gdb-stub attach | driver for everything else |
| `re-vm-ssh` | v0.5.0 (full) | 8/8 real | paramiko + ssh_exec + file_put/get + tunnel registry | exports client/tunnel modules for the bridges |
| `re-vm-launch` | v0.5.1 (full) | 6/6 real | upload + launch + wait + kill + handle registry | WMI Create with CREATE_SUSPENDED |
| `re-vm-memory` | v0.5.1 (full) | 6/6 real | QMP pmemsave + page-walk + search + hash + diff_snapshots | shared page_walk.py in `src/re_breaker/` |
| `re-vm-debug` | v0.5.3 (full) | 15/15 real | QEMU gdb stub client (g/w packet, Z1/Z2, c/s, virt walk) | gdb stub at `127.0.0.1:1234` |
| `re-ida-remote` | v0.5.2 (full) | 9/9 real | bridge to `idalib-mcp` upstream | **live-tested ✓** end-to-end |
| `re-ghidra-remote` | v0.5.2 (full) | 8/8 real | bridge to `bethington/ghidra-mcp` | **live-tested ✓** end-to-end |
| `re-x64dbg-remote` | v0.5.2 (full) | 11/11 real | bridge to `AgentSmithers/x64DbgMCPServer` | **live-tested partial** — v1.3 plugin works on 50300, bridge `/sse` path is implemented but has a pending response-routing bug (see "What's left" below) |

## What works live (verified this session)

- **IDA** — `re-ida-remote` → `idalib-mcp` on guest 127.0.0.1:8744.
  Tools/list returns `server_health`, `lookup_funcs`, `int_convert`, and
  dozens more. End-to-end pipeline: Linux MCP client → SSH -L 28744 →
  Windows 127.0.0.1:8744 → idalib-mcp. Requires a valid IDA Pro
  license at `C:\IDA\idapro.hexlic` (or under `~/.idapro/`) and a
  valid PE binary (notepad.exe works as a placeholder).
- **Ghidra** — `re-ghidra-remote` → `bridge_mcp_ghidra.py` on guest
  127.0.0.1:8089 (streamable-HTTP). Tools/list returns
  `list_instances`, `connect_instance`. Bearer auth: pass via
  `$RE_BREAKER_GHIDRA_AUTH_TOKEN` env on the bridge.
- **x64dbg** (partial) — `re-x64DbgMCPServer.dp64` v1.3 from the
  upstream's `v1.3` release is installed at
  `C:\x64dbg\release\x64\plugins\x64DbgMCPServer\`. Listens on
  127.0.0.1:50300 using the **legacy MCP-over-SSE transport**
  (GET /sse + POST /message?sessionId=...). The bridge's legacy
  path captures the endpoint event correctly, but the response
  routing has a pending bug — see "What's left" below.

## What's left to do (resume target for the next session)

### 1. Finish the x64dbg legacy /sse response routing

`re-vm-bridge/src/re_vm_bridge/proxy.py` has the legacy transport
implemented: it auto-detects `upstream_path == "/sse"`, opens a
GET /sse stream via a single reader thread that demuxes events into
a queue. The endpoint URL is captured
(`data: /message?sessionId=<id>`). The POST URL is built. The
initial `tools/list` call sends a POST and waits on the queue for
the response with matching `id`.

**Symptom:** `tools/list` times out (`legacy: timed out waiting for
response to id=1`). The reader thread IS running, the POST IS
being sent, but the response doesn't appear on the queue.

**Likely cause candidates to investigate (in order):**
1. v1.3's POST handler may not actually send the response back on
   the same GET /sse stream (could be: a separate short-lived
   stream, a different response shape, or requires a specific
   `Accept` header on the POST).
2. The response might come back with a different `id` field (some
   legacy servers use the request `id` as a string vs int; check
   `int(req_id) == int(obj["id"])`).
3. v1.3 might require `Content-Type: text/event-stream` on the
   POST (or some other header combination).
4. The reader thread might be crashing silently — add a
   `log.info` at the end of `_legacy_sse_reader` to confirm it's
   still running after the endpoint event.

**Test command:**
```bash
cd RE_BREAKER_PLUGIN_ROOT
python3.12 -c "
import sys, time
sys.path.insert(0, 'servers/re-vm-ssh/src')
sys.path.insert(0, 'src')
from re_breaker.vm_client import open_tunnel
open_tunnel(name='x64dbg-test', local_port=15030, remote_host='127.0.0.1', remote_port=50300)
time.sleep(60)
" &
sleep 4
python3.12 -c "
import sys
sys.path.insert(0, 'servers/re-vm-bridge/src')
sys.path.insert(0, 'src')
from re_vm_bridge.proxy import BridgeProxy
proxy = BridgeProxy(name='x64dbg', local_port=15030, upstream_path='/sse', timeout_s=20.0)
proxy.open()
print('post_url:', proxy._legacy_post_url)
print(proxy.call('tools/list')[:2000])
"
```

### 2. Wait for v1.5 of x64DbgMCPServer

The upstream README says:
> "Unless you directly require x64 streamable HTTP MCP server use
> ver 1.3"

v1.4 (the Streamable HTTP one on the `Compiled` tag) is broken per
the upstream's own README + the `.log` file in the zip
(`AmbiguousMatchException`, `TypeLoadException`). v1.5 is
forthcoming.

**When v1.5 ships:** switch `re-x64dbg-remote.start_x64dbg()` to
launch v1.5, then change `BridgeProxy(..., upstream_path="/mcp")`
in the bridge to talk the new transport. The bridge proxy
already auto-detects `/mcp` as the streamable-HTTP transport.
One-line change.

### 3. (Optional) Pre-built v1.4 try

The v1.4 streamable release at
`https://github.com/AgentSmithers/x64DbgMCPServer/releases/tag/Compiled`
in the `x96.MCP.Http.Streamable.zip.zip` asset is the one we
want (Bearer auth, /mcp endpoint). But the prebuilt .dp64 is
broken (compile errors). Don't waste tokens on it; wait for v1.5.

## Architecture (the conventions established this session)

- **Source-of-truth: host's Z:\\ = RE-BREAKER checkout, shared
  via 9pfs.** The 3 upstream MCPs live as vendored (NOT
  submodules) at `re-mcps/<name>/` on the host. The VM also
  keeps a one-time `C:\re-mcp-src\<name>\` copy because 9pfs
  lacks the file locking that Python package builds need.
- **Windows services, not ephemeral processes.** `re-mcps/install-services.bat`
  installs `re-mcp-ida`, `re-mcp-ghidra`, `re-mcp-x64dbg` in
  `LocalSystem` session 0. They survive SSH session ends. Use
  `install-services.bat {install,start,stop,uninstall,status}`.
- **Shared SSH client.** `re-vm-ssh` exports a paramiko client
  cached in `re_breaker.vm_client.get_ssh()`. All other VM servers
  that need SSH call this. The bridge uses `open_tunnel(name,
  local_port, remote_host, remote_port)` from the same module.
- **Bridge proxy with two transport modes.** `BridgeProxy`
  auto-detects: `upstream_path="/sse"` → legacy MCP-over-SSE
  (single reader thread + queue); anything else → modern
  MCP Streamable-HTTP (POST + session-id handshake).

## File layout

```
servers/
  re-vm-control/  re-vm-ssh/  re-vm-launch/  re-vm-memory/  re-vm-debug/   (2 fully impl since v0.5.0)
  re-vm-bridge/   (shared package, not an MCP server itself)
  re-ida-remote/  re-ghidra-remote/  re-x64dbg-remote/                  (3 bridges, at v0.5.2)

src/re_breaker/
  vm_client.py       SSH + libvirt + QMP + tunnel registry
  page_walk.py        x86_64 4-level page-walk (shared by re-vm-memory + re-vm-debug)

re-mcps/                 vendored upstream MCPs (not git submodules)
  ida-pro-mcp/   ghidra-mcp/   x64DbgMCPServer/
  install-services.bat   (Windows-side installer for the 3 services)
  wrappers/         (per-upstream .bat + placeholder.exe)
  README.md         (this layout, lifecycle)
  .gitignore        (no nested .git, no build artefacts)

scripts/
  re_vm_provision_guest.py    (plan-only by default; --execute --acknowledge-license to apply)
  re_vm_smoke_test.py          (QMP + SSH + gdb stub probe)
  re_vm_manage_snapshots.py    (CLI around re-vm-control snapshot ops)
  re_vm_capture_evidence.py    (process list + SPICE screenshot)
  re_vm_attach_external_mcps.py (escape hatch for upstream-direct .mcp.json)
```

## Two-step "open a tool" pattern

For IDA / Ghidra / x64dbg (3 bridges):
1. **Revert to a known-clean snapshot.** `re-vm-control.snapshot_revert("Clean")`.
2. **Bring the tool up.** For IDA: `re-ida-remote.start_ida_mcp(local_port=18744)` —
   opens the SSH tunnel, prints the upstream launch command.
   For Ghidra: same shape via `re-ghidra-remote.start_ghidra_mcp`.
   For x64dbg: `re-x64dbg-remote.start_x64dbg(target=...)` — launches
   x64dbg with the .dp64 plugin auto-loaded.
3. **Run the tool calls.** e.g. `re-ida-remote.decompile_function(...)`.
4. **Tear down.** `re-ida-remote.stop_ida_mcp()` (closes tunnel + kills
   upstream).

## Resume plan for the next session

1. **First action: verify VM state.** `python scripts/re_vm_smoke_test.py`
   (5/5 should still pass), then `ssh john@RE_BREAKER_SSH_HOST
   "C:\re-mcps-logs\install-services.bat status"` to see which
   services are running.
2. **Start with the x64dbg legacy /sse bug.** That's the
   in-progress work from this session. The v1.3 plugin is
   installed and listening on 50300. The bridge's legacy path
   captures the endpoint correctly. The bug is in the response
   routing. See the debug commands under "What's left" above.
3. **If/when v1.5 lands upstream**, switch the bridge to
   `upstream_path="/mcp"`.
