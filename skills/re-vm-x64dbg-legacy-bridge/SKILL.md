---
name: re-vm-x64dbg-legacy-bridge
description: In-progress work on the x64dbg legacy MCP-over-SSE transport in the re-vm-bridge proxy. Use this when the next session resumes the v0.5.2-of-VM-toolchain (project v0.5.5) work on re-x64dbg-remote — specifically, when the bridge's `tools/list` call against x64DbgMCPServer v1.3 times out with "legacy: timed out waiting for response to id=N".
---

# re-vm-x64dbg-legacy-bridge (in progress)

## The problem in one sentence

`servers/re-vm-bridge/src/re_vm_bridge/proxy.py`'s `BridgeProxy` is
auto-detecting `upstream_path == "/sse"` and routing calls through
the legacy MCP-over-SSE transport (GET /sse + POST /message?sessionId=...).
The endpoint capture works. The POST goes out. The reader thread is
running. But the response never appears on the queue, so
`call('tools/list')` times out after 20s with:
`upstream x64dbg-legacy-N legacy: timed out waiting for response to id=1`

## What's known to work (verified)

- x64dbg is running in the guest (x64DbgMCPServer v1.3 prebuilt
  `.dp64` + `.Impl.dll` + `.RemotingHelper.dll` installed at
  `C:\x64dbg\release\x64\plugins\x64DbgMCPServer\`).
- v1.3 listens on 127.0.0.1:50300 and serves the legacy
  MCP-over-SSE transport.
- The bridge opens `GET /sse` successfully and parses the
  `event: endpoint` / `data: /message?sessionId=<id>` line.
- The session id is captured into `proxy._session_id`.
- `proxy._legacy_post_url` is set to
  `http://127.0.0.1:<port>/message?sessionId=<id>`.
- The reader thread `proxy._legacy_sse_reader` is running and
  iterates `resp.iter_bytes()`.

## The bug

After `_open_legacy` returns, the first call to
`_raw_call_legacy("tools/list", {})`:
1. POSTs the JSON-RPC payload to `proxy._legacy_post_url`
2. The POST response itself may or may not contain a JSON-RPC
   `result` (some legacy upstreams return the result in the POST
   body, others push it via the SSE stream)
3. Waits up to `timeout_s` (20s) on `_legacy_event_q` for a
   queue item with the matching `id`
4. Times out — nothing arrived

## Hypotheses to test, in order of likelihood

### H1: v1.3's POST handler returns 200 with a 202-like acknowledgement and pushes the actual response on a *new* short-lived SSE stream per request

Test: in the raw socket probe, do TWO GET /sse streams with
the same sessionId get separate responses? If yes, the bridge
needs to also poll a new GET /sse after each POST.

```bash
# In the guest (PowerShell):
# After running our test which makes one POST, are there multiple
# "data: " events in the original /sse stream, or is the second
# request routed to a new stream?
```

### H2: v1.3's response is JSON-RPC without an `id` field (just `result`)

Look at the actual SSE events the upstream is sending. Maybe
the response is shaped like `{"result": {...}}` without
`jsonrpc: "2.0"` or `id` fields. The reader thread's parser:

```python
try:
    obj = json.loads(event_data)
    req_id = obj.get("id")
    if req_id is not None:
        self._legacy_event_q.put((req_id, obj))
except Exception:
    pass
```

silently drops events that lack an `id`. Add a debug log:

```python
log.info("legacy reader got event: %s", event_data[:200])
```

in `_legacy_sse_reader` to see what shape the events actually are.

### H3: The reader thread IS reading but the queue connection is broken

The reader pushes `(req_id, obj)` tuples. The consumer in
`_raw_call_legacy` does:

```python
while time.time() < deadline:
    try:
        item = self._legacy_event_q.get(timeout=0.5)
    except queue.Empty:
        continue
    if item is None:
        break
    rid, obj = item
    if rid == req_id:
        return obj.get("result", obj)
```

If `item` is some other shape (e.g., a 3-tuple, a dict), this
unpacks wrong. Add a debug log on the consumer side too:

```python
log.info("legacy consumer got item type=%s val=%s", type(item), item)
```

### H4: The POST response body itself IS the JSON-RPC result (no SSE needed)

Some legacy MCP implementations return the result synchronously
in the POST response body. The current code does try this:

```python
try:
    direct = resp.json()
    if "id" in direct and direct["id"] == req_id and "result" in direct:
        return direct.get("result", direct)
except Exception:
    pass
```

But the check is too strict. v1.3 might return `{"jsonrpc":
"2.0", "result": {...}}` without an `id` field in the direct
response. Loosen the check:

```python
if "result" in direct or "error" in direct:
    return direct.get("result", direct)
```

## How to test the next time

```bash
# 0. Verify VM state
python RE_BREAKER_PLUGIN_ROOT/scripts/re_vm_smoke_test.py
ssh john@RE_BREAKER_SSH_HOST 'C:\re-mcps-logs\install-services.bat status'
ssh john@RE_BREAKER_SSH_HOST 'powershell -NoProfile -Command "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 50300 } | Format-Table"'
# (If x64dbg isn't running, start it via the run-x64dbg-mcp.bat wrapper.)

# 1. Raw socket probe — see exactly what v1.3 sends
cat > /tmp/probe_x64dbg.py <<'PY'
import socket, time
s = socket.create_connection(('127.0.0.1', 50300), timeout=5)
# Set up SSH tunnel first (see the bridge test below for how)
# (this assumes a tunnel is open on 15030)
s = socket.create_connection(('127.0.0.1', 15030), timeout=5)
s.sendall(b'GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n\r\n')
time.sleep(2)
data = s.recv(8192).decode('utf-8', errors='replace')
print(data)
PY
# Run with a tunnel holder
cd RE_BREAKER_PLUGIN_ROOT
python3.12 -c "
import sys, time
sys.path.insert(0, 'servers/re-vm-ssh/src'); sys.path.insert(0, 'src')
from re_breaker.vm_client import open_tunnel
open_tunnel(name='x64dbg-debug', local_port=15030, remote_host='127.0.0.1', remote_port=50300)
time.sleep(120)
" &
sleep 4
python3.12 /tmp/probe_x64dbg.py

# 2. After raw probe, add debug logging to the bridge and re-run
# Edit servers/re-vm-bridge/src/re_vm_bridge/proxy.py:
#   - in _legacy_sse_reader, log every event_data line (or first 200 chars)
#   - in _raw_call_legacy, log what came out of the POST response body
#   - in _raw_call_legacy, log the queue items as they arrive

# 3. Re-test with debug logs
python3.12 -c "
import sys, time
sys.path.insert(0, 'servers/re-vm-ssh/src'); sys.path.insert(0, 'servers/re-vm-bridge/src'); sys.path.insert(0, 'src')
from re_breaker.vm_client import open_tunnel
from re_vm_bridge.proxy import BridgeProxy
open_tunnel(name='dbg', local_port=15031, remote_host='127.0.0.1', remote_port=50300)
time.sleep(60)
" &
sleep 4
python3.12 -c "
import sys; sys.path.insert(0, 'servers/re-vm-bridge/src'); sys.path.insert(0, 'src')
from re_vm_bridge.proxy import BridgeProxy
p = BridgeProxy(name='dbg', local_port=15031, upstream_path='/sse', timeout_s=20.0)
p.open()
print(p.call('tools/list'))
"
```

## When v1.5 ships upstream

The fix is a one-line change in `re-x64dbg-remote/src/re_x64dbg_remote/server.py`:

```diff
-        return get_or_open(name="x64dbg-mcp", local_port=_X64DBG_STATE["local_port"], upstream_path="/sse", timeout_s=60.0)
+        return get_or_open(name="x64dbg-mcp", local_port=_X64DBG_STATE["local_port"], upstream_path="/mcp", timeout_s=60.0)
```

(Plus updating the install command in `re-mcps/install-services.bat`'s
`run-x64dbg-mcp.bat` to launch the v1.5 build.)

The bridge's streamable-HTTP path is already battle-tested against
IDA (works end-to-end with session-id handshake + Accept negotiation
+ JSON-or-SSE response parsing). Same code will work for v1.5.

## Files touched this session (uncommitted)

`servers/re-vm-bridge/src/re_vm_bridge/proxy.py`:
- Added legacy transport import (`queue`, `threading` at top)
- Added `_transport = "sse-legacy" if upstream_path == "/sse" else "streamable-http"`
- Added `_open_legacy` (opens GET /sse, captures endpoint, starts reader)
- Added `_legacy_sse_reader` (background thread, iterates stream, pushes to queue)
- Modified `_raw_call` to dispatch to `_raw_call_legacy` for the legacy transport
- Added `_raw_call_legacy` (POST to /message?sessionId=..., wait on queue)

`re-mcps/ilrepack.runtimeconfig.json` (new):
- Configures ILRepack to allow BinaryFormatter (this approach was
  abandoned in favor of prebuilt releases, file is no longer needed
  for the immediate goal)

## RESOLVED in v0.5.8 (2026-06-09)

### Root cause (not in the SKILL hypotheses)

It wasn't H1 (new SSE per request) or H2 (no `id` field) or H4
(synchronous POST body). All three were red herrings. The actual
bug was the reader's per-chunk `splitlines()` parsing the SSE
events.

x64DbgMCPServer v1.3's GET /sse body is HTTP-chunked. The
`tools/list` response is ~5.6 KB, so the server chunks it into
five 1024-byte TCP writes plus a 406-byte tail. The old reader:

```python
for chunk in resp.iter_bytes():
    for line in chunk.decode().splitlines():
        if line.startswith("data: "):
            event_data = line[6:].strip()
            json.loads(event_data)   # SILENT FAIL on truncated JSON
```

ran `splitlines()` on each chunk independently. Chunk 1's
`data: ` line was truncated mid-JSON (`..."type"`), the
`json.loads` raised inside a bare `except: pass`, and chunks 2-5
had no `data: ` prefix at all (continuations of the previous
`data: ` line) so they were never processed. The consumer
hung on the queue until the 20s timeout.

### Fix (committed to `servers/re-vm-bridge/src/re_vm_bridge/proxy.py`)

Buffer across chunks; split on SSE event boundaries (`\n\n`);
then process each event's `data: ` line as a unit:

```python
buf = b""
for chunk in resp.iter_bytes():
    if not chunk: break
    buf += chunk
    while b"\n\n" in buf:
        event_bytes, buf = buf.split(b"\n\n", 1)
        text = event_bytes.decode("utf-8", errors="replace")
        data = next(
            (line[6:] for line in text.splitlines() if line.startswith("data: ")),
            None,
        )
        if data is None: continue
        if not self._legacy_endpoint.is_set():
            # capture /message?sessionId=... URL
            ...
            continue
        try:
            obj = json.loads(data)
            req_id = obj.get("id")
            if req_id is not None:
                self._legacy_event_q.put((req_id, obj))
        except Exception:
            pass
```

### Live verification (raw socket probe + bridge smoke test)

```
$ # 1. Raw socket probe of GET /sse + POST /message
$ GET /sse → HTTP/1.1 200 OK (chunked)
    event: endpoint
    data: /message?sessionId=0Z00IQ8GUxkzMaY3O9KUrA
$ POST /message?sessionId=0Z00IQ8GUxkzMaY3O9KUrA
  with {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
  → HTTP/1.1 202 Accepted
    body: "Accepted" (the actual JSON-RPC result is on the GET /sse stream)
$ # 2. Bridge smoke test
$ python3.12 -c 'from re_vm_bridge.proxy import BridgeProxy; ...'
$ BridgeProxy(name='x64dbg-test', local_port=15030, upstream_path='/sse', timeout_s=15.0)
$ bridge[x64dbg-test] legacy POST URL: http://127.0.0.1:15030/message?sessionId=SUBKLw16qrSDQSkaOPbSMg
$ bridge[x64dbg-test] legacy handshake ok
$ count: 19
$ all tool names:
  - StartMCPServer
  - StopMCPServer
  - ExecuteDebuggerCommand
  - ExecuteDebuggerCommandWithVar
  - ExecuteDebuggerCommandWithOutput
  - GetBreakpointInfo
  - ListDebuggerCommands
  - DbgValFromString
  - ExecuteDebuggerCommandDirect
  - WriteMemToAddress
  - CommentOrLabelAtAddress
  - GetLabel
  - GetAllModulesFromMemMap
  - GetCallStack
  - GetAllActiveThreads
  - GetAllRegisters
  - ReadDismAtAddress
  - DumpModuleToFile
  - Echo
```

All 19 tools listed. The bridge is now end-to-end live.

### Important: MCP needs a restart to pick up the fix

`re-vm-bridge` is imported at module top of
`re_x64dbg_remote.server.py`. Python's import cache pins the
version that was loaded when the MCP started, so the in-progress
session is still running the buggy reader. Restart Claude Code
(or just the `re-x64dbg-remote` MCP via `/mcp`) to load the
fixed `_legacy_sse_reader`.
