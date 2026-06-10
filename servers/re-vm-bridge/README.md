# re-vm-bridge

Shared package, not an MCP server. Provides `BridgeProxy` (an
httpx-SSE client to the upstream MCPs running in the Windows VM)
and a `get_or_open` registry for keeping one proxy per upstream.

Used by:

- `servers/re-ida-remote` — bridge to mrexodia/ida-pro-mcp
- `servers/re-ghidra-remote` — bridge to bethington/ghidra-mcp
- `servers/re-x64dbg-remote` — bridge to AgentSmithers/x64DbgMCPServer

The upstream MCPs run in the Windows VM (started by the analyst
via `scripts/re_vm_provision_guest.py`) and listen on
`127.0.0.1:8744` (IDA), `127.0.0.1:8089` (Ghidra), or
`127.0.0.1:50300` (x64dbg). The Linux-side `re-vm-ssh`
server opens an SSH `-L` tunnel to one of those ports; the bridges
then point their `BridgeProxy` at `127.0.0.1:<tunnel_local_port>`.
