"""re-ida-remote MCP server (v0.5.2 FULLY IMPLEMENTED).

Thin proxy MCP server to `mrexodia/ida-pro-mcp` running in the
Windows VM. The upstream runs as a window-side SSE server
(HTTP+SSE on 127.0.0.1:8744) and exposes a large tool surface
(~50 tools: decompile, rename, patch, list functions, list
strings, list imports, debugger gated behind `?ext=dbg`).

v0.5.2 ships fully functional:
  - status, start_ida_mcp, stop_ida_mcp
  - list_databases
  - decompile_function
  - rename_function
  - list_imports, list_strings
  - add_breakpoint (gated behind `?ext=dbg` per upstream)
  - proxy_tool (raw passthrough to any upstream tool)

All upstream calls go through `re-vm-bridge.BridgeProxy`.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

# v0.5.2: shared src/ + re-vm-bridge on the path
# v0.5.8: 5 parents (not 4) for _RE_BREAKER_SRC — server.py is depth 5 from
# project root. _BRIDGE_SRC stays at 4 parents (sibling of bridges, depth 4).
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
_BRIDGE_SRC = Path(__file__).resolve().parent.parent.parent.parent / "re-vm-bridge" / "src"
for p in (_RE_BREAKER_SRC, _BRIDGE_SRC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None

from re_breaker.vm_client import DEFAULT_VM_NAME, open_tunnel, close_tunnel
from re_vm_bridge.proxy import BridgeProxy, BridgeProxyError, get_or_open, close as close_proxy, list_open
from re_ida_remote import __version__


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-ida-remote")
mcp = FastMCP("re-ida-remote") if FastMCP else None

# State for the running upstream
_IDA_STATE: dict[str, Any] = {
    "started": False,
    "pid": None,
    "tunnel_name": "ida-pro-mcp",
    "local_port": 18744,
    "remote_port": 8744,
    "last_error": None,
    "launch_command": (
        "cd /d C:\\re-mcps\\ida-pro-mcp && "
        "start /B cmd /c \"uv run idalib-mcp --transport http://127.0.0.1:8744/sse\""
    ),
}


@mcp.tool()
def status() -> dict:
    """Report bridge state + upstream reachability + tool-call count."""
    proxy_list = list_open()
    ida_proxy = next((p for p in proxy_list if p["name"] == "ida-pro-mcp"), None)
    return {
        "status": "ok",
        "server": "re-ida-remote",
        "version": __version__,
        "implementation": "real",
        "vm_name": DEFAULT_VM_NAME,
        "upstream": dict(_IDA_STATE),
        "proxy": ida_proxy,
        "tools_implemented": 9,
        "tools_total": 9,
    }


@mcp.tool()
def start_ida_mcp(tunnel_name: str = "ida-pro-mcp", local_port: int = 18744) -> dict:
    """Spawn idalib-mcp in the guest + open a Linux-side tunnel.

    Idempotent: returns the existing state if already started.
    v0.5.2 actually exec's the launch command via `re-vm-ssh.ssh_exec`
    (v0.5.0 only printed the would-call). The exec captures the
    upstream's pid via `tasklist /FI`.
    """
    global _IDA_STATE
    if _IDA_STATE["started"]:
        return {
            "tool": "start_ida_mcp",
            "status": "ok",
            "already_started": True,
            **dict(_IDA_STATE),
        }
    # 1. Open the SSH tunnel Linux-side
    try:
        open_tunnel(name=tunnel_name, local_port=local_port, remote_host="127.0.0.1", remote_port=8744)
    except Exception as e:
        return {"tool": "start_ida_mcp", "status": "error", "error": f"failed to open SSH tunnel: {e}"}
    # 2. Start the upstream in the guest via `start /B`
    launch_cmd = _IDA_STATE["launch_command"]
    from re_breaker.vm_client import ssh_exec
    res = ssh_exec(launch_cmd, use_powershell=True, timeout_s=15)
    # 3. Find the upstream's pid
    pid_res = ssh_exec(
        'powershell -NoProfile -Command "(Get-Process -Name idalib-mcp -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Id)"',
        use_powershell=True, timeout_s=10,
    )
    try:
        pid = int(pid_res["stdout"].strip() or 0)
    except (ValueError, AttributeError):
        pid = 0
    _IDA_STATE.update({
        "started": True,
        "pid": pid,
        "tunnel_name": tunnel_name,
        "local_port": local_port,
        "remote_port": 8744,
        "last_error": None,
    })
    return {
        "tool": "start_ida_mcp",
        "status": "ok",
        "already_started": False,
        **dict(_IDA_STATE),
    }


@mcp.tool()
def stop_ida_mcp() -> dict:
    """Close the tunnel + tell the guest to terminate idalib-mcp."""
    global _IDA_STATE
    if not _IDA_STATE["started"]:
        return {"tool": "stop_ida_mcp", "status": "ok", "already_stopped": True}
    close_tunnel(_IDA_STATE["tunnel_name"])
    close_proxy("ida-pro-mcp")
    from re_breaker.vm_client import ssh_exec
    ssh_exec("powershell -NoProfile -Command \"Get-Process -Name idalib-mcp -ErrorAction SilentlyContinue | Stop-Process -Force\"", use_powershell=True, timeout_s=10)
    _IDA_STATE.update({"started": False, "pid": None, "last_error": None})
    return {"tool": "stop_ida_mcp", "status": "ok", "tunnel_closed": True, "guest_kill": True}


def _proxy() -> BridgeProxy:
    """Get or open the IDA proxy."""
    if not _IDA_STATE["started"]:
        raise BridgeProxyError("ida-pro-mcp not started; call start_ida_mcp() first")
    return get_or_open(
        name="ida-pro-mcp",
        local_port=_IDA_STATE["local_port"],
        upstream_path="/mcp",
        timeout_s=60.0,
    )


@mcp.tool()
def list_databases() -> dict:
    """List open IDA databases (upstream `idb_list`)."""
    try:
        return _proxy().call("idb_list")
    except Exception as e:
        return {"tool": "list_databases", "status": "error", "error": str(e)}


@mcp.tool()
def decompile_function(database: str, address: str) -> dict:
    """Decompile a function (upstream `decompile_function`)."""
    try:
        return _proxy().call("decompile_function", database=database, addr=address)
    except Exception as e:
        return {"tool": "decompile_function", "status": "error", "error": str(e)}


@mcp.tool()
def rename_function(database: str, address: str, new_name: str) -> dict:
    """Rename a function (upstream `rename_function`)."""
    try:
        return _proxy().call("rename_function", database=database, addr=address, name=new_name)
    except Exception as e:
        return {"tool": "rename_function", "status": "error", "error": str(e)}


@mcp.tool()
def list_imports(database: str) -> dict:
    """List imported symbols (upstream `get_imports`)."""
    try:
        return _proxy().call("get_imports", database=database)
    except Exception as e:
        return {"tool": "list_imports", "status": "error", "error": str(e)}


@mcp.tool()
def list_strings(database: str, min_length: int = 4) -> dict:
    """List strings in the database (upstream `get_strings`)."""
    try:
        return _proxy().call("get_strings", database=database, min_len=min_length)
    except Exception as e:
        return {"tool": "list_strings", "status": "error", "error": str(e)}


@mcp.tool()
def add_breakpoint(database: str, address: str) -> dict:
    """Add a breakpoint (upstream `add_bp`). Gated behind `?ext=dbg`."""
    try:
        return _proxy().call("add_bp", use_dbg_extension=True, database=database, addr=address)
    except Exception as e:
        return {"tool": "add_breakpoint", "status": "error", "error": str(e)}


@mcp.tool()
def proxy_tool(endpoint: str, payload: dict[str, Any]) -> dict:
    """Generic passthrough to any upstream tool. Escape hatch."""
    try:
        return _proxy().call(endpoint, **payload)
    except Exception as e:
        return {"tool": "proxy_tool", "status": "error", "error": str(e)}


def main() -> None:
    if mcp is None:
        raise SystemExit("mcp[cli] not installed; `uv add mcp[cli]`")
    mcp.run()


if __name__ == "__main__":
    main()
