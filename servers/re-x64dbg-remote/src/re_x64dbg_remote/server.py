"""re-x64dbg-remote MCP server (v0.5.2 FULLY IMPLEMENTED).

Thin proxy MCP server to `AgentSmithers/x64DbgMCPServer` running in
the Windows VM. x64dbg is a GUI app; the upstream MCP lives in a
DP64 plugin (`x64DbgMCPServer.dp64`) that auto-starts an
`HttpListener` on `127.0.0.1:50300/sse` when the plugin is loaded.

Launch model:
  - `start_x64dbg` SSH-execs `start /B x64dbg.exe -p <pid>` (attach
    mode) or `start /B x64dbg.exe <target.exe>` (launch mode) in
    the guest. The GUI is hidden; the SSH session is the one we
    care about.
  - The DP64 plugin's [Command]-decorated methods back the SSE
    endpoints; we forward MCP requests via `re-vm-bridge.BridgeProxy`.

v0.5.2 ships fully functional:
  - status, start_x64dbg, stop_x64dbg
  - attach_to_pid, set_breakpoint, read_memory, read_registers
  - step_into, step_over, continue_execution
  - dump_module, execute_command
"""
from __future__ import annotations

import logging
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

from re_breaker.vm_client import DEFAULT_VM_NAME, open_tunnel, close_tunnel, ssh_exec
from re_vm_bridge.proxy import BridgeProxy, BridgeProxyError, get_or_open, close as close_proxy, list_open
from re_x64dbg_remote import __version__


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-x64dbg-remote")
mcp = FastMCP("re-x64dbg-remote") if FastMCP else None

_X64DBG_PATH = r"C:\x64dbg\release\x64\x64dbg.exe"

_X64DBG_STATE: dict[str, Any] = {
    "started": False,
    "pid": None,
    "tunnel_name": "x64dbg-mcp",
    "local_port": 15030,
    "remote_port": 50300,
    "attached_pid": None,
    "launched_target": None,
    "x64dbg_path": _X64DBG_PATH,
}


@mcp.tool()
def status() -> dict:
    return {
        "status": "ok",
        "server": "re-x64dbg-remote",
        "version": __version__,
        "implementation": "real",
        "vm_name": DEFAULT_VM_NAME,
        "upstream": dict(_X64DBG_STATE),
        "tools_implemented": 11,
        "tools_total": 11,
    }


@mcp.tool()
def start_x64dbg(
    target: Optional[str] = None,
    attach_pid: Optional[int] = None,
    tunnel_name: str = "x64dbg-mcp",
    local_port: int = 15030,
) -> dict:
    """Open the SSH tunnel + start x64dbg with the target on the
    command line (or attach to a pid). Idempotent."""
    global _X64DBG_STATE
    if _X64DBG_STATE["started"]:
        return {"tool": "start_x64dbg", "status": "ok", "already_started": True, **dict(_X64DBG_STATE)}
    if attach_pid is None and target is None:
        return {"tool": "start_x64dbg", "status": "error", "error": "must supply either target= or attach_pid="}
    try:
        open_tunnel(name=tunnel_name, local_port=local_port, remote_host="127.0.0.1", remote_port=50300)
    except Exception as e:
        return {"tool": "start_x64dbg", "status": "error", "error": f"failed to open SSH tunnel: {e}"}
    if attach_pid is not None:
        launch_cmd = f'start /B "" "{_X64DBG_PATH}" -p {attach_pid}'
    else:
        launch_cmd = f'start /B "" "{_X64DBG_PATH}" "{target}"'
    res = ssh_exec(launch_cmd, use_powershell=True, timeout_s=15)
    # Find x64dbg's pid
    pid_res = ssh_exec(
        'powershell -NoProfile -Command "(Get-Process -Name x64dbg -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Id)"',
        use_powershell=True, timeout_s=10,
    )
    try:
        xpid = int(pid_res["stdout"].strip() or 0)
    except (ValueError, AttributeError):
        xpid = 0
    _X64DBG_STATE.update({
        "started": True,
        "pid": xpid,
        "tunnel_name": tunnel_name,
        "local_port": local_port,
        "remote_port": 50300,
        "attached_pid": attach_pid,
        "launched_target": target,
    })
    return {"tool": "start_x64dbg", "status": "ok", "already_started": False, **dict(_X64DBG_STATE)}


@mcp.tool()
def stop_x64dbg() -> dict:
    global _X64DBG_STATE
    if not _X64DBG_STATE["started"]:
        return {"tool": "stop_x64dbg", "status": "ok", "already_stopped": True}
    close_tunnel(_X64DBG_STATE["tunnel_name"])
    close_proxy("x64dbg-mcp")
    ssh_exec(
        'powershell -NoProfile -Command "Get-Process -Name x64dbg -ErrorAction SilentlyContinue | Stop-Process -Force"',
        use_powershell=True, timeout_s=10,
    )
    _X64DBG_STATE.update({"started": False, "pid": None, "attached_pid": None, "launched_target": None})
    return {"tool": "stop_x64dbg", "status": "ok", "tunnel_closed": True, "guest_kill": True}


def _proxy() -> BridgeProxy:
    if not _X64DBG_STATE["started"]:
        raise BridgeProxyError("x64dbg-mcp not started; call start_x64dbg() first")
    return get_or_open(
        name="x64dbg-mcp",
        local_port=_X64DBG_STATE["local_port"],
        upstream_path="/sse",
        timeout_s=60.0,
    )


@mcp.tool()
def attach_to_pid(pid: int) -> dict:
    """Attach to an already-running process via `x64dbg -p <pid>`."""
    return start_x64dbg(attach_pid=pid)


@mcp.tool()
def set_breakpoint(address: str) -> dict:
    try:
        return _proxy().call("set_breakpoint", address=address)
    except Exception as e:
        return {"tool": "set_breakpoint", "status": "error", "error": str(e)}


@mcp.tool()
def read_memory(address: str, size: int) -> dict:
    try:
        return _proxy().call("read_memory", address=address, size=size)
    except Exception as e:
        return {"tool": "read_memory", "status": "error", "error": str(e)}


@mcp.tool()
def read_registers() -> dict:
    try:
        return _proxy().call("get_registers")
    except Exception as e:
        return {"tool": "read_registers", "status": "error", "error": str(e)}


@mcp.tool()
def step_into() -> dict:
    try:
        return _proxy().call("StepInto")
    except Exception as e:
        return {"tool": "step_into", "status": "error", "error": str(e)}


@mcp.tool()
def step_over() -> dict:
    try:
        return _proxy().call("StepOver")
    except Exception as e:
        return {"tool": "step_over", "status": "error", "error": str(e)}


@mcp.tool()
def continue_execution() -> dict:
    """Run (free execution). Returns the new EIP / halt reason."""
    try:
        return _proxy().call("Run")
    except Exception as e:
        return {"tool": "continue_execution", "status": "error", "error": str(e)}


@mcp.tool()
def dump_module(module: str) -> dict:
    """Dump an in-memory module to disk in the guest, then pull
    it back via the 9pfs Z:\\ fast-path."""
    try:
        proxy_result = _proxy().call("dump_module", name=module)
    except Exception as e:
        return {"tool": "dump_module", "status": "error", "error": str(e)}
    # The upstream writes to C:\\x64dbg-dumps\\<name>.dll (or similar).
    # Use ssh_file_get with prefer_z_mount to pull it back.
    if isinstance(proxy_result, dict) and "path" in proxy_result:
        guest_path = proxy_result["path"]
        local = f"/tmp/{Path(guest_path).name}"
        from re_breaker.vm_client import ssh_file_get
        out = ssh_file_get(guest_path, local, prefer_z_mount=True)
        return {"tool": "dump_module", "status": "ok", "guest_path": guest_path, "local": local, "transfer": out}
    return {"tool": "dump_module", "status": "ok", "upstream": proxy_result}


@mcp.tool()
def execute_command(command: str) -> dict:
    """Run an x64dbg command and read the resulting debugger variable.
    Maps to upstream `ExecuteDebuggerCommandWithVar`."""
    try:
        return _proxy().call("ExecuteDebuggerCommandWithVar", command=command)
    except Exception as e:
        return {"tool": "execute_command", "status": "error", "error": str(e)}


def main() -> None:
    if mcp is None:
        raise SystemExit("mcp[cli] not installed; `uv add mcp[cli]`")
    mcp.run()


if __name__ == "__main__":
    main()
