"""re-ghidra-remote MCP server (v0.5.2 FULLY IMPLEMENTED).

Thin proxy MCP server to `bethington/ghidra-mcp` running in the
Windows VM. The upstream has 3 components: the Java plugin
(`GhidraMCP.jar`) loaded into Ghidra, the Python bridge
(`bridge_mcp_ghidra.py`), and the headless Ghidra `analyzeHeadless`
for the programmatic path.

Auth: the upstream refuses to bind to non-loopback unless
`GHIDRA_MCP_AUTH_TOKEN` is set (Bearer token, timing-safe). We
read `$RE_BREAKER_GHIDRA_AUTH_TOKEN` and pass it to the proxy as
a Bearer header.

v0.5.2 ships fully functional:
  - status, start_ghidra_mcp, stop_ghidra_mcp
  - open_program (runs Ghidra analyzeHeadless + bridges to the
    upstream)
  - list_functions, decompile_function, list_xrefs
  - run_script_inline (gated behind RE_BREAKER_GHIDRA_ALLOW_SCRIPTS=1)
  - get_metadata
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

from re_breaker.vm_client import DEFAULT_VM_NAME, open_tunnel, close_tunnel, ssh_exec
from re_vm_bridge.proxy import BridgeProxy, BridgeProxyError, get_or_open, close as close_proxy, list_open
from re_ghidra_remote import __version__


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-ghidra-remote")
mcp = FastMCP("re-ghidra-remote") if FastMCP else None

_GHIDRA_AUTH_TOKEN = os.environ.get("RE_BREAKER_GHIDRA_AUTH_TOKEN") or None
_GHIDRA_ALLOW_SCRIPTS = bool(os.environ.get("RE_BREAKER_GHIDRA_ALLOW_SCRIPTS"))

_GHIDRA_STATE: dict[str, Any] = {
    "started": False,
    "pid": None,
    "auth_token_present": bool(_GHIDRA_AUTH_TOKEN),
    "tunnel_name": "ghidra-mcp",
    "local_port": 18089,
    "remote_port": 8089,
    "ghidra_path": r"C:\ghidra",
    "launch_command": (
        r"$env:GHIDRA_INSTALL_DIR='C:\ghidra'; "
        r"$env:GHIDRA_MCP_AUTH_TOKEN = (Get-Content $env:USERPROFILE\.ghidra-mcp-token -Raw).Trim(); "
        r"cd /d C:\re-mcps\ghidra-mcp; "
        r"start /B cmd /c \"python bridge_mcp_ghidra.py --mcp-transport http --mcp-port 8089\""
    ),
}


@mcp.tool()
def status() -> dict:
    return {
        "status": "ok",
        "server": "re-ghidra-remote",
        "version": __version__,
        "implementation": "real",
        "vm_name": DEFAULT_VM_NAME,
        "upstream": dict(_GHIDRA_STATE),
        "auth_token_present": _GHIDRA_STATE["auth_token_present"],
        "allow_scripts": _GHIDRA_ALLOW_SCRIPTS,
        "tools_implemented": 8,
        "tools_total": 8,
    }


@mcp.tool()
def start_ghidra_mcp(
    tunnel_name: str = "ghidra-mcp",
    local_port: int = 18089,
    ghidra_path: str = r"C:\ghidra",
) -> dict:
    """Open the SSH tunnel + start the upstream via re-vm-ssh.ssh_exec."""
    global _GHIDRA_STATE
    if _GHIDRA_STATE["started"]:
        return {"tool": "start_ghidra_mcp", "status": "ok", "already_started": True, **dict(_GHIDRA_STATE)}
    try:
        open_tunnel(name=tunnel_name, local_port=local_port, remote_host="127.0.0.1", remote_port=8089)
    except Exception as e:
        return {"tool": "start_ghidra_mcp", "status": "error", "error": f"failed to open SSH tunnel: {e}"}
    launch_cmd = _GHIDRA_STATE["launch_command"].replace("C:\\ghidra", ghidra_path)
    res = ssh_exec(launch_cmd, use_powershell=True, timeout_s=15)
    pid_res = ssh_exec(
        'powershell -NoProfile -Command "(Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*bridge_mcp_ghidra*' } | Select-Object -First 1 -ExpandProperty Id)"',
        use_powershell=True, timeout_s=10,
    )
    try:
        pid = int(pid_res["stdout"].strip() or 0)
    except (ValueError, AttributeError):
        pid = 0
    _GHIDRA_STATE.update({
        "started": True,
        "pid": pid,
        "tunnel_name": tunnel_name,
        "local_port": local_port,
        "remote_port": 8089,
        "ghidra_path": ghidra_path,
    })
    return {"tool": "start_ghidra_mcp", "status": "ok", "already_started": False, **dict(_GHIDRA_STATE)}


@mcp.tool()
def stop_ghidra_mcp() -> dict:
    global _GHIDRA_STATE
    if not _GHIDRA_STATE["started"]:
        return {"tool": "stop_ghidra_mcp", "status": "ok", "already_stopped": True}
    close_tunnel(_GHIDRA_STATE["tunnel_name"])
    close_proxy("ghidra-mcp")
    ssh_exec(
        'powershell -NoProfile -Command "Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like \'*bridge_mcp_ghidra*\' } | Stop-Process -Force"',
        use_powershell=True, timeout_s=10,
    )
    _GHIDRA_STATE.update({"started": False, "pid": None})
    return {"tool": "stop_ghidra_mcp", "status": "ok", "tunnel_closed": True, "guest_kill": True}


def _proxy() -> BridgeProxy:
    if not _GHIDRA_STATE["started"]:
        raise BridgeProxyError("ghidra-mcp not started; call start_ghidra_mcp() first")
    return get_or_open(
        name="ghidra-mcp",
        local_port=_GHIDRA_STATE["local_port"],
        upstream_path="/mcp",
        auth_token=_GHIDRA_AUTH_TOKEN,
        timeout_s=60.0,
    )


@mcp.tool()
def open_program(binary_path: str, project_name: Optional[str] = None) -> dict:
    """Open a binary in Ghidra (runs `analyzeHeadless` in the guest
    + registers the result on the bridge via upstream `open_program`)."""
    from re_breaker.vm_client import ssh_exec
    if not project_name:
        project_name = Path(binary_path).stem
    proj_dir = "C:\\ghidra-projects"
    ps = (
        f"& '{_GHIDRA_STATE['ghidra_path']}\\support\\analyzeHeadless.bat' "
        f"'{proj_dir}' '{project_name}' -import '{binary_path}' -deleteProject"
    )
    headless = ssh_exec(ps, use_powershell=True, timeout_s=300)
    try:
        return _proxy().call("open_program", binary_path=binary_path, project_name=project_name)
    except Exception as e:
        return {
            "tool": "open_program",
            "status": "error",
            "error": str(e),
            "headless_stderr": headless.get("stderr"),
        }


@mcp.tool()
def list_functions() -> dict:
    try:
        return _proxy().call("list_functions")
    except Exception as e:
        return {"tool": "list_functions", "status": "error", "error": str(e)}


@mcp.tool()
def decompile_function(address: str) -> dict:
    try:
        return _proxy().call("decompile_function", address=address)
    except Exception as e:
        return {"tool": "decompile_function", "status": "error", "error": str(e)}


@mcp.tool()
def list_xrefs(address: str) -> dict:
    try:
        return _proxy().call("get_xrefs", address=address)
    except Exception as e:
        return {"tool": "list_xrefs", "status": "error", "error": str(e)}


@mcp.tool()
def run_script_inline(script: str) -> dict:
    """Refuses unless `$RE_BREAKER_GHIDRA_ALLOW_SCRIPTS=1` AND
    `GHIDRA_MCP_ALLOW_SCRIPTS=1` on the upstream. Mirrors the
    upstream's documented gating (added v5.4.1)."""
    if not _GHIDRA_ALLOW_SCRIPTS:
        return {
            "tool": "run_script_inline",
            "status": "error",
            "error": "RE_BREAKER_GHIDRA_ALLOW_SCRIPTS not set; refusing to run arbitrary script in guest",
        }
    try:
        return _proxy().call("run_script_inline", script=script)
    except Exception as e:
        return {"tool": "run_script_inline", "status": "error", "error": str(e)}


@mcp.tool()
def get_metadata() -> dict:
    try:
        return _proxy().call("get_metadata")
    except Exception as e:
        return {"tool": "get_metadata", "status": "error", "error": str(e)}


def main() -> None:
    if mcp is None:
        raise SystemExit("mcp[cli] not installed; `uv add mcp[cli]`")
    mcp.run()


if __name__ == "__main__":
    main()
