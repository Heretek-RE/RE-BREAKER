"""re-vm-ssh MCP server (v0.5.0).

Paramiko-based SSH orchestration against the Windows VM. The
**second** of the two fully-implemented servers in v0.5.0 (alongside
re-vm-control). The other VM servers (re-vm-launch, the three MCP
bridges) all import this module's helpers rather than spinning fresh
paramiko sockets per tool call.

v0.5.0 ships fully functional:
  - status, guest_status
  - ssh_exec
  - ssh_file_put, ssh_file_get (via the 9pfs Z:\\ mount where possible,
    direct SCP otherwise)
  - ssh_tunnel_open, ssh_tunnel_close, tunnel_list

Note: this server's `client.py` and `tunnel.py` re-export the helpers
in `re_breaker.vm_client` so other per-server pyprojects can do
`from re_vm_ssh import client` and get the same paramiko transport
without depending on the full re_breaker shared module's import path.
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

# v0.5.0: ensure RE-BREAKER's shared src/ is on the Python path
# v0.5.8: 5 parents (not 4) — server.py is depth 5 from project root
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None

from re_breaker.vm_client import (
    DEFAULT_SSH_HOST,
    DEFAULT_SSH_KEY,
    DEFAULT_VM_NAME,
    SshSession,
    _plugin_root,
    close_ssh,
    close_tunnel,
    get_ssh,
    guest_z_path,
    host_path_from_z,
    list_tunnels,
    open_tunnel,
)
from re_vm_ssh import __version__


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-vm-ssh")
mcp = FastMCP("re-vm-ssh") if FastMCP else None


# ----------------------------------------------------------------------------
# Re-exports for "from re_vm_ssh import client" imports in other servers
# ----------------------------------------------------------------------------

from re_breaker import vm_client as client  # noqa: E402,F401
from re_breaker.vm_client import open_tunnel as _open_tunnel, close_tunnel as _close_tunnel, list_tunnels as _list_tunnels  # noqa: E402,F401
tunnel = client  # alias so `from re_vm_ssh import tunnel` works


# ----------------------------------------------------------------------------
# Tools
# ----------------------------------------------------------------------------

@mcp.tool()
def status() -> dict:
    """Report server health: SSH reachability + active tunnels."""
    try:
        sess = get_ssh()
        # Round-trip a tiny command to confirm the transport is live
        stdin, stdout, stderr = sess.client.exec_command("echo ok", timeout=5)
        ok = stdout.read().decode().strip() == "ok"
        return {
            "status": "ok" if ok else "degraded",
            "server": "re-vm-ssh",
            "version": __version__,
            "implementation": "real",
            "ssh_host": DEFAULT_SSH_HOST,
            "ssh_key": DEFAULT_SSH_KEY,
            "transport_alive": sess.client.get_transport().is_active(),
            "round_trip": ok,
            "active_tunnels": len(list_tunnels()),
            "tools_implemented": 8,
            "tools_total": 8,
        }
    except Exception as e:
        return {
            "status": "error",
            "server": "re-vm-ssh",
            "version": __version__,
            "error": str(e),
        }


@mcp.tool()
def guest_status(vm: str = DEFAULT_VM_NAME) -> dict:
    """PowerShell one-liner that returns hostname, user, uptime, and
    the top-N CPU-consuming processes. Returns the parsed dict."""
    # Use `tasklist /FO CSV /NH` to avoid codepage issues; parse on the host.
    ps = (
        "$env:COMPUTERNAME + '|' + "
        "(Get-Process -Id $PID).ProcessName + '|' + "
        "[int]([Environment]::TickCount / 1000) + '|' + "
        "([System.Diagnostics.Process]::GetCurrentProcess().WorkingSet64)"
    )
    sess = get_ssh()
    stdin, stdout, stderr = sess.client.exec_command(
        f'powershell -NoProfile -Command "{ps}"', timeout=10
    )
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    parts = out.split("|")
    result = {
        "vm": vm,
        "raw": out,
        "stderr": err or None,
    }
    if len(parts) >= 4:
        result.update({
            "hostname": parts[0],
            "user_process": parts[1],
            "uptime_sec": int(parts[2]),
            "ws_bytes": int(parts[3]),
        })
    # Also do a process count via tasklist
    try:
        stdin, stdout, _ = sess.client.exec_command("tasklist /FO CSV /NH", timeout=10)
        procs = []
        for line in stdout.read().decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            # CSV: "name","pid","session","session_num","mem"
            try:
                fields = [f.strip('"') for f in line.split('","')]
                procs.append({"name": fields[0], "pid": fields[1], "mem": fields[4] if len(fields) > 4 else None})
            except Exception:
                continue
        result["process_count"] = len(procs)
        result["sample_processes"] = procs[:5]
    except Exception as e:
        result["process_list_error"] = str(e)
    return result


@mcp.tool()
def ssh_exec(command: str, timeout_s: int = 30, use_powershell: bool = False) -> dict:
    """Run a command in the Windows VM over SSH.

    Args:
        command: the shell command to execute
        timeout_s: kill the command after N seconds
        use_powershell: wrap in `powershell -NoProfile -Command` (default False)
    """
    sess = get_ssh()
    cmd = f'powershell -NoProfile -Command "{command}"' if use_powershell else command
    stdin, stdout, stderr = sess.client.exec_command(cmd, timeout=timeout_s)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return {
        "command": command,
        "use_powershell": use_powershell,
        "stdout": out,
        "stderr": err,
        "returncode": rc,
    }


@mcp.tool()
def ssh_file_put(local_path: str, remote_path: str, prefer_z_mount: bool = True) -> dict:
    """Upload a file to the Windows VM.

    If `prefer_z_mount` and the file is under RE-BREAKER's plugin root
    (which is 9pfs-mounted at `Z:\\` in the guest), we tell the guest
    to copy the file from the shared mount rather than transferring
    bytes. This is the fast path for RE-BREAKER's own artefacts.
    Otherwise fall back to SFTP.
    """
    local = Path(local_path).expanduser().resolve()
    if not local.is_file():
        return {"error": f"local file not found: {local}"}
    if prefer_z_mount:
        plugin = _plugin_root().resolve()
        try:
            rel = local.relative_to(plugin)
            z = f"Z:\\{str(rel).replace('/', chr(92))}"
            # The file is already on Z:\; the guest just needs to
            # copy it to the target.
            target = remote_path.replace("/", chr(92))
            res = ssh_exec(
                f"Copy-Item -LiteralPath '{z}' -Destination '{target}' -Force",
                use_powershell=True,
            )
            return {
                "method": "z_mount_copy",
                "source_z": z,
                "target": target,
                "rc": res["returncode"],
                "stderr": res["stderr"],
            }
        except ValueError:
            pass  # not under plugin root; fall through
    sess = get_ssh()
    sftp = sess.client.open_sftp()
    try:
        sftp.put(str(local), remote_path)
    finally:
        sftp.close()
    return {"method": "sftp", "local": str(local), "remote": remote_path}


@mcp.tool()
def ssh_file_get(remote_path: str, local_path: str, prefer_z_mount: bool = True) -> dict:
    """Download a file from the Windows VM."""
    if prefer_z_mount:
        try:
            host = host_path_from_z(remote_path)
            if host.is_file():
                local = Path(local_path).expanduser().resolve()
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_bytes(host.read_bytes())
                return {
                    "method": "z_mount_read",
                    "remote_z": remote_path,
                    "host_path": str(host),
                    "local": str(local),
                    "size": local.stat().st_size,
                }
        except Exception:
            pass
    sess = get_ssh()
    sftp = sess.client.open_sftp()
    try:
        sftp.get(remote_path, str(local_path))
    finally:
        sftp.close()
    return {"method": "sftp", "remote": remote_path, "local": str(local_path)}


@mcp.tool()
def ssh_tunnel_open(
    name: str,
    local_port: int,
    remote_host: str = "127.0.0.1",
    remote_port: int = 22,
) -> dict:
    """Open a persistent SSH `-L` forward. Stays open until
    `ssh_tunnel_close(name)` is called or the process exits.
    `local_port=0` lets the OS pick a free port (returned)."""
    if local_port == 0:
        import socket as _socket
        with _socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            local_port = s.getsockname()[1]
    info = open_tunnel(name=name, local_port=local_port, remote_host=remote_host, remote_port=remote_port)
    return {
        "name": name,
        "local_port": info["local_port"],
        "remote_host": info["remote_host"],
        "remote_port": info["remote_port"],
        "endpoint": f"127.0.0.1:{info['local_port']}",
        "opened_at": info["opened_at"],
    }


@mcp.tool()
def ssh_tunnel_close(name: str) -> dict:
    return {"name": name, "closed": close_tunnel(name)}


@mcp.tool()
def tunnel_list() -> dict:
    return {"tunnels": list_tunnels()}


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------

def main() -> None:
    if mcp is None:
        raise SystemExit("mcp[cli] not installed; `uv add mcp[cli]`")
    try:
        mcp.run()
    finally:
        close_ssh()


if __name__ == "__main__":
    main()
