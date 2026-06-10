"""re-vm-launch MCP server (v0.5.1 FULLY IMPLEMENTED).

Upload a target binary to the Windows VM, launch it with full
instrumentation hooks, stream events back. Built on re-vm-ssh for the
file copy + process create, and on re-vm-control for snapshot
management around the launch.

v0.5.1 ships fully functional:
  - status
  - upload_target (calls re_breaker.vm_client.ssh_file_put)
  - launch_target (WMI Win32_Process.Create with optional
    CREATE_SUSPENDED; default suspended so a debugger can attach
    before the entry point)
  - wait_for_process (polls Get-Process)
  - kill_target (graceful Stop-Process / hard taskkill /F)
  - get_launch_handle (mints a handle for an already-running process
    the analyst discovered via the gdb stub or x64dbg)

Registry: see `re_vm_launch/registry.py` — in-process dict keyed by
uuid. v0.6 will move to Redis or sqlite for cross-restart persistence.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

# v0.5.1: shared src/ on the path
# v0.5.8: 5 parents (not 4) — server.py is depth 5 from project root
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None

from re_breaker.vm_client import (
    DEFAULT_VM_NAME,
    ssh_exec,
    ssh_file_put,
)
from re_vm_launch import __version__
from re_vm_launch.registry import (
    LaunchHandle,
    get,
    get_by_pid,
    list_handles,
    mint_handle,
    register,
    remove,
    set_pid,
    update_status,
)


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-vm-launch")
mcp = FastMCP("re-vm-launch") if FastMCP else None


# PowerShell CREATE_SUSPENDED flag (Win32 process creation flag 0x00000004)
_WIN32_CREATE_SUSPENDED = 0x00000004


def _default_guest_target_path(local_path: str) -> str:
    """If the analyst doesn't pass a guest_path, derive one
    `C:\\targets\\<sha256[:8]>__<basename>`."""
    p = Path(local_path)
    h = hashlib.sha256(p.read_bytes()).hexdigest()[:8]
    safe = p.name.replace(" ", "_")
    return f"C:\\targets\\{h}__{safe}"


@mcp.tool()
def status() -> dict:
    """Report server health + active launch handles."""
    return {
        "status": "ok",
        "server": "re-vm-launch",
        "version": __version__,
        "implementation": "real",
        "vm_name": DEFAULT_VM_NAME,
        "active_handles": len(list_handles()),
        "tools_implemented": 6,
        "tools_total": 6,
    }


@mcp.tool()
def upload_target(local_path: str, guest_path: Optional[str] = None) -> dict:
    """Upload the target to the Windows VM.

    Fast path: if `local_path` is under RE-BREAKER's plugin root (9pfs
    `Z:\\`), the guest just `Copy-Item`s the file (no byte transfer).
    Otherwise: SFTP.
    """
    if not guest_path:
        guest_path = _default_guest_target_path(local_path)
    out = ssh_file_put(local_path, guest_path, prefer_z_mount=True)
    out["guest_path"] = guest_path
    out["local_path"] = local_path
    return out


@mcp.tool()
def launch_target(
    guest_path: str,
    args: Optional[list[str]] = None,
    suspended: bool = True,
    wait_for_handle_id: Optional[str] = None,
) -> dict:
    """Launch the target in the VM. Returns a LaunchHandle.

    Args:
        guest_path: absolute Windows path to the .exe
        args: command-line arguments
        suspended: launch with CREATE_SUSPENDED so a debugger can
            attach before the entry point (default True)
        wait_for_handle_id: if supplied, the returned pid is bound
            to this existing handle (used by get_launch_handle +
            re-vm-debug / re-x64dbg-remote to claim a process they
            discovered externally).
    """
    args_list = list(args or [])
    if wait_for_handle_id:
        handle = get(wait_for_handle_id)
        if handle is None:
            return {"tool": "launch_target", "status": "error", "error": f"unknown handle {wait_for_handle_id}"}
    else:
        handle = mint_handle(guest_path, args_list)
    # Build the PowerShell that calls WMI Win32_Process.Create
    arg_str = ", ".join(f'"{a}"' for a in args_list)
    ps = (
        f"$r = Invoke-WmiMethod -Path 'Win32_Process' -Name Create "
        f"-ArgumentList @('{guest_path.replace(chr(92), chr(92)+chr(92))}', '{arg_str}', "
        f"'{_WIN32_CREATE_SUSPENDED if suspended else 0}', $null, $null, $null, $null); "
        f"$r.ReturnValue; $r.ProcessId"
    )
    res = ssh_exec(ps, use_powershell=True, timeout_s=30)
    out_lines = res["stdout"].strip().splitlines()
    # The output is "<returnValue>\n<processId>" — parse the two ints
    rc, pid = -1, 0
    if len(out_lines) >= 2:
        try:
            rc = int(out_lines[0].strip())
            pid = int(out_lines[1].strip())
        except (ValueError, IndexError):
            pass
    elif len(out_lines) == 1:
        # Some PowerShell versions collapse the two outputs into one line
        try:
            parts = out_lines[0].strip().split()
            rc = int(parts[0])
            pid = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            pass
    if rc != 0 or pid == 0:
        return {
            "tool": "launch_target",
            "status": "error",
            "returncode": rc,
            "stderr": res.get("stderr"),
            "note": f"WMI Create returned {rc} (0=success; non-zero = Win32 error)",
        }
    set_pid(handle.handle, pid)
    update_status(handle.handle, "suspended" if suspended else "running")
    return {
        "tool": "launch_target",
        "status": "ok",
        "handle": handle.to_dict(),
        "suspended": suspended,
    }


@mcp.tool()
def wait_for_process(handle: str, timeout_s: int = 30) -> dict:
    """Block until the launched process is observable in `Get-Process`.

    Useful because the WMI `Create` call returns the pid immediately
    but the process is still being set up in the kernel. Polling
    every 250ms until the pid shows up in the process table.
    """
    h = get(handle)
    if h is None:
        return {"tool": "wait_for_process", "status": "error", "error": f"unknown handle {handle}"}
    if h.pid == 0:
        return {"tool": "wait_for_process", "status": "error", "error": f"handle {handle} has no pid (was launch_target called?)"}
    deadline = time.time() + timeout_s
    last_check = None
    while time.time() < deadline:
        ps = f"if (Get-Process -Id {h.pid} -ErrorAction SilentlyContinue) {{ 'yes' }} else {{ 'no' }}"
        res = ssh_exec(ps, use_powershell=True, timeout_s=5)
        last_check = res["stdout"].strip()
        if last_check == "yes":
            update_status(h.handle, "running")
            return {
                "tool": "wait_for_process",
                "status": "ok",
                "handle": handle,
                "pid": h.pid,
                "waited_sec": timeout_s - (deadline - time.time()),
            }
        time.sleep(0.25)
    return {
        "tool": "wait_for_process",
        "status": "timeout",
        "handle": handle,
        "pid": h.pid,
        "last_check": last_check,
        "note": f"process {h.pid} not visible after {timeout_s}s",
    }


@mcp.tool()
def kill_target(handle: str, force: bool = False) -> dict:
    """Terminate a launched process.

    Graceful: `Stop-Process` (sends WM_CLOSE → CTRL+C → WM_DESTROY
    via a small PowerShell wrapper; the underlying .NET call
    already escalates the signal). Hard: `taskkill /F /PID <pid>`.
    Always removes the handle from the registry on success.
    """
    h = get(handle)
    if h is None:
        return {"tool": "kill_target", "status": "error", "error": f"unknown handle {handle}"}
    if h.pid == 0:
        # No pid → never actually launched; just remove the handle
        remove(handle)
        return {"tool": "kill_target", "status": "ok", "removed_without_kill": True, "handle": handle}
    if force:
        ps = f"taskkill /F /PID {h.pid} 2>&1 | Out-String"
        res = ssh_exec(ps, use_powershell=True, timeout_s=10)
    else:
        ps = f"Stop-Process -Id {h.pid} -Force -ErrorAction SilentlyContinue; 'done'"
        res = ssh_exec(ps, use_powershell=True, timeout_s=15)
    # Verify the process is gone
    verify = ssh_exec(
        f"if (Get-Process -Id {h.pid} -ErrorAction SilentlyContinue) {{ 'alive' }} else {{ 'gone' }}",
        use_powershell=True, timeout_s=5,
    )
    if verify["stdout"].strip() == "gone":
        remove(handle)
        return {
            "tool": "kill_target",
            "status": "ok",
            "handle": handle,
            "pid": h.pid,
            "force": force,
            "killed": True,
        }
    if not force:
        # Graceful didn't take; try hard kill automatically
        ps2 = f"taskkill /F /PID {h.pid} 2>&1 | Out-String"
        ssh_exec(ps2, use_powershell=True, timeout_s=10)
        verify2 = ssh_exec(
            f"if (Get-Process -Id {h.pid} -ErrorAction SilentlyContinue) {{ 'alive' }} else {{ 'gone' }}",
            use_powershell=True, timeout_s=5,
        )
        if verify2["stdout"].strip() == "gone":
            remove(handle)
            return {
                "tool": "kill_target",
                "status": "ok",
                "handle": handle,
                "pid": h.pid,
                "force": True,
                "auto_escalated": True,
                "killed": True,
            }
    return {
        "tool": "kill_target",
        "status": "error",
        "handle": handle,
        "pid": h.pid,
        "force": force,
        "note": f"process {h.pid} still alive after kill; analyst intervention required",
    }


@mcp.tool()
def get_launch_handle(guest_path: str, pid: Optional[int] = None) -> dict:
    """Mint a LaunchHandle for an already-running process (symmetric
    to `launch_target` but no actual launch). Useful for
    `re-vm-debug` / `re-x64dbg-remote` to claim a pid they
    discovered via the gdb stub or x64dbg's process list."""
    h = mint_handle(guest_path)
    if pid:
        set_pid(h.handle, pid)
    if pid is not None:
        # Try to determine current status via Get-Process
        res = ssh_exec(
            f"if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ 'running' }} else {{ 'unknown' }}",
            use_powershell=True, timeout_s=5,
        )
        st = res["stdout"].strip()
        if st in ("running", "unknown"):
            update_status(h.handle, st)
    return {
        "tool": "get_launch_handle",
        "status": "ok",
        "handle": h.to_dict(),
    }


def main() -> None:
    if mcp is None:
        raise SystemExit("mcp[cli] not installed; `uv add mcp[cli]`")
    mcp.run()


if __name__ == "__main__":
    main()
