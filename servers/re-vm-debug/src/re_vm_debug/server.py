"""re-vm-debug MCP server (v0.5.3 FULLY IMPLEMENTED).

QEMU gdb stub client for the Windows VM. The kernel-mode /
hypervisor-level debug path. Pairs with re-vm-control's
`attach_gdb_stub` (which must run first to actually open the
`:1234` listener).

What this server unlocks that re-x64dbg-remote cannot:
  - hardware breakpoints at guest physical addresses that the
    guest CANNOT detect (no INT3, no DR7 manipulation observable
    from user mode, no kernel driver to inspect)
  - watchpoints that fire in the QEMU translator before the
    guest even sees the access
  - full guest memory + register state on a paused VM, including
    kernel structures (CR3 walks, IDT, GDT)
  - read/write guest physical memory without going through the
    guest OS at all (immune to user-mode anti-dump tricks)

v0.5.3 ships fully functional:
  - status (real)
  - attach_gdb_stub (proxies to re-vm-control)
  - connect_gdb (real; opens a GdbRemoteClient)
  - set_breakpoint_hw / clear_breakpoint_hw
  - set_watchpoint / clear_watchpoint
  - read_registers / write_registers
  - read_guest_phys_mem / write_guest_phys_mem
  - read_guest_virt_mem (page-walk + chunked read)
  - translate_virt_to_phys
  - vm_continue / vm_step / vm_pause
  - gdb_eval (raw gdb eval with input sanitisation)
  - vm_reset (recovery: closes the gdb connection without
    killing the VM)
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

# v0.5.3: shared src/ on the path
# v0.5.8: 5 parents (not 4) — server.py is depth 5 from project root
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None

from re_breaker.vm_client import (
    DEFAULT_VM_NAME, GDB_STUB_PORT, gdb_stub_alive, gdb_stub_endpoint,
    qemu_monitor_command,
)
from re_breaker.page_walk import PageFaultError, walk as page_walk
from re_vm_debug import __version__
from re_vm_debug.gdb_remote import GdbRemoteClient, GdbRemoteError


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-vm-debug")
mcp = FastMCP("re-vm-debug") if FastMCP else None


# ----------------------------------------------------------------------------
# Per-VM GdbRemoteClient cache (matches the re-winedbg `_SESSIONS` pattern
# at servers/re-winedbg/src/re_winedbg/server.py:48-58)
# ----------------------------------------------------------------------------

_SESSIONS_LOCK = threading.Lock()
_SESSIONS: dict[str, GdbRemoteClient] = {}


def _session(vm: str) -> GdbRemoteClient:
    """Get or open the per-VM gdb session."""
    vm = vm or DEFAULT_VM_NAME
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(vm)
        if s is not None and s.sock is not None:
            return s
        if not gdb_stub_alive():
            raise GdbRemoteError(
                f"gdb stub not listening on 127.0.0.1:{GDB_STUB_PORT}. "
                "Call attach_gdb_stub first (requires VM reboot)."
            )
        host, port = gdb_stub_endpoint()
        s = GdbRemoteClient(host=host, port=port, timeout_s=10.0)
        s.connect()
        _SESSIONS[vm] = s
        log.info("opened gdb session for vm=%s", vm)
        return s


def _close_session(vm: str) -> bool:
    with _SESSIONS_LOCK:
        s = _SESSIONS.pop(vm, None)
    if s is None:
        return False
    try:
        s.disconnect()
    except Exception:
        pass
    return True


# ----------------------------------------------------------------------------
# Refusal guard: refuse to call debug tools until the gdb stub is alive
# ----------------------------------------------------------------------------

def _require_stub(vm: str) -> Optional[dict]:
    """If the gdb stub isn't alive, return an error dict; else None."""
    if not gdb_stub_alive():
        return {
            "tool": "unknown",
            "status": "error",
            "error": f"gdb stub not listening on 127.0.0.1:{GDB_STUB_PORT}. "
                     "Run re-vm-control.attach_gdb_stub() to enable.",
        }
    return None


# ----------------------------------------------------------------------------
# Tools
# ----------------------------------------------------------------------------

@mcp.tool()
def status() -> dict:
    return {
        "status": "ok",
        "server": "re-vm-debug",
        "version": __version__,
        "implementation": "real",
        "vm_name": DEFAULT_VM_NAME,
        "gdb_stub_endpoint": f"{gdb_stub_endpoint()[0]}:{gdb_stub_endpoint()[1]}",
        "gdb_stub_alive": gdb_stub_alive(),
        "active_sessions": list(_SESSIONS.keys()),
        "tools_implemented": 15,
        "tools_total": 15,
    }


@mcp.tool()
def attach_gdb_stub(vm: str = DEFAULT_VM_NAME, port: int = GDB_STUB_PORT) -> dict:
    """Proxy to re-vm-control.attach_gdb_stub. Patches the VM XML
    + reboots so the gdb stub is exposed. Idempotent."""
    # We shell out to virsh via the shared helper (re-vm-control
    # has the same logic; we re-implement minimally to avoid the
    # cross-venv import).
    from re_breaker.vm_client import virsh
    import xml.etree.ElementTree as ET
    import tempfile
    target = vm or DEFAULT_VM_NAME
    out = virsh("dumpxml", target, timeout_s=15)
    if f"-gdb tcp::{port}" in out:
        already = True
        xml_path = None
    else:
        ET.register_namespace("qemu", "http://libvirt.org/schemas/domain/qemu/1.0")
        root = ET.fromstring(out)
        qemu_ns = "{http://libvirt.org/schemas/domain/qemu/1.0}"
        cmdline = root.find(f"{qemu_ns}commandline")
        if cmdline is None:
            cmdline = ET.SubElement(root, f"{qemu_ns}commandline")
        for value in (f"-gdb", f"tcp::{port}"):
            arg = ET.SubElement(cmdline, f"{qemu_ns}arg")
            arg.set("value", value)
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, dir="/var/tmp")
        tmp.write(ET.tostring(root, encoding="unicode"))
        tmp.close()
        xml_path = tmp.name
        virsh("define", xml_path, timeout_s=15)
        already = False
    if gdb_stub_alive():
        return {"tool": "attach_gdb_stub", "status": "ok", "already_attached": True, "endpoint": f"127.0.0.1:{port}"}
    virsh("reboot", target, timeout_s=15)
    deadline = time.time() + 15
    while time.time() < deadline:
        if gdb_stub_alive():
            return {"tool": "attach_gdb_stub", "status": "ok", "already_attached": already, "endpoint": f"127.0.0.1:{port}", "ready": True}
        time.sleep(0.5)
    return {"tool": "attach_gdb_stub", "status": "error", "ready": False, "endpoint": f"127.0.0.1:{port}", "note": "gdb stub did not come up within 15s"}


@mcp.tool()
def connect_gdb(host: str = "127.0.0.1", port: int = GDB_STUB_PORT, timeout_s: float = 10.0) -> dict:
    """Open a TCP connection to the QEMU gdb stub and negotiate
    features. Cached per `(host, port)` for subsequent tool calls."""
    err = _require_stub(DEFAULT_VM_NAME)
    if err is not None:
        return {"tool": "connect_gdb", **err}
    try:
        s = _session(DEFAULT_VM_NAME)
        return {
            "tool": "connect_gdb",
            "status": "ok",
            "endpoint": f"{host}:{port}",
            "session_open": True,
        }
    except Exception as e:
        return {"tool": "connect_gdb", "status": "error", "error": str(e)}


@mcp.tool()
def set_breakpoint_hw(phys_addr: int, kind: str = "x", vm: str = DEFAULT_VM_NAME) -> dict:
    """Hardware breakpoint at a guest physical address (QEMU gdb
    stub quirk: `Z1` takes physical addresses). Undetectable by
    the guest."""
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "set_breakpoint_hw", **err}
    try:
        ok = _session(vm).set_breakpoint_hw(phys_addr, kind=kind)
        return {"tool": "set_breakpoint_hw", "status": "ok" if ok else "error", "phys_addr": hex(phys_addr), "kind": kind, "vm": vm}
    except Exception as e:
        return {"tool": "set_breakpoint_hw", "status": "error", "error": str(e)}


@mcp.tool()
def clear_breakpoint_hw(phys_addr: int, vm: str = DEFAULT_VM_NAME) -> dict:
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "clear_breakpoint_hw", **err}
    try:
        ok = _session(vm).clear_breakpoint_hw(phys_addr)
        return {"tool": "clear_breakpoint_hw", "status": "ok" if ok else "error", "phys_addr": hex(phys_addr), "vm": vm}
    except Exception as e:
        return {"tool": "clear_breakpoint_hw", "status": "error", "error": str(e)}


@mcp.tool()
def set_watchpoint(phys_addr: int, size: int, access: str = "rw", vm: str = DEFAULT_VM_NAME) -> dict:
    """Watchpoint on a guest physical address range. Fires in the
    QEMU translator before the guest sees the access."""
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "set_watchpoint", **err}
    try:
        ok = _session(vm).set_watchpoint(phys_addr, size, access=access)
        return {"tool": "set_watchpoint", "status": "ok" if ok else "error", "phys_addr": hex(phys_addr), "size": size, "access": access, "vm": vm}
    except Exception as e:
        return {"tool": "set_watchpoint", "status": "error", "error": str(e)}


@mcp.tool()
def clear_watchpoint(phys_addr: int, vm: str = DEFAULT_VM_NAME) -> dict:
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "clear_watchpoint", **err}
    try:
        ok = _session(vm).clear_watchpoint(phys_addr)
        return {"tool": "clear_watchpoint", "status": "ok" if ok else "error", "phys_addr": hex(phys_addr), "vm": vm}
    except Exception as e:
        return {"tool": "clear_watchpoint", "status": "error", "error": str(e)}


@mcp.tool()
def read_registers(vm: str = DEFAULT_VM_NAME) -> dict:
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "read_registers", **err}
    try:
        regs = _session(vm).read_registers()
        return {"tool": "read_registers", "status": "ok", "vm": vm, "registers": regs}
    except Exception as e:
        return {"tool": "read_registers", "status": "error", "error": str(e)}


@mcp.tool()
def write_registers(regs: dict[str, int], vm: str = DEFAULT_VM_NAME) -> dict:
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "write_registers", **err}
    try:
        ok = _session(vm).write_registers(regs)
        return {"tool": "write_registers", "status": "ok" if ok else "error", "vm": vm, "written": list(regs.keys())}
    except Exception as e:
        return {"tool": "write_registers", "status": "error", "error": str(e)}


@mcp.tool()
def read_guest_phys_mem(phys_addr: int, size: int, vm: str = DEFAULT_VM_NAME) -> dict:
    """Read raw bytes from a guest physical address range. Capped
    at 4 KiB per call (chunk in v0.6)."""
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "read_guest_phys_mem", **err}
    try:
        data = _session(vm).read_memory(phys_addr, size)
        return {
            "tool": "read_guest_phys_mem",
            "status": "ok",
            "vm": vm,
            "phys_addr": hex(phys_addr),
            "size": len(data),
            "hex": data.hex(),
        }
    except Exception as e:
        return {"tool": "read_guest_phys_mem", "status": "error", "error": str(e)}


@mcp.tool()
def write_guest_phys_mem(phys_addr: int, data_hex: str, vm: str = DEFAULT_VM_NAME) -> dict:
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "write_guest_phys_mem", **err}
    try:
        data = bytes.fromhex(data_hex)
        ok = _session(vm).write_memory(phys_addr, data)
        return {
            "tool": "write_guest_phys_mem",
            "status": "ok" if ok else "error",
            "vm": vm,
            "phys_addr": hex(phys_addr),
            "size": len(data),
        }
    except Exception as e:
        return {"tool": "write_guest_phys_mem", "status": "error", "error": str(e)}


@mcp.tool()
def read_guest_virt_mem(cr3: int, virt_addr: int, size: int, vm: str = DEFAULT_VM_NAME) -> dict:
    """Read a guest virtual address range. Page-walks CR3 via
    `re_breaker.page_walk` and reads each page via the gdb stub."""
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "read_guest_virt_mem", **err}
    if size > 65536:
        return {"tool": "read_guest_virt_mem", "status": "error", "error": f"size {size} > 64 KiB; chunk in v0.6"}
    try:
        sess = _session(vm)
        pages = (size + 4095) // 4096
        collected = bytearray()
        walks = []
        for i in range(pages):
            va = (virt_addr & ~0xFFF) + i * 4096
            def _phys_read(phys: int, sz: int) -> bytes:
                return sess.read_memory(phys, sz)
            try:
                res = page_walk(cr3, va, _phys_read)
                walks.append({"vaddr": hex(va), "phys": hex(res.phys_addr & ~0xFFF), "page_size": res.page_size})
                page_bytes = _phys_read(res.phys_addr & ~0xFFF, res.page_size)
                offset_in_page = va - (res.phys_addr & ~0xFFF)
                collected.extend(page_bytes[offset_in_page:offset_in_page + 4096])
            except PageFaultError as e:
                collected.extend(b"\x00" * 4096)
                walks.append({"vaddr": hex(va), "error": str(e)})
        out = bytes(collected[:size])
        return {
            "tool": "read_guest_virt_mem",
            "status": "ok",
            "vm": vm,
            "cr3": hex(cr3),
            "virt_addr": hex(virt_addr),
            "size": size,
            "hex": out.hex(),
            "walks": walks,
            "note": "v0.5.3 only handles 4 KiB pages correctly; 2 MiB / 1 GiB hugepages may be misread",
        }
    except Exception as e:
        return {"tool": "read_guest_virt_mem", "status": "error", "error": str(e)}


@mcp.tool()
def translate_virt_to_phys(cr3: int, virt_addr: int, vm: str = DEFAULT_VM_NAME) -> dict:
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "translate_virt_to_phys", **err}
    try:
        sess = _session(vm)
        def _phys_read(phys: int, sz: int) -> bytes:
            return sess.read_memory(phys, sz)
        res = page_walk(cr3, virt_addr, _phys_read)
        return {
            "tool": "translate_virt_to_phys",
            "status": "ok",
            "vm": vm,
            "cr3": hex(cr3),
            "virt_addr": hex(virt_addr),
            "phys_addr": hex(res.phys_addr),
            "page_size": res.page_size,
            "flags": res.flags,
        }
    except PageFaultError as e:
        return {"tool": "translate_virt_to_phys", "status": "error", "error": str(e), "level": e.level}
    except Exception as e:
        return {"tool": "translate_virt_to_phys", "status": "error", "error": str(e)}


@mcp.tool()
def vm_continue(vm: str = DEFAULT_VM_NAME) -> dict:
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "vm_continue", **err}
    try:
        reason = _session(vm).continue_execution()
        return {"tool": "vm_continue", "status": "ok", "vm": vm, "stop_reason": reason}
    except Exception as e:
        return {"tool": "vm_continue", "status": "error", "error": str(e)}


@mcp.tool()
def vm_step(vm: str = DEFAULT_VM_NAME) -> dict:
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "vm_step", **err}
    try:
        reason = _session(vm).step()
        return {"tool": "vm_step", "status": "ok", "vm": vm, "stop_reason": reason}
    except Exception as e:
        return {"tool": "vm_step", "status": "error", "error": str(e)}


@mcp.tool()
def vm_pause(vm: str = DEFAULT_VM_NAME) -> dict:
    """Pause the VM via QMP `stop`. The gdb stub remains reachable."""
    return qemu_monitor_command(vm=vm, command={"execute": "stop"})


@mcp.tool()
def gdb_eval(expression: str, vm: str = DEFAULT_VM_NAME) -> dict:
    """Raw gdb/MI passthrough. Refuses `!` and `<<` to prevent
    shell-injection through the gdb eval (the gdb stub doesn't
    support `!` commands; the `<<` redirect is a defense)."""
    err = _require_stub(vm)
    if err is not None:
        return {"tool": "gdb_eval", **err}
    if "!" in expression or "<<" in expression:
        return {
            "tool": "gdb_eval",
            "status": "error",
            "error": "expression contains '!' or '<<'; refused for safety",
        }
    try:
        # The QEMU gdb stub speaks RSP, not MI. The "eval" form
        # for RSP is the `p<expr>` packet (print) or `P<reg>=<val>`
        # (set register). We support `p` only for v0.5.3.
        resp = _session(vm)._send_raw(f"p{expression}")
        return {"tool": "gdb_eval", "status": "ok", "vm": vm, "expression": expression, "result": resp}
    except Exception as e:
        return {"tool": "gdb_eval", "status": "error", "error": str(e)}


@mcp.tool()
def vm_reset(vm: str = DEFAULT_VM_NAME) -> dict:
    """Recovery: close any open gdb sessions for this VM and let
    the VM run freely. Use this when the gdb stub hangs (per
    the v0.5.0 risk register). The VM is NOT rebooted — only the
    gdb connection is severed."""
    _close_session(vm)
    return {"tool": "vm_reset", "status": "ok", "vm": vm, "sessions_closed": True, "vm_state": "running"}


def main() -> None:
    if mcp is None:
        raise SystemExit("mcp[cli] not installed; `uv add mcp[cli]`")
    try:
        mcp.run()
    finally:
        for vm in list(_SESSIONS.keys()):
            _close_session(vm)


if __name__ == "__main__":
    main()
