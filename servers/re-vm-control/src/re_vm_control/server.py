"""re-vm-control MCP server (v0.5.0).

Libvirt + QEMU control for the RE-BREAKER native-Windows-VM toolchain.

v0.5.0 ships **fully functional** libvirt + QMP control:
  - status: health check
  - list_vms, dominfo
  - start_vm, stop_vm, reboot_vm, pause_vm, resume_vm
  - snapshot_create, snapshot_revert, snapshot_delete, snapshot_list
  - qemu_monitor_command: raw QMP passthrough
  - attach_gdb_stub: idempotent — adds a <qemu:commandline>
    `-gdb tcp::1234` patch to the VM XML, restarts the VM, returns
    the gdb-stub endpoint.
  - nmi: inject a non-maskable interrupt (useful for triggering
    crash dumps in anti-debug research)
  - screenshot_via_spice: virsh screendump (PPM)

This is the **driver** for the rest of the VM toolchain: re-vm-debug
refuses to start until attach_gdb_stub has been called; re-vm-memory
uses the same QMP connection; the MCP bridges piggyback on
re-vm-ssh which uses the same VM coordinates.
"""
from __future__ import annotations

import json
import logging
import os
import re
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
    DEFAULT_LIBVIRT_URI,
    DEFAULT_VM_NAME,
    GDB_STUB_PORT,
    _plugin_root,
    gdb_stub_alive,
    qemu_monitor_command,
    virsh,
)
from re_vm_control import __version__


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-vm-control")
mcp = FastMCP("re-vm-control") if FastMCP else None


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _conn():
    """Cached libvirt connection (re-uses the shared one in vm_client)."""
    from re_breaker.vm_client import get_libvirt
    return get_libvirt()


def _resolve_vm(vm: str) -> str:
    return vm or DEFAULT_VM_NAME


def _domain(vm: str):
    conn = _conn()
    d = conn.lookupByName(_resolve_vm(vm))
    return d


def _gdb_stub_present_in_xml(vm: str) -> bool:
    """True if the VM XML already has our `<qemu:commandline>` gdb stub."""
    out = virsh("dumpxml", _resolve_vm(vm), timeout_s=15)
    return f"-gdb tcp::{GDB_STUB_PORT}" in out


def _patch_xml_for_gdb_stub(vm: str) -> str:
    """Add the gdb stub to the VM's XML, idempotently. Returns the path to
    the patched XML (libvirt writes a temp file in the qemu dir)."""
    import tempfile
    target = _resolve_vm(vm)
    # Pull the current XML
    raw = virsh("dumpxml", target, timeout_s=15)
    if f"-gdb tcp::{GDB_STUB_PORT}" in raw:
        return "(already-present)"
    # Inject the <qemu:commandline> block. We use ET for safe XML.
    import xml.etree.ElementTree as ET
    # The qemu namespace must be registered
    ET.register_namespace("qemu", "http://libvirt.org/schemas/domain/qemu/1.0")
    tree = ET.ElementTree(ET.fromstring(raw))
    root = tree.getroot()
    qemu_ns = "{http://libvirt.org/schemas/domain/qemu/1.0}"
    # Find or create the <qemu:commandline> child
    cmdline = root.find(f"{qemu_ns}commandline")
    if cmdline is None:
        cmdline = ET.SubElement(root, f"{qemu_ns}commandline")
    # Add the <qemu:arg value='-gdb'/> and <qemu:arg value='tcp::1234'/>
    # (qemu's actual gdb flag is -gdb tcp::PORT; we add it as two args).
    for value in (f"-gdb", f"tcp::{GDB_STUB_PORT}"):
        arg = ET.SubElement(cmdline, f"{qemu_ns}arg")
        arg.set("value", value)
    # Write to a temp file next to the libvirt state dir
    out = ET.tostring(root, encoding="unicode")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, dir="/var/tmp")
    tmp.write(out)
    tmp.close()
    return tmp.name


# ----------------------------------------------------------------------------
# Tools
# ----------------------------------------------------------------------------

@mcp.tool()
def status() -> dict:
    """Report server health: libvirt + QEMU + gdb stub availability."""
    try:
        conn = _conn()
        libvirt_ok = True
        libvirt_version = conn.getVersion()  # host libvirtd version
        uri = conn.getURI()
    except Exception as e:
        return {
            "status": "degraded",
            "server": "re-vm-control",
            "version": __version__,
            "implementation": "real",
            "libvirt_ok": False,
            "libvirt_error": str(e),
            "tools_implemented": 15,
            "tools_total": 15,
        }
    try:
        d = _domain(DEFAULT_VM_NAME)
        vm_state, vm_ok = d.state()[0], True
    except Exception as e:
        vm_state, vm_ok = None, False
        vm_err = str(e)
    return {
        "status": "ok",
        "server": "re-vm-control",
        "version": __version__,
        "implementation": "real",
        "libvirt_uri": uri,
        "libvirt_version": libvirt_version,
        "vm_name": DEFAULT_VM_NAME,
        "vm_state": vm_state,
        "vm_ok": vm_ok,
        "gdb_stub_port": GDB_STUB_PORT,
        "gdb_stub_alive": gdb_stub_alive(),
        "tools_implemented": 15,
        "tools_total": 15,
    }


@mcp.tool()
def list_vms(state_filter: str = "all") -> dict:
    """List all VMs visible to the libvirt system URI.

    Args:
        state_filter: one of "all", "running", "paused", "shutoff"
    """
    conn = _conn()
    out = []
    for d in conn.listAllDomains():
        st, _reason = d.state()
        if state_filter != "all" and _state_name(st) != state_filter:
            continue
        out.append({
            "name": d.name(),
            "uuid": d.UUIDString(),
            "state": _state_name(st),
            "id": d.ID() if d.isActive() else None,
        })
    return {"count": len(out), "vms": out}


@mcp.tool()
def dominfo(vm: str = DEFAULT_VM_NAME) -> dict:
    """Return the libvirt domain info dict (state, maxMem, cpus, etc.)."""
    d = _domain(vm)
    info = d.info()
    return {
        "name": d.name(),
        "uuid": d.UUIDString(),
        "state": _state_name(info[0]),
        "max_mem_kb": info[1],
        "used_mem_kb": info[2],
        "nr_virt_cpu": info[3],
        "cpu_time_ns": info[4],
    }


@mcp.tool()
def start_vm(vm: str = DEFAULT_VM_NAME) -> dict:
    """Start (boot) a defined VM. No-op if already running."""
    d = _domain(vm)
    if d.isActive():
        return {"vm": d.name(), "already": "running"}
    d.create()
    return {"vm": d.name(), "started": True}


@mcp.tool()
def stop_vm(vm: str = DEFAULT_VM_NAME, force: bool = False) -> dict:
    """Shutdown a VM (graceful) or destroy (force)."""
    d = _domain(vm)
    if not d.isActive():
        return {"vm": d.name(), "already": "stopped"}
    if force:
        d.destroy()
        return {"vm": d.name(), "stopped": "force"}
    d.shutdown()
    return {"vm": d.name(), "stopped": "graceful"}


@mcp.tool()
def reboot_vm(vm: str = DEFAULT_VM_NAME) -> dict:
    """Reboot a VM (uses libvirt's reboot, not a power cycle)."""
    d = _domain(vm)
    if not d.isActive():
        return {"vm": d.name(), "error": "not running"}
    d.reboot()
    return {"vm": d.name(), "rebooted": True}


@mcp.tool()
def pause_vm(vm: str = DEFAULT_VM_NAME) -> dict:
    d = _domain(vm)
    if not d.isActive():
        return {"vm": d.name(), "error": "not running"}
    d.suspend()
    return {"vm": d.name(), "paused": True}


@mcp.tool()
def resume_vm(vm: str = DEFAULT_VM_NAME) -> dict:
    d = _domain(vm)
    d.resume()
    return {"vm": d.name(), "resumed": True}


@mcp.tool()
def snapshot_create(name: str, vm: str = DEFAULT_VM_NAME, description: str = "") -> dict:
    """Snapshot the current VM state (memory + disk, like hibernate)."""
    d = _domain(vm)
    xml = (
        "<domainsnapshot>"
        f"<name>{name}</name>"
        f"<description>{description}</description>"
        "</domainsnapshot>"
    )
    snap = d.snapshotCreateXML(xml, 0)  # 0 = default flags (memory+disk)
    return {"vm": d.name(), "snapshot": name, "created": True}


@mcp.tool()
def snapshot_revert(name: str, vm: str = DEFAULT_VM_NAME, force: bool = False) -> dict:
    """Revert a VM to a named snapshot. `force=True` to revert even if
    the VM is currently running (suspends, restores, resumes)."""
    d = _domain(vm)
    snap = d.snapshotLookupByName(name, 0)
    flags = 0
    if force:
        flags |= 1  # VIR_DOMAIN_SNAPSHOT_REVERT_FORCE
    snap.revert(flags)
    return {"vm": d.name(), "snapshot": name, "reverted": True, "force": force}


@mcp.tool()
def snapshot_delete(name: str, vm: str = DEFAULT_VM_NAME) -> dict:
    d = _domain(vm)
    snap = d.snapshotLookupByName(name, 0)
    snap.delete(0)
    return {"vm": d.name(), "snapshot": name, "deleted": True}


@mcp.tool()
def snapshot_list(vm: str = DEFAULT_VM_NAME) -> dict:
    """List all snapshots for a VM."""
    d = _domain(vm)
    snaps = d.listAllSnapshots(0)
    out = []
    for s in snaps:
        ts = s.getCreateTime()
        out.append({
            "name": s.getName(),
            "creation_time": ts,
            "creation_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)) if ts else None,
            "state": _state_name(s.getState()[0]),
        })
    return {"vm": d.name(), "count": len(out), "snapshots": out}


@mcp.tool()
def qemu_monitor_command(command: dict, vm: str = DEFAULT_VM_NAME, timeout_s: int = 30) -> dict:
    """Raw QMP passthrough. `command` is a QMP command dict like
    `{"execute":"query-status"}`. Returns the parsed `return` field
    or raises on error. Use this for QMP commands not yet wrapped
    (pmemsave, screendump, device_add, etc.)."""
    return qemu_monitor_command(vm=_resolve_vm(vm), command=command, timeout_s=timeout_s)


@mcp.tool()
def attach_gdb_stub(vm: str = DEFAULT_VM_NAME, port: int = GDB_STUB_PORT) -> dict:
    """Idempotent: patch the VM XML to add `-gdb tcp::<port>`, then
    reboot the VM. After this returns, the QEMU gdb stub is reachable
    on `127.0.0.1:<port>` and `re-vm-debug` becomes usable.

    NOTE: this restarts the VM. Anything running inside the guest is
    terminated; snapshot the VM first if you need to roll back.
    """
    target = _resolve_vm(vm)
    if _gdb_stub_present_in_xml(target):
        already = True
        xml_action = "(already-present)"
    else:
        xml_path = _patch_xml_for_gdb_stub(target)
        # Define the new XML (overwrites the running config).
        out = virsh("define", xml_path, timeout_s=15)
        xml_action = xml_path
        already = False
    # Reboot so the new args take effect. (Cold boot would be cleaner
    # but requires the VM to be off; reboot preserves any in-flight
    # analysis the analyst has staged in /tmp etc.)
    if gdb_stub_alive():
        return {
            "vm": target,
            "port": port,
            "already_attached": True,
            "xml_action": xml_action,
            "note": "gdb stub already listening; not rebooting",
        }
    reboot_vm(target)
    # Wait up to 15s for the stub to come up
    deadline = time.time() + 15
    while time.time() < deadline:
        if gdb_stub_alive():
            return {
                "vm": target,
                "port": port,
                "already_attached": already,
                "xml_action": xml_action,
                "endpoint": f"127.0.0.1:{port}",
                "ready": True,
            }
        time.sleep(0.5)
    return {
        "vm": target,
        "port": port,
        "already_attached": already,
        "xml_action": xml_action,
        "ready": False,
        "note": "VM rebooted but gdb stub did not come up within 15s; check `virsh console win11`",
    }


@mcp.tool()
def nmi(vm: str = DEFAULT_VM_NAME) -> dict:
    """Inject a non-maskable interrupt into the guest. Useful for
    triggering BSODs in anti-debug research or crash-dump collection."""
    return qemu_monitor_command(
        vm=_resolve_vm(vm),
        command={"execute": "inject-nmi"},
    )


@mcp.tool()
def screenshot_via_spice(vm: str = DEFAULT_VM_NAME, output_path: str = "/tmp/win11-screen.ppm") -> dict:
    """Capture the current SPICE display as a PPM. Returns the path."""
    target = _resolve_vm(vm)
    out = virsh("screendump", target, output_path, timeout_s=30)
    p = Path(output_path)
    return {
        "vm": target,
        "path": str(p),
        "exists": p.is_file(),
        "size": p.stat().st_size if p.is_file() else 0,
        "raw": out,
    }


# ----------------------------------------------------------------------------
# State-name helper
# ----------------------------------------------------------------------------

_STATE_NAMES = {
    0: "no-state",
    1: "running",
    2: "blocked",
    3: "paused",
    4: "shutdown",
    5: "shutoff",
    6: "crashed",
    7: "pmsuspended",
}


def _state_name(code: int) -> str:
    return _STATE_NAMES.get(code, f"unknown({code})")


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------

def main() -> None:
    if mcp is None:
        raise SystemExit("mcp[cli] not installed; `uv add mcp[cli]`")
    mcp.run()


if __name__ == "__main__":
    main()
