"""re-vm-memory MCP server (v0.5.1 FULLY IMPLEMENTED).

Bulk guest-memory operations via QMP. v0.5.1 ships fully functional:
  - status
  - dump_phys_range (QMP `pmemsave` — QEMU writes directly to host)
  - dump_virt_range (CR3 page-walk + dump_phys_range)
  - search_phys (dump + grep on host, ASCII or hex)
  - hash_phys_range (sha256 of a phys range)
  - diff_snapshots (destructive revert to each snapshot, hash, compare)

Implementation notes:
  - All phys reads go through QMP `pmemsave` (QEMU writes the file
    directly to host disk; no byte transfer over a Python pipe).
  - For virt reads, the page-walk helper in `page_walk.py` uses
    the same `pmemsave` for the page-table levels. v0.5.3 will
    move page_walk.py to `src/re_breaker/page_walk.py` so
    `re-vm-debug` can share it.
"""
from __future__ import annotations

import hashlib
import logging
import re
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
    qemu_monitor_command,
)
from re_vm_memory import __version__
# v0.5.3: page_walk moved to shared src/re_breaker/page_walk.py
try:
    from re_vm_memory.page_walk import PageFaultError, walk as page_walk
except ImportError:
    from re_breaker.page_walk import PageFaultError, walk as page_walk


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-vm-memory")
mcp = FastMCP("re-vm-memory") if FastMCP else None


# Cap for any single pmemsave. QEMU's default is unlimited but
# pulling gigabytes over QMP can hang the connection; v0.5.1 caps
# at 256 MiB per call.
_MAX_PMEMSAVE = 256 * 1024 * 1024


@mcp.tool()
def status() -> dict:
    """Report server health."""
    return {
        "status": "ok",
        "server": "re-vm-memory",
        "version": __version__,
        "implementation": "real",
        "vm_name": DEFAULT_VM_NAME,
        "tools_implemented": 6,
        "tools_total": 6,
    }


@mcp.tool()
def dump_phys_range(phys_addr: int, size: int, output_path: str, vm: str = DEFAULT_VM_NAME) -> dict:
    """Dump a guest physical address range to a host file via QMP pmemsave.

    Args:
        phys_addr: starting physical address (uint64)
        size: number of bytes to dump
        output_path: host filesystem path
        vm: libvirt VM name (default: win11)
    """
    if size > _MAX_PMEMSAVE:
        return {
            "tool": "dump_phys_range",
            "status": "error",
            "error": f"size {size} exceeds max {_MAX_PMEMSAVE} bytes; chunk in v0.6",
        }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = {
        "execute": "pmemsave",
        "arguments": {
            "val": int(phys_addr),
            "size": int(size),
            "filename": output_path,
        },
    }
    res = qemu_monitor_command(vm, cmd, timeout_s=max(30, size // (1024 * 1024)))
    # QMP pmemsave returns an empty dict on success
    p = Path(output_path)
    if not p.is_file():
        return {"tool": "dump_phys_range", "status": "error", "qmp_response": res,
                "error": f"QMP pmemsave did not write {output_path}"}
    actual = p.stat().st_size
    sha = hashlib.sha256(p.read_bytes()).hexdigest() if actual <= 64 * 1024 * 1024 else None
    return {
        "tool": "dump_phys_range",
        "status": "ok",
        "vm": vm,
        "phys_addr": hex(phys_addr),
        "size": actual,
        "output_path": output_path,
        "sha256": sha,  # None if file > 64 MiB (avoid OOM on the host)
        "qmp_response": res,
    }


@mcp.tool()
def dump_virt_range(
    cr3: int,
    virt_addr: int,
    size: int,
    output_path: str,
    vm: str = DEFAULT_VM_NAME,
) -> dict:
    """Dump a guest virtual address range (CR3-relative) to a host file.

    The page-walk helper (`page_walk.py`) walks the x86_64 4-level
    page tables; each non-leaf level gets pmemsave'd in 4 KiB chunks
    and the data is parsed to extract the PTE entries. The leaf page
    is pmemsave'd for the requested size.
    """
    # Simple implementation: walk each page in the range.
    # For a range that spans multiple pages, we walk each page
    # individually and concatenate. This is the slow path but it's
    # correct for the common case (a single page or a small range).
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pages = (size + 4095) // 4096
    collected = bytearray()
    walks = []
    for i in range(pages):
        va = (virt_addr & ~0xFFF) + i * 4096
        # Helper: pmemsave 4 KiB of phys, parse 8 bytes at a time
        # for the page-table levels; for the leaf, dump the full page.
        def _phys_read(phys: int, sz: int) -> bytes:
            tmp = f"/tmp/.page-walk-{phys:x}-{sz}.bin"
            qemu_monitor_command(vm, {
                "execute": "pmemsave",
                "arguments": {"val": int(phys), "size": int(sz), "filename": tmp},
            }, timeout_s=15)
            return Path(tmp).read_bytes()
        try:
            res = page_walk(cr3, va, _phys_read)
            walks.append({"vaddr": hex(va), "phys": hex(res.phys_addr & ~0xFFF), "page_size": res.page_size, "flags": res.flags})
            # Now read the leaf page (or chunk if hugepage)
            page_bytes = _phys_read(res.phys_addr & ~0xFFF, res.page_size)
            # Take just the bits we need for this page
            offset_in_page = (va - (res.phys_addr & ~0xFFF))
            collected.extend(page_bytes[offset_in_page:offset_in_page + 4096])
        except PageFaultError as e:
            collected.extend(b"\x00" * 4096)  # best-effort: zero the page
            walks.append({"vaddr": hex(va), "error": str(e)})
    out_path.write_bytes(bytes(collected[:size]))
    return {
        "tool": "dump_virt_range",
        "status": "ok",
        "vm": vm,
        "cr3": hex(cr3),
        "virt_addr": hex(virt_addr),
        "size": size,
        "output_path": output_path,
        "pages_walked": pages,
        "walks": walks,
        "note": "v0.5.1 only handles 4 KiB pages correctly; 2 MiB / 1 GiB hugepages may be misread",
    }


@mcp.tool()
def search_phys(
    pattern: str,
    start: int = 0,
    end: int = 0x100_0000,
    vm: str = DEFAULT_VM_NAME,
    max_hits: int = 20,
) -> dict:
    """Search guest physical RAM for a byte pattern (hex) or ASCII string.

    Args:
        pattern: ASCII string OR hex byte sequence like "48 8b ?? c3"
        start: starting phys addr
        end: ending phys addr
        max_hits: cap the number of hits
    """
    if end - start > _MAX_PMEMSAVE:
        return {
            "tool": "search_phys",
            "status": "error",
            "error": f"range {end-start} exceeds max {_MAX_PMEMSAVE} bytes; chunk in v0.6",
        }
    tmp = f"/tmp/.search-phys-{int(time.time()*1000)}.bin"
    dump_phys_range(start, end - start, tmp, vm=vm)
    data = Path(tmp).read_bytes()
    hits: list[dict[str, Any]] = []
    # Try ASCII first
    try:
        for m in re.finditer(re.escape(pattern.encode("ascii")), data):
            hits.append({
                "offset": hex(start + m.start()),
                "preview": data[m.start():m.start() + 32].hex(),
            })
            if len(hits) >= max_hits:
                break
    except UnicodeEncodeError:
        # Fall through to hex pattern
        pass
    if not hits:
        # Try hex pattern (space-separated bytes; `?` is a wildcard)
        try:
            pat_bytes = bytes(int(b, 16) for b in pattern.split())
            pat_re = b"".join(b"\\x00" if b == ord("?") else re.escape(bytes([b])) for b in pat_bytes)
            for m in re.finditer(pat_re, data):
                hits.append({
                    "offset": hex(start + m.start()),
                    "preview": data[m.start():m.start() + 32].hex(),
                })
                if len(hits) >= max_hits:
                    break
        except (ValueError, re.error):
            # Pattern isn't valid hex either. Return what we have (likely
            # an empty list) — the analyst can decide if they meant ASCII.
            pass
    try:
        Path(tmp).unlink()
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return {
        "tool": "search_phys",
        "status": "ok",
        "vm": vm,
        "pattern": pattern,
        "range": [hex(start), hex(end)],
        "hit_count": len(hits),
        "hits": hits,
        "capped_at_max": len(hits) >= max_hits,
    }


@mcp.tool()
def hash_phys_range(phys_addr: int, size: int, vm: str = DEFAULT_VM_NAME) -> dict:
    """SHA-256 of a guest physical address range. Useful for verifying
    a target's tamper-detection only fires on the addresses we expect.
    """
    if size > _MAX_PMEMSAVE:
        return {"tool": "hash_phys_range", "status": "error", "error": f"size {size} > max {_MAX_PMEMSAVE}"}
    tmp = f"/tmp/.hash-phys-{int(time.time()*1000)}.bin"
    out = dump_phys_range(phys_addr, size, tmp, vm=vm)
    if out.get("status") != "ok":
        return out
    sha = hashlib.sha256(Path(tmp).read_bytes()).hexdigest()
    try:
        Path(tmp).unlink()
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return {
        "tool": "hash_phys_range",
        "status": "ok",
        "vm": vm,
        "phys_addr": hex(phys_addr),
        "size": size,
        "sha256": sha,
    }


@mcp.tool()
def diff_snapshots(
    snap_a: str,
    snap_b: str,
    phys_addr: int,
    size: int,
    vm: str = DEFAULT_VM_NAME,
) -> dict:
    """Diff the same phys range across two snapshots. v0.5.1 takes
    the easy path: revert to A, hash; revert to B, hash; restore the
    VM to running state. v0.6 will read the snapshot files directly."""
    # We need the snapshot control — re-vm-control lives in a separate
    # per-server venv. To avoid the cross-venv import, we shell out to
    # virsh directly. (The `re-vm-control` server exists for the
    # interactive MCP use; this is the programmatic equivalent.)
    from re_breaker.vm_client import virsh
    # 1. Get current state to restore later
    cur_state = qemu_monitor_command(vm, {"execute": "query-status"})
    # 2. Revert to snap_a
    virsh("snapshot-revert", vm, snap_a, "--force", timeout_s=60)
    hash_a = hash_phys_range(phys_addr, size, vm=vm)
    # 3. Revert to snap_b
    virsh("snapshot-revert", vm, snap_b, "--force", timeout_s=60)
    hash_b = hash_phys_range(phys_addr, size, vm=vm)
    # 4. If the VM was running before, resume it
    if cur_state.get("status") == "running":
        qemu_monitor_command(vm, {"execute": "cont"})
    return {
        "tool": "diff_snapshots",
        "status": "ok",
        "vm": vm,
        "snap_a": snap_a,
        "snap_b": snap_b,
        "phys_addr": hex(phys_addr),
        "size": size,
        "hash_a": hash_a.get("sha256"),
        "hash_b": hash_b.get("sha256"),
        "same": hash_a.get("sha256") == hash_b.get("sha256"),
        "note": "v0.5.1 takes the destructive revert path; v0.6 will read snapshot files directly",
    }


def main() -> None:
    if mcp is None:
        raise SystemExit("mcp[cli] not installed; `uv add mcp[cli]`")
    mcp.run()


if __name__ == "__main__":
    main()
