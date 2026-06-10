"""v0.8.0+ — RE-BREAKER site-list population (Wave 1, Item B).

Reads the per-target triage JSON's `per_site_rvas` and emits a sidecar
file that the C-side injection library polls to populate its site list.

Why a sidecar file (not a real IPC command channel):
  The current C-side IPC is one-way: C writes events, Python reads them.
  The hook_engine.c `re_breaker_push_site()` API is already designed for
  Python-driven population — it just needs a delivery channel. A file
  polled on the heartbeat interval is the lowest-friction addition:
  no new socket type, no threading changes, and the C-side writer can
  `flock` the file so multiple Python writers don't race.

File format (`~/.re-breaker/sites-{pid}.jsonl`):
  One JSON object per line. Line types:
    {"op": "push_site", "address": "0x7ffd...", "primitive": "INT_3"}
    {"op": "clear_sites"}

Lifecycle:
  - Python (this module) writes lines to the file.
  - C side (hook_engine.c) reads + processes the file every 5s, then
    truncates it (atomic rename, so a writer that arrives mid-poll
    doesn't lose its line).

Usage:
  from load_target_sites import emit_sites_for_target
  emit_sites_for_target(
      target="/path/to/fm.exe",
      binary_base=0x7ffd00000000,    # typically pulled from /proc/PID/maps
      pid=12345,
      primitives=["INT_3", "INVD"],   # which per_site_rvas keys to emit
  )
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Iterable, Optional


# Default site file location: $HOME/.re-breaker/sites-{pid}.jsonl
# (sibling to events.log; C side already knows about ~/.re-breaker/)
def sites_file_for_pid(pid: int) -> Path:
    home = Path(os.environ.get("HOME") or os.path.expanduser("~"))
    return home / ".re-breaker" / f"sites-{pid}.jsonl"


def _plugin_root() -> Path:
    env = os.environ.get("RE_BREAKER_PLUGIN_ROOT")
    if env and Path(env).is_dir():
        return Path(env)
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "servers").is_dir() and (parent / "vendored").is_dir():
            return parent
    return Path.cwd()


def _load_triage(target: str, triage_json_path: Optional[str] = None) -> dict:
    """Load the triage dict. Falls back to the shared loader when no
    explicit path is given.
    """
    if triage_json_path:
        p = Path(triage_json_path)
        if not p.exists():
            raise FileNotFoundError(f"triage_json_path does not exist: {p}")
        return json.loads(p.read_text())
    # Sibling module — only importable when re-injection-runtime's src/ is on path
    plugin_root = _plugin_root()
    sys.path.insert(0, str(plugin_root / "src"))
    try:
        from re_breaker.triage import load_triage as _shared_load_triage  # type: ignore
        return _shared_load_triage(target)
    except Exception as e:
        raise FileNotFoundError(
            f"could not load triage for {target} (no explicit path, shared loader failed: {e})"
        )


def _resolve_binary_base(target: str, pid: Optional[int]) -> int:
    """Resolve the in-memory load address of `target` (or pid's main binary).

    Priority:
      1. Caller-supplied `binary_base` (preferred).
      2. Read /proc/<pid>/maps for the first executable mapping of
         the file matching `target`'s basename.
      3. Raise.
    """
    if pid is not None and sys.platform == "linux":
        try:
            maps = Path(f"/proc/{pid}/maps").read_text()
        except OSError as e:
            raise RuntimeError(f"could not read /proc/{pid}/maps: {e}")
        base_name = Path(target).name
        for line in maps.splitlines():
            # Format: address           perms offset  dev   inode   pathname
            # 7ffd0000-7ffd1000        r-xp 00000000 08:01 12345   /path/to/fm.exe
            parts = line.split()
            if len(parts) < 6:
                continue
            path = parts[-1]
            if not path.endswith(base_name):
                continue
            if "r-xp" not in parts[1]:
                continue
            addr_range = parts[0]
            base = int(addr_range.split("-")[0], 16)
            return base
        raise RuntimeError(
            f"no executable mapping for {base_name} in /proc/{pid}/maps"
        )
    raise RuntimeError(
        "binary_base must be supplied when running off-host "
        "(no pid available for /proc/<pid>/maps lookup)"
    )


def _write_sites_file(
    pid: int,
    sites: Iterable[tuple[int, str]],
    clear_first: bool = True,
) -> int:
    """Append a sequence of (address, primitive) tuples to the sites file.

    Returns the number of sites written.
    """
    path = sites_file_for_pid(pid)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Use 'a' mode (append) so concurrent writers don't clobber each other
    # — the C side drains the file on its 5s tick, so duplicates are bounded
    # by the polling interval.
    written = 0
    with path.open("a") as f:
        if clear_first:
            f.write(json.dumps({"op": "clear_sites"}) + "\n")
        for addr, primitive in sites:
            f.write(json.dumps({
                "op": "push_site",
                "address": hex(addr),
                "primitive": primitive,
            }) + "\n")
            written += 1
    return written


def emit_sites_for_target(
    target: str,
    pid: int,
    *,
    binary_base: Optional[int] = None,
    primitives: Optional[list[str]] = None,
    triage_json_path: Optional[str] = None,
    clear_first: bool = True,
) -> dict:
    """Top-level entry: read the triage, compute virtual addresses, write the sites file.

    Args:
        target: path to the binary (used to find the triage + look up base)
        pid: the target's host PID (where the C-side injection library is loaded)
        binary_base: in-memory load address of the target. If None, reads
                     /proc/<pid>/maps. Required on Windows (where there's
                     no /proc equivalent).
        primitives: list of `per_site_rvas` keys to emit. Default: every
                     primitive that has ≥ 1 site.
        triage_json_path: explicit path to a triage.json (overrides lookup)
        clear_first: emit a `clear_sites` op before the new sites (default True)

    Returns:
        {
          "status": "ok" | "error",
          "triage_json_path": str,
          "binary_base": int,
          "sites_written": int,
          "per_primitive_count": {"INT_3": 1315, "INVD": 187, ...},
          "sites_file": str,
        }
    """
    triage = _load_triage(target, triage_json_path=triage_json_path)
    if not triage:
        return {
            "status": "error",
            "error": f"no triage found for {target}",
            "server": "re-injection-runtime",
            "version": "0.8.0+",
        }
    per_site = triage.get("per_site_rvas", {}) or {}
    if not per_site:
        return {
            "status": "error",
            "error": f"triage has no per_site_rvas: {triage.get('target_key', '?')}",
            "server": "re-injection-runtime",
            "version": "0.8.0+",
        }
    if primitives is None:
        primitives = [k for k, v in per_site.items() if isinstance(v, list) and v]
    if not primitives:
        return {
            "status": "error",
            "error": f"no sites for any of the requested primitives",
            "available_primitives": list(per_site.keys()),
            "server": "re-injection-runtime",
            "version": "0.8.0+",
        }
    # Resolve base
    if binary_base is None:
        try:
            binary_base = _resolve_binary_base(target, pid)
        except Exception as e:
            return {
                "status": "error",
                "error": f"could not resolve binary_base: {e}. "
                         "Pass binary_base= explicitly when running off-host.",
                "server": "re-injection-runtime",
                "version": "0.8.0+",
            }
    # Build the (address, primitive) tuples
    sites: list[tuple[int, str]] = []
    per_primitive_count: dict[str, int] = {}
    for prim in primitives:
        rvas = per_site.get(prim, [])
        if not isinstance(rvas, list):
            continue
        per_primitive_count[prim] = len(rvas)
        for rva in rvas:
            addr = binary_base + int(rva)
            sites.append((addr, prim))
    if not sites:
        return {
            "status": "error",
            "error": f"no sites to emit (primitives={primitives}, per_primitive_count={per_primitive_count})",
            "per_primitive_count": per_primitive_count,
            "server": "re-injection-runtime",
            "version": "0.8.0+",
        }
    written = _write_sites_file(pid, sites, clear_first=clear_first)
    return {
        "status": "ok",
        "server": "re-injection-runtime",
        "version": "0.8.0+",
        "triage_json_path": triage_json_path or f"re-triage-output/.../{triage.get('target_key', '?')}-triage.json",
        "target": target,
        "pid": pid,
        "binary_base": binary_base,
        "primitives": primitives,
        "per_primitive_count": per_primitive_count,
        "sites_written": written,
        "sites_file": str(sites_file_for_pid(pid)),
        "note": (
            "v0.8.0+ site-list emitter. The C-side injection library polls "
            "this file on its 5s heartbeat tick, processes push_site/clear_sites "
            "ops, then truncates the file (atomic rename). See "
            "hook_engine.c::re_breaker_drain_sites_file()."
        ),
    }


def drain_sites_file(pid: int) -> list[dict]:
    """Read + clear the sites file. Returns the list of ops.

    C side calls this on its 5s heartbeat. The atomic rename is the
    file-locking primitive: while the rename is in progress, any Python
    writer that opens the file by name will get a new inode (or fail
    with ENOENT, in which case the writer creates a fresh file).
    """
    path = sites_file_for_pid(pid)
    if not path.exists():
        return []
    # Atomic rename: rename to a tmp name, read the tmp, delete the tmp
    tmp = path.with_suffix(f".{os.getpid()}.{int(time.time() * 1e6)}.drained")
    try:
        os.rename(path, tmp)
    except FileNotFoundError:
        return []
    except OSError:
        return []
    ops: list[dict] = []
    try:
        for line in tmp.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ops.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return ops


__all__ = [
    "sites_file_for_pid",
    "emit_sites_for_target",
    "drain_sites_file",
]
