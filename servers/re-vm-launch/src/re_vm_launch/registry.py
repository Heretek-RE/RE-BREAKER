"""re-vm-launch/registry.py — disk-persistent launch-handle registry (v0.6.0).

Maps a uuid4 handle → LaunchHandle (the metadata of a launched
process in the Windows VM). v0.5.1 was in-memory; v0.6.0 persists
to `${RE_BREAKER_LAUNCH_REGISTRY_PATH:-~/.cache/re-vm-launch/registry.json}`
so the registry survives MCP server restarts.

Per ADR 0006: persistproc is NOT a fit here because the launched
process is a guest-side Windows PID (WMI Win32_Process.Create), not
a host subprocess. Disk-persistence gives us the cross-restart-state
win without persistproc's host-subprocess constraint.

Thread-safe: a single `_REGISTRY_LOCK` guards `_REGISTRY` (the dict),
`_HANDLE_BY_PID` (reverse lookup, so `re-x64dbg-remote` and
`re-vm-debug` can find the right handle when they observe a pid from
outside the launch path), and the lazy-load flag.

PID-reuse caveat: a persisted LaunchHandle with `status=running`
might refer to a guest PID that's been recycled by Windows. The
caller (launch_target, kill_target, etc.) does the guest-side WMI
verification on every operation — persistence is metadata-only.

Caveat for tests: the registry path is determined once at import
time, so monkey-patching the path requires re-import.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("re-vm-launch.registry")

# Where to persist the registry. Override via env for tests.
_REGISTRY_PATH = Path(
    os.environ.get(
        "RE_BREAKER_LAUNCH_REGISTRY_PATH",
        str(Path.home() / ".cache" / "re-vm-launch" / "registry.json"),
    )
).expanduser().resolve()


@dataclass
class LaunchHandle:
    """All the metadata we need to find + manage a launched process."""
    handle: str
    pid: int
    guest_path: str
    args: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    status: str = "launching"  # launching | running | suspended | killed | exited
    # Optional: a cross-reference to a debugger handle (x64dbg attach, gdb stub)
    debugger: Optional[str] = None  # e.g. "x64dbg" | "gdb-stub" | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_REGISTRY_LOCK = threading.Lock()
_REGISTRY: dict[str, LaunchHandle] = {}
_HANDLE_BY_PID: dict[int, str] = {}
_LOADED = False  # lazy-load flag; first access triggers the load


# ----------------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------------

def _load() -> None:
    """Load the registry from disk. Idempotent (no-op if already loaded)."""
    global _LOADED
    if _LOADED:
        return
    if _REGISTRY_PATH.exists():
        try:
            data = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
            for h_dict in data.get("handles", []):
                h = LaunchHandle(**h_dict)
                _REGISTRY[h.handle] = h
                if h.pid:
                    _HANDLE_BY_PID[h.pid] = h.handle
            log.info("loaded %d launch-handles from %s", len(_REGISTRY), _REGISTRY_PATH)
        except (json.JSONDecodeError, OSError, TypeError) as exc:
            log.warning(
                "failed to load launch-registry from %s: %r; starting empty",
                _REGISTRY_PATH, exc,
            )
    _LOADED = True


def _save() -> None:
    """Write the registry to disk. Caller must hold _REGISTRY_LOCK."""
    _REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"handles": [h.to_dict() for h in _REGISTRY.values()]}
    tmp = _REGISTRY_PATH.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(_REGISTRY_PATH)  # atomic on POSIX
    except OSError as exc:
        log.warning("failed to save launch-registry to %s: %r", _REGISTRY_PATH, exc)


def flush() -> None:
    """Force a save right now (test helper, also for clean shutdown)."""
    with _REGISTRY_LOCK:
        _load()
        _save()


def reset_for_tests() -> None:
    """Drop the in-memory state and the on-disk file. Tests only."""
    global _LOADED
    with _REGISTRY_LOCK:
        _REGISTRY.clear()
        _HANDLE_BY_PID.clear()
        _LOADED = False
        if _REGISTRY_PATH.exists():
            _REGISTRY_PATH.unlink()


# ----------------------------------------------------------------------------
# Public API (sync, thread-safe, persisted)
# ----------------------------------------------------------------------------

def mint_handle(guest_path: str, args: Optional[list[str]] = None) -> LaunchHandle:
    """Create a new LaunchHandle (no process launch)."""
    h = LaunchHandle(
        handle=str(uuid.uuid4()),
        pid=0,  # will be set by set_pid()
        guest_path=guest_path,
        args=list(args or []),
    )
    with _REGISTRY_LOCK:
        _load()
        _REGISTRY[h.handle] = h
        _save()
    return h


def register(handle_obj: LaunchHandle) -> None:
    """Insert / update a handle in the registry."""
    with _REGISTRY_LOCK:
        _load()
        _REGISTRY[handle_obj.handle] = handle_obj
        if handle_obj.pid:
            _HANDLE_BY_PID[handle_obj.pid] = handle_obj.handle
        _save()


def set_pid(handle_id: str, pid: int) -> LaunchHandle:
    """Bind a pid to a handle (used after launch_target returns the pid)."""
    with _REGISTRY_LOCK:
        _load()
        h = _REGISTRY[handle_id]
        h.pid = pid
        h.status = "running"
        _HANDLE_BY_PID[pid] = handle_id
        _save()
        return h


def get(handle_id: str) -> Optional[LaunchHandle]:
    with _REGISTRY_LOCK:
        _load()
        return _REGISTRY.get(handle_id)


def get_by_pid(pid: int) -> Optional[LaunchHandle]:
    with _REGISTRY_LOCK:
        _load()
        h_id = _HANDLE_BY_PID.get(pid)
        if h_id is None:
            return None
        return _REGISTRY.get(h_id)


def list_handles() -> list[dict[str, Any]]:
    with _REGISTRY_LOCK:
        _load()
        return [h.to_dict() for h in _REGISTRY.values()]


def remove(handle_id: str) -> Optional[LaunchHandle]:
    with _REGISTRY_LOCK:
        _load()
        h = _REGISTRY.pop(handle_id, None)
        if h is not None and h.pid:
            _HANDLE_BY_PID.pop(h.pid, None)
        _save()
        return h


def update_status(handle_id: str, status: str) -> None:
    with _REGISTRY_LOCK:
        _load()
        h = _REGISTRY.get(handle_id)
        if h is not None:
            h.status = status
            _save()
