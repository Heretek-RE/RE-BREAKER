"""re-launch-and-observe MCP server (v0.2.0 — persistproc-backed ffmpeg).

v0.2.0 implements the observability loop. The key change from the
v0.1.0 SCAFFOLD: ffmpeg x11grab captures are spawned via the
`re-persistproc` MCP sidecar, so the host subprocess (and its log
files) survive an MCP server restart.

Integration shape (see docs/decisions/0006-persistproc-integration-shape.md):
- ffmpeg is started via `persistproc.client.make_client(8947).call_tool(
  "ctrl", action="start", command_or_label="ffmpeg ...", working_directory=tmp,
  label=f"obs-{observability_id}")`.
- The combined log file is read directly from
  `${PERSISTPROC_DATA_DIR}/process_logs/<pid>.ffmpeg_*.combined` —
  no MCP roundtrip on the read path.
- After a server restart, `recover_observability(observability_id)`
  re-queries `list` by label to re-bind the in-process state.

The in-process state (observability_id → _ObsState) is still
in-memory; cross-restart persistence for that dict is a separate
refactor (deferred to a later phase — see ADR 0006).

Tools:
- find_wine_window(winclass, winname_contains) — v0.1.0 stub
- launch_with_observability(target, wine_prefix, ...) — v0.2.0 real
- dump_observability(observability_id) — v0.2.0 real (reads ffmpeg log)
- recover_observability(observability_id) — v0.2.0 NEW
- stop_observability(observability_id) — v0.2.0 NEW
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(asctime)s.%(msecs)03d] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("re-launch-and-observe")

__version__ = "0.2.0"

mcp = FastMCP("re-launch-and-observe")

# ----------------------------------------------------------------------------
# persistproc client (sync wrapper around the async fastmcp client)
# ----------------------------------------------------------------------------

PERSISTPROC_PORT = int(os.environ.get("PERSISTPROC_PORT", "8947"))
PERSISTPROC_DATA_DIR = Path(
    os.environ.get("PERSISTPROC_DATA_DIR", str(Path.home() / ".local" / "share" / "persistproc"))
).expanduser().resolve()

# Add the vendored persistproc to sys.path so we can import its client.
# The vendored venv at vendored/persistproc/.venv has fastmcp installed;
# we import from the persistproc/ source dir directly (editable install).
_PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
_PP_SRC = _PLUGIN_ROOT / "vendored" / "persistproc" / "persistproc"
if str(_PP_SRC) not in sys.path:
    sys.path.insert(0, str(_PP_SRC))


def _pp_client():
    """Return a fresh `fastmcp.client.Client` for the persistproc sidecar.

    Each call returns a new client — they are cheap to construct and
    this keeps the sync→async bridge below simple.
    """
    from persistproc.client import make_client  # type: ignore[import-not-found]
    return make_client(PERSISTPROC_PORT)


def _pp_call(tool: str, payload: dict[str, Any], timeout_s: float = 30.0) -> dict[str, Any]:
    """Sync wrapper around an MCP tool call to persistproc.

    RE-BREAKER's MCP tool handlers are sync (FastMCP registers them as
    plain `def`, not `async def`). We bridge to persistproc's async
    `fastmcp.client.Client` via `asyncio.run`. Each call spins up a
    short-lived event loop, which is fine since the persistproc server
    is on localhost and the calls are sub-second.
    """
    async def _call() -> dict[str, Any]:
        async with _pp_client() as c:
            res = await c.call_tool(tool, payload)
            return json.loads(res[0].text)

    return asyncio.run(asyncio.wait_for(_call(), timeout=timeout_s))


# ----------------------------------------------------------------------------
# In-process state
# ----------------------------------------------------------------------------

@dataclass
class _ObsState:
    """Per-observability-run state. Keyed by observability_id.

    Note (v0.6.0 ADR 0006): this dict is in-memory only; cross-restart
    persistence for it lands in a later phase. The HOST-side ffmpeg
    process IS persistent (via persistproc) — only the metadata here
    is not, and `recover_observability()` rebuilds it from persistproc.
    """
    observability_id: str
    target: str
    wine_prefix: str
    pid: int = 0
    persistproc_label: str = ""
    ffmpeg_log_path: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None
    status: str = "starting"  # starting | running | recovered | stopped | failed
    # Background observer threads (only alive while running)
    _xprop_thread: Optional[threading.Thread] = field(default=None, repr=False)
    _log_tail_thread: Optional[threading.Thread] = field(default=None, repr=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, repr=False)
    _events: list[dict[str, Any]] = field(default_factory=list, repr=False)
    _events_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Strip non-serializable thread/lock fields
        d.pop("_xprop_thread", None)
        d.pop("_log_tail_thread", None)
        d.pop("_stop_event", None)
        d.pop("_events", None)
        d.pop("_events_lock", None)
        return d


_STATE: dict[str, _ObsState] = {}
_STATE_LOCK = threading.Lock()


# ----------------------------------------------------------------------------
# Background observers (xprop + log tail)
# ----------------------------------------------------------------------------

def _xprop_observer(state: _ObsState, target: str) -> None:
    """Poll xprop for the Wine child's window-id and record changes.

    Best-effort — xprop may not be available in all environments, and
    the Wine child's WM_CLASS can shift between attempts (see the
    v0.4.2.0 known issue in the original tool docstring). We log
    whatever xprop says and let the analyst filter downstream.
    """
    try:
        import subprocess
    except ImportError:
        return

    # We don't actually run xprop in v0.2.0 — that's a future phase.
    # v0.2.0 ships the persistproc-backed ffmpeg integration; xprop
    # polling and log tailing are stubbed here so the event log
    # structure is correct for downstream tools.
    while not state._stop_event.is_set():
        time.sleep(2.0)
        with state._events_lock:
            state._events.append({
                "ts": time.time(),
                "kind": "xprop_stub",
                "payload": {"note": "v0.2.0 stub; xprop polling lands in v0.3.0"},
            })


def _log_tail_observer(state: _ObsState, log_path: str) -> None:
    """Tail the ffmpeg combined log file and append new lines to events.

    The path is `<PERSISTPROC_DATA_DIR>/process_logs/<pid>.<escaped-cmd>.combined`.
    We poll the file (no inotify) — ffmpeg doesn't write often, polling
    at 1s is fine.
    """
    p = Path(log_path)
    last_size = 0
    while not state._stop_event.is_set():
        if p.exists():
            try:
                size = p.stat().st_size
                if size > last_size:
                    with p.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(last_size)
                        new = fh.read()
                    last_size = size
                    with state._events_lock:
                        state._events.append({
                            "ts": time.time(),
                            "kind": "ffmpeg_log",
                            "payload": {"bytes": len(new), "tail": new[-500:]},
                        })
            except OSError:
                pass
        time.sleep(1.0)


# ----------------------------------------------------------------------------
# Tools
# ----------------------------------------------------------------------------

@mcp.tool()
def find_wine_window(winclass: str, winname_contains: str = "") -> dict[str, Any]:
    """Resolve the X11 window ID of a Wine child window.

    v0.1.0 SCAFFOLD — see the original docstring. Real implementation
    in a later phase.
    """
    log.info("find_wine_window(%r, %r) — SCAFFOLD", winclass, winname_contains)
    return {
        "window_id": None,
        "title": None,
        "wm_class": None,
        "found": False,
        "note": "SCAFFOLD — xprop polling lands in a later phase",
    }


@mcp.tool()
def launch_with_observability(
    target: str,
    wine_prefix: str,
    env: Optional[dict[str, str]] = None,
    monitor_windows: bool = True,
    monitor_x11: bool = True,
    monitor_logs: tuple[str, ...] = ("winsock", "wininet", "http", "fixme-all"),
    capture_interval_sec: int = 5,
    duration_sec: int = 180,
    display: str = ":0",
    ffmpeg_video_size: str = "1920x1080",
    ffmpeg_framerate: int = 30,
    key_injections: Optional[list[tuple[str, int]]] = None,
) -> dict[str, Any]:
    """Spawn a Wine target with full observability: xprop polling, ffmpeg
    x11grab capture, emulator log tailing, scheduled XTest key injection.

    v0.2.0: the ffmpeg capture is spawned via the `re-persistproc` sidecar,
    so the host subprocess survives a re-launch-and-observe MCP server
    restart. Use `recover_observability(observability_id)` to re-bind the
    in-process metadata to the still-running ffmpeg.

    Args:
        target: absolute path to the .exe (informational; not used in v0.2.0)
        wine_prefix: WINEPREFIX path (informational)
        env: extra env vars passed to ffmpeg (e.g. DISPLAY=:0)
        monitor_windows: poll xprop for window changes
        monitor_x11: run ffmpeg x11grab at capture_interval_sec intervals
        monitor_logs: which Wine debug channels to capture (informational v0.2.0)
        capture_interval_sec: seconds between ffmpeg frames (informational v0.2.0)
        duration_sec: total duration; ffmpeg is started with `-t {duration_sec}`
        display: X11 display for ffmpeg's x11grab input
        ffmpeg_video_size: WxH for x11grab
        ffmpeg_framerate: fps for x11grab
        key_injections: list of (key_name, at_seconds) pairs to fire via XTest (informational v0.2.0)

    Returns:
        dict with keys: observability_id, target, wine_prefix, duration_sec,
        persistproc_pid, ffmpeg_log_path, status, note
    """
    obs_id = str(uuid.uuid4())
    label = f"obs-{obs_id}"

    # Build the ffmpeg command. -t stops ffmpeg naturally after duration_sec.
    ffmpeg_cmd = (
        f"ffmpeg -video_size {ffmpeg_video_size} -framerate {ffmpeg_framerate} "
        f"-f x11grab -i {shlex.quote(display)} -t {duration_sec} -y /dev/null"
    )

    # persistproc requires a working_directory that exists; use a tmpdir
    # scoped to the observability run so it's easy to find the artifacts.
    work_dir = Path(f"/tmp/re-launch-and-observe/{obs_id}")
    work_dir.mkdir(parents=True, exist_ok=True)

    # Build the environment for ffmpeg: include the caller's `env` (so
    # DISPLAY etc. are set), and force unbuffered output for the log
    # file to update promptly.
    ffmpeg_env = {
        "DISPLAY": display,
        "PYTHONUNBUFFERED": "1",
        "FFMPEG_LOG_PATH": str(work_dir / "ffmpeg.log"),
        **(env or {}),
    }

    log.info(
        "launch_with_observability(obs=%s, target=%r) — spawning ffmpeg via persistproc",
        obs_id, target,
    )
    log.info("  ffmpeg_cmd = %s", ffmpeg_cmd)
    log.info("  work_dir   = %s", work_dir)
    log.info("  label      = %s", label)

    try:
        info = _pp_call("ctrl", {
            "action": "start",
            "command_or_label": ffmpeg_cmd,
            "working_directory": str(work_dir),
            "environment": ffmpeg_env,
            "label": label,
        })
    except Exception as exc:
        log.exception("persistproc ctrl start failed")
        return {
            "observability_id": obs_id,
            "target": target,
            "wine_prefix": wine_prefix,
            "duration_sec": duration_sec,
            "status": "failed",
            "error": f"persistproc ctrl start failed: {exc!r}",
            "note": "re-launch-and-observe v0.2.0; see ADR 0006 for the persistproc shape",
        }

    if info.get("error"):
        return {
            "observability_id": obs_id,
            "target": target,
            "wine_prefix": wine_prefix,
            "duration_sec": duration_sec,
            "status": "failed",
            "error": info["error"],
            "note": "persistproc refused to start ffmpeg",
        }

    pid = info["pid"]
    ffmpeg_log = info.get("log_combined") or ""

    state = _ObsState(
        observability_id=obs_id,
        target=target,
        wine_prefix=wine_prefix,
        pid=pid,
        persistproc_label=label,
        ffmpeg_log_path=ffmpeg_log,
        status="running",
    )

    # Start the background observers (xprop + log tail).
    if monitor_windows:
        t = threading.Thread(
            target=_xprop_observer,
            args=(state, target),
            daemon=True,
            name=f"xprop-{obs_id[:8]}",
        )
        t.start()
        state._xprop_thread = t
    if monitor_x11 and ffmpeg_log:
        t = threading.Thread(
            target=_log_tail_observer,
            args=(state, ffmpeg_log),
            daemon=True,
            name=f"logtail-{obs_id[:8]}",
        )
        t.start()
        state._log_tail_thread = t

    with _STATE_LOCK:
        _STATE[obs_id] = state

    return {
        "observability_id": obs_id,
        "target": target,
        "wine_prefix": wine_prefix,
        "duration_sec": duration_sec,
        "persistproc_pid": pid,
        "ffmpeg_log_path": ffmpeg_log,
        "status": "running",
        "note": "re-launch-and-observe v0.2.0; ffmpeg persists across MCP restarts via persistproc",
    }


@mcp.tool()
def dump_observability(observability_id: str) -> dict[str, Any]:
    """Return the captured event log for a prior launch_with_observability run.

    Reads the ffmpeg combined log file directly (no MCP roundtrip), plus
    the in-process event log.

    Args:
        observability_id: the ID returned by launch_with_observability

    Returns:
        dict with keys: observability_id, events (list), screenshot_paths (list),
        ffmpeg_log_path, persistproc_pid, persistproc_status
    """
    with _STATE_LOCK:
        state = _STATE.get(observability_id)

    if state is None:
        # Try to recover from persistproc (ffmpeg may still be running
        # from a prior MCP-server run)
        rec = _try_recover(observability_id)
        if rec is None:
            return {
                "observability_id": observability_id,
                "events": [],
                "screenshot_paths": [],
                "status": "unknown",
                "note": "no in-process state and persistproc has no record; was the obs_id ever launched?",
            }
        state = rec

    # Read the ffmpeg log directly (it's just a file)
    log_tail = ""
    if state.ffmpeg_log_path and Path(state.ffmpeg_log_path).exists():
        with open(state.ffmpeg_log_path, "r", encoding="utf-8", errors="replace") as fh:
            log_tail = fh.read()[-5000:]  # last 5KB

    # Get the in-process events snapshot
    with state._events_lock:
        events = list(state._events)

    # Check persistproc's current status
    pp_status = "unknown"
    try:
        list_info = _pp_call("list", {"pid": state.pid})
        procs = list_info.get("processes", [])
        if procs:
            pp_status = procs[0].get("status", "unknown")
    except Exception as exc:
        log.warning("persistproc list failed: %r", exc)

    return {
        "observability_id": observability_id,
        "events": events,
        "screenshot_paths": [],  # ffmpeg in v0.2.0 writes to /dev/null; populated in v0.3.0
        "ffmpeg_log_path": state.ffmpeg_log_path,
        "ffmpeg_log_tail": log_tail,
        "persistproc_pid": state.pid,
        "persistproc_status": pp_status,
        "in_process_status": state.status,
    }


@mcp.tool()
def recover_observability(observability_id: str) -> dict[str, Any]:
    """Re-bind the in-process state for an observability_id by querying
    persistproc for the still-running ffmpeg.

    Use this after a re-launch-and-observe MCP server restart: the
    ffmpeg process is still running (persistproc kept it alive), but
    the in-process dict was lost. Calling this rebuilds the binding
    so `dump_observability` works again.

    Args:
        observability_id: the ID returned by the original launch_with_observability

    Returns:
        dict with keys: observability_id, recovered (bool), persistproc_pid,
        ffmpeg_log_path, status, note
    """
    state = _try_recover(observability_id)
    if state is None:
        return {
            "observability_id": observability_id,
            "recovered": False,
            "status": "not_found",
            "note": "no persistproc process with that label; was the obs_id ever launched?",
        }
    with _STATE_LOCK:
        _STATE[observability_id] = state
    return {
        "observability_id": observability_id,
        "recovered": True,
        "persistproc_pid": state.pid,
        "ffmpeg_log_path": state.ffmpeg_log_path,
        "status": state.status,
        "note": "re-bound to the still-running persistproc ffmpeg",
    }


@mcp.tool()
def stop_observability(observability_id: str, force: bool = False) -> dict[str, Any]:
    """Stop a running ffmpeg capture via persistproc.

    Args:
        observability_id: the ID returned by launch_with_observability
        force: if True, SIGKILL the ffmpeg process

    Returns:
        dict with keys: observability_id, stopped (bool), persistproc_pid,
        exit_code, status
    """
    with _STATE_LOCK:
        state = _STATE.get(observability_id)
    if state is None:
        state = _try_recover(observability_id)
    if state is None:
        return {
            "observability_id": observability_id,
            "stopped": False,
            "status": "not_found",
        }

    try:
        info = _pp_call("ctrl", {
            "action": "stop",
            "pid": state.pid,
            "force": force,
        })
    except Exception as exc:
        return {
            "observability_id": observability_id,
            "stopped": False,
            "persistproc_pid": state.pid,
            "error": f"persistproc ctrl stop failed: {exc!r}",
        }

    # Stop the background threads
    if state is not None:
        state._stop_event.set()

    return {
        "observability_id": observability_id,
        "stopped": info.get("error") is None,
        "persistproc_pid": state.pid,
        "exit_code": info.get("exit_code"),
        "status": "stopped" if info.get("error") is None else "error",
        "error": info.get("error"),
    }


# ----------------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------------

def _try_recover(observability_id: str) -> Optional[_ObsState]:
    """Look up a running ffmpeg by persistproc label and rebuild _ObsState."""
    label = f"obs-{observability_id}"
    try:
        info = _pp_call("list", {"command_or_label": label})
    except Exception as exc:
        log.warning("persistproc list failed during recover: %r", exc)
        return None

    procs = info.get("processes", [])
    matching = [p for p in procs if p.get("label") == label and p.get("status") == "running"]
    if not matching:
        return None

    p = matching[0]
    pid = p["pid"]
    ffmpeg_log = p.get("log_combined") or p.get("log_stdout") or ""

    return _ObsState(
        observability_id=observability_id,
        target="(recovered)",
        wine_prefix="(recovered)",
        pid=pid,
        persistproc_label=label,
        ffmpeg_log_path=ffmpeg_log,
        status="recovered",
    )


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------

def main() -> None:
    log.info("re-launch-and-observe v%s (persistproc-backed ffmpeg)", __version__)
    log.info("  persistproc port    = %d", PERSISTPROC_PORT)
    log.info("  persistproc data dir= %s", PERSISTPROC_DATA_DIR)
    mcp.run()


if __name__ == "__main__":
    main()
