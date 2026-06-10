"""v0.4.1.3 — RE-BREAKER IPC consumer (Python side).

Connects to the C-side IPC channel:
  - Windows: \\\\.\pipe\\re-breaker-{pid}  (named pipe, server writes / client reads)
  - Linux:   /tmp/re-breaker-{pid}.sock     (Unix domain socket, server accepts+writes / client reads)

The C side does an `accept()` per `send()`, so each call requires a new
client connection. This module reconnects per message, with a tight retry
loop, until the deadline expires or the process exits.

Returns a list of parsed events: [{"event": "...", "payload": "..."}, ...]
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Optional


def pipe_path_for_pid(pid: int) -> str:
    """Linux: path of the Unix domain socket the C side created."""
    return f"/tmp/re-breaker-{pid}.sock"


def connect_linux(pid: int, timeout_s: float = 2.0) -> Optional[socket.socket]:
    """Connect to the C-side Unix socket for `pid`."""
    path = pipe_path_for_pid(pid)
    if not os.path.exists(path):
        return None
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        s.connect(path)
        return s
    except (FileNotFoundError, ConnectionRefusedError, socket.timeout, OSError):
        s.close()
        return None


def connect_windows(pid: int, timeout_s: float = 2.0):
    """Connect to the C-side named pipe for `pid`. Returns a file-like obj.

    Uses msvcrt.open_osfhandle + CreateFileA. PyWin32 not required.
    """
    import msvcrt  # type: ignore
    import _winapi  # type: ignore
    import ctypes
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = -1

    pipe_name = f"\\\\.\\pipe\\re-breaker-{pid}"
    # Use Win32 CreateFileW via ctypes
    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.restype = wintypes.HANDLE
    CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    # FILE_SHARE_READ | FILE_SHARE_WRITE
    handle = CreateFileW(pipe_name, GENERIC_READ, 3, None, OPEN_EXISTING, 0, None)
    if handle in (INVALID_HANDLE_VALUE, None, 0):
        return None
    if handle == -1:
        return None
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    return os.fdopen(fd, "rb", buffering=0)


def read_one_event_linux(pid: int, timeout_s: float = 2.0) -> Optional[dict]:
    """Connect, read one JSON line, return parsed event or None.

    v0.4.1.3: the C side does `accept()` → `write(1 message)` → `close(client)`
    per `ipc_send()`. So the client must connect, read whatever the server
    wrote (a single newline-terminated JSON line), then handle the close.
    The server may take up to 5s (heartbeat interval) to do its first
    `accept()`, so we use a long connect timeout.
    """
    s = connect_linux(pid, timeout_s=timeout_s)
    if s is None:
        return None
    try:
        buf = b""
        deadline = time.time() + 1.0  # recv window after connect
        while time.time() < deadline:
            try:
                chunk = s.recv(4096)
            except (ConnectionResetError, BrokenPipeError):
                # server closed the connection after writing its message
                break
            except socket.timeout:
                break
            if not chunk:
                # orderly close — message was already fully delivered
                break
            buf += chunk
            if b"\n" in buf:
                break
        if not buf:
            return None
        line, _, _ = buf.partition(b"\n")
        try:
            return json.loads(line.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {"event": "raw", "payload": line.decode("utf-8", errors="replace").rstrip()}
    finally:
        s.close()


def read_one_event_windows(pid: int, timeout_s: float = 2.0) -> Optional[dict]:
    """Connect to the named pipe, read one JSON line, return parsed event or None.

    v0.4.1.3: the C side does a single `WriteFile` then keeps the pipe
    handle open (PIPE_ACCESS_OUTBOUND, single instance). Client reads
    until newline or EOF.
    """
    f = connect_windows(pid, timeout_s=timeout_s)
    if f is None:
        return None
    try:
        buf = b""
        deadline = time.time() + 1.0
        while time.time() < deadline:
            try:
                chunk = f.read(1)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break
        if not buf:
            return None
        line, _, _ = buf.partition(b"\n")
        try:
            return json.loads(line.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {"event": "raw", "payload": line.decode("utf-8", errors="replace").rstrip()}
    finally:
        f.close()


def read_one_event(pid: int, timeout_s: float = 2.0) -> Optional[dict]:
    """OS-aware single-event read."""
    if sys.platform == "win32":
        return read_one_event_windows(pid, timeout_s)
    return read_one_event_linux(pid, timeout_s)


def consume(
    pid: int,
    duration_s: float = 10.0,
    max_events: int = 100,
    heartbeat_s: float = 5.0,
) -> list[dict]:
    """Consume events from `pid`'s IPC channel for `duration_s` seconds.

    Returns up to `max_events` events. The poll is busy: re-connecting per
    message (the C side's accept-per-send model). Each connect blocks for
    up to `heartbeat_s` seconds — the C-side worker thread sends a
    heartbeat every 5s, so the connect catches the next available event.
    """
    events = []
    deadline = time.time() + duration_s
    got_first = False
    # First connect: be patient (up to the full duration).
    # Subsequent: the heartbeat interval (with a small slack).
    first_connect_timeout = max(heartbeat_s, duration_s)
    while time.time() < deadline and len(events) < max_events:
        timeout_s = first_connect_timeout if not got_first else heartbeat_s + 0.5
        evt = read_one_event(pid, timeout_s=timeout_s)
        if evt is None:
            if not got_first:
                # never connected — the C side may not be sending events at all
                break
            # got at least one — small backoff before next reconnect
            time.sleep(0.2)
            continue
        events.append(evt)
        got_first = True
    return events


def is_target_alive(pid: int) -> bool:
    """Check if a process with `pid` is still alive."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def events_log_path() -> Path:
    """The fallback batched log the C side writes (in addition to IPC)."""
    home = Path(os.environ.get("HOME") or os.path.expanduser("~"))
    return home / ".re-breaker" / "events.log"
