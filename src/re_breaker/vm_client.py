"""RE-BREAKER shared VM client (v0.5.0).

The native-Windows-VM toolchain (`re-vm-control`, `re-vm-ssh`,
`re-vm-launch`, `re-vm-debug`, `re-vm-memory`, `re-ida-remote`,
`re-ghidra-remote`, `re-x64dbg-remote`) all want the same three things:

1. **Plugin root resolution** — find the RE-BREAKER checkout from
   anywhere on disk (used to locate `data/catalog.json`, vendored
   RE-AI, etc.).
2. **A libvirt/QEMU handle** — talk to the running KVM guest via QMP.
3. **A persistent SSH transport to the Windows guest** — plus
   lifecycle-managed SSH `-L` tunnels for the upstream MCP servers.

This module centralises all three so each per-server `pyproject.toml`
is just `dependencies = [..., "re-vm-ssh"]` and the implementation
imports the helpers it needs (rather than spinning fresh paramiko
sockets per tool call).

The shared module is **imported**, not invoked through MCP — matching
the pattern existing servers use for `re_breaker.triage` (see
`servers/re-winedbg/src/re_winedbg/server.py:30-33` for the path-poking
that lets a per-server `uv` venv import from the project-wide `src/`).
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

log = logging.getLogger("re_breaker.vm_client")


# ----------------------------------------------------------------------------
# Plugin root resolution (mirrors re_breaker.triage._plugin_root)
# ----------------------------------------------------------------------------

def _plugin_root() -> Path:
    """Resolve the RE-BREAKER plugin root from any working directory.

    Order:
    1. `$RE_BREAKER_PLUGIN_ROOT` env var if set.
    2. Walk up from this file until we find a directory containing both
       `servers/` and `vendored/`.
    3. The cwd if it has the right shape.
    4. Raise.
    """
    env = os.environ.get("RE_BREAKER_PLUGIN_ROOT")
    if env and Path(env).is_dir():
        return Path(env)
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "servers").is_dir() and (parent / "vendored").is_dir():
            return parent
    cwd = Path.cwd()
    if (cwd / "servers").is_dir() and (cwd / "vendored").is_dir():
        return cwd
    raise RuntimeError(
        "RE-BREAKER plugin root not found. Set RE_BREAKER_PLUGIN_ROOT or run from "
        "inside the RE-BREAKER checkout."
    )


# ----------------------------------------------------------------------------
# Default VM coordinates (overridable via env)
# ----------------------------------------------------------------------------

# These defaults match the user's current setup (verified during
# v0.5.0 planning: VM "win11" at RE_BREAKER_SSH_HOST, reachable as
# john@<ip> with the existing ed25519 key).
DEFAULT_LIBVIRT_URI = os.environ.get("RE_BREAKER_LIBVIRT_URI", "qemu:///system")
DEFAULT_VM_NAME = os.environ.get("RE_BREAKER_VM_NAME", "win11")
DEFAULT_SSH_HOST = os.environ.get("RE_BREAKER_SSH_HOST", "john@RE_BREAKER_SSH_HOST")
DEFAULT_SSH_KEY = os.environ.get(
    "RE_BREAKER_SSH_KEY", str(Path.home() / ".ssh" / "id_ed25519")
)
DEFAULT_SSH_PORT = int(os.environ.get("RE_BREAKER_SSH_PORT", "22"))


# ----------------------------------------------------------------------------
# Libvirt handle (cached, thread-safe)
# ----------------------------------------------------------------------------

_LIBVIRT_LOCK = threading.Lock()
_LIBVIRT_CONN: Optional[Any] = None  # libvirt.virConnect


def get_libvirt() -> Any:
    """Return a cached `libvirt.virConnect` for the system URI.

    Lazy-imports libvirt so the helpers are usable in tests that don't
    have the C extension available (the c-injection-build server has
    the same pattern).
    """
    global _LIBVIRT_CONN
    with _LIBVIRT_LOCK:
        if _LIBVIRT_CONN is not None:
            return _LIBVIRT_CONN
        try:
            import libvirt  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "libvirt-python not installed; `pip install libvirt-python`"
            ) from e
        _LIBVIRT_CONN = libvirt.open(DEFAULT_LIBVIRT_URI)
        if _LIBVIRT_CONN is None:
            raise RuntimeError(f"failed to open libvirt URI: {DEFAULT_LIBVIRT_URI}")
        return _LIBVIRT_CONN


# ----------------------------------------------------------------------------
# QMP helper (raw passthrough via `virsh qemu-monitor-command`)
# ----------------------------------------------------------------------------

def qemu_monitor_command(vm: str, command: dict[str, Any], timeout_s: int = 30) -> dict:
    """Run a QMP `command` dict against `vm` via `virsh`.

    We shell out to `virsh` rather than talking to the QMP socket
    directly because libvirt serialises the connection for us and
    rejects concurrent writers, so we get correct locking for free.
    Use the raw socket via `_qemu_monitor_socket` only for hot loops.

    Returns the parsed `return` field, or raises on `error`.
    """
    cmd_json = json.dumps(command)
    # `virsh qemu-monitor-command` does not have a --timeout flag
    # (libvirt 12.x); the only knob is the subprocess timeout. We
    # pass the timeout to subprocess.run so a hung QMP doesn't block
    # the MCP tool call indefinitely.
    proc = subprocess.run(
        ["virsh", "-c", DEFAULT_LIBVIRT_URI, "qemu-monitor-command", vm, cmd_json],
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"virsh qemu-monitor-command failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"virsh returned non-JSON: {proc.stdout!r}") from e
    if "error" in payload and payload.get("error"):
        raise RuntimeError(f"QMP error: {payload['error']}")
    return payload.get("return", payload)


# ----------------------------------------------------------------------------
# QEMU gdb stub port (mutated by re-vm-control.attach_gdb_stub)
# ----------------------------------------------------------------------------

GDB_STUB_PORT = int(os.environ.get("RE_BREAKER_GDB_STUB_PORT", "1234"))


def gdb_stub_endpoint() -> tuple[str, int]:
    """The (host, port) tuple the QEMU gdb stub listens on once attached.

    Always 127.0.0.1 because libvirt's QEMU monitor exposes a `-gdb`
    UNIX socket or a TCP port bound to 127.0.0.1 (we use the latter
    so we can talk to it from any language).
    """
    return ("127.0.0.1", GDB_STUB_PORT)


def gdb_stub_alive(timeout_s: float = 0.5) -> bool:
    """True iff a TCP listener responds on the configured gdb stub port.

    Cheap probe; safe to call before every `re-vm-debug` operation.
    """
    host, port = gdb_stub_endpoint()
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


# ----------------------------------------------------------------------------
# SSH transport pool (one persistent paramiko client per process)
# ----------------------------------------------------------------------------

@dataclass
class SshSession:
    """A cached paramiko SSH client + the registry entry for it.

    The `tunnels` dict maps a user-supplied name → the
    `paramiko.Channel` of the local-side of the port forward. We keep
    them open in a `DirectTcpipChannel` so the local endpoint stays
    bound even when no one is connected (analyst can connect later).
    """
    client: Any
    host: str
    port: int
    username: str
    key_path: Path
    tunnels: dict[str, dict[str, Any]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __repr__(self) -> str:  # pragma: no cover (debug only)
        return f"<SshSession {self.username}@{self.host}:{self.port} tunnels={len(self.tunnels)}>"


_SSH_LOCK = threading.Lock()
_SSH_SESSION: Optional[SshSession] = None


def _parse_ssh_host(spec: str) -> tuple[str, int, str]:
    """Parse `user@host[:port]` (the form ssh(1) accepts)."""
    if "@" in spec:
        user, host_port = spec.split("@", 1)
    else:
        user, host_port = os.environ.get("USER", "john"), spec
    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        return user, int(port), host
    return user, DEFAULT_SSH_PORT, host_port


def get_ssh() -> SshSession:
    """Return the cached SshSession, opening it on first use."""
    global _SSH_SESSION
    with _SSH_LOCK:
        if _SSH_SESSION is not None and _SSH_SESSION.client.get_transport().is_active():
            return _SSH_SESSION
        try:
            import paramiko  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "paramiko not installed; `pip install paramiko` (or `uv add paramiko`)"
            ) from e
        user, port, host = _parse_ssh_host(DEFAULT_SSH_HOST)
        key_path = Path(DEFAULT_SSH_KEY).expanduser()
        if not key_path.is_file():
            raise RuntimeError(f"SSH key not found: {key_path}")
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=user,
            key_filename=str(key_path),
            allow_agent=True,
            look_for_keys=True,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
        _SSH_SESSION = SshSession(
            client=client,
            host=host,
            port=port,
            username=user,
            key_path=key_path,
        )
        log.info("opened SSH session to %s@%s:%d", user, host, port)
        return _SSH_SESSION


def close_ssh() -> None:
    """Tear down the cached SSH session + all tunnels."""
    global _SSH_SESSION
    with _SSH_LOCK:
        if _SSH_SESSION is None:
            return
        sess = _SSH_SESSION
        _SSH_SESSION = None
    with sess.lock:
        for name, t in list(sess.tunnels.items()):
            try:
                t["channel"].close()
            except Exception:
                pass
        sess.tunnels.clear()
    try:
        sess.client.close()
    except Exception:
        pass


# ----------------------------------------------------------------------------
# SSH -L port forward lifecycle
# ----------------------------------------------------------------------------

def open_tunnel(name: str, local_port: int, remote_host: str, remote_port: int) -> dict[str, Any]:
    """Open a persistent SSH `-L` forward from `local_port` on the Linux
    host to `remote_host:remote_port` inside the Windows VM.

    Returns a dict suitable for stashing in the registry. The tunnel
    stays open until `close_tunnel(name)` is called or the process
    exits.

    Why paramiko's `request_port_forward` rather than a backgrounded
    `ssh -L -N`? Because the upstream MCP servers are stateful
    (long-lived HTTP listeners); restarting the SSH process per tool
    call would tear down the listener. We keep the paramiko transport
    alive and bind the local port on a background thread.

    v0.6.0: also persists the tunnel metadata to
    `${RE_BREAKER_TUNNELS_REGISTRY_PATH:-~/.cache/re-vm-ssh/tunnels.json}`
    so `recover_tunnels()` can re-open them after a MCP server restart
    (the paramiko transport dies on restart, but the local-port binds
    can be re-established by re-calling open_tunnel after SSH reconnect).
    """
    sess = get_ssh()
    transport = sess.client.get_transport()
    if transport is None:
        raise RuntimeError("SSH transport not open")

    # Bind the local side.
    import threading as _threading
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", local_port))
    server_sock.listen(8)
    server_sock.settimeout(None)

    # Register the remote-side forward with the paramiko transport.
    try:
        transport.request_port_forward("", local_port)
    except Exception as e:
        server_sock.close()
        raise RuntimeError(
            f"failed to register SSH port forward on 127.0.0.1:{local_port}: {e}"
        )

    def _accept_loop(sock: socket.socket) -> None:
        try:
            while True:
                client_sock, _addr = sock.accept()
                try:
                    channel = transport.open_channel(
                        "direct-tcpip",
                        (remote_host, remote_port),
                        client_sock.getpeername(),
                    )
                except Exception:
                    client_sock.close()
                    continue
                # Pump bytes between client_sock and channel in two threads.
                import threading as __t
                def _pipe(src, dst):
                    try:
                        while True:
                            data = src.recv(4096)
                            if not data:
                                break
                            dst.sendall(data)
                    except Exception:
                        pass
                    finally:
                        try: src.close()
                        except Exception: pass
                        try: dst.close()
                        except Exception: pass
                __t.Thread(target=_pipe, args=(client_sock, channel), daemon=True).start()
                __t.Thread(target=_pipe, args=(channel, client_sock), daemon=True).start()
        except Exception:
            return

    accept_thread = _threading.Thread(target=_accept_loop, args=(server_sock,), daemon=True)
    accept_thread.start()

    with sess.lock:
        sess.tunnels[name] = {
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "channel": accept_thread,
            "server_sock": server_sock,
            "opened_at": time.time(),
        }
    _save_tunnels(sess)
    log.info("opened tunnel %r: 127.0.0.1:%d -> %s:%d", name, local_port, remote_host, remote_port)
    return sess.tunnels[name]


def close_tunnel(name: str) -> bool:
    """Close a named tunnel. Returns True if it existed."""
    sess = get_ssh()
    with sess.lock:
        t = sess.tunnels.pop(name, None)
    if t is None:
        return False
    try:
        t["server_sock"].close()
    except Exception:
        pass
    _save_tunnels(sess)
    log.info("closed tunnel %r", name)
    return True


def list_tunnels() -> list[dict[str, Any]]:
    """Snapshot of the current tunnel registry."""
    sess = get_ssh()
    with sess.lock:
        return [
            {
                "name": name,
                "local_port": t["local_port"],
                "remote_host": t["remote_host"],
                "remote_port": t["remote_port"],
                "opened_at": t["opened_at"],
                "age_sec": time.time() - t["opened_at"],
            }
            for name, t in sess.tunnels.items()
        ]


# ----------------------------------------------------------------------------
# Tunnel registry disk-persistence (v0.6.0)
# ----------------------------------------------------------------------------

_TUNNELS_PATH = Path(
    os.environ.get(
        "RE_BREAKER_TUNNELS_REGISTRY_PATH",
        str(Path.home() / ".cache" / "re-vm-ssh" / "tunnels.json"),
    )
).expanduser().resolve()


def _save_tunnels(sess: SshSession) -> None:
    """Persist the tunnel metadata to disk (no live sockets/threads)."""
    try:
        _TUNNELS_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "tunnels": [
                {
                    "name": name,
                    "local_port": t["local_port"],
                    "remote_host": t["remote_host"],
                    "remote_port": t["remote_port"],
                    "opened_at": t["opened_at"],
                }
                for name, t in sess.tunnels.items()
            ]
        }
        tmp = _TUNNELS_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(_TUNNELS_PATH)
    except OSError as exc:
        log.warning("failed to save tunnels registry to %s: %r", _TUNNELS_PATH, exc)


def load_persisted_tunnels() -> list[dict[str, Any]]:
    """Read the persisted tunnel metadata. Returns [] if file missing/corrupt.

    Used by `recover_tunnels()` to re-open tunnels after an MCP server
    restart. Returns the raw records — caller is responsible for the
    `open_tunnel` call (which needs a live SSH session).
    """
    if not _TUNNELS_PATH.exists():
        return []
    try:
        data = json.loads(_TUNNELS_PATH.read_text(encoding="utf-8"))
        return list(data.get("tunnels", []))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("failed to load tunnels registry from %s: %r", _TUNNELS_PATH, exc)
        return []


def recover_tunnels() -> list[dict[str, Any]]:
    """Re-open all persisted tunnels against the current SSH session.

    Called after an MCP server restart: the paramiko transport is
    re-established by `get_ssh()` (lazily), then this function reads
    the on-disk tunnel records and calls `open_tunnel` for each one
    that isn't already in the live registry.

    Returns a list of {name, status, error} dicts.
    """
    sess = get_ssh()  # ensures the SSH transport is alive
    persisted = load_persisted_tunnels()
    results = []
    for t in persisted:
        name = t["name"]
        with sess.lock:
            if name in sess.tunnels:
                results.append({"name": name, "status": "already_open"})
                continue
        try:
            open_tunnel(
                name=name,
                local_port=t["local_port"],
                remote_host=t["remote_host"],
                remote_port=t["remote_port"],
            )
            results.append({"name": name, "status": "recovered"})
        except OSError as exc:
            # The local port might be in use by something else, or the
            # bind might fail for other reasons. Surface the error but
            # don't crash the whole recovery.
            results.append({
                "name": name,
                "status": "failed",
                "error": f"{exc!r}",
            })
        except Exception as exc:
            results.append({
                "name": name,
                "status": "failed",
                "error": f"{exc!r}",
            })
    return results


# ----------------------------------------------------------------------------
# Guest file paths (the 9pfs Z:\ mount)
# ----------------------------------------------------------------------------

def guest_z_path(host_path: str | Path) -> str:
    """Convert a Linux host path to its `Z:\\...` equivalent on the guest.

    The 9pfs tag is `RE-BREAKER`, mounted at `Z:\\` on Windows. Paths
    are translated with backslashes (Windows semantics) and a single
    leading `Z:\\` is preserved.
    """
    p = Path(host_path).expanduser().resolve()
    plugin = _plugin_root().resolve()
    try:
        rel = p.relative_to(plugin)
    except ValueError:
        rel = p
    return "Z:\\" + str(rel).replace("/", "\\")


def host_path_from_z(z_path: str) -> Path:
    """Inverse of `guest_z_path` — `Z:\\foo\\bar` → host `<plugin>/foo/bar`."""
    p = z_path.replace("\\", "/").lstrip("/")
    if p.startswith("Z:/"):
        p = p[len("Z:/"):]
    return _plugin_root() / p


# ----------------------------------------------------------------------------
# Convenience: a one-shot shell command via `virsh` (no libvirt-python dep)
# ----------------------------------------------------------------------------

def virsh(*args: str, timeout_s: int = 30) -> str:
    """Run `virsh <args>` and return stdout. Stderr is logged on failure."""
    proc = subprocess.run(
        ["virsh", "-c", DEFAULT_LIBVIRT_URI, *args],
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        log.warning("virsh %s failed (rc=%d): %s", " ".join(args), proc.returncode, proc.stderr.strip())
    return proc.stdout


# ----------------------------------------------------------------------------
# SSH file put / get (moved from re-vm-ssh so re-vm-launch can import)
# ----------------------------------------------------------------------------

def ssh_file_put(local_path: str, remote_path: str, prefer_z_mount: bool = True) -> dict[str, Any]:
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
            target = remote_path.replace("/", chr(92))
            ps = (
                f"if (Test-Path -LiteralPath '{z}') {{ "
                f"Copy-Item -LiteralPath '{z}' -Destination '{target}' -Force; "
                f"exit 0 }} else {{ exit 1 }}"
            )
            sess = get_ssh()
            i, o, e = sess.client.exec_command(f'powershell -NoProfile -Command "{ps}"', timeout=30)
            rc = o.channel.recv_exit_status()
            if rc == 0:
                return {"method": "z_mount_copy", "source_z": z, "target": target, "rc": 0}
            # fall through to SFTP if the file isn't on the share
        except ValueError:
            pass  # not under plugin root; fall through
    sess = get_ssh()
    sftp = sess.client.open_sftp()
    try:
        sftp.put(str(local), remote_path)
    finally:
        sftp.close()
    return {"method": "sftp", "local": str(local), "remote": remote_path}


def ssh_file_get(remote_path: str, local_path: str, prefer_z_mount: bool = True) -> dict[str, Any]:
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


def ssh_exec(command: str, timeout_s: int = 30, use_powershell: bool = False) -> dict[str, Any]:
    """Run a command in the Windows VM over SSH. Returns the parsed dict.

    Convenience wrapper for `re-vm-launch` and `re-vm-debug` that
    don't want to plumb the paramiko client directly.
    """
    sess = get_ssh()
    cmd = f'powershell -NoProfile -Command "{command}"' if use_powershell else command
    i, o, e = sess.client.exec_command(cmd, timeout=timeout_s)
    out = o.read().decode("utf-8", errors="replace")
    err = e.read().decode("utf-8", errors="replace")
    rc = o.channel.recv_exit_status()
    return {
        "command": command,
        "use_powershell": use_powershell,
        "stdout": out,
        "stderr": err,
        "returncode": rc,
    }


__all__ = [
    "_plugin_root",
    "DEFAULT_LIBVIRT_URI",
    "DEFAULT_VM_NAME",
    "DEFAULT_SSH_HOST",
    "DEFAULT_SSH_KEY",
    "DEFAULT_SSH_PORT",
    "get_libvirt",
    "qemu_monitor_command",
    "GDB_STUB_PORT",
    "gdb_stub_endpoint",
    "gdb_stub_alive",
    "SshSession",
    "get_ssh",
    "close_ssh",
    "open_tunnel",
    "close_tunnel",
    "list_tunnels",
    "load_persisted_tunnels",
    "recover_tunnels",
    "guest_z_path",
    "host_path_from_z",
    "virsh",
    "ssh_file_put",
    "ssh_file_get",
    "ssh_exec",
]
