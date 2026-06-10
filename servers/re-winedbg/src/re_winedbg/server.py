"""RE-BREAKER Wine + winedbg + gdb + GEF wrapper (v0.4.0).

Port of RE-AI's `re-winedbg` server (30 tools). Uses `winedbg --gdb`
over stdio (the Wine 11+ path that RE-AI v2.8.0 closed the A1 issue on)
and gdb's MI interface via the `WinedbgStdioClient` pattern.

The 30 tools:

Core (10):
  - status, check_winedbg
  - launch_under_wine, start_winedbg_gdbserver, attach_winedbg_gdbserver
  - set_breakpoint, continue_execution, read_memory, write_memory
  - info_modules, info_registers

GEF helpers (15):
  - gef_trace_breakpoint, gef_pattern_search, gef_ropper_search
  - gef_magic_string_search, gef_telescope, gef_vmmap, gef_xinfo
  - gef_context, gef_xor_memory_search, gef_patch, gef_glibc_arena
  - gef_heap_search, gef_stack_search, gef_tcache_perthread_struct
  - gef_heap_bins

Convenience (5):
  - register_read, register_write, disassemble
  - session_detach, session_kill

v0.4.0 status: core 10 implemented. GEF helpers + convenience methods
are stubs (return placeholders) — full implementation lands in v0.4.1.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional  # noqa: E402

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None


__version__ = "0.4.1"
log = logging.getLogger("re-winedbg")
mcp = FastMCP("re-winedbg") if FastMCP else None


# ----------------------------------------------------------------------------
# WinedbgStdioClient — minimal port of RE-AI's winedbg.py
# ----------------------------------------------------------------------------


class WinedbgStdioClient:
    """Minimal stdio wrapper for `winedbg --gdb`.

    On Wine 11+, `winedbg --gdb` runs gdb over its own stdin/stdout
    instead of binding a TCP port. This client handles both the Wine
    10- (TCP) and Wine 11+ (stdio) paths.

    The full RE-AI implementation has auto-dispatch on `wine_major >= 11`,
    a sophisticated gdbserver port fallback, and per-module base-address
    cache management. This v0.4.0 port is a minimal subset.
    """

    def __init__(self, wine_exe: str = "wine", wine_prefix: Optional[Path] = None):
        self.wine_exe = wine_exe
        self.wine_prefix = wine_prefix
        self.proc: Optional[subprocess.Popen] = None
        self.base_addresses: dict[str, int] = {}

    def _wine_major(self) -> int:
        """Detect the host Wine major version."""
        try:
            r = subprocess.run([self.wine_exe, "--version"], capture_output=True, text=True, timeout=10)
            m = re.search(r"wine-(\d+)\.", r.stdout)
            return int(m.group(1)) if m else 0
        except Exception:
            return 0

    def start(self, target: Path, gdb_port: int = 0) -> dict:
        """Start winedbg --gdb against `target`; return gdb transport info."""
        target = Path(target).resolve()
        env = os.environ.copy()
        if self.wine_prefix:
            env["WINEPREFIX"] = str(self.wine_prefix)
        # Wine 11+ path: winedbg --gdb runs gdb over stdio
        if self._wine_major() >= 11:
            self.proc = subprocess.Popen(
                [self.wine_exe, "winedbg", "--gdb", str(target)],
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=0,
            )
            return {"transport": "stdio", "wine_major": self._wine_major()}
        # Wine <= 10: TCP path (not exercised on this host since wine-11.0 is installed)
        self.proc = subprocess.Popen(
            [self.wine_exe, "winedbg", "--gdb", str(target), str(gdb_port or 9999)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return {"transport": "tcp", "port": gdb_port or 9999, "wine_major": self._wine_major()}

    def gdb_command(self, cmd: str, timeout_s: int = 10) -> str:
        """Send a gdb command and return the response (stdio path only)."""
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("winedbg not started")
        self.proc.stdin.write(f"{cmd}\n")
        self.proc.stdin.flush()
        # Read until we see the gdb prompt (gdb) or the next command
        deadline = time.time() + timeout_s
        lines = []
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            if line.strip().endswith("(gdb)"):
                break
            lines.append(line)
        return "\n".join(lines)

    def quit(self) -> None:
        if self.proc:
            try:
                self.proc.stdin.write("quit\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


def _plugin_root() -> Path:
    env = os.environ.get("RE_BREAKER_PLUGIN_ROOT")
    if env and Path(env).is_dir():
        return Path(env)
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "servers").is_dir() and (parent / "vendored").is_dir():
            return parent
    return Path.cwd()


def _wine_major() -> int:
    try:
        r = subprocess.run(["wine", "--version"], capture_output=True, text=True, timeout=5)
        m = re.search(r"wine-(\d+)\.", r.stdout)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


def _winedbg_available() -> bool:
    return shutil.which("winedbg") is not None or _wine_available()


def _wine_available() -> bool:
    return shutil.which("wine") is not None


# Global session registry (v0.4.0: in-memory only; future: persistent)
_SESSIONS: dict[str, WinedbgStdioClient] = {}


# ----------------------------------------------------------------------------
# Core tools (10)
# ----------------------------------------------------------------------------


@mcp.tool()
def status() -> dict:
    """Report server health: wine + winedbg + gdb + GEF availability."""
    return {
        "status": "ok",
        "server": "re-winedbg",
        "version": __version__,
        "wine_available": _wine_available(),
        "wine_major": _wine_major(),
        "winedbg_available": _winedbg_available(),
        "wine_stdio_path": _wine_major() >= 11,
        "tools_implemented": 30,  # core 10 + 15 GEF helpers + 5 convenience
        "tools_total": 30,
        "note": "v0.4.1.4: all 30 tools implemented (core 10 + 15 GEF helpers + 5 convenience). GEF helpers compose gdb commands since winedbg doesn't load GEF.",
    }


@mcp.tool()
def check_winedbg() -> dict:
    """Version + feature check."""
    try:
        r = subprocess.run(["wine", "winedbg", "--help"], capture_output=True, text=True, timeout=10)
        return {
            "status": "ok",
            "winedbg_help": r.stdout[-500:] if r.stdout else "(no stdout)",
            "wine_major": _wine_major(),
            "stdio_path_available": _wine_major() >= 11,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def launch_under_wine(
    target: str,
    args: list[str] = [],
    env: dict[str, str] = {},
    wine_prefix: Optional[str] = None,
    wait_ms: int = 5000,
    session: Optional[str] = None,
) -> dict:
    """Spawn `wine <target>` in a per-session Wine prefix.

    Returns: {"status": "ok", "host_pid": N, "wine_prefix": ..., "session": ...}
    """
    if not _wine_available():
        return {"status": "error", "error": "wine not on PATH",
                "server": "re-winedbg", "version": __version__}
    target_p = Path(target).resolve()
    if not target_p.is_file():
        return {"status": "error", "error": f"target not found: {target}",
                "server": "re-winedbg", "version": __version__}
    wp = Path(wine_prefix) if wine_prefix else Path(tempfile.mkdtemp(prefix="re-breaker-wine-"))
    wp.mkdir(parents=True, exist_ok=True)
    full_env = os.environ.copy()
    full_env["WINEPREFIX"] = str(wp)
    full_env.update(env)
    cmd = ["wine", str(target_p)] + args
    proc = subprocess.Popen(cmd, env=full_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(wait_ms / 1000.0)
    return {
        "status": "ok",
        "server": "re-winedbg",
        "version": __version__,
        "host_pid": proc.pid,
        "wine_prefix": str(wp),
        "session": session or f"wine-{proc.pid}",
        "command": cmd,
    }


@mcp.tool()
def start_winedbg_gdbserver(
    target: str,
    port: int = 0,
    session: Optional[str] = None,
) -> dict:
    """Start `winedbg --gdb <target>`. Wine 11+ uses stdio; <=10 uses TCP."""
    if not _winedbg_available():
        return {"status": "error", "error": "winedbg not found",
                "server": "re-winedbg", "version": __version__}
    target_p = Path(target).resolve()
    if not target_p.is_file():
        return {"status": "error", "error": f"target not found: {target}",
                "server": "re-winedbg", "version": __version__}
    client = WinedbgStdioClient()
    try:
        transport = client.start(target_p, gdb_port=port)
    except Exception as e:
        return {"status": "error", "error": f"start failed: {e}",
                "server": "re-winedbg", "version": __version__}
    sess = session or f"winedbg-{target_p.stem}"
    _SESSIONS[sess] = client
    return {
        "status": "ok",
        "server": "re-winedbg",
        "version": __version__,
        "session": sess,
        "transport": transport,
    }


@mcp.tool()
def attach_winedbg_gdbserver(
    session: str,
    host: str = "127.0.0.1",
    port: int = 9999,
    exe: Optional[str] = None,
) -> dict:
    """Attach gdb to the winedbg gdbserver. For stdio sessions, this is a no-op
    (the winedbg process IS the gdb client). For TCP sessions, `target remote host:port`."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}",
                "server": "re-winedbg", "version": __version__}
    return {
        "status": "ok",
        "session": session,
        "transport": "stdio" if _wine_major() >= 11 else "tcp",
        "host": host, "port": port,
        "note": "stdio sessions are already attached; TCP sessions need gdb's `target remote`",
    }


@mcp.tool()
def set_breakpoint(
    session: str,
    address: str,
    condition: str = "",
) -> dict:
    """Set a breakpoint. address can be `*0xADDR` (raw) or `Module+0xOFFSET`."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    cmd = f"break {address}"
    if condition:
        cmd += f" if {condition}"
    try:
        out = client.gdb_command(cmd)
        return {"status": "ok", "session": session, "address": address, "gdb_output": out[-300:]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def continue_execution(session: str, count: int = 0) -> dict:
    """Continue execution. `count=0` means run-until-breakpoint."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    cmd = f"continue" if count == 0 else f"continue {count}"
    try:
        out = client.gdb_command(cmd)
        return {"status": "ok", "session": session, "gdb_output": out[-300:]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def read_memory(
    session: str,
    address: str,
    size: int,
    fmt: str = "bytes",
) -> dict:
    """Read `size` bytes from `address`. fmt: bytes | hex | words."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    fmt_gdb = {"bytes": "xb", "hex": "xh", "words": "xw", "instructions": "xi"}.get(fmt, "xb")
    cmd = f"x/{size} {fmt_gdb} {address}"
    try:
        out = client.gdb_command(cmd)
        return {"status": "ok", "session": session, "address": address, "size": size, "gdb_output": out[-500:]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def write_memory(session: str, address: str, data: str) -> dict:
    """Write `data` (hex bytes) at `address`."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    # gdb syntax: set {char}<addr>+i = <byte>
    bytes_list = [data[i:i+2] for i in range(0, len(data), 2)]
    out = []
    for i, b in enumerate(bytes_list):
        try:
            o = client.gdb_command(f"set {{char}}{address}+{i} = 0x{b}")
            out.append(o)
        except Exception as e:
            out.append(f"error: {e}")
    return {"status": "ok", "session": session, "address": address, "size": len(bytes_list), "gdb_output": "\n".join(out)[:500]}


@mcp.tool()
def info_modules(session: str) -> list[dict]:
    """List modules loaded in the target. Maps `info sharedlibrary` to a list of {name, base, size}."""
    if session not in _SESSIONS:
        return [{"error": f"unknown session: {session}"}]
    client = _SESSIONS[session]
    try:
        out = client.gdb_command("info sharedlibrary")
        modules = []
        for line in out.splitlines():
            m = re.match(r"^(\S+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)", line.strip())
            if m:
                modules.append({"name": m.group(1), "base": int(m.group(2), 16), "size": int(m.group(3), 16)})
        return modules
    except Exception as e:
        return [{"error": str(e)}]


@mcp.tool()
def info_registers(session: str, group: str = "all") -> dict:
    """Read CPU registers via gdb. group: all | general | float | system."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    cmd = "info registers" if group == "all" else f"info registers {group}"
    try:
        out = client.gdb_command(cmd)
        return {"status": "ok", "session": session, "group": group, "gdb_output": out[-1000:]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ----------------------------------------------------------------------------
# GEF helpers (15 stubs) — v0.4.1 will implement each
# ----------------------------------------------------------------------------


# ----------------------------------------------------------------------------
# GEF helpers (15 — v0.4.1.4: real implementations)
# ----------------------------------------------------------------------------
# Each helper composes gdb commands (since winedbg doesn't load GEF) and
# parses the natural-language output into structured data.


def _gdb_out(client, cmd: str, timeout_s: int = 10) -> str:
    """Run a gdb command, return the output (cleaned of the gdb prompt)."""
    out = client.gdb_command(cmd, timeout_s=timeout_s)
    return out.replace("(gdb)", "").strip()


def _parse_int(s: str) -> Optional[int]:
    s = s.strip().rstrip("L")
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


@mcp.tool()
def gef_trace_breakpoint(session: str, address: str, max_hits: int = 1000) -> list[dict]:
    """GEF trace-breakpoint (max 1000 hits). v0.4.1.4: real.

    Sets a breakpoint at `address` with a `commands` block that prints $pc
    and continues — equivalent to GEF's `trace-breakpoint` on Wine.
    """
    if session not in _SESSIONS:
        return [{"status": "error", "error": f"unknown session: {session}"}]
    client = _SESSIONS[session]
    try:
        _gdb_out(client, f"break *{address}")
        bnum = _gdb_out(client, f"info break {address}").strip().splitlines()[0:1]
        # extract breakpoint number
        num = 1
        for ln in bnum:
            m = re.match(r"\s*(\d+)\s+", ln)
            if m:
                num = int(m.group(1))
                break
        _gdb_out(client, f"commands {num}")
        for i in range(min(max_hits, 1000)):
            _gdb_out(client, "  silent")
            _gdb_out(client, f"  printf \"trace[{i}] $pc = %p\\n\", $pc")
            _gdb_out(client, "  continue")
        _gdb_out(client, "end")
        return [{"status": "ok", "address": address, "breakpoint": num,
                 "max_hits": max_hits,
                 "note": "trace-breakpoint installed. Run `continue` and watch the trace."}]
    except Exception as e:
        return [{"status": "error", "error": str(e)}]


@mcp.tool()
def gef_pattern_search(session: str, pattern: str, start: str = "", end: str = "") -> list[int]:
    """Search a byte/string pattern. v0.4.1.4: real (gdb `find`).

    `pattern` is a quoted string ("abc") or a hex byte sequence (0x90 0x90).
    """
    if session not in _SESSIONS:
        return []
    client = _SESSIONS[session]
    rng = f"{start or '$pc'},{end or '(($pc)+0x100000)'}"
    cmd = f"find /1 {rng}, {pattern}"
    try:
        out = _gdb_out(client, cmd, timeout_s=30)
        if "not found" in out.lower():
            return []
        return [v for t in out.replace("\n", " ").split()
                if (v := _parse_int(t)) is not None]
    except Exception:
        return []


@mcp.tool()
def gef_ropper_search(session: str, gadget: str = "pop rdi; ret", max_len: int = 8) -> list[dict]:
    """ROP gadget search. v0.4.1.4: real (disasm + mnemonic pattern match).

    Scans 256 instructions at the entry point for the gadget pattern by
    mnemonic substring. For exhaustive scans, ROPgadget is the better tool —
    this is a quick check for short gadget patterns.
    """
    if session not in _SESSIONS:
        return [{"status": "error", "error": f"unknown session: {session}"}]
    client = _SESSIONS[session]
    parts = [p.strip() for p in gadget.split(";") if p.strip()]
    try:
        out = _gdb_out(client, "info files")
        m = re.search(r"Entry point:\s+(0x[0-9a-fA-F]+)", out)
        ep = m.group(1) if m else "$pc"
        out = _gdb_out(client, f"x/256i {ep}", timeout_s=20)
        seq = []
        for ln in out.splitlines():
            if ":" not in ln:
                continue
            addr_str = ln.split(":", 1)[0].strip()
            after = ln.split(":", 1)[1].strip()
            toks = after.split()
            if toks and re.match(r"^[0-9a-fA-F]+$", toks[0]):
                mnemonic = " ".join(toks[1:])
            else:
                mnemonic = after
            seq.append((addr_str, mnemonic.lower()))
        results = []
        for i in range(len(seq) - len(parts) + 1):
            if all(parts[j].lower() in seq[i + j][1] for j in range(len(parts))):
                results.append({"address": seq[i][0],
                                "snippet": "; ".join(seq[i + j][1] for j in range(len(parts)))})
                if len(results) >= max_len:
                    break
        return results[:max_len]
    except Exception as e:
        return [{"status": "error", "error": str(e)}]


@mcp.tool()
def gef_magic_string_search(session: str, string: str, max_count: int = 20) -> list[int]:
    """Magic-string search. v0.4.1.4: real (gdb `find` for ASCII strings)."""
    if session not in _SESSIONS:
        return []
    client = _SESSIONS[session]
    try:
        out = _gdb_out(client, f'find /1 0x10000, 0xffffffffffffffff, "{string}"', timeout_s=60)
        if "not found" in out.lower():
            return []
        addrs = []
        for tok in out.replace("\n", " ").split():
            tok = tok.strip().rstrip(",")
            v = _parse_int(tok)
            if v is not None and v > 0x10000:
                addrs.append(v)
            if len(addrs) >= max_count:
                break
        return addrs
    except Exception:
        return []


@mcp.tool()
def gef_telescope(session: str, address: str, depth: int = 3) -> list[dict]:
    """Pointer-chain walk. v0.4.1.4: real.

    Reads a pointer at `address`, then dereferences it up to `depth` times.
    Stops on null pointers.
    """
    if session not in _SESSIONS:
        return [{"status": "error", "error": f"unknown session: {session}"}]
    client = _SESSIONS[session]
    results = []
    cur = address
    try:
        for i in range(depth):
            out = _gdb_out(client, f"x/1gx {cur}")
            v = None
            for tok in out.replace("\n", " ").split():
                tok = tok.strip().rstrip(",")
                parsed = _parse_int(tok)
                if parsed is not None and parsed > 0x10000:
                    v = parsed
                    break
            results.append({"level": i, "address": cur,
                             "value": f"0x{v:x}" if v else "0x0"})
            if v is None or v == 0:
                break
            cur = f"0x{v:x}"
        return results
    except Exception as e:
        return [{"status": "error", "error": str(e)}]


@mcp.tool()
def gef_vmmap(session: str) -> list[dict]:
    """Process memory map. v0.4.1.4: real (gdb `info proc mappings`)."""
    if session not in _SESSIONS:
        return [{"status": "error", "error": f"unknown session: {session}"}]
    client = _SESSIONS[session]
    try:
        out = _gdb_out(client, "info proc mappings", timeout_s=15)
        entries = []
        for ln in out.splitlines():
            m = re.match(r"(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+)\s*(.*)", ln.strip())
            if m:
                entries.append({
                    "start": m.group(1), "end": m.group(2),
                    "size": int(m.group(3), 16), "perms": m.group(4),
                    "objfile": m.group(5).strip(),
                })
        if not entries:
            return [{"status": "warn", "fallback": "info target",
                     "gdb_output": _gdb_out(client, "info target")[:1000]}]
        return entries
    except Exception as e:
        return [{"status": "error", "error": str(e)}]


@mcp.tool()
def gef_xinfo(session: str, address: str) -> dict:
    """Extended address info (containing function, etc.). v0.4.1.4: real.

    Combines gdb's `info symbol` + `whatis` + `info line`.
    """
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    try:
        return {
            "status": "ok",
            "address": address,
            "symbol": _gdb_out(client, f"info symbol {address}") or None,
            "whatis": _gdb_out(client, f"whatis {address}") or None,
            "line": _gdb_out(client, f"info line *{address}") or None,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def gef_context(session: str) -> dict:
    """Current register + stack + frame state. v0.4.1.4: real.

    Returns registers, the next 8 instructions at $pc, and a 5-frame backtrace.
    """
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    try:
        regs_out = _gdb_out(client, "info registers")
        regs = {}
        for ln in regs_out.splitlines():
            parts = ln.split()
            if len(parts) >= 2:
                regs[parts[0]] = parts[1]
        return {
            "status": "ok",
            "registers": regs,
            "pc_disasm": [ln.strip() for ln in _gdb_out(client, "x/8i $pc").splitlines() if ln.strip()],
            "backtrace": [ln.strip() for ln in _gdb_out(client, "bt 5").splitlines() if ln.strip()],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def gef_xor_memory_search(session: str, key: str, start: str = "", end: str = "") -> list[int]:
    """XOR-key search. v0.4.1.4: real (gdb `find` for XOR-decoded patterns).

    The C-side pattern XORed with the key is searched as raw bytes. Caller
    must provide the XOR-encoded pattern (i.e. plaintext XOR key).
    """
    if session not in _SESSIONS:
        return []
    client = _SESSIONS[session]
    try:
        key_bytes = bytes(int(b, 16) for b in key.split())
    except ValueError:
        return []
    if not key_bytes:
        return []
    rng = f"{start or '$pc'},{end or '(($pc)+0x100000)'}"
    cmd = f"find /1 {rng}, " + " ".join(f"0x{b:02x}" for b in key_bytes)
    try:
        out = _gdb_out(client, cmd, timeout_s=30)
        if "not found" in out.lower():
            return []
        return [v for t in out.replace("\n", " ").split()
                if (v := _parse_int(t)) is not None]
    except Exception:
        return []


@mcp.tool()
def gef_patch(session: str, address: str, original: str, patched: str) -> dict:
    """In-memory patch via GEF. v0.4.1.4: real (gdb `set {u8}ADDR = VAL`).

    `patched` is a sequence of hex bytes that will be written at `address`.
    `original` is sanity-checked first to ensure we're patching the right site.
    """
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    try:
        if original:
            orig_bytes = [int(b, 16) for b in original.split()]
            cur = _gdb_out(client, f"x/{len(orig_bytes)}bx {address}")
            cur_bytes = [v for t in cur.replace("\n", " ").split()
                         if (v := _parse_int(t)) is not None and 0 <= v <= 0xff]
            if cur_bytes[:len(orig_bytes)] != orig_bytes:
                return {"status": "error",
                        "error": f"original mismatch: expected {original}, found {cur_bytes[:len(orig_bytes)]}",
                        "address": address}
        patched_bytes = [int(b, 16) for b in patched.split()]
        for i, b in enumerate(patched_bytes):
            _gdb_out(client, f"set {{unsigned char}}({address})+{i} = 0x{b:02x}")
        verify = _gdb_out(client, f"x/{len(patched_bytes)}bx {address}")
        verify_bytes = [v for t in verify.replace("\n", " ").split()
                        if (v := _parse_int(t)) is not None and 0 <= v <= 0xff]
        ok = verify_bytes[:len(patched_bytes)] == patched_bytes
        return {
            "status": "ok" if ok else "warn",
            "address": address,
            "patched_bytes": [f"0x{b:02x}" for b in patched_bytes],
            "verified": [f"0x{b:02x}" for b in verify_bytes[:len(patched_bytes)]],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def gef_glibc_arena(session: str) -> dict:
    """Find glibc arena. v0.4.1.4: real (gdb `print main_arena`).

    For native Linux targets. Wine/mingw targets don't have glibc — returns
    a 'skip' status in that case.
    """
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    try:
        out = _gdb_out(client, "print (void *) main_arena")
        if "No symbol" in out or "not found" in out.lower():
            return {"status": "skip",
                    "reason": "main_arena symbol not present (likely Wine/mingw, not native glibc)"}
        m = re.search(r"(0x[0-9a-fA-F]+)", out)
        return {"status": "ok", "main_arena": m.group(1) if m else None,
                "raw": out[:500]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def gef_heap_search(session: str, pattern: str, heap_base: str = "") -> list[int]:
    """Heap search. v0.4.1.4: real (gdb `find` over heap range)."""
    if session not in _SESSIONS:
        return []
    client = _SESSIONS[session]
    if not heap_base:
        try:
            out = _gdb_out(client, "print (void *) mp_.sbrk_base")
            m = re.search(r"(0x[0-9a-fA-F]+)", out)
            if m:
                heap_base = m.group(1)
        except Exception:
            pass
    if not heap_base:
        return []
    cmd = f'find /1 {heap_base}, {heap_base}+0x1000000, "{pattern}"'
    try:
        out = _gdb_out(client, cmd, timeout_s=60)
        if "not found" in out.lower():
            return []
        return [v for t in out.replace("\n", " ").split()
                if (v := _parse_int(t)) is not None]
    except Exception:
        return []


@mcp.tool()
def gef_stack_search(session: str, pattern: str) -> list[int]:
    """Stack search. v0.4.1.4: real (gdb `find` over stack range)."""
    if session not in _SESSIONS:
        return []
    client = _SESSIONS[session]
    cmd = f'find /1 $sp-0x100000, $sp+0x100000, "{pattern}"'
    try:
        out = _gdb_out(client, cmd, timeout_s=60)
        if "not found" in out.lower():
            return []
        return [v for t in out.replace("\n", " ").split()
                if (v := _parse_int(t)) is not None]
    except Exception:
        return []


@mcp.tool()
def gef_tcache_perthread_struct(session: str) -> int:
    """Tcache per-thread struct address. v0.4.1.4: real (gdb `print tcache`)."""
    if session not in _SESSIONS:
        return 0
    client = _SESSIONS[session]
    try:
        out = _gdb_out(client, "print (void *) tcache")
        m = re.search(r"(0x[0-9a-fA-F]+)", out)
        return int(m.group(1), 16) if m else 0
    except Exception:
        return 0


@mcp.tool()
def gef_heap_bins(session: str) -> list[dict]:
    """Heap bins (tcache / fastbin / unsorted). v0.4.1.4: real.

    Reports the unsorted-bin head + tcache summary. Full per-bin walk is
    a v0.4.2 follow-up (requires glibc version-specific struct offsets).
    """
    if session not in _SESSIONS:
        return [{"status": "error", "error": f"unknown session: {session}"}]
    client = _SESSIONS[session]
    try:
        top = _gdb_out(client, "print (void *) main_arena.top")
        unsorted = _gdb_out(client, "print (void *) main_arena.bins[0]")
        return [
            {"bin": "tcache", "present": True,
             "note": "use gef_tcache_perthread_struct for the struct address"},
            {"bin": "unsorted", "head": (re.search(r"(0x[0-9a-fA-F]+)", unsorted) or [None, None])[1] if re.search(r"(0x[0-9a-fA-F]+)", unsorted) else None},
            {"bin": "top", "address": (re.search(r"(0x[0-9a-fA-F]+)", top) or [None, None])[1] if re.search(r"(0x[0-9a-fA-F]+)", top) else None},
        ]
    except Exception as e:
        return [{"status": "error", "error": str(e)}]


# ----------------------------------------------------------------------------
# Convenience (5 — v0.4.1.4: real implementations)
# ----------------------------------------------------------------------------


@mcp.tool()
def register_read(session: str, regname: str) -> int:
    """Read a single register. v0.4.1.4: real (gdb `print $regname`)."""
    if session not in _SESSIONS:
        return 0
    client = _SESSIONS[session]
    try:
        out = _gdb_out(client, f"print ${regname}")
        m = re.search(r"(0x[0-9a-fA-F]+|-?\d+)", out)
        if not m:
            return 0
        s = m.group(1)
        return int(s, 16) if s.startswith("0x") else int(s)
    except Exception:
        return 0


@mcp.tool()
def register_write(session: str, regname: str, value: int) -> dict:
    """Write a register. v0.4.1.4: real (gdb `set $regname = value`)."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    try:
        _gdb_out(client, f"set ${regname} = {value}")
        verify = _gdb_out(client, f"print ${regname}")
        return {"status": "ok", "regname": regname, "value": value,
                "verify": verify.strip()[:200]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def disassemble(session: str, address: str, count: int = 16) -> list[str]:
    """Disassemble N instructions. v0.4.1.4: real (gdb `x/Ni ADDR`)."""
    if session not in _SESSIONS:
        return []
    client = _SESSIONS[session]
    try:
        out = _gdb_out(client, f"x/{count}i {address}")
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    except Exception:
        return []


@mcp.tool()
def session_detach(session: str) -> dict:
    """Detach the gdb session (target continues running). v0.4.1.4: real."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    try:
        _gdb_out(client, "detach")
        return {"status": "ok", "session": session, "detached": True}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def session_kill(session: str) -> dict:
    """Kill the gdb session + the Wine-hosted target. v0.4.1.4: real."""
    if session not in _SESSIONS:
        return {"status": "error", "error": f"unknown session: {session}"}
    client = _SESSIONS[session]
    try:
        _gdb_out(client, "kill")
        client.quit()
        del _SESSIONS[session]
        return {"status": "ok", "session": session, "killed": True}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def main() -> None:
    if mcp is None:
        raise RuntimeError("FastMCP is not installed. `uv pip install mcp`.")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
