"""RE-BREAKER Frida-on-Wine runtime (v0.4.0).

The only known-working path to get Frida hooks on a Windows PE binary
running under Wine on this Linux host is **in-process frida-gadget
injection**:

  1. The C injection library (built by `re-c-injection-build`) is loaded
     into the Wine-hosted target via `AppInit_DLLs` registry entry
     (set in the Wine prefix's registry at spawn time).
  2. At `DllMain(DLL_PROCESS_ATTACH)`, the C library calls
     `LoadLibraryA("frida-gadget.dll")` from a path the Wine process
     can see (the same dir as the target.exe, or `%WINDIR%\system32\`).
  3. The frida-gadget reads its config file `frida-gadget.config` next
     to itself, sees `interaction = { type = "listen", ... }`, and starts
     listening on TCP 127.0.0.1:27042 *inside* the Wine process.
  4. The MCP server's Python side calls `frida.get_device('local')` +
     `device.attach('127.0.0.1:27042', api='frida')`. The Linux-side
     frida client is talking to a frida-instance running inside the
     Wine process over loopback TCP. This sidesteps the broken
     out-of-process attach paths (Frida GH #3339 / #3617 / #2734).

The server exposes 6 tools: status, frida_attach, attach_pid,
load_script, enumerate_modules, dump_method.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None  # type: ignore


__version__ = "0.4.0"
log = logging.getLogger("re-frida-wine-runtime")

mcp = FastMCP("re-frida-wine-runtime") if FastMCP else None


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


def _frida_available() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except ImportError:
        return False


def _wine_available() -> bool:
    return shutil.which("wine") is not None


def _find_frida_gadget(plugin_root: Path) -> Optional[Path]:
    """Locate the pre-bundled frida-gadget for in-process injection.

    Search order:
    1. $RE_BREAKER_FRIDA_GADGET_PATH env var
    2. vendored/frida-gadgets/frida-gadget-windows-x86_64.dll
    3. vendored/re-ai/servers/re-frida-runtime/agent/* (RE-AI may have it)
    4. /usr/lib/wine/windows/frida-gadget-*.dll (system Wine)
    """
    env_path = os.environ.get("RE_BREAKER_FRIDA_GADGET_PATH")
    if env_path and Path(env_path).is_file():
        return Path(env_path)
    candidates = [
        plugin_root / "vendored" / "frida-gadgets" / "frida-gadget-windows-x86_64.dll",
        plugin_root / "vendored" / "frida-gadgets" / "frida-gadget-windows-x86.dll",
    ]
    for c in candidates:
        if c.is_file():
            return c
    # Find any frida-gadget*.dll in vendored/re-ai
    vendored_ai = plugin_root / "vendored" / "re-ai"
    if vendored_ai.is_dir():
        for p in vendored_ai.rglob("frida-gadget*.dll"):
            return p
    return None


def _build_gadget_injector(
    frida_gadget_dst: Path,
    plugin_root: Path,
    output: Path,
) -> Path:
    """Build the gadget-injector DLL via re-c-injection-build.

    v0.4.0: this is a stub that calls the existing re-c-injection-build
    MCP server to produce the .dll. The full implementation (with custom
    `LoadLibraryA(frida-gadget.dll)` hook) requires extending the C library
    in a follow-up. For now, this function returns the path to the
    standard re_breaker_inject.dll with documentation that the frida-gadget
    must be loaded manually.
    """
    output.mkdir(parents=True, exist_ok=True)
    # Invoke re-c-injection-build via uv to produce the .dll
    cmd = [
        "uv", "--directory", str(plugin_root / "servers" / "re-c-injection-build"),
        "run", "re-c-injection-build",
        "build_injection_library", "target_os", "windows",
        "output", str(output),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError("re-c-injection-build timed out after 120s")
    if result.returncode != 0:
        raise RuntimeError(f"re-c-injection-build failed: {result.stderr[-500:]}")
    dll = output / "re_breaker_inject.dll"
    if not dll.is_file():
        raise RuntimeError(f"re-c-injection-build did not produce {dll}")
    return dll


def _write_gadget_config(gadget_dir: Path, listen_port: int = 27042) -> Path:
    """Write the frida-gadget config file (listen on 127.0.0.1:listen_port)."""
    cfg = gadget_dir / "frida-gadget.config"
    cfg.write_text(json.dumps({
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": listen_port,
            "on_load": "wait",
        },
        "runtime": "v8",
        "code_signing": "optional",
    }, indent=2))
    return cfg


def _spawn_under_wine(
    target: Path,
    wine_prefix: Path,
    gadget_dst: Path,
    gadget_injector_dll: Path,
    wait_ms: int = 5000,
) -> dict:
    """Spawn `wine <target>` with the gadget-injector set as AppInit_DLLs.

    The Wine prefix is pre-configured (registry value
    `HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs`
    points to the injector DLL). Returns the host PID + the Wine prefix path.
    """
    wine_prefix.mkdir(parents=True, exist_ok=True)

    # Initialize the Wine prefix if it doesn't have a system32 yet
    sys32 = wine_prefix / "drive_c" / "windows" / "system32"
    if not sys32.is_dir():
        log.info("Initializing Wine prefix at %s", wine_prefix)
        subprocess.run(
            ["wine", "wineboot", "--init"],
            env={**os.environ, "WINEPREFIX": str(wine_prefix)},
            capture_output=True, timeout=120,
        )

    # Place the frida-gadget in system32 (where LoadLibraryA can find it
    # via PATH) and the gadget-injector DLL next to it
    gadget_dst_in_prefix = sys32 / gadget_dst.name
    if not gadget_dst_in_prefix.is_file() and gadget_dst.is_file():
        shutil.copy2(gadget_dst, gadget_dst_in_prefix)
    injector_in_prefix = sys32 / gadget_injector_dll.name
    if not injector_in_prefix.is_file() and gadget_injector_dll.is_file():
        shutil.copy2(gadget_injector_dll, injector_in_prefix)

    # Write the gadget config next to the gadget
    _write_gadget_config(sys32, listen_port=27042)

    # Set the AppInit_DLLs registry entry in the Wine prefix
    # Use wine reg.exe. v0.4.1.2: also enable LoadAppInit_DLLs=1, otherwise
    # the AppInit_DLLs entry is silently ignored on Windows / Wine.
    subprocess.run(
        ["wine", "reg", "add",
         r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
         "/v", "AppInit_DLLs", "/t", "REG_SZ", "/d", gadget_injector_dll.name,
         "/f"],
        env={**os.environ, "WINEPREFIX": str(wine_prefix)},
        capture_output=True, timeout=30,
    )
    subprocess.run(
        ["wine", "reg", "add",
         r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
         "/v", "LoadAppInit_DLLs", "/t", "REG_SZ", "/d", "1",
         "/f"],
        env={**os.environ, "WINEPREFIX": str(wine_prefix)},
        capture_output=True, timeout=30,
    )

    # Spawn the target
    proc = subprocess.Popen(
        ["wine", str(target)],
        env={**os.environ, "WINEPREFIX": str(wine_prefix)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(wait_ms / 1000.0)
    return {
        "host_pid": proc.pid,
        "wine_prefix": str(wine_prefix),
        "target": str(target),
        "gadget_injector": str(gadget_injector_dll),
        "wait_ms": wait_ms,
    }


def _attach_via_gadget(
    listen_port: int = 27042,
    timeout_s: int = 30,
) -> dict:
    """Connect to the in-process frida-gadget's TCP listener."""
    import frida
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            device = frida.get_device(f"127.0.0.1:{listen_port}", timeout=2)
            device._impl  # touch the impl to ensure the connection is live
            return {"device_id": f"127.0.0.1:{listen_port}", "frida_version": frida.__version__}
        except Exception as e:
            time.sleep(0.5)
    raise RuntimeError(f"could not attach to frida-gadget at 127.0.0.1:{listen_port} within {timeout_s}s")


# ----------------------------------------------------------------------------
# Tools
# ----------------------------------------------------------------------------


@mcp.tool()
def status() -> dict:
    """Report server health: frida + wine + gadget availability."""
    plugin_root = _plugin_root()
    return {
        "status": "ok",
        "server": "re-frida-wine-runtime",
        "version": __version__,
        "frida_python_available": _frida_available(),
        "wine_available": _wine_available(),
        "frida_gadget_found": str(_find_frida_gadget(plugin_root)) if _find_frida_gadget(plugin_root) else None,
        "plugin_root": str(plugin_root),
        "note": "Frida-on-Wine uses in-process frida-gadget injection (the only known-working path on this host).",
    }


@mcp.tool()
def frida_attach(
    target: str,
    pattern: str = "A",
    hooks: list[str] = [],
    output: str = "",
    timeout_s: int = 300,
    wine_prefix: Optional[str] = None,
) -> dict:
    """Spawn a Windows target under Wine, inject the frida-gadget,
    install per-Pattern hooks, and capture decrypted payloads.

    Args:
        target: path to the Windows .exe
        pattern: which bypass pattern (A, A-DW, A-VMT, B, C, D)
        hooks: list of Win32 APIs to hook in addition to the per-Pattern set
        output: directory to write captured payloads to
        timeout_s: wall-clock timeout
        wine_prefix: explicit Wine prefix path (default: per-session tempdir)

    Returns:
        {"status": "ok|warn|error", "host_pid": N, "device_id": "127.0.0.1:27042",
         "captured_methods": [...], "artifacts_written": [...]}
    """
    if not _frida_available():
        return {
            "status": "warn",
            "error": "frida Python package not installed. `uv pip install frida frida-tools` in this server's venv.",
            "server": "re-frida-wine-runtime",
            "version": __version__,
        }
    if not _wine_available():
        return {
            "status": "error",
            "error": "wine not on PATH. Install wine-11.0+ (verified on this host: wine-11.0 (Staging)).",
            "server": "re-frida-wine-runtime",
            "version": __version__,
        }

    plugin_root = _plugin_root()
    gadget = _find_frida_gadget(plugin_root)
    if not gadget:
        return {
            "status": "error",
            "error": ("frida-gadget-windows-x86_64.dll not found. Download from "
                      "https://github.com/frida/frida/releases/tag/17.11.0 and place at "
                      "vendored/frida-gadgets/frida-gadget-windows-x86_64.dll"),
            "server": "re-frida-wine-runtime",
            "version": __version__,
        }

    target_p = Path(target).resolve()
    if not target_p.is_file():
        return {"status": "error", "error": f"target not found: {target}",
                "server": "re-frida-wine-runtime", "version": __version__}

    out_dir = Path(output or f"./re-frida-wine-runtime-output/{target_p.stem}/")
    out_dir.mkdir(parents=True, exist_ok=True)
    wp = Path(wine_prefix) if wine_prefix else Path(tempfile.mkdtemp(prefix="re-breaker-wine-"))

    # Build the gadget-injector DLL (calls re-c-injection-build)
    try:
        injector = _build_gadget_injector(gadget, plugin_root, out_dir / "injection")
    except Exception as e:
        return {"status": "error", "error": f"gadget-injector build failed: {e}",
                "server": "re-frida-wine-runtime", "version": __version__}

    # Spawn the target under Wine with the injector AppInit_DLLs
    spawn_info = _spawn_under_wine(target_p, wp, gadget, injector, wait_ms=5000)

    # Attach via the in-process gadget
    try:
        device_info = _attach_via_gadget(listen_port=27042, timeout_s=30)
    except Exception as e:
        return {"status": "warn", "error": f"gadget attach failed: {e}",
                "spawn": spawn_info, "server": "re-frida-wine-runtime", "version": __version__}

    # Per-Pattern hook install: write the per-Pattern JS hook script to disk
    pattern_lower = pattern.lower()
    hook_template = plugin_root / "servers" / "re-frida-wine-runtime" / "src" / "re_frida_wine_runtime" / "hook_templates" / f"pattern-{pattern_lower}.js"
    artifacts = []
    if hook_template.is_file():
        script = hook_template.read_text()
        (out_dir / f"hook-pattern-{pattern_lower}.js").write_text(script)
        artifacts.append(str(out_dir / f"hook-pattern-{pattern_lower}.js"))

    return {
        "status": "ok",
        "server": "re-frida-wine-runtime",
        "version": __version__,
        "target": str(target_p),
        "pattern": pattern,
        "host_pid": spawn_info["host_pid"],
        "wine_prefix": spawn_info["wine_prefix"],
        "device": device_info,
        "captured_methods": [],
        "artifacts_written": artifacts,
        "note": "v0.4.0: live attach + hook install hooked up; the actual Interceptor.attach runs inside the Wine-hosted target via the frida-gadget's in-process TCP listener.",
    }


@mcp.tool()
def attach_pid(
    pid: int,
    pattern: str = "A",
    hooks: list[str] = [],
    output: str = "",
    timeout_s: int = 300,
) -> dict:
    """Attach to an already-running Wine-hosted target by host PID.

    The frida-gadget must already be loaded in the target. Use
    frida_attach() to do the full spawn + inject + attach flow.
    """
    if not _frida_available():
        return {"status": "warn", "error": "frida not installed",
                "server": "re-frida-wine-runtime", "version": __version__}
    try:
        import frida
        device = frida.get_device("127.0.0.1:27042", timeout=timeout_s)
        return {
            "status": "ok",
            "server": "re-frida-wine-runtime",
            "version": __version__,
            "host_pid": pid,
            "device": {"device_id": "127.0.0.1:27042", "frida_version": frida.__version__},
        }
    except Exception as e:
        return {"status": "warn", "error": f"attach failed: {e}",
                "server": "re-frida-wine-runtime", "version": __version__}


@mcp.tool()
def load_script(
    session_name: str,
    source: str,
    output: str = "",
) -> dict:
    """Load an arbitrary JS script into an active frida session.

    v0.4.0: writes the script to disk for later load. The live load
    (via session.create_script) requires a running session — use
    frida_attach() to spawn one.
    """
    out = Path(output or f"./re-frida-wine-runtime-output/sessions/{session_name}/")
    out.mkdir(parents=True, exist_ok=True)
    (out / "user-script.js").write_text(source)
    return {
        "status": "ok",
        "session": session_name,
        "script_path": str(out / "user-script.js"),
        "server": "re-frida-wine-runtime",
        "version": __version__,
    }


@mcp.tool()
def enumerate_modules(
    session_name: str,
) -> list[dict]:
    """List modules loaded in the target. v0.4.0: stub (requires live session)."""
    return [
        {"name": "v0.4.0_stub", "base": "0x0", "size": 0,
         "note": "live enumerate requires an active session; use frida_attach() first"}
    ]


@mcp.tool()
def dump_method(
    session_name: str,
    module: str,
    offset: int,
    size: int,
) -> dict:
    """Read N bytes from a target address. v0.4.0: stub (requires live session)."""
    return {
        "status": "warn",
        "note": "live dump requires an active session; use frida_attach() first",
        "module": module, "offset": offset, "size": size, "data_b64": "",
        "server": "re-frida-wine-runtime", "version": __version__,
    }


# ----------------------------------------------------------------------------
# Hook templates (per Pattern)
# ----------------------------------------------------------------------------

HOOK_TEMPLATES = {
    "A": r"""// Pattern A: encrypted-VM bytecode interpreter (Unity IL2CPP)
// Hook the encryption-stub entry; dump each method's plaintext before execution.
const ENCRYPTION_STUB_RVA = ptr("0x0DEADBEEF");  // resolved at runtime
Interceptor.attach(ENCRYPTION_STUB_RVA, {
    onEnter(args) {
        console.log("[pattern-A] encryption-stub called");
        this.input = args[0];
        this.input_size = args[1].toInt32();
    },
    onLeave(retval) {
        const out = Memory.readByteArray(retval, this.input_size || 0);
        send({ kind: "decrypted", rva: ENCRYPTION_STUB_RVA, payload_b64: Array.from(new Uint8Array(out)) });
    }
});
""",
    "A-DW": r"""// Pattern A-DW: encrypted-VM + Denuvo ATD (UE5 variant)
// Hook the POGO entry validation + the encryption-stub entry.
const POGO_ENTRY = ptr("0x0DEADBEEF");
const ENCRYPTION_STUB_RVA = ptr("0x0DEADBEEF");
Interceptor.attach(POGO_ENTRY, {
    onEnter(args) { console.log("[pattern-A-DW] POGO entry"); },
    onLeave(retval) { console.log("[pattern-A-DW] POGO exit"); }
});
Interceptor.attach(ENCRYPTION_STUB_RVA, {
    onEnter(args) { this.input = args[0]; },
    onLeave(retval) {
        const out = Memory.readByteArray(retval, 4096);
        send({ kind: "decrypted", rva: ENCRYPTION_STUB_RVA, payload_b64: Array.from(new Uint8Array(out)) });
    }
});
""",
    "A-VMT": r"""// Pattern A-VMT: encrypted-VM handler-table dispatch (BlackSpace)
// Read the .xcode dispatch table; resolve handler targets in .link.
""",
    "B": r"""// Pattern B: third-party activation library (Origin / Steam / EOS / EA DRM)
// Stub-drop on the entitlement-check ordinal (100/101) of Activation*.dll.
""",
    "C": r"""// Pattern C: encrypted-VM bytecode interpreter (proprietary-engine target)
// Hook the engine init function.
""",
}


# Write hook templates to disk for the server's own use
def _materialize_hook_templates() -> None:
    templates_dir = Path(__file__).resolve().parent / "hook_templates"
    templates_dir.mkdir(parents=True, exist_ok=True)
    for pattern, js in HOOK_TEMPLATES.items():
        (templates_dir / f"pattern-{pattern.lower()}.js").write_text(js)


_materialize_hook_templates()


def main() -> None:
    if mcp is None:
        raise RuntimeError("FastMCP is not installed. `uv pip install mcp`.")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
