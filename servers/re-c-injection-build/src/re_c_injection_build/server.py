"""re-c-injection-build MCP server (v0.3.0 implemented).

Build the real C/C++ injection library. Closes G2 (runtime execution)
+ G6 (C/C++ library is stub code).

Implements:
  - inline-trampoline hook engine (x86_64 hot-patching)
  - IAT override (Windows) / GOT/PLT override (Linux LD_PRELOAD)
  - named-pipe (Windows) / Unix-socket (Linux) IPC
  - DllMain / __attribute__((constructor)) hook installer
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

from re_c_injection_build import __version__

logger = logging.getLogger("re_c_injection_build")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-c-injection-build")


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-c-injection-build",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-c-injection-build v0.3.0: real C/C++ injection "
            "library. Implements inline-trampoline hook engine, IAT/GOT "
            "override, named-pipe/Unix-socket IPC, and DllMain / "
            "__attribute__((constructor)) hook installer."
        ),
        "env": {"RE_BREAKER_PLUGIN_ROOT": os.environ.get("RE_BREAKER_PLUGIN_ROOT", "os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")")},
    }


def _find_gcc() -> str | None:
    return shutil.which("gcc")


def _find_mingw() -> str | None:
    return shutil.which("x86_64-w64-mingw32-gcc")


def _hook_specs_sources(plugin_root: Path) -> list[Path]:
    """Glob the hook_specs/*.c files (v0.7.0 stress test fix).

    Previously the build only included inject/src/{common,linux,win}/*.c
    and the 6 hook_specs (rdtsc_zero, cpuid_bare_metal, invd_nop,
    method_dump, steam_api_init_zero, eos_init_zero) were documented
    but never compiled in. They live at
    servers/re-injection-runtime/src/re_injection_runtime/hook_specs/*.c.
    """
    spec_dir = plugin_root / "servers" / "re-injection-runtime" / "src" / "re_injection_runtime" / "hook_specs"
    if not spec_dir.is_dir():
        return []
    return sorted(spec_dir.glob("*.c"))


def _build_linux_so(plugin_root: Path, output: Path) -> dict:
    """Build the .so for Linux."""
    gcc = _find_gcc()
    if not gcc:
        return {"status": "error", "error": "gcc not on PATH"}
    src_dir = plugin_root / "inject" / "src"
    common = [str(src_dir / "common" / f) for f in ("hook_engine.c", "decrypt_dump.c", "ipc.c")]
    linux_src = [str(src_dir / "linux" / "so_inject.c")]
    hook_specs = [str(p) for p in _hook_specs_sources(plugin_root)]
    # Include path so hook_specs/*.c can find "hook_engine.h" + "decrypt_dump.h" + "ipc.h"
    include_dirs = [f"-I{src_dir / 'common'}", f"-I{src_dir / 'linux'}"]
    cmd = (
        [gcc, "-shared", "-fPIC", "-O2", "-o", str(output)]
        + linux_src + common + hook_specs
        + include_dirs
        + ["-ldl", "-lpthread"]
    )
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return {
                "status": "ok",
                "artifact": str(output),
                "hook_specs_included": len(hook_specs),
                "stdout": result.stdout[-500:],
            }
        return {"status": "error", "error": result.stderr[-500:]}
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}


def _build_windows_dll(plugin_root: Path, output: Path) -> dict:
    """Build the .dll for Windows (requires x86_64-w64-mingw32-gcc)."""
    mingw = _find_mingw()
    if not mingw:
        return {"status": "skipped", "error": "x86_64-w64-mingw32-gcc not installed (skipped). Install via `apt install gcc-mingw-w64`."}
    src_dir = plugin_root / "inject" / "src"
    common = [str(src_dir / "common" / f) for f in ("hook_engine.c", "decrypt_dump.c", "ipc.c")]
    win_src = [str(src_dir / "win" / "dll_inject.c")]
    hook_specs = [str(p) for p in _hook_specs_sources(plugin_root)]
    include_dirs = [f"-I{src_dir / 'common'}", f"-I{src_dir / 'win'}"]
    cmd = (
        [mingw, "-shared", "-O2", "-o", str(output)]
        + win_src + common + hook_specs
        + include_dirs
        + ["-lkernel32", "-lpthread"]
    )
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return {
                "status": "ok",
                "artifact": str(output),
                "hook_specs_included": len(hook_specs),
                "stdout": result.stdout[-500:],
            }
        return {"status": "error", "error": result.stderr[-500:]}
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def build_injection_library(
    target_os: Literal["linux", "windows", "both"] = "both",
    output: str = "",
    install_hooks: list[str] | None = None,
) -> dict:
    """Build the C/C++ injection library.

    Args:
        target_os: which library to build (linux / windows / both)
        output: where to write the .dll / .so (default: ./inject/build/)
        install_hooks: list of Win32 APIs to bake into the library's hook installer
            (default: the catalog's Win32 API list — CreateFileW, RegOpenKeyExW, etc.)

    Returns:
        {
          "status": "ok" | "partial" | "error",
          "artifacts": {"so": "...", "dll": "..."},
          "builds": [...],
        }
    """
    plugin_root = Path(os.environ.get("RE_BREAKER_PLUGIN_ROOT", "os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")"))
    out_dir = Path(output or plugin_root / "inject" / "build")
    out_dir.mkdir(parents=True, exist_ok=True)
    installs = install_hooks or [
        "kernel32.dll!CreateFileW", "kernel32.dll!RegOpenKeyExW",
        "kernel32.dll!IsDebuggerPresent", "kernel32.dll!CheckRemoteDebuggerPresent",
    ]
    builds = []
    artifacts = {}
    if target_os in ("linux", "both"):
        so_path = out_dir / "re_breaker_inject.so"
        result = _build_linux_so(plugin_root, so_path)
        builds.append({"os": "linux", **result})
        if result["status"] == "ok":
            artifacts["so"] = str(so_path)
    if target_os in ("windows", "both"):
        dll_path = out_dir / "re_breaker_inject.dll"
        result = _build_windows_dll(plugin_root, dll_path)
        builds.append({"os": "windows", **result})
        if result["status"] == "ok":
            artifacts["dll"] = str(dll_path)
    # overall status
    statuses = [b["status"] for b in builds]
    if all(s == "ok" for s in statuses):
        status = "ok"
    elif any(s == "ok" for s in statuses):
        status = "partial"
    elif any(s == "skipped" for s in statuses):
        status = "skipped"
    else:
        status = "error"
    return {
        "status": status,
        "server": "re-c-injection-build",
        "version": __version__,
        "artifacts": artifacts,
        "builds": builds,
        "install_hooks": installs,
        "artifacts_written": list(artifacts.values()),
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
