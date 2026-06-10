"""RE-BREAKER C-injection runtime (v0.4.0).

Wraps the `re-c-injection-build` C library (inline trampolines, IAT/GOT
override, named-pipe / Unix-domain-socket IPC) for runtime hooking without
Frida. Useful when:
  - Frida-on-Wine is unavailable (no frida-gadget, no Wine)
  - JS-hook overhead is too high for tight loops
  - The hook spec is simple enough to express in C

The C library's IPC channel is consumed by `ipc.py` (named-pipe on
Windows, Unix-domain-socket on Linux).

Tools: status, build_injection, inject, attach_pid.
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

# v0.4.1.3: import the IPC consumer (sibling module)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ipc_consumer import (  # noqa: E402
    consume as ipc_consume,
    is_target_alive,
    events_log_path,
    pipe_path_for_pid,
)

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None


__version__ = "0.4.0"
log = logging.getLogger("re-injection-runtime")

mcp = FastMCP("re-injection-runtime") if FastMCP else None


# v0.8.0+ Wave 1 (Item B): site-list plumbing imports
from load_target_sites import (  # noqa: E402
    emit_sites_for_target,
    sites_file_for_pid,
    drain_sites_file,
)


# ----------------------------------------------------------------------------
# Hook specs (per C source)
# ----------------------------------------------------------------------------

HOOK_SPECS = {
    "rdtsc_zero": r"""// rdtsc_zero.c — override RDTSC to return 0
#include "hook_engine.h"
void re_breaker_rdtsc_zero(void) {
    // patch the RDTSC opcode (0F 31) at every site enumerated by the catalog
    extern void re_breaker_patch_opcode(uint8_t *addr, const uint8_t *original, size_t original_len, const uint8_t *patched, size_t patched_len);
    uint8_t orig[2] = {0x0F, 0x31};
    uint8_t patched[2] = {0x90, 0x90};
    re_breaker_patch_opcode_at_sites(orig, 2, patched, 2);
}
""",
    "cpuid_bare_metal": r"""// cpuid_bare_metal.c — return bare-metal snapshot for CPUID leaf 1 ECX bit 31
#include "hook_engine.h"
void re_breaker_cpuid_spoof(void) {
    extern void re_breaker_register_cpuid_hook(void *handler);
    re_breaker_register_cpuid_hook(re_breaker_cpuid_spoof_handler);
}
static void re_breaker_cpuid_spoof_handler(void *ctx) {
    // zero bit 31 of ECX (hypervisor present)
    ((uint32_t *)ctx)[2] &= ~(1u << 31);
}
""",
    "invd_nop": r"""// invd_nop.c — replace INVD with NOP NOP
#include "hook_engine.h"
void re_breaker_invd_nop(void) {
    uint8_t orig[2] = {0x0F, 0x08};
    uint8_t patched[2] = {0x90, 0x90};
    re_breaker_patch_opcode_at_sites(orig, 2, patched, 2);
}
""",
    "method_dump": r"""// method_dump.c — at the encryption-stub entry, capture (input, output) and send to IPC
#include "hook_engine.h"
#include "decrypt_dump.h"
void re_breaker_method_dump(void) {
    extern void re_breaker_register_encryption_stub_hook(void *handler);
    re_breaker_register_encryption_stub_hook(re_breaker_method_dump_handler);
}
static void re_breaker_method_dump_handler(void *input, size_t in_size, void *output) {
    re_breaker_write_decrypted_region("method", (const uint8_t *)output, in_size);
    re_breaker_write_event("method.dump", "ok");
}
""",
    # v0.4.0 NEW: entitlement-layer hook specs.
    "steam_api_init_zero": r"""// steam_api_init_zero.c — hook SteamAPI_Init to return k_ESteamAPIInitResult_OK
// Defeats the Steamworks CEG entitlement check at the launcher's import boundary.
// Per SOW-X §J.3: Steamworks CEG bypass research is in scope.
#include "hook_engine.h"

// k_ESteamAPIInitResult_OK = 0
typedef unsigned int ESteamAPIInitResult;

static ESteamAPIInitResult re_breaker_steamapi_init_replacement(void) {
    return 0u;  // k_ESteamAPIInitResult_OK
}

void re_breaker_steam_api_init_zero(void) {
    re_breaker_install_hook("steam_api64", "SteamAPI_Init",
                            (void *)re_breaker_steamapi_init_replacement);
}
""",
    "eos_init_zero": r"""// eos_init_zero.c — hook EOS_Initialize to return EOS_Success
// Defeats the EOS handshake entitlement check at the launcher's import boundary.
// Per SOW-X §K.2 + SOW-X §Q.1: EOS handshake bypass is in scope; EOS AC is NOT in scope.
#include "hook_engine.h"

// EOS_Success = 0
typedef int EOS_EResult;

static EOS_EResult re_breaker_eos_initialize_replacement(void) {
    return 0;  // EOS_Success
}

void re_breaker_eos_init_zero(void) {
    re_breaker_install_hook("EOSSDK-Win64-Shipping", "EOS_Initialize",
                            (void *)re_breaker_eos_initialize_replacement);
}
""",
    # v0.8.0+ Wave 1 (Item B): per-site opcode patch hook specs.
    # These iterate the per-target site list (populated by load_target_sites.py
    # via the ~/.re-breaker/sites-{pid}.jsonl file polled on the heartbeat tick).
    "int3_nop": r"""// int3_nop.c — NOP every INT 3 (0xCC) in the per-target site list.
// Site list is populated by load_target_sites.py + hook_engine.c
// re_breaker_drain_sites_file() at runtime.
// INT 3 is a 1-byte opcode (0xCC); site RVAs point to a single byte.
#include "hook_engine.h"
void re_breaker_int3_nop(void) {
    uint8_t orig[1] = {0xCC};
    uint8_t patched[1] = {0x90};
    re_breaker_patch_opcode_at_sites(orig, 1, patched, 1);
}
""",
    "invd_nop_at_sites": r"""// invd_nop_at_sites.c — NOP every INVD (0x0F 0x08) in the per-target site list.
// Distinct from invd_nop.c which is a no-op (the per-target site list for
// INVD is populated by the per-target triage; without that list, there are
// no sites to patch).
#include "hook_engine.h"
void re_breaker_invd_nop_at_sites(void) {
    uint8_t orig[2] = {0x0F, 0x08};
    uint8_t patched[2] = {0x90, 0x90};
    re_breaker_patch_opcode_at_sites(orig, 2, patched, 2);
}
""",
    "cpuid_zero_at_sites": r"""// cpuid_zero_at_sites.c — NOP every CPUID (0x0F 0xA2) in the per-target site list.
// Per-target CPUID sites are typically rare (FM26 has 5); most CPUID detection
// happens in user-mode code that's not enumerated by the static analyzer.
// Defeats the enumerated subset.
#include "hook_engine.h"
void re_breaker_cpuid_zero_at_sites(void) {
    uint8_t orig[2] = {0x0F, 0xA2};
    uint8_t patched[2] = {0x90, 0x90};
    re_breaker_patch_opcode_at_sites(orig, 2, patched, 2);
}
""",
}


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


def _gcc_available(target_os: str) -> bool:
    if target_os in ("linux", "both"):
        if shutil.which("gcc"):
            return True
    if target_os in ("windows", "both"):
        if shutil.which("x86_64-w64-mingw32-gcc"):
            return True
    return False


def _build_injection_lib(
    hook_specs: list[str],
    target_os: str,
    plugin_root: Path,
    output: Path,
) -> dict:
    """Build the C injection library with the requested hook specs baked in.

    v0.4.1.3: import the c-injection-build module directly instead of
    shelling out via uv. The MCP server's `main()` only runs stdio —
    it doesn't parse sys.argv. Direct import is faster, more reliable,
    and lets us surface detailed build errors.
    """
    # import the build module from the sibling server
    cib_path = plugin_root / "servers" / "re-c-injection-build" / "src"
    sys.path.insert(0, str(cib_path))
    try:
        from re_c_injection_build.server import build_injection_library  # type: ignore
    except Exception as e:
        raise RuntimeError(
            f"could not import re_c_injection_build (from {cib_path}): {e}. "
            "Make sure the c-injection-build server's venv is initialized."
        )
    installs = hook_specs or None
    if installs and "," in installs[0]:
        installs = [s.strip() for s in installs[0].split(",")]
    try:
        result = build_injection_library(
            target_os=target_os,
            output=str(output),
            install_hooks=installs,
        )
    except Exception as e:
        raise RuntimeError(f"re_c_injection_build.build_injection_library failed: {e}")
    if result.get("status") not in ("ok", "partial"):
        raise RuntimeError(f"build failed: {result.get('error') or result}")
    artifacts = result.get("artifacts") or {}
    return {"artifacts": artifacts, "stdout": json.dumps(result)[:400]}


def _spawn_with_injection(
    target: Path,
    injector_dll: Optional[Path],
    wine_prefix: Optional[Path],
    wait_ms: int,
) -> dict:
    """Spawn a target with the injection library preloaded.

    v0.4.0: Linux uses LD_PRELOAD on the .so; Windows uses AppInit_DLLs via
    the Wine registry. Native (non-Wine) Windows is not yet supported
    (would require CreateRemoteThread + WriteProcessMemory).
    """
    target_p = Path(target).resolve()
    if not target_p.is_file():
        raise FileNotFoundError(f"target not found: {target}")
    env = os.environ.copy()
    if injector_dll and injector_dll.suffix == ".so":
        env["LD_PRELOAD"] = str(injector_dll)
    if wine_prefix:
        env["WINEPREFIX"] = str(wine_prefix)
    cmd = [str(target_p)] if not wine_prefix else ["wine", str(target_p)]
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(wait_ms / 1000.0)
    return {"host_pid": proc.pid, "command": cmd, "ld_preload": env.get("LD_PRELOAD", "")}


# ----------------------------------------------------------------------------
# Tools
# ----------------------------------------------------------------------------


@mcp.tool()
def status() -> dict:
    """Report server health + C compiler availability."""
    plugin_root = _plugin_root()
    return {
        "status": "ok",
        "server": "re-injection-runtime",
        "version": __version__,
        "gcc_linux": _gcc_available("linux"),
        "gcc_windows_mingw": _gcc_available("windows"),
        "plugin_root": str(plugin_root),
        "hook_specs_available": list(HOOK_SPECS.keys()),
        "note": "C-injection runtime — uses re-c-injection-build's library + per-hook C sources.",
    }


@mcp.tool()
def build_injection(
    hook_specs: list[str] = [],
    target_os: str = "linux",
    output: str = "",
) -> dict:
    """Build the C injection library with the requested hook specs baked in.

    Args:
        hook_specs: list of hook names (rdtsc_zero, cpuid_bare_metal, invd_nop, method_dump)
        target_os: linux | windows | both
        output: directory to write the .so/.dll artifacts

    Returns: {"artifacts": {"so": ..., "dll": ...}, "stdout": "..."}
    """
    plugin_root = _plugin_root()
    out_dir = Path(output or f"./re-injection-runtime-output/build/")
    out_dir.mkdir(parents=True, exist_ok=True)
    # Validate hook_specs
    valid = [s for s in (hook_specs or []) if s in HOOK_SPECS]
    invalid = [s for s in (hook_specs or []) if s not in HOOK_SPECS]
    if invalid:
        return {"status": "warn", "error": f"unknown hook_specs: {invalid}",
                "valid_hook_specs": list(HOOK_SPECS.keys()),
                "server": "re-injection-runtime", "version": __version__}
    try:
        result = _build_injection_lib(valid, target_os, plugin_root, out_dir)
    except Exception as e:
        return {"status": "error", "error": str(e),
                "server": "re-injection-runtime", "version": __version__}
    return {
        "status": "ok",
        "server": "re-injection-runtime",
        "version": __version__,
        "target_os": target_os,
        "hook_specs": valid,
        **result,
    }


@mcp.tool()
def inject(
    target: str,
    hook_specs: list[str] = [],
    wine_prefix: Optional[str] = None,
    output: str = "",
    timeout_s: int = 300,
    consume_s: float = 10.0,
    max_events: int = 100,
) -> dict:
    """Build + spawn + inject + consume IPC events. Linux uses LD_PRELOAD; Wine uses AppInit_DLLs.

    Returns: {"status": "ok", "host_pid": N, "artifacts": {...}, "captured": [...]}

    v0.4.1.3: the consumer (ipc_consumer.py) now reads events from the
    spawned target's named-pipe (Windows) or Unix-socket (Linux) for
    `consume_s` seconds, up to `max_events` events. Heartbeats arrive
    every 5s; method-dump events arrive on demand.
    """
    plugin_root = _plugin_root()
    out_dir = Path(output or f"./re-injection-runtime-output/inject/{Path(target).stem}/")
    out_dir.mkdir(parents=True, exist_ok=True)
    target_p = Path(target).resolve()
    target_os = "windows" if wine_prefix else "linux"
    try:
        build_result = _build_injection_lib(hook_specs or [], target_os, plugin_root, out_dir / "injection")
    except Exception as e:
        return {"status": "error", "error": f"build failed: {e}",
                "server": "re-injection-runtime", "version": __version__}
    artifacts = build_result["artifacts"]
    dll = Path(artifacts["dll"]) if target_os == "windows" else None
    so = Path(artifacts["so"]) if "so" in artifacts else None
    injector = dll if wine_prefix else so
    if not injector or not injector.is_file():
        return {"status": "error", "error": f"no injector artifact for {target_os}",
                "server": "re-injection-runtime", "version": __version__}
    try:
        spawn_info = _spawn_with_injection(target_p, injector, Path(wine_prefix) if wine_prefix else None, wait_ms=3000)
    except Exception as e:
        return {"status": "error", "error": f"spawn failed: {e}",
                "server": "re-injection-runtime", "version": __version__}
    host_pid = spawn_info["host_pid"]
    # v0.4.1.3: consume IPC events from the spawned target
    captured: list[dict] = []
    consumer_error: str = ""
    if consume_s > 0:
        try:
            captured = ipc_consume(host_pid, duration_s=consume_s, max_events=max_events)
        except Exception as e:
            consumer_error = f"{type(e).__name__}: {e}"
    # also read the batched events.log if it exists
    log_tail: list[dict] = []
    log_path = events_log_path()
    if log_path.is_file():
        try:
            lines = log_path.read_text().splitlines()[-50:]
            for ln in lines:
                try:
                    log_tail.append(json.loads(ln))
                except json.JSONDecodeError:
                    pass
        except OSError:
            pass
    return {
        "status": "ok",
        "server": "re-injection-runtime",
        "version": __version__,
        "target": str(target_p),
        "host_pid": host_pid,
        "artifacts": artifacts,
        "captured": captured,
        "captured_count": len(captured),
        "events_log_tail": log_tail,
        "events_log_path": str(log_path),
        "consumer_error": consumer_error,
        "ipc_endpoint": pipe_path_for_pid(host_pid),
        "consume_s": consume_s,
        "note": ("v0.4.1.3: build + spawn + inject + IPC consume hooked up. "
                 "C side sends JSON-line events on a per-PID named-pipe (Windows) "
                 "or Unix-socket (Linux); the Python consumer reconnects per message "
                 "because the C side does accept() per send()."),
    }


@mcp.tool()
def attach_pid(
    pid: int,
    hook_specs: list[str] = [],
    output: str = "",
    timeout_s: int = 300,
    consume_s: float = 10.0,
    max_events: int = 100,
) -> dict:
    """Attach to an already-running target by host PID.

    v0.4.1.3: the IPC consumer (ipc_consumer.py) now connects to the
    target's named-pipe/Unix-socket (created by the injection library's
    DllMain/re_breaker_ipc_init) and streams events for `consume_s` seconds.

    v0.4.0 caveat: the target must already have the injection library
    loaded (otherwise no IPC channel exists). True ptrace-attach +
    WriteProcessMemory library-injection is a v0.4.1+ follow-up — for now
    the target must be pre-injected (e.g. by re-injection-runtime.inject
    or by AppInit_DLLs on Wine).
    """
    if not is_target_alive(pid):
        return {
            "status": "error",
            "error": f"pid {pid} not found",
            "server": "re-injection-runtime",
            "version": __version__,
        }
    # check if the IPC channel exists
    ipc_path = pipe_path_for_pid(pid)
    ipc_exists = os.path.exists(ipc_path)
    if not ipc_exists and sys.platform == "win32":
        # Windows: try opening the named pipe
        try:
            import msvcrt  # type: ignore
            ipc_exists = True  # the connect call below will tell us
        except ImportError:
            ipc_exists = False
    captured: list[dict] = []
    consumer_error: str = ""
    if consume_s > 0 and ipc_exists:
        try:
            captured = ipc_consume(pid, duration_s=consume_s, max_events=max_events)
        except Exception as e:
            consumer_error = f"{type(e).__name__}: {e}"
    elif not ipc_exists:
        consumer_error = (
            f"no IPC channel for pid {pid} at {ipc_path}. "
            "The injection library must be loaded into the target first "
            "(via inject() or AppInit_DLLs on Wine)."
        )
    return {
        "status": "ok" if not consumer_error else "warn",
        "server": "re-injection-runtime",
        "version": __version__,
        "host_pid": pid,
        "ipc_endpoint": ipc_path,
        "ipc_present": ipc_exists,
        "captured": captured,
        "captured_count": len(captured),
        "consumer_error": consumer_error,
        "consume_s": consume_s,
        "note": ("v0.4.1.3: attach_pid consumes events from an already-injected "
                 "target's IPC channel. True ptrace-attach + in-process library "
                 "injection is a follow-up. Heartbeats arrive every 5s."),
    }


@mcp.tool()
def consume_ipc(
    pid: int,
    duration_s: float = 10.0,
    max_events: int = 100,
) -> dict:
    """Standalone IPC consumer — read events from `pid`'s channel.

    v0.4.1.3: connects to the named-pipe/Unix-socket, reconnects per
    message (C-side accept-per-send model), returns parsed JSON events.
    """
    if not is_target_alive(pid):
        return {
            "status": "error",
            "error": f"pid {pid} not found",
            "server": "re-injection-runtime",
            "version": __version__,
        }
    try:
        events = ipc_consume(pid, duration_s=duration_s, max_events=max_events)
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "server": "re-injection-runtime",
            "version": __version__,
        }
    return {
        "status": "ok",
        "server": "re-injection-runtime",
        "version": __version__,
        "host_pid": pid,
        "ipc_endpoint": pipe_path_for_pid(pid),
        "events": events,
        "event_count": len(events),
        "duration_s": duration_s,
    }


# ----------------------------------------------------------------------------
# v0.8.0+ Wave 1 (Item B): site-list plumbing tools
# ----------------------------------------------------------------------------


@mcp.tool()
def load_target_sites(
    target: str,
    pid: int,
    *,
    binary_base: Optional[int] = None,
    primitives: Optional[list[str]] = None,
    triage_json_path: Optional[str] = None,
    clear_first: bool = True,
) -> dict:
    """v0.8.0+ Wave 1 (Item B): read the triage JSON's per_site_rvas and emit
    a sidecar file that the C-side injection library polls to populate its site list.

    The file lives at `$HOME/.re-breaker/sites-{pid}.jsonl`. The C side
    (`re_breaker_drain_sites_file()` in hook_engine.c) drains it on its
    5s heartbeat tick.

    Args:
        target: path to the target binary (used to locate the triage + the
                binary's load address via /proc/<pid>/maps on Linux).
        pid: the host PID where the C-side injection library is loaded.
        binary_base: explicit in-memory load address of the target. If
                     None, reads /proc/<pid>/maps for the first r-xp
                     mapping matching `target`'s basename. Required on
                     Windows (no /proc equivalent).
        primitives: list of `per_site_rvas` keys to emit. Default: every
                     primitive that has ≥ 1 site in the triage.
        triage_json_path: explicit path to a triage.json (overrides lookup).
        clear_first: emit a `clear_sites` op before the new sites (default True).
                     Set False to append (e.g. when accumulating sites
                     across multiple targets in the same process — rare).

    Returns: dict with sites_written, per_primitive_count, sites_file, etc.
    """
    return emit_sites_for_target(
        target=target,
        pid=pid,
        binary_base=binary_base,
        primitives=primitives,
        triage_json_path=triage_json_path,
        clear_first=clear_first,
    )


@mcp.tool()
def sites_file_path(pid: int) -> dict:
    """Return the path to the sites file for `pid`. Diagnostic only."""
    return {
        "server": "re-injection-runtime",
        "version": __version__,
        "pid": pid,
        "sites_file": str(sites_file_for_pid(pid)),
        "note": "The C-side worker thread polls this file on its 5s heartbeat.",
    }


@mcp.tool()
def drain_sites_file(pid: int) -> dict:
    """Standalone drain — read + parse + delete the sites file. Diagnostic only.

    The C side calls this on its heartbeat; this tool exists for the
    case where a developer wants to peek at what's queued without
    waiting for the next heartbeat.
    """
    if not is_target_alive(pid):
        return {
            "status": "error",
            "error": f"pid {pid} not found",
            "server": "re-injection-runtime",
            "version": __version__,
        }
    ops = drain_sites_file(pid)
    return {
        "status": "ok",
        "server": "re-injection-runtime",
        "version": __version__,
        "pid": pid,
        "ops_drained": ops,
        "sites_file": str(sites_file_for_pid(pid)),
        "note": "v0.8.0+ drain: read + delete the sites file. Returns 0 ops if no file.",
    }


# ----------------------------------------------------------------------------
# Hook spec materialization
# ----------------------------------------------------------------------------

def _materialize_hook_specs() -> None:
    specs_dir = Path(__file__).resolve().parent / "hook_specs"
    specs_dir.mkdir(parents=True, exist_ok=True)
    for name, source in HOOK_SPECS.items():
        (specs_dir / f"{name}.c").write_text(source)


_materialize_hook_specs()


def main() -> None:
    if mcp is None:
        raise RuntimeError("FastMCP is not installed. `uv pip install mcp`.")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
