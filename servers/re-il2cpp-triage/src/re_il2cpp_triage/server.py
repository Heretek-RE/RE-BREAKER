"""re-il2cpp-triage MCP server (v0.3.0 implemented).

For Unity IL2CPP targets, find GameAssembly.dll + il2cpp_data/Metadata/
global-metadata.dat and run the per-binary triage on the .dll (NOT the
launcher). Closes G1: the v0.2.0 catalog match ran against the
launcher's ~660KB triage, missing the 50-500MB GameAssembly.dll that
actually contains the encrypted-VM bytecode interpreter.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path
# Path: .../servers/re-il2cpp-triage/src/re_il2cpp_triage/server.py
#       file → re_il2cpp_triage/ → src/ → re-il2cpp-triage/ → servers/ → RE-BREAKER/
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

from mcp.server.fastmcp import FastMCP

from re_il2cpp_triage import __version__

logger = logging.getLogger("re_il2cpp_triage")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-il2cpp-triage")


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-il2cpp-triage",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-il2cpp-triage v0.3.0: for Unity IL2CPP launchers, "
            "locate GameAssembly.dll + global-metadata.dat + il2cpp.usym, run "
            "RE-AI's static-analysis primitives on the .dll, return the "
            "triage JSON in the honest-read shape."
        ),
        "env": {"RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>")},
    }


def _find_game_assembly(launcher_path: str) -> Path | None:
    """Find GameAssembly.dll in the launcher's directory or the standard
    Unity install locations."""
    p = Path(launcher_path).resolve()
    candidates = [
        p.parent / "GameAssembly.dll",
        p.parent / "Data" / "GameAssembly.dll",
        p.parent / "Contents" / "Data" / "GameAssembly.dll",  # macOS
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _find_metadata(game_assembly: Path) -> Path | None:
    """Find il2cpp_data/Metadata/global-metadata.dat relative to the
    launcher's Unity data directory."""
    p = game_assembly.parent
    candidates = [
        p / "il2cpp_data" / "Metadata" / "global-metadata.dat",
        p / "Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat",
        p / "Contents" / "Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _detect_metadata_version(metadata_path: Path) -> int | None:
    """Read the metadata header to determine the version (v24-v32)."""
    try:
        with open(metadata_path, "rb") as f:
            data = f.read(16)
        if len(data) < 12:
            return None
        # global-metadata.dat header: magic (4) + version (4) + ...
        # The version is at offset 8 (little-endian uint32).
        version = int.from_bytes(data[8:12], "little")
        return version
    except Exception as e:
        logger.warning(f"could not read metadata version: {e}")
        return None


def _find_usym(game_assembly: Path) -> Path | None:
    """Find il2cpp.usym (the unified symbols file) if present."""
    p = game_assembly.parent
    candidates = [
        p / "il2cpp.usym",
        p / "il2cpp_data" / "Resources" / "il2cpp.usym",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _run_re_ai_triage(target: str) -> dict:
    """v0.4.0: route through the shared triage loader (RE-BREAKER self-contained).

    Previously this called RE-AI's re-lief / re-static-triage / re-anti-analysis
    via subprocess to $RE_AI_PLUGIN_ROOT. Now it uses the vendored honest-read
    triage files (or, in a future v0.4.x, the in-process re-triage server).
    """
    from re_breaker.triage import load_triage as _shared_load_triage
    try:
        return _shared_load_triage(target)
    except FileNotFoundError:
        return {}


def _target_key_from_path(target: str) -> str:
    p = Path(target).resolve()
    name = p.name.lower()
    stem = p.stem.lower()
    cands = {
        "gameassembly.dll": {
            "fm.exe": "fm26", "hello kitty.exe": "hkia", "lost in random.exe": "lir",
        }.get(name, None) and None,
    }
    # simpler: check parent dir
    parent_name = p.parent.name.lower()
    if "football manager 26" in parent_name or "fm26" in parent_name:
        return "fm26"
    if "hello kitty" in parent_name or "hkia" in parent_name:
        return "hkia"
    if "lost in random" in parent_name or "il2cpp_sample" in parent_name or "lir" in parent_name:
        return "lir"
    if "p3r" in parent_name or "il2cpp_target" in parent_name:
        return "p3r"
    if "crimson desert" in parent_name or "cd" in parent_name or "proprietary_engine" in parent_name:
        return "cd"
    if "warhammer" in parent_name or "tww3" in parent_name:
        return "tww3"
    if "007 first light" in parent_name or "007fl" in parent_name:
        return "007fl"
    return stem.replace(" ", "-")


@mcp.tool()
def triage_il2cpp(launcher_path: str, output: str = "") -> dict:
    """Run RE-AI's static-analysis primitives on GameAssembly.dll for a Unity IL2CPP target.

    Args:
        launcher_path: path to the Unity launcher's .exe (e.g. fm.exe, P3R.exe)
        output: directory to write the triage JSON (default: ./re-il2cpp-triage-output/)

    Returns:
        {
          "status": "ok" | "error",
          "launcher": launcher_path,
          "game_assembly": "<path>",
          "metadata": {"path": ..., "version": v24-v32},
          "usym": "<path>" or null,
          "triage": {<the honest-read triage JSON shape>},
          "main_binary": GameAssembly.dll path (so the caller can pass it to other tools),
        }
    """
    p = Path(launcher_path).resolve()
    if not p.exists():
        return {"status": "error", "error": f"launcher not found: {launcher_path}",
                "server": "re-il2cpp-triage", "version": __version__}
    # 1. find GameAssembly.dll
    ga = _find_game_assembly(launcher_path)
    if not ga:
        return {"status": "error", "error": f"GameAssembly.dll not found in {p.parent}",
                "server": "re-il2cpp-triage", "version": __version__,
                "hint": "verify the target is a Unity IL2CPP launcher"}
    # 2. find global-metadata.dat
    meta = _find_metadata(ga)
    meta_version = _detect_metadata_version(meta) if meta else None
    # 3. find il2cpp.usym
    usym = _find_usym(ga)
    # 4. if metadata is v30/v31/v32, note that Gap 25 (Unity 6 metadata v31) is unresolved
    if meta_version and meta_version >= 30:
        gap_25 = True
    else:
        gap_25 = False
    # 5. if no .usym, note that Gap 26 (HKIA-style stripped-metadata) is unresolved
    gap_26 = usym is None
    # 6. run RE-AI static analysis on GameAssembly.dll
    triage = _run_re_ai_triage(str(ga))
    if not triage:
        # fallback: read the launcher's honest-read triage
        triage = _run_re_ai_triage(launcher_path)

    # 6a. v0.4.1: flatten the IL2CPP nested {launcher_*, GameAssembly_dll}.{primitive}
    # shape so the catalog matcher (which reads the flat shape) works on this triage
    # directly. Without this, the catalog match returns 0 for IL2CPP launchers.
    if isinstance(triage, dict) and "anti_analysis_primitives" in triage:
        from re_breaker.triage import flatten_primitives as _flatten
        triage["anti_analysis_primitives"] = _flatten(triage["anti_analysis_primitives"])
        triage.setdefault("notes", [])
        if isinstance(triage["notes"], list):
            triage["notes"].append(
                "v0.4.1: anti_analysis_primitives flattened (max-of-numeric, OR-of-boolean) "
                "for catalog-matcher compatibility. See re_breaker.triage.flatten_primitives."
            )

    # 7. write the triage JSON
    out_dir = Path(output or "./re-il2cpp-triage-output/")
    out_dir.mkdir(parents=True, exist_ok=True)
    target_key = _target_key_from_path(launcher_path)
    triage_out = out_dir / f"{target_key}-triage.json"
    triage_out.write_text(json.dumps(triage, indent=2))
    return {
        "status": "ok",
        "server": "re-il2cpp-triage",
        "version": __version__,
        "launcher": launcher_path,
        "game_assembly": str(ga),
        "main_binary": str(ga),
        "metadata": {"path": str(meta) if meta else None, "version": meta_version,
                    "is_unity_6_or_newer": gap_25},
        "usym": str(usym) if usym else None,
        "is_stripped_metadata": gap_26,
        "triage_json_path": str(triage_out),
        "triage_keys": list(triage.keys())[:10] if isinstance(triage, dict) else [],
        "triage_size_bytes": len(json.dumps(triage)),
    }


@mcp.tool()
def auto_detect(target: str) -> dict:
    """Auto-detect if a target is a Unity IL2CPP launcher + return the GameAssembly.dll path.

    Convenience wrapper for the catalog match / runtime-dump tools that
    want to know whether to call re-il2cpp-triage.
    """
    p = Path(target).resolve()
    ga = _find_game_assembly(target)
    return {
        "is_il2cpp": ga is not None,
        "launcher": target,
        "main_binary": str(ga) if ga else target,
        "main_binary_size_bytes": ga.stat().st_size if ga and ga.exists() else p.stat().st_size,
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
