"""RE-BREAKER shared triage loader (v0.4.0).

Replaces the near-identical `_load_triage` functions that were scattered
across 7 servers (`re-catalog-match`, `re-anti-debug-patch`, `re-vm-decrypt`,
`re-anti-vm-spoof`, `re-runtime-dump`, `re-patch-apply`, `re-il2cpp-triage`).
All of them used to look in `$RE_AI_PLUGIN_ROOT/See the RE-AI output directory.`
which required RE-AI as a sibling. This loader works without RE-AI.

Order of resolution (first match wins):
1. `triage_json_path=` argument passed by the caller.
2. The vendored pre-baked honest-read triage at
   `vendored/re-ai/output/2026-06-07-honest-read/per-binary/<key>/triage.json`.
2.5. The orchestrator-generated triage at
   `re-triage-output/orchestrator/<key>-triage.json`.
2.6. The re-triage server's own output at
   `servers/re-triage/re-triage-output/<key>-triage.json`.
3. The 2-arg form `load_triage(target, output=...)` which calls the
   in-process re-triage server (`re_triage.triage_target`) to produce a
   fresh triage on demand. Shape: native-PE (flat anti_analysis_primitives).
4. Raise a clear error.

The function is deliberately shape-tolerant: it returns the triage dict
as-is. Callers that need to read the IL2CPP-style nested shape
(`{launcher_*, GameAssembly_dll}.{RDTSC, ...}`) should use
`re_breaker.triage.flatten_primitives(triage)` from this same module.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional


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
    if env:
        p = Path(env)
        if p.is_dir():
            return p
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "servers").is_dir() and (parent / "vendored").is_dir():
            return parent
    cwd = Path.cwd()
    if (cwd / "servers").is_dir() and (cwd / "vendored").is_dir():
        return cwd
    raise RuntimeError(
        "RE-BREAKER plugin root not found: cannot locate a directory containing "
        "both 'servers/' and 'vendored/'. Set $RE_BREAKER_PLUGIN_ROOT or run "
        "from the RE-BREAKER root."
    )


def _target_key(target: str) -> str:
    """Normalize a target path to a key matching the vendored triage dir.

    Examples:
        "/home/.../Input/007 First Light/Retail/007FirstLight.exe" -> "007fl"
        "/home/.../Input/Football Manager 26/fm.exe"                 -> "fm26"
        "/home/.../Input/il2cpp_target/.../P3R.exe"                  -> "p3r"
        "/home/.../Input/il2cpp_sample/Lost In Random.exe"            -> "lir"
    """
    name = Path(target).name.lower()
    # Strip extensions and common suffixes
    name = re.sub(r"\.(exe|dll)$", "", name)
    # CamelCase -> hyphen-separated, take first 3-4 chars
    # "007FirstLight" -> "007-first-light" -> "007fl" (after keymap)
    keymap = {
        "007firstlight": "007fl",
        "p3r": "p3r",
        "crimsondesert": "cd",
        "warhammer3": "tww3",
        "fm": "fm26",  # Football Manager's launcher
        "lostinrandom": "lir",
        "hello kitty": "hkia",  # uncommon but defensive
        "f1_25": "f1_25",  # v0.5.0: F1 25 Iconic Edition (InsaneRamZes)
        "bge": "bge",  # v0.6.0: Beyond Good and Evil 20th Anniversary Edition
        "borderlands4": "borderlands4",  # v0.6.0: Borderlands 4
        "thelostcrown": "thelostcrown",  # v0.6.0: Prince of Persia The Lost Crown
    }
    if name in keymap:
        return keymap[name]
    # Fallback: take first 3 chars of stripped name
    return re.sub(r"[^a-z0-9]", "", name)[:6]


def _target_key_from_dll(target: str) -> str:
    """For IL2CPP-style triage lookups, normalize the .dll's path too.

    Examples:
        "Input/Football Manager 26/GameAssembly.dll" -> "fm26"
        "Input/il2cpp_target/.../P3R/Binaries/Win64/P3R.exe" -> "p3r"
    """
    name = Path(target).name.lower()
    name = re.sub(r"\.(exe|dll)$", "", name)
    if name == "gameassembly":
        # The .dll is in a parent dir named after the target. Walk up.
        # .../Input/Football Manager 26/GameAssembly.dll -> parent dir = Football Manager 26
        parent_name = Path(target).parent.name.lower()
        keymap = {
            "football manager 26": "fm26",
            "hello kitty island adventure": "hkia",
            "il2cpp_sample": "lir",
            "il2cpp_target": "p3r",  # could also be tww3; check path
        }
        if parent_name in keymap:
            return keymap[parent_name]
    return _target_key(target)


def load_triage(
    target: str,
    triage_json_path: Optional[str] = None,
    *,
    output: Optional[str] = None,
    call_in_process_triage: bool = True,
) -> dict:
    """Load a triage JSON for the given target.

    Args:
        target: path to the binary
        triage_json_path: explicit path to a triage.json (overrides everything)
        output: if `call_in_process_triage=True` and no vendored triage found,
                the fresh triage is written here. The function then reads it back.
        call_in_process_triage: if True (default), fall back to calling
                re_triage.triage_target() in-process when no vendored triage is found.

    Returns:
        The triage dict. Empty `{}` if nothing found and in-process triage is disabled.

    Raises:
        FileNotFoundError: if no triage can be located and call_in_process_triage is False.
    """
    # 1. explicit override
    if triage_json_path:
        p = Path(triage_json_path)
        if not p.exists():
            raise FileNotFoundError(f"triage_json_path does not exist: {p}")
        return _read_json(p)

    plugin_root = _plugin_root()
    key = _target_key(target)
    key_dll = _target_key_from_dll(target)

    # 2. vendored pre-baked honest-read triage (preferred default)
    vendored_glob_keys = [key, key_dll, _target_key(Path(target).stem)]
    for k in vendored_glob_keys:
        if not k:
            continue
        vendored_path = (
            plugin_root
            / "vendored"
            / "re-ai"
            / "output"
            / "2026-06-07-honest-read"
            / "per-binary"
            / k
            / "triage.json"
        )
        if vendored_path.exists():
            return _read_json(vendored_path)

    # 2.5 orchestrator-generated triage (most common for fresh targets)
    # The orchestrator writes triage.json to re-triage-output/orchestrator/<key>-triage.json.
    for k in [key, key_dll]:
        if not k:
            continue
        orchestrator_triage = (
            plugin_root
            / "re-triage-output"
            / "orchestrator"
            / f"{k}-triage.json"
        )
        if orchestrator_triage.exists():
            return _read_json(orchestrator_triage)

    # 2.6 re-triage server's own output directory
    # The re-triage MCP server writes triage.json to
    # servers/re-triage/re-triage-output/<key>-triage.json.
    for k in [key, key_dll]:
        if not k:
            continue
        server_triage = (
            plugin_root
            / "servers"
            / "re-triage"
            / "re-triage-output"
            / f"{k}-triage.json"
        )
        if server_triage.exists():
            return _read_json(server_triage)

    # 3. in-process fresh triage (soft fallback)
    if call_in_process_triage:
        try:
            # Lazy import: re_triage is an MCP server, not a normal Python module.
            # We use a subprocess call to its CLI driver instead.
            import json
            import subprocess
            out_dir = output or f"./re-triage-output/loader/{key}/"
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            # `uv` is the per-server venv driver. Spawn re-triage via uv.
            result = subprocess.run(
                [
                    "uv",
                    "--directory", str(plugin_root / "servers" / "re-triage"),
                    "run", "re-triage",
                    "triage_target", target,
                    "--output", out_dir,
                ],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                # Parse the JSON the server emitted
                # The server returns a status:ok response with triage_json_path
                # inside the response text. Find the path and read it.
                m = re.search(r'"triage_json_path"\s*:\s*"([^"]+)"', result.stdout)
                if m:
                    return _read_json(Path(m.group(1)))
                # Fallback: look for the most recent triage in out_dir
                triage_files = sorted(Path(out_dir).glob("*-triage.json"), key=lambda p: p.stat().st_mtime, reverse=True)
                if triage_files:
                    return _read_json(triage_files[0])
        except Exception as e:
            # Soft fallback failure: don't raise here, just continue
            pass

    # 4. nothing found
    raise FileNotFoundError(
        f"No triage.json found for target='{target}' (key={key!r}, key_dll={key_dll!r}). "
        f"Checked: explicit triage_json_path, vendored honest-read triage at "
        f"vendored/re-ai/output/2026-06-07-honest-read/per-binary/<key>/triage.json, "
        f"orchestrator triage at re-triage-output/orchestrator/<key>-triage.json, "
        f"re-triage server output at servers/re-triage/re-triage-output/<key>-triage.json, "
        f"in-process re_triage. Either provide triage_json_path explicitly, "
        f"place a triage.json in the vendored tree, or install frida/re-triage "
        f"dependencies and pass call_in_process_triage=True (default)."
    )


def flatten_primitives(primitives: dict) -> dict:
    """v0.4.0: flatten nested {launcher_*, GameAssembly_dll}.{primitive} shape.

    Native PE triage: {"anti_analysis_primitives": {"RDTSC": 1966, ...}}
    IL2CPP triage:    {"anti_analysis_primitives": {"launcher_fm_exe": {"RDTSC": 0, ...},
                                                    "GameAssembly_dll": {"RDTSC": 61, ...}}}

    Returns a flat dict with max-of-primitive for numerics, OR-of-primitive
    for booleans, first-of for strings. Idempotent on already-flat input.
    """
    if not primitives or not any(isinstance(v, dict) for v in primitives.values()):
        return primitives
    flat: dict = {}
    for k, v in primitives.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if isinstance(v2, bool):
                    flat[k2] = flat.get(k2, False) or v2
                elif isinstance(v2, (int, float)):
                    cur = flat.get(k2, 0)
                    flat[k2] = v2 if isinstance(cur, bool) else max(cur, v2)
                elif isinstance(v2, str):
                    if k2 not in flat or not flat[k2]:
                        flat[k2] = v2
        elif isinstance(v, (int, float, bool, str)):
            flat[k] = v
    return flat


def _read_json(path: Path) -> dict:
    import json
    with open(path, "r") as f:
        return json.load(f)


__all__ = ["load_triage", "flatten_primitives", "_target_key"]
