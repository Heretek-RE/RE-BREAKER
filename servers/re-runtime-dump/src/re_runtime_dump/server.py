"""re-runtime-dump MCP server (v0.2.0 implemented).

Tiered injection tool: emulator (Speakeasy) / frida / inject (custom
C/C++ DLL/SO). For each invocation, the server:
  1. Loads the catalog + the target's triage JSON (from
     RE-AI/See the RE-AI output directory.
  2. Runs the catalog matcher (in-process) to identify the techniques
     the target uses.
  3. For each matched entry, builds a "would do X" plan per the
     offender-side recipe.
  4. Returns the plan + a per-mode backend selection.

v0.2.0 ships the planning layer end-to-end. The actual runtime execution
(launching Speakeasy, attaching Frida, injecting the DLL) is a
v0.3.0 item — for v0.2.0 the server produces a structured plan that
another agent (or a human) can execute.

This is intentional: RE-BREAKER's charter is "RE-BREAKER is a thin
orchestrator over RE-AI" — the planning layer is the value-add; the
runtime is a thin wrapper over RE-AI's existing primitives (re-speakeasy,
re-frida, re-patch) plus the C/C++ injection library.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Literal, Optional

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

from mcp.server.fastmcp import FastMCP

from re_runtime_dump import __version__

logger = logging.getLogger("re_runtime_dump")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-runtime-dump")


@mcp.tool()
def status() -> dict:
    """Return server status + relevant env-var config."""
    return {
        "server": "re-runtime-dump",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-runtime-dump v0.2.0: tiered injection planner. "
            "Loads data/catalog.json + the target's triage JSON, runs the "
            "catalog matcher, builds a per-mode execution plan (emulator / "
            "frida / inject). Runtime execution lands in v0.3.0."
        ),
        "env": {
            "RE_BREAKER_LICENSE_FILE": os.environ.get("RE_BREAKER_LICENSE_FILE", "<unset>"),
            "RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>"),
        },
    }


DumpMode = Literal["emulator", "frida", "inject"]


def _load_catalog() -> dict:
    """Load the catalog from data/catalog.json (relative to plugin root)."""
    # try a few locations
    candidates = [
        Path(__file__).resolve().parents[5] / "data" / "catalog.json",  # src/re_*/re_*/server.py → ../../../data
        Path("Path(os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")) / "data" / "catalog.json""),
    ]
    for p in candidates:
        if p.exists():
            return json.loads(p.read_text())
    raise FileNotFoundError("catalog not found")


def _parse_section_table(section_table_str: str) -> list[str]:
    sections: list[str] = []
    for chunk in section_table_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r"^(\.[A-Za-z0-9_$]+)", chunk)
        if m:
            sections.append(m.group(1))
    return sections


def _has_section_set_intersection(sections: list[str], sig_value: str) -> bool:
    m = re.search(r"\[([^\]]+)\]", sig_value)
    if not m:
        return False
    cands = [s.strip().strip("'\"") for s in m.group(1).split(",")]
    return any(c in sections for c in cands)


def _has_byte_sequence_enough(triage: dict, byte_seq_hex: str, min_count: int) -> bool:
    primitives = triage.get("anti_analysis_primitives", {}) or {}
    seq = byte_seq_hex.replace(" ", "").upper()
    name_map = {
        "0F31": "RDTSC", "0FA2": "CPUID", "0F01C1": "VMCALL",
        "F30F01C4": "VMXON", "CD2D": "INT_2D", "CC": "INT_3", "0F08": "INVD",
    }
    name = name_map.get(seq)
    if not name:
        return False
    flag = f"{name}_count_ge_200"
    if flag in primitives and primitives[flag]:
        return True
    raw = primitives.get(name)
    return isinstance(raw, int) and raw >= min_count


def _target_key_from_path(target: str) -> str:
    p = Path(target).resolve()
    name = p.name.lower()
    stem = p.stem.lower()
    candidates = {
        "007firstlight.exe": "007fl", "fm.exe": "fm26",
        "hello kitty.exe": "hkia", "lost in random.exe": "lir",
        "p3r.exe": "p3r", "crimsondesert.exe": "cd", "warhammer3.exe": "tww3",
    }
    for k, v in candidates.items():
        if k in name or k == stem:
            return v
    return p.parent.name.lower().replace(" ", "-")


def _load_triage(target: str, triage_json_path: Optional[str] = None) -> dict:
    """v0.4.0: route through the shared triage loader (RE-BREAKER self-contained)."""
    from re_breaker.triage import load_triage as _shared_load_triage
    try:
        return _shared_load_triage(target, triage_json_path=triage_json_path)
    except FileNotFoundError:
        return {}


def _match(catalog: dict, triage: dict) -> list[dict]:
    """Run the catalog matcher in-process."""
    sections = _parse_section_table(triage.get("section_table", ""))
    matches = []
    for entry in catalog["entries"]:
        sigs = entry["defender"]["detection_signatures"]
        matched = []
        confidence = 0.0
        for sig in sigs:
            stype = sig.get("type")
            sval = sig.get("value", "")
            sconf = float(sig.get("confidence", 0.5))
            if stype == "structural" and "section_set_intersects" in sval:
                if _has_section_set_intersection(sections, sval):
                    matched.append({"type": stype, "value": sval, "confidence": sconf})
                    confidence += sconf
            elif stype == "byte_sequence":
                if _has_byte_sequence_enough(triage, sval, sig.get("min_count", 1)):
                    matched.append({"type": stype, "value": sval, "confidence": sconf})
                    confidence += sconf
        if matched:
            matches.append({
                "id": entry["id"],
                "name": entry["name"],
                "family": entry["family"],
                "severity": entry["severity"],
                "confidence": round(min(1.0, confidence), 3),
                "matched_signatures": matched,
                "offender": {
                    "summary": entry["offender"]["summary"],
                    "tools": entry["offender"].get("tools", []),
                    "playbook": entry["offender"].get("playbook", ""),
                    "expected_runtime_minutes": entry["offender"].get("expected_runtime_minutes", 0),
                    "success_probability": entry["offender"].get("success_probability", 0.0),
                },
            })
    matches.sort(key=lambda m: m["confidence"], reverse=True)
    return matches


def _build_plan(matches: list[dict], target: str, mode: DumpMode, output: str) -> dict:
    """Build the per-mode execution plan."""
    plan: dict[str, Any] = {
        "target": target,
        "mode": mode,
        "output": output or "./re-dump-output/",
        "execution_status": "dry-run",  # v0.2.0: planning only
        "backend": {},
        "hooks": [],
        "expected_artifacts": [],
    }
    if mode == "emulator":
        plan["backend"] = {
            "name": "speakeasy",
            "command": (
                # v0.4.0: vendored path
                f"uv --directory $RE_BREAKER_PLUGIN_ROOT/vendored/re-ai/servers/re-speakeasy run re-speakeasy "
                f"--target {target} --output {plan['output']}"
            ),
            "estimated_runtime_seconds": sum(
                m["offender"]["expected_runtime_minutes"] for m in matches
            ) * 60,
            "captures": ["decrypted .text region", "Win32 API call trace", "encrypted-VM handler dispatch"],
        }
        plan["hooks"] = ["CreateFileW", "RegOpenKeyExW", "IsDebuggerPresent", "RDTSC (via in-tree triage)"]
    elif mode == "frida":
        plan["backend"] = {
            "name": "frida",
            "command": (
                # v0.4.0: vendored path
                f"uv --directory $RE_BREAKER_PLUGIN_ROOT/vendored/re-ai/servers/re-frida run re-frida "
                f"--target {target} --hooks 'encryption-stub,RDTSC,CPUID,CreateFileW'"
            ),
            "estimated_runtime_seconds": 600,
            "captures": ["encryption-stub input + output", "live anti-analysis primitive trace", "decrypted payload in shared memory"],
        }
        plan["hooks"] = ["encryption-stub entry (per Pattern)", "RDTSC/CPUID/INT 2D/INT 3", "VMCALL/VMXON"]
    elif mode == "inject":
        plan["backend"] = {
            "name": "custom-c-injection",
            "command": (
                f"bash inject/build.sh && uv run python inject/inject.py "
                f"--target {target} --output {plan['output']}"
            ),
            "estimated_runtime_seconds": 300,
            "captures": ["per-method decrypted body", "decrypted region written to ~/.re-breaker/dumps/<sha256>/"],
        }
        plan["hooks"] = ["inline-trampoline on encryption-stub", "IAT/GOT override on Win32 APIs", "shared-memory IPC to agent"]
    for m in matches[:3]:  # top 3
        plan["expected_artifacts"].append({
            "catalog_entry": m["id"],
            "playbook": m["offender"]["playbook"],
            "tools": m["offender"]["tools"],
            "success_probability": m["offender"]["success_probability"],
        })
    return plan


@mcp.tool()
def dump_target(target: str, mode: DumpMode = "emulator", output: str = "") -> dict:
    """Build a per-mode execution plan to dump the decrypted-VM-encrypted region.

    v0.2.0: returns a structured plan (the runtime execution lands in
    v0.3.0). The plan includes:
      - catalog match (which techniques the target uses)
      - backend selection (speakeasy / frida / custom-C-injection)
      - hooks to install
      - expected runtime + artifacts
      - per-Pattern playbook references

    Args:
        target: path to the .exe / .dll / .so
        mode: which backend to plan for (default: emulator)
        output: directory to plan to write the decrypted dump (default: ./re-dump-output/)
    """
    try:
        catalog = _load_catalog()
    except FileNotFoundError as e:
        return {"status": "error", "error": str(e), "server": "re-runtime-dump", "version": __version__}

    triage = _load_triage(target)
    if not triage:
        return {
            "status": "error",
            "error": f"no triage.json found for {target}; cannot match catalog",
            "hint": "ensure RE_AI_PLUGIN_ROOT is set and the target is in RE-BREAKER/Input/ with prior analysis under RE-AI/See the RE-AI output directory.",
            "server": "re-runtime-dump",
            "version": __version__,
            "target": target,
        }

    matches = _match(catalog, triage)
    plan = _build_plan(matches, target, mode, output)

    return {
        "status": "ok",
        "server": "re-runtime-dump",
        "version": __version__,
        "target": target,
        "mode": mode,
        "output": plan["output"],
        "execution_status": plan["execution_status"],
        "matches_count": len(matches),
        "top_matches": [{"id": m["id"], "name": m["name"], "confidence": m["confidence"]} for m in matches[:5]],
        "plan": plan,
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
