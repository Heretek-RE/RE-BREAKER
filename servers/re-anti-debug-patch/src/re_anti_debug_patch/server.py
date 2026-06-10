"""re-anti-debug-patch MCP server (v0.2.0 implemented).

Orchestrator on top of RE-AI's re-patch + re-anti-analysis primitives.
For each target, the server:
  1. Loads the catalog + the target's triage JSON.
  2. Identifies every RDTSC / CPUID / VMCALL / VMXON / INT 2D / INT 3 site
     from RE-AI's re-anti-analysis-scan output (the ge_200 flags + raw counts).
  3. Plans a per-site patch per the strategy (zero / constant / passthrough).
  4. Returns the patch plan: per-site offset, original bytes, patched bytes,
     strategy, expected runtime. The actual byte-level application
     delegates to RE-AI's re-patch (v0.2.0: planning; v0.3.0: apply).
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Literal, Optional

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path so the
# shared `re_breaker.triage` helper can be imported regardless of cwd.
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

from mcp.server.fastmcp import FastMCP

from re_anti_debug_patch import __version__

logger = logging.getLogger("re_anti_debug_patch")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-anti-debug-patch")


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-anti-debug-patch",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-anti-debug-patch v0.2.0: builds a per-site patch "
            "plan for RDTSC/CPUID/VMCALL/VMXON/INT 2D/INT 3 anti-debug "
            "primitives. Application delegates to RE-AI's re-patch + "
            "re-anti-analysis in v0.3.0."
        ),
        "env": {"RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>")},
    }


RdtscStrategy = Literal["zero", "constant", "passthrough"]
CpuidStrategy = Literal["zero", "nop", "passthrough"]
GeneralStrategy = Literal["zero", "passthrough"]


PATCH_BYTES = {
    ("RDTSC", "zero"):       ("0F 31", "90 90", "NOP NOP"),
    ("RDTSC", "constant"):   ("0F 31", "B8 00 10 00 00 90", "mov eax, 0x1000; nop"),
    ("RDTSC", "passthrough"): ("0F 31", "0F 31", "(no patch)"),
    ("CPUID", "zero"):       ("0F A2", "B8 00 00 00 00 90", "mov eax, 0; nop"),
    ("CPUID", "nop"):        ("0F A2", "90 90", "NOP NOP"),
    ("CPUID", "passthrough"): ("0F A2", "0F A2", "(no patch)"),
    ("VMCALL", "zero"):      ("0F 01 C1", "B8 00 00 00 00 90 90 90", "mov eax, 0; nop x3"),
    ("VMCALL", "passthrough"): ("0F 01 C1", "0F 01 C1", "(no patch)"),
    ("VMXON", "zero"):       ("F3 0F 01 C4", "B8 00 00 00 00 90 90 90 90 90", "mov eax, 0; nop x5"),
    ("VMXON", "passthrough"): ("F3 0F 01 C4", "F3 0F 01 C4", "(no patch)"),
    ("INT_2D", "zero"):      ("CD 2D", "90 90", "NOP NOP"),
    ("INT_2D", "passthrough"): ("CD 2D", "CD 2D", "(no patch)"),
    ("INT_3", "zero"):       ("CC", "90", "NOP"),
    ("INT_3", "passthrough"): ("CC", "CC", "(no patch)"),
}


def _load_catalog() -> dict:
    p = Path("Path(os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")) / "data" / "catalog.json"")
    if not p.exists():
        p = Path(__file__).resolve().parents[5] / "data" / "catalog.json"
    return json.loads(p.read_text())


def _target_key(target: str) -> str:
    p = Path(target).resolve()
    name = p.name.lower()
    cands = {
        "007firstlight.exe": "007fl", "fm.exe": "fm26",
        "hello kitty.exe": "hkia", "lost in random.exe": "lir",
        "p3r.exe": "p3r", "crimsondesert.exe": "cd", "warhammer3.exe": "tww3",
    }
    for k, v in cands.items():
        if k in name:
            return v
    return p.parent.name.lower().replace(" ", "-")


def _load_triage(target: str, triage_json_path: Optional[str] = None) -> dict:
    """v0.4.0: route through the shared triage loader (RE-BREAKER self-contained).

    See src/re_breaker/triage.py for the resolution order:
    1. explicit triage_json_path
    2. vendored honest-read triage
    3. in-process re_triage fallback
    4. FileNotFoundError
    """
    from re_breaker.triage import load_triage as _shared_load_triage
    try:
        return _shared_load_triage(target, triage_json_path=triage_json_path)
    except FileNotFoundError:
        return {}


def _estimate_site_count(triage: dict, primitive: str) -> int:
    pa = triage.get("anti_analysis_primitives", {}) or {}
    if pa.get(f"{primitive}_count_ge_200"):
        return 200
    raw = pa.get(primitive)
    return raw if isinstance(raw, int) else 0


def _build_plan(triage: dict, target: str, output: str, **strategies) -> dict:
    plan = {
        "target": target,
        "output": output or "./re-anti-debug-patch-output/",
        "execution_status": "dry-run",
        "patched_sites": [],
        "verify": {
            # v0.4.0: vendored RE-AI code is imported directly. The verifier
            # commands below are documentation; the actual verify path in
            # re-patch-apply uses vendored/re-ai/servers/re-speakeasy/...
            "re_speakeasy_dry_run": "uv --directory $RE_BREAKER_PLUGIN_ROOT/vendored/re-ai/servers/re-speakeasy run re-speakeasy --target <patched-binary> --check-no-sigabrt",
            "re_frida_attach": "uv --directory $RE_BREAKER_PLUGIN_ROOT/vendored/re-ai/servers/re-frida run re-frida --target <patched-binary> --verify-no-anti-debug-signal",
        },
    }
    site_estimates = {
        "RDTSC":  _estimate_site_count(triage, "RDTSC"),
        "CPUID":  _estimate_site_count(triage, "CPUID"),
        "VMCALL": _estimate_site_count(triage, "VMCALL"),
        "VMXON":  _estimate_site_count(triage, "VMXON"),
        "INT_2D": _estimate_site_count(triage, "INT_2D"),
        "INT_3":  _estimate_site_count(triage, "INT_3"),
    }
    primitive_to_strategy = {
        "RDTSC":  strategies.get("rdtsc_strategy", "zero"),
        "CPUID":  strategies.get("cpuid_strategy", "zero"),
        "VMCALL": strategies.get("vmcall_strategy", "zero"),
        "VMXON":  strategies.get("vmxon_strategy", "zero"),
        "INT_2D": strategies.get("int2d_strategy", "zero"),
        "INT_3":  strategies.get("int3_strategy", "zero"),
    }
    for primitive, n_sites in site_estimates.items():
        if n_sites == 0:
            continue
        strategy = primitive_to_strategy.get(primitive, "zero")
        key = (primitive, strategy)
        patch_info = PATCH_BYTES.get(key)
        if not patch_info:
            continue
        orig, patched, mnemonic = patch_info
        plan["patched_sites"].append({
            "primitive": primitive,
            "strategy": strategy,
            "estimated_sites": n_sites,
            "original_bytes": orig,
            "patched_bytes": patched,
            "mnemonic": mnemonic,
            "note": "v0.2.0: planning. v0.3.0: enumerate exact offsets via RE-AI re-anti-analysis + apply via RE-AI re-patch.",
        })
    return plan


@mcp.tool()
def patch_target(
    target: str,
    rdtsc_strategy: RdtscStrategy = "zero",
    cpuid_strategy: CpuidStrategy = "zero",
    vmxon_strategy: GeneralStrategy = "zero",
    vmcall_strategy: GeneralStrategy = "zero",
    int2d_strategy: GeneralStrategy = "zero",
    int3_strategy: GeneralStrategy = "zero",
    output: str = "",
) -> dict:
    """Build a per-site patch plan for the target's anti-debug primitives.

    v0.2.0: returns a structured plan. v0.3.0: applies the plan via
    RE-AI's re-patch + re-speakeasy dry-run verification.

    Strategies per primitive:
      - RDTSC:  zero (NOP) | constant (mov eax, 0x1000) | passthrough
      - CPUID:  zero (mov eax, 0) | nop (NOP) | passthrough
      - VMCALL: zero | passthrough
      - VMXON:  zero | passthrough
      - INT 2D: zero | passthrough
      - INT 3:  zero | passthrough
    """
    catalog = _load_catalog()
    triage = _load_triage(target)
    if not triage:
        return {
            "status": "error",
            "error": f"no triage.json found for {target}",
            "server": "re-anti-debug-patch",
            "version": __version__,
        }
    plan = _build_plan(
        triage, target, output,
        rdtsc_strategy=rdtsc_strategy, cpuid_strategy=cpuid_strategy,
        vmxon_strategy=vmxon_strategy, vmcall_strategy=vmcall_strategy,
        int2d_strategy=int2d_strategy, int3_strategy=int3_strategy,
    )
    # catalog match: anti-debug family
    matches = []
    prim_to_byte = {"RDTSC": "0F 31", "CPUID": "0F A2", "VMCALL": "0F 01 C1", "VMXON": "F3 0F 01 C4", "INT_2D": "CD 2D", "INT_3": "CC"}
    for entry in catalog["entries"]:
        if entry["family"] != "anti-debug":
            continue
        sigs = entry["defender"]["detection_signatures"]
        conf = 0.0
        for sig in sigs:
            if sig.get("type") == "byte_sequence":
                prim = {v: k for k, v in prim_to_byte.items()}.get(sig["value"].strip())
                if prim and _estimate_site_count(triage, prim) >= sig.get("min_count", 1):
                    conf += float(sig.get("confidence", 0.5))
        if conf > 0:
            matches.append({
                "id": entry["id"], "name": entry["name"],
                "confidence": round(min(1.0, conf), 3),
                "playbook": entry["offender"].get("playbook", ""),
                "tools": entry["offender"].get("tools", []),
            })
    matches.sort(key=lambda m: m["confidence"], reverse=True)
    return {
        "status": "ok",
        "server": "re-anti-debug-patch",
        "version": __version__,
        "target": target,
        "output": plan["output"],
        "execution_status": plan["execution_status"],
        "strategies": {
            "rdtsc": rdtsc_strategy, "cpuid": cpuid_strategy,
            "vmxon": vmxon_strategy, "vmcall": vmcall_strategy,
            "int2d": int2d_strategy, "int3": int3_strategy,
        },
        "catalog_matches": matches[:5],
        "plan": plan,
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
