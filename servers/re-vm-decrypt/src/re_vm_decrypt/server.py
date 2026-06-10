"""re-vm-decrypt MCP server (v0.2.0 implemented).

Lift the decrypted method bodies from a running encrypted-VM bytecode
interpreter.

Patterns:
  - Pattern A / A-DW: hook the encryption-stub entry (the lazy-decrypt
    routine that fires on first execution of an encrypted method).
  - Pattern A-VMT: hook the .xcode handler dispatch. Reconstruct the
    handler table from .xcode (dispatch) / .link (jump targets) /
    .arch (handler bodies).

v0.2.0: returns a plan. v0.3.0: runtime execution.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Literal, Optional

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

from mcp.server.fastmcp import FastMCP

from re_vm_decrypt import __version__

logger = logging.getLogger("re_vm_decrypt")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-vm-decrypt")


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-vm-decrypt",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-vm-decrypt v0.2.0: builds a per-Pattern plan "
            "to lift the encrypted-VM-encrypted method bodies."
        ),
        "env": {"RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>")},
    }


DumpMode = Literal["emulator", "frida", "inject"]
Pattern = Literal["A", "A-DW", "A-VMT", "B", "C", "D"]


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
    """v0.4.0: route through the shared triage loader (RE-BREAKER self-contained)."""
    from re_breaker.triage import load_triage as _shared_load_triage
    try:
        return _shared_load_triage(target, triage_json_path=triage_json_path)
    except FileNotFoundError:
        return {}


def _build_plan(target, triage, pattern, mode, handler_id, output):
    sections = []
    for chunk in triage.get("section_table", "").split(","):
        m = re.match(r"^(\.[A-Za-z0-9_$]+)", chunk.strip())
        if m:
            sections.append(m.group(1))
    if pattern == "A-VMT":
        expected_sections = [".xcode", ".link", ".arch"]
    else:
        expected_sections = [".xtls", ".xpdata", ".xdata", ".arch", ".link", ".sbss", ".xcode"]
    matched_sections = [s for s in sections if s in expected_sections]
    plan = {
        "target": target,
        "pattern": pattern,
        "mode": mode,
        "handler_id": handler_id,
        "output": output or "./re-vm-decrypt-output/",
        "execution_status": "dry-run",
        "expected_sections": expected_sections,
        "matched_sections": matched_sections,
        "section_coverage": f"{len(matched_sections)}/{len(expected_sections)}",
        "encryption_stub": {
            "expected_offsets": "via RE-AI re-lief + re-anti-analysis: the first RVA in the .xtls section is the lazy-decrypt stub entry",
            "v0.3.0_hook": f"{'frida attach' if mode == 'frida' else 'CreateRemoteThread + DLL inject' if mode == 'inject' else 'speakeasy hook on the stub RVA'}",
        },
    }
    if pattern == "A-VMT":
        plan["handler_table_reconstruction"] = {
            "dispatch_section": ".xcode",
            "jump_targets_section": ".link",
            "handler_bodies_section": ".arch",
            "handler_id_filter": handler_id,
            "reconstruction_steps": [
                "1. dump .xcode dispatch table (each entry is a 16-byte handler_id → handler_offset pair)",
                "2. resolve handler_offset in .link (each entry is a jump to a .arch body)",
                "3. dump .arch body (runtime-decrypted form, one per handler_id)",
                "4. write per-handler binary: output/handler-<id>-<rva>.bin",
            ],
        }
    else:
        plan["method_extraction"] = {
            "encryption_stub_entry": "first RVA in .xtls (or first .xtext RVA for Pattern A-DW)",
            "extraction_steps": [
                "1. hook the encryption-stub entry",
                "2. on each call: capture input (encrypted bytes) + output (decrypted method body)",
                "3. write per-method binary: output/method-<rva>-<sha256>.bin",
            ],
        }
    return plan


@mcp.tool()
def decrypt_target(
    target: str,
    mode: DumpMode = "emulator",
    pattern: Pattern = "A",
    handler_id: int | None = None,
    output: str = "",
    timeout_s: int = 300,
) -> dict:
    """Build a per-Pattern plan to lift the encrypted-VM-encrypted method bodies."""
    catalog = _load_catalog()
    triage = _load_triage(target)
    if not triage:
        return {"status": "error", "error": f"no triage.json found for {target}",
                "server": "re-vm-decrypt", "version": __version__}
    plan = _build_plan(target, triage, pattern, mode, handler_id, output)
    matches = []
    for entry in catalog["entries"]:
        if entry["family"] != "encrypted-vm-bytecode-interpreter":
            continue
        sigs = entry["defender"]["detection_signatures"]
        conf = 0.0
        for sig in sigs:
            if sig.get("type") == "structural" and "section_set_intersects" in sig.get("value", ""):
                m = re.search(r"\[([^\]]+)\]", sig["value"])
                if m:
                    cands = [c.strip().strip("'\"") for c in m.group(1).split(",")]
                    if any(c in plan["matched_sections"] for c in cands):
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
        "server": "re-vm-decrypt",
        "version": __version__,
        "target": target,
        "mode": mode,
        "pattern": pattern,
        "catalog_matches": matches[:5],
        "plan": plan,
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
