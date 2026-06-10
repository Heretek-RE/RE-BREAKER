"""re-encrypted-vm-bypass MCP server (v0.2.0 implemented).

Per-Pattern orchestrator. Combines the per-Pattern recipes:
  - Pattern A: trigger the lazy-decrypt stub, dump each method's plaintext.
  - Pattern A-DW: bypass the POGO entry validation, then trigger the stub.
  - Pattern A-VMT: dump the .xcode dispatch table, resolve the handler
    targets in .link, dump the handler bodies in .arch.
  - Pattern B: third-party activation library — fingerprint the activator,
    identify the ordinals, stub-drop the entitlement check.
  - Pattern C: proprietary engine encrypted-VM — per-family recipe.
  - Pattern D: publisher telemetry attack surface — hook telemetry senders.

v0.2.0: returns a plan. v0.3.0: runtime execution.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

from re_encrypted_vm_bypass import __version__

logger = logging.getLogger("re_encrypted_vm_bypass")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-encrypted-vm-bypass")


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-encrypted-vm-bypass",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-encrypted-vm-bypass v0.2.0: per-Pattern "
            "orchestrator. Returns a multi-step plan."
        ),
        "env": {
            "RE_BREAKER_PATTERNS_PATH": os.environ.get("RE_BREAKER_PATTERNS_PATH", "<unset>"),
            "RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>"),
        },
    }


Pattern = Literal["A", "A-DW", "A-VMT", "B", "C", "D"]
Mode = Literal["emulator", "frida", "inject"]


RECIPES = {
    "A": [
        {"step": 1, "tool": "re-anti-debug-patch",
         "args": {"rdtsc_strategy": "zero", "cpuid_strategy": "zero"},
         "purpose": "neutralize the 50+ RDTSC / 50+ CPUID anti-debug primitives so the lazy-decrypt stub doesn't SIGABRT"},
        {"step": 2, "tool": "re-vm-decrypt",
         "args": {"pattern": "A", "mode": "emulator"},
         "purpose": "hook the encryption-stub entry, dump each method's plaintext to output/"},
    ],
    "A-DW": [
        {"step": 1, "tool": "re-anti-debug-patch",
         "args": {"rdtsc_strategy": "zero", "cpuid_strategy": "zero", "vmcall_strategy": "zero"},
         "purpose": "neutralize the 200+ RDTSC / 200+ CPUID / 36 VMCALL anti-debug primitives"},
        {"step": 2, "tool": "re-anti-vm-spoof",
         "args": {"cpuid_strategy": "bare-metal-snapshot", "vmdetect_strategy": "zero"},
         "purpose": "defeat the Denuvo ATD's CPUID hypervisor leaf + VMCALL probes"},
        {"step": 3, "tool": "re-vm-decrypt",
         "args": {"pattern": "A-DW", "mode": "frida"},
         "purpose": "hook the POGO entry + the encryption-stub entry, dump each method's plaintext"},
    ],
    "A-VMT": [
        {"step": 1, "tool": "re-vm-decrypt",
         "args": {"pattern": "A-VMT", "mode": "frida", "handler_id": None},
         "purpose": "hook the .xcode handler dispatch, capture each handler body's runtime-decrypted form"},
    ],
    "B": [
        {"step": 1, "tool": "re-runtime-dump", "args": {"mode": "inject"},
         "purpose": "inject the C/C++ DLL into a copy of the target (never the live one) and hook the activation DLL's ordinal 100/101"},
        {"step": 2, "tool": "re-anti-debug-patch", "args": {"rdtsc_strategy": "passthrough"},
         "purpose": "leave RDTSC passthrough, but patch any debug-validation routines the activator calls"},
    ],
    "C": [
        {"step": 1, "tool": "re-anti-debug-patch",
         "args": {"rdtsc_strategy": "zero", "cpuid_strategy": "zero"},
         "purpose": "neutralize the proprietary engine's anti-debug primitives (typically 200+ RDTSC + 200+ CPUID)"},
        {"step": 2, "tool": "re-anti-vm-spoof", "args": {"cpuid_strategy": "bare-metal-snapshot"},
         "purpose": "defeat the proprietary engine's anti-VM detection (typically SMBIOS/ACPI/registry entropy probes)"},
        {"step": 3, "tool": "re-vm-decrypt", "args": {"pattern": "C", "mode": "frida"},
         "purpose": "hook the proprietary engine's encryption-stub entry, dump each method's plaintext"},
    ],
    "D": [
        {"step": 1, "tool": "re-runtime-dump", "args": {"mode": "frida"},
         "purpose": "attach Frida to the target process and install telemetry hooks (sentry_capture_event, hermes_publish, rd_kafka_produce, EOS_Reporting_SetCallback)"},
        {"step": 2, "tool": "re-anti-vm-spoof",
         "args": {"cpuid_strategy": "bare-metal-snapshot", "vmdetect_strategy": "zero"},
         "purpose": "concurrent spoof for kernel-active targets that pair telemetry with anti-VM"},
    ],
}


def _load_catalog() -> dict:
    p = Path("Path(os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")) / "data" / "catalog.json"")
    if not p.exists():
        p = Path(__file__).resolve().parents[5] / "data" / "catalog.json"
    return json.loads(p.read_text())


def _load_pattern_yaml(pattern: str) -> dict | None:
    patterns_dir = Path(os.environ.get(
        "RE_BREAKER_PATTERNS_PATH",
        "Path(os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")) / "data" / "patterns"",
    ))
    p = patterns_dir / f"pattern-{pattern.lower()}.yml"
    if not p.exists():
        return None
    try:
        import yaml
        return yaml.safe_load(p.read_text())
    except ImportError:
        return None


@mcp.tool()
def bypass_pattern(
    target: str,
    pattern: Pattern,
    mode: Mode = "emulator",
    rdtsc_strategy: str = "zero",
    cpuid_strategy: str = "bare-metal-snapshot",
    output: str = "",
    timeout_s: int = 600,
) -> dict:
    """Build a per-Pattern orchestrator plan for the target.

    v0.2.0: returns a multi-step plan. v0.3.0: runtime execution.
    """
    catalog = _load_catalog()
    recipe = RECIPES.get(pattern, [])
    out_dir = output or "./re-encrypted-vm-bypass-output/"
    for step in recipe:
        if step["tool"] == "re-anti-debug-patch":
            step["args"]["rdtsc_strategy"] = rdtsc_strategy
        if step["tool"] == "re-anti-vm-spoof":
            step["args"]["cpuid_strategy"] = cpuid_strategy
        if step["tool"] in ("re-vm-decrypt", "re-runtime-dump"):
            step["args"]["mode"] = mode
        step["output"] = f"{out_dir.rstrip('/')}/step-{step['step']}-{step['tool']}/"
    pattern_yaml = _load_pattern_yaml(pattern)
    target_id = f"encrypted-vm.bytecode-interpreter.pattern-{pattern.lower()}"
    matches = []
    for entry in catalog["entries"]:
        if entry["id"] == target_id:
            matches.append({
                "id": entry["id"], "name": entry["name"],
                "severity": entry["severity"],
                "playbook": entry["offender"].get("playbook", ""),
                "tools": entry["offender"].get("tools", []),
                "expected_runtime_minutes": entry["offender"].get("expected_runtime_minutes", 0),
                "success_probability": entry["offender"].get("success_probability", 0.0),
            })
        elif entry["family"] == "encrypted-vm-bytecode-interpreter":
            matches.append({
                "id": entry["id"], "name": entry["name"], "family": entry["family"],
                "playbook": entry["offender"].get("playbook", ""),
                "tools": entry["offender"].get("tools", []),
            })
    return {
        "status": "ok",
        "server": "re-encrypted-vm-bypass",
        "version": __version__,
        "target": target,
        "pattern": pattern,
        "mode": mode,
        "output": out_dir,
        "execution_status": "dry-run",
        "recipe_steps": len(recipe),
        "recipe": recipe,
        "pattern_yaml": pattern_yaml,
        "catalog_matches": matches,
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
