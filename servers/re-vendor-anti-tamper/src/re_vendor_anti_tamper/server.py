"""re-vendor-anti-tamper MCP server (v0.2.0 implemented).

Per-vendor bypass shell. Shells out to the right open-source tool per
target:
  - denuvo: no general tool; the catalog entry is returned with a
    pointer to the per-Pattern A-DW + POGO approach.
  - vmprotect: void-stack/VMUnprotect, can1357/NoVmp.
  - themida: samrashaikh/Themida-Unpacker (partial).
  - starforce: out-of-scope (no open-source tool).
  - arxan: out-of-scope (no open-source tool).
  - eac / be: defensive-utility only (per MRTEA Part V §5).

v0.2.0: returns a plan. v0.3.0: actual shell-out execution.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

from re_vendor_anti_tamper import __version__

logger = logging.getLogger("re_vendor_anti_tamper")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-vendor-anti-tamper")


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-vendor-anti-tamper",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-vendor-anti-tamper v0.2.0: per-vendor bypass shell. "
            "Returns a plan that names the open-source tool to shell out to."
        ),
        "env": {"RE_BREAKER_VENDORS": os.environ.get("RE_BREAKER_VENDORS", "<unset>")},
    }


Vendor = Literal["denuvo", "vmprotect", "themida", "starforce", "arxan", "eac", "be"]
Mode = Literal["emulator", "frida", "inject"]


VENDOR_RECIPES = {
    "denuvo": {
        "general_tool": None,
        "reasoning": "No general Denuvo bypass tool exists. Bypass requires months of per-title reverse engineering per game.",
        "fallback_approach": "Use Pattern A-DW (UE5 + Denuvo ATD) workflow: re-anti-debug-patch the 200+ RDTSC sites, re-anti-vm-spoof the CPUID hypervisor leaf, re-vm-decrypt the POGO entry.",
        "catalog_entry": "anti-tamper-vendors.denuvo",
        "out_of_scope": True,
        "caveats": [
            "Per-title bypass is months of work per game",
            "Anti-tamper upgrade cycles invalidate the PoC",
            "Denuvo Anti-Cheat (the AC product) is a separate vendor in the catalog",
            "Per MRTEA Part V §4.1, no key extraction as a deliverable",
        ],
    },
    "vmprotect": {
        "general_tool": "anpa1200/Unpacker (v0.8.0+ Wave 2 Item F)",
        "tool_url": "https://github.com/anpa1200/Unpacker",
        "fallback_approach": "void-stack/VMUnprotect if anpa1200 doesn't support the target version",
        "fallback_url": "https://github.com/void-stack/VMUnprotect",
        "out_of_scope": False,
        "unpacker_backend": "qiling (64-bit) | unipacker (32-bit)",
        "vendored_path": "vendored/anpa1200-Unpacker/",
        "caveats": [
            "Partial coverage — Ultra variant is best-supported",
            "Blackbone / Mutation / Virtualization engines each need a different recipe",
            "Per MRTEA SOW-X §B.4, do not publish or distribute unpackers except as Findings",
            "v0.2.0 referenced can1357/NoVmp as the secondary; v0.8.0+ replaces with anpa1200/Unpacker",
        ],
    },
    "themida": {
        "general_tool": "anpa1200/Unpacker (v0.8.0+ Wave 2 Item F)",
        "tool_url": "https://github.com/anpa1200/Unpacker",
        "fallback_approach": "Reuse Pattern A: re-anti-debug-patch + re-vm-decrypt",
        "out_of_scope": False,
        "unpacker_backend": "qiling (64-bit) | unipacker (32-bit)",
        "vendored_path": "vendored/anpa1200-Unpacker/",
        "caveats": [
            "Partial coverage — Themida's SecureEngine macros and CodeReplace features each need a different approach",
            "Per MRTEA SOW-X §C.4, do not publish or distribute 'unpackers' except as Findings",
            "v0.2.0 referenced samrashaikh/Themida-Unpacker (now 404'd); v0.8.0+ replaces with anpa1200/Unpacker",
        ],
    },
    "starforce": {
        "general_tool": None,
        "reasoning": "No open-source StarForce bypass tool exists.",
        "out_of_scope": True,
        "caveats": [
            "StarForce's hardware-binding mechanism (where used) is in scope for analysis, but no general tool exists to clone a hardware profile",
            "Per MRTEA SOW-X §D.2, no tool that enables a third party to clone a hardware profile may be developed or distributed",
        ],
    },
    "arxan": {
        "general_tool": None,
        "reasoning": "No open-source Arxan bypass tool exists.",
        "out_of_scope": True,
        "caveats": [
            "Arxan's white-box crypto keys (where used) are in scope for analysis but the key value is reported to Arxan only",
            "Per MRTEA SOW-X §E.3, white-box keys are not extracted as a deliverable",
        ],
    },
    "eac": {
        "general_tool": None,
        "reasoning": "EAC is an anti-cheat (AC) product, not an anti-tamper (AT) product. Per MRTEA Part V §5, no weaponized PoC Exploits for AC.",
        "out_of_scope": True,
        "defensive_utility": True,
        "caveats": [
            "Per MRTEA SOW-X §F.4, no PoC Exploit that demonstrates a Bypass against a specific game or specific player",
            "Per MRTEA Part V §5.2, no distribution to cheat developers or game-hacking communities",
            "Defensive primacy: the primary deliverable for AC Findings is a defensive recommendation, not a PoC Exploit",
        ],
    },
    "be": {
        "general_tool": None,
        "reasoning": "BattlEye is an anti-cheat (AC) product. Same restrictions as EAC.",
        "out_of_scope": True,
        "defensive_utility": True,
        "caveats": [
            "Per MRTEA SOW-X §G.4, no cheat, hack, or similar tool against any game using BattlEye",
            "Per MRTEA Part V §5.2, no distribution to cheat developers",
        ],
    },
}


def _load_catalog() -> dict:
    p = Path("Path(os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")) / "data" / "catalog.json"")
    if not p.exists():
        p = Path(__file__).resolve().parents[5] / "data" / "catalog.json"
    return json.loads(p.read_text())


@mcp.tool()
def run_vendor_tool(
    vendor: Vendor,
    target: str,
    tool: str | None = None,
    mode: Mode = "emulator",
    output: str = "",
    timeout_s: int = 600,
) -> dict:
    """Build a per-vendor bypass plan.

    v0.2.0: returns a plan.
    v0.3.0: actual shell-out execution.
    v0.8.0+ (Wave 2 Item F): when vendor is vmprotect or themida AND
    anpa1200/Unpacker is available, actually invoke the unpacker (closes
    the gap that the v0.2.0 plan-only reference to samrashaikh left open).
    """
    catalog = _load_catalog()
    recipe = VENDOR_RECIPES.get(vendor, {})
    matches = []
    for entry in catalog["entries"]:
        if entry["family"] != "anti-tamper-vendors":
            continue
        if entry["id"] == f"anti-tamper-vendors.{vendor}":
            matches.append({
                "id": entry["id"], "name": entry["name"],
                "severity": entry["severity"],
                "playbook": entry["offender"].get("playbook", ""),
                "tools": entry["offender"].get("tools", []),
                "expected_runtime_minutes": entry["offender"].get("expected_runtime_minutes", 0),
                "success_probability": entry["offender"].get("success_probability", 0.0),
                "limitations": entry["offender"].get("limitations", []),
            })
    related = []
    for entry in catalog["entries"]:
        if entry["family"] in ("anti-vm", "anti-debug") and vendor in ("denuvo", "vmprotect", "themida"):
            related.append({
                "id": entry["id"], "name": entry["name"], "family": entry["family"],
                "playbook": entry["offender"].get("playbook", ""),
                "tools": entry["offender"].get("tools", []),
            })
    matches.extend(related[:5])
    tool_to_use = tool or recipe.get("general_tool")
    tool_available = None
    if tool_to_use:
        tool_available = shutil.which(tool_to_use.split("/")[-1]) is not None
    result: dict = {
        "status": "ok",
        "server": "re-vendor-anti-tamper",
        "version": __version__,
        "target": target,
        "vendor": vendor,
        "tool": tool_to_use,
        "tool_available_on_path": tool_available,
        "mode": mode,
        "output": output or "./re-vendor-anti-tamper-output/",
        "execution_status": "dry-run",
        "out_of_scope": recipe.get("out_of_scope", False),
        "defensive_utility_only": recipe.get("defensive_utility", False),
        "recipe": recipe,
        "catalog_matches": matches,
    }
    # v0.8.0+ Wave 2 (Item F): actually invoke anpa1200 for vmprotect / themida
    if vendor in ("vmprotect", "themida"):
        try:
            from re_vendor_anti_tamper.backends.unpacker import anpa1200
            if anpa1200.is_available():
                unpack_result = anpa1200.unpack(
                    target=target,
                    vendor=vendor,
                    output=output or "./re-vendor-anti-tamper-output/unpacker/",
                    timeout_s=timeout_s,
                    mode="auto",
                )
                result["anpa1200_invocation"] = unpack_result
                result["execution_status"] = unpack_result.get("status", "dry-run")
                if unpack_result.get("unpacked_path"):
                    result["unpacked_binary"] = unpack_result["unpacked_path"]
            else:
                result["anpa1200_invocation"] = {
                    "status": "not-available",
                    "note": "anpa1200/Unpacker not cloned into vendored/. See vendored/anpa1200-Unpacker/README.md for setup.",
                }
        except Exception as e:
            result["anpa1200_invocation"] = {
                "status": "error",
                "error": f"{type(e).__name__}: {e}",
            }
    return result


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
