"""RE-BREAKER orchestrator MCP server (v0.1.0).

Closes G2: runtime execution of bypass recipes. The orchestrator chains
the planning tools (re-catalog-match, re-encrypted-vm-bypass, re-vendor-
anti-tamper, re-anti-vm-spoof, re-entitlement-bypass) into a single
end-to-end workflow.

Modes:
  - plan(target):   dry-run only (v0.1.0 default). Returns the combined
                    catalog match + bypass recipe + entitlement plan as
                    a single JSON. Each step lists which real MCP
                    server to invoke for execution.
  - execute(target): v0.2.0 follow-up. Actually calls the real engines
                    via the parent MCP manager.

This server is a *thin* orchestrator — it does not duplicate the
catalog matching or recipe generation. It composes the existing
servers.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

# v0.8.0+ fix: ensure sibling debugger servers' src/ are on sys.path so
# the auto-start imports in _auto_start_debugger() resolve at runtime.
# The tests mock these via sys.modules; in the real MCP runtime (uv
# --directory re-orchestrator run re-orchestrator) only this package's
# own src/ is on sys.path, so the sibling imports would otherwise fail
# with "No module named 're_x64dbg_remote'".
_SERVERS_DIR = Path(__file__).resolve().parent.parent.parent.parent
for _sibling in ("re-x64dbg-remote", "re-ida-remote", "re-ghidra-remote"):
    _src = _SERVERS_DIR / _sibling / "src"
    if _src.exists() and str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

try:
    from mcp.server.fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    FastMCP = None
    MCP_AVAILABLE = False

from re_orchestrator import __version__

log = logging.getLogger("re_orchestrator")
log.setLevel(logging.INFO)

mcp = FastMCP("re-orchestrator") if MCP_AVAILABLE else None

# v0.1.0 compat shim: when MCP isn't available, the @mcp.tool() decorator
# is a no-op. The tools stay callable as plain Python functions for unit
# testing. The stdio transport still requires MCP_AVAILABLE.
def _noop(*args, **kwargs):
    def wrap(fn): return fn
    return wrap

if not MCP_AVAILABLE:
    class _MCPShim:
        tool = staticmethod(_noop)
        def run(self, *a, **kw): pass
    mcp = _MCPShim()

PLUGIN_ROOT = Path(os.environ.get("RE_BREAKER_PLUGIN_ROOT", "os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")"))

# v0.8.0: ensure the catalog matcher has its env vars set. The
# re-catalog-match server reads catalog + yara rules from env, not
# from a CLI arg. If unset, the matcher returns 0 matches silently.
os.environ.setdefault("RE_BREAKER_CATALOG_PATH", str(PLUGIN_ROOT / "data" / "catalog.json"))
os.environ.setdefault("RE_BREAKER_YARA_RULES_PATH", str(PLUGIN_ROOT / "data" / "yara" / "techniques.yar"))


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-orchestrator",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-orchestrator v0.1.0: chains re-catalog-match + "
            "re-encrypted-vm-bypass + re-vendor-anti-tamper + re-anti-vm-spoof + "
            "re-entitlement-bypass into a single workflow. plan() is the "
            "dry-run mode; execute() is the v0.2.0 runtime follow-up."
        ),
        "env": {
            "RE_BREAKER_PLUGIN_ROOT": str(PLUGIN_ROOT),
            "RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>"),
        },
        "tools_implemented": 2,
        "tools_total": 2,
    }


def _run_cli(cli_path: Path, *args: str) -> dict:
    """Run a RE-BREAKER CLI tool and return its JSON output."""
    if not cli_path.exists():
        return {"status": "error", "error": f"CLI not found: {cli_path}"}
    try:
        result = subprocess.run(
            ["python3", str(cli_path), *args, "--json"],
            capture_output=True, text=True, timeout=120,
            cwd=str(PLUGIN_ROOT),
        )
        if result.returncode != 0:
            return {"status": "error", "error": result.stderr[-500:]}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "CLI timeout (120s)"}
    except json.JSONDecodeError as e:
        return {"status": "error", "error": f"JSON parse error: {e}"}
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def plan(target: str, catalog_min_confidence: float = 0.3) -> dict:
    """Build the combined per-target workflow plan.

    Runs (via CLI subprocess):
      1. re-triage.triage_target(target)  — if no triage JSON exists
      2. re-catalog-match.match_catalog(target, triage_json_path=...)  — match
      3. re-encrypted-vm-bypass.bypass_pattern(target, pattern=<from match>)
      4. re-vendor-anti-tamper.run_vendor_tool(target, vendor=<from match>)
      5. re-anti-vm-spoof.spoof_target(target)
      6. re-entitlement-bypass.plan_emulation(target)

    Returns a single dict with all 6 outputs and a per-step "next action"
    that lists which real MCP tool to call for execution.
    """
    target_path = Path(target)
    if not target_path.exists():
        return {"status": "error", "error": f"target not found: {target}"}

    # Step 1: triage
    triage_json = PLUGIN_ROOT / "re-triage-output" / "orchestrator" / f"{target_path.stem}-triage.json"
    triage_json.parent.mkdir(parents=True, exist_ok=True)
    if triage_json.exists():
        triage_step = {"status": "cached", "triage_json_path": str(triage_json)}
    else:
        triage_step = {
            "status": "needed",
            "next_action": f"mcp__re-triage.triage_target(target={target!r}, output={str(triage_json.parent)!r})",
            "triage_json_path": str(triage_json),
        }

    # Step 2: catalog match (needs triage_json from step 1)
    catalog_step = {
        "status": "pending_step_1",
        "next_action": f"mcp__re-catalog-match.match_catalog(target={target!r}, triage_json_path={str(triage_json)!r}, min_confidence={catalog_min_confidence})",
    }

    # Step 3: encrypted-vm bypass (needs catalog match from step 2)
    bypass_step = {
        "status": "pending_step_2",
        "next_action": "mcp__re-encrypted-vm-bypass.bypass_pattern(target=<T>, pattern=<from catalog match>, mode=emulator|frida|inject)",
    }

    # Step 4: vendor anti-tamper (needs catalog match from step 2)
    vendor_step = {
        "status": "pending_step_2",
        "next_action": "mcp__re-vendor-anti-tamper.run_vendor_tool(target=<T>, vendor=<from catalog match>, mode=emulator)",
    }

    # Step 5: anti-vm-spoof (needs triage from step 1)
    antidebug_step = {
        "status": "pending_step_1",
        "next_action": f"mcp__re-anti-vm-spoof.spoof_target(target={target!r}, mode=frida)",
    }

    # Step 6: entitlement bypass (per-target manifest)
    target_key_map = {
        "007FirstLight.exe": "007fl",
        "fm.exe": "fm26",
        "Hello Kitty.exe": "hkia",
        "Lost In Random.exe": "lir",
        "P3R.exe": "p3r",
        "CrimsonDesert.exe": "cd",
        "Warhammer3.exe": "tww3",
    }
    target_key = target_key_map.get(target_path.name, target_path.stem)
    entitlement_step = {
        "status": "always_run",
        "next_action": f"mcp__re-entitlement-bypass.plan_emulation(target={target_key!r})",
    }

    return {
        "status": "ok",
        "server": "re-orchestrator",
        "version": __version__,
        "target": target,
        "execution_status": "plan-only",  # v0.1.0 — execute() is v0.2.0
        "workflow_steps": [
            triage_step,
            catalog_step,
            bypass_step,
            vendor_step,
            antidebug_step,
            entitlement_step,
        ],
        "step_count": 6,
        "notes": [
            "plan() is dry-run only in v0.1.0. Each step lists the real MCP tool to call for execution.",
            "execute() is a v0.2.0 follow-up that actually invokes the tools via the parent MCP manager.",
        ],
    }


@mcp.tool()
def execute(
    target: str,
    runtime_mode: Literal["emulator", "frida", "inject"] = "frida",
    catalog_min_confidence: float = 0.3,
    layers: list[str] | None = None,
    preferred_debugger: Literal["x64dbg", "ida", "ghidra", "auto", "none"] = "auto",
) -> dict:
    """v0.8.0: execute the workflow against a real target.

    v0.8.0+ (Wave 3 Item H): the `preferred_debugger` parameter controls
    which debugger (x64dbg / IDA Pro / Ghidra) is auto-started before
    any debug step. Set to "auto" to pick based on the target's
    complexity (large binaries → Ghidra, small → x64dbg), or "none" to
    skip auto-start entirely.

    Chains the per-step tools via direct Python import (the MCP server
    functions are plain Python under the @mcp.tool() decorator — we
    import and call them in-process). This avoids the Claude Code MCP
    sibling-tool forwarding limitation.

    For each workflow step:
      1. triage       — re_triage.server.triage_target
      2. catalog      — re_catalog_match.server.match_catalog
      3. anti-vm      — re_anti_vm_spoof.server.spoof_target
      4. bypass       — re_encrypted_vm_bypass.server.bypass_pattern
                         (uses the catalog match from step 2)
      5. vendor       — re_vendor_anti_tamper.server.run_vendor_tool
                         (uses the catalog match from step 2)
      6. entitlement  — re_entitlement_bypass.server.plan_emulation +
                         bypass_entitlement (uses the per-target key)

    Returns per-step success + payload paths + verdict.
    """
    target_path = Path(target)
    if not target_path.exists():
        return {"status": "error", "error": f"target not found: {target}"}

    # Map target binary name → entitlement key (per servers/re-entitlement-bypass/data/...)
    target_key_map = {
        "007FirstLight.exe": "007fl",
        "fm.exe": "fm26",
        "Hello Kitty.exe": "hkia",
        "Lost In Random.exe": "lir",
        "P3R.exe": "p3r",
        "CrimsonDesert.exe": "cd",
        "Warhammer3.exe": "tww3",
    }
    target_key = target_key_map.get(target_path.name, target_path.stem)
    layers = layers or ["steam_ceg", "eos", "sega_sso", "ioi", "pa", "sunblink", "atlus", "origin"]


def _auto_start_debugger(preferred: str, target: Path) -> dict:
    """v0.8.0+ Wave 3 (Item H): auto-start the preferred debugger.

    Args:
        preferred: "x64dbg" | "ida" | "ghidra" | "auto"
                   "auto" picks based on the target's binary size:
                   - < 10 MB  → x64dbg (fast, good for runtime patching)
                   - < 100 MB → IDA Pro (deeper analysis, medium size)
                   - ≥ 100 MB → Ghidra (headless, handles huge binaries)
        target: the target binary

    Returns a step result dict.
    """
    if preferred == "auto":
        try:
            size = target.stat().st_size
            if size < 10 * 1024 * 1024:
                preferred = "x64dbg"
            elif size < 100 * 1024 * 1024:
                preferred = "ida"
            else:
                preferred = "ghidra"
        except OSError:
            preferred = "x64dbg"  # safest default
    result: dict = {
        "step": 0,
        "name": f"auto-start-{preferred}",
        "preferred_debugger": preferred,
        "target_size_bytes": target.stat().st_size if target.exists() else 0,
    }
    try:
        if preferred == "x64dbg":
            from re_x64dbg_remote.server import start_x64dbg
            start_result = start_x64dbg(target=str(target))
            result.update({
                "status": "ok",
                "tool_called": "start_x64dbg",
                "already_started": start_result.get("already_started", False),
                "x64dbg_pid": start_result.get("pid", 0),
                "tunnel_name": start_result.get("tunnel_name", ""),
            })
        elif preferred == "ida":
            from re_ida_remote.server import start_ida_mcp
            start_result = start_ida_mcp()
            result.update({
                "status": "ok",
                "tool_called": "start_ida_mcp",
                "tunnel_name": start_result.get("tunnel_name", ""),
            })
        elif preferred == "ghidra":
            from re_ghidra_remote.server import start_ghidra_mcp
            start_result = start_ghidra_mcp()
            result.update({
                "status": "ok",
                "tool_called": "start_ghidra_mcp",
                "tunnel_name": start_result.get("tunnel_name", ""),
            })
        else:
            result["status"] = "error"
            result["error"] = f"unknown preferred_debugger: {preferred!r}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {e}"
        log.warning(f"auto-start {preferred} failed: {e}")
    return result

    step_results: list[dict] = []

    # v0.8.0+ Wave 3 (Item H): auto-start the preferred debugger before
    # any debug step. The debugger servers are already idempotent
    # (start_x64dbg returns already_started=True if running).
    if preferred_debugger != "none":
        log.info(f"execute() step 0: auto-start preferred_debugger={preferred_debugger}")
        step_results.append(_auto_start_debugger(preferred_debugger, target_path))

    # Step 1: triage
    log.info("execute() step 1: triage")
    triage_json_path = ""  # will be populated from the triage response
    try:
        from re_triage.server import triage_target
        triage_out_dir = PLUGIN_ROOT / "re-triage-output" / "orchestrator"
        triage_out_dir.mkdir(parents=True, exist_ok=True)
        triage_result = triage_target(target=str(target_path), output=str(triage_out_dir))
        # v0.8.0 fix: the triage tool writes the file as
        # {target_key}-triage.json (NOT {stem}-triage.json). Parse the
        # triage response to find the actual triage_json_path it wrote.
        # The tool returns the path in triage_result.get("triage_json_path").
        triage_json_path = triage_result.get("triage_json_path", "")
        if not triage_json_path or not Path(triage_json_path).exists():
            # Fallback: look in the output dir for the most recent triage JSON
            candidates = sorted(triage_out_dir.glob(f"*{target_path.stem}*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if candidates:
                triage_json_path = str(candidates[0])
        step_results.append({
            "step": 1, "name": "triage",
            "status": "ok" if triage_result.get("status") == "ok" else "error",
            "triage_json_path": triage_json_path,
            "result_summary": {k: v for k, v in triage_result.items() if k in ("target", "version", "triage_json_path")},
        })
    except Exception as e:
        step_results.append({"step": 1, "name": "triage", "status": "error", "error": f"{type(e).__name__}: {e}"})

    # Step 2: catalog match
    # v0.8.0 smart fallback: if the catalog returns 0 matches on the launcher,
    # auto-detect the GameAssembly.dll (Unity IL2CPP) and retry. This is
    # the F4 fix applied at the orchestrator level.
    log.info("execute() step 2: catalog match")
    import os as _os
    log.info(f"  env: RE_BREAKER_CATALOG_PATH={_os.environ.get('RE_BREAKER_CATALOG_PATH')}")
    top_match = None
    matches = []
    catalog_main_binary = str(target_path)
    try:
        from re_catalog_match.server import match_catalog
        catalog_result = match_catalog(
            target=str(target_path),
            triage_json_path=triage_json_path,
            min_confidence=catalog_min_confidence,
        )
        matches = catalog_result.get("matches", [])
        # F4 fallback: if 0 matches, look for GameAssembly.dll next to the launcher
        if not matches:
            game_assembly = target_path.parent / "GameAssembly.dll"
            if game_assembly.exists():
                log.info(f"step 2 F4 fallback: retrying with {game_assembly}")
                catalog_main_binary = str(game_assembly)
                # Triage the .dll
                try:
                    from re_triage.server import triage_target
                    dll_triage_out = PLUGIN_ROOT / "re-triage-output" / "orchestrator" / f"{game_assembly.stem}-triage.json"
                    dll_triage_out.parent.mkdir(parents=True, exist_ok=True)
                    triage_target(target=str(game_assembly), output=str(dll_triage_out.parent))
                    triage_json_path = str(dll_triage_out)
                except Exception as e:
                    log.warning(f"  F4 fallback triage failed: {e}")
                catalog_result = match_catalog(
                    target=str(game_assembly),
                    triage_json_path=triage_json_path,
                    min_confidence=catalog_min_confidence,
                )
                matches = catalog_result.get("matches", [])
        top_match = matches[0] if matches else None
        step_results.append({
            "step": 2, "name": "catalog",
            "status": "ok" if catalog_result.get("status") == "ok" else "error",
            "matches_count": len(matches),
            "top_match": top_match.get("id") if top_match else None,
            "top_confidence": top_match.get("defender", {}).get("confidence") if top_match else None,
            "main_binary": catalog_main_binary,
        })
    except Exception as e:
        step_results.append({"step": 2, "name": "catalog", "status": "error", "error": f"{type(e).__name__}: {e}"})

    # Step 3: anti-vm spoof (v0.8.0+ Wave 1 Item C: actually invoke it)
    log.info("execute() step 3: anti-vm spoof")
    try:
        from re_anti_vm_spoof.server import spoof_target, spoof_runtime
        spoof_result = spoof_target(target=str(target_path), mode=runtime_mode)
        step_results.append({
            "step": 3, "name": "anti-vm-spoof",
            "status": "ok" if spoof_result.get("status") == "ok" else "error",
            "target_posture": spoof_result.get("plan", {}).get("target_posture"),
            "snapshot": spoof_result.get("plan", {}).get("hooks", {}).get("cpuid", {}).get("snapshot"),
            "is_kernel_active": spoof_result.get("plan", {}).get("is_kernel_active"),
        })
        # v0.8.0+ Wave 1 (Item C): if the target is kernel-active AND we have
        # a running PID, actually invoke spoof_runtime (Item C closes the
        # gap that v0.2.0's plan-only `spoof_target` left open).
        is_kernel_active = spoof_result.get("plan", {}).get("is_kernel_active", False)
        runtime_pid = step_results[0].get("host_pid")  # from step 1 (if injected)
        if is_kernel_active and runtime_pid:
            log.info("execute() step 3: target is kernel-active — invoking spoof_runtime")
            try:
                runtime_result = spoof_runtime(
                    target=str(target_path),
                    pid=runtime_pid,
                    timeout_s=30,
                )
                step_results.append({
                    "step": 3.5, "name": "anti-vm-spoof-runtime",
                    "status": runtime_result.get("status"),
                    "execution_status": runtime_result.get("execution_status"),
                    "frida_available": runtime_result.get("frida_available"),
                    "hooks_installed": runtime_result.get("hooks_installed", []),
                    "spoof_input_path": runtime_result.get("spoof_input_path"),
                })
            except Exception as inner_e:
                step_results.append({
                    "step": 3.5, "name": "anti-vm-spoof-runtime",
                    "status": "error",
                    "error": f"{type(inner_e).__name__}: {inner_e}",
                })
    except Exception as e:
        step_results.append({"step": 3, "name": "anti-vm-spoof", "status": "error", "error": f"{type(e).__name__}: {e}"})

    # Step 4: bypass pattern (uses top_match from step 2)
    if top_match:
        log.info("execute() step 4: bypass pattern")
        try:
            from re_encrypted_vm_bypass.server import bypass_pattern
            # Choose the best pattern from the match
            bypass_pattern_arg = None
            for m in matches:
                mid = m.get("id", "")
                if "pattern-a-vmt" in mid:
                    bypass_pattern_arg = "A-VMT"
                    break
                if "pattern-a-dw" in mid:
                    bypass_pattern_arg = "A-DW"
                    break
                if "encrypted-vm.bytecode-interpreter.pattern-a" == mid:
                    bypass_pattern_arg = "A"
                    break
            if bypass_pattern_arg is None:
                # Default to Pattern A (Unity IL2CPP)
                bypass_pattern_arg = "A"
            bypass_result = bypass_pattern(target=str(target_path), pattern=bypass_pattern_arg, mode=runtime_mode)
            step_results.append({
                "step": 4, "name": "bypass",
                "status": "ok" if bypass_result.get("status") == "ok" else "error",
                "pattern": bypass_pattern_arg,
                "recipe_steps": bypass_result.get("recipe_steps"),
            })
        except Exception as e:
            step_results.append({"step": 4, "name": "bypass", "status": "error", "error": f"{type(e).__name__}: {e}"})

    # Step 5: vendor anti-tamper
    log.info("execute() step 5: vendor")
    try:
        from re_vendor_anti_tamper.server import run_vendor_tool
        vendor_arg = "denuvo"  # default
        if top_match and "denuvo" in top_match.get("id", "").lower():
            vendor_arg = "denuvo"
        vendor_result = run_vendor_tool(target=str(target_path), vendor=vendor_arg, mode=runtime_mode)
        step_results.append({
            "step": 5, "name": "vendor",
            "status": "ok",
            "vendor": vendor_arg,
            "out_of_scope": vendor_result.get("out_of_scope", False),
            "fallback": vendor_result.get("recipe", {}).get("fallback_approach"),
        })
    except Exception as e:
        step_results.append({"step": 5, "name": "vendor", "status": "error", "error": f"{type(e).__name__}: {e}"})

    # Step 6: entitlement bypass
    log.info("execute() step 6: entitlement")
    entitlement_layer_results = []
    try:
        from re_entitlement_bypass.server import plan_emulation, bypass_entitlement
        plan_result = plan_emulation(target=target_key)
        for layer in layers:
            try:
                ent_result = bypass_entitlement(target=str(target_path), vendor=layer, mode=runtime_mode)
                entitlement_layer_results.append({
                    "layer": layer,
                    "status": ent_result.get("execution_status", "unknown"),
                    "playbook": ent_result.get("playbook"),
                })
            except Exception as e:
                entitlement_layer_results.append({"layer": layer, "status": "error", "error": f"{type(e).__name__}: {e}"})
        step_results.append({
            "step": 6, "name": "entitlement",
            "status": "ok",
            "target_key": target_key,
            "sow": plan_result.get("sow"),
            "sow_gate": plan_result.get("sow_gate"),
            "layers": entitlement_layer_results,
        })
    except Exception as e:
        step_results.append({"step": 6, "name": "entitlement", "status": "error", "error": f"{type(e).__name__}: {e}"})

    # Aggregate verdict
    step_statuses = [s.get("status") for s in step_results]
    if all(s == "ok" for s in step_statuses):
        verdict = "ok"
    elif any(s == "ok" for s in step_statuses):
        verdict = "partial"
    else:
        verdict = "error"

    return {
        "status": verdict,
        "server": "re-orchestrator",
        "version": "0.8.0",
        "target": str(target_path),
        "runtime_mode": runtime_mode,
        "step_count": len(step_results),
        "step_results": step_results,
        "next_action": "Inspect step_results for per-step success + payload paths. Use re-injection-runtime.inject for runtime attach.",
    }


def main() -> None:
    if mcp:
        mcp.run(transport="stdio")
    else:
        log.error("mcp SDK not available; cannot start server")


if __name__ == "__main__":
    main()
