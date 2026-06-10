"""re-entitlement-bypass MCP server (v0.1.0 implemented).

Generic orchestrator for the entitlement layer (Steam CEG, EOS handshake,
IOI Account, Pearl Abyss internal). Returns a per-vendor plan that
references the appropriate PoC artifact built at
See the RE-BREAKER output directory.

v0.1.0 is plan-only (mirrors re-encrypted-vm-bypass v0.2.0). Runtime
execution (deploying the stub / starting the emulator / validating
the bypass) is a v0.2.0 follow-up.

This server is the entitlement-layer counterpart to
re-encrypted-vm-bypass. Where re-encrypted-vm-bypass orchestrates the
AT layer, re-entitlement-bypass orchestrates the entitlement layer.
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

from re_entitlement_bypass import __version__

logger = logging.getLogger("re_entitlement_bypass")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-entitlement-bypass")

# -----------------------------------------------------------------------------
# Constants — PoC artifact paths (relative to the live-fire engagement output)
# -----------------------------------------------------------------------------

# These paths are relative to the project root. The server's cwd is the
# server dir, so we resolve relative to the project root.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
_OUTPUT_ROOT = _PROJECT_ROOT / "Output" / "2026-06-08-live-fire" / "03-poc"

PoCVendor = Literal["steam", "eos", "ioi", "pa", "origin", "sunblink"]
PoCMode = Literal["stub", "emulator"]

# Per-vendor PoC artifact paths
POC_ARTIFACTS = {
    "steam": {
        "stub_dll": _OUTPUT_ROOT / "steam-ceg-bypass" / "steam_api64.dll",
        "stub_source": _OUTPUT_ROOT / "steam-ceg-bypass" / "steam_api64_stub.c",
        "makefile": _OUTPUT_ROOT / "steam-ceg-bypass" / "Makefile",
        "readme": _OUTPUT_ROOT / "steam-ceg-bypass" / "README.md",
        "playbook": _PROJECT_ROOT / "docs" / "PLAYBOOKS" / "entitlement-steam-ceg.md",
        "sow": "J",
        "finding_id": "J-001",
    },
    "eos": {
        "emulator_py": _OUTPUT_ROOT / "eos-handshake-emulator" / "emulator.py",
        "hosts_txt": _OUTPUT_ROOT / "eos-handshake-emulator" / "hosts.txt",
        "protocol_md": _OUTPUT_ROOT / "eos-handshake-emulator" / "protocol.md",
        "readme": _OUTPUT_ROOT / "eos-handshake-emulator" / "README.md",
        "playbook": _PROJECT_ROOT / "docs" / "PLAYBOOKS" / "entitlement-eos.md",
        "sow": "K",
        "finding_id": "K-001",
    },
    "ioi": {
        "emulator_py": _OUTPUT_ROOT / "ioi-account-emulator" / "emulator.py",
        "hosts_txt": _OUTPUT_ROOT / "ioi-account-emulator" / "hosts.txt",
        "protocol_md": _OUTPUT_ROOT / "ioi-account-emulator" / "protocol.md",
        "readme": _OUTPUT_ROOT / "ioi-account-emulator" / "README.md",
        "playbook": _PROJECT_ROOT / "docs" / "PLAYBOOKS" / "entitlement-ioi-account.md",
        "sow": "L",
        "finding_id": "L-001",
    },
    "pa": {
        "playbook": _PROJECT_ROOT / "docs" / "PLAYBOOKS" / "entitlement-pa.md",
        "sow": "O",
        "finding_id": "O-001-pending",
        "note": "PA internal protocol emulator not yet built; see entitlement-pa.md scaffold",
    },
    "origin": {
        "playbook": _PROJECT_ROOT / "docs" / "PLAYBOOKS" / "ea-origin-stub-drop.md",
        "sow": "N",
        "finding_id": "N-001-pending",
        "note": "EA Origin stub-drop is a stress-test path (LIR), not a live-fire target",
    },
}

# Per-vendor Wine override / hosts / port
WINE_DEPLOYMENT = {
    "steam": {
        "winedlloverride": "steam_api64=n",
        "drop_in_path": "${WINEPREFIX}/drive_c/windows/system32/steam_api64.dll",
        "no_emulator": True,
    },
    "eos": {
        "emulator_command": "python3 emulator.py --bind 127.0.0.1 --port 8443",
        "hosts_entries": [
            "api.epicgames.dev", "eos.epicgames.com", "api.epicgames.com",
            "eos-ic.epicgames.com", "eos-auth.epicgames.com", "eos-ecom.epicgames.com",
        ],
    },
    "ioi": {
        "emulator_command": "python3 emulator.py --bind 127.0.0.1 --port 8443",
        "hosts_entries": [
            "account.ioi.dk", "api.ioi.dk", "entitlement.ioi.dk",
            "auth.ioi.dk", "telemetry.ioi.dk",
        ],
    },
    "pa": {
        "note": "TBD — see entitlement-pa.md scaffold",
    },
    "origin": {
        "playbook_ref": "ea-origin-stub-drop.md",
    },
}


# -----------------------------------------------------------------------------
# Tools
# -----------------------------------------------------------------------------

@mcp.tool()
def status() -> dict:
    """Health check for the re-entitlement-bypass server.

    Returns the server version, status, and env vars.
    """
    return {
        "server": "re-entitlement-bypass",
        "version": __version__,
        "status": "implemented",
        "note": ("RE-BREAKER re-entitlement-bypass v0.1.0: generic orchestrator "
                 "for Steam CEG, EOS handshake, IOI Account, and PA internal "
                 "entitlement bypasses. Returns per-vendor plans in v0.1.0; "
                 "runtime execution is a v0.2.0 follow-up."),
        "env": {
            "RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>"),
            "RE_BREAKER_PLUGIN_ROOT": os.environ.get("RE_BREAKER_PLUGIN_ROOT", "<unset>"),
        },
    }


@mcp.tool()
def bypass_entitlement(
    target: str,
    vendor: PoCVendor = "steam",
    mode: PoCMode = "stub",
    output: str = "",
) -> dict:
    """Build a per-vendor plan to deploy an entitlement-bypass PoC.

    Args:
        target: absolute path to the target launcher (.exe).
        vendor: entitlement layer vendor. One of:
            - "steam" — Steamworks CEG (SOW-X §J.3)
            - "eos"   — Epic Online Services handshake (SOW-X §K.2; AC carve-out)
            - "ioi"   — IO Interactive IOI Account (SOW-X §L.6)
            - "pa"    — Pearl Abyss internal protocol (SOW-X §O.7)
            - "origin"— EA Origin stub-drop (SOW-X stress-test)
        mode: deployment mode. "stub" for drop-in DLL; "emulator" for Python HTTP server.
        output: optional path to write the plan JSON. Empty = return only.

    Returns:
        A dict with the plan, per-vendor PoC artifact paths, and the
        per-vendor Wine deployment recipe. v0.1.0 is plan-only
        (execution_status: "dry-run"); runtime execution lands in v0.2.0.
    """
    logger.info("bypass_entitlement target=%s vendor=%s mode=%s", target, vendor, mode)

    if vendor not in POC_ARTIFACTS:
        return {
            "status": "error",
            "error": f"unknown vendor: {vendor}",
            "known_vendors": list(POC_ARTIFACTS.keys()),
        }

    artifacts = POC_ARTIFACTS[vendor]
    deployment = WINE_DEPLOYMENT[vendor]

    plan = {
        "status": "ok",
        "server": "re-entitlement-bypass",
        "version": __version__,
        "target": target,
        "vendor": vendor,
        "mode": mode,
        "output": output or "(not written)",
        "execution_status": "dry-run",
        "poc_artifacts": {k: str(v) for k, v in artifacts.items()},
        "wine_deployment": deployment,
        "playbook": str(artifacts.get("playbook", "")),
        "sow": artifacts.get("sow", "?"),
        "finding_id": artifacts.get("finding_id", "?"),
        "recipe_steps": _build_recipe_steps(vendor, target, deployment),
    }

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(plan, f, indent=2)
        plan["output"] = str(out_path)

    return plan


@mcp.tool()
def validate_bypass(
    target: str,
    vendor: PoCVendor = "steam",
    wine_prefix: str = "",
) -> dict:
    """Validate the entitlement-bypass deployment in a Wine prefix.

    Checks (per vendor):
    - Steam: steam_api64.dll exists in system32 and is the stub (size ≈ 100KB, not the real ~6MB).
    - EOS: emulator process is running on 127.0.0.1:8443; hosts file has the right entries.
    - IOI: same as EOS.
    - PA: TBD.

    Args:
        target: absolute path to the target launcher.
        vendor: entitlement layer vendor.
        wine_prefix: absolute path to the Wine prefix. Empty = skip prefix checks.

    Returns:
        A dict with per-vendor validation results. v0.1.0 is plan-only
        (returns "would-validate" guidance rather than executing checks).
    """
    logger.info("validate_bypass target=%s vendor=%s prefix=%s", target, vendor, wine_prefix)

    if vendor not in POC_ARTIFACTS:
        return {"status": "error", "error": f"unknown vendor: {vendor}"}

    checks = []
    if vendor == "steam":
        if wine_prefix:
            dll_path = Path(wine_prefix) / "drive_c" / "windows" / "system32" / "steam_api64.dll"
            stub_path = POC_ARTIFACTS["steam"]["stub_dll"]
            checks.append({
                "check": "stub_dll_in_system32",
                "expected_path": str(dll_path),
                "expected_size_kb_approx": 100,
                "real_steam_api64_size_mb_approx": 6,
                "validate_via": f"ls -la {dll_path} (should be ≈ 100KB, not ≈ 6MB)",
            })
            checks.append({
                "check": "stub_dll_sha256_matches",
                "expected_sha256": "see $stub_dll's SHA256SUMS",
                "validate_via": f"sha256sum {dll_path}",
            })
        checks.append({
            "check": "WINEDLLOVERRIDES_set",
            "validate_via": "echo $WINEDLLOVERRIDES (should be 'steam_api64=n')",
        })
        checks.append({
            "check": "spawn_target_no_steam_dialog",
            "validate_via": "wine $target (no Steam dialog should appear)",
        })
        checks.append({
            "check": "winedbg_steamapi_init_returns_ok",
            "validate_via": "re-winedbg.set_breakpoint on steam_api64.SteamAPI_Init; continue; EAX should be 0",
        })
    elif vendor in ("eos", "ioi"):
        emulator_path = POC_ARTIFACTS[vendor]["emulator_py"]
        checks.append({
            "check": "emulator_running",
            "validate_via": f"pgrep -f 'python3.*emulator.py' (should return a PID)",
        })
        checks.append({
            "check": "emulator_health_endpoint",
            "validate_via": "curl -k https://127.0.0.1:8443/<service>/v1/health (should return 200)",
        })
        if wine_prefix:
            hosts_path = Path(wine_prefix) / "drive_c" / "windows" / "system32" / "drivers" / "etc" / "hosts"
            checks.append({
                "check": "wine_hosts_has_entitlement_entries",
                "expected_path": str(hosts_path),
                "expected_entries": WINE_DEPLOYMENT[vendor].get("hosts_entries", []),
                "validate_via": f"grep <domain> {hosts_path}",
            })
        if vendor == "eos":
            checks.append({
                "check": "winedbg_eos_initialize_returns_success",
                "validate_via": "re-winedbg.set_breakpoint on EOS_Initialize in EOSSDK-Win64-Shipping.dll; continue; EAX should be 0",
            })
        elif vendor == "ioi":
            checks.append({
                "check": "winedbg_ioi_account_url_builder",
                "validate_via": "re-winedbg.set_breakpoint on ioi_account_client.dll URL builder; confirm request is sent to 127.0.0.1:8443",
            })
    elif vendor == "pa":
        checks.append({
            "check": "pa_emulator_not_yet_built",
            "note": "PA internal protocol emulator is a follow-up; see entitlement-pa.md",
        })

    return {
        "status": "ok",
        "server": "re-entitlement-bypass",
        "version": __version__,
        "target": target,
        "vendor": vendor,
        "wine_prefix": wine_prefix or "(not provided)",
        "execution_status": "dry-run",
        "checks": checks,
        "note": "v0.1.0 returns validation guidance; v0.2.0 will execute the checks.",
    }


def _build_recipe_steps(vendor: str, target: str, deployment: dict) -> list:
    """Build the per-vendor recipe steps."""
    if vendor == "steam":
        return [
            {
                "step": 1,
                "tool": "manual",
                "action": "build the Steam CEG stub (or use the pre-built artifact)",
                "command": "cd See the RE-BREAKER output directory. && make clean build verify",
            },
            {
                "step": 2,
                "tool": "manual",
                "action": "create a per-session Wine prefix",
                "command": "PREFIX=/tmp/re-breaker-wine-$(basename $target); WINEDEBUG=-all wineboot -i",
            },
            {
                "step": 3,
                "tool": "manual",
                "action": "drop the stub into Wine system32",
                "command": f"cp See the RE-BREAKER output directory. $PREFIX/drive_c/windows/system32/steam_api64.dll",
            },
            {
                "step": 4,
                "tool": "re-winedbg",
                "action": "spawn the target with the override",
                "command": f"WINEDEBUG=-all WINEDLLOVERRIDES='steam_api64=n' wine {target}",
            },
            {
                "step": 5,
                "tool": "re-winedbg",
                "action": "validate: no Steam dialog; winedbg breakpoint on SteamAPI_Init returns 0",
                "command": "re-winedbg.set_breakpoint on steam_api64.SteamAPI_Init; continue; info_registers; EAX should be 0",
            },
        ]
    if vendor in ("eos", "ioi"):
        hosts = deployment.get("hosts_entries", [])
        return [
            {
                "step": 1,
                "tool": "manual",
                "action": f"start the {vendor} emulator (background)",
                "command": f"cd See the RE-BREAKER output directory. if vendor == 'eos' else 'ioi-account-emulator')} && python3 emulator.py --bind 127.0.0.1 --port 8443 &",
            },
            {
                "step": 2,
                "tool": "manual",
                "action": "create a per-session Wine prefix",
                "command": "PREFIX=/tmp/re-breaker-wine-$(basename $target); WINEDEBUG=-all wineboot -i",
            },
            {
                "step": 3,
                "tool": "manual",
                "action": "add hosts file entries to route entitlement domains to 127.0.0.1",
                "command": f"cat See the RE-BREAKER output directory. if vendor == 'eos' else 'ioi-account-emulator')}/hosts.txt >> $PREFIX/drive_c/windows/system32/drivers/etc/hosts",
            },
            {
                "step": 4,
                "tool": "manual (optional)",
                "action": "install the self-signed cert OR patch the SDK/client to skip cert validation (re-patch-apply follow-up)",
                "command": "wine reg add HKCU\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates /v 'Emulator CA' /t REG_BINARY /d \"$(base64 -w0 cert.pem)\" /f",
            },
            {
                "step": 5,
                "tool": "manual (optional)",
                "action": "redirect :443 to :8443 (if launcher hardcodes :443)",
                "command": "sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443",
            },
            {
                "step": 6,
                "tool": "re-winedbg",
                "action": "spawn the target",
                "command": f"WINEDEBUG=-all wine {target}",
            },
            {
                "step": 7,
                "tool": "re-winedbg",
                "action": f"validate: no entitlement dialog; emulator log shows the request; winedbg breakpoint on the entitlement function returns the expected value",
                "command": (
                    "re-winedbg.set_breakpoint on EOS_Initialize in EOSSDK-Win64-Shipping.dll; continue; info_registers; EAX should be 0"
                    if vendor == "eos"
                    else "re-winedbg.set_breakpoint on ioi_account_client.dll URL builder; continue; read_memory on URL buffer; should be 'https://127.0.0.1:8443/account/v1/...'"
                ),
            },
        ]
    if vendor == "pa":
        return [
            {
                "step": 1,
                "tool": "manual",
                "action": "build the PA internal protocol emulator (TBD; see entitlement-pa.md scaffold)",
                "command": "see See the RE-BREAKER output directory. (not yet built)",
            }
        ]
    if vendor == "origin":
        return [
            {
                "step": 1,
                "tool": "manual",
                "action": "follow the EA Origin stub-drop playbook",
                "command": "see docs/PLAYBOOKS/ea-origin-stub-drop.md",
            }
        ]
    return []


def main() -> None:
    """Entry point for the re-entitlement-bypass server."""
    mcp.run()


# -----------------------------------------------------------------------------
# v0.2.0: New MCP tools (additive, bypass_entitlement preserved for back-compat)
# -----------------------------------------------------------------------------

# Import the new backends so they self-register in LAYER_REGISTRY
from re_entitlement_bypass.core.layer_base import LAYER_REGISTRY, get_deployer  # noqa: E402
from re_entitlement_bypass.core.sow_gate import SOWGate  # noqa: E402
from re_entitlement_bypass.core.status import DeployStatus, LayerDeployStatus  # noqa: E402
from re_entitlement_bypass.core.target_manifest import TargetManifest  # noqa: E402
from re_entitlement_bypass.backends import http as _http_backends  # noqa: E402,F401
from re_entitlement_bypass.backends import dll as _dll_backends  # noqa: E402,F401
from re_entitlement_bypass.backends.base import hypervisor_base  # noqa: E402,F401
from re_entitlement_bypass.backends.http import (  # noqa: E402,F401
    eos_emulator, ioi_emulator, sega_sso_emulator, atlus_emulator,
    sunblink_emulator, pa_emulator, origin_emulator,
)
from re_entitlement_bypass.backends.dll import steam_ceg_dll, eos_sdk_dll  # noqa: E402,F401

_MANIFEST = TargetManifest.load_default()


def _resolve_backend_kind(layer: str, backend_arg: str) -> str:
    if backend_arg == "auto":
        return "dll" if layer == "steam_ceg" else "http"
    if backend_arg in ("dll", "http", "hypervisor"):
        return backend_arg
    raise ValueError(f"unknown --backend={backend_arg}")


@mcp.tool()
def plan_emulation(
    target: str,
    layers: str = "",
    backend: str = "auto",
    override_sow_gate: bool = False,
) -> dict:
    """Plan the entitlement-emulation deploy for a target (v0.2.0 new tool).

    Returns a JSON status dict with per-layer plans + the SOW gate verdict.
    No writes are made; this is a dry-run.

    Args:
        target: target key (e.g. "fm26", "hkia", "007fl", "tww3", "p3r", "lir", "cd")
        layers: comma-sep layer list (default: all from data/targets.json)
        backend: "auto" | "dll" | "http" (default: "auto")
        override_sow_gate: skip the SOW ethical-wall check (logged to audit)
    """
    if not _MANIFEST.has(target):
        return {"status": "error", "error": f"unknown target '{target}'", "valid_targets": _MANIFEST.target_keys}

    t = _MANIFEST.get(target)
    layer_list = [l.strip() for l in layers.split(",")] if layers else t.layers

    sow_gate = "ok"
    sow_gate_reason = None
    for layer in layer_list:
        allowed, reason = SOWGate.check(t.sow, layer, override=override_sow_gate)
        if not allowed:
            sow_gate = "refused"
            sow_gate_reason = reason
            break

    layer_statuses: dict = {}
    for layer in layer_list:
        try:
            kind = _resolve_backend_kind(layer, backend)
            deployer = get_deployer(layer, backend_kind=kind)
            layer_statuses[layer] = deployer.plan(t, dry_run=True).model_dump()
        except KeyError as e:
            layer_statuses[layer] = {"status": "error", "error": str(e)}

    return DeployStatus(
        target=t.key,
        sow=t.sow,
        sow_gate=sow_gate,
        sow_gate_reason=sow_gate_reason,
        layers={k: LayerDeployStatus(**v) if isinstance(v, dict) else v for k, v in layer_statuses.items()},
        dry_run=True,
    ).model_dump()


@mcp.tool()
def audit_emulation(target: str) -> dict:
    """Audit a target's current deploy state without re-deploying (v0.2.0 new tool).

    Re-runs SHA-256 of every deployed file, verifies the per-layer audit state,
    and returns a structured status dict.

    Args:
        target: target key
    """
    if not _MANIFEST.has(target):
        return {"status": "error", "error": f"unknown target '{target}'"}
    t = _MANIFEST.get(target)
    layer_statuses: dict = {}
    for layer in t.layers:
        try:
            kind = _resolve_backend_kind(layer, "auto")
            deployer = get_deployer(layer, backend_kind=kind)
            layer_statuses[layer] = deployer.audit(t).model_dump()
        except KeyError as e:
            layer_statuses[layer] = {"status": "error", "error": str(e)}
    return DeployStatus(
        target=t.key,
        sow=t.sow,
        sow_gate="ok",
        layers={k: LayerDeployStatus(**v) if isinstance(v, dict) else v for k, v in layer_statuses.items()},
        dry_run=False,
    ).model_dump()


if __name__ == "__main__":
    main()
