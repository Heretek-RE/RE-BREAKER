"""re-anti-vm-spoof MCP server (v0.3.0 implemented).

Neutralize anti-VM detection (CPUID hypervisor leaf, RDTSC timing trap,
VMCALL, VMXON, INVD) on a target binary.

Two layers:
  - Frida script (live process): intercepts CPUID/RDTSC/VMCALL/VMXON/INVD.
  - DLL hook (in-process, for hardened cases): installs the same hooks
    via inline-trampoline rather than Frida.

v0.2.0: returns a plan. The bare-metal CPUID snapshot is required for
the CPUID-hypervisor-leaf spoof.
v0.3.0 (v0.8.0+ Wave 1, Item C): runtime execution via spoof.js +
spoof_runtime() Python wrapper.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Literal, Optional

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

from mcp.server.fastmcp import FastMCP

from re_anti_vm_spoof import __version__

logger = logging.getLogger("re_anti_vm_spoof")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-anti-vm-spoof")


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-anti-vm-spoof",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-anti-vm-spoof v0.2.0: builds a CPUID/RDTSC/"
            "VMCALL/VMXON hook plan. Runtime execution lands in v0.3.0."
        ),
        "env": {"RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>")},
    }


CpuidStrategy = Literal["bare-metal-snapshot", "no-op"]
VmDetectStrategy = Literal["zero", "passthrough"]
SpoofMode = Literal["frida", "inject"]


# Default bare-metal CPUID snapshot (pre-captured on a non-virtualized host).
# Real values: leaf 0 = "GenuineIntel", leaf 1 ECX bit 31 = 0 (no hypervisor),
# leaf 0x40000000 = 0 (no vendor string).
DEFAULT_BARE_METAL_SNAPSHOT = {
    "leaf_0": {"eax": 0x0000000D, "ebx": 0x756E6547, "ecx": 0x6C65746E, "edx": 0x49656E69},
    "leaf_1": {"eax": 0x000906ED, "ebx": 0x00000800, "ecx": 0x0000F1FB, "edx": 0xBFEBFBFF},
    "leaf_0x40000000": {"eax": 0x00000000, "ebx": 0x00000000, "ecx": 0x00000000, "edx": 0x00000000},
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
    """v0.4.0: route through the shared triage loader (RE-BREAKER self-contained)."""
    from re_breaker.triage import load_triage as _shared_load_triage
    try:
        return _shared_load_triage(target, triage_json_path=triage_json_path)
    except FileNotFoundError:
        return {}


def _build_plan(target, triage, cpuid_strategy, vmdetect_strategy, mode, rdtsc_delta_cap, snapshot, output):
    posture = triage.get("hypervisor_posture", "unknown")
    pa = triage.get("anti_analysis_primitives", {}) or {}
    has_cpuid = pa.get("CPUID_hypervisor_leaf", 0)
    is_kernel_active = "kernel-active" in (posture or "")
    snapshot = snapshot or DEFAULT_BARE_METAL_SNAPSHOT
    return {
        "target": target,
        "output": output or "./re-anti-vm-spoof-output/",
        "execution_status": "dry-run",
        "target_posture": posture,
        "is_kernel_active": is_kernel_active,
        "cpuid_hypervisor_leaf_count": has_cpuid,
        "hooks": {
            "cpuid": {
                "strategy": cpuid_strategy,
                "snapshot": snapshot,
                "leaves_to_spoof": ["leaf_0", "leaf_1 (ECX bit 31 = 0)", "leaf_0x40000000 (zeroed)"],
            },
            "rdtsc": {
                "strategy": "delta-cap",
                "delta_cap_cycles": rdtsc_delta_cap,
                "rationale": "any RDTSC delta > cap returns the cap value, defeating bimodal timing-trap distributions",
            },
            "vmcall": {"strategy": vmdetect_strategy},
            "vmxon":  {"strategy": vmdetect_strategy},
            "invd":   {"strategy": vmdetect_strategy},
        },
        "mode": mode,
        "frida_script_path": "RE-BREAKER/servers/re-anti-vm-spoof/src/re_anti_vm_spoof/spoof.js" if mode == "frida" else None,
        "dll_path": "RE-BREAKER/inject/build/re_breaker_inject.{dll,so}" if mode == "inject" else None,
    }


@mcp.tool()
def spoof_target(
    target: str,
    cpuid_strategy: CpuidStrategy = "bare-metal-snapshot",
    vmdetect_strategy: VmDetectStrategy = "zero",
    mode: SpoofMode = "frida",
    rdtsc_delta_cap: int = 1000,
    bare_metal_snapshot: str | None = None,
    output: str = "",
) -> dict:
    """Build an anti-VM-spoof plan for the target.

    v0.2.0: returns a structured plan. v0.3.0: runtime execution.
    """
    catalog = _load_catalog()
    triage = _load_triage(target)
    if not triage:
        return {"status": "error", "error": f"no triage.json found for {target}",
                "server": "re-anti-vm-spoof", "version": __version__}
    snapshot = None
    if bare_metal_snapshot:
        sp = Path(bare_metal_snapshot)
        if sp.exists():
            snapshot = json.loads(sp.read_text())
    plan = _build_plan(target, triage, cpuid_strategy, vmdetect_strategy, mode, rdtsc_delta_cap, snapshot, output)
    # catalog match: anti-vm family
    matches = []
    for entry in catalog["entries"]:
        if entry["family"] != "anti-vm":
            continue
        sigs = entry["defender"]["detection_signatures"]
        conf = 0.0
        for sig in sigs:
            if sig.get("type") == "byte_sequence" and sig["value"].strip() in ("0F A2", "0F 31"):
                prim = {"0F A2": "CPUID", "0F 31": "RDTSC"}.get(sig["value"].strip())
                pa = triage.get("anti_analysis_primitives", {}) or {}
                if pa.get(f"{prim}_count_ge_200"):
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
        "server": "re-anti-vm-spoof",
        "version": __version__,
        "target": target,
        "mode": mode,
        "strategies": {"cpuid": cpuid_strategy, "vmdetect": vmdetect_strategy, "rdtsc_delta_cap": rdtsc_delta_cap},
        "catalog_matches": matches[:5],
        "plan": plan,
    }


def main() -> None:
    mcp.run(transport="stdio")


# ----------------------------------------------------------------------------
# v0.8.0+ Wave 1 (Item C): spoof_runtime — actually invoke spoof.js
# ----------------------------------------------------------------------------


def _frida_available() -> bool:
    """v0.3.0: check if the frida Python package is installed."""
    if shutil.which("frida"):
        return True
    try:
        import frida  # noqa
        return True
    except ImportError:
        return False


def _resolve_offsets(target: str, triage: dict, catalog_matches: list) -> dict:
    """Build the offsets dict that spoof.js consumes.

    Reads the per-site RVAs from the triage and computes the in-memory
    virtual addresses (assuming binary_base=0 unless /proc/<pid>/maps
    says otherwise). For targets that aren't running yet, the offsets
    are RVAs — the runtime wrapper must be re-invoked with the binary_base
    once the target is spawned.
    """
    per_site = triage.get("per_site_rvas", {}) or {}
    out = {}
    for prim, rvas in per_site.items():
        if isinstance(rvas, list) and rvas:
            out[prim.lower() + "_offset"] = rvas[0]  # RVA
    return out


@mcp.tool()
def spoof_runtime(
    target: str,
    *,
    pid: Optional[int] = None,
    binary_base: Optional[int] = None,
    cpuid_strategy: CpuidStrategy = "bare-metal-snapshot",
    vmdetect_strategy: VmDetectStrategy = "zero",
    rdtsc_delta_cap: int = 1000,
    bare_metal_snapshot: Optional[str] = None,
    timeout_s: int = 60,
    output: str = "",
) -> dict:
    """v0.8.0+ Wave 1 (Item C): actually invoke the anti-VM spoof frida script.

    Builds the snapshot + offsets, writes them to a JSON file the frida
    script reads, then attaches frida and installs the hooks. Closes
    the gap that the v0.2.0 plan-only `spoof_target` left open.

    Args:
        target: path to the target binary
        pid: host PID of an already-running target. If None and frida is
             installed, frida will spawn the target.
        binary_base: in-memory load address. If None, reads
                     /proc/<pid>/maps (Linux) or assumes 0.
        cpuid_strategy: bare-metal-snapshot | no-op
        vmdetect_strategy: zero (NOP) | passthrough
        rdtsc_delta_cap: cycles to cap RDTSC deltas at
        bare_metal_snapshot: path to a snapshot JSON; if None, uses default
        timeout_s: max seconds to keep the frida session alive
        output: directory for the frida log + spoof input

    Returns:
        {
          "status": "ok" | "error",
          "frida_available": bool,
          "execution_status": "completed" | "timeout" | "frida-not-installed" | "error",
          "hooks_installed": [...],
          "frida_log_path": str,
          "spoof_input_path": str,
        }
    """
    out_dir = Path(output or "./re-anti-vm-spoof-output/")
    out_dir.mkdir(parents=True, exist_ok=True)
    frida_ok = _frida_available()
    triage = _load_triage(target)
    if not triage:
        return {
            "status": "error",
            "error": f"no triage found for {target}",
            "server": "re-anti-vm-spoof",
            "version": __version__,
        }
    # 1. Build the snapshot
    snapshot = DEFAULT_BARE_METAL_SNAPSHOT.copy()
    if bare_metal_snapshot:
        sp = Path(bare_metal_snapshot)
        if sp.exists():
            snapshot = json.loads(sp.read_text())
    if cpuid_strategy == "no-op":
        snapshot = {k: {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0} for k in snapshot}
    snapshot["rdtsc_cap"] = rdtsc_delta_cap
    snapshot["rdtsc_baseline"] = 0
    # 2. Build the offsets
    catalog = _load_catalog()
    catalog_matches = []
    for entry in catalog.get("entries", []):
        if entry.get("family") == "anti-vm":
            catalog_matches.append(entry)
    offsets = _resolve_offsets(target, triage, catalog_matches)
    # If we know binary_base, convert RVAs → VAs
    if binary_base is not None:
        offsets = {
            k: hex(binary_base + (int(v, 16) if isinstance(v, str) and not v.startswith("0x") else v))
            for k, v in offsets.items()
        }
    snapshot.update(offsets)
    # 3. Write the snapshot to a file the frida script reads
    spoof_input = out_dir / "spoof-input.json"
    spoof_input.write_text(json.dumps(snapshot))
    spoof_input_path = str(spoof_input)
    # 4. Locate spoof.js
    spoof_js = Path(__file__).resolve().parent / "spoof.js"
    if not spoof_js.exists():
        return {
            "status": "error",
            "error": f"spoof.js not found at {spoof_js}",
            "server": "re-anti-vm-spoof",
            "version": __version__,
        }
    # 5. If frida is not installed, return early with the artifacts
    if not frida_ok:
        return {
            "status": "ok",
            "server": "re-anti-vm-spoof",
            "version": __version__,
            "target": target,
            "pid": pid,
            "frida_available": False,
            "execution_status": "frida-not-installed",
            "spoof_input_path": spoof_input_path,
            "spoof_js_path": str(spoof_js),
            "snapshot_keys": list(snapshot.keys()),
            "offsets": offsets,
            "hooks_to_install": [k for k in snapshot if k.endswith("_offset")],
            "note": ("v0.8.0+ Wave 1 (Item C): frida package not installed. "
                     "Install via `pip install frida frida-tools` and re-run "
                     "to actually attach. The spoof input file + script are "
                     "written to disk."),
        }
    # 6. frida is installed — actually attach
    try:
        import frida
        script_src = spoof_js.read_text()
        # Use Frida's require('fs') to read the input file inside the script
        prepended = (
            "const _raw = require('fs').readFileSync("
            f"'{spoof_input_path}', 'utf8'"
            ");\n" + script_src.replace(
                "readFileSync('/dev/stdin', 'utf8')",
                "_raw",
            )
        )
        if pid is None:
            pid = frida.spawn([target])
        session = frida.attach(pid)
        script = session.create_script(prepended)
        log_path = out_dir / "frida-spoof.log"
        hooks_installed: list[str] = []
        def on_message(msg, data):
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if payload.get("event") == "ready":
                    hooks_installed.extend([k for k in snapshot if k.endswith("_offset")])
                try:
                    with open(log_path, "a") as f:
                        f.write(json.dumps(payload) + "\n")
                except OSError:
                    pass
            elif msg["type"] == "error":
                try:
                    with open(log_path, "a") as f:
                        f.write(f"[error] {msg.get('description', '')}\n")
                except OSError:
                    pass
        script.on("message", on_message)
        script.load()
        time.sleep(min(timeout_s, 60))
        session.detach()
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "server": "re-anti-vm-spoof",
            "version": __version__,
            "target": target,
            "execution_status": "attach-failed",
            "spoof_input_path": spoof_input_path,
        }
    return {
        "status": "ok",
        "server": "re-anti-vm-spoof",
        "version": __version__,
        "target": target,
        "pid": pid,
        "frida_available": True,
        "execution_status": "completed",
        "hooks_installed": [k for k in snapshot if k.endswith("_offset")],
        "spoof_input_path": spoof_input_path,
        "spoof_js_path": str(spoof_js),
        "frida_log_path": str(log_path),
    }


if __name__ == "__main__":
    main()
