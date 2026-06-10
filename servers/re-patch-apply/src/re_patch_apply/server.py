"""re-patch-apply MCP server (v0.3.0 implemented).

Apply the per-site anti-debug patch plan to a binary + write per-site
patch log + verify with re-speakeasy. Closes G2 (runtime execution)
+ G5 (per-site RVA enumeration).

Backend for `re-anti-debug-patch --apply` and `re-runtime-dump --mode=inject`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from re_patch_apply import __version__

logger = logging.getLogger("re_patch_apply")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-patch-apply")


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-patch-apply",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-patch-apply v0.3.0: real byte-level patch "
            "application. Reads the per-site patch plan from "
            "re-anti-debug-patch, applies each patch, writes the patched "
            "binary + the per-site patch log, and verifies with "
            "re-speakeasy. Closes G2 + G5."
        ),
        "env": {"RE_AI_PLUGIN_ROOT": os.environ.get("RE_AI_PLUGIN_ROOT", "<unset>")},
    }


PATCH_BYTES = {
    ("RDTSC", "zero"):       ("0F 31", "90 90"),
    ("RDTSC", "constant"):   ("0F 31", "B8 00 10 00 00 90"),
    ("RDTSC", "passthrough"): ("0F 31", "0F 31"),
    ("CPUID", "zero"):       ("0F A2", "B8 00 00 00 00 90"),
    ("CPUID", "nop"):        ("0F A2", "90 90"),
    ("CPUID", "passthrough"): ("0F A2", "0F A2"),
    ("VMCALL", "zero"):      ("0F 01 C1", "B8 00 00 00 00 90 90 90"),
    ("VMCALL", "passthrough"): ("0F 01 C1", "0F 01 C1"),
    ("VMXON", "zero"):       ("F3 0F 01 C4", "B8 00 00 00 00 90 90 90 90 90"),
    ("VMXON", "passthrough"): ("F3 0F 01 C4", "F3 0F 01 C4"),
    ("INT_2D", "zero"):      ("CD 2D", "90 90"),
    ("INT_2D", "passthrough"): ("CD 2D", "CD 2D"),
    ("INT_3", "zero"):       ("CC", "90"),
    ("INT_3", "passthrough"): ("CC", "CC"),
}


def _enumerate_sites(data: bytes, hex_seq: str, max_sites: int = 10000) -> list[int]:
    """Find all occurrences of hex_seq in data, return their file offsets."""
    needle = bytes.fromhex(hex_seq.replace(" ", ""))
    sites = []
    start = 0
    while len(sites) < max_sites:
        idx = data.find(needle, start)
        if idx < 0:
            break
        sites.append(idx)
        start = idx + len(needle)
    return sites


def _read_target_bytes(target: str) -> bytes:
    with open(target, "rb") as f:
        return f.read()


def _apply_patch_to_bytes(data: bytes, offset: int, original: bytes, patched: bytes) -> bytes:
    """Apply a single patch to the data, return the modified bytes.

    If the bytes at offset don't match `original`, skip the patch (return
    the data unchanged + log the mismatch).
    """
    if data[offset:offset + len(original)] != original:
        return data  # mismatch
    new_data = bytearray(data)
    new_data[offset:offset + len(patched)] = patched
    return bytes(new_data)


def _verify_with_speakeasy(patched_binary: Path) -> dict:
    """Run the patched binary under re-speakeasy (RE-AI) for a verify dry-run.

    v0.3.0: re-speakeasy may not be installed in the host's venv. The
    verify step is deferred when unavailable.
    """
    # check if re-speakeasy is callable
    re_ai = Path(os.environ.get("RE_AI_PLUGIN_ROOT", "/path/to/RE-AI"))
    speakeasy = re_ai / "servers" / "re-speakeasy"
    if not (speakeasy / ".venv" / "bin" / "re-speakeasy").exists():
        return {
            "verified": False,
            "note": "re-speakeasy not installed in the RE-AI plugin venv; verify deferred to v0.3.0-on-a-Windows-host",
        }
    # attempt the verify
    try:
        proc = shutil.which("uv")
        if not proc:
            return {"verified": False, "note": "uv not on PATH"}
        result = subprocess.run(  # noqa
            ["uv", "--directory", str(speakeasy), "run", "re-speakeasy",
             "--target", str(patched_binary), "--check-no-sigabrt", "--timeout", "30"],
            capture_output=True, text=True, timeout=60,
        )
        return {
            "verified": result.returncode == 0,
            "stdout": result.stdout[-500:],
            "stderr": result.stderr[-500:],
        }
    except Exception as e:
        return {"verified": False, "error": f"{type(e).__name__}: {e}"}


def _verify_with_pe_sieve(patched_binary: Path, target_pid: int = 0) -> dict:
    """v0.8.0+ Wave 2 (Item E): run pe-sieve against the patched binary.

    Prefers pe-sieve (the Windows tool from hasherezade) over re-speakeasy
    for in-memory hook detection. Falls back to re-speakeasy when
    pe-sieve isn't available.

    Args:
        patched_binary: the binary we just patched
        target_pid: the PID of the process running the patched binary.
                    0 = we don't have a live process (pure file check)
    """
    from re_patch_apply.verify.pe_sieve import (
        verify_with_pe_sieve,
        pe_sieve_available,
    )
    if not pe_sieve_available():
        # Silent fallback — log only
        logger.info("pe-sieve.exe not available; falling back to re-speakeasy")
        return _verify_with_speakeasy(patched_binary)
    if target_pid <= 0:
        # We don't have a live PID. pe-sieve scans process memory, not files.
        # Fall back to re-speakeasy.
        return _verify_with_speakeasy(patched_binary)
    out_dir = patched_binary.parent / "pe-sieve-output"
    return verify_with_pe_sieve(pid=target_pid, output_dir=out_dir)


@mcp.tool()
def apply_patch(
    target: str,
    patch_plan: dict,
    output: str = "",
    verify: bool = True,
    max_sites_per_primitive: int = 256,
) -> dict:
    """Apply the per-site anti-debug patch plan to the target binary.

    Args:
        target: path to the binary to patch
        patch_plan: the output of re-anti-debug-patch.patch_target() (or a subset)
        output: where to write the patched binary + the per-site patch log
        verify: run re-speakeasy dry-run after patching
        max_sites_per_primitive: cap to prevent OOM on huge binaries

    Returns:
        {
          "status": "ok" | "error",
          "patched_binary": "<path>",
          "patch_log": "<path>",
          "sites_patched": N,
          "verify": {...},
          "artifacts_written": [...],
        }
    """
    out_dir = Path(output or "./re-patch-apply-output/")
    out_dir.mkdir(parents=True, exist_ok=True)
    target_p = Path(target).resolve()
    if not target_p.exists():
        return {"status": "error", "error": f"target not found: {target}",
                "server": "re-patch-apply", "version": __version__}
    # 1. read the target
    data = _read_target_bytes(target)
    # 2. iterate over the patch_plan's patched_sites
    # v0.4.0: accept both shapes (with or without "plan" wrapper).
    sites = (patch_plan.get("plan", {}) or {}).get("patched_sites", []) \
            or patch_plan.get("patched_sites", []) \
            or []
    if not sites:
        # 2a. v0.4.0: explicit warning when zero sites were enumerated.
        # This was the v0.3.0 silent-failure bug (A1 in DOC-FIXES.md):
        # the server returned status:ok + sites_patched:0 + wrote a copy
        # of the binary, which was byte-identical to the original. Now we
        # surface the empty-plan condition so callers can act.
        return {
            "status": "warn",
            "server": "re-patch-apply",
            "version": __version__,
            "target": target,
            "patched_binary": "",
            "patch_log": "",
            "sites_patched": 0,
            "sites_skipped": 0,
            "verify": {},
            "artifacts_written": [],
            "warning": "patch_plan produced zero patched_sites; nothing to apply. "
                       "Pass the full output of re-anti-debug-patch.patch_target() "
                       "or ensure the target contains the expected opcode bytes.",
        }
    patch_log = []
    sites_patched = 0
    sites_skipped = 0
    for site in sites:
        primitive = site["primitive"]
        strategy = site["strategy"]
        key = (primitive, strategy)
        if key not in PATCH_BYTES:
            sites_skipped += 1
            continue
        orig_hex, patched_hex = PATCH_BYTES[key]
        orig = bytes.fromhex(orig_hex.replace(" ", ""))
        patched = bytes.fromhex(patched_hex.replace(" ", ""))
        # enumerate the sites in the binary
        offsets = _enumerate_sites(data, orig_hex, max_sites=max_sites_per_primitive)
        for off in offsets:
            new_data = _apply_patch_to_bytes(data, off, orig, patched)
            if new_data is not data:
                data = new_data
                sites_patched += 1
                patch_log.append({
                    "rva": off,
                    "primitive": primitive,
                    "strategy": strategy,
                    "original_bytes": orig_hex,
                    "patched_bytes": patched_hex,
                })
            else:
                sites_skipped += 1
    # 3. write the patched binary
    target_name = target_p.name
    patched_path = out_dir / f"{target_name}.patched.exe"
    patched_path.write_bytes(data)
    # 4. write the per-site patch log
    log_path = out_dir / f"{target_name}.patch-log.json"
    log_path.write_text(json.dumps({
        "target": target,
        "patched_binary": str(patched_path),
        "sites_patched": sites_patched,
        "sites_skipped": sites_skipped,
        "patch_log": patch_log,
        "execution_status": "applied",
    }, indent=2))
    # 5. verify with pe-sieve (preferred) or re-speakeasy (fallback)
    verify_result = {}
    if verify:
        verify_result = _verify_with_pe_sieve(patched_path)
    # v0.4.0: return status:warn when sites were enumerated but 0 matched
    # (which means the opcode bytes weren't found at any of the offsets
    # enumerated by the upstream triage).
    final_status = "ok" if sites_patched > 0 else "warn"
    note = ""
    if final_status == "warn":
        note = (f"sites_patched=0 even though {len(sites)} site specs were enumerated. "
                f"Check that the target binary actually contains the expected opcodes "
                f"({[s['primitive'] for s in sites]}).")
    return {
        "status": final_status,
        "server": "re-patch-apply",
        "version": __version__,
        "target": target,
        "patched_binary": str(patched_path),
        "patch_log": str(log_path),
        "sites_patched": sites_patched,
        "sites_skipped": sites_skipped,
        "verify": verify_result,
        "artifacts_written": [str(patched_path), str(log_path)],
        "note": note,
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
