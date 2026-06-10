"""v0.8.0+ Wave 2 (Item E) — pe-sieve wrapper for re-patch-apply.

pe-sieve (hasherezade/pe-sieve, 2.4k+ stars) scans a Windows process's
memory for in-memory hooks and implanted PEs. It runs against a live
process (not a file), so we use it to verify that our patched binary
has no unexpected hooks when loaded into a target process.

The CLI:
    pe-sieve.exe /pid <pid> /ofolder <output> /json

The JSON output lists each detected hook + implanted PE with a confidence
score. We aggregate the per-section counts into a single confidence metric.

If pe-sieve.exe isn't on PATH, the wrapper returns `available=False` so
the caller can fall back to re-speakeasy.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional


log = logging.getLogger("re-patch-apply.verify.pe_sieve")


# pe-sieve is Windows-only. On Linux, callers should run it in a Windows
# VM + scan a copy of the patched binary loaded into a sacrificial process.
PE_SIEVE_WINDOWS_ONLY = True


def _pe_sieve_exe() -> Optional[Path]:
    """Find pe-sieve.exe on PATH or in the vendored location."""
    env_path = os.environ.get("RE_BREAKER_PE_SIEVE_PATH")
    if env_path and Path(env_path).is_file():
        return Path(env_path)
    on_path = shutil.which("pe-sieve") or shutil.which("pe-sieve.exe")
    if on_path:
        return Path(on_path)
    # vendored
    plugin_root = Path(os.environ.get("RE_BREAKER_PLUGIN_ROOT", "os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")"))
    vendored = plugin_root / "vendored" / "pe-sieve" / "pe-sieve.exe"
    if vendored.is_file():
        return vendored
    return None


def pe_sieve_available() -> bool:
    """True iff pe-sieve.exe is on PATH or in the vendored location."""
    return _pe_sieve_exe() is not None


def verify_with_pe_sieve(
    pid: int,
    output_dir: Path,
    timeout_s: int = 60,
) -> dict:
    """Run pe-sieve against a live process and return a structured verdict.

    Args:
        pid: the host PID of the process to scan
        output_dir: where to write pe-sieve's JSON report
        timeout_s: max seconds for the scan

    Returns:
        {
          "available": bool,
          "verified": bool,
          "scanned": int,
          "hooked": int,
          "implanted": int,
          "confidence": float,  # 1.0 - (hooked + implanted) / scanned
          "per_section": {...},
          "report_path": str,
          "raw": dict (if available),
          "note": str,
        }
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    exe = _pe_sieve_exe()
    if exe is None:
        return {
            "available": False,
            "verified": False,
            "note": (
                "pe-sieve.exe not on PATH. Set RE_BREAKER_PE_SIEVE_PATH or "
                "download from hasherezade/pe-sieve to vendored/pe-sieve/. "
                "Falling back to re-speakeasy dry-run."
            ),
        }
    if PE_SIEVE_WINDOWS_ONLY and os.name != "nt":
        # We're on Linux. pe-sieve.exe needs Wine to run.
        wine = shutil.which("wine")
        if not wine:
            return {
                "available": False,
                "verified": False,
                "note": (
                    "pe-sieve is Windows-only. We're on Linux. Install Wine "
                    "to run pe-sieve.exe under Wine, OR scan the patched "
                    "binary in a Windows VM + report the result back."
                ),
            }
        cmd = [wine, str(exe), "/pid", str(pid), "/ofolder", str(output_dir), "/json"]
    else:
        cmd = [str(exe), "/pid", str(pid), "/ofolder", str(output_dir), "/json"]
    report_path = output_dir / f"pe-sieve-{pid}.json"
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
        )
        # pe-sieve writes the JSON to a file in ofolder
        # (not stdout). The exact filename is `<exe_name>.json` or
        # `process_<pid>.json` depending on version.
        actual_report = None
        for candidate in (output_dir / f"process_{pid}.json",
                          output_dir / f"{pid}.json",
                          report_path):
            if candidate.is_file():
                actual_report = candidate
                break
        if actual_report is None:
            # pe-sieve may have written to <pid>.<exe>.json
            for p in output_dir.glob(f"*{pid}*.json"):
                actual_report = p
                break
        if actual_report is None:
            return {
                "available": True,
                "verified": False,
                "report_path": str(report_path),
                "note": f"pe-sieve ran (rc={result.returncode}) but no JSON report found in {output_dir}",
                "stdout_tail": result.stdout[-200:],
                "stderr_tail": result.stderr[-200:],
            }
        report = json.loads(actual_report.read_text())
        return _parse_pe_sieve_report(report, actual_report)
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "verified": False,
            "error": f"pe-sieve timed out after {timeout_s}s",
            "report_path": str(report_path),
        }
    except Exception as e:
        return {
            "available": True,
            "verified": False,
            "error": f"{type(e).__name__}: {e}",
            "report_path": str(report_path),
        }


def _parse_pe_sieve_report(report: dict, report_path: Path) -> dict:
    """Convert pe-sieve's JSON output into our standard shape.

    pe-sieve's report shape (v0.4+):
        {
          "pid": 1234,
          "modules": [
            {
              "name": "game.dll",
              "path": "...",
              "scanned": true,
              "hooked": 0,
              "iat_hooked": 0,
              "implanted": 0,
              "header": {...},
              "sections": [...]
            },
            ...
          ],
          "scanned": <total scanned>,
          "hooked": <total hooked>,
          "implanted": <total implanted>,
        }
    """
    modules = report.get("modules", [])
    total_scanned = sum(1 for m in modules if m.get("scanned"))
    total_hooked = sum(m.get("hooked", 0) for m in modules)
    total_implanted = sum(m.get("implanted", 0) for m in modules)
    total_iat_hooked = sum(m.get("iat_hooked", 0) for m in modules)
    per_section: dict[str, dict] = {}
    for m in modules:
        name = m.get("name", "<unknown>")
        per_section[name] = {
            "scanned": m.get("scanned", False),
            "hooked": m.get("hooked", 0),
            "iat_hooked": m.get("iat_hooked", 0),
            "implanted": m.get("implanted", 0),
        }
    denominator = max(total_scanned, 1)
    confidence = 1.0 - (total_hooked + total_implanted + total_iat_hooked) / denominator
    confidence = max(0.0, min(1.0, confidence))
    return {
        "available": True,
        "verified": True,
        "scanned": total_scanned,
        "hooked": total_hooked,
        "iat_hooked": total_iat_hooked,
        "implanted": total_implanted,
        "confidence": round(confidence, 3),
        "per_module": per_section,
        "report_path": str(report_path),
        "raw_report_keys": list(report.keys()),
        "note": (
            f"pe-sieve v0.4+ report: {total_scanned} modules scanned, "
            f"{total_hooked} inline hooks + {total_iat_hooked} IAT hooks + "
            f"{total_implanted} implants detected. "
            f"Confidence: {confidence:.1%}"
        ),
    }


__all__ = ["verify_with_pe_sieve", "pe_sieve_available"]
