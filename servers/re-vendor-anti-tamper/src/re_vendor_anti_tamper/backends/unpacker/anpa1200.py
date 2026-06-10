"""v0.8.0+ Wave 2 (Item F) — anpa1200/Unpacker wrapper for re-vendor-anti-tamper.

anpa1200/Unpacker (https://github.com/anpa1200/Unpacker) integrates:
  - Unipacker (32-bit) — for legacy VMProtect / Themida 32-bit
  - Qiling (64-bit)     — for modern VMProtect 3.x 64-bit + Themida 64-bit

Replaces the 404'd samrashaikh/Themida-Unpacker reference in the v0.2.0
recipe table.

Usage:
    from re_vendor_anti_tamper.backends.unpacker.anpa1200 import unpack
    result = unpack(target, vendor="vmprotect", mode="auto")

Returns:
    {
      "status": "ok" | "error" | "dry-run",
      "vendor": str,
      "backend": "unipacker" | "qiling" | "auto",
      "unpacked_path": str,
      "diagnostics": dict,
    }
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Literal

log = logging.getLogger("re-vendor-anti-tamper.unpacker.anpa1200")


# Locations the anpa1200 repo can live:
#   1. $RE_BREAKER_PLUGIN_ROOT/vendored/anpa1200-Unpacker/  (preferred)
#   2. /path/to/anpa1200-Unpacker/             (sibling of RE-BREAKER)
#   3. $ANPA1200_UNPACKER_PATH                               (env override)


def _anpa1200_root() -> Path | None:
    env = os.environ.get("ANPA1200_UNPACKER_PATH")
    if env and Path(env).is_dir():
        return Path(env)
    plugin_root = os.environ.get("RE_BREAKER_PLUGIN_ROOT", "os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")")
    vendored = Path(plugin_root) / "vendored" / "anpa1200-Unpacker"
    if vendored.is_dir() and (vendored / "unpacker").is_dir():
        return vendored
    sibling = Path("/path/to/anpa1200-Unpacker")
    if sibling.is_dir():
        return sibling
    return None


def is_available() -> bool:
    """True iff anpa1200/Unpacker is cloned somewhere we can find it."""
    return _anpa1200_root() is not None


def _select_backend(target: Path, vendor: str) -> Literal["unipacker", "qiling", "auto"]:
    """Pick the right backend based on the target's bitness.

    - 32-bit → Unipacker
    - 64-bit → Qiling
    - default → "auto" (anpa1200 picks based on PE header)
    """
    if not target.is_file():
        return "auto"
    try:
        with open(target, "rb") as f:
            dos_stub = f.read(0x40)
            if len(dos_stub) < 0x40:
                return "auto"
            pe_offset = int.from_bytes(dos_stub[0x3C:0x40], "little")
            f.seek(pe_offset + 4)  # skip "PE\0\0"
            coff = f.read(20)
            if len(coff) < 20:
                return "auto"
            machine = int.from_bytes(coff[0:2], "little")
            # 0x14c = IMAGE_FILE_MACHINE_I386 (32-bit)
            # 0x8664 = IMAGE_FILE_MACHINE_AMD64 (64-bit)
            if machine == 0x14c:
                return "unipacker"
            if machine == 0x8664:
                return "qiling"
    except OSError:
        pass
    return "auto"


def unpack(
    target: str,
    vendor: Literal["vmprotect", "themida"] = "vmprotect",
    output: str = "",
    timeout_s: int = 300,
    mode: Literal["auto", "unipacker", "qiling", "dry-run"] = "auto",
) -> dict:
    """Unpack a VMProtect or Themida-protected binary via anpa1200/Unpacker.

    Args:
        target: path to the protected binary
        vendor: which anti-tamper vendor we're unpacking
        output: directory for the unpacked binary (default: ./re-vendor-anti-tamper-output/unpacker/)
        timeout_s: max seconds
        mode:
            - "auto": pick the backend based on PE bitness
            - "unipacker": force 32-bit Unipacker
            - "qiling": force 64-bit Qiling
            - "dry-run": generate the plan but don't actually run

    Returns:
        {
          "status": "ok" | "error" | "dry-run",
          "vendor": str,
          "backend": str,
          "unpacked_path": str,
          "diagnostics": dict,
          "note": str,
        }
    """
    target_p = Path(target).resolve()
    out_dir = Path(output or "./re-vendor-anti-tamper-output/unpacker/")
    out_dir.mkdir(parents=True, exist_ok=True)
    if mode == "dry-run":
        if not target_p.is_file():
            # The target may not exist yet (plan-only mode). Return a
            # dry-run plan anyway with a warning.
            return {
                "status": "dry-run",
                "vendor": vendor,
                "backend": "auto",
                "target": str(target_p),
                "output_dir": str(out_dir),
                "note": "dry-run: target doesn't exist yet; cannot select backend. "
                        "anpa1200 must be cloned into vendored/anpa1200-Unpacker/ first.",
            }
        return {
            "status": "dry-run",
            "vendor": vendor,
            "backend": _select_backend(target_p, vendor),
            "target": str(target_p),
            "output_dir": str(out_dir),
            "note": "dry-run: would invoke anpa1200's selected backend. "
                     "anpa1200 must be cloned into vendored/anpa1200-Unpacker/ first.",
        }
    if not target_p.is_file():
        return {
            "status": "error",
            "error": f"target not found: {target_p}",
            "server": "re-vendor-anti-tamper",
        }
    root = _anpa1200_root()
    if root is None:
        return {
            "status": "error",
            "error": "anpa1200/Unpacker not found. Clone it into vendored/anpa1200-Unpacker/ "
                     "or set $ANPA1200_UNPACKER_PATH. See vendored/anpa1200-Unpacker/README.md.",
            "vendor": vendor,
            "server": "re-vendor-anti-tamper",
        }
    backend = "auto" if mode == "auto" else mode
    if backend == "auto":
        backend = _select_backend(target_p, vendor)
    cmd = ["python3", str(root / "unpacker" / "__main__.py"),
           "--target", str(target_p),
           "--vendor", vendor,
           "--backend", backend,
           "--output", str(out_dir)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
            cwd=str(root),
        )
        if result.returncode != 0:
            return {
                "status": "error",
                "error": f"anpa1200 exited with rc={result.returncode}",
                "vendor": vendor,
                "backend": backend,
                "stdout_tail": result.stdout[-500:],
                "stderr_tail": result.stderr[-500:],
            }
        # Find the unpacked binary in the output dir
        unpacked_files = sorted(
            out_dir.glob("*.unpacked.exe"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ) or sorted(
            out_dir.glob("*.exe"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        unpacked_path = str(unpacked_files[0]) if unpacked_files else None
        return {
            "status": "ok",
            "vendor": vendor,
            "backend": backend,
            "unpacked_path": unpacked_path,
            "diagnostics": {
                "stdout_tail": result.stdout[-500:],
                "stderr_tail": result.stderr[-500:],
                "output_dir_contents": [p.name for p in out_dir.iterdir()],
            },
            "note": f"v0.8.0+ Wave 2 (Item F): anpa1200 unpack via {backend}.",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": f"anpa1200 timed out after {timeout_s}s",
            "vendor": vendor,
            "backend": backend,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "vendor": vendor,
            "backend": backend,
        }


__all__ = ["unpack", "is_available"]
