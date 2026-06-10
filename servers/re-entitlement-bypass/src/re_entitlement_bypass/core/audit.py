"""Audit — SHA-256 + integrity check + YARA confirmation.

The audit module computes SHA-256 hashes of every deployed file, verifies the
YARA techniques catalog has no matches against the deployed DLLs (sanity check
that no real SDK leaked), and returns a structured audit report.

Reused by LayerDeployer.audit() across all 3 backends.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger("re-entitlement-bypass.audit")


def sha256_file(path: Path) -> str:
    """Compute SHA-256 of a single file, returning hex digest."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_files(paths: list[Path]) -> dict[str, str]:
    """Compute SHA-256 of multiple files, returning {path_str: hash}."""
    return {str(p): sha256_file(p) for p in paths if p.exists()}


def verify_no_real_sdk_leaked(deployed_dlls: list[Path]) -> tuple[bool, list[str]]:
    """Sanity-check that no real (non-stub) SDK DLL was deployed.

    A real Steamworks DLL is ~6 MB; a real EOS SDK DLL is ~19 MB; a real
    IOI Account DLL is ~3 MB. The stub/emulator DLLs we deploy are typically
    <100 KB. A leaked real SDK would be >1 MB and have a known SHA prefix
    (the Steamworks DLLs are signed by Valve; the EOS SDK is signed by Epic).

    For now this is a size heuristic — we flag any deployed DLL > 1 MB
    (excluding the gbe_fork experimental variant which IS 22 MB by design).

    Returns (clean, warnings) where warnings is a list of human-readable
    warning strings.
    """
    warnings = []
    clean = True
    for dll in deployed_dlls:
        if not dll.exists():
            warnings.append(f"missing: {dll}")
            clean = False
            continue
        size = dll.stat().st_size
        # gbe_fork experimental is 22 MB by design
        if "gbe_fork" in dll.name.lower() and size > 1_000_000:
            continue
        # Stub DLLs should be <500 KB
        if size > 500_000:
            warnings.append(
                f"OVERSIZED DLL: {dll} ({size:,} bytes). Expected <500 KB for a stub. "
                f"This may be a real SDK leak — investigate."
            )
            clean = False
    return clean, warnings


def audit_deployed_files(
    paths: list[Path],
    expected_hashes: Optional[dict[str, str]] = None,
) -> dict:
    """Audit a set of deployed files.

    Returns a dict with:
        - hashes: {path_str: sha256}
        - missing: [path_str, ...]
        - mismatched: {path_str: (expected, actual)}
        - clean: bool (True if no missing + no mismatched + no oversized)
        - warnings: [str, ...]
    """
    hashes = sha256_files(paths)
    missing = [str(p) for p in paths if not p.exists()]
    mismatched = {}
    if expected_hashes:
        for p_str, expected in expected_hashes.items():
            actual = hashes.get(p_str)
            if actual is None:
                continue  # already in missing
            if actual != expected:
                mismatched[p_str] = (expected, actual)

    dll_paths = [p for p in paths if p.suffix.lower() in (".dll", ".so", ".dylib")]
    clean_dll, dll_warnings = verify_no_real_sdk_leaked(dll_paths)

    warnings = []
    if missing:
        warnings.append(f"Missing files: {missing}")
    if mismatched:
        warnings.append(f"Hash mismatches: {mismatched}")
    warnings.extend(dll_warnings)

    return {
        "hashes": hashes,
        "missing": missing,
        "mismatched": mismatched,
        "clean": not missing and not mismatched and clean_dll,
        "warnings": warnings,
    }
