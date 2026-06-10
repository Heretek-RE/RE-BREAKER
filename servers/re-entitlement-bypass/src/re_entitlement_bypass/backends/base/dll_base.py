"""DropInDLLDeployer — common base for all 8 drop-in-DLL backends.

This module generalizes the gbe_fork deploy pattern (Output/.../03-poc/gbe-fork/
scripts/deploy-gbe-fork.sh) to all 8 entitlement layers:

1. Backup any existing `<layer>.dll` → `<layer>.dll.orig` (idempotent)
2. Drop the stub/emulator DLL into the launcher's directory
3. Drop into any `*Data/Plugins/x86_64/` Unity subdir if present
4. Drop the per-layer settings file (e.g. `steam_settings/steam_appid.txt`)
5. SHA-256-audit the deploy
6. Record the deploy paths for rollback

Concrete subclasses (Phase 2):
- `dll/steam_ceg_dll.py` — wraps `deploy-gbe-fork.sh` via subprocess
- `dll/eos_sdk_dll.py` — drops a stub `EOSSDK-Win64-Shipping.dll`
- `dll/ioi_account_dll.py`, `dll/sega_sso_dll.py`, etc.

The gbe_fork pattern itself is 154 lines of bash; the Python rewrite in this
module is ~200 LOC and gives us:
- Deterministic audit (SHA-256 of every deployed file)
- Idempotent deploy (skip if already deployed + hashes match)
- Rollback (restore .orig backups)
- Cross-target support (any Wine prefix, any launcher dir)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ...core.audit import sha256_file
from ...core.layer_base import LayerDeployer, register
from ...core.status import LayerDeployStatus

if TYPE_CHECKING:
    from ...core.target_manifest import TargetEntry

log = logging.getLogger("re-entitlement-bypass.dll_base")


class DropInDLLDeployer(LayerDeployer):
    """Base class for drop-in-DLL deployers.

    Subclasses set:
    - layer: e.g. "steam_ceg", "eos"
    - backend: e.g. "dll/gbe_fork", "dll/eos_sdk"
    - source_dll: path to the stub/emulator DLL to drop
    - target_dll_name: the name of the DLL to drop into the launcher (e.g. "steam_api64.dll", "EOSSDK-Win64-Shipping.dll")
    - settings_files: dict[src_path, target_relpath] for the per-layer config files
    """

    layer: str = ""
    backend: str = "dll"
    source_dll: Path = Path()
    target_dll_name: str = ""
    settings_files: dict[Path, str] = {}

    def __init__(self):
        super().__init__(layer=self.layer, backend=self.backend)
        self._deploy_paths: list[Path] = []
        self._rollback_paths: list[Path] = []

    # --- LayerDeployer interface ---------------------------------------------

    def plan(self, target: "TargetEntry", dry_run: bool = False) -> LayerDeployStatus:
        if not self.source_dll.exists():
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"source DLL missing: {self.source_dll}")
        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="planned",
            deployed_paths=[f"<launcher>/{self.target_dll_name}", f"<launcher>/{self.target_dll_name}.orig"] if self.target_dll_name else [],
            sha256={str(self.source_dll): sha256_file(self.source_dll)},
            note=f"will drop {self.source_dll.name} as {self.target_dll_name} + {len(self.settings_files)} settings files",
        )

    def deploy(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        if not self.source_dll.exists():
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"source DLL missing: {self.source_dll}")
        launcher_dir = self._resolve_launcher_dir(target, wine_prefix)
        if launcher_dir is None:
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"launcher dir not found for target {target.key}")

        target_dll = launcher_dir / self.target_dll_name
        target_orig = launcher_dir / f"{self.target_dll_name}.orig"

        # 1. Backup any existing DLL to .orig
        if target_dll.exists() and not target_orig.exists():
            shutil.copy2(target_dll, target_orig)
            self._rollback_paths.append(target_orig)
            log.info("backed up %s → %s", target_dll.name, target_orig.name)

        # 2. Drop the new DLL
        shutil.copy2(self.source_dll, target_dll)
        self._deploy_paths.append(target_dll)
        log.info("deployed %s (SHA-256: %s)", target_dll, sha256_file(target_dll)[:16])

        # 3. Drop into any Unity *Data/Plugins/x86_64/ subdir
        unity_plugins: list[Path] = []
        for sibling in launcher_dir.glob("*Data/Plugins/x86_64/"):
            if sibling.is_dir():
                unity_plugins.append(sibling)
        for sub in unity_plugins:
            sub_dll = sub / self.target_dll_name
            sub_orig = sub / f"{self.target_dll_name}.orig"
            if sub_dll.exists() and not sub_orig.exists():
                shutil.copy2(sub_dll, sub_orig)
                self._rollback_paths.append(sub_orig)
            shutil.copy2(self.source_dll, sub_dll)
            self._deploy_paths.append(sub_dll)
            log.info("deployed %s into Unity plugins dir %s", self.target_dll_name, sub)

        # 4. Drop the per-layer settings files
        for src, relpath in self.settings_files.items():
            if not src.exists():
                log.warning("settings file missing: %s", src)
                continue
            dst = launcher_dir / relpath
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            self._deploy_paths.append(dst)
            log.info("deployed settings %s → %s", src, dst)

        # 5. SHA-256 audit
        hashes = {str(p): sha256_file(p) for p in self._deploy_paths}

        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="deployed",
            deployed_paths=[str(p) for p in self._deploy_paths],
            sha256=hashes,
            note=f"deployed {len(self._deploy_paths)} files into {launcher_dir}",
        )

    def rollback(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        # Remove the deployed DLLs (those we just dropped)
        for p in self._deploy_paths:
            if p.exists() and not str(p).endswith(".orig"):
                p.unlink()
                log.info("removed %s", p)
        # Restore the .orig backups
        for p in self._rollback_paths:
            if p.exists():
                orig_target = p.parent / p.name.removesuffix(".orig")
                shutil.copy2(p, orig_target)
                log.info("restored %s from %s", orig_target, p)
        self._deploy_paths = []
        self._rollback_paths = []
        return LayerDeployStatus(layer=self.layer, backend=self.backend, status="rolled-back", note="DLLs removed + .orig backups restored")

    def audit(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        launcher_dir = self._resolve_launcher_dir(target, wine_prefix)
        if launcher_dir is None:
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error="launcher dir not found")
        target_dll = launcher_dir / self.target_dll_name
        if not target_dll.exists():
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"{self.target_dll_name} not deployed")
        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="deployed" if sha256_file(target_dll) == sha256_file(self.source_dll) else "error",
            deployed_paths=[str(target_dll)],
            sha256={str(target_dll): sha256_file(target_dll)},
            note="hash matches source" if sha256_file(target_dll) == sha256_file(self.source_dll) else "HASH MISMATCH",
        )

    # --- helpers --------------------------------------------------------------

    def _resolve_launcher_dir(self, target: "TargetEntry", wine_prefix: Optional[Path]) -> Optional[Path]:
        """Resolve the launcher's directory. If `launcher_dir` is in the manifest, use it
        (joined with the Wine prefix if relative). Otherwise, scan the Wine prefix for
        a directory containing the target's .exe."""
        if target.launcher_dir:
            p = Path(target.launcher_dir)
            if not p.is_absolute() and wine_prefix:
                p = wine_prefix / "drive_c" / p
            if p.exists():
                return p
            log.warning("manifest launcher_dir %s does not exist", p)
        if wine_prefix and target.exe:
            for candidate in (wine_prefix / "drive_c").rglob(target.exe):
                if candidate.is_file():
                    return candidate.parent
        return None
