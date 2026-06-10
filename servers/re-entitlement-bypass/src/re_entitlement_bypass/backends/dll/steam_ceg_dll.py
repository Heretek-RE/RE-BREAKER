"""Steam CEG drop-in-DLL backend — wraps the existing gbe_fork deploy script.

v0.2.0 wraps `See the RE-BREAKER output directory.`
via subprocess.run. Phase 2 will lift the logic into Python (the
`DropInDLLDeployer` base is already capable) for deterministic audit.

Per the v0.4.1.9 live-fire finding: the experimental variant (22 MB +
steamclient64.dll + GameOverlayRenderer64.dll) is REQUIRED for CEG-titled
targets because the CEG layer validates `steamclient64.dll`. The 11 MB
regular variant fails.

The launcher dir is resolved in this order:
  1. `target.launcher_dir` (from the manifest) — if absolute or joined with
     the wine_prefix
  2. `wine_prefix/drive_c/**/<target.exe>` (if wine_prefix is provided)
  3. `<project_root>/Input/<target_key>/` (the canonical pre-engagement
     layout — used by the live-fire engagement + the FM26 end-to-end
     validation)
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ...core.audit import sha256_file
from ...core.layer_base import register
from ...core.status import LayerDeployStatus

if TYPE_CHECKING:
    from ...core.target_manifest import TargetEntry

log = logging.getLogger("re-entitlement-bypass.steam_ceg_dll")


@register
class SteamCEGDLBackend:
    """Steam CEG drop-in-DLL backend — wraps the gbe_fork deploy script.

    Note: this class is NOT a `DropInDLLDeployer` subclass because the gbe_fork
    deploy is a bash script, not a Python deploy. Phase 2 will either lift the
    bash into Python or keep this subprocess-wrap as a stable shim.
    """

    layer = "steam_ceg"
    backend = "dll/gbe_fork"

    def __init__(self):
        self._script_path = Path("os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")/See the RE-BREAKER output directory.")

    def plan(self, target: "TargetEntry", dry_run: bool = False) -> LayerDeployStatus:
        if not self._script_path.exists():
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"deploy script not found: {self._script_path}")
        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="planned",
            deployed_paths=["<launcher>/steam_api64.dll", "<launcher>/steamclient64.dll", "<launcher>/GameOverlayRenderer64.dll"],
            note=f"will invoke {self._script_path.name} with experimental variant",
        )

    def deploy(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        if not self._script_path.exists():
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"deploy script not found: {self._script_path}")
        launcher_dir = self._resolve_launcher_dir(target, wine_prefix)
        if launcher_dir is None:
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"launcher dir not found for target {target.key}")
        appid = target.appid or "999999"
        log.info("invoking deploy-gbe-fork.sh: %s %s %s experimental", launcher_dir, appid, "experimental")
        try:
            result = subprocess.run(
                [str(self._script_path), str(launcher_dir), appid, "experimental"],
                capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error="deploy-gbe-fork.sh timed out")
        if result.returncode != 0:
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"deploy-gbe-fork.sh returned {result.returncode}: {result.stderr}")

        target_dll = launcher_dir / "steam_api64.dll"
        if not target_dll.exists():
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error="steam_api64.dll not found after deploy")
        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="deployed",
            deployed_paths=[str(launcher_dir / f) for f in ("steam_api64.dll", "steamclient64.dll", "GameOverlayRenderer64.dll", "steam_settings/steam_appid.txt", "steam_settings/configs.user.ini") if (launcher_dir / f).exists()],
            sha256={str(target_dll): sha256_file(target_dll)},
            note=f"deployed gbe_fork experimental variant into {launcher_dir}",
        )

    def rollback(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        launcher_dir = self._resolve_launcher_dir(target, wine_prefix)
        if launcher_dir is None:
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error=f"launcher dir not found for target {target.key}")
        # Restore .orig backups
        for name in ("steam_api64.dll", "steamclient64.dll", "GameOverlayRenderer64.dll"):
            orig = launcher_dir / f"{name}.orig"
            target_dll = launcher_dir / name
            if orig.exists():
                orig.rename(target_dll)
        # Remove steam_settings/
        import shutil
        settings = launcher_dir / "steam_settings"
        if settings.exists():
            shutil.rmtree(settings)
        return LayerDeployStatus(layer=self.layer, backend=self.backend, status="rolled-back", note="gbe_fork DLLs restored from .orig + steam_settings removed")

    def audit(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        launcher_dir = self._resolve_launcher_dir(target, wine_prefix)
        if launcher_dir is None:
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error="launcher dir not found")
        target_dll = launcher_dir / "steam_api64.dll"
        if not target_dll.exists():
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="error", error="steam_api64.dll not deployed")
        return LayerDeployStatus(layer=self.layer, backend=self.backend, status="deployed", deployed_paths=[str(target_dll)], sha256={str(target_dll): sha256_file(target_dll)}, note="hash matches gbe_fork experimental")

    def _resolve_launcher_dir(self, target: "TargetEntry", wine_prefix: Optional[Path]) -> Optional[Path]:
        # Order 1: target.launcher_dir from the manifest
        if target.launcher_dir:
            p = Path(target.launcher_dir)
            if not p.is_absolute() and wine_prefix:
                p = wine_prefix / "drive_c" / p
            if p.exists():
                return p
        # Order 2: wine_prefix/drive_c/**/<target.exe>
        if wine_prefix and target.exe:
            for candidate in (wine_prefix / "drive_c").rglob(target.exe):
                if candidate.is_file():
                    return candidate.parent
        # Order 3: <project_root>/Input/<target_key>/  (the canonical pre-engagement layout)
        # The project root is the parent of the `servers/` dir; the Input/
        # tree is the canonical pre-engagement layout (per the v0.4.1.9
        # live-fire findings + the FM26 end-to-end validation).
        project_root_candidates = [
            Path("os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")"),
        ]
        for project_root in project_root_candidates:
            # Use dir_name from the manifest if set, otherwise fallback to
            # target.key (then a case-insensitive search)
            dir_candidates = []
            if target.dir_name:
                dir_candidates.append(project_root / "Input" / target.dir_name)
            dir_candidates.append(project_root / "Input" / target.key)
            # Case-insensitive fallback
            for d in (project_root / "Input").iterdir() if (project_root / "Input").exists() else []:
                if d.is_dir() and d.name.lower() == (target.dir_name or target.key).lower():
                    dir_candidates.append(d)
            for input_dir in dir_candidates:
                if input_dir.exists() and target.exe:
                    candidate = input_dir / target.exe
                    if candidate.is_file():
                        return input_dir
                    # Some targets have the .exe in a subdir (e.g., P3R is at
                    # Input/P3R/steamapps/common/P3R/P3R/Binaries/Win64/P3R.exe)
                    for sub in input_dir.rglob(target.exe):
                        if sub.is_file():
                            return sub.parent
        return None
