"""target_manifest — the per-target layer mapping (single source of truth).

The orchestrator reads `data/targets.json` to resolve:
- which layers a target needs
- which SOW the target is under
- which launcher .exe to deploy into
- which Steam AppID (if any) to drop in `steam_settings/steam_appid.txt`

v0.2.0 ships the 7 targets from the 2026-06-08 live-fire engagement. New
targets can be added by appending to `data/targets.json`.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

log = logging.getLogger("re-entitlement-bypass.target_manifest")


class TargetEntry(BaseModel):
    """A single target's manifest entry."""

    key: str = Field(..., description="Target key (e.g. 'fm26', 'hkia')")
    sow: Optional[str] = Field(None, description="SOW letter (e.g. 'M', 'O') or null for stress-test")
    exe: str = Field(..., description="Main launcher .exe (e.g. 'fm.exe', 'Warhammer3.exe')")
    dir_name: Optional[str] = Field(None, description="Directory name under Input/ (defaults to target.key if not set)")
    launcher_dir: Optional[str] = Field(None, description="Default launcher dir (relative to Wine prefix drive_c); auto-resolved if None")
    appid: Optional[str] = Field(None, description="Steam AppID; auto-detected from binary if None")
    layers: list[str] = Field(default_factory=list, description="Entitlement layers this target needs")
    denuvo_check: Optional[str] = Field(None, description="Phase-1 denuvo-presence check verdict (e.g. 'present', 'absent', 'phase-1')")
    denuvo_carveout: bool = Field(False, description="True if Denuvo ATD is carve-out for this target (SOW-X §P.1)")
    notes: Optional[str] = Field(None, description="Free-form engagement notes")


# The default manifest, embedded here so the orchestrator works without
# requiring `data/targets.json` to be loadable (useful for tests + dry-run).
# The on-disk `data/targets.json` is the same content; this is the fallback.
DEFAULT_TARGETS: dict[str, dict] = {
    "fm26": {
        "sow": "M",
        "exe": "fm.exe",
        "layers": ["steam_ceg", "eos", "sega_sso"],
        "notes": "Football Manager 26 (SEGA / Sports Interactive). Cinematic wall at v0.4.1.9.",
    },
    "hkia": {
        "sow": "N",
        "exe": "HelloKittyIslandAdventure.exe",
        "appid": "70503",
        "layers": ["steam_ceg", "sunblink"],
        "notes": "Hello Kitty Island Adventure (Sunblink). Server-reachability dialog blocks main menu.",
    },
    "007fl": {
        "sow": "L",
        "exe": "007FirstLight.exe",
        "layers": ["steam_ceg", "ioi"],
        "notes": "007 First Light (IO Interactive). Hits Wine cryptasn SPC page fault (SPC spcSpAgencyInfo OID 1.3.6.1.4.1.311.2.1.4 missing).",
    },
    "tww3": {
        "sow": "Q",
        "exe": "Warhammer3.exe",
        "appid": "1142710",
        "layers": ["steam_ceg", "eos"],
        "notes": "Total War: WARHAMMER III (CA / Microsoft). Hits Wine SEH invalid frame from 18 VMCALL sites (CA Clockwork framework).",
    },
    "p3r": {
        "sow": "P",
        "exe": "P3R.exe",
        "layers": ["steam_ceg", "atlus"],
        "denuvo_check": "phase-1",
        "denuvo_carveout": True,
        "notes": "Persona 3 Reload (SEGA / Atlus). UE5 + custom ATD (Denuvo-style carve-out per SOW-X §P.1). WinInet 12029 retry loop blocks main menu.",
    },
    "lir": {
        "sow": None,
        "exe": "LostInRandom.exe",
        "layers": ["origin"],
        "notes": "Lost In Random (EA / stress-test only, no SOW). .orig pollution from prior failed patcher run; needs full Origin client-stack emulator.",
    },
    "cd": {
        "sow": "O",
        "exe": "CrimsonDesert.exe",
        "layers": ["steam_ceg", "pa"],
        "denuvo_check": "phase-1",
        "notes": "Crimson Desert (Pearl Abyss). BlackSpace engine + Denuvo. Steam CEG layer defeated via gbe_fork; Denuvo hypervisor bypass via DenuvOwO (RE-only on Wine).",
    },
}


class TargetManifest:
    """The per-target layer manifest, loaded from `data/targets.json` (or DEFAULT_TARGETS)."""

    def __init__(self, data: Optional[dict[str, dict]] = None, data_path: Optional[Path] = None):
        if data is not None:
            self._data = data
        elif data_path is not None and data_path.exists():
            self._data = json.loads(data_path.read_text())
        else:
            self._data = DEFAULT_TARGETS

    @property
    def target_keys(self) -> list[str]:
        return sorted(self._data.keys())

    def has(self, target: str) -> bool:
        return target in self._data

    def get(self, target: str) -> TargetEntry:
        if target not in self._data:
            raise KeyError(f"Unknown target '{target}'; valid targets: {self.target_keys}")
        return TargetEntry(key=target, **self._data[target])

    def layers_for(self, target: str) -> list[str]:
        return self.get(target).layers

    def sow_for(self, target: str) -> Optional[str]:
        return self.get(target).sow

    @classmethod
    def load_default(cls) -> "TargetManifest":
        """Load the default manifest from `data/targets.json` next to the package."""
        # Walk up from this file to find data/targets.json
        here = Path(__file__).resolve()
        for ancestor in here.parents:
            candidate = ancestor / "data" / "targets.json"
            if candidate.exists():
                return cls(data_path=candidate)
        return cls(data=None)  # fallback to embedded defaults
