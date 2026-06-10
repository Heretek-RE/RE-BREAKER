"""DeployStatus pydantic model — the per-layer deploy result."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

# Per-layer status taxonomy
LayerStatus = Literal[
    "planned",       # plan() succeeded; no writes
    "deployed",      # deploy() succeeded; files/certs/hosts in place
    "rolled-back",   # rollback() succeeded; previous state restored
    "refused",       # SOW gate or other refusal
    "re-only",       # layer is RE-only (no deploy), e.g. denuvo on Wine
    "error",         # unexpected failure
    "stub",          # layer is a stub (scaffold-only); reverse from binary before live use
]


class LayerDeployStatus(BaseModel):
    """The per-layer deploy result."""

    layer: str = Field(..., description="Layer name (e.g. 'steam_ceg', 'eos', 'atlus')")
    backend: str = Field(..., description="Backend used (e.g. 'dll/steam_ceg_dll', 'http/eos', 'hypervisor/denuvo')")
    status: LayerStatus = Field(..., description="Final status")
    deployed_paths: list[str] = Field(default_factory=list, description="Files written/copied (for rollback)")
    sha256: Optional[dict[str, str]] = Field(default=None, description="Per-deployed-path SHA-256 hash")
    hosts_lines: list[str] = Field(default_factory=list, description="Hosts file lines added (for HTTP backends)")
    bind: Optional[str] = Field(default=None, description="Bind address for HTTP backends (127.0.0.1:8443 etc.)")
    note: Optional[str] = Field(default=None, description="Free-form note (e.g. 'requires Windows host' for RE-only layers)")
    error: Optional[str] = Field(default=None, description="Error message if status == 'error'")


class DeployStatus(BaseModel):
    """The per-target deploy result (the orchestrator's return value)."""

    target: str = Field(..., description="Target key (e.g. 'fm26', 'hkia', 'cd')")
    sow: Optional[str] = Field(None, description="SOW letter (e.g. 'M', 'N', 'O')")
    sow_gate: Literal["ok", "refused"] = Field(..., description="SOW gate verdict")
    sow_gate_reason: Optional[str] = Field(None, description="Refusal reason if sow_gate == 'refused'")
    layers: dict[str, LayerDeployStatus] = Field(default_factory=dict, description="Per-layer status")
    dry_run: bool = Field(False, description="True if this was a plan-only call")
    duration_sec: float = Field(0.0, description="Total time spent in deploy()")

    def to_json(self) -> str:
        """Return a JSON representation suitable for `re-ee emulate --json` output."""
        return self.model_dump_json(indent=2)
