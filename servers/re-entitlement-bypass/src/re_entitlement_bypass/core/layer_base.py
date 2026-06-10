"""LayerDeployer — abstract base class for all 3 backend patterns.

The orchestrator dispatches to a LayerDeployer per (target, layer, backend)
combination. There are 3 concrete backends:
- HTTPEmulatorDeployer (backends/base/http_base.py) — Python HTTP emulator
- DropInDLLDeployer (backends/base/dll_base.py) — drop-in-DLL installer
- HypervisorDeployer (backends/hypervisor/) — RE-only on Wine (Phase 3)

Each backend registers itself in LAYER_REGISTRY (a dict mapping layer name to
deployer class). The orchestrator iterates target.layers, looks up the
deployer, and dispatches.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from .status import LayerDeployStatus

if TYPE_CHECKING:
    from .target_manifest import TargetEntry

log = logging.getLogger("re-entitlement-bypass.layer_base")


class LayerDeployer(ABC):
    """Abstract base for all entitlement-layer deployers.

    Concrete subclasses implement plan(), deploy(), rollback(), audit().
    The orchestrator iterates (target, layer) pairs and dispatches.
    """

    #: The layer this deployer handles (e.g. "steam_ceg", "eos", "atlus")
    layer: str = ""

    #: The backend pattern (e.g. "dll/gbe_fork", "http", "hypervisor/denuvo")
    backend: str = ""

    def __init__(self, layer: str, backend: str):
        self.layer = layer
        self.backend = backend

    @abstractmethod
    def plan(self, target: "TargetEntry", dry_run: bool = False) -> LayerDeployStatus:
        """Plan the deploy — what files would be written, what hosts entries added, what certs generated.

        Returns a LayerDeployStatus with status="planned" (or "stub" if the
        layer is a scaffold-only stub that needs RE before live use).
        """
        raise NotImplementedError

    @abstractmethod
    def deploy(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        """Execute the deploy — write files, start emulators, etc.

        Returns a LayerDeployStatus with status="deployed" (or "error" on failure).
        """
        raise NotImplementedError

    @abstractmethod
    def rollback(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        """Undo the last deploy — restore .orig backups, stop emulators, etc."""
        raise NotImplementedError

    @abstractmethod
    def audit(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        """Re-verify the deploy without re-deploying.

        Returns a LayerDeployStatus with the current audit state.
        """
        raise NotImplementedError


# -----------------------------------------------------------------------------
# The registry — populated by the backends on import.
# Keyed by (layer, backend_kind) where backend_kind is 'http' or 'dll' or 'hypervisor'.
# The same layer can have multiple backends; the orchestrator picks one per call.
# -----------------------------------------------------------------------------
LAYER_REGISTRY: dict[tuple[str, str], type[LayerDeployer]] = {}


def register(deployer_class: type[LayerDeployer]) -> type[LayerDeployer]:
    """Class decorator to register a LayerDeployer subclass in the registry."""
    if not deployer_class.layer:
        raise ValueError(f"{deployer_class.__name__} must set class attribute `layer`")
    # Derive the backend kind from the backend string (e.g. "http/eos" → "http")
    kind = deployer_class.backend.split("/", 1)[0] if deployer_class.backend else "unknown"
    LAYER_REGISTRY[(deployer_class.layer, kind)] = deployer_class
    log.debug("Registered layer deployer: %s/%s → %s", deployer_class.layer, kind, deployer_class.__name__)
    return deployer_class


def get_deployer(layer: str, backend_kind: str = "http") -> LayerDeployer:
    """Look up the deployer class for a given layer + backend kind.

    Args:
        layer: the layer name (e.g. "steam_ceg", "eos", "atlus")
        backend_kind: "http" | "dll" | "hypervisor" (default: "http")

    Raises KeyError if no deployer is registered.
    """
    cls = LAYER_REGISTRY.get((layer, backend_kind))
    if cls is None:
        raise KeyError(
            f"No deployer registered for layer='{layer}' backend='{backend_kind}'. "
            f"Known: {sorted(LAYER_REGISTRY.keys())}"
        )
    return cls()
