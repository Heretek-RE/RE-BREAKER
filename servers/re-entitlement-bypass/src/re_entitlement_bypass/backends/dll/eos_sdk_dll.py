"""EOS SDK drop-in-DLL backend — SCAFFOLD for Phase 2.

Phase 2 will write a C/C++ stub `EOSSDK-Win64-Shipping.dll` (the
`vendored/stubs/eos_sdk/EOSSDKStub.cpp` deliverable) that implements
~12 entry points returning hard-coded "subscribed" structs. This module
will then register the stub with the `DropInDLLDeployer` base.

For v0.2.0, this module is a scaffold that returns a status="stub" with a
pointer to the Phase 2 deliverable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ...core.layer_base import register
from ...core.status import LayerDeployStatus

if TYPE_CHECKING:
    from ...core.target_manifest import TargetEntry

log = logging.getLogger("re-entitlement-bypass.eos_sdk_dll")


@register
class EosSdkDllBackend:
    """EOS SDK drop-in-DLL backend — SCAFFOLD for Phase 2."""

    layer = "eos"
    backend = "dll/eos_sdk"

    def __init__(self):
        self._stub_dll = Path("os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")/servers/re-entitlement-bypass/vendored/stubs/eos_sdk/EOSSDKStub.dll")

    def plan(self, target: "TargetEntry", dry_run: bool = False) -> LayerDeployStatus:
        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="stub",
            note="Phase 2 SCAFFOLD — vendored/stubs/eos_sdk/EOSSDKStub.{cpp,h} is not yet written. Use the http/eos backend for v0.2.0.",
        )

    def deploy(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        return self.plan(target)

    def rollback(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        return LayerDeployStatus(layer=self.layer, backend=self.backend, status="stub", note="nothing to roll back (Phase 2 SCAFFOLD)")

    def audit(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        return self.plan(target)
