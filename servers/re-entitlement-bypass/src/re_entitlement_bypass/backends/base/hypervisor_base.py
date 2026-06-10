"""HypervisorDeployer — RE-only stub for the DenuvOwO Denuvo hypervisor bypass.

Per the user's decision: no Windows host available, no driver deploy, no build.
The goal of this module is to **document** the technique and refuse cleanly
when invoked.

The actual RE walkthrough lives in `backends/hypervisor/simplesvm_re_notes.md`,
`backends/hypervisor/hyperkd_re_notes.md`, and `backends/hypervisor/technique_summary.md`.

See `docs/PLAYBOOKS/denuvo-hypervisor-technique.md` for the operator-facing guide.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ...core.layer_base import LayerDeployer, register
from ...core.status import LayerDeployStatus

if TYPE_CHECKING:
    from ...core.target_manifest import TargetEntry

log = logging.getLogger("re-entitlement-bypass.hypervisor_base")


@register
class HypervisorDeployer(LayerDeployer):
    """RE-only stub for the Denuvo + hypervisor bypass.

    On any host (Wine or Windows), this deployer returns status="re-only" with
    a pointer to the RE walkthrough docs. The user is expected to read the docs
    and understand the technique without deploying anything.
    """

    layer = "denuvo"
    backend = "hypervisor/denuvo-re-only"

    def plan(self, target: "TargetEntry", dry_run: bool = False) -> LayerDeployStatus:
        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="re-only",
            note="Denuvo hypervisor bypass is RE-only on this engagement (no Windows host). See docs/PLAYBOOKS/denuvo-hypervisor-technique.md for the technique walkthrough.",
        )

    def deploy(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        return self.plan(target)

    def rollback(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        return LayerDeployStatus(layer=self.layer, backend=self.backend, status="re-only", note="nothing to roll back (RE-only layer)")

    def audit(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        return self.plan(target)
