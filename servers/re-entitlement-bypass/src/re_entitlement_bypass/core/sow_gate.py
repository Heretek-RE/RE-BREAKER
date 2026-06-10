"""SOW gate — refuses layer deploys that aren't covered by the per-target SOW.

Per MRTEA Part V §2.7 + Exhibit H: each SOW covers a specific set of entitlement
layers. The orchestrator's SOW gate refuses to deploy a layer if the target's
SOW doesn't cover it (e.g. refuse `pa` for fm26 because Pearl Abyss is SOW-X,
not SOW-X).

SOW coverage (per the 2026-06-08 live-fire engagement + MRTEA-2026-001):
  SOW-X (Steam CEG): all CEG-titled targets (FM26, HKIA, TWW3, P3R, 007FL, CD)
  SOW-X (EOS): EOS-titled (FM26, TWW3)
  SOW-X (IOI Account): IOI (007FL)
  SOW-X (SEGA / Sports Interactive): FM26 (SEGA SSO)
  SOW-X (Sunblink / EGS): HKIA
  SOW-X (Pearl Abyss): CD (PA internal protocol)
  SOW-X (SEGA / Atlus): P3R (Atlus Account)
  SOW-X (CA / Microsoft): TWW3 (non-EOS-AC)
  (no SOW): LIR (EA Origin, stress-test only)

Override: the operator can override the SOW gate with
`--override-sow-gate=I-understand-the-SOW-implications` (logged to audit).
"""

from __future__ import annotations

from typing import Optional


# Per-layer → SOW-coverages mapping.
# A layer is deployable against a target if the target's SOW is in this set.
LAYER_SOW_COVERAGE: dict[str, set[Optional[str]]] = {
    "steam_ceg":   {"J", "N", "P", "Q", "L", "O", "M"},  # All SOWs include CEG (it's a Steam layer)
    "eos":         {"K", "Q", "M", "O"},                  # EOS is in SOW-X (primary), SOW-X (CA's TWW3), SOW-X (FM26's SEGA), SOW-X (CD can also use EOS)
    "ioi":         {"L"},                                  # IOI Account is IOI-only
    "sega_sso":    {"M"},                                  # SEGA SSO is SEGA-SI only
    "atlus":       {"P"},                                  # Atlus is SEGA-Atlus only
    "sunblink":    {"N"},                                  # Sunblink / EGS / XOG is Sunblink only
    "pa":          {"O"},                                  # Pearl Abyss is PA only
    "origin":      {None},                                 # EA Origin is stress-test only (no SOW)
    "denuvo":      {"O", "P"},                             # Denuvo can be in SOW-X (CD) or SOW-X (P3R carve-out)
}


class SOWGate:
    """The SOW gate — refuses layer deploys that aren't covered by the SOW."""

    @staticmethod
    def check(target_sow: Optional[str], layer: str, override: bool = False) -> tuple[bool, Optional[str]]:
        """Check if `layer` is deployable against a target with `target_sow`.

        Args:
            target_sow: the target's SOW letter (e.g. "M") or None for stress-test
            layer: the layer name (e.g. "steam_ceg", "pa", "atlus")
            override: if True, skip the check (logged to audit)

        Returns:
            (allowed, reason) — True/None if allowed, (False, reason) if refused.
        """
        if override:
            return True, "SOW gate overridden by operator"

        covered_sows = LAYER_SOW_COVERAGE.get(layer)
        if covered_sows is None:
            return False, f"Unknown layer '{layer}'"

        if target_sow not in covered_sows:
            return False, (
                f"SOW-{target_sow} does not cover '{layer}' layer "
                f"(this layer is covered by: {sorted(s for s in covered_sows if s is not None) or ['<no SOW — stress-test only>']})"
            )

        return True, None

    @staticmethod
    def explain(layer: str) -> str:
        """Return a human-readable explanation of which SOWs cover a layer."""
        covered = LAYER_SOW_COVERAGE.get(layer, set())
        if not covered:
            return f"Layer '{layer}': UNKNOWN (not in registry)"
        sorted_covered = sorted(s for s in covered if s is not None)
        if None in covered:
            return f"Layer '{layer}': covered by SOW-{', SOW-'.join(sorted_covered)} + <no SOW — stress-test only>"
        return f"Layer '{layer}': covered by SOW-{', SOW-'.join(sorted_covered)}"
