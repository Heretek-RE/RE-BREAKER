"""re-entitlement-bypass — unified entitlement-emulation stack (v0.2.0).

v0.2.0 adds:
- A unified orchestrator (`re-ee emulate <target>`) that covers Steam CEG
  (via gbe_fork), EOS handshake, IOI Account, SEGA SSO, Atlus, Sunblink,
  Pearl Abyss, and EA Origin.
- A common base class (`EmulatorHTTPBase`) for all 7 HTTP-based entitlement
  emulators (refactors the 3 existing EOS/IOI/SEGA emulators + adds 4 new
  scaffolded ones).
- A `DropInDLLDeployer` base class that generalizes the gbe_fork deploy
  pattern to all drop-in-DLL layers.
- A SOW gate that refuses out-of-scope layer deploys.
- A Phase 1 RE-utility (`wire_re`) for reversing the per-binary wire formats
  of the 4 new layers (Atlus, Sunblink, PA, Origin).
- 2 new MCP tools: `plan_emulation` and `audit_emulation` (additive; the
  existing `bypass_entitlement` tool is preserved for back-compat).
"""

__version__ = "0.2.0"
