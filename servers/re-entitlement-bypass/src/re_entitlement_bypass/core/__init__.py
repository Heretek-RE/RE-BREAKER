"""re_entitlement_bypass.core — the unified-stack core.

Modules:
- target_manifest: per-target manifest (target → SOW → layers)
- layer_base: abstract LayerDeployer (plan/deploy/rollback/audit/status)
- sow_gate: per-target SOW ethical-wall check
- audit: SHA-256 + integrity-audit + YARA confirmation
- status: DeployStatus pydantic model
- wire_re: per-binary wire-format extraction utility
"""
