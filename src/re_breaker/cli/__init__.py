"""re-breaker CLI: thin wrappers over the 7 RE-BREAKER MCP servers.

Each entry point (`re-dump`, `re-catalog-match`, etc.) is an argparse
script that:
  1. Enforces `--license-acknowledge` (per LICENSE-OFFENSIVE.md).
  2. Forks the corresponding MCP server (or imports its core function
     in-process for stdio-direct operation).
  3. Returns the structured result as JSON (with `--json`) or text.

v0.2.0: real dispatch via subprocess to the per-server venv.
"""
__all__ = [
    "re_dump",
    "re_catalog_match",
    "re_anti_debug_patch",
    "re_anti_vm_spoof",
    "re_vm_decrypt",
    "re_encrypted_vm_bypass",
    "re_vendor_anti_tamper",
]
