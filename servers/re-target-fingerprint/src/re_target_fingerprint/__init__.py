"""RE-BREAKER re-target-fingerprint MCP server (v0.1.0 / v0.8.0+ Wave 3, Item G).

Per-target YARA fingerprinting. Extracts unique byte patterns from a
target binary (e.g. runtime_metadata header magic, anti-tamper dispatcher
magic) and emits a YARA rule that matches the target with confidence 1.0
and any other target with confidence 0.0.

Closes the v0.7.0 gap that the catalog matcher couldn't tell targets
apart (the technique-class rules cover e.g. "VMProtect" but not
"VMProtect v3.2 build 1234").

Tools:
  - generate_fingerprints(target): extract unique byte patterns → YARA rule
  - match_fingerprint(target): match against data/yara/target-fingerprints.yar
  - status: server health
"""
__version__ = "0.1.0"
