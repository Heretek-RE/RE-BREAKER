"""re-catalog-match: match a target binary against the RE-BREAKER technique catalog.

v0.2.0: dispatches to re-catalog-match MCP server, which loads
data/catalog.json (48 entries) + data/yara/techniques.yar (48 YARA rules)
and returns ranked matches with defender-side confidence + offender-side
playbook references.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from re_breaker.cli._base import plugin_root, require_license_ack, spawn_mcp_server


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="re-catalog-match",
        description="Match a target binary against the RE-BREAKER technique catalog. v0.2.0.",
    )
    parser.add_argument("--target", required=True, help="path to the target .exe or .dll")
    parser.add_argument("--intent", choices=["defender", "offender", "both"], default="both",
                        help="what to return (default: both)")
    parser.add_argument("--triage-json", default=None,
                        help="path to a pre-computed triage JSON (skip server-side triage)")
    parser.add_argument("--min-confidence", type=float, default=0.0,
                        help="drop matches below this confidence (0.0-1.0)")
    parser.add_argument("--json", action="store_true", help="output as JSON, not text")
    parser.add_argument("--quiet", action="store_true", help="suppress non-error output")
    parser.add_argument("--license-acknowledge", action="store_true",
                        help="acknowledge the offensive-research-use clause (LICENSE-OFFENSIVE.md)")
    args = parser.parse_args()

    rc = require_license_ack(args.license_acknowledge)
    if rc != 0:
        return rc

    root = plugin_root()
    request = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "match_catalog",
            "arguments": {
                "target": args.target,
                "intent": args.intent,
                "triage_json_path": args.triage_json,
                "min_confidence": args.min_confidence,
            },
        },
    }
    return spawn_mcp_server(
        "re-catalog-match",
        env_extras={
            "RE_BREAKER_CATALOG_PATH": str(root / "data" / "catalog.json"),
            "RE_BREAKER_YARA_RULES_PATH": str(root / "data" / "yara" / "techniques.yar"),
        },
        request=request,
    )


if __name__ == "__main__":
    sys.exit(main())
