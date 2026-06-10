"""re-vendor-anti-tamper: per-vendor bypass shell.

v0.2.0: dispatches to re-vendor-anti-tamper MCP server. Shells out
to the right open-source tool per target:
  - denuvo: no general tool. Placeholder that links to the A-DW + POGO approach.
  - vmprotect: void-stack/VMUnprotect, can1357/NoVmp.
  - themida: samrashaikh/Themida-Unpacker (partial).
  - starforce: out-of-scope (no open-source tool).
  - arxan: out-of-scope (no open-source tool).
  - eac / be: defensive-utility only (per MRTEA Part V §5 — no weaponized PoCs).
"""
from __future__ import annotations

import argparse
import sys

from re_breaker.cli._base import plugin_root, require_license_ack, spawn_mcp_server


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="re-vendor-anti-tamper",
        description="Per-vendor anti-tamper bypass shell. v0.2.0.",
    )
    parser.add_argument("--vendor", required=True,
                        choices=["denuvo", "vmprotect", "themida", "starforce", "arxan", "eac", "be"],
                        help="which vendor's anti-tamper to target")
    parser.add_argument("--target", required=True, help="path to the protected binary")
    parser.add_argument("--tool", default=None,
                        help="which open-source tool to shell out to (default: auto-pick from --vendor)")
    parser.add_argument("--mode", choices=["emulator", "frida", "inject"], default="emulator")
    parser.add_argument("--output", default="./re-vendor-anti-tamper-output/")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--license-acknowledge", action="store_true",
                        help="acknowledge LICENSE-OFFENSIVE.md")
    args = parser.parse_args()

    rc = require_license_ack(args.license_acknowledge)
    if rc != 0:
        return rc

    root = plugin_root()
    request = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "run_vendor_tool",
            "arguments": {
                "vendor": args.vendor,
                "target": args.target,
                "tool": args.tool,
                "mode": args.mode,
                "output": args.output,
                "timeout_s": args.timeout,
            },
        },
    }
    return spawn_mcp_server(
        "re-vendor-anti-tamper",
        env_extras={"RE_BREAKER_VENDORS": "denuvo,vmprotect,themida,starforce,arxan,eac,be"},
        request=request,
    )


if __name__ == "__main__":
    sys.exit(main())
