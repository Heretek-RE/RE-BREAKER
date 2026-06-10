"""re-encrypted-vm-bypass: per-Pattern orchestrator. Combine anti-debug patch + anti-VM spoof + VM-decrypt to bypass a target's encrypted-VM bytecode interpreter.

v0.2.0: dispatches to re-encrypted-vm-bypass MCP server. Recipes:
  - Pattern A: trigger the lazy-decrypt stub, dump each method's plaintext.
  - Pattern A-DW: bypass the POGO entry validation, then trigger the stub.
  - Pattern A-VMT: dump the .xcode dispatch table, resolve the handler targets in .link, dump the handler bodies in .arch.
  - Pattern B: third-party activation library — fingerprint the activator, identify the ordinals, stub-drop the entitlement check.
  - Pattern C: proprietary engine encrypted-VM — per-family recipe.
  - Pattern D: publisher telemetry attack surface — hook telemetry senders.
"""
from __future__ import annotations

import argparse
import sys

from re_breaker.cli._base import plugin_root, require_license_ack, spawn_mcp_server


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="re-encrypted-vm-bypass",
        description="Per-Pattern orchestrator: anti-debug + anti-VM + VM-decrypt + activation-gate stub-drop. v0.2.0.",
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--pattern", choices=["A", "A-DW", "A-VMT", "B", "C", "D"],
                        required=True, help="which VM pattern to bypass")
    parser.add_argument("--mode", choices=["emulator", "frida", "inject"], default="emulator")
    parser.add_argument("--rdtsc-strategy", choices=["zero", "constant", "passthrough"], default="zero")
    parser.add_argument("--cpuid-strategy", choices=["bare-metal-snapshot", "no-op"], default="bare-metal-snapshot")
    parser.add_argument("--output", default="./re-encrypted-vm-bypass-output/")
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
            "name": "bypass_pattern",
            "arguments": {
                "target": args.target,
                "pattern": args.pattern,
                "mode": args.mode,
                "rdtsc_strategy": args.rdtsc_strategy,
                "cpuid_strategy": args.cpuid_strategy,
                "output": args.output,
                "timeout_s": args.timeout,
            },
        },
    }
    return spawn_mcp_server(
        "re-encrypted-vm-bypass",
        env_extras={
            "RE_BREAKER_PATTERNS_PATH": str(root / "data" / "patterns"),
            # v0.4.0: RE-AI sibling dependency removed.
            "RE_BREAKER_PLUGIN_ROOT": str(root),
        },
        request=request,
    )


if __name__ == "__main__":
    sys.exit(main())
