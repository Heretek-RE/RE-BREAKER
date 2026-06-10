"""re-anti-debug-patch: byte-level patch the anti-debug primitives (RDTSC, CPUID, INT 2D, INT 3, VMCALL, VMXON) in a target binary.

v0.2.0: dispatches to re-anti-debug-patch MCP server, which uses
RE-AI's re-anti-analysis-scan (to locate sites) + re-patch (to apply
the patch) + capstone/iced-x86 (to disasm-walk the context for each
site) + re-speakeasy (to verify the patched binary doesn't crash).
"""
from __future__ import annotations

import argparse
import sys

from re_breaker.cli._base import plugin_root, require_license_ack, spawn_mcp_server


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="re-anti-debug-patch",
        description="Patch anti-debug primitives (RDTSC/CPUID/INT 2D/INT 3/VMCALL/VMXON) in a target binary. v0.2.0.",
    )
    parser.add_argument("--target", required=True, help="path to the target .exe or .dll")
    parser.add_argument("--rdtsc-strategy", choices=["zero", "constant", "passthrough"],
                        default="zero", help="how to handle RDTSC sites (default: zero)")
    parser.add_argument("--cpuid-strategy", choices=["zero", "nop", "passthrough"],
                        default="zero", help="how to handle CPUID sites (default: zero)")
    parser.add_argument("--vmxon-strategy", choices=["zero", "passthrough"],
                        default="zero", help="how to handle VMXON sites (default: zero)")
    parser.add_argument("--vmcall-strategy", choices=["zero", "passthrough"],
                        default="zero", help="how to handle VMCALL sites (default: zero)")
    parser.add_argument("--int2d-strategy", choices=["zero", "passthrough"],
                        default="zero", help="how to handle INT 2D sites (default: zero)")
    parser.add_argument("--int3-strategy", choices=["zero", "passthrough"],
                        default="zero", help="how to handle INT 3 sites (default: zero)")
    parser.add_argument("--output", default="./re-anti-debug-patch-output/",
                        help="where to write the patched binary + per-site log")
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
            "name": "patch_target",
            "arguments": {
                "target": args.target,
                "rdtsc_strategy": args.rdtsc_strategy,
                "cpuid_strategy": args.cpuid_strategy,
                "vmxon_strategy": args.vmxon_strategy,
                "vmcall_strategy": args.vmcall_strategy,
                "int2d_strategy": args.int2d_strategy,
                "int3_strategy": args.int3_strategy,
                "output": args.output,
            },
        },
    }
    return spawn_mcp_server(
        "re-anti-debug-patch",
        # v0.4.0: RE-AI sibling dependency removed.
        env_extras={"RE_BREAKER_PLUGIN_ROOT": str(root)},
        request=request,
    )


if __name__ == "__main__":
    sys.exit(main())
