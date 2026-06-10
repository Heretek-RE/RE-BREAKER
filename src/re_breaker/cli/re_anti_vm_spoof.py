"""re-anti-vm-spoof: neutralize anti-VM detection (CPUID hypervisor leaf, RDTSC timing trap, VMCALL, VMXON, INVD) on a running target.

v0.2.0: dispatches to re-anti-vm-spoof MCP server, which uses Frida
(live process) and/or the C/C++ injection library (in-process) to
install CPUID/RDTSC/VMCALL/VMXON hooks. CPUID hypervisor leaf (0x40000000)
+ leaf 1 ECX bit 31 are returned from a "bare-metal" snapshot JSON
(pre-captured from a non-virtualized host). RDTSC delta is capped to a
configurable threshold to defeat timing traps.
"""
from __future__ import annotations

import argparse
import sys

from re_breaker.cli._base import plugin_root, require_license_ack, spawn_mcp_server


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="re-anti-vm-spoof",
        description="Neutralize anti-VM detection in a target binary. v0.2.0.",
    )
    parser.add_argument("--target", required=True, help="path to the target .exe or .dll")
    parser.add_argument("--cpuid-strategy", choices=["bare-metal-snapshot", "no-op"],
                        default="bare-metal-snapshot",
                        help="how to handle CPUID hypervisor leaves (default: bare-metal-snapshot)")
    parser.add_argument("--vmdetect-strategy", choices=["zero", "passthrough"],
                        default="zero", help="how to handle VMCALL/VMXON/INVD sites (default: zero)")
    parser.add_argument("--rdtsc-delta-cap", type=int, default=1000,
                        help="max RDTSC delta in cycles before the trap fires (default: 1000)")
    parser.add_argument("--bare-metal-snapshot", default=None,
                        help="path to a pre-captured bare-metal CPUID snapshot JSON")
    parser.add_argument("--mode", choices=["frida", "inject"], default="frida",
                        help="which hook layer to use (default: frida)")
    parser.add_argument("--output", default="./re-anti-vm-spoof-output/",
                        help="where to write the CPUID/RDTSC trace")
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
            "name": "spoof_target",
            "arguments": {
                "target": args.target,
                "cpuid_strategy": args.cpuid_strategy,
                "vmdetect_strategy": args.vmdetect_strategy,
                "rdtsc_delta_cap": args.rdtsc_delta_cap,
                "bare_metal_snapshot": args.bare_metal_snapshot,
                "mode": args.mode,
                "output": args.output,
            },
        },
    }
    return spawn_mcp_server(
        "re-anti-vm-spoof",
        # v0.4.0: RE-AI sibling dependency removed.
        env_extras={"RE_BREAKER_PLUGIN_ROOT": str(root)},
        request=request,
    )


if __name__ == "__main__":
    sys.exit(main())
