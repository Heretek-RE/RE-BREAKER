"""re-vm-decrypt: lift the decrypted method bodies from a running encrypted-VM bytecode interpreter.

v0.2.0: dispatches to re-vm-decrypt MCP server. For Pattern A / A-DW,
hooks the encryption-stub entry (the lazy-decrypt routine that fires
on first execution of an encrypted method), captures input (encrypted
bytes) + output (decrypted method body), writes per-method binaries
to --output/. For Pattern A-VMT (Crimson Desert's BlackSpace engine),
hooks the .xcode handler dispatch, captures each handler body's
runtime-decrypted form, reconstructs the handler table from
.xcode (dispatch) / .link (jump targets) / .arch (handler bodies).
"""
from __future__ import annotations

import argparse
import sys

from re_breaker.cli._base import plugin_root, require_license_ack, spawn_mcp_server


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="re-vm-decrypt",
        description="Lift decrypted VM-encrypted method bodies. v0.2.0.",
    )
    parser.add_argument("--target", required=True, help="path to the target .exe or .dll")
    parser.add_argument("--mode", choices=["emulator", "frida", "inject"], default="emulator",
                        help="which backend to use (default: emulator)")
    parser.add_argument("--pattern", choices=["A", "A-DW", "A-VMT"], default="A",
                        help="which VM pattern to target (default: A)")
    parser.add_argument("--handler-id", type=int, default=None,
                        help="for Pattern A-VMT, log only this handler ID")
    parser.add_argument("--output", default="./re-vm-decrypt-output/",
                        help="where to write the decrypted method bodies")
    parser.add_argument("--timeout", type=int, default=300)
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
            "name": "decrypt_target",
            "arguments": {
                "target": args.target,
                "mode": args.mode,
                "pattern": args.pattern,
                "handler_id": args.handler_id,
                "output": args.output,
                "timeout_s": args.timeout,
            },
        },
    }
    return spawn_mcp_server(
        "re-vm-decrypt",
        # v0.4.0: RE-AI sibling dependency removed.
        env_extras={"RE_BREAKER_PLUGIN_ROOT": str(root)},
        request=request,
    )


if __name__ == "__main__":
    sys.exit(main())
