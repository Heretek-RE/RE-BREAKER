"""re-dump: dump the decrypted-VM-encrypted region of a target binary.

v0.2.0: dispatches to re-runtime-dump MCP server. For backward
compatibility, the argparse surface is preserved; the v0.1.0 license gate
+ JSON output remain.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def _plugin_root() -> Path:
    """Resolve the RE-BREAKER plugin root (parent of src/)."""
    return Path(__file__).resolve().parents[3]


def _spawn_runtime_dump_server(args: argparse.Namespace) -> int:
    """Fork the re-runtime-dump MCP server in stdio mode and pipe the
    request. v0.2.0: uses `uv --directory servers/re-runtime-dump run`
    so the per-server venv + dependencies are honored.
    """
    plugin_root = _plugin_root()
    cmd = [
        "uv",
        "--directory", str(plugin_root / "servers" / "re-runtime-dump"),
        "run", "re-runtime-dump",
    ]
    env = os.environ.copy()
    env["RE_BREAKER_LICENSE_FILE"] = str(plugin_root / "LICENSE-OFFENSIVE.md")
    # v0.4.0: RE-AI sibling dependency removed. The vendored RE-AI code
    # lives under plugin_root/vendored/re-ai/ and is imported directly.
    env["RE_BREAKER_PLUGIN_ROOT"] = str(plugin_root)
    env["PYTHONUNBUFFERED"] = "1"

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "dump_target",
            "arguments": {
                "target": args.target,
                "mode": args.mode if args.mode != "auto" else "emulator",
                "output": args.output,
            },
        },
    }
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
        env=env, text=True,
    )
    out, _ = proc.communicate(json.dumps(request) + "\n", timeout=args.timeout)
    print(out)
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="re-dump",
        description="Dump the decrypted-VM-encrypted region of a target binary. v0.2.0 dispatches to re-runtime-dump.",
    )
    parser.add_argument("--target", required=True, help="path to the target .exe or .dll")
    parser.add_argument("--mode", choices=["emulator", "frida", "inject", "auto"],
                        default="auto", help="which backend to use (default: auto-pick from --target)")
    parser.add_argument("--output", default="./re-dump-output/", help="where to write the decrypted dump")
    parser.add_argument("--hooks", default=None, help="comma-separated Win32 APIs to hook")
    parser.add_argument("--vm-handler-id", type=int, default=None, help="for VM dispatchers, log only this handler ID")
    parser.add_argument("--rdtsc-strategy", choices=["zero", "constant", "passthrough"], default="constant")
    parser.add_argument("--cpuid-strategy", choices=["bare-metal-snapshot", "no-op"], default="bare-metal-snapshot")
    parser.add_argument("--timeout", type=int, default=300, help="max wall-clock seconds for the dump")
    parser.add_argument("--catalog-match", default=None, help="limit to a specific catalog entry")
    parser.add_argument("--playbook", default=None, help="run a specific playbook end-to-end")
    parser.add_argument("--json", action="store_true", help="output as JSON, not text")
    parser.add_argument("--quiet", action="store_true", help="suppress non-error output")
    parser.add_argument("--license-acknowledge", action="store_true",
                        help="acknowledge the offensive-research-use clause (LICENSE-OFFENSIVE.md)")
    args = parser.parse_args()

    if not args.license_acknowledge:
        print("=" * 72, file=sys.stderr)
        print("RE-BREAKER: --license-acknowledge is required.", file=sys.stderr)
        print("Read LICENSE-OFFENSIVE.md and re-run with --license-acknowledge.", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        return 77  # EX_NOPERM

    # v0.2.0: dispatch to the runtime-dump MCP server
    rc = _spawn_runtime_dump_server(args)
    return rc


if __name__ == "__main__":
    sys.exit(main())
