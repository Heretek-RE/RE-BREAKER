#!/usr/bin/env python3
"""scripts/re_vm_attach_external_mcps.py — one-shot SSH-tunnel + .mcp.json
snippet generator (v0.5.0 SCAFFOLD).

Spawns the three upstream MCPs in the Windows VM and registers their
Linux-side tunnel ports in a generated `.mcp.json.snippet` file the
analyst can paste into their own `.mcp.json` if they prefer to use
the upstream MCPs directly rather than going through RE-BREAKER's
bridge servers (escape hatch).

v0.5.0 ships as a **print-only** script (no .mcp.json edits, no
auto-spawn). v0.5.1 will do the actual work.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_RE_BREAKER_SRC))
from re_breaker.vm_client import _plugin_root  # noqa: E402


def snippet() -> dict:
    """The .mcp.json snippet the analyst can paste in."""
    return {
        "_comment": "v0.5.0 SCAFFOLD — paste these into your own .mcp.json to use the upstream MCPs directly (escape hatch from the RE-BREAKER bridge servers). Requires re_vm_provision_guest.py to have run in the VM.",
        "ida-pro-mcp": {
            "command": "uv",
            "args": ["--directory", "./servers/ida-pro-mcp", "run", "ida-pro-mcp", "--transport", "http://127.0.0.1:18744/sse"],
            "_note": "tunnel must be open on Linux: re-vm-ssh.ssh_tunnel_open ida-pro-mcp 18744 127.0.0.1 8744",
        },
        "ghidra-mcp": {
            "command": "uv",
            "args": ["--directory", "./servers/ghidra-mcp", "run", "ghidra-mcp"],
            "_note": "tunnel must be open on Linux: re-vm-ssh.ssh_tunnel_open ghidra-mcp 18089 127.0.0.1 8089",
        },
        "x64dbg-mcp": {
            "command": "uv",
            "args": ["--directory", "./servers/x64dbg-mcp", "run", "x64dbg-mcp"],
            "_note": "tunnel must be open on Linux: re-vm-ssh.ssh_tunnel_open x64dbg-mcp 15030 127.0.0.1 50300",
        },
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--write", type=Path, help="write the snippet to this file (default: stdout)")
    args = p.parse_args()
    payload = snippet()
    text = json.dumps(payload, indent=2)
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(text)
        print(f"Wrote {args.write}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
