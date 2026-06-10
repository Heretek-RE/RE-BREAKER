#!/usr/bin/env python3
"""scripts/re_vm_provision_guest.py — one-time guest provisioning (v0.5.0).

Installs, in the Windows VM:
  - Python 3.11+ (via winget)
  - uv (via the astral-sh install script)
  - The three upstream MCP repos (mrexodia/ida-pro-mcp,
    AgentSmithers/x64DbgMCPServer, bethington/ghidra-mcp) to
    C:\\re-mcps\\<name>\\
  - One-liner start scripts at C:\\re-mcps\\start-<name>.ps1 that
    the RE-BREAKER bridges invoke.

v0.5.0 ships this as a **plan-only** script (`--dry-run` is the
default). v0.5.1 will auto-execute after the analyst runs
`re_vm_provision_guest.py --execute` and acknowledges the
LICENSE-OFFENSIVE.md clause (mirrors `re-dump --license-acknowledge`).
"""
from __future__ import annotations

import argparse
import os
import sys
import textwrap
from pathlib import Path

# Resolve RE-BREAKER's plugin root
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_RE_BREAKER_SRC))
from re_breaker.vm_client import _plugin_root, DEFAULT_SSH_HOST, DEFAULT_SSH_KEY  # noqa: E402


def emit_commands() -> list[str]:
    """The PowerShell commands the analyst would run, in order."""
    cmds = [
        # 1. Python 3.11+ via winget
        'winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements',
        # 2. uv (the pip-install path, since winget doesn't always have it)
        'pip install --upgrade uv',
        # 3. Clone the three upstream MCP repos
        r'mkdir C:\re-mcps',
        r'git clone https://github.com/mrexodia/ida-pro-mcp.git C:\re-mcps\ida-pro-mcp',
        r'git clone https://github.com/AgentSmithers/x64DbgMCPServer.git C:\re-mcps\x64DbgMCPServer',
        r'git clone https://github.com/bethington/ghidra-mcp.git C:\re-mcps\ghidra-mcp',
        # 4. Generate a Ghidra auth token (Bearer) and stash it
        r'$token = [guid]::NewGuid().ToString()',
        r'Set-Content -Path $env:USERPROFILE\.ghidra-mcp-token -Value $token -NoNewline',
        # 5. Write the one-liner start scripts
        textwrap.dedent('''\
            @'
            cd /d C:\\re-mcps\\ida-pro-mcp
            uv run idalib-mcp --transport http://127.0.0.1:8744/sse
            '@ | Out-File -Encoding ascii C:\\re-mcps\\start-ida-mcp.ps1
        '''),
        textwrap.dedent('''\
            @'
            $env:GHIDRA_INSTALL_DIR='C:\\ghidra'
            $env:GHIDRA_MCP_AUTH_TOKEN = (Get-Content $env:USERPROFILE\\.ghidra-mcp-token -Raw).Trim()
            cd /d C:\\re-mcps\\ghidra-mcp
            python bridge_mcp_ghidra.py --mcp-transport http --mcp-port 8089
            '@ | Out-File -Encoding ascii C:\\re-mcps\\start-ghidra-mcp.ps1
        '''),
        # x64dbg doesn't need a separate start script — the DP64 plugin
        # auto-loads; the analyst just needs to launch x64dbg.exe
        # with a target on the command line.
    ]
    return cmds


def main() -> int:
    p = argparse.ArgumentParser(description="RE-BREAKER v0.5.0 guest provisioner (plan-only)")
    p.add_argument("--execute", action="store_true", help="auto-execute (v0.5.1; v0.5.0 plan-only)")
    p.add_argument("--acknowledge-license", action="store_true", help="acknowledge LICENSE-OFFENSIVE.md (required for --execute)")
    args = p.parse_args()

    plugin = _plugin_root()
    print(f"RE-BREAKER plugin root: {plugin}")
    print(f"SSH target: {DEFAULT_SSH_HOST} (key: {DEFAULT_SSH_KEY})")
    print()
    if args.execute and not args.acknowledge_license:
        print("ERROR: --execute requires --acknowledge-license (mirrors re-dump --license-acknowledge).", file=sys.stderr)
        return 2
    print("=" * 78)
    print("Plan (v0.5.0 PLAN-ONLY; pass --execute --acknowledge-license to run):")
    print("=" * 78)
    for i, cmd in enumerate(emit_commands(), 1):
        print(f"\n--- Step {i} ---\n{cmd}")
    print()
    print("=" * 78)
    if not args.execute:
        print("Nothing was executed. Re-run with --execute --acknowledge-license to apply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
