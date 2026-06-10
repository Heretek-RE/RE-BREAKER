"""Shared helpers for the RE-BREAKER CLI entry points.

Used by re_*.py modules to:
  1. Resolve the plugin root.
  2. Spawn the corresponding MCP server via `uv --directory servers/<name> run`.
  3. Build the JSON-RPC request.
  4. Capture and return the response.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def plugin_root() -> Path:
    """Resolve the RE-BREAKER plugin root (parent of src/re_breaker/)."""
    return Path(__file__).resolve().parents[3]


def spawn_mcp_server(
    server_dir: str,
    env_extras: dict[str, str] | None = None,
    request: dict[str, Any] | None = None,
    timeout: int = 300,
) -> int:
    """Spawn a per-server MCP server and pipe a single JSON-RPC request.

    Args:
        server_dir: name of the server subdir (e.g. "re-catalog-match")
        env_extras: extra env vars to merge into the server's environment
        request: the JSON-RPC request body (default: a no-op `status` call)
        timeout: wall-clock timeout in seconds

    Returns:
        The server's exit code. The server's stdout is printed to our
        stdout.
    """
    root = plugin_root()
    cmd = [
        "uv",
        "--directory", str(root / "servers" / server_dir),
        "run", server_dir,
    ]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    if env_extras:
        env.update(env_extras)
    if request is None:
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "status", "arguments": {}}}

    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
        env=env, text=True,
    )
    try:
        out, _ = proc.communicate(json.dumps(request) + "\n", timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        print(json.dumps({"error": "timeout", "timeout_s": timeout}), file=sys.stderr)
        return 124  # EX_TIMEOUT
    print(out)
    return proc.returncode


def require_license_ack(license_ack: bool) -> int:
    """Enforce the offensive-research-use license acknowledgement.

    Returns 0 if acknowledged, 77 (EX_NOPERM) otherwise. Also prints the
    LICENSE-OFFENSIVE.md pointer to stderr.
    """
    if license_ack:
        return 0
    print("=" * 72, file=sys.stderr)
    print("RE-BREAKER: --license-acknowledge is required.", file=sys.stderr)
    print("Read LICENSE-OFFENSIVE.md and re-run with --license-acknowledge.", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    return 77
