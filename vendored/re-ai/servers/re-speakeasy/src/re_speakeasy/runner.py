"""Subprocess wrapper around the ``speakeasy-cli`` Python helper.

Mandiant Speakeasy (mandiant/speakeasy, Apache-2.0) is a Python
emulator for Windows executables. The expected install layout is
a ``speakeasy-cli`` Python script installed by ``pip install
speakeasy-emulator`` (which install.sh handles).

The CLI surface is intentionally tiny — Speakeasy's own Python
API is rich, but for a subprocess wrapper the only thing the
MCP server needs is "run this .exe and return the trace as
JSON".

  speakeasy-cli check                              -> version
  speakeasy-cli emulate <path> [--timeout N]        -> trace JSON
  speakeasy-cli list-emulated-apis                  -> api catalog

When the helper is missing, the tools return ``WARN`` and
Claude Code surfaces a clear install hint.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


_CLI_NAME = "speakeasy-cli"


def _binary_path() -> Path | None:
    override = os.environ.get("RE_SPEAKEASY_CLI_PATH")
    if override and Path(override).is_file():
        return Path(override)
    server_root = Path(__file__).resolve().parent.parent.parent
    default = server_root / "bin" / _CLI_NAME
    if default.is_file() and os.access(default, os.X_OK):
        return default
    on_path = shutil.which(_CLI_NAME)
    if on_path:
        return Path(on_path)
    return None


def run_subcommand(subcommand: str, *args: str, timeout_s: int = 120) -> dict[str, Any] | None:
    """Invoke speakeasy-cli; return parsed JSON, or None if missing."""
    binary = _binary_path()
    if binary is None:
        return None
    cmd = [str(binary), subcommand, *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    output = (proc.stdout or "").strip()
    if not output:
        return {
            "error": (proc.stderr or "").strip() or "no output",
            "exit_code": proc.returncode,
        }
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return {"text": output, "exit_code": proc.returncode}
    if isinstance(parsed, dict) and "error" in parsed:
        return {"error": parsed.get("error", "unknown"), "exit_code": proc.returncode}
    return parsed if isinstance(parsed, dict) else {"result": parsed}
