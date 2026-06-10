"""MCP server entry point for re-speakeasy.

Exposes Mandiant Speakeasy Windows API emulation tools to Claude
Code via the Model Context Protocol stdio transport. The Python
server is a thin wrapper around a ``speakeasy-cli`` Python
helper installed by install.sh via ``pip install
speakeasy-emulator``.

When the helper is missing, the server reports ``WARN`` (not
``ERROR``) and the tools return a clean install hint — the
Python server itself always loads.

All output is vendor-neutral: Speakeasy's emulator trace describes
the binary's per-API calls (CreateFileW, RegOpenKeyExW, ...) in
vendor-neutral terms. The encrypted-VM bytecode detection work
that uses this trace never names a specific commercial product.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from re_speakeasy import runner

logger = logging.getLogger("re_speakeasy")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-speakeasy")


# ── Health ──────────────────────────────────────────────────────────────


@mcp.tool()
def check_speakeasy() -> dict:
    """Return speakeasy-cli version + Python module availability.

    Reports ``WARN`` (not ``ERROR``) when the helper is not
    found. The fallback chain: ``$RE_SPEAKEASY_CLI_PATH`` ->
    ``<server>/bin/speakeasy-cli`` -> PATH.
    """
    cli = runner._binary_path()
    info: dict = {"server": "re-speakeasy", "version": "0.1.0"}
    if cli is None:
        info["status"] = "WARN"
        info["error"] = "speakeasy-cli not found"
        info["hint"] = (
            "Run the installer (./install.sh) — it installs "
            "`speakeasy-emulator` from PyPI. Or set "
            "RE_SPEAKEASY_CLI_PATH=/path/to/speakeasy-cli."
        )
        return info
    info["status"] = "OK"
    info["cli_path"] = str(cli)
    out = runner.run_subcommand("check")
    if out is None or "error" in out:
        info["status"] = "WARN"
        info["error"] = (out or {}).get("error", "speakeasy-cli check failed")
    else:
        info["speakeasy_version"] = out.get("version")
        info["emulated_apis_count"] = out.get("emulated_apis_count", 0)
    return info


# ── Emulation ───────────────────────────────────────────────────────────


@mcp.tool()
def emulate_binary(path: str, timeout_s: int = 60) -> dict:
    """Run *path* under Speakeasy and return a structured per-API trace.

    Speakeasy is a Windows API emulator — it loads the .exe /
    .dll in-process and serves the same Win32 surface that
    Windows would, but in pure Python. The trace captures every
    API call the binary makes (CreateFileW, RegOpenKeyExW,
    NtCreateFile, etc.) with arguments + return values.

    Args:
        path: Windows .exe / .dll to emulate
        timeout_s: wall-clock budget (default 60s; binaries that
            loop or call Sleep(INFINITE) can hang the emulator)

    Returns::

        {"path": "...",
         "trace": [
            {"api": "CreateFileW", "args": [...], "return": "...",
             "timestamp_ns": N, "module": "kernel32"},
            ...
         ],
         "summary": {"api_count": N, "unique_apis": [...],
                     "files_accessed": [...], "registry_keys": [...],
                     "processes_spawned": [...], "network_calls": [...]}}

    On a missing helper, returns ``{"status": "WARN", "error":
    "speakeasy-cli not installed", ...}`` so the agent knows to
    retry after install.sh.
    """
    out = runner.run_subcommand("emulate", path, "--timeout", str(timeout_s))
    if out is None:
        return {
            "path": path,
            "status": "WARN",
            "error": "speakeasy-cli not installed; run install.sh",
        }
    if "error" in out:
        return {"path": path, "error": out["error"]}
    return {
        "path": path,
        "trace": out.get("trace", []),
        "summary": out.get("summary", {}),
    }


@mcp.tool()
def list_emulated_apis() -> dict:
    """Return the list of Win32 APIs Speakeasy knows how to emulate.

    Useful for "can Speakeasy handle this binary's API surface?"
    before calling :func:`emulate_binary` on a long-running
    target. The list is large (thousands of APIs) — the default
    is to return the count and a few sample categories.
    """
    out = runner.run_subcommand("list-emulated-apis")
    if out is None:
        return {
            "status": "WARN",
            "error": "speakeasy-cli not installed; run install.sh",
        }
    if "error" in out:
        return {"error": out["error"]}
    return {
        "count": out.get("count", 0),
        "sample": out.get("sample", []),
    }


# ── Entrypoint ─────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio (the standard Claude Code transport)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
