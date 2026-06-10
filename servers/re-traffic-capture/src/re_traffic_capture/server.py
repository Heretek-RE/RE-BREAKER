"""re-traffic-capture MCP server (v0.1.0 SCAFFOLD).

v0.1.0 is plan-only. v0.2.0 will spawn a Wine target with
WINEDEBUG=+winsock,+wininet,+http and parse the output into a structured
event log (DNS lookup, HTTP request, response code, payload snippet).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-traffic-capture")

__version__ = "0.1.0"

mcp = FastMCP("re-traffic-capture")


@mcp.tool()
def capture(
    target: str,
    wine_prefix: str,
    filter: str = "winsock|wininet|http|connect",
    duration_sec: int = 120,
) -> dict[str, Any]:
    """Spawn a Wine target and capture its traffic into a structured log.

    Args:
        target: absolute path to the .exe
        wine_prefix: WINEPREFIX path
        filter: regex of which Wine debug channels to capture
        duration_sec: total duration of the capture

    Returns:
        dict with keys: capture_id, target, duration_sec, events (list of {timestamp, pid, function, args, return_value, parsed_url?, resolved_addr?})
    """
    # v0.1.0 SCAFFOLD
    log.info("capture(%r, %r) — SCAFFOLD", target, wine_prefix)
    return {
        "capture_id": "cap-stub-0001",
        "target": target,
        "duration_sec": duration_sec,
        "events": [],
        "note": "SCAFFOLD — v0.2.0 will spawn with WINEDEBUG=+winsock,+wininet,+http and parse the output",
    }


@mcp.tool()
def list_endpoints(capture_id: str) -> dict[str, Any]:
    """Return the unique hostnames / IPs / ports the target reached during a capture.

    Args:
        capture_id: the ID returned by capture()

    Returns:
        dict with keys: capture_id, hostnames (list), ips (list), ports (list), miss_rate
    """
    # v0.1.0 SCAFFOLD
    log.info("list_endpoints(%r) — SCAFFOLD", capture_id)
    return {
        "capture_id": capture_id,
        "hostnames": [],
        "ips": [],
        "ports": [],
        "miss_rate": None,
        "note": "SCAFFOLD — v0.2.0 will aggregate the capture's events into endpoint stats",
    }


@mcp.tool()
def install_certs(ca_cert_path: str, wine_prefix: str) -> dict[str, Any]:
    """Install a self-signed CA cert into the Wine CA store (replacement for `certutil`).

    Args:
        ca_cert_path: absolute path to the .pem cert to install
        wine_prefix: WINEPREFIX path

    Returns:
        dict with keys: status, cert_installed, path
    """
    # v0.1.0 SCAFFOLD: uses certutil if available, else drops into system32/certs-<name>.pem as fallback
    import shutil
    import subprocess

    cert_name = Path(ca_cert_path).stem
    target_path = Path(wine_prefix) / "drive_c" / "windows" / "system32" / f"certs-{cert_name}.pem"
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(ca_cert_path, target_path)

    if shutil.which("certutil"):
        result = subprocess.run(
            ["certutil", "-addstore", "-f", "root", ca_cert_path],
            capture_output=True,
            text=True,
        )
        return {
            "status": "certutil" if result.returncode == 0 else "certutil-failed",
            "cert_installed": result.returncode == 0,
            "path": str(target_path),
        }

    return {
        "status": "fallback-drop-only",
        "cert_installed": False,
        "path": str(target_path),
        "note": "certutil not available; cert dropped to system32 only. Apps that don't trust the drop location will fail TLS verification.",
    }


def main():
    log.info("re-traffic-capture v%s SCAFFOLD", __version__)
    mcp.run()


if __name__ == "__main__":
    main()
