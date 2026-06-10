"""MCP server entry point for re-capa."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from re_capa import capa_runner

logger = logging.getLogger("re_capa")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-capa")


@mcp.tool()
def check_capa() -> dict:
    """Return capa version and rules path."""
    return capa_runner.check_capa()


@mcp.tool()
def detect_capabilities(path: str, rules: str = "", format: str = "json") -> dict:
    """Run capa on *path* and return the full structured report.

    Args:
        path: file to analyze
        rules: optional custom rules directory
        format: "json" (default) or "vverbose" (human-readable)
    """
    return capa_runner.detect_capabilities(path, rules=rules, fmt=format)


@mcp.tool()
def extract_mbc(path: str, rules: str = "") -> dict:
    """Return only the Malware Behavior Catalog mappings.

    Args:
        path: file to analyze
        rules: optional path to a custom rules directory
    """
    return capa_runner.extract_mbc(path, rules=rules)


@mcp.tool()
def find_interesting(path: str, min_score: int = 3, rules: str = "") -> dict:
    """Filter capa's output to high-confidence / unique matches.

    Args:
        path: file to analyze
        min_score: minimum rule-per-namespace count to be "interesting"
        rules: optional path to a custom rules directory
    """
    return capa_runner.find_interesting(path, min_score, rules=rules)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
