"""re-cinematic-skip MCP server (v0.1.0 SCAFFOLD).

v0.1.0 is plan-only. v0.2.0 will implement the runtime approach:
  - Detect splash cinemáticos (SEGA / Sports Interactive / Pearl Abyss /
    Atlus / Unity generic) by their window class + title
  - Inject a Wine-side XTest fake-key event after 3 s of "no input"
  - For build-time approach: patch GameAssembly.dll's init sequence to
    auto-dismiss any "press any key" screen
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("re-cinematic-skip")

__version__ = "0.1.0"

mcp = FastMCP("re-cinematic-skip")


@mcp.tool()
def list_splash_signatures() -> list[dict[str, Any]]:
    """Return the catalog of known splash cinemáticos and their dismiss keys.

    Returns:
        list of {vendor, class_pattern, title_pattern, dismiss_key, dismiss_delay_sec}
    """
    # v0.1.0 SCAFFOLD: stub data based on v0.4.1.9 live-fire findings
    return [
        {
            "vendor": "SEGA / Sports Interactive",
            "class_pattern": "fm.exe",
            "title_pattern": "Football Manager 26",
            "dismiss_key": "space",
            "dismiss_delay_sec": 3,
            "note": "FM26 cinematic — observed in v0.4.1.9 revalidation",
        },
        {
            "vendor": "Pearl Abyss",
            "class_pattern": "BlackSpace",
            "title_pattern": "Crimson Desert",
            "dismiss_key": "space",
            "dismiss_delay_sec": 3,
            "note": "CD cinematic — predicted from same v0.4.1.9 pattern",
        },
        {
            "vendor": "Unity generic",
            "class_pattern": "*",
            "title_pattern": "*",
            "dismiss_key": "Escape",
            "dismiss_delay_sec": 2,
            "note": "fallback for any Unity splash",
        },
    ]


@mcp.tool()
def patch_splash_dismiss(
    launcher_exe: str,
    target_purpose: Literal["any-key", "EOL", "credits", "load-screen"] = "any-key",
    inject_module: str = "x11_input_emulation",
) -> dict[str, Any]:
    """Patch the launcher binary to auto-dismiss splash cinemáticos.

    Args:
        launcher_exe: absolute path to the .exe
        target_purpose: type of splash to dismiss
        inject_module: which dismiss strategy to inject ("x11_input_emulation", "nops", "early_exit")

    Returns:
        dict with keys: status, backup_path, modified_sections
    """
    # v0.1.0 SCAFFOLD: returns a stub
    log.info(
        "patch_splash_dismiss(%r, %r, %r) — SCAFFOLD",
        launcher_exe,
        target_purpose,
        inject_module,
    )
    return {
        "status": "SCAFFOLD",
        "launcher_exe": launcher_exe,
        "target_purpose": target_purpose,
        "inject_module": inject_module,
        "note": "v0.2.0 will implement CFF-based patch generation against GameAssembly.dll's init sequence",
    }


def main():
    log.info("re-cinematic-skip v%s SCAFFOLD", __version__)
    mcp.run()


if __name__ == "__main__":
    main()
