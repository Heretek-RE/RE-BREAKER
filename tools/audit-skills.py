#!/usr/bin/env python3
"""audit-skills.py — per bug ledger C-01.

Per the v0.4.0 live-fire bug ledger (See the output directory.
14 skills reference ~9 MCP tools that are not registered in .mcp.json. This script:

1. Parses every SKILL.md in skills/
2. Greps for mcp__<srv>.<tool> AND mcp__<srv>__<tool> references
3. Cross-references against the RE-BREAKER .mcp.json's mcpServers dict
4. Outputs a per-skill gap list (referenced tool not in .mcp.json)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SKILLS_DIR = Path("skills")
MCP_CONFIG_PATHS = [
    Path(".") / ".mcp.json",  # RE-BREAKER/.mcp.json
    Path.home() / ".claude.json",
    Path.home() / ".claude" / "settings.json",
]

# Tool refs in skills use BOTH forms:
#   - mcp__<srv>.<tool>(...)  (period — used in skill body docs)
#   - mcp__<srv>__<tool>(...)  (double underscore — used in actual MCP server tool names)
# We grep for both.
TOOL_REF_PATTERN = re.compile(r"mcp__([a-z0-9_-]+)(?:__|\.)([a-z0-9_]+)")


def load_mcp_servers() -> set[str]:
    """Return the set of registered MCP server names (e.g. {'re-triage', 're-catalog-match', ...})."""
    servers: set[str] = set()
    for path in MCP_CONFIG_PATHS:
        if not path.exists():
            continue
        try:
            cfg = json.loads(path.read_text())
            s = cfg.get("mcpServers") or cfg.get("mcp_servers") or {}
            for srv_name in s.keys():
                servers.add(srv_name)
        except Exception as e:
            print(f"warn: failed to parse {path}: {e}", file=sys.stderr)
    return servers


def find_tool_refs(skill_text: str) -> set[str]:
    """Extract every mcp__<srv>.<tool> or mcp__<srv>__<tool> reference from a skill."""
    return {f"mcp__{m.group(1)}__{m.group(2)}" for m in TOOL_REF_PATTERN.finditer(skill_text)}


def main() -> int:
    registered = load_mcp_servers()
    if not registered:
        print("error: no MCP servers found in any known config", file=sys.stderr)
        return 1
    print(f"Registered MCP servers ({len(registered)}): {sorted(registered)}")
    print()

    skills = sorted(p for p in SKILLS_DIR.glob("*/SKILL.md"))
    if not skills:
        print(f"error: no skills found in {SKILLS_DIR}", file=sys.stderr)
        return 1

    total_refs = 0
    total_gaps = 0
    per_skill_gaps: dict[str, set[str]] = {}
    for skill_path in skills:
        text = skill_path.read_text()
        refs = find_tool_refs(text)
        gaps: set[str] = set()
        for ref in refs:
            srv = ref.split("__")[1]  # mcp__<srv>__<tool> -> srv
            if srv not in registered:
                gaps.add(ref)
        if gaps:
            per_skill_gaps[skill_path.parent.name] = gaps
            total_gaps += len(gaps)
        total_refs += len(refs)

    print(f"Audit summary: {len(skills)} skills, {total_refs} tool refs, {total_gaps} gaps")
    print()
    if per_skill_gaps:
        print("Per-skill gap list (referenced tool not in .mcp.json):")
        for skill_name, gaps in sorted(per_skill_gaps.items()):
            print(f"  {skill_name}:")
            for g in sorted(gaps):
                srv = g.split("__")[1]
                print(f"    - {g}  (server '{srv}' not registered)")
    else:
        print("No gaps. All skill tool references are registered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
