---
name: re-orchestrator-debug-auto-start
version: 0.1.0
status: implemented
family: workflow-orchestration
severity: medium
---

# re-orchestrator-debug-auto-start

**v0.8.0+ Wave 3 (Item H).** The orchestrator's `execute()` now auto-starts the preferred debugger (x64dbg / IDA Pro / Ghidra) before any debug step.

## When to use

Always. The `execute()` tool takes a `preferred_debugger` parameter; set it to:
- `"auto"` (default) — pick based on the target's size:
  - < 10 MB → x64dbg (fast runtime patching)
  - < 100 MB → IDA Pro (medium analysis)
  - ≥ 100 MB → Ghidra (headless, handles huge binaries)
- `"x64dbg" | "ida" | "ghidra"` — explicit choice
- `"none"` — skip auto-start entirely

## How it works

1. `execute(target, preferred_debugger=...)` is called.
2. Before any debug step (Step 0), `_auto_start_debugger()` is called.
3. The auto-start function:
   - Picks the debugger (auto-detect by size, or explicit)
   - Calls the appropriate `start_*` tool from the debugger's MCP server
   - These are idempotent — if the debugger is already started, returns `already_started: True`
4. The orchestrator continues with the rest of the workflow (triage, catalog match, etc.)

## Example

```python
# Auto-pick based on target size
mcp__re-orchestrator.execute(target="/path/to/fm.exe", runtime_mode="frida")

# Force x64dbg
mcp__re-orchestrator.execute(target="/path/to/fm.exe", runtime_mode="frida", preferred_debugger="x64dbg")

# Skip auto-start (you've already started the debugger yourself)
mcp__re-orchestrator.execute(target="/path/to/fm.exe", runtime_mode="frida", preferred_debugger="none")
```

## Known limitations

- The auto-start adds ~10-20s of debugger startup time (especially for Ghidra).
- Auto-start fails gracefully — if the debugger binary isn't installed, the orchestrator continues with a `status: "error"` step result; the rest of the workflow still runs.
- The `start_x64dbg` / `start_ida_mcp` / `start_ghidra_mcp` tools must be reachable via `from re_*_remote.server import start_*`. If the debugger's MCP server isn't running, the import fails.

## See also

- [RE-BREAKER README](../../README.md)
- [Orchestrator workflow](../../docs/ORCHESTRATOR.md)
- [Threat model](../../THREAT-MODEL.md)
