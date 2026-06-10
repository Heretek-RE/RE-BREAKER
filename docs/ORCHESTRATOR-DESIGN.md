# Orchestrator Design (v0.1.0)

**Closes G2** — runtime execution of bypass recipes.

## What the orchestrator is

A thin composition layer. It does NOT duplicate the catalog matching, recipe generation, or runtime execution. It composes the existing servers into a single workflow.

## What it does (v0.1.0)

Two tools:

### `re-orchestrator.status()`

Health check. Returns version, status, env, and tools_implemented/total.

### `re-orchestrator.plan(target)`

Dry-run mode. Returns a single JSON describing the 6-step workflow for a target:

1. **Triage** — `mcp__re-triage.triage_target(target, output=...)` if not already cached
2. **Catalog match** — `mcp__re-catalog-match.match_catalog(target, triage_json_path=...)`
3. **Encrypted-VM bypass** — `mcp__re-encrypted-vm-bypass.bypass_pattern(target, pattern=<from match>, mode=...)`
4. **Vendor anti-tamper** — `mcp__re-vendor-anti-tamper.run_vendor_tool(target, vendor=<from match>, mode=...)`
5. **Anti-VM spoof** — `mcp__re-anti-vm-spoof.spoof_target(target, mode=frida)`
6. **Entitlement plan** — `mcp__re-entitlement-bypass.plan_emulation(target=<target_key>)`

Each step's `next_action` field is the literal MCP tool call to make. The Claude Code conversation can invoke these in order.

### `re-orchestrator.execute(target, runtime_mode)`

**Not implemented in v0.1.0.** Returns `{status: "not_implemented", note: "v0.1.0 is plan-only"}`.

The execution path requires the parent MCP manager to forward tool calls between sibling servers (e.g., orchestrator → re-catalog-match → re-encrypted-vm-bypass). Claude Code's MCP protocol does not currently support this — each MCP server is a separate stdio process and can only be called by the host (Claude Code), not by another server.

## Why "thin"?

A fat orchestrator that re-implemented catalog matching, recipe generation, etc. would be:
- Duplicative (the same logic would have to be in two places)
- Stale-prone (catalog entries change, recipes evolve)
- Harder to test

A thin orchestrator that just chains the existing tools is:
- Honest (it doesn't pretend to be smarter than the tools)
- Maintainable (catalog changes propagate automatically)
- Testable (each step is independently verifiable)

## v0.2.0 design (proposed)

Three options for the actual execution:

**Option A: in-process CLI invocation**
The orchestrator subprocess-invokes the existing CLI tools (`re-dump`, `re-anti-debug-patch`, etc.) directly. Pros: works today. Cons: bypasses the MCP layer, no audit trail.

**Option B: parent MCP manager forwarding**
Extend the parent MCP manager (Claude Code) to forward tool calls between siblings. Pros: clean. Cons: requires Claude Code protocol changes.

**Option C: shared state via IPC**
The orchestrator + per-step servers communicate via a shared IPC channel (named-pipe or Unix-socket). Pros: works with current MCP. Cons: more infra.

v0.2.0 will implement Option A (CLI invocation) as the baseline, since the CLIs exist and are tested. Option B is the long-term goal.

## How the orchestrator fits with the other servers

```
                +-------------------+
                | re-orchestrator   |  ← thin composition
                | (plan + execute)  |
                +---------+---------+
                          |
       composes (CLI subprocess or MCP call)
                          v
  +-------+-------+-------+-------+-------+-------+
  | triage| catalog| bypass| vendor| anti-vm| entit|
  +-------+-------+-------+-------+-------+-------+
                          |
                they use the underlying engines
                          v
       +---------+---------+---------+---------+
       | patch-apply | frida | inject | runtime |
       +---------+---------+---------+---------+
```

The orchestrator is a coordinator. The underlying servers are the workers. The orchestrator doesn't add capability; it adds workflow.

## Per-target workflow example (FM26)

```
mcp__re-triage.triage_target(target=".../fm.exe", output=".../orchestrator/")
mcp__re-catalog-match.match_catalog(target=".../fm.exe",
                                     triage_json_path=".../orchestrator/fm-triage.json",
                                     min_confidence=0.3)
                                          | returns 6 matches (Pattern A at 0.40, anti-debug primitives)
                                          v
mcp__re-encrypted-vm-bypass.bypass_pattern(target=".../fm.exe", pattern="A", mode="emulator")
                                          | returns 2-step recipe:
                                          |   step 1: re-anti-debug-patch(rdtsc=zero, cpuid=zero)
                                          |   step 2: re-vm-decrypt(pattern=A, mode=emulator)
                                          v
mcp__re-anti-debug-patch.patch_target(target=".../fm.exe", rdtsc=zero, cpuid=zero)
                                          | returns patch plan with per-site RVAs
                                          v
mcp__re-patch-apply.apply_patch(target=".../fm.exe", patch_plan=<from above>, output=..., verify=True)
                                          | applies the patches
                                          v
mcp__re-vm-decrypt.decrypt_target(target=".../fm.exe/GameAssembly.dll", pattern="A", mode="emulator")
                                          | returns the decryption plan (v0.2.0: actually executes)
                                          v
mcp__re-anti-vm-spoof.spoof_target(target=".../fm.exe", mode="frida")
                                          | returns the frida-script-based hook plan
                                          v
mcp__re-frida-runtime.frida_attach(target=".../fm.exe", pattern="A", hooks=...)
                                          | actually installs the hooks
                                          v
mcp__re-entitlement-bypass.plan_emulation(target="fm26")
                                          | returns the per-layer entitlement plan
                                          v
mcp__re-entitlement-bypass.bypass_entitlement(target=".../fm.exe", vendor="steam", mode="emulator")
                                          | real: deploys gbe_fork stub
```

This is the v0.2.0 runtime. v0.1.0 is plan-only.

## Files

- Server: `servers/re-orchestrator/src/re_orchestrator/server.py`
- Plan / execute / status tools
- Registered in `.mcp.json`

## Per-engagement status

| SOW | Target | plan() | execute() v0.2.0 |
|---|---|---|---|
| L | 007FL | yes (10 catalog matches) | blocked by Denuvo + Wine cryptasn |
| M | FM26 | yes (6 matches) | blocked by Steam CEG stub-drop runtime |
| N | HKIA | yes (8 matches, stripped metadata) | blocked by Sunblink protocol RE |
| O | CD | yes (12 matches) | blocked by Denuvo + Wine cryptasn |
| P | P3R | yes (12 matches) | blocked by Denuvo |
| Q | TWW3 | yes (12 matches) | blocked by EOS handshake + Wine SEH |

For all 6: `plan()` returns a real workflow. `execute()` is a v0.2.0 follow-up.
