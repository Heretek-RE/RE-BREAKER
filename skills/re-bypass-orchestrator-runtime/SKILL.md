# re-bypass-orchestrator-runtime

**v0.7.0 NEW.** Workflow for the new re-orchestrator MCP server. Closes G2.

## When to use this skill

Invoke when:
- The catalog match returned a meaningful match set (≥ 3 matches)
- The operator wants a single end-to-end workflow instead of per-tool calls
- The operator is in a "let the toolkit drive" mode (vs. an interactive RE session)

## What the orchestrator does

The orchestrator chains the planning tools into a single 6-step workflow:

1. **Triage** — `re-triage.triage_target(target, output=...)` (cached if already triaged)
2. **Catalog match** — `re-catalog-match.match_catalog(target, triage_json_path=...)`
3. **Encrypted-VM bypass** — `re-encrypted-vm-bypass.bypass_pattern(target, pattern=<from match>)`
4. **Vendor anti-tamper** — `re-vendor-anti-tamper.run_vendor_tool(target, vendor=<from match>)`
5. **Anti-VM spoof** — `re-anti-vm-spoof.spoof_target(target)`
6. **Entitlement plan** — `re-entitlement-bypass.plan_emulation(target=<key>)`

`re-orchestrator.plan(target)` returns the workflow as JSON, with each step's `next_action` field listing the literal MCP tool call to make.

`re-orchestrator.execute(target)` is **v0.2.0 follow-up** — it would actually invoke the tools via the parent MCP manager. v0.1.0 is plan-only.

## Tools invoked

- `mcp__re-orchestrator.status()` — health check
- `mcp__re-orchestrator.plan(target, catalog_min_confidence=0.3)` — workflow JSON
- `mcp__re-orchestrator.execute(target, runtime_mode=frida)` — v0.2.0 (currently not_implemented)

## Workflow (v0.7.0 — manual execution)

1. **Run plan().** `mcp__re-orchestrator.plan(target=".../fm.exe")` returns the 6-step workflow.
2. **Walk the workflow.** For each step's `next_action`, invoke the corresponding MCP tool from the Claude Code conversation:
   - `mcp__re-triage.triage_target(...)` for step 1
   - `mcp__re-catalog-match.match_catalog(...)` for step 2
   - etc.
3. **Aggregate results.** Each tool returns a per-step status + payload paths. The orchestrator's plan() output provides the per-step scaffolding.

## Example

For FM26 (`/Input/<target-game>/fm.exe`):

```
plan() returns:
  step 1: mcp__re-triage.triage_target(target=..., output=.../orchestrator/)
  step 2: mcp__re-catalog-match.match_catalog(target=..., triage_json_path=.../orchestrator/fm-triage.json, min_confidence=0.3)
  step 3: mcp__re-encrypted-vm-bypass.bypass_pattern(target=..., pattern=A, mode=frida)
  step 4: mcp__re-vendor-anti-tamper.run_vendor_tool(target=..., vendor=denuvo, mode=frida)  # returns out_of_scope=True
  step 5: mcp__re-anti-vm-spoof.spoof_target(target=..., mode=frida)
  step 6: mcp__re-entitlement-bypass.plan_emulation(target=fm26)
```

FM26 has 3 entitlement layers (steam_ceg, eos, sega_sso) — the plan_emulation() call returns all 3.

## What this skill does NOT do

- Does not actually execute the workflow (v0.2.0). The user invokes each step's tool from the conversation.
- Does not bypass the entitlement layer (that's a separate step, gated on the entitlement emulator being live).
- Does not bypass Denuvo (out of scope per MRTEA Part V §4.1). The orchestrator returns `out_of_scope: true` and the Pattern A-DW fallback.

## Where this fits in the existing skill taxonomy

- **re-runtime-frida** — runtime frida attach (the actual execution)
- **re-c-injection-build** — builds the C injection lib with the hook_specs
- **re-anti-debug-patch-apply** — workflow for static patching
- **re-bypass-orchestrator-runtime** (this) — workflow for chaining all the above

This is the topmost layer. Use it when you want the toolkit to coordinate the lower-level skills automatically.
