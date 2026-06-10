# RE-BREAKER Agent Guide

This document describes how AI agents compose RE-BREAKER's 30 MCP servers and 35 skills into bypass workflows.

## Architecture

RE-BREAKER is a **self-contained plugin**. The `.mcp.json` registers all 30 servers; skills compose them into multi-step bypass workflows. The 8 RE-AI servers it depends on are vendored under `vendored/re-ai/` (library code, not MCP-exposed).

## The bypass workflow

A typical Pattern A bypass:

1. **Triage** — `re-triage.triage_target(path)` produces a triage JSON
2. **Catalog match** — `re-catalog-match.run_matcher(triage_json)` identifies the protection pattern
3. **Plan** — `re-encrypted-vm-bypass.plan_bypass(triage_json, pattern)` generates a step-by-step plan
4. **Execute** — `re-runtime-dump.execute_plan(plan)` runs the plan (Frida attach, method body capture, etc.)
5. **Verify** — `re-catalog-match.run_matcher(result_json)` confirms the protection is neutralized

## Pattern taxonomy

| Pattern | Description | Key servers |
|---|---|---|
| A | Encrypted-VM bytecode interpreter (IL2CPP) | re-vm-decrypt, re-encrypted-vm-bypass |
| A-DW | Pattern A + third-party ATD wrapping | re-vendor-anti-tamper, re-encrypted-vm-bypass |
| A-VMT | Handler-table dispatch (proprietary engine) | re-encrypted-vm-bypass |
| B | Hardware fingerprinting | re-anti-vm-spoof |
| C | Proprietary-engine VM | re-encrypted-vm-bypass |
| D | Telemetry leaks | re-vendor-anti-tamper |

## Skill categories

| Category | Skills | Effect envelope |
|---|---|---|
| **Pattern bypass** | re-bypass-pattern-{a,a-dw,a-vmt,b,c,d} | write-binary |
| **Vendor bypass** | re-bypass-{denuvo,vmprotect,themida,starforce,arxan,eac,be} | write-binary |
| **Entitlement** | re-entitlement-bypass, re-steam-ceg-bypass, re-eos-bypass | network + write |
| **Triage** | re-triage-fresh-target, re-il2cpp-triage | read-only |
| **Runtime** | re-runtime-frida, re-c-injection-build | write-binary |
| **VM** | re-vm-native-toolchain, re-vm-ui-automate, re-ssh-mcp-orchestrator | write-device |
| **Observability** | re-input-audit, re-vendor-coverage-classification | read-only |

## License gate

**All bypass CLI tools require `--license-acknowledge` before execution.** The CLI prints `LICENSE-OFFENSIVE.md` on first run and prompts for "I AGREE". Without this flag, the bypass primitives refuse to run (exit code 77).

MCP servers do not enforce the gate (they are library code). The gate is on the CLI entry points only.

## Key data files

- `data/catalog.json` — 59-entry defender+offender technique catalog
- `data/yara/techniques.yar` — YARA export of the catalog
- `data/patterns/*.yml` — per-Pattern bypass playbook YAMLs
- `data/catalog.json` references `drm-indicators.yaml` patterns for matching

## Vendored code

The `vendored/` directory makes RE-BREAKER self-contained:

- `vendored/re-ai/` — 8 RE-AI servers (re-lief, re-anti-analysis, re-rizin, re-yara, re-pdb, re-capa, re-patch, re-speakeasy). Library code used by RE-BREAKER's own servers via Python imports. NOT registered in `.mcp.json`.
- `vendored/persistproc/` — Cross-restart persistence (MIT)
- `vendored/touchpoint/` — UI automation (MIT, not yet wired)
- `vendored/ssh-mcp/` — SSH MCP bridge (MIT, not yet built)

See `vendored/re-ai/VENDORED.md` for provenance and sync policy.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `RE_BREAKER_PLUGIN_ROOT` | `.` | Root path for all RE-BREAKER resources |
| `RE_BREAKER_SSH_HOST` | — | Win11 VM SSH endpoint for VM servers |
| `RE_BREAKER_SSH_KEY` | — | Path to SSH private key for VM access |
| `RE_BREAKER_LICENSE_FILE` | `LICENSE-OFFENSIVE.md` | Path to the license gate document |

## Conventions

- **No engagement references** in committed code: no game titles, SOW codes, host paths, or per-target output paths.
- **Vendor names** at the protection-family level (Denuvo, EAC, VMProtect, etc.) are the subjects the tools analyze.
- **MCP servers** use `FastMCP`. Entry point is `server.py` with a `main()` function.
- **Skills** are SKILL.md files with YAML frontmatter. Each skill declares `effect_envelope` and `test_cases`.
