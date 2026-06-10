---
name: re-triage-fresh-target
version: 0.3.0
status: implemented
family: workflow
catalog_entry: null
playbook: docs/PLAYBOOKS/pattern-a.md
pattern_yaml: data/patterns/triage-fresh-target.yml
---

# re-triage-fresh-target

**v0.3.0 implemented.** Triage a target that has **no prior analysis** (no honest-read triage.json, no GameAssembly.dll, no static analysis output). Closes G3: the v0.2.0 catalog match required pre-computed triage from the vendored honest-read; fresh targets couldn't be triaged.

## When to use this skill

Invoke when:
- The target is a new binary with no prior vendored analysis
- The catalog match returns `error: no triage.json found`
- The operator wants to set up a new target from scratch

## Tools invoked

- `mcp__re-triage.triage_target(target, output)` — runs the in-tree re-triage primitives on the binary + produces the triage JSON
- `mcp__re-catalog-match.match_catalog(target, intent="both")` — runs the catalog match against the freshly-produced triage

## Workflow

1. **Run re-triage on the target.** Call `mcp__re-triage.triage_target(target, output="/tmp/<key>-triage/")`. The response includes the per-site RVA enumeration (closes G5) and a `triage_json_path` field.
2. **Pass the freshly-produced triage to re-catalog-match.** Call `mcp__re-catalog-match.match_catalog(target, intent="both", triage_json_path="<path-from-step-1>", main_binary="<path>")`. The catalog match returns the ranked matches.
3. **Continue with the per-tool plans** (re-anti-debug-patch, re-anti-vm-spoof, re-vm-decrypt, etc.) as documented in `re-bypass-pattern-a`.

## What this skill does NOT do

- Does not execute any bypass. The triage + catalog match are read-only.
- Does not invoke Frida or runtime tools. Use `re-runtime-frida` for that.
- Does not patch any binary. Use `re-anti-debug-patch-apply` for that.

## Known limitations

- The on-the-fly re-triage uses a pure-Python PE parser for sections (lief if available). For extremely large binaries (>1GB), the section parse can be slow. Consider using the in-tree re-lief (vendored) for production triage.
- The on-the-fly triage does not perform symbolic execution. The per-site RVA enumeration is byte-pattern matching only.

## Test cases

- A fresh binary from `tests/fixtures/` (any small .exe) should produce a valid triage JSON in <1s.
- The re-triage tool can scan a 50MB binary in <1s, a 500MB binary in ~10s.

## See also

- [RE-BREAKER README](../../README.md)
- [Threat model](../../THREAT-MODEL.md)
- [re-triage server](../../servers/re-triage/)
- [re-catalog-match server](../../servers/re-catalog-match/)
- [Pattern A playbook](../../docs/PLAYBOOKS/encrypted-vm-bytecode-interpreter-pattern-a.md)
