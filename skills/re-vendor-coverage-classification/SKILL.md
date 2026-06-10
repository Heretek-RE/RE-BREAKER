# re-vendor-coverage-classification

**v0.7.0 NEW.** Closes G10. Distinguishes "general tool" vs "class-of-technique Bypass" vs "out-of-scope" in vendor plans.

## When to use this skill

Invoke when:
- Planning a vendor attack for a target
- The `re-vendor-anti-tamper.run_vendor_tool()` returns `out_of_scope: true`
- You need to know if there's a real attack path (class-of-technique) or if it's truly out of scope

## The three coverage classes

### `general`
A general tool exists that can bypass the vendor's protection:
- **VMProtect** (64-bit): `anpa1200/Unpacker` via Qiling
- **VMProtect** (32-bit): `anpa1200/Unpacker` via Unipacker
- **Themida** (32-bit): `anpa1200/Unpacker` via Unipacker
- **EA Anti-Cheat** (EAC): not a DRM (anti-cheat) — out of charter

### `class`
A class-of-technique Bypass applies, but per-target work is required:
- **Denuvo Anti-Tamper**: Pattern A-DW workflow (months of per-target work)
- **Pearl Abyss internal** (CD): PA-specific RE work (per-target)
- **IOI Account** (007FL): IOI-specific RE work (per-target)
- **Sunblink** (HKIA): SCAFFOLD — needs wire format RE (S5 skill)

### `out_of_scope` / `defensive_utility_only`
The vendor's protection is out of charter per MRTEA Part V:
- **EAC, BattlEye**: anti-cheat, not anti-RE (per MRTEA Part V §5)
- **EAAC, VAC**: same
- **Starforce, Arxan**: no public tools, no class-of-technique Bypass
- **QEMU source patches**: would need a fork (out of v0.7.0)

## Tools invoked

- `mcp__re-vendor-anti-tamper.run_vendor_tool(target=..., vendor=..., mode=...)` — now returns `coverage: [general|class|out_of_scope]` alongside `out_of_scope: bool`
- Manual: read the per-vendor playbook in `docs/PLAYBOOKS/`

## Workflow

1. **Check the catalog entry.** Look up the vendor in `data/catalog.json`:
   ```python
   import json
   d = json.load(open("data/catalog.json"))
   entry = next(e for e in d["entries"] if "denuvo" in e["id"])
   print(entry.get("v0_7_0", {}))  # → {"coverage": "class"}
   ```

2. **Call the vendor tool.**
   ```
   mcp__re-vendor-anti-tamper.run_vendor_tool(target=".../fm.exe", vendor="denuvo", mode="emulator")
   ```
   Returns: `{coverage: "class", out_of_scope: true, fallback: "Use Pattern A-DW workflow", ...}`

3. **Choose the attack path:**
   - `general`: use the tool directly (e.g., `anpa1200/Unpacker`)
   - `class`: use the class-of-technique workflow (e.g., Pattern A-DW for Denuvo)
   - `out_of_scope`: document the gap, do not attempt the bypass

## What this skill does NOT do

- Does not bypass the vendor — it just classifies
- Does not replace the actual bypass — you still need to invoke the bypass tool separately
- Does not change the catalog — coverage is added per the G10 fix, but the underlying bypass logic is unchanged

## Effort estimate

The G10 fix (adding the `coverage` field to vendor plans) is ~2 hours, already done. The per-vendor playbook updates are ~4 hours.
