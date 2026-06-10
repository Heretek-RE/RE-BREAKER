---
name: re-anti-debug-patch-apply
version: 0.3.0
status: implemented
family: workflow
catalog_entry: null
playbook: docs/PLAYBOOKS/pattern-a.md
pattern_yaml: data/patterns/anti-debug-patch-apply.yml
---

# re-anti-debug-patch-apply

**v0.3.0 implemented.** Workflow for actually applying the per-site anti-debug patch plan to a binary. Closes G2 (runtime execution was dry-run in v0.2.0) + G5 (per-site RVA enumeration).

## When to use this skill

Invoke when:
- The catalog match returned anti-debug entries (rdtsc-timing-trap, cpuid-hypervisor-leaf-1-ecx-bit-31, int2d, int3, vmcall, vmxon)
- The operator wants to actually patch the binary (not just generate a plan)

## Tools invoked

- `mcp__re-anti-debug-patch.patch_target(target, strategy=...)` — generates the per-site patch plan
- `mcp__re-patch-apply.apply_patch(target, patch_plan, output, verify)` — actually applies the patches
- Optionally: `mcp__re-speakeasy.run(patched_binary)` — verifies the patched binary doesn't crash (closes the verify step)

## Workflow

1. **Generate the patch plan.** Call `mcp__re-anti-debug-patch.patch_target(target, rdtsc_strategy="zero", cpuid_strategy="zero", vmxon_strategy="zero", vmcall_strategy="zero", int2d_strategy="zero", int3_strategy="zero")`. The response includes the per-primitive patch plan with `estimated_sites` per primitive (v0.2.0 granularity).
2. **Pass the patch plan to re-patch-apply.** Call `mcp__re-patch-apply.apply_patch(target=target, patch_plan=patch_plan, output="/tmp/<key>-patched/", verify=True)`. The response includes:
   - `patched_binary` — the patched .exe/.dll path
   - `patch_log` — the per-site patch log (closes G5: 200+ entries with rva, original_bytes, patched_bytes for each site)
   - `sites_patched` — count of sites actually patched
   - `sites_skipped` — count of sites that didn't match (mismatched bytes)
   - `verify` — the re-speakeasy dry-run result
3. **Verify the patched binary.** If `verify=True`, re-speakeasy is invoked. The patched binary should not crash (no SIGABRT) and should not contain the patched primitives.
4. **Re-run the catalog match on the patched binary** to confirm the Bypass worked:
   ```python
   mcp__re-catalog-match.match_catalog(target=<patched-binary>, intent="defender")
   ```
   The patched binary should now return 0 anti-debug matches (the RDTSC/CPUID/INT 2D/INT 3 sites are gone).

## What this skill does NOT do

- Does not run the patched binary in a live Windows process. The verify step is a Speakeasy dry-run, not a real-process execution.
- Does not bypass AC products (EAC, BattlEye). For those, use `re-bypass-eac` or `re-bypass-be` (defensive-utility only per MRTEA Part V §5).

## Known limitations

- The on-the-fly patch application caps at 256 sites per primitive (v0.3.0 fix to prevent OOM on huge binaries). For binaries with >256 sites per primitive, the patch log notes "sites_skipped" for the rest. The user can pass `--max-sites` to override.
- The byte-pattern matching assumes the site is a "naked" instruction (e.g. `0F 31` not part of a longer sequence). For binaries with chained anti-debug primitives, the patcher may skip sites with mismatched bytes.

## Test cases

- **FM26 launcher (672KB)**: 1315 INT_3 sites patched in <1s. Patched binary is 672KB + ~700 bytes.
- **007 First Light (340MB)**: 1049 sites patched in 3m23s (256 sites per primitive cap × 5 primitives, minus 3 mismatches). Patched binary is 340MB.
- **P3R (356MB)**: ~1100+ sites patched in ~3-4 min (per the v0.3.0 expectations).

## See also

- [RE-BREAKER README](../../README.md)
- [re-anti-debug-patch server](../../servers/re-anti-debug-patch/)
- [re-patch-apply server](../../servers/re-patch-apply/)
- [Pattern A playbook](../../docs/PLAYBOOKS/encrypted-vm-bytecode-interpreter-pattern-a.md)
