---
name: re-bypass-vmprotect
version: 0.3.0
status: implemented
family: anti-tamper-vendors
severity: critical
catalog_entry: anti-tamper-vendors.vmprotect
playbook: docs/PLAYBOOKS/pattern-a-vmt-blackspace.md
pattern_yaml: data/patterns/pattern-a-vmt.yml
---

# re-bypass-vmprotect

**v0.3.0 (v0.8.0+ Wave 2 Item F): VMProtect unpacking via anpa1200/Unpacker.** Replaces the v0.2.0 references to void-stack/VMUnprotect and can1357/NoVmp (both unmaintained as of 2024-Q2).

## When to use this skill

The catalog's anti-tamper-vendors.vmprotect entry matches. The skill delegates to [anpa1200/Unpacker](https://github.com/anpa1200/Unpacker) (vendored at `vendored/anpa1200-Unpacker/`), which integrates:
- Unipacker (32-bit, for legacy VMProtect 2.x)
- Qiling (64-bit, for modern VMProtect 3.x)

See `vendored/anpa1200-Unpacker/README.md` for the one-time setup.

## Tools invoked

- `mcp__re_vendor_anti_tamper.run_vendor_tool(vendor="vmprotect", target=...)` — actually invokes anpa1200 (v0.8.0+)
- `mcp__re_vm_decrypt.*` — re-vm-decrypt (for the lifted method bodies)
- `mcp__re_runtime_dump.*` — re-runtime-dump (for the runtime dump)



## v0.3.0 pre-step: Resolve the main binary

**Add this step to the existing workflow before Step 1.**

0. **Resolve the main binary.** If the target is a Unity IL2CPP launcher
   (a small ~660KB .exe with a companion `GameAssembly.dll` in the same
   dir), call `mcp__re-il2cpp-triage.triage_il2cpp(launcher_path=target)` to
   redirect the analysis to `GameAssembly.dll` (which contains the
   encrypted-VM bytecode interpreter). If the target has no prior triage,
   call `mcp__re-triage.triage_target(target)` to compute the triage
   on-the-fly. **Then pass `main_binary` to the catalog match**:
   `mcp__re-catalog-match.match_catalog(target=target, main_binary="<resolved-main>")`.

This pre-step is required for FM26 / HKIA / LIR (Unity IL2CPP launchers).
For non-IL2CPP targets (P3R / 007FL / CD / TWW3) it can be skipped.

## Workflow

1. **Confirm the catalog match.** Run `mcp__re-catalog-match.match_catalog(target, intent="offender")` and verify the match is `anti-tamper-vendors.vmprotect` with high confidence.
2. **Plan the bypass.** Run `mcp__re-encrypted-vm-bypass.bypass_pattern(target, pattern="<the-pattern>", mode=...)` (or `mcp__re-vendor-anti-tamper.run_vendor_tool(...)` for vendor skills) and capture the structured plan.
3. **Apply anti-debug patches if the target has anti-debug.** Run `mcp__re-anti-debug-patch.patch_target(target, rdtsc_strategy="zero", cpuid_strategy="zero", ...)` and confirm the patch plan is sound.
4. **Apply anti-VM spoof if the target has anti-VM detection.** Run `mcp__re-anti-vm-spoof.spoof_target(target, cpuid_strategy="bare-metal-snapshot", vmdetect_strategy="zero", ...)` and confirm the hook plan is sound.
5. **Lift the encrypted-VM-encrypted method bodies.** Run `mcp__re-vm-decrypt.decrypt_target(target, pattern="<the-pattern>", mode=...)` and confirm the per-method extraction plan.
6. **Document the result.** Write `Output/<date>/per-binary/<key>/bypass-result.md` with: which primitives were neutralized, which sections were decrypted, what the runtime cost was, what was NOT possible.

## Known limitations

- The bypass is per-build breakable; a publisher-pushed update requires a re-run.
- The bypass is lab-only per MRTEA §4. Production deployment is prohibited without an executed SOW.
- White-box crypto key extraction is prohibited as a deliverable per MRTEA Part V §4.1 — only the bypass technique is delivered.
- For anti-cheat vendors (EAC, BE), the skill is defensive-utility only per MRTEA Part V §5.

## Test cases

- (no specific test cases documented; see the playbook for target classes)

## See also

- [RE-BREAKER README](../../README.md)
- [Threat model](../../THREAT-MODEL.md)
- [License + Offensive-Research-Use clause](../../LICENSE-OFFENSIVE.md)
- [Catalog entry this skill implements](../../data/catalog.json) — `anti-tamper-vendors.vmprotect`
- [Pattern YAML](../../data/patterns/pattern-a-vmt.yml)
- [Playbook](../../docs/PLAYBOOKS/pattern-a-vmt-blackspace.md)
