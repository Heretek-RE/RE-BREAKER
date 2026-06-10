---
name: re-il2cpp-triage
version: 0.3.0
status: implemented
family: workflow
catalog_entry: null
playbook: docs/PLAYBOOKS/encrypted-vm-bytecode-interpreter-pattern-a.md
pattern_yaml: data/patterns/il2cpp-triage.yml
---

# re-il2cpp-triage

**v0.3.0 implemented.** Unity IL2CPP-specific triage workflow. For a Unity IL2CPP launcher (e.g. `fm.exe`, `P3R.exe`, `Hello Kitty.exe`), find the companion `GameAssembly.dll` (50-500MB) + `il2cpp_data/Metadata/global-metadata.dat` and run the per-binary triage on the .dll (not the launcher). Closes G1: the v0.2.0 catalog match ran against the launcher's ~660KB triage, missing the encrypted-VM bytecode interpreter entirely.

## When to use this skill

Invoke when:
- The target is a Unity IL2CPP launcher (~660KB executable)
- The companion `GameAssembly.dll` exists in the same dir
- The catalog match returns 0 matches because the launcher's section set + primitive counts are too small

## Tools invoked

- `mcp__re-il2cpp-triage.triage_il2cpp(launcher_path)` — auto-detects `GameAssembly.dll` + `global-metadata.dat` + `il2cpp.usym`, runs re-triage on the .dll, returns the triage JSON
- `mcp__re-catalog-match.match_catalog(target, intent="both", main_binary="<GameAssembly.dll>")` — runs the catalog match against the .dll's triage

## Workflow

1. **Auto-detect the GameAssembly.dll.** Call `mcp__re-il2cpp-triage.auto_detect(target=launcher_path)`. The response includes `main_binary` (the path to the .dll) + `main_binary_size_bytes`.
2. **Run the per-binary triage on the .dll.** Call `mcp__re-il2cpp-triage.triage_il2cpp(launcher_path=launcher_path, output="/tmp/<key>-il2cpp-triage/")`. The response includes:
   - `game_assembly` — path to the .dll
   - `metadata` — path + version of `global-metadata.dat` + whether it's Unity 6 or newer (Gap 25)
   - `usym` — path to `il2cpp.usym` or None
   - `is_stripped_metadata` — whether the metadata is stripped (Gap 26)
   - `triage_json_path` — path to the freshly-produced triage JSON
3. **Pass the .dll's triage to re-catalog-match.** Call `mcp__re-catalog-match.match_catalog(target=launcher_path, intent="both", triage_json_path="<triage-from-step-2>", main_binary="<GameAssembly.dll>")`. The catalog match now reads the .dll's triage (which has the encrypted-VM section set + the anti-debug primitives).
4. **Continue with the per-tool plans** as documented in `re-bypass-pattern-a`.

## What this skill does NOT do

- Does not invoke `re-il2cpp-static-triage`'s runtime-Frida-fallback (Gap 26) when metadata is v30/v31/v32 or `.usym` is missing. That integration is a future v0.4.0 item.

## Known limitations

- If the .dll uses an obfuscated loader (e.g. custom anti-tamper wrapping GameAssembly.dll in a custom packer), the re-triage will see the wrapper rather than the IL2CPP bytecode. v0.3.0 detects the standard Unity IL2CPP layout; custom packers are out of scope.
- If the metadata version is v30/v31/v32 (Unity 6+), the re-il2cpp-static-triage's runtime-Frida-fallback is required (Gap 25 unresolved). v0.3.0 notes this in the response (`is_unity_6_or_newer: true`) but doesn't invoke the fallback.

## Test cases

- **FM26**: `GameAssembly.dll` (50.4MB, 7 sections, no .usym, 61 RDTSC + 84 CPUID). Returns 6 catalog matches (was 0 in v0.2.0).
- **HKIA**: `GameAssembly.dll` (360.4MB, 18 sections, no .usym, 1617 RDTSC + 1.7M CPUID + 16 VMCALL). Returns 12 catalog matches (was 0 in v0.2.0).
- **LIR**: `GameAssembly.dll` (505.8MB, 16 sections, no .usym, 2531 RDTSC + 3.6M CPUID + 32 VMCALL). Returns 10 catalog matches (was 0 in v0.2.0).

## See also

- [RE-BREAKER README](../../README.md)
- [re-il2cpp-triage server](../../servers/re-il2cpp-triage/)
- [re-catalog-match server](../../servers/re-catalog-match/)
- [Pattern A playbook](../../docs/PLAYBOOKS/encrypted-vm-bytecode-interpreter-pattern-a.md)
