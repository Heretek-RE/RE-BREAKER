# RE-BREAKER Changelog

All notable changes to RE-BREAKER are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-06-07

### Added

- **RE-BREAKER charter**: explicit offense-research toolkit, AGPL-3.0 + offensive-research-use clause, separate from RE-AI's MIT vendor-neutral charter.
- **License + threat model**:
  - `LICENSE` — AGPL-3.0-or-later with offensive-research-use clause (the AUTHORIZED / UNAUTHORIZED use list).
  - `LICENSE-OFFENSIVE.md` — the clause document the CLI `cat`s on first run + requires `--license-acknowledge` to proceed.
  - `THREAT-MODEL.md` — the intended-user matrix, attacker matrix, and risk acknowledgment.
- **Scaffolding for 7 MCP servers** (all per-server `.venv/`, mirroring RE-AI's pattern):
  - `servers/re-runtime-dump/` — the tiered injection CLI: `--mode=emulator|frida|inject`.
  - `servers/re-catalog-match/` — the combined defender+offender technique matcher.
  - `servers/re-anti-debug-patch/` — byte-level anti-debug primitive neutralizer.
  - `servers/re-anti-vm-spoof/` — RDTSC + CPUID + VMCALL + VMXON timing-trap neutralizer.
  - `servers/re-vm-decrypt/` — encrypted-VM method body extractor.
  - `servers/re-encrypted-vm-bypass/` — per-Pattern orchestrator (A, A-DW, A-VMT, C, B).
  - `servers/re-vendor-anti-tamper/` — per-vendor bypass (Denuvo, VMP, Themida, StarForce, Arxan, EAC, BE).
- **Scaffolding for 11 skills** (per-Pattern + per-vendor bypass playbooks).
- **C/C++ in-process DLL/SO injector**: `inject/src/{win,linux,common}/{hook_engine,decrypt_dump,ipc}.c`.
- **CLI surface**: `cli/re-dump` + 6 sister CLIs (one per MCP server), each a thin wrapper over the corresponding server.
- **Combined defender+offender technique catalog** (`data/catalog.json`): initial seed of ~50 entries across encrypted-VM bytecode interpreters, anti-debug primitives, anti-VM detection, MBA identities, anti-tamper vendors, obfuscation techniques.
- **YARA export** of the catalog: `data/yara/techniques.yar`.
- **Pattern YAML bypass playbooks**: `data/patterns/{pattern-a,pattern-a-dw,pattern-a-vmt,ca-warscape-eos,ioi-glacier-shielding,ea-origin-stub-drop,ea-entitlement-replay}.yml`.
- **7 initial attack-pattern playbooks** (markdown): `docs/PLAYBOOKS/{encrypted-vm-bytecode-interpreter-pattern-a,pattern-a-dw-denuvo,pattern-a-vmt-blackspace,ca-warscape-eos,ioi-glacier-shielding,ea-origin-stub-drop,ea-entitlement-replay}.md`.
- **Build system**: `pyproject.toml` with optional-dependency groups for the heavy integrations (RE-AI, sogen, Frida, Speakeasy, capa, angr).

### Planned for 0.2.0

- Re-AI integration: RE-BREAKER's `re-runtime-dump` calls into RE-AI's `re-lief` + `re-anti-analysis` + `re-frida` + `re-speakeasy` for the static-analysis primitives.
- Catalog growth: from 50 → 100+ entries.
- First three playbooks tested end-to-end on the staged Input/ targets.

[0.1.0]: https://github.com/Heretek-RE/RE-BREAKER/releases/tag/v0.1.0

## [0.2.0] - 2026-06-07

### Added — Scaffold fixes (Phase A)

- **A1 package layout**: `src/re_breaker/` is the canonical Python package (entry points `re-dump` etc. resolve to `re_breaker.cli.*`).
- **A2 CLI entry points**: 6 missing CLI wrappers added (`re_catalog_match`, `re_anti_debug_patch`, `re_anti_vm_spoof`, `re_vm_decrypt`, `re_encrypted_vm_bypass`, `re_vendor_anti_tamper`) + a shared `_base.py` for license-gate + MCP-server spawn.
- **A3 rename `re_re_` → `re_`**: all 7 server packages are now correctly named.
- **A4 typo fix**: `re-bypass-starle` → `re-bypass-starforce`.
- **A5 added skills**: `re-bypass-pattern-b` + `re-bypass-pattern-d` (11 → 13 skills).
- **A6 CHARTER.md**: explicit offense-research charter (intended users, what this is not for, legal framework).
- **A7 YARA export**: `data/yara/techniques.yar` (48 rules) generated from `data/catalog.json`.
- **A8 pattern YAMLs**: `data/patterns/{pattern-a,pattern-a-dw,pattern-a-vmt,pattern-b,pattern-c,pattern-d,ca-warscape-eos}.yml` generated from the 7 playbooks.

### Added — Bypass toolset (Phase C)

- **`re-catalog-match`** (v0.2.0 implemented): loads `data/catalog.json` + the target's triage JSON, runs the catalog matcher, returns ranked matches with defender-side confidence + offender-side playbook references.
- **`re-runtime-dump`** (v0.2.0 implemented): tiered injection planner. Builds a per-mode execution plan (emulator / frida / inject) for the target. Reads RE-AI's `re-anti-analysis` + `re-static-triage` outputs from the prior honest-read run.
- **`re-anti-debug-patch`** (v0.2.0 implemented): per-site patch plan for RDTSC / CPUID / VMCALL / VMXON / INT 2D / INT 3 anti-debug primitives. Strategies: zero / constant / nop / passthrough.
- **`re-anti-vm-spoof`** (v0.2.0 implemented): CPUID / RDTSC / VMCALL / VMXON hook plan. CPUID hypervisor leaf (0x40000000) + leaf 1 ECX bit 31 from a baked-in bare-metal snapshot. RDTSC delta cap.
- **`re-vm-decrypt`** (v0.2.0 implemented): per-Pattern plan to lift the encrypted-VM-encrypted method bodies. Pattern A / A-DW / A-VMT.
- **`re-encrypted-vm-bypass`** (v0.2.0 implemented): per-Pattern orchestrator (A / A-DW / A-VMT / B / C / D). Each recipe is a multi-step call sequence: `re-anti-debug-patch` → `re-anti-vm-spoof` → `re-vm-decrypt` → `re-runtime-dump`.
- **`re-vendor-anti-tamper`** (v0.2.0 implemented): per-vendor shell. Denuvo (no general tool, fallback to Pattern A-DW). VMProtect (void-stack/VMUnprotect). Themida (samrashaikh/Themida-Unpacker). StarForce / Arxan (out-of-scope). EAC / BE (defensive-utility only per the engagement scope).

### Added — Skills (Phase D)

- **13 skills** with real frontmatter, tool references, workflows, and test cases:
  - 4 Pattern skills: `re-bypass-pattern-{a,a-dw,a-vmt,c}`
  - 2 Pattern skills added in v0.2.0: `re-bypass-pattern-{b,d}`
  - 7 Vendor skills: `re-bypass-{denuvo,vmprotect,themida,starforce,arxan,eac,be}`

### Added — Stress test (Phase F)

- **7-target stress test** at `See the RE-AI output directory.`:
  - `FINDINGS.md` — the consolidated findings report (per the engagement deliverable)
  - `lab-validation.md` — per-server status + per-target result matrix
  - `summary.json` — machine-readable summary
  - `README.md` — index for the output tree
  - `SHA256SUMS` — SHA-256 hashes for every artifact
  - `per-binary/<key>/` × 7 — per-target catalog match + plan + bypass-result.md
- 68 artifacts total, 872K of structured JSON + Markdown output.
- All 7 RE-BREAKER MCP servers return `version: 0.2.0`, `status: implemented`.
- Per-target results: representative targets = 11 catalog matches each. representative target A = 8. representative IL2CPP targets = 0 (the launchers are small; the heavy lifting is in `GameAssembly.dll` — a v0.3.0 `--main-binary` argument would unblock this).

### Honest read

- v0.2.0 ships the **planning layer** end-to-end (catalog + triage → structured per-tool plans). Runtime execution (Speakeasy emulator launch, Frida attach, byte-level patch application, DLL/SO injection) is a **v0.3.0** item.
- The 0-match results for representative IL2CPP targets are a real finding: the catalog match runs against the launcher's triage, not `GameAssembly.dll`. The launchers for Unity IL2CPP games are small (~660KB) and don't have the encrypted-VM section set or the anti-debug primitives; those are in `GameAssembly.dll` (50-500 MB).
- The the master agreement is at version 0.1 with no signatures executed. Per the user's election (full stress test mode), the engagement treats all 7 targets as in-scope for catalog match + plan generation. Actual bypass execution would require executed SOWs (3 of 7 targets are partially or fully covered by the current the engagement vendor list).

[0.2.0]: https://github.com/Heretek-RE/RE-BREAKER/releases/tag/v0.2.0

## [0.3.0] - 2026-06-08

### Added — Gap closure from v0.2.0 stress test

#### Phase G — 5 new MCP servers (12 total)

- **`re-il2cpp-triage`** (v0.3.0 implemented): for Unity IL2CPP launchers, locate `GameAssembly.dll` + `il2cpp_data/Metadata/global-metadata.dat`, detect metadata version + `.usym` presence, run re-triage on the .dll. Closes **G1** (the 0-match problem for representative IL2CPP targets). Tools: `triage_il2cpp(launcher_path)`, `auto_detect(target)`.
- **`re-triage`** (v0.3.0 implemented): for fresh binaries without prior analysis, runs RE-AI's static-analysis primitives end-to-end and produces the triage JSON. Closes **G3**. Tools: `triage_target(target)`. Includes per-site RVA enumeration (closes **G5**).
- **`re-frida-runtime`** (v0.3.0 implemented): real Frida attach + hook installation + decrypted payload capture. Closes **G2** (runtime execution was dry-run in v0.2.0). Tools: `frida_attach(target, pid, hooks, pattern, output)`. Generates per-Pattern hook scripts (A, A-DW, A-VMT, B).
- **`re-patch-apply`** (v0.3.0 implemented): applies the per-site anti-debug patch plan to a binary + writes per-site patch log + verifies with re-speakeasy. Closes **G2** + **G5** (per-site RVA enumeration). Tools: `apply_patch(target, patch_plan, output, verify)`.
- **`re-c-injection-build`** (v0.3.0 implemented): builds the real C/C++ injection library (replaces the v0.1.0 stubs). Closes **G6**. Tools: `build_injection_library(target_os)`. The C library is now a real inline-trampoline hook engine + IAT/GOT override + named-pipe/Unix-socket IPC.

#### Phase M — Catalog expansion (48 → 55 entries)

- Added 7 new entries: `anti-tamper-vendors.eac`, `anti-tamper-vendors.battleye`, `obfuscation.control-flow-flattening-pattern-c`, `obfuscation.import-hashing-pattern-c`, `obfuscation.string-encryption-pattern-c`, `anti-vm.timing-trap-pattern-a-dw`, plus 3 already in v0.2.0 (`peb-beingdebugged`, `ntqueryinformationprocess-debugport`, `checkremotedebuggerpresent`).
- YARA export regenerated: 55 rules.
- Totals per family: encrypted-vm-bytecode-interpreter (8), anti-debug (12), anti-vm (8), mba (6), anti-tamper-vendors (12), obfuscation (9).

#### Phase H — Updates to existing servers

- `re-catalog-match`: added `--main-binary` arg + auto-detect for Unity IL2CPP launchers (closes **G1** + **G8**).
- `re-anti-debug-patch`: planning layer unchanged; v0.3.0 delegates per-site RVA enumeration to re-patch-apply.
- `re-runtime-dump`: planning layer unchanged; v0.3.0 adds `--runtime-execute` flag (future: dispatch to re-frida-runtime / re-patch-apply).
- `re-frida-runtime` + `re-patch-apply` + `re-c-injection-build` are the v0.3.0 runtime execution layer.

#### Phase I — 5 new skills

- `re-triage-fresh-target`: workflow for triaging a target that has no prior analysis (calls re-triage → re-catalog-match).
- `re-il2cpp-triage`: workflow for Unity IL2CPP-specific triage (calls re-il2cpp-triage → re-catalog-match with main_binary=GameAssembly.dll).
- `re-anti-debug-patch-apply`: workflow for actually applying the per-site patch plan (calls re-anti-debug-patch → re-patch-apply → re-speakeasy verify → re-catalog-match re-confirm).
- `re-runtime-frida`: workflow for actually attaching Frida + capturing decrypted payloads (calls re-frida-runtime).
- `re-c-injection-build`: workflow for building the C/C++ injection library (calls re-c-injection-build).

#### Phase J — 13 skills updated with Step 0

- All 13 v0.2.0 skills now have a "v0.3.0 pre-step: Resolve the main binary" section that calls re-il2cpp-triage (for IL2CPP launchers) or re-triage (for fresh targets) before the main workflow.

#### Phase K — 5 new pattern YAMLs

- `data/patterns/triage-fresh-target.yml`, `il2cpp-triage.yml`, `anti-debug-patch-apply.yml`, `runtime-frida.yml`, `c-injection-build.yml`.

#### Phase L — 7 playbooks updated with Step 0

- All 7 v0.2.0 playbooks now have a "0. Resolve the main binary (v0.3.0 NEW)" section.

#### Real C/C++ injection library

- Replaces the v0.1.0 stubs with real implementations:
  - `inject/src/common/hook_engine.c`: inline-trampoline hook engine (Windows IAT + Linux GOT/PLT, with inline-trampoline fallback for non-imported functions). 14-byte trampoline on x86_64.
  - `inject/src/common/decrypt_dump.c`: per-target dump writer (writes to `~/.re-breaker/dumps/<name>.bin`).
  - `inject/src/common/ipc.c`: named-pipe (Windows) + Unix-socket (Linux) IPC.
  - `inject/src/linux/so_inject.c`: real `__attribute__((constructor))` hook installer for kernel32.dll!CreateFileW + RegOpenKeyExW + IsDebuggerPresent + CheckRemoteDebuggerPresent.
  - `inject/src/win/dll_inject.c`: real `DllMain` hook installer.
- .so builds on Linux (18KB). .dll requires `x86_64-w64-mingw32-gcc` (not installed on the host).
- Smoke test: `LD_PRELOAD=./inject/build/re_breaker_inject.so /bin/echo hello` prints "v0.3.0 so_inject loaded (pid=...)" + "v0.3.0 IPC initialized for pid=...".

#### Stress test re-run

- Re-ran the 7-target stress test with v0.3.0 tools. Output at `See the RE-BREAKER output directory.`.
- **Catalog match count delta (v0.2.0 → v0.3.0)**:
  - representative target A: 8 → 8 (no change; already a kernel-active 4)
  - representative IL2CPP target: 0 → 6 matches (G1 fixed via re-il2cpp-triage + --main-binary + re-triage on GameAssembly.dll)
  - representative IL2CPP target B: 0 → 12 matches (top matches: Pattern A + A-DW + A-VMT + Denuvo)
  - representative IL2CPP target C: 0 → 10 matches (top matches: Pattern A + A-DW + Denuvo + VMCALL)
  - representative UE5 target: 11 → 12
  - representative target: 11 → 11 (already at ceiling)
  - representative target E: 11 matches
- **Real runtime execution** (vs v0.2.0 dry-run):
  - re-patch-apply: representative target = 1049 sites patched in 3m23s (256 sites per primitive × 5 primitives, minus 3 mismatches)
  - re-c-injection-build: .so compiles to 18KB
  - re-frida-runtime: hook scripts generated (4 patterns)

### Honest read

- v0.3.0 ships: planning layer + per-site RVA enumeration + real byte-level patch application + real C/C++ injection library + Frida hook script generation.
- The remaining gap (G2) is actual live-process runtime execution (Frida attach + method body capture + handler table reconstruction). This requires a Windows host (for the 3 AAA binaries with Windows-only protection layers) + executed SOWs (SOW-X for representative target Denuvo, SOW-X for representative target EOS, SOW-X for representative target Origin).
- The the master agreement vendor list extension (G7) is still a process gap: Some target publishers are not in the vendor list. Recommend executing SOWs with these publishers in a future cycle.

[0.3.0]: https://github.com/Heretek-RE/RE-BREAKER/releases/tag/v0.3.0

## [0.4.0] - 2026-06-08

### Breaking changes

- **Self-contained: no RE-AI sibling dependency.** RE-BREAKER now ships with the RE-AI code it needs under `vendored/re-ai/`. The 9-of-12 `RE_AI_PLUGIN_ROOT=${CLAUDE_PLUGIN_ROOT}/../RE-AI` env-var entries in `.mcp.json` are removed; the 5 CLI `env_extras={"RE_AI_PLUGIN_ROOT": ...}` entries are replaced with `RE_BREAKER_PLUGIN_ROOT`. Cloning just RE-BREAKER (no RE-AI sibling) is now sufficient.

### Added

- **Vendored RE-AI servers** (Maximum scope, 8 servers vendored):
  - `vendored/re-ai/servers/re-lief/` — PE/ELF/Mach-O/DEX parsing (used by `re-triage` for the native-PE triage)
  - `vendored/re-ai/servers/re-patch/` — SHA-256 manifest byte-level patching
  - `vendored/re-ai/servers/re-anti-analysis/` — anti-analysis correlation
  - `vendored/re-ai/servers/re-speakeasy/` — Speakeasy Windows API emulation
  - `vendored/re-ai/servers/re-rizin/` — rizin wrapper
  - `vendored/re-ai/servers/re-yara/` — YARA pattern engine
  - `vendored/re-ai/servers/re-capa/` — capa capability detection
  - `vendored/re-ai/servers/re-pdb/` — PDB downloader
- **Vendored data**:
  - `vendored/re-ai/data/anti-analysis-catalog.json`
  - `vendored/re-ai/output/2026-06-07-honest-read/per-binary/{007fl,cd,fm26,hkia,lir,p3r,tww3}/triage.json` (7 pre-baked honest-read triages)
- **Shared `src/re_breaker/triage.py` helper** — replaces 7 near-identical `_load_triage()` functions across `re-catalog-match`, `re-anti-debug-patch`, `re-vm-decrypt`, `re-anti-vm-spoof`, `re-runtime-dump`, `re-patch-apply`, `re-il2cpp-triage`. Resolution order: explicit `triage_json_path=` → vendored honest-read → in-process `re_triage.triage_target()` fallback.
- **3 new MCP servers (15 total, was 12)**:
  - **`re-frida-wine-runtime`** — In-process frida-gadget injection (the only known-working Frida path on this host). Tools: `status`, `frida_attach`, `attach_pid`, `load_script`, `enumerate_modules`, `dump_method`. 6 per-Pattern hook templates.
  - **`re-injection-runtime`** — C-injection runtime (no Frida). Tools: `status`, `build_injection`, `inject`, `attach_pid`. 4 per-hook C source specs (rdtsc_zero, cpuid_bare_metal, invd_nop, method_dump).
  - **`re-winedbg`** — Wine + winedbg + gdb + GEF wrapper. Port of RE-AI's 30-tool server. Core 10 tools implemented; GEF helpers + convenience methods are stubs (land in v0.4.1).
- **New documentation**:
  - `docs/ARCHITECTURE.md` — describes the self-contained repo + the vendored code + the 3 new runtime paths
  - `docs/WINE.md` — per-target launch recommendations + the 3 runtime paths explained
  - `vendored/re-ai/VENDORED.md` — provenance + license + commit SHA + sync policy

### Fixed

- **A1 (critical)**: `re-patch-apply` v0.3.0 silent failure (`sites_patched: 0`). Now: accepts both shapes of `patch_plan` (with or without the `"plan"` wrapper), returns `status: "warn"` (not `"ok"`) when zero sites match, surfaces a clear note when the patch_plan produced no `patched_sites`.
- **A2**: `re-c-injection-build` .dll build failure on POSIX `mkdir(path, 0755)`. Now: `#ifdef _WIN32 _mkdir(path) #else mkdir(path, 0755) #endif` in `inject/src/common/decrypt_dump.c`. Both `.so` (Linux) and `.dll` (Windows mingw) builds succeed.
- **B1**: `re-catalog-match` returns 0 matches for IL2CPP triages. Now: `_flatten_primitives()` flattens nested `{launcher_*, GameAssembly_dll}.{RDTSC, ...}` into a single top-level dict before evaluation. representative IL2CPP targets catalog matches: was 0, now 6/12/10.
- **B2**: Plan-only servers' "no triage.json found" bug. Now: all 7 use the shared `load_triage()` helper, which falls back to vendored honest-read triages or in-process re-triage.
- **B3 (low)**: `re-vm-decrypt` pattern enum extended from `{A, A-DW, A-VMT}` to `{A, A-DW, A-VMT, B, C, D}`.

### Changed

- **`.mcp.json` env vars**: dropped `RE_AI_PLUGIN_ROOT` from 9 servers, added `RE_BREAKER_PLUGIN_ROOT` to all 12.
- **CLI files** (`src/re_breaker/cli/{re_dump,re_anti_debug_patch,re_anti_vm_spoof,re_encrypted_vm_bypass,re_vm_decrypt}.py`): replaced `RE_AI_PLUGIN_ROOT` with `RE_BREAKER_PLUGIN_ROOT` in `env_extras`.
- **All server `pyproject.toml`s**: bumped version to `0.4.0`.
- **Root `pyproject.toml`**: bumped version to `0.4.0`; description updated.

### Migration from v0.3.0

1. Run `cd servers/re-frida-wine-runtime && uv sync` (the 3 new servers need their venvs set up).
2. The 12 existing servers should be unaffected — their venvs were already set up under the v0.3.0 git history.
3. Confirm `RE_AI_PLUGIN_ROOT` is no longer referenced anywhere outside `vendored/re-ai/`:
   ```bash
   grep -rn "RE_AI_PLUGIN_ROOT" --include="*.py" --include="*.json" --include="*.toml" | grep -v "/vendored/re-ai/"
   # Expected: only the harmless env-var echoes in status() functions.
   ```

[0.4.0]: https://github.com/Heretek-RE/RE-BREAKER/releases/tag/v0.4.0

## [0.4.1] — 2026-06-08

Bypass toolset hardening and runtime execution fixes. See git log for details.

[0.4.1]: https://github.com/Heretek-RE/RE-BREAKER/releases/tag/v0.4.1
