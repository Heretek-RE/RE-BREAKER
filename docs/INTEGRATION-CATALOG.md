# External Tool Integration Catalog

External tools surveyed for potential RE-BREAKER integration.

## Tier 1: Real integration targets (verified, will integrate)

### qilingframework/qiling
**URL:** https://github.com/qilingframework/qiling
**Use case:** Binary emulator alternative to Speakeasy
**Status:** Mature, 15+ releases, Black Hat talks, multi-arch (x86/x64/ARM/ARM64/MIPS/RISC-V), Windows + Linux + macOS + Android + UEFI
**Integration point:** `re-runtime-dump` (alternative backend for `mode=emulator`)
**Integration effort:** 1-2 weeks (write a qiling loader, wire it as an alternative to Speakeasy, add a `qiling_backend: True` flag)
**License:** GPL-2.0 (compatible with RE-BREAKER's AGPL-3.0 + offensive-use clause)
**Priority:** P2 (Speakeasy works for the v0.7.0 needs; Qiling would be a v0.8.0 swap for better multi-arch support)

### hasherezade/pe-sieve
**URL:** https://github.com/hasherezade/pe-sieve
**Use case:** In-memory patch detection
**Status:** Mature, 2.4k+ stars, used in malware analysis
**Integration point:** `re-patch-apply` (new backend) — pe-sieve finds hooks/hollows in process memory
**Integration effort:** 2-3 days (write a pe-sieve wrapper, wire it into `apply_patch(verify=True)`)
**License:** BSD-2-Clause (compatible)
**Priority:** P1 (would significantly improve the verify step's signal-to-noise)

### hasherezade/hollows_hunter
**URL:** https://github.com/hasherezade/hollows_hunter
**Use case:** Process scanner for hollowed/replaced PEs
**Status:** Mature, 2.3k+ stars, sister project to pe-sieve
**Integration point:** `re-runtime-dump` (new tool: `find_decrypted_regions` — hollows_hunter scans for the dumped method bodies in process memory)
**Integration effort:** 1-2 days
**License:** BSD-2-Clause
**Priority:** P1 (would close a real gap in the current `re-runtime-dump` plan-only workflow)

### anpa1200/Unpacker
**URL:** https://github.com/anpa1200/Unpacker
**Use case:** Packer detection + unpacking (UPX, ASPack, Themida, VMProtect)
**Status:** Recent (2026), 9 stars, integrates Unipacker (32-bit) + Qiling (64-bit VMProtect)
**Integration point:** `re-vendor-anti-tamper` — for the VMProtect + Themida skills (current skills say "use void-stack" or "samrashaikh/Themida-Unpacker" which is 404)
**Integration effort:** 3-5 days (write a wrapper, integrate Qiling as the 64-bit VMProtect backend, integrate Unipacker as the 32-bit backend)
**License:** MIT
**Priority:** P2 (the VMProtect + Themida skills currently point to dead tools; this would fix them)

## Tier 2: Reference docs (not direct integration, but cited in our docs)

### hasherezade/demos
**URL:** https://github.com/hasherezade/demos
**Use case:** Process injection technique reference
**Status:** Mature, 1k+ stars
**Use in RE-BREAKER:** Reference for AppInit_DLLs + LoadLibraryA-from-main + alternative injection vectors. The `inject/tests/host_appinit.c` test pattern (LoadLibraryA from main + hook + cleanup) is essentially hasherezade-style.
**Priority:** P3 (reference, no code integration)

## Tier 3: Considered, rejected (with rationale)

### Various Denuvo bypass projects
Searches for "Denuvo bypass github" returned no usable results. The 2 known Denuvo bypasses are version-specific (DenuvOwO for one Crimson Desert build, and a separate private one for Persona 5). The RE-BREAKER plan-only "class-of-technique" approach is the honest answer. **Rejected as general tools.**

### steam-stub-remover / steam DRM tools
The Steam CEG bypass via `gbe_fork` is already in the RE-BREAKER repo at `See the RE-BREAKER output directory.`. The experimental variant covers CEG-titled targets. **Already adopted.**

### Various VMProtect / Themida unpackers (Unipacker, etc.)
Already cited in the v0.2.0 `re-vendor-anti-tamper` plans. The samrashaikh/Themida-Unpacker is 404 (replaced by anpa1200/Unpacker + Qiling). **Mark for P2 integration via anpa1200/Unpacker.**

### QEMU anti-detection forks
Searches didn't surface a maintained project. The most-known is the QEMU-Anti-Detection patchset on GitHub, but it's outdated (last update 2022) and patches older QEMU. **Out of scope for v0.7.0.** A custom libvirt XML config (host-passthrough CPUID + SMBIOS) would do 80% of what those patches do, and is in scope for v0.7.0 (M3: re-qemu-antidetect).

### IL2CPP metadumper tools (Il2CppInspector, Il2CppDumper)
For targets that have `global-metadata.dat` (FM26, LIR), these work and are referenced in the existing skills. For HKIA which has stripped metadata, they don't work — we need `re-hkia-metadata-decrypt` (M4) to recover the metadata first. **Already referenced; novel reverse needed for HKIA.**

## Tier 4: Search was empty (would need to build)

The following have no good public implementations and would need to be built in-house:

- **Encrypted-VM bytecode interpreter lifter** (for Pattern A) — `re-vm-decrypt` is plan-only
- **Encrypted-VM handler-table dispatcher** (for Pattern A-VMT, BlackSpace) — plan-only
- **POGO entry validator bypass** (for Pattern A-DW, UE5 + Denuvo) — per-target RE work
- **Sunblink SDK protocol reverse** (for HKIA's stripped metadata) — `S5` skill
- **Wine `cryptasn` patch** (for 007FL + CD) — would need a Wine source fork
- **Wine `RtlUnwindEx` EXCEPTION_INVALID_FRAME patch** (for TWW3) — would need Wine source fork
- **Bare-metal CPUID + RDTSC + VMCALL runtime hook chain** (for all anti-VM bypass) — `re-anti-vm-spoof` is plan-only, the frida runtime does the work

## Integration roadmap

| Priority | Tool | Effort | Impact |
|---|---|---|---|
| P1 | hasherezade/pe-sieve | 2-3 days | improves `apply_patch(verify=True)` signal |
| P1 | hasherezade/hollows_hunter | 1-2 days | closes `re-runtime-dump` gap |
| P2 | qilingframework/qiling | 1-2 weeks | better multi-arch emulator |
| P2 | anpa1200/Unpacker | 3-5 days | fixes VMProtect + Themida skills |
| P3 | hasherezade/demos | reference | docs only |

Total integration effort: ~3-4 weeks. The v0.7.0 release would gain real runtime capability for the verify step + process scan + better emulator.

## What we did NOT find (and what to do about it)

| Need | Status | Action |
|---|---|---|
| General Denuvo bypass | unsolvable | Plan-only class-of-technique Bypass |
| Steam CEG bypass beyond gbe_fork | already in repo | use gbe_fork |
| EA Origin bypass | already in repo | use Origin emulator (v0.5.2) |
| IOI Account bypass | already in repo | use IOI emulator |
| Pearl Abyss bypass | already in repo | use PA emulator |
| Atlus Account bypass | already in repo | use Atlus emulator (v0.5.2) — was missing from stress test! |
| Sunblink bypass | SCAFFOLD only | novel RE work needed (S5) |
| EA BattleEye bypass | defensive-only | MRTEA Part V §5 — out of scope |

The repo's entitlement emulators (Atlus, Origin, Sunblink, PA, SEGA SSO, IOI, EOS) cover most of the entitlement layer. The Denuvo + EAC + BE targets are correctly identified as out-of-scope.
