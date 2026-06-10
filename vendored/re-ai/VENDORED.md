# Vendored RE-AI code (v0.4.0)

This directory contains code vendored from the RE-AI repository.

## Origin

- **Source repo**: `RE-AI` (Heretek-AI, Inc.)
- **Local source path** (at vendoring time): `/home/john/Desktop/RE/RE-AI/`
- **Vendored on**: 2026-06-08
- **Commit SHA**: (HEAD of RE-AI at vendoring time)
- **License**: AGPL-3.0-or-later + Offensive-Research-Use Clause (matches RE-BREAKER's license)
- **Contact for upstream sync**: RE-BREAKER maintainers

## What was vendored

Eight RE-AI servers (library code, not exposed as MCP tools):

- `servers/re-lief/` — LIEF cross-format binary analysis (PE/ELF/Mach-O/COFF/DEX/ART)
- `servers/re-patch/` — on-disk binary patching (SHA-256 manifest + byte-level patch + restore)
- `servers/re-anti-analysis/` — cross-section correlation of anti-debug + anti-VM + anti-sandbox primitives
- `servers/re-speakeasy/` — Speakeasy Windows API emulation
- `servers/re-rizin/` — rizin (radare2 successor) wrapper
- `servers/re-yara/` — YARA pattern-matching engine
- `servers/re-capa/` — capa capability detection with MITRE ATT&CK / MBC mappings
- `servers/re-pdb/` — PDB downloader (Microsoft Symbol Server)

Plus:
- `data/anti-analysis-catalog.json` — the anti-analysis catalog used by `re-anti-analysis` and the catalog matcher
- `output/2026-06-07-honest-read/per-binary/{007fl,cd,fm26,hkia,lir,p3r,tww3}/triage.json` — 7 pre-baked honest-read triage JSONs

## What was NOT vendored

- Per-server `.venv/` directories (each re-created via `uv sync` on demand; the venvs are .gitignored in RE-AI's source repo)
- `uv.lock` files
- `__pycache__/` directories
- `*.pyc` bytecode

## How the vendored code is used

RE-BREAKER's own servers import the vendored code via Python's import system. The shared `src/re_breaker/triage.py` helper looks up triage JSONs in the vendored tree; the (future) per-server refactors will import from `vendored.re_ai.servers.<name>...` directly.

The RE-AI env var (`RE_AI_PLUGIN_ROOT`) is **not read** by any non-vendored RE-BREAKER code. The vendored code may still reference `RE_AI_PLUGIN_ROOT` for its own internal use; this is a vendored-code internal concern, not an RE-BREAKER one.

## How to sync with upstream

1. `cd /home/john/Desktop/RE-AI && git pull`
2. `cd /home/john/Desktop/RE/RE-BREAKER && bash scripts/sync-vendored.sh` (TBD; v0.4.0 ships without this script — manual re-copy for now)
3. Re-run the stress test (`Output/stress/2026-06-08-v0.4.0/`) and diff against the v0.4.0 baseline.

## Vendoring policy

- Vendored code is **library code, not exposed as MCP tools**. The 8 vendored servers are not in `.mcp.json` and will not be picked up by the harness.
- Vendored code retains its original RE-AI license header in each source file.
- Bug fixes to vendored code should ideally be pushed upstream to RE-AI first, then re-vendored. In practice, v0.4.0 ships with the RE-AI code as-is.
- New RE-AI servers (e.g., a future `re-triton`, `re-vtil`) can be added by repeating the vendoring process.

## Why not git subtree?

Considered, but deferred to v0.4.1. The current manual-copy approach is sufficient for v0.4.0; RE-BREAKER doesn't need to track RE-AI's git history. When/if upstream sync becomes a regular operation, a `git subtree add` of RE-AI at `vendored/re-ai/` is the right move.
