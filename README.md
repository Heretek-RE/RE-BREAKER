# RE-BREAKER

> **Offense-research toolkit** for defeating anti-reverse-engineering protection on binaries the analyst has the legal right to analyze.

RE-BREAKER builds on [RE-AI v2.9.2](https://github.com/Heretek-RE/RE-AI/) (the analyzer + fingerprinter + IL lifter) and adds the explicit **bypass primitives** that RE-AI's charter forbids. If you need to lift encrypted method bodies from a binary you have the right to RE, this is the tool. If you're trying to pirate software, go elsewhere — this isn't for you, and the legal exposure is on you.

## Charter

This is a **defensive + offensive research** toolkit. The intended users are:

- Reverse-engineering consultants (with a signed engagement letter for the target binary)
- Malware analysts (with authorization to analyze the malware sample)
- Blue-team / purple-team staff (analyzing detection rules + tooling)
- Security researchers (publishing under responsible-disclosure)
- Academic RE labs (peer-reviewed research)

The out-of-scope uses (which the LICENSE-OFFENSIVE.md clauses explicitly forbid):

- Piracy of commercial software
- Bypassing DRM to access content without paying
- Unauthorized access to systems the analyst doesn't own
- Any use that violates the laws of the operator's jurisdiction

If you accept that the `re-dump` CLI's `--license-acknowledge` flag requires, then you're operating within the charter. If you don't, the CLI refuses to run.

## Relationship to the other repos

| Repo | Charter | License | What it does |
|---|---|---|---|
| [RE-AI](https://github.com/Heretek-RE/RE-AI/) | Identify, lift, fingerprint | MIT | The static analysis foundation. 31 MCP servers + 29 skills. Vendor-neutral in shipped content. |
| [RE-Library](https://github.com/Heretek-RE/RE-Library/) | Public docs on RE techniques | MIT | 12-category Astro site + PyPI MCP server. DRM-system names only in `drm/`. |
| [RE-UNLEASHED](https://github.com/Heretek-RE/RE-Library/#engines-storefronts-protection) | Cite-only vendor attribution | MIT | Per-publisher / per-engine / per-protection doc tree. Names vendors but vendoring-forbids source. |
| **RE-BREAKER** (this) | Offense research: bypass | AGPL-3.0 + offensive-research-use clause | The new bypass toolset. The tiered injection tool. The combined defender+offender technique catalog. |

RE-BREAKER is **self-contained** as of v0.4.0: it no longer requires RE-AI to be checked out as a sibling. The RE-AI code RE-BREAKER depends on (PE parsing, anti-analysis correlation, Speakeasy emulation, rizin, YARA, capa, PDB) is vendored under `vendored/re-ai/`. See `docs/ARCHITECTURE.md` for the full layout.

## What this v0.4.0 ships

- **15 MCP servers** in `servers/` (was 12 in v0.3.0; +3 new in v0.4.0):
  - The 12 from v0.3.0: `re-triage`, `re-il2cpp-triage`, `re-catalog-match`, `re-anti-debug-patch`, `re-patch-apply`, `re-runtime-dump`, `re-encrypted-vm-bypass`, `re-vm-decrypt`, `re-frida-runtime`, `re-c-injection-build`, `re-anti-vm-spoof`, `re-vendor-anti-tamper`
  - **NEW `re-frida-wine-runtime`** — In-process frida-gadget injection (the only known-working Frida path on this host). 6 tools + 6 per-Pattern hook templates.
  - **NEW `re-injection-runtime`** — C-injection runtime (no Frida). 4 tools + 4 per-hook C source specs.
  - **NEW `re-winedbg`** — Wine + winedbg + gdb + GEF wrapper. 30 tools (core 10 implemented; GEF + convenience are stubs).
- **19 skills** in `skills/` (per-Pattern + per-vendor bypass playbooks; unchanged in v0.4.0)
- **8 vendored RE-AI servers** under `vendored/re-ai/servers/` (library code; not exposed as MCP):
  - `re-lief`, `re-patch`, `re-anti-analysis`, `re-speakeasy`, `re-rizin`, `re-yara`, `re-capa`, `re-pdb`
- **7 vendored honest-read triage JSONs** at `Vendored RE-AI catalog data and triage outputs.`
- The combined defender+offender technique catalog (`data/catalog.json`, 59 entries — v0.4.0 NEW: entitlement family)
- The YARA export of the catalog (`data/yara/techniques.yar`)
- The 7 attack-pattern playbooks (`docs/PLAYBOOKS/`)
- The C/C++ in-process DLL/SO injector (`inject/src/`)
- The shared `src/re_breaker/triage.py` helper (replaces 7 near-identical `_load_triage()` functions)
- The `LICENSE-OFFENSIVE.md` clause document
- The new `docs/ARCHITECTURE.md` and `docs/WINE.md`

**Critical bug fixes in v0.4.0**:
- A1: `re-patch-apply` no longer silently returns `sites_patched: 0`
- A2: `re-c-injection-build` now builds both `.so` and `.dll` (the `.dll` build previously failed on POSIX `mkdir(path, 0755)`)
- B1: `re-catalog-match` no longer returns 0 matches for IL2CPP targets (flattens nested `{launcher_*, GameAssembly_dll}.{RDTSC, ...}` shape)
- B2: Plan-only servers (`re-anti-debug-patch`, `re-vm-decrypt`, `re-anti-vm-spoof`, `re-runtime-dump`) no longer fail with "no triage.json found"

## Quickstart

```bash
git clone https://github.com/Heretek-RE/RE-BREAKER.git
cd RE-BREAKER
python -m venv .venv-re-breaker
source .venv-re-breaker/bin/activate
pip install -e .

# Read the offensive-research-use clause (required before first run)
cat LICENSE-OFFENSIVE.md

# Run the catalog matcher on a target
re-catalog-match --target=/path/to/foo.exe --intent=both

# Run the tiered injection CLI
re-dump --target=/path/to/foo.exe --mode=emulator --output=/tmp/dump/ --license-acknowledge
```

## License

- **AGPL-3.0-or-later** for the code (see `LICENSE`).
- **Offensive-research-use clause** as a separate `LICENSE-OFFENSIVE.md` that the CLI `cat`s on first run and requires explicit acknowledgement.
- Per the cite-only contract (inherited from RE-UNLEASHED), no third-party source is vendored, even when the upstream license permits it.


## v0.4.1+

Bypass toolset hardening and runtime execution fixes. See `CHANGELOG.md` or the git log for details.

## Roadmap

- Per-Pattern bypass orchestrator
- Per-vendor bypass skills reaching production coverage
- Additional runtime execution paths (Speakeasy emulator, Frida attach, C-injection)
