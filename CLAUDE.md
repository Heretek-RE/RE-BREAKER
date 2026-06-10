# RE-BREAKER

Offense-research toolkit for defeating anti-reverse-engineering protection on binaries the analyst has the legal right to analyze. AGPL-3.0 + Offensive-Research-Use Clause.

## Structure

```
servers/                # 30 MCP servers
  re-catalog-match/     # Combined defender+offender technique matcher
  re-runtime-dump/      # Tiered injection planner (emulator / Frida / inject)
  re-anti-debug-patch/  # Byte-level anti-debug primitive neutralizer
  re-anti-vm-spoof/     # RDTSC + CPUID + VMCALL timing-trap neutralizer
  re-vm-decrypt/        # Encrypted-VM method body extractor
  re-encrypted-vm-bypass/ # Per-Pattern orchestrator (A, A-DW, A-VMT, B, C, D)
  re-vendor-anti-tamper/  # Per-vendor bypass shell (Denuvo, VMP, Themida, etc.)
  re-il2cpp-triage/     # Unity IL2CPP launcher triage
  re-triage/            # Fresh-binary triage (calls RE-AI primitives)
  re-frida-runtime/     # Frida attach + hook installation
  re-c-injection-build/ # C/C++ injection library builder
  re-patch-apply/       # On-disk byte-level patching
  re-winedbg/           # Wine + winedbg + gdb + GEF wrapper
  re-entitlement-bypass/  # Steam CEG / EOS / per-vendor entitlement emulation
  re-vm-launch/         # Win11 KVM guest management
  re-vm-ssh/            # SSH transport to Win11 VM
  re-vm-control/        # VM lifecycle control
  re-vm-debug/          # QEMU gdb stub client
  re-vm-memory/         # VM memory inspection
  re-ghidra-remote/     # Ghidra headless remote
  re-ida-remote/        # IDA remote
  re-x64dbg-remote/     # x64dbg remote
  re-traffic-capture/   # Network traffic capture
  re-launch-and-observe/ # Launch + observe target
  re-cinematic-skip/    # Auto-dismiss splash cinematics
  re-qemu-antidetect/   # QEMU anti-detection
  re-injection-runtime/ # C-injection runtime (no Frida)
  re-frida-wine-runtime/ # In-process frida-gadget injection
  re-persistproc/       # Sidecar to vendored persistproc
  re-ui-automate/       # Sidecar to vendored touchpoint
  re-target-fingerprint/ # Target binary fingerprinting
skills/                 # 35 skill definitions (per-Pattern + per-vendor bypass playbooks)
data/                   # Technique catalog + YARA rules + pattern YAMLs
  catalog.json          # 59-entry defender+offender catalog
  yara/techniques.yar   # YARA export of the catalog
  patterns/             # Per-Pattern bypass playbook YAMLs
inject/                 # C/C++ in-process DLL/SO injector
  src/{win,linux,common}/ # Platform-specific injection code
vendored/               # Vendored dependencies (self-contained operation)
  re-ai/                # 8 RE-AI servers (library code, not MCP-exposed)
  persistproc/          # Cross-restart persistence (MIT)
  touchpoint/           # UI automation (MIT)
  ssh-mcp/              # SSH MCP bridge (MIT)
docs/                   # Architecture, charter, playbooks
src/re_breaker/         # Python package (CLI wrappers, triage helper, VM client)
scripts/                # Build/test/audit scripts
tools/                  # Environment setup scripts
```

## Build commands

### Install
```bash
pip install -e .[all]   # install with all optional deps
# or install specific groups:
pip install -e .[frida,speakeasy,capa]
```

### License gate
```bash
re-dump --license-acknowledge --help  # must acknowledge before first run
cat LICENSE-OFFENSIVE.md              # read the terms
```

### Run CLI tools
```bash
re-dump --target=/path/to/binary --mode=emulator --output=/tmp/dump/ --license-acknowledge
re-catalog-match --target=/path/to/binary --intent=both
re-anti-debug-patch --target=/path/to/binary
re-vendor-anti-tamper --target=/path/to/binary --list-vendors
```

### Run MCP servers (via uv)
```bash
uv --directory servers/re-catalog-match run re-catalog-match
```

### Test
```bash
pytest tests/
```

## Architecture

RE-BREAKER is **self-contained**. The 8 RE-AI servers it depends on are vendored under `vendored/re-ai/` (library code, not MCP-exposed). The `RE_BREAKER_PLUGIN_ROOT` env var is the single root path; all server paths resolve relative to it.

### Pattern taxonomy

| Pattern | Description | Example |
|---|---|---|
| A | Encrypted-VM bytecode interpreter (IL2CPP) | Unity IL2CPP + third-party ATD |
| A-DW | Pattern A wrapped by third-party anti-tamper | UE5 + Denuvo ATD |
| A-VMT | Handler-table dispatch (proprietary engine) | BlackSpace Engine |
| B | Hardware fingerprinting | CPUID + RDTSC timing traps |
| C | Proprietary-engine VM | Custom protection layers |
| D | Telemetry leaks | Sentry SDK crash-reporting |

### CLI entry points

7 CLI commands registered in `pyproject.toml`: `re-dump`, `re-catalog-match`, `re-anti-debug-patch`, `re-anti-vm-spoof`, `re-vm-decrypt`, `re-encrypted-vm-bypass`, `re-vendor-anti-tamper`. Each wraps the corresponding MCP server with the license gate.

## Conventions

- **License gate:** All bypass CLI tools require `--license-acknowledge` before execution. First run prints `LICENSE-OFFENSIVE.md` and prompts for confirmation.
- **MCP servers** use `FastMCP` from `mcp[cli]`. Entry point is `server.py` with a `main()` function.
- **Skills** are SKILL.md files with YAML frontmatter declaring the workflow, tools, and test cases.
- **No engagement references** in committed code: no game titles, SOW codes, host paths, or per-target output paths.
- **Vendor names** at the protection-family level (Denuvo, EAC, VMProtect, etc.) are kept as they are the subjects the tools analyze.

## Key files

- `LICENSE-OFFENSIVE.md` — the offensive-research-use clause
- `THREAT-MODEL.md` — intended user matrix and risk acknowledgment
- `docs/CHARTER.md` — tool philosophy and scope
- `docs/ARCHITECTURE.md` — self-contained repo layout
- `docs/PLAYBOOKS/` — per-vendor bypass playbooks
- `.mcp.json` — MCP server registry (30 servers)
- `data/catalog.json` — the 59-entry technique catalog
