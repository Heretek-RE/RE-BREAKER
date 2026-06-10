# RE-BREAKER Architecture (v0.4.0 + v0.5.3)

**RE-BREAKER is self-contained.** Cloning just this repo is enough; **no RE-AI sibling is required**. This document describes the architectural decisions and the file layout.

## 1. Why this matters

Prior to v0.4.0, RE-BREAKER's 9 of 12 MCP servers depended on RE-AI being checked out as a sibling directory. The env var `RE_AI_PLUGIN_ROOT=${CLAUDE_PLUGIN_ROOT}/../RE-AI` was set in `.mcp.json`, and several servers read pre-baked triage JSON files from `RE-AI/See the RE-AI output directory.`. This made RE-BREAKER unusable in isolation.

v0.4.0 breaks that dependency. RE-BREAKER now vendors the RE-AI code it needs under `vendored/re-ai/`. The catalog, the 8 RE-AI servers (re-lief, re-patch, re-anti-analysis, re-speakeasy, re-rizin, re-yara, re-capa, re-pdb), and the 7 pre-baked triage JSON files all ship with RE-BREAKER.

## 2. Directory layout (v0.4.0)

```
RE-BREAKER/
├── .mcp.json                          # 15 MCP servers (was 12; +3 new in v0.4.0)
├── pyproject.toml                     # root package metadata (v0.4.0)
├── README.md
├── CHANGELOG.md
├── THREAT-MODEL.md
├── LICENSE-OFFENSIVE.md
│
├── servers/                           # 15 MCP servers (one per workstream)
│   ├── re-triage/                     # v0.3.0 — fresh-target triage
│   ├── re-il2cpp-triage/              # v0.3.0 — IL2CPP-style triage (reads vendored honest-read)
│   ├── re-catalog-match/              # v0.2.0 — catalog match
│   ├── re-anti-debug-patch/           # v0.2.0 — plan only
│   ├── re-patch-apply/                # v0.3.0 — byte-level patch
│   ├── re-runtime-dump/               # v0.2.0 — plan only
│   ├── re-encrypted-vm-bypass/        # v0.2.0 — per-Pattern orchestrator
│   ├── re-vm-decrypt/                 # v0.2.0 — VM decrypt plan
│   ├── re-frida-runtime/              # v0.3.0 — Frida runtime (script-only when no frida)
│   ├── re-c-injection-build/          # v0.3.0 — C injection library build
│   ├── re-anti-vm-spoof/              # v0.2.0 — plan only
│   ├── re-vendor-anti-tamper/         # v0.2.0 — per-vendor plan
│   │
│   ├── re-frida-wine-runtime/         # v0.4.0 NEW — Frida-on-Wine (in-process frida-gadget)
│   ├── re-injection-runtime/          # v0.4.0 NEW — C-injection runtime (no Frida)
│   └── re-winedbg/                    # v0.4.0 NEW — Wine + winedbg + gdb + GEF (30 tools)
│
├── src/re_breaker/                    # shared helpers (v0.4.0)
│   ├── __init__.py
│   ├── triage.py                      # shared load_triage() + flatten_primitives()
│   └── cli/                           # 5 CLI drivers (re_dump, re_catalog_match, etc.)
│
├── vendored/                          # v0.4.0 NEW — vendored RE-AI code
│   └── re-ai/
│       ├── VENDORED.md                # provenance + license + commit SHA
│       ├── servers/                   # 8 vendored RE-AI servers (not exposed as MCP)
│       │   ├── re-lief/               # PE/ELF/Mach-O/DEX parsing
│       │   ├── re-patch/              # SHA-256 manifest byte-level patch
│       │   ├── re-anti-analysis/      # cross-section correlation
│       │   ├── re-speakeasy/          # Windows API emulator
│       │   ├── re-rizin/              # rizin wrapper
│       │   ├── re-yara/               # YARA pattern engine
│       │   ├── re-capa/               # capa capability detection
│       │   └── re-pdb/                # PDB downloader
│       ├── data/
│       │   └── anti-analysis-catalog.json
│       └── output/2026-06-07-honest-read/per-binary/
│           ├── 007fl/triage.json
│           ├── cd/triage.json
│           ├── fm26/triage.json
│           ├── hkia/triage.json
│           ├── lir/triage.json
│           ├── p3r/triage.json
│           └── tww3/triage.json
│
├── skills/                            # 23 skills (v0.4.0: +4 entitlement skills)
├── data/
│   ├── catalog.json                   # 59 catalog entries (v0.4.0: +4 entitlement family)
│   ├── yara/techniques.yar
│   └── patterns/*.yml
├── inject/                            # C injection library (compiled by re-c-injection-build)
└── Output/                            # stress-test outputs (gitignored)
    └── stress/2026-06-08/             # v0.3.0 baseline
    └── stress/2026-06-08-v0.4.0/      # v0.4.0 re-run
```

## 3. Vendored RE-AI code (v0.4.0)

The 8 RE-AI servers under `vendored/re-ai/servers/` are **library code, not exposed as MCP tools**. They are imported by RE-BREAKER's own servers via the `re_breaker.triage` shared helper, or are intended to be imported directly in future per-server refactors.

Each vendored server has been vendored with:
- Original `pyproject.toml` and `server.py` preserved.
- RE-AI-specific path/env-var references updated to read `RE_BREAKER_PLUGIN_ROOT/vendored/re-ai/...`.
- `VENDORED.md` marker at the root noting: origin (RE-AI commit SHA), license, contact for upstream sync.

The vendored code is **imported, not subprocessed**. RE-BREAKER's own MCP servers do the import in-process; they no longer shell out to `uv --directory $RE_AI_PLUGIN_ROOT/... run <server> ...`.

## 4. The 3 new runtime paths (v0.4.0)

The user's primary motivation for v0.4.0 was getting runtime analysis to actually work on the 7 stress-test targets. Three new MCP servers cover the three viable paths:

| Server | Backend | Use case | Status |
|---|---|---|---|
| `re-frida-wine-runtime` | In-process frida-gadget injection | Dynamic JS hooks | v0.4.0: scaffolding + script-only mode; full attach requires frida-gadget download |
| `re-injection-runtime` | C-injection library (no Frida) | Fast C hooks, no JS overhead | v0.4.0: scaffolding + 4 hook specs; IPC consumer in v0.4.1 |
| `re-winedbg` | Wine + winedbg + gdb + GEF | Vendor-neutral, in-tree dynamic analysis | v0.4.0: core 10 tools implemented; GEF helpers + convenience methods are stubs (land in v0.4.1) |

See `docs/WINE.md` for the per-server launch recommendations and the in-process frida-gadget technique.

## 5. Self-containment verification

To verify RE-BREAKER is self-contained, clone it to a clean directory and confirm:

```bash
# 1. The .venv dirs for the 12 existing servers were already set up under gitignore.
#    The 3 new servers (re-frida-wine-runtime, re-injection-runtime, re-winedbg)
#    are NOT in git — clone + `uv sync` in each.
for s in re-frida-wine-runtime re-injection-runtime re-winedbg; do
  (cd servers/$s && uv sync)
done

# 2. No RE-AI env var is set anywhere in non-vendored code.
grep -rn "RE_AI_PLUGIN_ROOT" --include="*.py" --include="*.json" --include="*.toml" \
    | grep -v "/vendored/re-ai/" \
    | head -20
# Expected output: only the harmless env-var echoes in status() functions.
# The actual code paths use the shared re_breaker.triage.load_triage() helper.

# 3. The vendored data is present.
ls vendored/re-ai/output/2026-06-07-honest-read/per-binary/
# Expected output: 007fl/ cd/ fm26/ hkia/ lir/ p3r/ tww3/

# 4. The 4 critical bug fixes are in place.
grep -n "plan_wrapper\|_load_triage\|mkdir.*0755\|_flatten_primitives" \
    servers/re-patch-apply/src/re_patch_apply/server.py \
    servers/re-anti-debug-patch/src/re_anti_debug_patch/server.py \
    servers/re-catalog-match/src/re_catalog_match/server.py \
    inject/src/common/decrypt_dump.c
# Expected output: all fixes present.
```

## 5b. X11 observability (v0.4.2.0 added)

The 2026-06-08 live-fire engagement revealed that **headless observability** is the precondition for any per-target progress. The X11 helpers promoted from `/tmp` to the repo are the v0.4.2.0 minimum-viable observability stack:

```
See the RE-BREAKER output directory.
├── x11-capture/
│   ├── xshot.py           # PIL-based X11 capture (PIL.ImageGrab)
│   ├── README.md          # Known Limitations: PIL fails on this host with
│   │                        X get_image failed: error 8 (73, 0, 896)
│   └── SHA256SUMS
└── x11-input/
    ├── xkey.py            # XTest-based X11 key sender
    ├── fmshot.sh          # multi-timepoint ffmpeg x11grab capture
    ├── README.md          # Known Limitations: XSetInputFocus BadWindow
    └── SHA256SUMS
```

### The AtomMan / Vulkan / :0-vs-:1 problem

The 7-target live-fire ran on a host with the following X11 configuration:

- **Display :0** — the X server AtomMan manages (low-level xprop / xwd / ffmpeg x11grab all see this)
- **Display :1** — the Vulkan swapchain target (where Unity / Unreal render)
- **Vulkan ICD** — `nvidia` (RTX 4070)

Wine's DXVK initializes the Vulkan swapchain on :1, but `ffmpeg -f x11grab` and `PIL.ImageGrab` capture from :0. Result: the captured framebuffer is a blank 8.6 KB PNG of the X server root, not the rendered game output. The launcher's XTest key events also go to :0, which may not focus the Wine child window.

This is the root cause of the v0.4.1.9 "screenshot tool is broken in this X11 environment" finding.

### 3 reserved slots (v0.4.2.0)

The 3 new MCP servers (added in v0.4.2.0) are the next-session's path forward:

| Server | Status | Role |
|---|---|---|
| `re-launch-and-observe` | v0.1.0 SCAFFOLD | Spawn a Wine target with xprop polling + ffmpeg x11grab + emulator log tailing + scheduled XTest key injection. Returns a structured event log. |
| `re-cinematic-skip` | v0.1.0 SCAFFOLD | Auto-dismiss Unity / Sports Interactive / Pearl Abyss splash cinemáticos. Either Wine-side XTest fake-key or build-time NOP of the "press any key" hook. |
| `re-traffic-capture` | v0.1.0 SCAFFOLD | Spawn with `WINEDEBUG=+winsock,+wininet,+http` and parse the output into a structured event log (DNS lookup, HTTP request, response code, payload snippet). |

## 6. Versioning

v0.4.0 is a **breaking** change relative to v0.3.0: any consumer that relied on `RE_AI_PLUGIN_ROOT` being a sibling must now use the vendored paths under `vendored/re-ai/`.

v0.4.0 is **additive** in MCP server count: 12 → 15. The 3 new servers are opt-in; existing consumers can ignore them.

v0.4.0 is **fixing** for the 4 critical stress-test bugs: re-patch-apply silent failure, c-injection-build .dll build failure, catalog matcher IL2CPP triage shape, plan-only servers' "no triage.json found" bug.

v0.4.2.0 is **additive** in MCP server count: 15 → 18 (with the 3 reserved slots in §5b). The 3 new servers are scaffold-only; runtime execution lands in v0.4.3.0. v0.4.2.0 also **adds** the `re-input-audit` skill + the `cross-target-entitlement-bypass` playbook + promotes the X11 helpers from `/tmp` to the repo + standardizes the SEGA SSO mock layout + fixes the `gbe-fork/scripts/deploy-gbe-fork.sh` path-quoting bug.

## 7. Native-Windows-VM toolchain (v0.5.3 / VM-stack v0.5.0)

The v0.4.x stack is Wine + winedbg; v0.5.3 adds a parallel stack
against a real libvirt KVM Windows 11 guest (`win11`, libvirt id 9)
with IDA Pro 9, Ghidra, and x64dbg installed natively.

### 7a. The 8 new MCP servers

```
re-vm-control  (fully impl.)  virsh / QMP / snapshots / SPICE / NMI / gdb stub attach
   │
   │ uses
   ▼
re-vm-ssh      (fully impl.)  paramiko / ssh_exec / file_put/get / tunnel registry
   │
   │ uses
   ▼
re-vm-launch   (scaffold)     upload + launch target in VM
   │
   │ uses
   ▼
re-vm-debug    (scaffold)     QEMU gdb stub client (gdb_remote.py = RSP)
re-vm-memory   (scaffold)     bulk QMP pmemsave + diff snapshots
re-ida-remote  (scaffold)     bridge to mrexodia/ida-pro-mcp
re-ghidra-remote (scaffold)   bridge to bethington/ghidra-mcp
re-x64dbg-remote (scaffold)   bridge to AgentSmithers/x64DbgMCPServer
```

### 7b. The shared module

`servers/re-vm-ssh/src/re_vm_ssh/server.py` re-exports the helpers from
`src/re_breaker/vm_client.py` so the bridge servers can `from re_vm_ssh
import client` rather than reimplementing paramiko + tunnel lifecycle
per server. Same import pattern that the existing servers use for
`re_breaker.triage`.

### 7c. VM coordinates (overridable via env)

```
RE_BREAKER_LIBVIRT_URI   = qemu:///system
RE_BREAKER_VM_NAME       = win11
RE_BREAKER_SSH_HOST      = john@RE_BREAKER_SSH_HOST
RE_BREAKER_SSH_KEY       = /home/john/.ssh/id_ed25519
RE_BREAKER_GDB_STUB_PORT = 1234
```

### 7d. Why two real + six scaffolds?

The v0.4.0 → v0.4.1.4 cadence the existing servers used split big
drops into `status + core` real + the rest scaffolded. v0.5.3 does the
same: `re-vm-control` + `re-vm-ssh` are the foundation every other
server uses, so they ship fully implemented. The other 6 are honest
"v0.5.1/0.5.2/0.5.3 of the VM toolchain will implement" shells that
return their planned tool shape so the rest of the toolchain can be
wired against a known interface.

**Update 2026-06-09 (v0.5.4 of project / v0.5.1 of VM toolchain):**
`re-vm-launch` + `re-vm-memory` are now real (6/6 tools each). The
4 remaining scaffolds are `re-ida-remote`, `re-ghidra-remote`,
`re-x64dbg-remote` (v0.5.2 of the VM toolchain), and `re-vm-debug`
(v0.5.3 of the VM toolchain).
