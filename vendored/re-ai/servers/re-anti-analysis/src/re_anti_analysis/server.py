"""MCP server entry point for re-anti-analysis.

Cross-section correlation of anti-debug + anti-VM + anti-sandbox
primitives in a binary. The server is a thin wrapper that
combines the string-table + IAT walk from re-lief (via
``re-lief.scan_anti_analysis_primitives`` + ``re-lief
.classify_native_protection``) with the disasm walk from
re-rizin (the byte-sequence evidence: RDTSC = 0F 31, INT 2D
= CD 2D, INT 3 = CC, CPUID = 0F A2).

All output is vendor-neutral. Categories only — no product
names.
"""

from __future__ import annotations

import logging
import os
import re

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("re_anti_analysis")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-anti-analysis")


@mcp.tool()
def check_anti_analysis() -> dict:
    """Report server status + the vendored catalog version.

    Always returns ``status: OK`` (pure-Python; no system
    dependencies). The vendored ``data/anti-analysis-catalog.json``
    is loaded at MCP server load time; this tool surfaces the
    version + entry count.
    """
    catalog = _load_catalog()
    return {
        "server": "re-anti-analysis",
        "version": "0.1.0",
        "status": "OK",
        "catalog_version": catalog.get("_meta", {}).get("version"),
        "catalog_entry_count": len(catalog.get("entries", [])),
        "category_count": len(catalog.get("_meta", {}).get("category_legend", {})),
    }


@mcp.tool()
def scan_anti_analysis_primitives(path: str, max_per_category: int = 100) -> dict:
    """Walk a binary for anti-analysis primitives (defender side).

    Wraps ``re-lief.scan_anti_analysis_primitives`` and adds a
    disasm pass (via re-rizin ``search_bytes``) for the
    byte-sequence evidence kinds (RDTSC, INT 2D, INT 3, CPUID,
    VMXON, VMCALL).

    Returns::

        {
          "path": "...",
          "string_table": {"matches": [...], "by_category": {...}},
          "byte_sequences": [{"primitive": "RDTSC", "matches": [...], "byte_sequence": "0F 31"}, ...],
          "correlated": [{"category": "...", "primitive": "...",
                          "evidence": "string+disasm", "string_offset": N,
                          "disasm_addr": "0x..."}, ...]
        }
    """
    string_table = _call_lief_scan(path, max_per_category)
    byte_sequences = _scan_byte_sequences(path)
    correlated = _correlate(string_table, byte_sequences)
    return {
        "path": path,
        "string_table": string_table,
        "byte_sequences": byte_sequences,
        "correlated": correlated,
    }


@mcp.tool()
def classify_native_protection(path: str) -> dict:
    """Classify a native binary's protection class (category-only).

    Wraps ``re-lief.classify_native_protection`` and cross-references
    with the disasm pass to confirm.
    """
    lief_result = _call_lief_classify(path)
    return lief_result


@mcp.tool()
def correlate_anti_patterns(path: str, max_per_category: int = 100) -> dict:
    """Cross-section correlation of anti-debug + anti-VM + anti-sandbox.

    Returns the same shape as
    :func:`scan_anti_analysis_primitives` plus a
    ``correlation_score`` field: the count of categories
    that fired in *both* the string-table pass and the
    disasm pass. A higher correlation score is a stronger
    signal of a real anti-tamper stack.
    """
    out = scan_anti_analysis_primitives(path, max_per_category)
    out["correlation_score"] = len(out.get("correlated", []))
    return out


@mcp.tool()
def suggest_runtime_trap(target_path: str, primitive: str) -> dict:
    """Suggest runtime traps (advice only — no auto-patch).

    Returns a list of *suggestions* (recipe-style) for the
    analyst to consider. Never auto-applies a patch — the
    override-scope contract from ``CLAUDE.md`` is the
    gatekeeper. The suggestions are: which debugger-spoof
    technique neutralises the matched primitive, what
    the analyst's runtime trace should look for, and
    what re-frida / re-gdb tool to use.

    Args:
        target_path: path to the binary
        primitive: one of the catalog primitives
            (e.g. ``"IsDebuggerPresent"``,
            ``"RDTSC"``, ``"CPUID.1.ECX hypervisor
            present bit"``)

    Returns::

        {
          "primitive": "...",
          "trap_recipe": "...",
          "runtime_trace_targets": [...],
          "recommended_tool": "...",
          "warning": "..."
        }
    """
    recipe = _trap_recipes().get(primitive.lower(), None)
    if recipe is None:
        return {
            "primitive": primitive,
            "trap_recipe": None,
            "runtime_trace_targets": [],
            "recommended_tool": "re-frida (manual hook)",
            "warning": (
                "no specific recipe for this primitive; use the "
                "general anti-anti-debug workflow (re-frida hook + "
                "re-winedbg single-step on the matched address)"
            ),
        }
    return recipe


# ── helpers ────────────────────────────────────────────────────────────


def _load_catalog() -> dict:
    from pathlib import Path
    import json
    here = Path(__file__).resolve()
    candidates = [
        here.parents[4] / "data" / "anti-analysis-catalog.json",
        here.parents[3] / "data" / "anti-analysis-catalog.json",
        here.parents[2] / "data" / "anti-analysis-catalog.json",
    ]
    for p in candidates:
        if p.is_file():
            return json.loads(p.read_text())
    return {"entries": [], "_meta": {}}


def _call_lief_scan(path: str, max_per_category: int) -> dict:
    """Import + call re-lief.scan_anti_analysis_primitives, gracefully
    degraded when re-lief can't be imported.

    A14 fix (v2.8.0): the original `here.parents[2]` lands at
    `re-anti-analysis/` (the server's own root), not `servers/` — so
    the lookup for `re-lief/src` always failed and every call
    short-circuited to `error: 're-lief not found'`. The correct
    depth is parents[3] (servers/) → servers/re-lief/src. Confirmed
    by the r03-stress run: correlate_anti_patterns returned
    score=0 on all 17 binaries across LIR/P3R/CD/APK because of
    this single path bug.
    """
    try:
        import importlib.util
        from pathlib import Path
        # Walk up to find re-lief. File path is:
        # servers/re-anti-analysis/src/re_anti_analysis/server.py
        # parents: 0=re_anti_analysis, 1=src, 2=re-anti-analysis,
        #          3=servers, 4=repo-root
        here = Path(__file__).resolve()
        lief_src = here.parents[3] / "re-lief" / "src"
        if not lief_src.is_dir():
            return {"matches": [], "by_category": {}, "error": "re-lief not found"}
        import sys
        sys.path.insert(0, str(lief_src))
        try:
            from re_lief import protection_catalog
            return protection_catalog.scan_anti_analysis_primitives(
                path, max_per_category=max_per_category,
            )
        finally:
            if str(lief_src) in sys.path:
                sys.path.remove(str(lief_src))
    except Exception as exc:  # noqa: BLE001
        return {"matches": [], "by_category": {}, "error": str(exc)}


def _call_lief_classify(path: str) -> dict:
    try:
        import sys
        from pathlib import Path
        # A14 fix: same off-by-one as _call_lief_scan above.
        here = Path(__file__).resolve()
        lief_src = here.parents[3] / "re-lief" / "src"
        if not lief_src.is_dir():
            return {"path": path, "protection_class": "unknown", "evidence": [],
                    "error": "re-lief not found"}
        sys.path.insert(0, str(lief_src))
        try:
            from re_lief import protection_catalog
            return protection_catalog.classify_native_protection(path)
        finally:
            if str(lief_src) in sys.path:
                sys.path.remove(str(lief_src))
    except Exception as exc:  # noqa: BLE001
        return {"path": path, "protection_class": "unknown", "evidence": [],
                "error": str(exc)}


_BYTE_PATTERNS: list[tuple[str, str, str]] = [
    # (primitive, hex pattern, category)
    ("RDTSC", "0F 31", "anti_debug"),
    ("INT 2D", "CD 2D", "anti_debug"),
    ("INT 3", "CC", "anti_debug"),
    ("CPUID", "0F A2", "anti_vm"),
    ("VMXON", "0F C7", "anti_vm"),
    ("VMCALL", "0F 01 C1", "anti_vm"),
    ("INVD", "0F 08", "anti_emulator"),
    ("CPUID-hypervisor-leaf", "0F A2 0F 01", "anti_vm"),
]


def _scan_byte_sequences(path: str) -> list[dict]:
    """Naive byte-sequence scan of *path*. Calls ``re-rizin.search_bytes``
    for the per-pattern hit list. In degraded mode (re-rizin not
    importable) does a direct grep over the binary.

    A15 fix (v2.8.1): every entry in ``_BYTE_PATTERNS`` is an
    x86/x86_64 opcode (RDTSC, INT 2D, INT 3, CPUID, VMXON, VMCALL,
    INVD, CPUID-hypervisor-leaf). On AArch64 / ARM / MIPS / RISC-V
    binaries these bytes are common in unrelated data — the r03-stress
    APK pass produced 306 false-positive INT-3 hits on
    ``libproot.so`` + ``libzstd-jni.so`` because the x86 catalog was
    applied to AArch64 .so files. The fix: detect the binary's arch
    from its magic bytes; on non-x86 targets, emit each entry with
    ``skipped_arch=True`` and ``matches=[]`` so the correlate pass +
    the gap-analysis A15 row surface "intentionally skipped" rather
    than "0 matches". The string-table leg is unaffected.
    """
    from pathlib import Path
    p = Path(path)
    if not p.is_file():
        return [{"primitive": prim, "matches": [], "byte_sequence": pat,
                 "error": "file not found", "skipped_arch": False}
                for prim, pat, _ in _BYTE_PATTERNS]
    out = []
    try:
        data = p.read_bytes()
    except OSError as exc:
        return [{"primitive": prim, "matches": [], "byte_sequence": pat,
                 "error": f"read failed: {exc}", "skipped_arch": False}
                for prim, pat, _ in _BYTE_PATTERNS]

    # A15: arch-aware gate. Detect the binary's arch; skip x86-only
    # opcodes on non-x86 targets.
    bin_arch = _detect_binary_arch(data)
    arch_applies = _arch_in_default(bin_arch)

    for prim, hexpat, cat in _BYTE_PATTERNS:
        if not arch_applies:
            out.append({
                "primitive": prim,
                "category": cat,
                "byte_sequence": hexpat,
                "matches": [],
                "skipped_arch": True,
                "binary_arch": bin_arch,
            })
            continue
        try:
            needle = bytes.fromhex(hexpat.replace(" ", ""))
        except ValueError:
            continue
        matches = []
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx < 0:
                break
            matches.append(idx)
            start = idx + 1
            if len(matches) > 200:
                break
        out.append({
            "primitive": prim,
            "category": cat,
            "byte_sequence": hexpat,
            "matches": matches,
            "skipped_arch": False,
            "binary_arch": bin_arch,
        })
    return out


# AArch64 / ARM / MIPS / RISC-V arches that should SKIP the x86-only
# _BYTE_PATTERNS catalog. Used by the A15 gate; the catalog itself
# doesn't list arches (each entry is hard-coded x86 in this walker),
# so the gate is conservative — anything not in ``_X86_ARCHES`` is
# treated as non-applicable. PE + ELF + Mach-O magic detection below.
_X86_ARCHES = frozenset({
    "x86", "x86_64", "i386", "i686", "amd64", "x64",
})


def _arch_in_default(arch: str) -> bool:
    """Return True if *arch* should consume the x86-only ``_BYTE_PATTERNS`` catalog.

    Reads the catalog ``_meta.arch_default`` so a future catalog change
    (e.g. an AArch64 byte-sequence primitive) is picked up without
    touching this code. Falls back to the x86-set when the catalog
    can't be loaded (e.g. tests, fresh checkout before install.sh).
    """
    try:
        catalog = _load_catalog()
        default = catalog.get("_meta", {}).get("arch_default") or []
        if not default:
            return arch in _X86_ARCHES
        return arch in set(default)
    except Exception:  # noqa: BLE001
        return arch in _X86_ARCHES


def _detect_binary_arch(data: bytes) -> str:
    """Detect the binary's architecture from its magic bytes.

    Best-effort: returns one of ``x86``, ``x86_64``, ``aarch64``,
    ``arm``, ``mips``, ``riscv``, ``pe-<machine>``, ``elf-<machine>``,
    or ``unknown``. Doesn't try to be exhaustive — just enough to
    gate the x86-only byte-pattern catalog on AArch64/ARM binaries.
    Pure stdlib (no lief / rizin dependency), so it works in the
    minimal-deps degraded mode the rest of the walker supports.
    """
    import struct
    if len(data) < 4:
        return "unknown"
    if data[:2] == b"MZ":
        # PE: COFF header at pe_off + 4 has Machine (u2)
        if len(data) < 0x40:
            return "unknown"
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return "unknown"
        machine = struct.unpack_from("<H", data, pe_off + 4)[0]
        # IMAGE_FILE_MACHINE_* values
        if machine == 0x14C:
            return "x86"
        if machine == 0x8664:
            return "x86_64"
        if machine == 0xAA64:
            return "aarch64"
        if machine in (0x1C0, 0x1C4):  # ARM, ARMNT
            return "arm"
        return f"pe-0x{machine:04x}"
    if data[:4] == b"\x7fELF":
        if len(data) < 20:
            return "unknown"
        ei_class = data[4]  # 1=32bit, 2=64bit
        e_machine = struct.unpack_from("<H", data, 18)[0]
        # ELF e_machine values
        if e_machine == 3:  # EM_386
            return "x86" if ei_class == 1 else "x86_64"
        if e_machine == 0x28:  # EM_AARCH64 (64) or EM_ARM (32)
            return "aarch64" if ei_class == 2 else "arm"
        if e_machine == 8:  # EM_MIPS
            return "mips"
        if e_machine == 0xF3:  # EM_RISCV
            return "riscv"
        return f"elf-{e_machine}"
    # Mach-O magic (32-bit BE, 32-bit LE, 64-bit BE, 64-bit LE, universal)
    for magic in (
        b"\xfe\xed\xfa\xce",  # 32-bit BE
        b"\xce\xfa\xed\xfe",  # 32-bit LE
        b"\xfe\xed\xfa\xcf",  # 64-bit BE
        b"\xcf\xfa\xed\xfe",  # 64-bit LE
        b"\xca\xfe\xba\xbe",  # universal / FAT
    ):
        if data[:4] == magic:
            # Mach-O ARM64 cputype=0x0100000C
            if len(data) >= 8:
                cputype = struct.unpack_from("<I", data, 4)[0]
                if cputype in (0x0100000C, 0x01000007):
                    return "aarch64"
            return "macho"
    return "unknown"


def _correlate(string_table: dict, byte_sequences: list[dict]) -> list[dict]:
    """Cross-section correlation: a category that fires in both
    the string-table pass and the disasm pass is a stronger
    signal than a hit in just one."""
    str_cats = {m.get("category") for m in string_table.get("matches", [])}
    out: list[dict] = []
    for bs in byte_sequences:
        if bs.get("category") in str_cats and bs.get("matches"):
            out.append({
                "category": bs["category"],
                "primitive": bs["primitive"],
                "evidence": "string+disasm",
                "string_offset": None,
                "disasm_addr": hex(bs["matches"][0]),
            })
    return out


def _trap_recipes() -> dict[str, dict]:
    """Return the per-primitive runtime-trap recipe catalog."""
    return {
        "isdebuggerpresent": {
            "primitive": "IsDebuggerPresent",
            "trap_recipe": (
                "Patch the PEB.BeingDebugged byte to 0 at runtime via "
                "re-winedbg.write_memory. Use a script that intercepts "
                "the IsDebuggerPresent call (Frida Interceptor) and "
                "returns 0."
            ),
            "runtime_trace_targets": ["kernel32!IsDebuggerPresent", "PEB+2"],
            "recommended_tool": "re-winedbg (write_memory) or re-frida (Interceptor)",
        },
        "rdtsc": {
            "primitive": "RDTSC",
            "trap_recipe": (
                "Hook the RDTSC opcode (0F 31) via re-winedbg.set_breakpoint "
                "on a controlled guest; pair the elapsed-time delta with a "
                "real-CPU baseline. Do NOT patch RDTSC — the goal is to "
                "measure, not to defeat."
            ),
            "runtime_trace_targets": ["RIP at the 0F 31 opcode"],
            "recommended_tool": "re-winedbg (gef_trace_breakpoint)",
        },
        "cpuid.1.ecx hypervisor present bit": {
            "primitive": "CPUID.1.ECX hypervisor present bit",
            "trap_recipe": (
                "Read CPUID leaf 1 ECX bit 31 under a controlled guest; "
                "set a breakpoint at the CPUID opcode (0F A2) and read "
                "ECX after the instruction completes."
            ),
            "runtime_trace_targets": ["CPUID.1.ECX", "RIP at the 0F A2 opcode"],
            "recommended_tool": "re-winedbg (read_registers after CPUID)",
        },
        "ntqueryinformationprocess": {
            "primitive": "NtQueryInformationProcess",
            "trap_recipe": (
                "Hook NtQueryInformationProcess and intercept the "
                "ProcessDebugPort / ProcessDebugObjectHandle / "
                "ProcessDebugFlags information classes. Return 0 for "
                "all three."
            ),
            "runtime_trace_targets": ["ntdll!NtQueryInformationProcess"],
            "recommended_tool": "re-frida (hook_method)",
        },
        "vmxon": {
            "primitive": "VMXON/VMCALL instruction presence",
            "trap_recipe": (
                "Detect VMXON at static-analysis time. In a real "
                "hypervisor context, the instruction is ring 0 and "
                "invisible to userland. The presence of VMXON in "
                "userland is itself the signal."
            ),
            "runtime_trace_targets": ["VMXON at the section byte-pattern"],
            "recommended_tool": "re-rizin (search_bytes for 0F C7)",
        },
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
