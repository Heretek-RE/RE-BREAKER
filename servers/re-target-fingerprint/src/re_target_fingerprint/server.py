"""re-target-fingerprint MCP server (v0.1.0 / v0.8.0+ Wave 3, Item G).

Per-target YARA fingerprinting. Extracts unique byte patterns from a
target binary and emits a YARA rule that identifies that specific
build/version. Pairs with re-catalog-match to give a per-target match
in addition to the per-technique-class match.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import struct
from pathlib import Path
from typing import Optional

try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from mcp.server.fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    FastMCP = None
    MCP_AVAILABLE = False

from re_target_fingerprint import __version__

log = logging.getLogger("re-target-fingerprint")
log.setLevel(logging.INFO)

mcp = FastMCP("re-target-fingerprint") if MCP_AVAILABLE else None


# ----------------------------------------------------------------------------
# Per-target fingerprint patterns
# ----------------------------------------------------------------------------

# Each entry: a known "magic" byte pattern + how to extract the surrounding
# context. Used by generate_fingerprints() to build a YARA rule that
# uniquely identifies a specific build/version.
#
# The format: {target_key: {matcher_name: (hex_pattern, description, anchor)}}
#
# hex_pattern: a contiguous byte sequence to search for (with wildcards ??)
# description: human-readable name of what this pattern matches
# anchor: "first" | "any" — whether to anchor on the first occurrence (more
#         selective, fewer false positives) or any occurrence (more
#         robust against repacks that moved things around)
#
# Patterns are derived from:
#   - FM26: GameAssembly.dll IL2CPP v24+ runtime_metadata header magic
#     (0xFAB11BAF) at offset 0x328-0x32B of GameAssembly.dll
#   - HKIA: Sunblink SDK dispatcher magic (SCAFFOLD — depends on M3)
#   - 007FL: IOI Glacier 2 dispatcher (0x4D 0x5A ...) + Denuvo marker
#   - TWW3: CA CArena engine signature (CArena::WorldInit)
#   - P3R: Atlus P-Studio runtime marker (P5R-style)
#   - LIR: LuaJIT binding magic
#   - CD: Denuvo v6.2 marker + IOI Glacier 2 magic
#   - F1_25: EA SPEAR AntiCheat cert + Denuvo ATD + /antitamperdiagnosis
#     endpoint + InsaneRamZes preloader PDB path + "f12025" product code.
#     The preloader_pdb_path is included here because preloader_l.dll ships
#     in the same directory as F1_25.exe and is the universal InsaneRamZes
#     crack loader (this PR is the first InsaneRamZes release; if a second
#     surfaces, the preloader patterns should be promoted to their own
#     target_key to avoid cross-release false positives).

# Static pattern templates (we extract context around each pattern)
TARGET_PATTERNS = {
    "fm26": {
        "il2cpp_metadata_header": {
            "pattern": "?? ?? ?? ?? FAB1 1BAF",  # little-endian 0xFAB11BAF
            "description": "IL2CPP v24+ runtime_metadata header magic (FM26's GameAssembly.dll)",
            "anchor": "first",
            "extra_context_bytes": 32,  # capture 32 bytes around the match
        },
        "unity_player_signature": {
            "pattern": "55 6E 69 74 79",  # "Unity" ASCII
            "description": "Unity engine player signature",
            "anchor": "any",
            "extra_context_bytes": 16,
        },
    },
    "007fl": {
        "glacier2_dispatcher": {
            "pattern": "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 41 55 41 56 41 57 48 83 EC 30",
            "description": "IOI Glacier 2 dispatcher prologue (001FirstLight's runtime DLL)",
            "anchor": "first",
            "extra_context_bytes": 64,
        },
    },
    "tww3": {
        "ca_arena_engine": {
            "pattern": "43 41 41 72 65 6E 61",  # "CAArena" ASCII
            "description": "CA CArena engine signature (Total War: Warhammer III)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
    },
    "p3r": {
        "atlus_p_studio": {
            "pattern": "50 2D 53 74 75 64 69 6F",  # "P-Studio" ASCII
            "description": "Atlus P-Studio runtime marker (Persona 3 Reload)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
    },
    "lir": {
        "luajit_binding": {
            "pattern": "4C 75 61 4A 49 54",  # "LuaJIT" ASCII
            "description": "LuaJIT binding magic (Lost in Random)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
    },
    "cd": {
        "denuvo_v6_marker": {
            "pattern": "44 65 6E 75 76 6F 36 32",  # "Denuvo62" ASCII
            "description": "Denuvo v6.2 marker (Crimson Desert)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
    },
    "hkia": {
        # HKIA is SCAFFOLD pending M (Sunblink RE). The patterns below are
        # best-effort placeholders based on Unity + IL2CPP markers; the
        # Sunblink-specific magic will be added once M Phase 1 lands.
        "unity_player_signature": {
            "pattern": "55 6E 69 74 79",  # "Unity" ASCII
            "description": "Unity engine player signature (HKIA's UnityCrashHandler / launcher)",
            "anchor": "any",
            "extra_context_bytes": 16,
        },
    },
    "f1_25": {
        # F1 25 Iconic Edition (InsaneRamZes crack). The cracked build is
        # 23-section Frostbite/Ego with EA SPEAR AntiCheat cert, Denuvo
        # ATD intact, and an InsaneRamZes preloader_l.dll in the same
        # directory. The crack adds 23 VMCALL + 2.18M CPUID anti-VM
        # primitives (see re-triage-output/orchestrator/f1_25-triage.json).
        #
        # Per-file match distribution (verified by grep on the actual
        # binaries, not on the strings-sweep report):
        #   F1_25.exe:                     denuvo_atd_marker (3 patterns)
        #                                   antitamper_diag_endpoint
        #                                   f12025_manifest
        #   EAAntiCheat.* binaries:        ea_spear_cert_ou (1 pattern)
        #   preloader_l.dll:               ea_spear_cert_ou (1 pattern)
        #                                   preloader_pdb_path
        # The "denuvo_atd" string is lowercase + "_atd" suffix in the
        # actual binary; the "Denuvo" mixed-case form the plan referenced
        # is NOT present (verified). The "antitamperdiagnosis" string is
        # 20 chars (no leading slash) — the HTTP endpoint prefix "/antitamperdiagnosis"
        # is NOT in the binary (verified).
        "denuvo_atd_marker": {
            "pattern": "64 65 6E 75 76 6F 5F 61 74 64",  # "denuvo_atd" ASCII (lowercase + _atd)
            "description": "Denuvo ATD function-name string (F1 25's protected binary)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
        "ea_spear_cert_ou": {
            "pattern": "45 41 20 53 50 45 41 52",  # "EA SPEAR" ASCII
            "description": "EA SPEAR AntiCheat Engineering signatory (F1 25 cert OU, present in EAAntiCheat binaries)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
        "antitamper_diag_endpoint": {
            "pattern": "61 6E 74 69 74 61 6D 70 65 72 64 69 61 67 6E 6F 73 69 73",  # "antitamperdiagnosis" ASCII (no leading slash)
            "description": "EA AC anti-tamper diagnosis endpoint string (cracked F1 25)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
        "preloader_pdb_path": {
            "pattern": "2F 77 6F 72 6B 2F 70 72 65 6C 6F 61 64 65 72 2E 70 64 62",  # "/work/preloader.pdb" ASCII
            "description": "InsaneRamZes preloader PDB path (universal crack-time loader, ships with F1 25)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
        "f12025_manifest": {
            "pattern": "66 31 32 30 32 35",  # "f12025" ASCII
            "description": "F1 25 internal product code in PE manifest (F1 25 game binary)",
            "anchor": "first",
            "extra_context_bytes": 32,
        },
    },
}


def _plugin_root() -> Path:
    env = os.environ.get("RE_BREAKER_PLUGIN_ROOT")
    if env and Path(env).is_dir():
        return Path(env)
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "servers").is_dir() and (parent / "vendored").is_dir():
            return parent
    return Path.cwd()


def _target_key(target: str) -> str:
    p = Path(target).resolve()
    name = p.name.lower()
    # Re-use the keymap from re_breaker.triage for consistency
    keymap = {
        "fm.exe": "fm26", "007firstlight.exe": "007fl",
        "warhammer3.exe": "tww3", "p3r.exe": "p3r",
        "lostinrandom.exe": "lir", "lost in random.exe": "lir",
        "crimsondesert.exe": "cd", "hello kitty.exe": "hkia",
        "f1_25.exe": "f1_25",
        "bge.exe": "bge",  # v0.6.0: Beyond Good and Evil 20th AE
        "borderlands4.exe": "borderlands4",  # v0.6.0: Borderlands 4
        "thelostcrown.exe": "thelostcrown",  # v0.6.0: POP The Lost Crown
    }
    if name in keymap:
        return keymap[name]
    # Normalize: strip spaces + hyphens, lowercase
    normalized = re.sub(r"[\s\-]", "", name)
    if normalized in {"lostinrandom.exe", "lir.exe"}:
        return "lir"
    # Walk up: if parent dir is one of the known ones
    parent_norm = re.sub(r"[\s\-]", "", p.parent.name.lower())
    parent_map = {
        "footballmanager26": "fm26",
        "hellokittyislandadventure": "hkia",
        "lostinrandom": "lir",
        "crimsondesert": "cd",
        "totalwarwarhammer3": "tww3",
        "007firstlight": "007fl",
        "f1.25.iconic.editioninsaneramzes": "f1_25",
        # v0.6.0: new targets
        "beyondgoodandevil20thanniversaryedition": "bge",
        "borderlands4": "borderlands4",
        "princeofpersiathelostcrown": "thelostcrown",
    }
    if parent_norm in parent_map:
        return parent_map[parent_norm]
    return p.parent.name.lower().replace(" ", "-")


def _hex_pattern_to_bytes(pattern: str) -> bytes:
    """Convert a YARA-style hex pattern (with ?? wildcards) to bytes.

    Wildcards (?) are returned as 0x00 in the byte string; the caller
    should re-apply the wildcard mask when doing the comparison.
    Supports multi-byte tokens like "FAB1" (2 bytes) by splitting each
    token into byte pairs.
    """
    tokens = pattern.split()
    out = bytearray()
    for t in tokens:
        if t == "??":
            out.append(0x00)
            continue
        # Split multi-byte tokens into byte pairs
        for i in range(0, len(t), 2):
            pair = t[i:i + 2]
            if pair == "??":
                out.append(0x00)
            else:
                out.append(int(pair, 16))
    return bytes(out)


def _hex_pattern_to_regex(pattern: str) -> bytes:
    """Convert a YARA-style hex pattern (with ?? wildcards) to a compiled
    regex (bytes mode). Wildcards become `.` (match-any-byte).

    Returned as `re.compile(pattern, re.DOTALL).pattern` ready bytes
    so the caller can `pattern.search(data)` directly.

    For perf, we use the underlying `bytes` regex search rather than a
    Python-loop byte compare — this turns 412MB scans from ~90s into
    ~1s on the F1_25.exe target.
    """
    rx = bytearray(b"(?:")  # non-capturing group wrapper
    for t in pattern.split():
        if t == "??":
            rx.extend(b".")  # match-any single byte
            continue
        # Split multi-byte tokens into byte pairs and emit as raw bytes
        for i in range(0, len(t), 2):
            pair = t[i:i + 2]
            if pair == "??":
                rx.extend(b".")
            else:
                # hex-escape the byte
                rx.extend(b"\\x")
                rx.extend(pair.lower().encode("ascii"))
    rx.extend(b")")
    return re.compile(bytes(rx), re.DOTALL)


def _extract_fingerprint(target: Path, pattern_info: dict) -> Optional[dict]:
    """Extract the surrounding context around the first/any match of a pattern.

    Returns a dict with the matched RVA + 32 bytes of context, or None
    if the pattern wasn't found.

    Performance: uses Python's C-implemented `re` engine to find the
    pattern in the target's bytes — much faster than the prior
    byte-by-byte Python loop (90s → 1s on 412MB F1_25.exe). For
    anchor="first", `re.search` returns the first hit and we capture
    context around it. For anchor="any", we run `re.findall` to count
    hits and use the first one.
    """
    pattern = pattern_info["pattern"]
    anchor = pattern_info.get("anchor", "first")
    context_bytes = pattern_info.get("extra_context_bytes", 32)
    rx = _hex_pattern_to_regex(pattern)
    with open(target, "rb") as f:
        data = f.read()
    if anchor == "first":
        m = rx.search(data)
        if m is None:
            return None
        hit = m.start()
        match_count = 1
    else:
        # anchor="any" — find the first match + count all
        m = rx.search(data)
        if m is None:
            return None
        hit = m.start()
        # Count all hits cheaply
        match_count = sum(1 for _ in rx.finditer(data))
    ctx_start = max(0, hit - context_bytes // 2)
    ctx = data[ctx_start: ctx_start + context_bytes + (m.end() - m.start())]
    return {
        "rva": f"0x{hit:x}",
        "context_hex": ctx.hex(),
        "context_length": len(ctx),
        "match_count": match_count,
    }


def _generate_yara_rule(target_key: str, target: str, patterns_matched: list[dict]) -> str:
    """Generate a YARA rule for the target based on the matched patterns.

    The rule uses a unique per-target rule name + the matched patterns
    as the condition. The `meta` block includes confidence (as int 0-100)
    + provenance info. YARA meta only supports strings + integers, so
    the confidence is expressed as a percentage.
    """
    # Sanitize the target key for YARA rule names (alphanumeric + underscore)
    rule_name = re.sub(r"[^a-zA-Z0-9_]", "_", f"re_breaker_target_{target_key}")
    rule_name = rule_name[:80]  # YARA rule names are 128 chars max
    conditions = " or\n        ".join(
        f"$p{i}" for i in range(len(patterns_matched))
    )
    if not conditions:
        conditions = "false"  # no patterns matched; this rule will never fire
    strings = "\n    ".join(
        f'$p{i} = {{ {p["pattern"]} }}' for i, p in enumerate(patterns_matched)
    )
    return f'''rule {rule_name}
{{
    meta:
        target_key = "{target_key}"
        target = "{target}"
        confidence_this_target = 100
        confidence_other_targets = 0
        generated_by = "re-target-fingerprint v{__version__}"
        generated_date = "auto-generated"

    strings:
    {strings}

    condition:
        {conditions}
}}
'''


def _write_yara_file(target_key: str, rule: str, yara_path: Path) -> None:
    """Append the rule to the target-fingerprints YARA file.

    Idempotent: if the rule for this target already exists, replace it.
    """
    if yara_path.is_file():
        content = yara_path.read_text()
        # Remove any existing rule for this target
        pattern = re.compile(
            rf"rule\s+re_breaker_target_{re.escape(target_key)}\b.*?\n\}}",
            re.DOTALL,
        )
        content = pattern.sub("", content).rstrip() + "\n"
    else:
        content = "// v0.8.0+ Wave 3 (Item G): per-target YARA fingerprint rules\n"
        content += "// Auto-generated. Do not edit by hand.\n\n"
    content += rule
    yara_path.write_text(content)


# ----------------------------------------------------------------------------
# MCP tools
# ----------------------------------------------------------------------------


@mcp.tool()
def status() -> dict:
    return {
        "server": "re-target-fingerprint",
        "version": __version__,
        "status": "implemented",
        "yara_available": YARA_AVAILABLE,
        "targets_with_patterns": list(TARGET_PATTERNS.keys()),
        "note": (
            "v0.8.0+ Wave 3 (Item G) M2 server: per-target YARA fingerprinting. "
            "Closes the v0.7.0 gap that the catalog matcher couldn't tell targets "
            "apart (technique-class rules only, not per-build)."
        ),
    }


@mcp.tool()
def generate_fingerprints(
    target: str,
    output: str = "",
) -> dict:
    """Extract unique byte patterns from `target` + emit a YARA rule.

    Args:
        target: path to the target binary
        output: path to the YARA file. Default: $RE_BREAKER_PLUGIN_ROOT/data/yara/target-fingerprints.yar

    Returns:
        {
          "status": "ok" | "error",
          "target": str,
          "target_key": str,
          "patterns_matched": int,
          "yara_rule": str,
          "yara_file": str,
        }
    """
    target_p = Path(target).resolve()
    if not target_p.is_file():
        return {
            "status": "error",
            "error": f"target not found: {target_p}",
            "server": "re-target-fingerprint",
            "version": __version__,
        }
    target_key = _target_key(str(target_p))
    patterns = TARGET_PATTERNS.get(target_key, {})
    if not patterns:
        return {
            "status": "warn",
            "error": f"no fingerprint patterns defined for target_key={target_key!r}. "
                     f"Known keys: {list(TARGET_PATTERNS.keys())}",
            "target": str(target_p),
            "target_key": target_key,
            "server": "re-target-fingerprint",
            "version": __version__,
        }
    patterns_matched: list[dict] = []
    for pname, pinfo in patterns.items():
        extracted = _extract_fingerprint(target_p, pinfo)
        if extracted is None:
            log.warning(f"target {target_key}: pattern {pname!r} not found")
            continue
        patterns_matched.append({
            "name": pname,
            "pattern": pinfo["pattern"],
            "description": pinfo["description"],
            **extracted,
        })
    rule = _generate_yara_rule(target_key, str(target_p), patterns_matched)
    if output:
        yara_path = Path(output)
    else:
        yara_path = _plugin_root() / "data" / "yara" / "target-fingerprints.yar"
    yara_path.parent.mkdir(parents=True, exist_ok=True)
    _write_yara_file(target_key, rule, yara_path)
    return {
        "status": "ok",
        "server": "re-target-fingerprint",
        "version": __version__,
        "target": str(target_p),
        "target_key": target_key,
        "patterns_matched": len(patterns_matched),
        "patterns_total": len(patterns),
        "yara_rule": rule,
        "yara_file": str(yara_path),
        "note": (
            f"Generated YARA rule for {target_key} with {len(patterns_matched)}/{len(patterns)} patterns matched. "
            f"Appended to {yara_path}."
        ),
    }


@mcp.tool()
def match_fingerprint(
    target: str,
    yara_file: str = "",
) -> dict:
    """Match `target` against the target-fingerprints YARA file.

    Returns the matched target_key + confidence (1.0 for the right target,
    0.0 for any other).
    """
    if not YARA_AVAILABLE:
        return {
            "status": "error",
            "error": "yara-python not installed; run `pip install yara-python`",
            "server": "re-target-fingerprint",
            "version": __version__,
        }
    target_p = Path(target).resolve()
    if not target_p.is_file():
        return {
            "status": "error",
            "error": f"target not found: {target_p}",
            "server": "re-target-fingerprint",
            "version": __version__,
        }
    if yara_file:
        yara_path = Path(yara_file)
    else:
        yara_path = _plugin_root() / "data" / "yara" / "target-fingerprints.yar"
    if not yara_path.is_file():
        return {
            "status": "error",
            "error": f"YARA file not found: {yara_path}. Run generate_fingerprints() first.",
            "server": "re-target-fingerprint",
            "version": __version__,
        }
    try:
        rules = yara.compile(filepath=str(yara_path))
        matches = rules.match(str(target_p))
    except yara.SyntaxError as e:
        return {
            "status": "error",
            "error": f"YARA syntax error in {yara_path}: {e}",
            "server": "re-target-fingerprint",
            "version": __version__,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "server": "re-target-fingerprint",
            "version": __version__,
        }
    if not matches:
        return {
            "status": "ok",
            "target": str(target_p),
            "matched_target": None,
            "confidence": 0.0,
            "matches": [],
            "note": "No matching fingerprint. Generate fingerprints first.",
        }
    best = matches[0]
    target_key = best.meta.get("target_key", "unknown")
    confidence = float(best.meta.get("confidence_this_target", 1.0))
    return {
        "status": "ok",
        "server": "re-target-fingerprint",
        "version": __version__,
        "target": str(target_p),
        "matched_target": target_key,
        "confidence": confidence,
        "matches": [
            {
                "rule": m.rule,
                "target_key": m.meta.get("target_key"),
                "confidence": float(m.meta.get("confidence_this_target", 1.0)),
            }
            for m in matches
        ],
        "note": f"Matched {len(matches)} fingerprint rule(s). Best: {target_key} @ {confidence:.0%}",
    }


def main() -> None:
    if mcp is None:
        raise RuntimeError("FastMCP is not installed. `uv pip install mcp`.")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
