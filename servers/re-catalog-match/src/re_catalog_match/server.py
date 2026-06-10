"""re-catalog-match MCP server (v0.2.0 implemented).

Combined defender+offender technique matcher. Loads the catalog from
`data/catalog.json` (48 entries) and matches a target binary's triage
JSON against the catalog's defender-side detection_signatures[].

Each catalog entry becomes a ranked match with:
  - aggregate confidence (sum of matching signature confidences)
  - defender-side: which signatures matched, the per-target evidence
  - offender-side: the playbook path + the tools to invoke + the
    expected runtime + the success probability + the limitations

Usage:
  mcp__re-catalog-match.match_catalog(target, intent="both", triage_json_path=None, min_confidence=0.0)
  mcp__re-catalog-match.match_catalog(target, intent="offender", triage_json_path="/path/to/triage.json")
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
# v0.4.0.1 hotfix: ensure RE-BREAKER's shared src/ is on the Python path
import sys
from pathlib import Path
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent / 'src'
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))



from re_catalog_match import __version__

logger = logging.getLogger("re_catalog_match")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-catalog-match")


# ── Health ──────────────────────────────────────────────────────────────


@mcp.tool()
def status() -> dict:
    """Return server status + relevant env-var config.

    Confirms the server is alive and reports the per-server config so an
    agent can diagnose the wiring without poking at the .mcp.json.
    """
    return {
        "server": "re-catalog-match",
        "version": __version__,
        "status": "implemented",
        "note": (
            "RE-BREAKER re-catalog-match v0.2.0: loads data/catalog.json "
            "(48 entries) and matches a target's triage JSON against the "
            "catalog's defender-side detection_signatures. Returns ranked "
            "matches with defender-side confidence + offender-side playbook "
            "references."
        ),
        "env": {
            "RE_BREAKER_CATALOG_PATH": os.environ.get(
                "RE_BREAKER_CATALOG_PATH", "<unset>"
            ),
            "RE_BREAKER_YARA_RULES_PATH": os.environ.get(
                "RE_BREAKER_YARA_RULES_PATH", "<unset>"
            ),
        },
    }


# ── Catalog match (v0.2.0 implementation) ─────────────────────────────


MatchIntent = Literal["defender", "offender", "both"]


def _load_catalog(catalog_path: str) -> dict[str, Any]:
    """Load the catalog from disk. Cached per-call (the catalog is small)."""
    p = Path(catalog_path)
    if not p.exists():
        raise FileNotFoundError(f"catalog not found at {p}")
    return json.loads(p.read_text())


def _parse_section_table(section_table_str: str) -> list[str]:
    """Parse a triage.json section_table string into a list of section names.

    The honest-read format is like: ".text(279MB,6.71), .rdata(20.2MB,5.55), .xtls(16KB,7.80)"
    We extract the section names (the text before the first "(").
    """
    sections: list[str] = []
    for chunk in section_table_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r"^(\.[A-Za-z0-9_$]+)", chunk)
        if m:
            sections.append(m.group(1))
    return sections


def _has_section_set_intersection(sections: list[str], sig_value: str) -> bool:
    """Evaluate a `section_set_intersects([.xtls, .xpdata, ...])` signature."""
    m = re.search(r"\[([^\]]+)\]", sig_value)
    if not m:
        return False
    candidates = [s.strip().strip("'\"") for s in m.group(1).split(",")]
    return any(c in sections for c in candidates)


def _flatten_primitives(primitives: dict) -> dict:
    """v0.4.0: flatten nested {launcher_*, GameAssembly_dll}.{primitive} shape.

    Native PE triage: {"anti_analysis_primitives": {"RDTSC": 1966, ...}}
    IL2CPP triage:    {"anti_analysis_primitives": {"launcher_fm_exe": {"RDTSC": 0, ...},
                                                    "GameAssembly_dll": {"RDTSC": 61, ...}}}

    We flatten by taking the max primitive value across all nested sub-dicts.
    For booleans, we OR. This lets the catalog matcher read both shapes.
    """
    if not primitives or not any(isinstance(v, dict) for v in primitives.values()):
        return primitives
    flat = {}
    for k, v in primitives.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if isinstance(v2, bool):
                    flat[k2] = flat.get(k2, False) or v2
                elif isinstance(v2, (int, float)):
                    flat[k2] = max(flat.get(k2, 0) if isinstance(flat.get(k2), (int, float)) else 0, v2)
                elif isinstance(v2, str):
                    flat[k2] = flat.get(k2, "") or v2
        elif isinstance(v, (int, float, bool, str)):
            flat[k] = v
    return flat


def _has_byte_sequence_enough(triage: dict, byte_seq_hex: str, min_count: int) -> bool:
    """Check if the anti_analysis_primitives supports this byte sequence.

    The triage.json stores primitive counts as `_ge_200` (or similar) flags.
    We map the byte sequence to a primitive name and check the flag. If the
    primitive is exactly known (VMCALL etc.) we read the count directly.

    v0.4.0: flattens the nested IL2CPP {launcher_*, GameAssembly_dll}.{primitive}
    shape so this function works for both native PE and IL2CPP triages.
    """
    primitives = _flatten_primitives(triage.get("anti_analysis_primitives", {}) or {})
    seq = byte_seq_hex.replace(" ", "").upper()
    name_map = {
        "0F31": "RDTSC",
        "0FA2": "CPUID",
        "0F01C1": "VMCALL",
        "F30F01C4": "VMXON",
        "CD2D": "INT_2D",
        "CC": "INT_3",
        "0F08": "INVD",
    }
    name = name_map.get(seq)
    if not name:
        return False
    flag = f"{name}_count_ge_200"
    if flag in primitives and primitives[flag]:
        return True
    raw = primitives.get(name)
    if isinstance(raw, int) and raw >= min_count:
        return True
    return False


def _evaluate_entry(entry: dict, triage: dict, *, yara_matched_ids: set[str] | None = None) -> dict[str, Any]:
    """Evaluate a single catalog entry against the triage data + YARA scan results.

    Args:
        entry: catalog entry dict (with defender.detection_signatures[])
        triage: triage JSON dict (with anti_analysis_primitives, section_table)
        yara_matched_ids: v0.6.0 — set of catalog entry IDs that matched
            the YARA scan of the target binary. If an entry's id is in this
            set, string_match and regex signatures are counted as matched.

    Returns:
        {
          "matched": bool,
          "confidence": float (0.0-1.0),
          "matched_signatures": [list of {type, value, confidence, evidence}],
          "false_positive_risks": [list of strings],
        }
    """
    sections = _parse_section_table(triage.get("section_table", ""))
    signatures = entry["defender"]["detection_signatures"]
    matched = []
    total_confidence = 0.0
    for sig in signatures:
        stype = sig.get("type")
        sval = sig.get("value", "")
        sconf = float(sig.get("confidence", 0.5))
        if stype == "structural" and "section_set_intersects" in sval:
            if _has_section_set_intersection(sections, sval):
                # collect which candidate sections actually matched
                m = re.search(r"\[([^\]]+)\]", sval)
                if m:
                    cands = [c.strip().strip("'\"") for c in m.group(1).split(",")]
                    matched_sections = [s for s in sections if s in cands]
                else:
                    matched_sections = []
                matched.append({
                    "type": stype, "value": sval, "confidence": sconf,
                    "evidence": {"matched_sections": matched_sections},
                })
                total_confidence += sconf
        elif stype == "byte_sequence":
            min_count = sig.get("min_count", 1)
            if _has_byte_sequence_enough(triage, sval, min_count):
                prim_name = {
                    "0F 31": "RDTSC", "0F A2": "CPUID",
                    "0F 01 C1": "VMCALL", "F3 0F 01 C4": "VMXON",
                    "CD 2D": "INT_2D", "CC": "INT_3", "0F 08": "INVD",
                }.get(sval.strip(), sval)
                primitives = triage.get("anti_analysis_primitives", {}) or {}
                raw = primitives.get(prim_name)
                flag = primitives.get(f"{prim_name}_count_ge_200")
                evidence = {
                    "primitive": prim_name,
                    "raw_count": raw,
                    "ge_200_flag": flag,
                    "min_required": min_count,
                }
                matched.append({
                    "type": stype, "value": sval, "confidence": sconf, "evidence": evidence,
                })
                total_confidence += sconf
        elif stype in ("string_match", "regex"):
            # v0.6.0: if the YARA scan already matched the rule for this
            # entry, count the string_match/regex signature as matched.
            # This avoids needing to read 500MB binaries for string search
            # at catalog-match time — the YARA rules already do this.
            if yara_matched_ids and entry["id"] in yara_matched_ids:
                matched.append({
                    "type": stype, "value": sval, "confidence": sconf,
                    "evidence": {"matched_via": "yara_scan", "entry_id": entry["id"]},
                })
                total_confidence += sconf

    return {
        "matched": bool(matched),
        "confidence": min(1.0, total_confidence),
        "matched_signatures": matched,
        "false_positive_risks": entry["defender"].get("false_positive_risks", []),
    }


# ── YARA scan helper (v0.6.0) ───────────────────────────────────────────

# Process-global cache for compiled YARA rules (compile once, match many).
_YARA_RULES_CACHE: dict[str, Any] = {}


def _run_yara_scan(target_path: str, yara_rules_path: str = "") -> set[str]:
    """Compile YARA rules + scan the target binary, returning matched entry IDs.

    Compiles techniques.yar and (if present) target-fingerprints.yar,
    then runs `rules.match(target_path)`. Returns the set of `meta.id`
    values from all matched rules.

    Gracefully returns an empty set if:
      - yara-python is not installed
      - YARA rules file does not exist
      - Target file does not exist
      - Any YARA error occurs

    The compiled rules are cached per-process (keyed by the rules file
    path + mtime) so repeated calls to match_catalog() don't recompile.
    """
    try:
        import yara as _yara
    except ImportError:
        return set()

    if not target_path or not Path(target_path).is_file():
        return set()

    plugin_root = Path(__file__).resolve().parent.parent.parent.parent.parent
    rules_files = []
    if yara_rules_path and Path(yara_rules_path).is_file():
        rules_files.append(yara_rules_path)
    techniques_yar = plugin_root / "data" / "yara" / "techniques.yar"
    if techniques_yar.is_file() and str(techniques_yar) not in rules_files:
        rules_files.append(str(techniques_yar))
    fingerprints_yar = plugin_root / "data" / "yara" / "target-fingerprints.yar"
    if fingerprints_yar.is_file() and str(fingerprints_yar) not in rules_files:
        rules_files.append(str(fingerprints_yar))

    if not rules_files:
        return set()

    # Cache key: file paths + mtimes (invalidates when files change)
    cache_key_parts = []
    for rf in rules_files:
        try:
            cache_key_parts.append(f"{rf}:{Path(rf).stat().st_mtime_ns}")
        except OSError:
            cache_key_parts.append(f"{rf}:0")
    cache_key = "|".join(cache_key_parts)

    if cache_key not in _YARA_RULES_CACHE:
        # Compile each YARA file independently. techniques.yar may fail
        # if the PE module is not available (rules with pe.sections[]);
        # target-fingerprints.yar should always succeed. Merge results
        # from all that succeed.
        compiled_list = []
        for rf in rules_files:
            try:
                compiled = _yara.compile(filepath=rf)
                compiled_list.append(compiled)
            except Exception as e:
                # techniques.yar uses pe module; if PE isn't available,
                # try extracting individual non-PE rules from the file.
                # As a fallback, compile the raw source with the pe
                # identifiers commented out (approximate heuristic).
                logger.debug("YARA compile failed for %s: %s", rf, e)
                if "pe" in str(e).lower() and rf.endswith("techniques.yar"):
                    # Try to extract rules that don't use pe module
                    try:
                        compiled = _try_compile_non_pe_rules(rf, _yara)
                        if compiled:
                            compiled_list.append(compiled)
                    except Exception:
                        pass
        if compiled_list:
            # Merge: the cache stores a list; match() iterates all
            _YARA_RULES_CACHE[cache_key] = compiled_list
        else:
            _YARA_RULES_CACHE[cache_key] = []

    compiled_list = _YARA_RULES_CACHE[cache_key]
    if not compiled_list:
        return set()

    # Match against all compiled rule sets
    matched_ids: set[str] = set()
    for compiled in compiled_list:
        try:
            matches = compiled.match(target_path)
            for m in matches:
                rule_id = m.meta.get("id")
                if rule_id:
                    matched_ids.add(rule_id)
        except Exception as e:
            logger.debug("YARA match failed: %s", e)

    return matched_ids


def _try_compile_non_pe_rules(yara_file: str, yara_module) -> Any:
    """Try to extract rules that don't use the PE module from a YARA file.

    If techniques.yar fails to compile because the PE module isn't
    available, this function extracts individual rules and tries to
    compile each one separately. Rules with pe.* in their condition
    are skipped (they require the PE module at runtime).
    """
    content = Path(yara_file).read_text()
    # Find each rule block
    rule_pattern = re.compile(r"^(rule \w+ \{.*?\n\})\s*$", re.MULTILINE | re.DOTALL)
    good_rules = []
    for m in rule_pattern.finditer(content):
        rule_text = m.group(1)
        # Skip rules that use pe module
        if re.search(r"\bpe\.", rule_text):
            continue
        try:
            yara_module.compile(source=rule_text)
            good_rules.append(rule_text)
        except Exception:
            continue
    if good_rules:
        combined = "\n\n".join(good_rules) + "\n"
        return yara_module.compile(source=combined)
    return None


def _target_key_from_path(target: str) -> str:
    """Infer a per-binary key from a target path.

    Used to look up a pre-computed triage.json from
    RE-AI/See the RE-AI output directory.
    """
    p = Path(target).resolve()
    name = p.name.lower()
    stem = p.stem.lower()
    candidates = {
        "007firstlight.exe": "007fl",
        "fm.exe": "fm26",
        "hello kitty.exe": "hkia",
        "lost in random.exe": "lir",
        "p3r.exe": "p3r",
        "crimsondesert.exe": "cd",
        "warhammer3.exe": "tww3",
        "f1_25.exe": "f1_25",  # v0.5.0: F1 25 (InsaneRamZes)
        "bge.exe": "bge",  # v0.6.0: Beyond Good and Evil 20th AE
        "borderlands4.exe": "borderlands4",  # v0.6.0: Borderlands 4
        "thelostcrown.exe": "thelostcrown",  # v0.6.0: POP The Lost Crown
    }
    for k, v in candidates.items():
        if k in name or k == stem:
            return v
    return p.parent.name.lower().replace(" ", "-")


@mcp.tool()
def match_catalog(
    target: str,
    intent: MatchIntent = "both",
    triage_json_path: str | None = None,
    min_confidence: float = 0.0,
    main_binary: str | None = None,
) -> dict:
    """Match a target binary against the RE-BREAKER technique catalog.

    v0.3.0: loads data/catalog.json (55 entries) + data/yara/techniques.yar
    (55 rules), evaluates each catalog entry's defender-side detection_signatures[]
    against the target's triage JSON. Returns ranked matches with defender-side
    confidence + offender-side playbook references.

    v0.3.0 additions:
      - `main_binary` arg: for Unity IL2CPP launchers, pass the path to
        GameAssembly.dll so the catalog match runs against the .dll's triage
        (which has the encrypted-VM section set + the anti-debug primitives),
        not the launcher's triage. Closes G1 — 3 of 7 targets (FM26, HKIA,
        LIR) returned 0 matches in v0.2.0 because the launcher triage is
        ~660KB and the heavy lifting is in `GameAssembly.dll` (50-500MB).
      - Auto-detect: if the target is a Unity IL2CPP launcher (has
        `GameAssembly.dll` in the same dir) and `main_binary` is not
        provided, auto-detect and use the .dll as the main binary.

    Args:
        target: path to the binary (launcher or main binary)
        intent: what to return — defender, offender, or both (default: both)
        triage_json_path: path to a pre-computed triage JSON
        min_confidence: drop matches below this confidence (0.0-1.0, default: 0.0)
        main_binary: path to the main analysis target (e.g. GameAssembly.dll)

    Returns:
        {
          "status": "ok" | "error",
          "server": "re-catalog-match",
          "version": __version__,
          "target": target,
          "main_binary": <resolved main binary path>,
          "main_binary_resolved_via": "explicit" | "auto-detect" | "target",
          "triage_json_path": "<path>",
          "matches": [...],
        }
    """
    catalog_path = os.environ.get("RE_BREAKER_CATALOG_PATH", "")
    yara_rules_path = os.environ.get("RE_BREAKER_YARA_RULES_PATH", "")

    if not catalog_path:
        return {
            "status": "error",
            "error": "RE_BREAKER_CATALOG_PATH env var is not set",
            "server": "re-catalog-match",
            "version": __version__,
        }

    try:
        catalog = _load_catalog(catalog_path)
    except FileNotFoundError as e:
        return {
            "status": "error",
            "error": str(e),
            "server": "re-catalog-match",
            "version": __version__,
        }

    # v0.3.0: resolve main_binary (auto-detect for Unity IL2CPP)
    main_binary_path, main_binary_resolved_via = _resolve_main_binary(target, main_binary)

    if triage_json_path:
        triage_path = Path(triage_json_path)
    else:
        # v0.4.0: route through the shared triage loader (RE-BREAKER self-contained).
        target_key = _target_key_from_path(main_binary_path)
        from re_breaker.triage import load_triage as _shared_load_triage
        try:
            triage = _shared_load_triage(main_binary_path)
        except FileNotFoundError as e:
            return {
                "status": "error",
                "error": f"no triage.json found for target_key={target_key}: {e}",
                "hint": "pass triage_json_path=... to a pre-computed triage JSON, or set RE_BREAKER_AUTO_TRIAGE=1 to run re-triage on the fly",
                "server": "re-catalog-match",
                "version": __version__,
                "target": target,
                "main_binary": main_binary_path,
                "main_binary_resolved_via": main_binary_resolved_via,
                "target_key": target_key,
            }

    # Load triage JSON if not already loaded via the implicit path
    if triage_json_path:
        if not triage_path.exists():
            return {
                "status": "error",
                "error": f"triage.json not found at {triage_path}",
                "server": "re-catalog-match",
                "version": __version__,
            }
        try:
            triage = json.loads(triage_path.read_text())
        except json.JSONDecodeError as e:
            return {
                "status": "error",
                "error": f"triage.json is not valid JSON: {e}",
                "server": "re-catalog-match",
                "version": __version__,
            }

    # v0.6.0: run YARA scan against the target binary (if installed)
    yara_matched_ids = _run_yara_scan(main_binary_path, yara_rules_path)

    matches = []
    for entry in catalog["entries"]:
        evaluation = _evaluate_entry(entry, triage, yara_matched_ids=yara_matched_ids)
        if not evaluation["matched"]:
            continue
        if evaluation["confidence"] < min_confidence:
            continue

        match = {
            "id": entry["id"],
            "name": entry["name"],
            "family": entry["family"],
            "severity": entry["severity"],
            "aliases": entry.get("aliases", []),
            "defender": {
                "confidence": round(evaluation["confidence"], 3),
                "matched_signatures": evaluation["matched_signatures"],
                "false_positive_risks": evaluation["false_positive_risks"],
                "see_also": entry["defender"].get("see_also", []),
            },
        }
        if intent in ("offender", "both"):
            match["offender"] = {
                "summary": entry["offender"]["summary"],
                "tools": entry["offender"].get("tools", []),
                "playbook": entry["offender"].get("playbook", ""),
                "expected_runtime_minutes": entry["offender"].get("expected_runtime_minutes", 0),
                "skill_complexity": entry["offender"].get("skill_complexity", "unknown"),
                "success_probability": entry["offender"].get("success_probability", 0.0),
                "limitations": entry["offender"].get("limitations", []),
            }
        matches.append(match)

    matches.sort(key=lambda m: m["defender"]["confidence"], reverse=True)

    return {
        "status": "ok",
        "server": "re-catalog-match",
        "version": __version__,
        "target": target,
        "main_binary": main_binary_path,
        "main_binary_resolved_via": main_binary_resolved_via,
        "triage_json_path": str(triage_path),
        "intent": intent,
        "catalog_entries_evaluated": len(catalog["entries"]),
        "matches_returned": len(matches),
        "min_confidence": min_confidence,
        "yara_rules_path": yara_rules_path,
        "yara_scan_result": {
            "matched_entry_ids": sorted(yara_matched_ids),
        },
        "matches": matches,
    }


def _resolve_main_binary(target: str, main_binary: str | None) -> tuple[str, str]:
    """v0.3.0: resolve the actual analysis target.

    1. If `main_binary` is provided, use it as-is.
    2. Else if the target is a Unity IL2CPP launcher (has GameAssembly.dll
       in the same dir), auto-detect and use the .dll.
    3. Else: use the target as-is.

    Returns (main_binary_path, resolution_strategy) where resolution_strategy
    is "explicit" | "auto-detect" | "target".
    """
    if main_binary:
        return main_binary, "explicit"
    # auto-detect Unity IL2CPP
    p = Path(target).resolve()
    if p.suffix.lower() == ".exe" and p.parent.is_dir():
        ga = p.parent / "GameAssembly.dll"
        if ga.exists():
            return str(ga), "auto-detect"
    return target, "target"


# ── Entrypoint ──────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
