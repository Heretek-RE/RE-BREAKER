"""Subprocess wrapper around the capa CLI.

capa is Mandiant's capability detector for PE/ELF/.NET/shellcode.
It maps findings to MITRE ATT&CK and the Malware Behavior Catalog (MBC).
This module is a thin wrapper that runs `capa --json` and parses
the structured output.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def get_capa_path() -> str:
    return os.environ.get("CAPA_PATH") or shutil.which("capa") or "capa"


def _resolve_default_rules_path() -> str:
    """Return the bundled capa rules path, or "" if not found.

    Cycle 2 fix (2026-06-06, RE-AI run r02): prefer the standalone
    ``data/capa-rules/`` directory (cloned by install.sh from the
    official Mandiant rules repo) over the ``capa.rules`` Python
    module path. The site-packages path contains the Python source
    of ``capa.rules`` (e.g. ``__init__.py``, ``cache.py``,
    ``__pycache__/``), and capa 9.4.0's stricter file-type check
    treats those as non-.yml rules and rejects the whole path with
    ``no rules selected``. The standalone ``data/capa-rules/`` dir
    contains only the ``.yml`` rule files, which is what capa wants.

    The resolution order is:
      1. ``<plugin_root>/data/capa-rules/`` (cloned by install.sh) —
         the upstream-blessed rules path.
      2. The ``capa.rules`` Python module's ``__path__[0]`` — the
         venv site-packages rules dir (works on older capa versions
         that didn't strict-check the file type).
      3. The ``rules/`` sibling of the capa binary — the source-tree
         fallback for ``python -m pip install -e .`` installs.
    """
    # 1. Standalone rules dir (preferred — install.sh clones this).
    plugin_root = Path(__file__).resolve().parents[4]
    standalone = plugin_root / "data" / "capa-rules"
    # The Mandiant rules repo (https://github.com/mandiant/capa-rules)
    # is organized into category subdirs (anti-analysis/,
    # collection/, communication/, ...) with .yml files at depth 1.
    # Use rglob so we detect the dir as "has rules" regardless of
    # whether the .yml files are at the top level or in subdirs.
    if standalone.exists() and any(standalone.rglob("*.yml")):
        return str(standalone)
    # 2. The capa.rules Python module path.
    try:
        import capa.rules  # type: ignore
        rules_path = getattr(capa.rules, "__path__", None)
        if rules_path:
            return str(list(rules_path)[0])
    except Exception:  # noqa: BLE001
        pass
    # 3. rules/ sibling of the capa binary.
    capa_bin = get_capa_path()
    if capa_bin and Path(capa_bin).exists():
        sibling = Path(capa_bin).parent.parent / "rules"
        if sibling.exists():
            return str(sibling)
    return ""


def _run_capa(
    path: str,
    *,
    rules: str = "",
    fmt: str = "json",
    timeout_s: int = 900,
) -> dict[str, Any] | str:
    """Run `capa -j` (or text) on *path*.

    capa 9.x removed the ``--format`` output flag (it was repurposed for
    *input* format only and accepts values like ``pe``/``elf``/``dotnet``).
    JSON output is now selected with the boolean ``--json`` flag, and
    vverbose is the default human renderer (no flag). The old
    ``--format json`` made argparse exit 2 with "unrecognized arguments".

    Cycle 2 fix (timeout): default bumped from 300s to 900s. A 357 MB
    PE (e.g. UE4 shipping exe) routinely exceeds 300s on a single
    core. ``detect_capabilities`` auto-scales by file size to avoid
    wasting time on small inputs.

    Cycle 2 fix (rules): when the caller passes an empty rules path,
    resolve the bundled rules directory and pass it explicitly via
    --rules. Without this, capa's "default rules" lookup fails on
    installs where the rules dir is not on the default search path
    (capa 9.x on some distros).
    """
    args = [get_capa_path(), path, "-q"]
    if fmt == "json":
        args.append("--json")
    effective_rules = rules or _resolve_default_rules_path()
    if effective_rules:
        args.extend(["--rules", effective_rules])
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"capa not found on PATH (set CAPA_PATH or pip install flare-capa): {exc}"
        ) from exc
    if proc.returncode != 0:
        # capa prints a "0 rules" warning to stderr but exits 0 normally;
        # a non-zero exit is a real error.
        raise RuntimeError(f"capa failed (exit {proc.returncode}): {proc.stderr[:500]}")
    if fmt == "json":
        return json.loads(proc.stdout)
    return proc.stdout


# ── Tool implementations ────────────────────────────────────────────────


def check_capa() -> dict[str, Any]:
    """Return capa version and rules path."""
    info: dict[str, Any] = {"capa": None, "status": "OK"}
    try:
        proc = subprocess.run(
            [get_capa_path(), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            info["capa"] = (proc.stdout or "").strip()
    except Exception as exc:  # noqa: BLE001
        info["capa"] = f"NOT FOUND: {exc}"
        info["status"] = "WARN"
    # Try to find rules path
    try:
        import capa.rules  # type: ignore

        info["rules_path"] = os.path.dirname(capa.rules.__file__)
    except Exception:  # noqa: BLE001
        info["rules_path"] = "default (bundled)"
    return info


def detect_capabilities(
    path: str,
    rules: str = "",
    fmt: str = "json",
    timeout_s: int | None = None,
) -> dict[str, Any]:
    """Run capa on *path* and return the structured report.

    Args:
        path: file to analyze
        rules: optional path to a custom rules dir
        fmt: "json" (default) or "vverbose" (human-readable)
        timeout_s: optional override. If None, the runner auto-scales
            based on file size: 900s for files >= 10 MB, 300s below.

    Cycle 2 fix: the prior default of 300s timed out on every binary
    > 1 MB on this host. The auto-scale keeps small inputs fast while
    letting large inputs (a 357 MB IL2CPP target binary,
    a 506 MB IL2CPP GameAssembly.dll) complete.
    """
    if fmt not in ("json", "vverbose"):
        raise ValueError(f"fmt must be 'json' or 'vverbose', got {fmt!r}")
    if timeout_s is None:
        try:
            size_mb = os.path.getsize(path) / (1024 * 1024)
        except OSError:
            size_mb = 0
        timeout_s = 900 if size_mb >= 10 else 300
    raw = _run_capa(path, rules=rules, fmt=fmt, timeout_s=timeout_s)
    if isinstance(raw, str):
        return {"format": "vverbose", "text": raw}
    # Summarize: top-level rules by namespace, ATT&CK IDs, MBC IDs
    summary: dict[str, Any] = {
        "format": "json",
        "rules_count": 0,
        "namespaces": {},
        "attack": [],
        "mbc": [],
    }
    rules_dict = raw.get("rules", {})
    summary["rules_count"] = len(rules_dict)
    for rule_name, rule_data in rules_dict.items():
        ns = rule_data.get("namespace", "")
        summary["namespaces"][ns] = summary["namespaces"].get(ns, 0) + 1
        meta = rule_data.get("meta", {})
        for att in meta.get("attack", []):
            summary["attack"].append({
                "id": att.get("id"),
                "tactic": att.get("tactic"),
                "technique": att.get("technique"),
                "rule": rule_name,
            })
        for mbc in meta.get("mbc", []):
            summary["mbc"].append({
                "id": mbc.get("id"),
                "objective": mbc.get("objective"),
                "behavior": mbc.get("behavior"),
                "rule": rule_name,
            })
    summary["raw"] = raw
    return summary


def extract_mbc(path: str, rules: str = "") -> dict[str, Any]:
    """Return just the Malware Behavior Catalog mappings."""
    full = detect_capabilities(path, rules=rules)
    return {
        "mbc": full.get("mbc", []),
        "mbc_count": len(full.get("mbc", [])),
    }


def find_interesting(path: str, min_score: int = 3, rules: str = "") -> dict[str, Any]:
    """Filter capa's output to only the high-confidence / unique matches.

    Cycle 2 fix: the prior heuristic returned 0 hits on every binary
    because the "score" it computed (count of rules per namespace) was
    too coarse — a namespace with `>= min_score` rules was considered
    interesting, but a 3 MB binary typically has 5-20 rules in any
    given namespace, so the threshold was crossed for every namespace
    (and the filter then filtered nothing out... but in some
    configurations the loop itself short-circuited to {} because the
    namespace strings did not match the rule's namespace key).

    New heuristic: a namespace is "interesting" if it has >= min_score
    rules **AND** at least one rule in that namespace has an
    ATT&CK or MBC mapping. This filters out rule-bundles that are
    generic-detection noise (e.g. "executable" / "compiler" /
    "anti-forensic") and surfaces the high-signal detection bundles
    (e.g. "anti-debug", "communication", "credential-access",
    "exfiltration").
    """
    full = detect_capabilities(path, rules=rules)
    raw = full.get("raw", {})
    namespaces = full.get("namespaces", {})

    # Compute which namespaces have at least one ATT&CK or MBC mapping.
    ns_has_attack_or_mbc: set[str] = set()
    for rule_data in raw.get("rules", {}).values():
        meta = rule_data.get("meta", {})
        ns = rule_data.get("namespace", "")
        if meta.get("attack") or meta.get("mbc"):
            ns_has_attack_or_mbc.add(ns)

    interesting_namespaces = {
        ns: count
        for ns, count in namespaces.items()
        if count >= min_score and ns in ns_has_attack_or_mbc
    }
    filtered_rules = {
        name: data
        for name, data in raw.get("rules", {}).items()
        if data.get("namespace") in interesting_namespaces
    }
    return {
        "min_score": min_score,
        "interesting_namespaces": interesting_namespaces,
        "rule_count": len(filtered_rules),
        "rules": filtered_rules,
    }
