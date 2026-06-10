"""MCP server entry point for re-yara.

Exposes the YARA pattern-matching engine to Claude Code via the
Model Context Protocol stdio transport. The server is
intentionally **rule-agnostic**: it does not ship any YARA rules.
The analyst points the server at a directory of user-authored
``*.yar`` files and the server compiles + runs them.

All YARA rule categories — encrypted-VM bytecode interpreter
dispatchers, MBA-obfuscated arithmetic, legacy disc-based
protection handshakes, anti-debug byte sequences — are
describable in this engine. Naming a specific commercial product
in a YARA rule is a user decision; the server does not pre-bake
that attribution.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("re-yara")

logger = logging.getLogger("re_yara")
logger.setLevel(logging.INFO)


# Count rules in a .yar/.yara source file by matching the
# `rule <name>` keyword. YARA 4.4+ removed the introspection API
# (compiled.rules) so we count from the source instead — it's
# the cross-version-stable approach.
_RULE_HEAD_RE = re.compile(r"(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*)")


# ── Health ──────────────────────────────────────────────────────────────


@mcp.tool()
def check_yara() -> dict:
    """Return YARA version + dependency availability.

    Always returns ``status: OK`` when ``yara-python`` (which wraps
    the C library) is importable. When the wrapper is missing, the
    status is ``WARN`` and the install hint points at ``pip install
    yara-python`` plus the system ``yara`` / ``libyara-dev``
    package.
    """
    import importlib.util

    yara_spec = importlib.util.find_spec("yara")
    if yara_spec is None:
        return {
            "server": "re-yara",
            "version": "0.1.0",
            "status": "WARN",
            "yara_python_available": False,
            "yara_version": None,
            "install_hint": (
                "pip install yara-python; also install the system "
                "yara / libyara-dev package (e.g. apt-get install yara libyara-dev)"
            ),
        }
    import yara  # type: ignore[import-untyped]

    version = getattr(yara, "__version__", None) or "imported"
    return {
        "server": "re-yara",
        "version": "0.1.0",
        "status": "OK",
        "yara_python_available": True,
        "yara_version": version,
    }


# ── Compilation ─────────────────────────────────────────────────────────


@mcp.tool()
def compile_rules(rules_dir: str) -> dict:
    """Compile every ``*.yar`` / ``*.yara`` file under *rules_dir*.

    Args:
        rules_dir: path to a directory containing YARA rule files.
            Sub-directories are walked recursively; the namespace
            passed to ``yara.compile`` is the file's relative path
            (so two rules with the same short name in different
            sub-directories do not collide).

    Returns::

        {
          "rules_dir": "...",
          "rule_count": N,
          "namespaces": ["...", ...],
          "files_compiled": [...],
          "errors": [{"file": "...", "error": "..."}, ...]
        }

    On any compile error, the offending file is recorded in
    ``errors``; other files are still attempted. ``rule_count`` is
    the number of rules present in the *successfully compiled*
    namespaces — a partial compile still returns 200 with a
    non-empty ``errors`` list.
    """
    import yara  # type: ignore[import-untyped]

    root = Path(rules_dir)
    if not root.is_dir():
        return {
            "rules_dir": rules_dir,
            "status": "ERROR",
            "error": f"rules_dir is not a directory: {rules_dir}",
        }

    files: list[Path] = sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in {".yar", ".yara"}
    )
    if not files:
        return {
            "rules_dir": rules_dir,
            "status": "WARN",
            "rule_count": 0,
            "namespaces": [],
            "files_compiled": [],
            "errors": [],
            "message": "no *.yar or *.yara files found under rules_dir",
        }

    filepaths: dict[str, str] = {}
    for f in files:
        # Use the relative path under rules_dir as the namespace.
        # The yara.compile(filepaths=...) API takes a dict of
        # {namespace: filepath}. We use the file's stem as the
        # default namespace to keep the on-the-wire rule names
        # readable; collisions are still resolved because YARA
        # namespaces are independent scopes.
        ns = str(f.relative_to(root).with_suffix("")).replace("\\", "/")
        filepaths[ns] = str(f.resolve())

    errors: list[dict] = []
    files_compiled: list[str] = []
    rule_count = 0
    compiled_obj: object | None = None

    try:
        compiled_obj = yara.compile(filepaths=filepaths)
    except yara.SyntaxError as exc:  # type: ignore[attr-defined]
        # One or more files had a syntax error. The yara-python
        # error message names the file when known; surface what we
        # can. Individual file fallback below gives a per-file
        # breakdown.
        errors.append({"file": "<batch>", "error": str(exc)})
    except yara.Error as exc:  # type: ignore[attr-defined]
        # Fall back to per-file compile to localise the error.
        compiled_obj = None

    if compiled_obj is None:
        # Per-file fallback so a single bad rule doesn't kill the
        # whole set. The successful files get concatenated into a
        # synthetic namespace and recompiled.
        ok_sources: list[str] = []
        for f in files:
            try:
                yara.compile(filepath=str(f))
                ok_sources.append(str(f.resolve()))
            except yara.SyntaxError as exc:  # type: ignore[attr-defined]
                errors.append({"file": str(f.relative_to(root)), "error": str(exc)})
            except yara.Error as exc:  # type: ignore[attr-defined]
                errors.append({"file": str(f.relative_to(root)), "error": str(exc)})
        if not ok_sources:
            return {
                "rules_dir": rules_dir,
                "status": "ERROR",
                "rule_count": 0,
                "files_compiled": [],
                "errors": errors,
            }
        # Build a per-file namespace dict for the survivors.
        filepaths = {
            str(Path(p).relative_to(root).with_suffix("")).replace("\\", "/"): p
            for p in ok_sources
        }
        try:
            compiled_obj = yara.compile(filepaths=filepaths)
            files_compiled = [
                str(Path(p).relative_to(root)) for p in ok_sources
            ]
        except (yara.SyntaxError, yara.Error) as exc:  # type: ignore[attr-defined]
            errors.append({"file": "<rescue>", "error": str(exc)})
            return {
                "rules_dir": rules_dir,
                "status": "ERROR",
                "rule_count": 0,
                "files_compiled": files_compiled,
                "errors": errors,
            }
    else:
        files_compiled = [str(f.relative_to(root)) for f in files]

    # Count rules in the compiled object. YARA 4.4+ removed
    # the ``compiled.rules`` introspection API, so we count from
    # the source files: a per-file regex on ``^rule <name>``
    # gives an accurate count for any 4.x yara-python.
    if compiled_obj is not None:
        rule_count = 0
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rule_count += len(_RULE_HEAD_RE.findall(text))
    else:
        rule_count = 0

    namespaces = sorted(filepaths.keys())
    return {
        "rules_dir": rules_dir,
        "status": "OK" if not errors else "WARN",
        "rule_count": rule_count,
        "namespaces": namespaces,
        "files_compiled": files_compiled,
        "errors": errors,
    }


# ── Scanning ────────────────────────────────────────────────────────────


def _ensure_compiled(rules_dir: str) -> tuple[object | None, dict]:
    """Compile the rules directory and return (compiled_obj, compile_meta).

    Used by both scan tools so we don't have to duplicate the
    error-handling branch. On any compile failure, returns
    ``(None, meta)`` where ``meta`` is a dict suitable for direct
    return to the MCP caller.
    """
    meta = compile_rules(rules_dir)
    if meta.get("status") == "ERROR" or meta.get("rule_count", 0) == 0:
        return None, meta
    # Recompile here so we hand the scan tool the live yara.Rules
    # object. The compile_rules tool above does the same work but
    # discards the compiled object after counting rules.
    import yara  # type: ignore[import-untyped]
    root = Path(rules_dir)
    files = sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in {".yar", ".yara"}
    )
    filepaths = {
        str(p.relative_to(root).with_suffix("")).replace("\\", "/"): str(p.resolve())
        for p in files
    }
    compiled = yara.compile(filepaths=filepaths)
    return compiled, meta


@mcp.tool()
def scan_binary(path: str, rules_dir: str) -> dict:
    """Run a compiled ruleset against a single file.

    Args:
        path: file to scan
        rules_dir: directory of ``*.yar`` / ``*.yara`` rule files
            (compiled on every call — rules are cheap to re-parse
            and YARA's compile cache isn't exposed through the
            Python wrapper)

    Returns::

        {
          "path": "...",
          "rules_dir": "...",
          "match_count": N,
          "matches": [
            {"rule": "...", "namespace": "...",
             "tags": [...], "meta": {...}, "strings": [...],
             "rule_length": N},
            ...
          ],
          "compile_meta": {...}   # from compile_rules()
        }
    """
    target = Path(path)
    if not target.is_file():
        return {
            "path": path,
            "rules_dir": rules_dir,
            "status": "ERROR",
            "error": f"path is not a file: {path}",
        }
    compiled, meta = _ensure_compiled(rules_dir)
    if compiled is None:
        return {
            "path": path,
            "rules_dir": rules_dir,
            "status": "ERROR",
            "error": "rule compilation failed",
            "compile_meta": meta,
        }
    try:
        matches = compiled.match(filepath=str(target))  # type: ignore[union-attr]
    except Exception as exc:  # noqa: BLE001
        return {
            "path": path,
            "rules_dir": rules_dir,
            "status": "ERROR",
            "error": f"scan failed: {exc}",
            "compile_meta": meta,
        }
    out_matches = []
    for m in matches:
        # m.rule, m.namespace, m.tags, m.meta, m.strings, m.rule_length
        # In yara-python 4.4+ ``m.strings`` is a list of
        # StringMatch objects with ``identifier`` + ``instances``.
        # Each instance has ``offset`` + ``matched_length``.
        string_hits: list[dict] = []
        for s in (getattr(m, "strings", []) or []):
            for inst in (getattr(s, "instances", []) or []):
                string_hits.append({
                    "identifier": getattr(s, "identifier", ""),
                    "offset": int(getattr(inst, "offset", 0)),
                    "length": int(getattr(inst, "matched_length", 0)),
                    "is_xor": bool(getattr(s, "is_xor", False)),
                })
        out_matches.append({
            "rule": getattr(m, "rule", ""),
            "namespace": getattr(m, "namespace", ""),
            "tags": list(getattr(m, "tags", []) or []),
            "meta": dict(getattr(m, "meta", {}) or {}),
            "strings": string_hits,
        })
    return {
        "path": path,
        "rules_dir": rules_dir,
        "status": "OK",
        "match_count": len(out_matches),
        "matches": out_matches,
        "compile_meta": {k: meta.get(k) for k in ("rule_count", "namespaces")},
    }


@mcp.tool()
def scan_directory(path: str, rules_dir: str) -> dict:
    """Walk a directory and run the compiled ruleset against every file.

    Args:
        path: directory to walk (recursive; follows symlinks)
        rules_dir: directory of ``*.yar`` / ``*.yara`` rule files

    Returns::

        {
          "path": "...",
          "rules_dir": "...",
          "files_scanned": N,
          "files_matched": N,
          "results": [
            {"path": "...", "match_count": N, "matched_rules": [...]},
            ...
          ]
        }

    Only files with at least one match appear in ``results``;
    the rest are summarised by ``files_scanned``. Symbolic links
    are followed; the walker skips FIFOs, sockets, and other
    non-regular files to avoid blocking on a 0-byte pipe.
    """
    import os

    root = Path(path)
    if not root.is_dir():
        return {
            "path": path,
            "rules_dir": rules_dir,
            "status": "ERROR",
            "error": f"path is not a directory: {path}",
        }
    compiled, meta = _ensure_compiled(rules_dir)
    if compiled is None:
        return {
            "path": path,
            "rules_dir": rules_dir,
            "status": "ERROR",
            "error": "rule compilation failed",
            "compile_meta": meta,
        }
    files_scanned = 0
    results: list[dict] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=True):
        for name in filenames:
            full = Path(dirpath) / name
            try:
                if not full.is_file():
                    continue
            except OSError:
                continue
            try:
                matches = compiled.match(filepath=str(full))  # type: ignore[union-attr]
            except (PermissionError, OSError):
                continue
            except Exception:  # noqa: BLE001
                # YARA's scanner is strict about format-magic on
                # some inputs (e.g. a 0-byte file with no signature
                # raises). Skip rather than fail the whole walk.
                continue
            files_scanned += 1
            if not matches:
                continue
            results.append({
                "path": str(full),
                "match_count": len(matches),
                "matched_rules": [
                    {
                        "rule": getattr(m, "rule", ""),
                        "namespace": getattr(m, "namespace", ""),
                        "tags": list(getattr(m, "tags", []) or []),
                    }
                    for m in matches
                ],
            })
    return {
        "path": path,
        "rules_dir": rules_dir,
        "status": "OK",
        "files_scanned": files_scanned,
        "files_matched": len(results),
        "results": results,
        "compile_meta": {k: meta.get(k) for k in ("rule_count", "namespaces")},
    }


# ── Entrypoint ─────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio (the standard Claude Code transport)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
