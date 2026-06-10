"""wire_re — per-binary wire-format extraction utility (Phase 1 RE).

The 4 new entitlement layers (Atlus, Sunblink, PA internal protocol, EA Origin)
need their wire formats reverse-engineered from the live binaries. This module
provides a small utility surface for that RE work:

1. `extract_dll_exports(launcher_dir)` — list the exports of every DLL in the
   launcher's directory; the SDK DLLs (e.g. `hermessdkcorewrapper_release.dll`
   for PA, `Galaxy64.dll` for Origin) reveal the function name surface.
2. `extract_url_patterns(launcher_dir)` — grep the DLLs for URL patterns; the
   entitlement endpoint hostnames appear as ASCII strings in the binary.
3. `extract_json_keys(launcher_dir)` — grep for JSON-shaped request/response
   keys; the entitlement layer's "user record" / "entitlement list" shapes
   appear as UTF-8 strings.
4. `extract_pipe_names(launcher_dir)` — grep for named-pipe strings; the
   Origin / Steamworks layers use named-pipes for in-proc token exchange.

These are not full RE; they're reconnaissance primitives that produce a
`wire_sigs/<target>.json` per the plan's "wire signatures" deliverable.

Per the user's direction, the actual RE of the 4 new layers is out of scope
for the plan's "scaffolded" Phase 1 — these utilities are the foundation for
that work. The Atlus / Sunblink / PA / Origin emulators in v0.2.0 return
`{"status":"stub"}` from unknown routes; the real wire formats are a future
RE effort.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

log = logging.getLogger("re-entitlement-bypass.wire_re")


# Common URL patterns in entitlement SDKs (Epic / IOI / SEGA / Atlus / Sunblink
# / PA / Origin all use https URLs to a small set of well-known hosts)
URL_PATTERNS = [
    re.compile(rb"https?://([a-zA-Z0-9\-\.]+\.(?:epicgames\.io|epicgames\.dev|ioi\.dk|atlus\.co|sega\.com|sunblink\.com|pearlabyss\.com|origin\.com|ea\.com)[/a-zA-Z0-9\-\.]*)"),
    re.compile(rb"\b([a-zA-Z0-9\-]+\.epicgames\.[a-z]+)\b"),
    re.compile(rb"\b([a-zA-Z0-9\-]+\.ioi\.dk)\b"),
    re.compile(rb"\b([a-zA-Z0-9\-]+\.atlus\.[a-z]+)\b"),
    re.compile(rb"\b([a-zA-Z0-9\-]+\.sega\.[a-z]+)\b"),
    re.compile(rb"\b([a-zA-Z0-9\-]+\.sunblink\.[a-z]+)\b"),
    re.compile(rb"\b([a-zA-Z0-9\-]+\.pearlabyss\.[a-z]+)\b"),
    re.compile(rb"\b([a-zA-Z0-9\-]+\.origin\.[a-z]+)\b"),
    re.compile(rb"\b([a-zA-Z0-9\-]+\.ea\.[a-z]+)\b"),
]

# Common JSON keys in entitlement responses
JSON_KEY_PATTERNS = [
    re.compile(rb'"(access_token|refresh_token|id_token|expires_in|entitlement_id|product_id|user_id|account_id|external_account_id|grant_type|external_auth_type|external_auth_token|sandbox_id|client_id|client_secret|display_name|preferred_language|country|namespace|id|product_user_id|continuation_token|item_id|transaction_id|owned|redeemed|consumable|catalog_version|entitlement_name|entitlement_ids|external_accounts)"'),
]

# Named-pipe patterns (Steamworks, Origin, IOI Account all use named pipes)
PIPE_PATTERNS = [
    re.compile(rb"\\\\\.\\pipe\\([a-zA-Z0-9_\-]+)"),
    re.compile(rb'"\\\\\\\\\.\\\\pipe\\\\([a-zA-Z0-9_\-]+)"'),
]


def extract_url_patterns(launcher_dir: Path, max_results: int = 50) -> list[str]:
    """Grep every binary in `launcher_dir` for URL patterns.

    Returns up to `max_results` unique URLs found across all binaries.
    """
    if not launcher_dir.exists():
        return []

    urls: set[str] = set()
    for binary in launcher_dir.rglob("*"):
        if not binary.is_file():
            continue
        if binary.suffix.lower() not in (".dll", ".exe", ".so", ".dylib"):
            continue
        if binary.stat().st_size > 200_000_000:  # skip >200MB binaries
            continue
        try:
            data = binary.read_bytes()
        except (PermissionError, OSError) as e:
            log.debug("skip %s: %s", binary, e)
            continue
        for pat in URL_PATTERNS:
            for m in pat.findall(data):
                try:
                    urls.add(m.decode("utf-8", errors="replace"))
                except UnicodeDecodeError:
                    pass
                if len(urls) >= max_results:
                    return sorted(urls)[:max_results]
    return sorted(urls)[:max_results]


def extract_json_keys(launcher_dir: Path, max_results: int = 100) -> list[str]:
    """Grep every binary in `launcher_dir` for JSON-shaped keys.

    Returns up to `max_results` unique keys found across all binaries.
    """
    if not launcher_dir.exists():
        return []

    keys: set[str] = set()
    for binary in launcher_dir.rglob("*"):
        if not binary.is_file():
            continue
        if binary.suffix.lower() not in (".dll", ".exe", ".so", ".dylib"):
            continue
        if binary.stat().st_size > 200_000_000:
            continue
        try:
            data = binary.read_bytes()
        except (PermissionError, OSError) as e:
            log.debug("skip %s: %s", binary, e)
            continue
        for pat in JSON_KEY_PATTERNS:
            for m in pat.findall(data):
                try:
                    keys.add(m.decode("utf-8", errors="replace"))
                except UnicodeDecodeError:
                    pass
                if len(keys) >= max_results:
                    return sorted(keys)[:max_results]
    return sorted(keys)[:max_results]


def extract_pipe_names(launcher_dir: Path, max_results: int = 20) -> list[str]:
    """Grep every binary in `launcher_dir` for named-pipe strings.

    Returns up to `max_results` unique pipe names found.
    """
    if not launcher_dir.exists():
        return []

    pipes: set[str] = set()
    for binary in launcher_dir.rglob("*"):
        if not binary.is_file():
            continue
        if binary.suffix.lower() not in (".dll", ".exe", ".so", ".dylib"):
            continue
        if binary.stat().st_size > 200_000_000:
            continue
        try:
            data = binary.read_bytes()
        except (PermissionError, OSError) as e:
            log.debug("skip %s: %s", binary, e)
            continue
        for pat in PIPE_PATTERNS:
            for m in pat.findall(data):
                try:
                    pipes.add(m.decode("utf-8", errors="replace"))
                except UnicodeDecodeError:
                    pass
                if len(pipes) >= max_results:
                    return sorted(pipes)[:max_results]
    return sorted(pipes)[:max_results]


def write_wire_sig(target: str, output_dir: Path, urls: list[str], json_keys: list[str], pipes: list[str], denuvo_check: Optional[dict] = None) -> Path:
    """Write a wire_sigs/<target>.json with the extracted signatures.

    Args:
        target: target key (e.g. "fm26", "p3r")
        output_dir: the wire_sigs dir (typically servers/re-entitlement-bypass/data/wire_sigs/)
        urls: list of URLs found in the binary
        json_keys: list of JSON keys found
        pipes: list of named-pipe names found
        denuvo_check: optional dict with {verdict: "present"|"absent", evidence: "..."}
    Returns the path of the written file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    out = {
        "target": target,
        "urls": urls,
        "json_keys": json_keys,
        "pipes": pipes,
        "denuvo_check": denuvo_check or {"verdict": "pending", "evidence": "Not yet checked"},
    }
    path = output_dir / f"{target}.json"
    path.write_text(json.dumps(out, indent=2))
    log.info("Wrote %s with %d urls, %d json_keys, %d pipes", path, len(urls), len(json_keys), len(pipes))
    return path
