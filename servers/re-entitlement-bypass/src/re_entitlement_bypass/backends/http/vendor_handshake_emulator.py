"""Sunblink / EGS / XOG emulator (v0.8.0+ Wave 3 Item M Phase 2 scaffold).

Per SOW-X (Sunblink): HKIA is the target. The server-reachability dialog
is the gate (per v0.4.1.9).

v0.8.0+ (Item M) updated the endpoint structure based on the discovered
Sunblink SDK methods from Phase 1's RE work. The endpoint paths below
are best-guess based on the typical Sunblink/EGS/XOG API shape; the
exact wire format is still pending Phase 1's frida-hook captures.

Phase 2 (next 1 week): capture real HTTP request bodies via frida
hooks on the Sunblink SDK methods, then replace the SCAFFOLD routes
with real endpoints.

Phase 3 (1 week): recover the stripped global-metadata.dat via the
custom encryption scheme Sunblink uses (M4: re-hkia-metadata-decrypt).
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Callable

from ..base.http_base import EmulatorHTTPBase
from ...core.layer_base import register
from ...core.status import LayerDeployStatus

log = logging.getLogger("re-entitlement-bypass.sunblink")


# v0.8.0+ Item M: in-memory store of "entitlements" we grant.
# Real flow (post-Phase 2) will store these persistently; for the
# SCAFFOLD we keep them in a module-level dict (lost on restart, which
# is fine since the entitlement dialog re-checks on every launch).
_ENTITLEMENTS: dict[str, dict] = {}


@register
class SunblinkEmulator(EmulatorHTTPBase):
    layer = "sunblink"
    backend = "http/sunblink"
    bind = "127.0.0.1"
    port = 8446
    hosts_subdomain = [
        "api.sunblink.com",
        "auth.sunblink.com",
        "entitlement.sunblink.com",
        "hkia.sunblink.com",
        "egs.sunblink.com",
    ]

    def _routes(self) -> dict[str, Callable]:
        return {
            "/sunblink/v1/health": _route_health,
            "/sunblink/v1/auth/login": _route_login,
            "/sunblink/v1/auth/refresh": _route_refresh,
            "/sunblink/v1/entitlement/list": _route_entitlement_list,
            "/sunblink/v1/entitlement/hkia/check": _route_hkia_check,
            "/sunblink/v1/entitlement/hkia/grant": _route_hkia_grant,
            "/sunblink/v1/game/hkia/launch": _route_game_launch,
        }


def _route_health(emulator, request: dict) -> dict:
    return {
        "status": "ok",
        "service": "sunblink-emulator",
        "version": "0.2.0",
        "build": "re-breaker-0.2.0-item-m-phase-2",
        "note": (
            "v0.8.0+ Item M Phase 2 SCAFFOLD. Routes are best-guess; "
            "Phase 1's frida hooks will replace these with the real wire format."
        ),
    }


def _route_login(emulator, request: dict) -> dict:
    """v0.8.0+ Item M: stub login that returns a fake access token.

    The real Sunblink login uses a custom JWT-like format. For the
    SCAFFOLD, we just return an opaque token.
    """
    body = request.get("body", {})
    username = body.get("username", "anonymous")
    access_token = f"sunblink-scaffold-{uuid.uuid4().hex[:16]}"
    refresh_token = f"sunblink-refresh-{uuid.uuid4().hex[:16]}"
    expires_at = int(time.time()) + 3600
    return {
        "status": "ok",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "user": {"id": f"user-{username}", "username": username},
    }


def _route_refresh(emulator, request: dict) -> dict:
    return {
        "status": "ok",
        "access_token": f"sunblink-refreshed-{uuid.uuid4().hex[:16]}",
        "expires_at": int(time.time()) + 3600,
    }


def _route_entitlement_list(emulator, request: dict) -> dict:
    """List all entitlements for the bearer token."""
    return {
        "status": "ok",
        "entitlements": list(_ENTITLEMENTS.values()),
        "count": len(_ENTITLEMENTS),
    }


def _route_hkia_check(emulator, request: dict) -> dict:
    """Check if the current user has the HKIA entitlement.

    The dialog in HKIA waits for this endpoint to return 200 with
    `granted: true` before allowing play to continue. The SCAFFOLD
    always returns granted: true.
    """
    body = request.get("body", {})
    user_id = body.get("user_id", "anonymous")
    e = _ENTITLEMENTS.get(f"{user_id}:hkia")
    return {
        "status": "ok",
        "user_id": user_id,
        "entitlement": "hkia",
        "granted": e is not None,
        "expires_at": e.get("expires_at", 0) if e else 0,
    }


def _route_hkia_grant(emulator, request: dict) -> dict:
    """Grant the HKIA entitlement to the current user.

    Used by the entitlement-bypass PoC to satisfy the dialog before
    HKIA launches the main game.
    """
    body = request.get("body", {})
    user_id = body.get("user_id", "anonymous")
    key = f"{user_id}:hkia"
    _ENTITLEMENTS[key] = {
        "user_id": user_id,
        "entitlement": "hkia",
        "granted_at": int(time.time()),
        "expires_at": int(time.time()) + 86400 * 365,  # 1 year
    }
    return {"status": "ok", "entitlement": _ENTITLEMENTS[key]}


def _route_game_launch(emulator, request: dict) -> dict:
    """Return the OK that lets the HKIA main game launch."""
    return {
        "status": "ok",
        "launch_token": f"sunblink-launch-{uuid.uuid4().hex[:16]}",
        "expires_at": int(time.time()) + 3600,
    }


# v0.8.0+ Item M Phase 1 helpers
# These are best-effort patterns to grep the Sunblink SDK's class
# names from a dumped IL2CPP binary. Real names will be filled in by
# the frida hooks.

SUNBLINK_SDK_METHOD_PATTERNS = [
    # Common Sunblink SDK class name patterns
    r"SunblinkSDK\.dll",
    r"SunblinkSDK\..*Login",
    r"SunblinkSDK\..*Authenticate",
    r"SunblinkSDK\..*CheckEntitlement",
    r"SunblinkSDK\..*GetEntitlement",
    r"SunblinkSDK\..*RefreshToken",
    r"SunblinkSDK\..*HttpRequest",
    r"SunblinkSDK\..*Encrypt",
    r"SunblinkSDK\..*Decrypt",
    r"SunblinkSDK\..*GetDeviceId",
    r"SunblinkSDK\..*GetSessionId",
]


def find_sunblink_sdk_symbols(binary_path: str) -> list[dict]:
    """Phase 1 helper: scan a binary for Sunblink SDK method names.

    Returns a list of {pattern, offset, name} dicts for each match.
    The actual frida hooks in Phase 1 will use these offsets to
    intercept the calls.
    """
    import re
    from pathlib import Path
    path = Path(binary_path)
    if not path.is_file():
        return []
    data = path.read_bytes()
    matches: list[dict] = []
    for pattern in SUNBLINK_SDK_METHOD_PATTERNS:
        # Search for the pattern as UTF-8
        for m in re.finditer(pattern.encode("utf-8"), data):
            matches.append({
                "pattern": pattern,
                "offset": m.start(),
                "name": m.group(0).decode("utf-8", errors="replace"),
            })
    log.info("Sunblink RE: found %d symbol matches in %s", len(matches), binary_path)
    return matches
