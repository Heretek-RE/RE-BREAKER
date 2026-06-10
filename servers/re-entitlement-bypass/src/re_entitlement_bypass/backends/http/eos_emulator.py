"""EOS (Epic Online Services) handshake emulator — refactored to extend EmulatorHTTPBase.

Per SOW-X §K.2 + SOW-X §Q.1: EOS handshake protocol analysis in scope; EOS
Anti-Cheat is SOW-X's carve-out and is NOT in scope. The emulator MUST NOT
implement the EOS AC layer.

Endpoints implemented (from the existing emulator.py + protocol.md):
  GET  /eos/v1/health           — health check
  POST /eos/v1/auth/login       — external_auth → access_token + refresh_token
  POST /eos/v1/auth/refresh     — refresh_token → new access_token
  GET  /eos/v1/user/info        — user info by access_token
  GET  /eos/v1/ecom/entitlements — list entitlements for user
  POST /eos/v1/ecom/redeem      — redeem entitlement
  POST /eos/v1/connect/login    — EOS Connect login (product_user_id)
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Callable

from ..base.http_base import EmulatorHTTPBase
from ...core.layer_base import register

log = logging.getLogger("re-entitlement-bypass.eos")

# Hard-coded test user (per SOW-X §K.2, lab-only)
EMULATOR_USER = {
    "account_id": "00000000-0000-0000-0000-000000000002",
    "display_name": "en_redteam_lab",
    "country": "US",
    "preferred_language": "en",
    "linked_external_accounts": [{"type": "steam", "id": "76561198000000002"}],
}

# Hard-coded test entitlement (TWW3 — see SOW-X §Q.1)
EMULATOR_ENTITLEMENT = {
    "entitlement_name": f"entitlement_{int(time.time())}",
    "entitlement_id": str(uuid.uuid4()),
    "product_id": "ce66d76f4b1b4b2896a1b6cbd3",
    "product_name": "Total War: WARHAMMER III",
    "catalog_version": "live",
    "consumable": False,
    "redeemed": True,
    "end_timestamp": int((datetime.now(timezone.utc) + timedelta(days=365 * 10)).timestamp()),
}


@register
class EOSEmulator(EmulatorHTTPBase):
    layer = "eos"
    backend = "http/eos"
    bind = "127.0.0.1"
    port = 8443
    hosts_subdomain = [
        "api.epicgames.dev",
        "eos.epicgames.com",
        "api.epicgames.com",
        "eos-ic.epicgames.com",
        "eos-auth.epicgames.com",
        "eos-ecom.epicgames.com",
    ]

    def __init__(self):
        super().__init__()
        # In-memory state
        self._tokens: dict[str, dict] = {}  # access_token → user record
        self._refresh_tokens: dict[str, str] = {}  # refresh_token → access_token
        self._entitlements: dict[str, list] = {}  # account_id → [entitlement, ...]

    def _routes(self) -> dict[str, Callable]:
        # All routes are module-level functions with signature (emulator, request) -> dict.
        # NOTE: This is a NEW design, not a faithful refactor of the original
        # `See the RE-BREAKER output directory.`.
        # The original had: /auth/login, /auth/verify, /auth/logout, /connect/login,
        # /connect/token, /ecom/checkout, /plat/active (7 endpoints).
        # This refactored version has: /health, /auth/login, /auth/refresh,
        # /user/info, /ecom/entitlements, /ecom/redeem, /connect/login (7 endpoints).
        # Differences: replaced /auth/verify with /auth/refresh; renamed
        # /ecom/checkout to /ecom/entitlements; added /health, /user/info,
        # /ecom/redeem; dropped /auth/logout, /connect/token, /plat/active.
        return {
            "/eos/v1/health": _route_health,
            "/eos/v1/auth/login": _route_login,
            "/eos/v1/auth/refresh": _route_refresh,
            "/eos/v1/user/info": _route_user_info,
            "/eos/v1/ecom/entitlements": _route_entitlements,
            "/eos/v1/ecom/redeem": _route_redeem,
            "/eos/v1/connect/login": _route_connect_login,
        }


def _route_health(emulator, request: dict) -> dict:
    return {"status": "ok", "service": "eos-handshake-emulator", "version": "0.2.0", "build": "re-breaker-0.2.0"}


def _route_login(emulator, request: dict) -> dict:
    token = str(uuid.uuid4())
    refresh = str(uuid.uuid4())
    with emulator._lock:
        emulator._tokens[token] = EMULATOR_USER
        emulator._refresh_tokens[refresh] = token
        emulator._entitlements.setdefault(EMULATOR_USER["account_id"], []).append(EMULATOR_ENTITLEMENT)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "refresh_token": refresh,
        "expires_in": 3600,
        "scope": "basic_profile",
        "account_id": EMULATOR_USER["account_id"],
        "client_id": "re-breaker-lab",
        "selected_account_id": EMULATOR_USER["account_id"],
    }


def _route_refresh(emulator, request: dict) -> dict:
    old_refresh = request.get("refresh_token", "")
    with emulator._lock:
        old_token = emulator._refresh_tokens.get(old_refresh)
        if old_token is None:
            return {"error": "invalid_grant", "error_description": "refresh_token not recognized"}
        new_token = str(uuid.uuid4())
        emulator._tokens[new_token] = emulator._tokens.pop(old_token)
        emulator._refresh_tokens[old_refresh] = new_token
    return {"access_token": new_token, "token_type": "Bearer", "expires_in": 3600, "scope": "basic_profile"}


def _route_user_info(emulator, request: dict) -> dict:
    # Token is in Authorization header — base class's handler doesn't pass headers.
    return EMULATOR_USER


def _route_entitlements(emulator, request: dict) -> dict:
    return {"entitlements": emulator._entitlements.get(EMULATOR_USER["account_id"], [EMULATOR_ENTITLEMENT])}


def _route_redeem(emulator, request: dict) -> dict:
    ent_id = request.get("entitlement_id", str(uuid.uuid4()))
    return {"entitlement_id": ent_id, "redeemed": True, "transaction_id": str(uuid.uuid4())}


def _route_connect_login(emulator, request: dict) -> dict:
    return {
        "product_user_id": "00000000000000000000000000000002",
        "display_name": EMULATOR_USER["display_name"],
        "status": "success",
        "country": EMULATOR_USER["country"],
        "preferred_language": EMULATOR_USER["preferred_language"],
    }


def _route_health(emulator, request: dict) -> dict:
    return {"status": "ok", "service": "eos-handshake-emulator", "version": "0.2.0", "build": "re-breaker-0.2.0"}


def _route_user_info(emulator, request: dict) -> dict:
    # Token is in Authorization header — base class's handler doesn't pass headers.
    return EMULATOR_USER


def _route_redeem(emulator, request: dict) -> dict:
    ent_id = request.get("entitlement_id", str(uuid.uuid4()))
    return {"entitlement_id": ent_id, "redeemed": True, "transaction_id": str(uuid.uuid4())}


def _route_connect_login(emulator, request: dict) -> dict:
    return {
        "product_user_id": "00000000000000000000000000000002",
        "display_name": EMULATOR_USER["display_name"],
        "status": "success",
        "country": EMULATOR_USER["country"],
        "preferred_language": EMULATOR_USER["preferred_language"],
    }
