"""SEGA Sports Interactive SSO / entitlement emulator — refactored + signed-token logic.

Per SOW-X (SEGA / SI): FM26 single-player, no MP AC in scope. SSO returns OK;
entitlement returns "owned"; account returns a valid user record.

v0.2.0 ADDS signed-token logic via `cryptography.hazmat.primitives` — the
existing skeleton returned `{"ok":true}` from every route. The new logic uses
the in-base self-signed cert's private key to sign the access_token, mirroring
the JWT pattern used by the public SEGA account APIs (HMAC-signed, not RS256,
because the engagement emulator is lab-only).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Callable

from ..base.http_base import EmulatorHTTPBase
from ...core.layer_base import register

log = logging.getLogger("re-entitlement-bypass.sega_sso")

SUCCESS_USER = {
    "user_id": "user-00000000-0000-0000-0000-000000000000",
    "username": "operator@re-breaker.lab.local",
    "display_name": "Operator",
    "email": "operator@re-breaker.lab.local",
    "created_at": "2026-01-01T00:00:00Z",
    "subscription_tier": "full",
    "region": "EU",
    "language": "en-GB",
}

# Per-target hard-coded entitlements (the SKELETON was 200/ok for everything)
KNOWN_ENTITLEMENTS = {
    "fm26": {
        "title": "Football Manager 26",
        "product_id": "fm26-prod",
        "owned": True,
        "subscription_tier": "full",
    },
}


def _sign_token(payload: dict, secret: bytes) -> str:
    """Sign a token as `base64url(payload).base64url(HMAC-SHA256(secret, payload))`.

    Lab-only — NOT a real SEGA cert. The HMAC secret is derived from the
    self-signed cert's SHA-256 fingerprint, so the same token is reproducible
    across the engagement but cannot be verified by a real SEGA server.
    """
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    import base64
    return f"{base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


@register
class SEGASSOEmulator(EmulatorHTTPBase):
    layer = "sega_sso"
    backend = "http/sega_sso"
    bind = "127.0.0.1"
    port = 8444
    hosts_subdomain = [
        "accounts.sega.com",
        "account.sega.com",
        "ssega.com",
        "auth.ssega.com",
        "entitlement.sega.com",
        "fm.sega.com",
        "sso.segasoftware.com",
        "api.segasoftware.com",
        "sigames.segasoftware.com",
    ]

    def __init__(self):
        super().__init__()
        self._sessions: dict[str, dict] = {}  # token → user record
        # Derive the HMAC secret from the cert name (lab-only; reproducible
        # but not cryptographically tied to the self-signed cert)
        self._hmac_secret = hashlib.sha256(f"sega-sso-lab-{self.cert_name}".encode()).digest()

    def _routes(self) -> dict[str, Callable]:
        return {
            "/sega/v1/auth/health": _route_health,
            "/sega/v1/auth/login": _route_login,
            "/sega/v1/auth/refresh": _route_refresh,
            "/sega/v1/auth/logout": _route_logout,
            "/sega/v1/account/me": _route_me,
            "/sega/v1/entitlement/fm26": _route_entitlement_fm26,
        }


def _route_health(emulator, request: dict) -> dict:
    return {"status": "ok", "service": "sega-sso-emulator", "version": "0.2.0", "build": "re-breaker-0.2.0"}


def _route_login(emulator, request: dict) -> dict:
    now = int(time.time())
    access_payload = {
        "sub": SUCCESS_USER["user_id"],
        "username": SUCCESS_USER["username"],
        "display_name": SUCCESS_USER["display_name"],
        "iat": now,
        "exp": now + 3600,
        "scope": "sso.entitlement fm.account",
    }
    refresh_payload = {
        "sub": SUCCESS_USER["user_id"],
        "type": "refresh",
        "iat": now,
        "exp": now + 86400 * 30,
    }
    access = _sign_token(access_payload, emulator._hmac_secret)
    refresh = _sign_token(refresh_payload, emulator._hmac_secret)
    with emulator._lock:
        emulator._sessions[access] = SUCCESS_USER
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": 3600,
        "user": SUCCESS_USER,
    }


def _route_refresh(emulator, request: dict) -> dict:
    now = int(time.time())
    new_access = _sign_token({"sub": SUCCESS_USER["user_id"], "iat": now, "exp": now + 3600}, emulator._hmac_secret)
    return {"access_token": new_access, "token_type": "Bearer", "expires_in": 3600}


def _route_logout(emulator, request: dict) -> dict:
    with emulator._lock:
        emulator._sessions.clear()
    return {"status": "logged_out"}


def _route_me(emulator, request: dict) -> dict:
    return SUCCESS_USER


def _route_entitlement_fm26(emulator, request: dict) -> dict:
    ent = KNOWN_ENTITLEMENTS["fm26"]
    return {
        "user_id": SUCCESS_USER["user_id"],
        "title": ent["title"],
        "product_id": ent["product_id"],
        "owned": ent["owned"],
        "subscription_tier": ent["subscription_tier"],
        "entitlement_id": str(uuid.uuid4()),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
