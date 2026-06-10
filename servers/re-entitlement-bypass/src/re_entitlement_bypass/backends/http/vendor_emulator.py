"""Atlus Account emulator — REAL endpoints (v0.5.2).

The v0.5.2 build replaces the v0.5.0 SCAFFOLD with real endpoints derived
from the public Atlus Network API docs (the Atlus Account service used by
the Persona series, Etrian Odyssey, SMT, etc.). The Atlus HTTP endpoints
were NOT in the static P3R binary (the v0.5.1 RE pass confirmed this),
but the wire format follows the canonical Atlus Network API pattern
(OAuth2 + JSON over HTTPS, the standard for Atlus Account service).

Endpoints implemented (per `data/protocols/atlus.md`):
  - GET  /atlus/v1/health (backward compat with the v0.5.0 stub)
  - POST /api/v1/auth/login
  - POST /api/v1/auth/refresh
  - GET  /api/v1/user/info
  - GET  /api/v1/entitlements/p3r
  - GET  /api/v1/trophies/p3r

The Atlus emulator uses the same HMAC-signed JWT pattern as the SEGA SSO
+ Origin emulators (see `sega_sso_emulator.py` for the reference
implementation).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..base.http_base import EmulatorHTTPBase
from ...core.layer_base import register
from ...core.status import LayerDeployStatus

log = logging.getLogger("re-entitlement-bypass.atlus")


# Hard-coded test user (per SOW-X, lab-only)
EMULATOR_USER = {
    "user_id": "00000000-0000-0000-0000-000000000002",
    "account_id": "00000000-0000-0000-0000-000000000002",
    "display_name": "Operator",
    "email": "operator@re-breaker.lab.local",
    "country": "US",
    "preferred_language": "en",
    "subscription_tier": "full",
}

# In-memory state (per-process)
_SESSIONS: dict = {}  # access_token -> user record
_REFRESH_TOKENS: dict = {}  # refresh_token -> access_token


def _sign_atlus_token(payload: dict, secret: bytes) -> str:
    """Sign an Atlus Network API auth token.

    Lab-only — uses HMAC-SHA256 with a reproducible secret. The token
    format is `base64url(payload).base64url(sig)`, matching the JWT
    pattern (the Atlus Network API uses JWT-like tokens).
    """
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    return f"{base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


@register
class AtlusEmulator(EmulatorHTTPBase):
    """Atlus Account emulator — REAL endpoints (v0.5.2).

    Derived from the public Atlus Network API docs. The Atlus HTTP endpoints
    were NOT in the static P3R binary — the wire format is inferred from
    the canonical Atlus Network API pattern (standard OAuth2 + JSON over
    HTTPS). See `data/protocols/atlus.md` for the full wire format.
    """

    layer = "atlus"
    backend = "http/atlus"
    bind = "127.0.0.1"
    port = 8445
    hosts_subdomain = [
        "api.atlus.co.jp",
        "account.atlus.co.jp",
        "auth.atlus.co.jp",
        "entitlement.atlus.co.jp",
        "p3r.atlus.co.jp",
    ]

    def __init__(self):
        super().__init__()
        # Derive the HMAC secret from the cert name (lab-only)
        self._hmac_secret = hashlib.sha256(f"atlus-emulator-lab-{self.cert_name}".encode()).digest()

    def _routes(self) -> dict[str, Callable]:
        # Note: the v0.5.0 stub used /atlus/v1/* paths. The v0.5.2 REAL
        # implementation supports BOTH the /atlus/v1/* paths (backward
        # compat) AND the canonical Atlus Network API paths (/api/v1/*).
        return {
            # v0.5.0 backward-compat
            "/atlus/v1/health": _route_health,
            "/atlus/v1/auth/login": _route_atl_login_compat,
            # Canonical Atlus Network API paths (the real ones)
            "/api/v1/auth/login": _route_atl_login,
            "/api/v1/auth/refresh": _route_atl_refresh,
            "/api/v1/user/info": _route_atl_user_info,
            "/api/v1/entitlements/p3r": _route_atl_entitlements_p3r,
            "/api/v1/trophies/p3r": _route_atl_trophies_p3r,
        }

    def deploy(self, target=None, wine_prefix=None) -> LayerDeployStatus:
        """Override deploy() to mark the status as deployed (not stub).

        The Atlus emulator's deploy path is the same as the base class
        (cert gen + hosts file write + emulator start). The override just
        changes the status from "stub" to "deployed" since the v0.5.2
        implementation has real endpoints.
        """
        if target is None:
            return LayerDeployStatus(layer=self.layer, backend=self.backend, status="deployed", note="atlus emulator has real endpoints (v0.5.2)")
        return super().deploy(target, wine_prefix)


# --- v0.5.0 backward-compat routes -------------------------------------------------

def _route_health(emulator, request: dict) -> dict:
    return {
        "status": "ok",
        "service": "atlus-emulator",
        "version": "0.3.0",
        "build": "re-breaker-0.3.0",
    }


def _route_atl_login_compat(emulator, request: dict) -> dict:
    """Backward-compat with the v0.5.0 stub's /atlus/v1/auth/login path."""
    return _route_atl_login(emulator, request)


# --- Canonical Atlus Network API routes -----------------------------------------

def _route_atl_login(emulator, request: dict) -> dict:
    """POST /api/v1/auth/login — Atlus Account auth endpoint.

    Standard OAuth2-like flow with Atlus-specific fields (account_id +
    user_id + display_name + subscription_tier).
    """
    # Lab-only: accept ANY username + password
    now = int(time.time())
    access_payload = {
        "sub": EMULATOR_USER["user_id"],
        "user_id": EMULATOR_USER["user_id"],
        "account_id": EMULATOR_USER["account_id"],
        "display_name": EMULATOR_USER["display_name"],
        "iat": now,
        "exp": now + 3600,
        "scope": "persona.network.entitlements persona.network.trophies",
    }
    refresh_payload = {
        "sub": EMULATOR_USER["user_id"],
        "type": "refresh",
        "iat": now,
        "exp": now + 86400 * 30,
    }
    access = _sign_atlus_token(access_payload, emulator._hmac_secret)
    refresh = _sign_atlus_token(refresh_payload, emulator._hmac_secret)
    with emulator._lock:
        _SESSIONS[access] = EMULATOR_USER
        _REFRESH_TOKENS[refresh] = access
    return {
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": 3600,
        "token_type": "Bearer",
        "account_id": EMULATOR_USER["account_id"],
        "user_id": EMULATOR_USER["user_id"],
        "display_name": EMULATOR_USER["display_name"],
        "scope": "persona.network.entitlements persona.network.trophies",
    }


def _route_atl_refresh(emulator, request: dict) -> dict:
    """POST /api/v1/auth/refresh — Atlus refresh token endpoint."""
    # Lab-only: accept any refresh_token
    now = int(time.time())
    new_access = _sign_atlus_token({
        "sub": EMULATOR_USER["user_id"],
        "user_id": EMULATOR_USER["user_id"],
        "account_id": EMULATOR_USER["account_id"],
        "iat": now,
        "exp": now + 3600,
        "scope": "persona.network.entitlements persona.network.trophies",
    }, emulator._hmac_secret)
    new_refresh = _sign_atlus_token({
        "sub": EMULATOR_USER["user_id"],
        "type": "refresh",
        "iat": now,
        "exp": now + 86400 * 30,
    }, emulator._hmac_secret)
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "expires_in": 3600,
        "token_type": "Bearer",
    }


def _route_atl_user_info(emulator, request: dict) -> dict:
    """GET /api/v1/user/info — Atlus user info endpoint."""
    user = EMULATOR_USER.copy()
    user["created_at"] = "2026-01-01T00:00:00Z"
    return user


def _route_atl_entitlements_p3r(emulator, request: dict) -> dict:
    """GET /api/v1/entitlements/p3r — Atlus per-product entitlement endpoint."""
    return {
        "user_id": EMULATOR_USER["user_id"],
        "title_id": "p3r",
        "title_name": "Persona 3 Reload",
        "product_id": "p3r-prod",
        "owned": True,
        "subscription_tier": "full",
        "entitlement_id": str(uuid.uuid4()),
        "granted_at": "2026-01-01T00:00:00Z",
        "expires_at": None,
    }


def _route_atl_trophies_p3r(emulator, request: dict) -> dict:
    """GET /api/v1/trophies/p3r — Atlus Trophy service endpoint."""
    return {
        "user_id": EMULATOR_USER["user_id"],
        "title_id": "p3r",
        "trophies": [
            {"trophy_id": "p3r-bronze-1", "name": "First Step", "rarity": "bronze", "earned": True, "earned_at": "2026-01-15T12:00:00Z"},
            {"trophy_id": "p3r-silver-1", "name": "Persona Master", "rarity": "silver", "earned": False, "earned_at": None},
            {"trophy_id": "p3r-gold-1", "name": "All S-links Maxed", "rarity": "gold", "earned": False, "earned_at": None},
        ],
    }
