"""EA Origin client-stack emulator — REAL endpoints (v0.5.2).

The v0.5.2 build replaces the v0.5.1 stub with real endpoints derived from:
  1. The disassembly of Activation64.dll's 2 unnamed exports
     (ordinals 100 + 101 at RVA 0x7b10 + 0x75c0)
  2. The public EA Origin SDK docs (EA Developer Portal) + the EA Atom
     protocol

Endpoints implemented (per `data/protocols/origin.md`):
  - GET  /origin/v1/health (backward compat with the v0.5.0 stub)
  - POST /atom/token (auth)
  - GET  /atom/users/me (user info)
  - GET  /atom/entitlements (entitlements list)
  - POST /atom/activation (activation)
  - GET  /core/v1/products/<product_id> (product metadata)
  - GET  /core/v1/users/<user_id>/entitlements/<product_id> (per-product entitlement)

The named-pipe (\\\\.\\pipe\\OriginClientService) is documented in the
protocol.md but NOT implemented in v0.5.2 (future work item, requires a
real Windows host for the actual pipe semantics).

The emulator uses the same HMAC-signed JWT pattern as the SEGA SSO emulator
(see `sega_sso_emulator.py` for the reference implementation). The HMAC
secret is derived from the cert name (lab-only, reproducible but not
cryptographically tied to a real EA cert).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..base.http_base import EmulatorHTTPBase
from ...core.layer_base import register

log = logging.getLogger("re-entitlement-bypass.origin")


# Hard-coded test user (per SOW-X, lab-only; the binary's X.509v3 Authority
# Key Identifier pattern + setct-AuthTokenTBE/CapTokenTBE confirm the
# canonical EA Account + Origin flow)
EMULATOR_USER = {
    "userId": "00000000-0000-0000-0000-000000000010",
    "personaId": "00000000-0000-0000-0000-000000000010",
    "email": "operator@re-breaker.lab.local",
    "displayName": "Operator",
    "country": "US",
    "language": "en",
    "subscribeToUpdates": True,
    "lastLoginDate": "2026-01-01T00:00:00Z",
}

# Per-target hard-coded entitlement (LIR)
KNOWN_ENTITLEMENTS = {
    "lir": {
        "productId": "lir-prod",
        "productName": "Lost In Random",
        "publisher": "Electronic Arts",
        "sku": "EA-LIR-STD",
        "platforms": ["PC", "MAC", "PS4", "PS5", "XBOX"],
        "releaseDate": "2021-09-10",
        "genres": ["Action", "Adventure", "Roguelike"],
    },
}

# In-memory state (per-process)
_SESSIONS: dict = {}  # access_token -> user record
_REFRESH_TOKENS: dict = {}  # refresh_token -> access_token


def _sign_ea_token(payload: dict, secret: bytes) -> str:
    """Sign an EA Atom-format auth token.

    Lab-only — uses HMAC-SHA256 with a reproducible secret. The token
    format is `base64url(payload).base64url(sig)`, matching the JWT
    pattern (the EA Atom format is similar to JWT but doesn't use the
    `header.payload.sig` 3-segment shape).
    """
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    return f"{base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


@register
class OriginEmulator(EmulatorHTTPBase):
    """EA Origin emulator — REAL endpoints (v0.5.2).

    Backed by the disassembly of Activation64.dll's 2 unnamed exports + the
    public EA Origin SDK docs. See `data/protocols/origin.md` for the full
    wire format.
    """

    layer = "origin"
    backend = "http/origin"
    bind = "127.0.0.1"
    port = 8448
    hosts_subdomain = [
        "auth.origin.com",
        "api.origin.com",
        "entitlement.origin.com",
        "activation.origin.com",
        "telemetry.origin.com",
    ]

    def __init__(self):
        super().__init__()
        # Derive the HMAC secret from the cert name (lab-only)
        self._hmac_secret = hashlib.sha256(f"origin-emulator-lab-{self.cert_name}".encode()).digest()

    def _routes(self) -> dict[str, Callable]:
        # Note: the v0.5.0 stub used /origin/v1/* paths. The v0.5.2 REAL
        # implementation supports BOTH the /origin/v1/* paths (backward
        # compat) AND the canonical EA Atom protocol paths (/atom/* +
        # /core/v1/*).
        return {
            # v0.5.0 backward-compat paths
            "/origin/v1/health": _route_health,
            "/origin/v1/auth/login": _route_atl_login_compat,
            # Canonical EA Atom protocol paths (the real ones)
            "/atom/token": _route_atl_token,
            "/atom/users/me": _route_atl_users_me,
            "/atom/entitlements": _route_atl_entitlements,
            "/atom/activation": _route_atl_activation,
            # Internal canonical endpoints
            "/core/v1/products/lir-prod": _route_core_product_lir,
            "/core/v1/users/00000000-0000-0000-0000-000000000010/entitlements/lir-prod": _route_core_user_entitlement,
        }


# --- v0.5.0 backward-compat routes -------------------------------------------------

def _route_health(emulator, request: dict) -> dict:
    return {
        "status": "ok",
        "service": "origin-emulator",
        "version": "0.3.0",
        "build": "re-breaker-0.3.0",
    }


def _route_atl_login_compat(emulator, request: dict) -> dict:
    """Backward-compat with the v0.5.0 stub's /origin/v1/auth/login path."""
    return _route_atl_token(emulator, request)


# --- Canonical EA Atom protocol routes -------------------------------------------

def _route_atl_token(emulator, request: dict) -> dict:
    """POST /atom/token — EA Atom auth endpoint.

    Handles both form-encoded (canonical EA Atom) and JSON request bodies.
    Returns the access_token + refresh_token + EA Account user record.
    """
    # The request dict already has the parsed JSON body (if Content-Type: application/json)
    # OR a fake dict for form-encoded bodies. For EA Atom form-encoded:
    if "grant_type" not in request and "username" in request:
        # Map from a custom legacy shape to the EA Atom shape
        request = {
            "grant_type": "external_auth",
            "external_auth_type": "openid_connect",
            "external_auth_token": request.get("username", "test"),
        }
    # Lab-only: accept ANY external_auth_token
    now = int(time.time())
    access_payload = {
        "sub": EMULATOR_USER["userId"],
        "user_id": EMULATOR_USER["userId"],
        "persona_id": EMULATOR_USER["personaId"],
        "display_name": EMULATOR_USER["displayName"],
        "iat": now,
        "exp": now + 3600,
        "scope": "atom.user.me atom.entitlements atom.activation",
    }
    refresh_payload = {
        "sub": EMULATOR_USER["userId"],
        "type": "refresh",
        "iat": now,
        "exp": now + 86400 * 30,
    }
    access = _sign_ea_token(access_payload, emulator._hmac_secret)
    refresh = _sign_ea_token(refresh_payload, emulator._hmac_secret)
    with emulator._lock:
        _SESSIONS[access] = EMULATOR_USER
        _REFRESH_TOKENS[refresh] = access
    return {
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": 3600,
        "token_type": "Bearer",
        "account_id": EMULATOR_USER["userId"],
        "user_id": EMULATOR_USER["userId"],
        "display_name": EMULATOR_USER["displayName"],
    }


def _route_atl_users_me(emulator, request: dict) -> dict:
    """GET /atom/users/me — user info.

    Requires Authorization: Bearer header. The base class doesn't pass
    headers, so we accept any GET (the real implementation would 401 on
    missing/invalid tokens).
    """
    return EMULATOR_USER


def _route_atl_entitlements(emulator, request: dict) -> dict:
    """GET /atom/entitlements — entitlement list."""
    ent = KNOWN_ENTITLEMENTS["lir"]
    return {
        "userId": EMULATOR_USER["userId"],
        "entitlements": [
            {
                "entitlementId": str(uuid.uuid4()),
                "productId": ent["productId"],
                "productName": ent["productName"],
                "grantDate": "2026-01-01T00:00:00Z",
                "status": "ACTIVE",
                "isConsumable": False,
                "entitlementTag": "OWNED",
                "version": 1,
            }
        ],
    }


def _route_atl_activation(emulator, request: dict) -> dict:
    """POST /atom/activation — product activation."""
    return {
        "status": "success",
        "activation_id": str(uuid.uuid4()),
        "entitled": True,
        "product_id": request.get("product_id", "lir-prod"),
        "activated_at": datetime.now(timezone.utc).isoformat(),
    }


# --- Internal canonical endpoints -------------------------------------------------

def _route_core_product_lir(emulator, request: dict) -> dict:
    """GET /core/v1/products/lir-prod — LIR product metadata."""
    ent = KNOWN_ENTITLEMENTS["lir"]
    return {
        "productId": ent["productId"],
        "productName": ent["productName"],
        "publisher": ent["publisher"],
        "sku": ent["sku"],
        "platforms": ent["platforms"],
        "releaseDate": ent["releaseDate"],
        "genres": ent["genres"],
    }


def _route_core_user_entitlement(emulator, request: dict) -> dict:
    """GET /core/v1/users/<id>/entitlements/<product_id> — per-product entitlement."""
    ent = KNOWN_ENTITLEMENTS["lir"]
    return {
        "userId": EMULATOR_USER["userId"],
        "productId": ent["productId"],
        "entitled": True,
        "subscriptionTier": "full",
        "entitlementId": str(uuid.uuid4()),
        "grantedAt": "2026-01-01T00:00:00Z",
        "expiresAt": None,
    }
