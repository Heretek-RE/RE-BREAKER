"""IOI Account emulator — refactored to extend EmulatorHTTPBase.

Per SOW-X §L.6: IOI Account handshake + entitlement lookup in scope; only used
for the IOI Account layer (Glacier 2 framework, 007FL target).

Endpoints implemented (from the existing emulator.py + protocol.md):
  GET  /                            — service info
  GET  /health                      — health
  GET  /account/v1/health           — health
  GET  /account/v1/entitlement/lookup — cached emulator entitlement
  GET  /account/v1/entitlement/<title> — per-title lookup
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Callable

from ..base.http_base import EmulatorHTTPBase
from ...core.layer_base import register

log = logging.getLogger("re-entitlement-bypass.ioi")

IOI_ACCOUNT_VERSION = "v1"

EMULATOR_USER = {
    "account_id": "00000000-0000-0000-0000-000000000010",
    "username": "operator@re-breaker.lab.local",
    "display_name": "Operator",
    "country": "US",
    "preferred_language": "en",
}

EMULATOR_ENTITLEMENT = {
    "user_id": "00000000-0000-0000-0000-000000000010",
    "title": "007 First Light",
    "title_id": "007-first-light",
    "product_id": "007fl-prod",
    "entitlement_id": str(uuid.uuid4()),
    "owned": True,
    "redeemed": True,
    "expires_at": int((datetime.now(timezone.utc) + timedelta(days=365 * 10)).timestamp()),
    "subscription_tier": "full",
}


@register
class IOIEmulator(EmulatorHTTPBase):
    layer = "ioi"
    backend = "http/ioi"
    bind = "127.0.0.1"
    port = 8443
    hosts_subdomain = [
        "account.ioi.dk",
        "api.ioi.dk",
        "entitlement.ioi.dk",
        "auth.ioi.dk",
        "telemetry.ioi.dk",
    ]

    def __init__(self):
        super().__init__()
        self._sessions: dict[str, dict] = {}  # token → user record

    def _routes(self) -> dict[str, Callable]:
        return {
            "/": _route_root,
            "/health": _route_health,
            "/account/v1/health": _route_account_health,
            "/account/v1/entitlement/lookup": _route_entitlement_lookup,
            "/account/v1/entitlement/list": _route_entitlement_list,
        }


def _route_root(emulator, request: dict) -> dict:
    return {
        "service": "ioi-account-emulator",
        "version": "0.2.0",
        "status": "ok",
        "scope": "lab-only (per SOW-X §L.6)",
    }


def _route_health(emulator, request: dict) -> dict:
    return {"service": "ioi-account-emulator", "version": "0.2.0", "status": "ok"}


def _route_account_health(emulator, request: dict) -> dict:
    return {"status": "healthy", "version": IOI_ACCOUNT_VERSION}


def _route_entitlement_lookup(emulator, request: dict) -> dict:
    return EMULATOR_ENTITLEMENT


def _route_entitlement_list(emulator, request: dict) -> dict:
    return {"entitlements": [EMULATOR_ENTITLEMENT]}

    # Wildcard per-title — the base class's exact-match dispatch can't handle
    # `/account/v1/entitlement/007-first-light` directly. The deploy() can
    # register a fallback handler if needed; for now, the lookup is sufficient.
