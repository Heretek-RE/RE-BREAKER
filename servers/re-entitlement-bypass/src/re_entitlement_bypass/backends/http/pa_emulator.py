"""Pearl Abyss internal protocol emulator — SCAFFOLD.

Per SOW-X (Pearl Abyss): CD is the target. The PA-internal handshake is
presumed to be via `pers.exe` + `hermessdkcorewrapper_release.dll` (per
`entitlement-pa.md` SCAFFOLD ONLY). The exact wire format was not captured
in v0.4.1.9 (the cinematic wall blocked the entitlement call).

Phase 1's RE work: reverse the PA SDK from the CD binary. The DenuvOwO build
at `Input/Crimson.Desert.Build.23578264-DenuvOwO/` may have a mock PA server
we can cross-reference.
"""

from __future__ import annotations

import logging
from typing import Callable

from ..base.http_base import EmulatorHTTPBase
from ...core.layer_base import register
from ...core.status import LayerDeployStatus

log = logging.getLogger("re-entitlement-bypass.pa")


@register
class PAEmulator(EmulatorHTTPBase):
    layer = "pa"
    backend = "http/pa"
    bind = "127.0.0.1"
    port = 8447
    hosts_subdomain = [
        "auth.pearlabyss.com",
        "api.pearlabyss.com",
        "entitlement.pearlabyss.com",
        "cd.pearlabyss.com",
        "hermes.pearlabyss.com",
    ]

    def _routes(self) -> dict[str, Callable]:
        return {
            "/pa/v1/health": _route_health,
            "/pa/v1/auth/login": _route_stub,
            "/pa/v1/entitlement/cd": _route_stub,
            "/hermes/v1/auth/login": _route_stub,
        }


def _route_health(emulator, request: dict) -> dict:
    return {
        "status": "stub",
        "service": "pa-emulator",
        "version": "0.2.0",
        "build": "re-breaker-0.2.0",
        "note": "Phase 1 SCAFFOLD — PA internal protocol is RE-only. Reverse from the CD binary (pers.exe + hermessdkcorewrapper_release.dll) before live use.",
    }


def _route_stub(emulator, request: dict) -> dict:
    return {
        "status": "stub",
        "note": "Phase 1 SCAFFOLD — PA internal protocol is RE-only. Reverse from the CD binary before live use.",
        "received": request,
    }
