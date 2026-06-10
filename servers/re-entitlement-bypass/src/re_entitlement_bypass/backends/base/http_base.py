"""EmulatorHTTPBase — common base for all 7 HTTP-based entitlement emulators.

This module collapses the cert/hosts/ThreadedHTTPServer boilerplate that was
copy-pasted across `eos-handshake-emulator/emulator.py`, `ioi-account-emulator/
emulator.py`, and `sega-sso-mock/sega_sso_mock.py` into a single base class.

Subclasses override:
- `_routes() -> dict[path, callable]` — the per-path handlers
- `_state() -> dict` — the in-memory emulator state (entitlements, tokens, etc.)
- `bind`, `port`, `cert_name` — the bind address + port + cert name

The base provides:
- `__init__` — generates self-signed cert if missing, sets up ThreadedHTTPServer
- `start()` / `stop()` — background-thread lifecycle
- `_make_handler()` — the BaseHTTPRequestHandler subclass that dispatches to routes
- `audit()` — SHA-256 of cert + key + hosts file
- `deploy()` / `rollback()` — write/remove hosts entries, start/stop emulator
- `plan()` — return the planned state (no writes)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from ...core.audit import sha256_file
from ...core.layer_base import LayerDeployer, register
from ...core.status import LayerDeployStatus

if TYPE_CHECKING:
    from ...core.target_manifest import TargetEntry

log = logging.getLogger("re-entitlement-bypass.http_base")


class EmulatorHTTPBase(LayerDeployer):
    """Base class for all 7 HTTP-based entitlement emulators.

    Subclasses set:
    - layer: e.g. "eos", "ioi", "atlus"
    - bind: default "127.0.0.1"
    - port: default 8443 (or 8444-8449 for non-EOS)
    - cert_name: default derived from layer name
    - hosts_subdomain: list of hostnames to route to 127.0.0.1
    """

    layer: str = ""
    backend: str = "http"
    bind: str = "127.0.0.1"
    port: int = 8443
    cert_name: Optional[str] = None
    hosts_subdomain: list[str] = []

    def __init__(self):
        super().__init__(layer=self.layer, backend=self.backend)
        if self.cert_name is None:
            self.cert_name = f"{self.layer}_emulator"
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._state: dict = {}
        self._lock = threading.Lock()

    # --- subclass-overridable hooks -------------------------------------------

    def _routes(self) -> dict[str, Callable]:
        """Return {path: handler(self, request_body) -> response_dict}."""
        return {}

    def _state(self) -> dict:
        """Return the in-memory emulator state (overridden by subclasses)."""
        return {}

    # --- lifecycle ------------------------------------------------------------

    def start(self, blocking: bool = False) -> None:
        """Start the emulator in a background thread (or block if blocking=True)."""
        if self._server is not None:
            log.warning("emulator already running on %s:%d", self.bind, self.port)
            return
        cert_dir = self._cert_dir()
        cert_path = cert_dir / f"{self.cert_name}.pem"
        key_path = cert_dir / f"{self.cert_name}.key"
        if not cert_path.exists() or not key_path.exists():
            self._generate_self_signed_cert(cert_path, key_path)

        handler_cls = self._make_handler()
        self._server = ThreadingHTTPServer((self.bind, self.port), handler_cls)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        log.info("emulator %s listening on https://%s:%d", self.layer, self.bind, self.port)

        if blocking:
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name=f"emulator-{self.layer}")
            self._thread.start()

    def stop(self) -> None:
        """Stop the emulator and join the background thread."""
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
        log.info("emulator %s stopped", self.layer)

    def is_running(self) -> bool:
        return self._server is not None

    # --- LayerDeployer interface ---------------------------------------------

    def plan(self, target: "TargetEntry", dry_run: bool = False) -> LayerDeployStatus:
        cert_path = self._cert_dir() / f"{self.cert_name}.pem"
        key_path = self._cert_dir() / f"{self.cert_name}.key"
        cert_sha = sha256_file(cert_path) if cert_path.exists() else "missing"
        key_sha = sha256_file(key_path) if key_path.exists() else "missing"
        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="planned",
            bind=f"{self.bind}:{self.port}",
            hosts_lines=[f"127.0.0.1 {h}" for h in self.hosts_subdomain],
            sha256={str(cert_path): cert_sha, str(key_path): key_sha},
            note=f"HTTP emulator on {self.bind}:{self.port} for {len(self.hosts_subdomain)} hostnames",
        )

    def deploy(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        hosts_path = self._resolve_hosts_path(wine_prefix)
        plan_status = self.plan(target)
        if not dry_run_marker():
            self._write_hosts_entries(hosts_path, plan_status.hosts_lines)
            self.start()
        return LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="deployed",
            bind=f"{self.bind}:{self.port}",
            hosts_lines=plan_status.hosts_lines,
            sha256=plan_status.sha256,
            note=f"emulator running on {self.bind}:{self.port}",
        )

    def rollback(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        hosts_path = self._resolve_hosts_path(wine_prefix)
        if not dry_run_marker():
            self._remove_hosts_entries(hosts_path, [f"127.0.0.1 {h}" for h in self.hosts_subdomain])
            self.stop()
        return LayerDeployStatus(layer=self.layer, backend=self.backend, status="rolled-back", note="emulator stopped + hosts entries removed")

    def audit(self, target: "TargetEntry", wine_prefix: Optional[Path] = None) -> LayerDeployStatus:
        return self.plan(target) if not self.is_running() else LayerDeployStatus(
            layer=self.layer,
            backend=self.backend,
            status="deployed",
            bind=f"{self.bind}:{self.port}",
            note=f"emulator running on {self.bind}:{self.port}",
        )

    # --- helpers --------------------------------------------------------------

    def _cert_dir(self) -> Path:
        """The directory for self-signed cert + key. Default: $RE_BREAKER_DATA_DIR/certs/ or ~/.cache/re-breaker/certs/."""
        from os import getenv
        override = getenv("RE_BREAKER_CERT_DIR")
        if override:
            return Path(override)
        return Path.home() / ".cache" / "re-breaker" / "certs"

    def _resolve_hosts_path(self, wine_prefix: Optional[Path]) -> Path:
        """Resolve the hosts file path. Per-Wine-prefix preferred; system /etc/hosts is the fallback."""
        if wine_prefix:
            p = wine_prefix / "drive_c" / "windows" / "system32" / "drivers" / "etc" / "hosts"
            if p.parent.exists():
                return p
        return Path("/etc/hosts")

    def _write_hosts_entries(self, hosts_path: Path, lines: list[str]) -> None:
        """Append the lines to the hosts file (idempotent — skips if already present)."""
        existing = hosts_path.read_text() if hosts_path.exists() else ""
        to_add = [l for l in lines if l not in existing]
        if not to_add:
            return
        with hosts_path.open("a") as f:
            for line in to_add:
                f.write(line + "\n")
        log.info("wrote %d hosts entries to %s", len(to_add), hosts_path)

    def _remove_hosts_entries(self, hosts_path: Path, lines: list[str]) -> None:
        if not hosts_path.exists():
            return
        existing = hosts_path.read_text().splitlines()
        to_remove = set(lines)
        kept = [l for l in existing if l not in to_remove]
        hosts_path.write_text("\n".join(kept) + "\n")
        log.info("removed %d hosts entries from %s", len(to_remove & set(existing)), hosts_path)

    def _generate_self_signed_cert(self, cert_path: Path, key_path: Path) -> None:
        """Generate a self-signed cert + key using openssl. 10-year validity, SAN includes self.hosts_subdomain."""
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        san_entries = ["DNS:localhost", "IP:127.0.0.1"] + [f"DNS:{h}" for h in self.hosts_subdomain]
        san_str = ",".join(san_entries)
        cn = f"{self.cert_name}.lab.local"
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-days", "3650",
            "-subj", f"/CN={cn}",
            "-addext", f"subjectAltName={san_str}",
        ]
        log.info("generating self-signed cert: %s", " ".join(cmd))
        subprocess.run(cmd, check=True, capture_output=True)
        log.info("wrote cert to %s (SAN: %s)", cert_path, san_str)

    def _make_handler(self) -> type:
        """Build a BaseHTTPRequestHandler subclass that dispatches to _routes()."""
        emulator = self
        routes = emulator._routes()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                log.debug("%s - - %s", self.address_string(), format % args)

            def do_GET(self):
                self._dispatch("GET")

            def do_POST(self):
                self._dispatch("POST")

            def _dispatch(self, method):
                handler = routes.get(self.path)
                if handler is None:
                    self.send_error(404, f"No route for {method} {self.path}")
                    return
                content_length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(content_length) if content_length else b""
                try:
                    if body:
                        request_body = json.loads(body)
                    else:
                        request_body = {}
                except json.JSONDecodeError:
                    request_body = {"_raw": body.decode("utf-8", errors="replace")}
                try:
                    response = handler(emulator, request_body)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                except Exception as e:
                    log.exception("handler error: %s", e)
                    self.send_error(500, str(e))

        return Handler


# Helper — the orchestrator's dry-run flag is captured in an env var so the
# subclasses don't need to thread it through every call.
def dry_run_marker() -> bool:
    from os import getenv
    return getenv("RE_EE_DRY_RUN") == "1"
