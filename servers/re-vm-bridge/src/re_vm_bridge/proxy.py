"""re-vm-bridge/proxy.py — thin SSE proxy to upstream MCPs (v0.5.3).

Used by `re-ida-remote` / `re-ghidra-remote` / `re-x64dbg-remote` to
talk to the upstream MCP servers running in the Windows VM. The
upstream servers expose HTTP (with SSE) on the guest's loopback;
we open an SSH -L tunnel to that loopback (via `re-vm-ssh.ssh_tunnel_open`)
and this proxy class makes JSON-RPC calls over that tunnel.

**Supports two upstream transports** (auto-detected by `upstream_path`):

1. **MCP Streamable-HTTP** (modern, used by idalib-mcp + bethington/ghidra-mcp):
   - POST /mcp HTTP/1.1 (Content-Type: application/json,
                            Accept: application/json, text/event-stream)
   - Server returns Mcp-Session-Id header; we echo it back on subsequent calls
   - Response body is either application/json (one-shot) or text/event-stream

2. **MCP-over-SSE (legacy, used by x64DbgMCPServer v1.3 + earlier)**:
   - GET /sse → server sends `event: endpoint\ndata: /message?sessionId=<id>`
   - POST /message?sessionId=<id> with the JSON-RPC payload
   - Server sends the response back over the GET /sse stream
   - We hold the GET stream open in a background thread and route
     responses to waiting call() invocations by session id + request id

The IDA upstream has an additional gating: the debugger tools
require `?ext=dbg` in the URL. The `call()` method takes a
`use_dbg_extension=False` kwarg for that.

Auth: the Ghidra upstream requires `Authorization: Bearer <token>`
when bound to non-loopback. We pass the token from
`$RE_BREAKER_GHIDRA_AUTH_TOKEN` (or, for non-loopback, from
`x-ghidra-mcp-auth-token` which the Ghidra bridge also accepts).
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from typing import Any, Iterator, Optional

log = logging.getLogger("re-vm-bridge.proxy")


class BridgeProxyError(RuntimeError):
    pass


class BridgeProxy:
    """SSE-MCP proxy to a single upstream (idalib-mcp / ghidra-mcp / x64dbg-mcp).

    Lifecycle:
        BridgeProxy(name, port, auth_token=...) → open
        proxy.call("tool_id", foo="bar") → dict
        proxy.stream("tool_id", foo="bar") → Iterator[dict]
        proxy.close()  # idempotent
    """

    def __init__(
        self,
        name: str,
        local_port: int,
        upstream_path: str = "/mcp",
        auth_token: Optional[str] = None,
        use_dbg_extension: bool = False,
        timeout_s: float = 60.0,
    ):
        self.name = name
        self.local_port = local_port
        self.base_url = f"http://127.0.0.1:{local_port}{upstream_path}"
        # Auto-detect transport: upstream_path="/sse" is the LEGACY
        # MCP-over-SSE transport (GET /sse + POST /message). All other
        # paths (typically /mcp) are the MODERN MCP Streamable-HTTP.
        self._transport = "sse-legacy" if upstream_path == "/sse" else "streamable-http"
        # For the legacy transport, `base_url` is the GET /sse URL;
        # POSTs go to a session-specific `/message?sessionId=...` URL
        # captured from the first SSE event. `_legacy_sse_thread` runs
        # the GET /sse subscriber in the background.
        self._session_id: Optional[str] = None
        self._legacy_post_url: Optional[str] = None
        self._legacy_event_q: Optional["queue.Queue[dict]"] = None
        self._legacy_sse_thread: Optional[threading.Thread] = None
        self._legacy_ready = threading.Event()
        if use_dbg_extension:
            sep = "&" if "?" in self.base_url else "?"
            self.base_url = f"{self.base_url}{sep}ext=dbg"
        self.auth_token = auth_token
        self.timeout_s = timeout_s
        self._id = 0
        self._client = None
        self._start_time: Optional[float] = None
        self._tool_count = 0

    def __enter__(self) -> "BridgeProxy":
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def open(self) -> None:
        """Open the httpx client (streamable-http) or start the SSE
        subscriber (legacy). The SSH tunnel is set up by the caller."""
        if self._client is not None or self._legacy_sse_thread is not None:
            return
        if self._transport == "sse-legacy":
            self._open_legacy()
        else:
            import httpx  # lazy import so re-vm-bridge works without httpx-sse
            self._client = httpx.Client(timeout=self.timeout_s)
            try:
                resp = self._raw_call("tools/list", {})
                log.info("bridge[%s] handshake ok on %s (got %d bytes)", self.name, self.base_url, len(resp))
            except Exception as e:
                self._client.close()
                self._client = None
                raise BridgeProxyError(f"failed to connect to upstream {self.name} at {self.base_url}: {e}")
        self._start_time = time.time()

    def _open_legacy(self) -> None:
        """Open the legacy MCP-over-SSE connection: GET /sse.
        A background thread reads the entire stream and pushes each
        parsed JSON event into a queue. The main thread waits on
        the queue for the initial 'endpoint' event to capture the
        /message?sessionId=... URL, then makes tool calls."""
        import httpx
        from urllib.parse import urlparse, parse_qs
        sse_url = self.base_url
        self._legacy_event_q = queue.Queue()
        self._legacy_endpoint = threading.Event()
        self._client = httpx.Client(timeout=None)
        try:
            req = self._client.build_request("GET", sse_url, headers={"Accept": "text/event-stream"})
            resp = self._client.send(req, stream=True)
            if resp.status_code != 200:
                resp.close()
                raise BridgeProxyError(f"GET {sse_url} returned {resp.status_code}")
            # Start the reader thread with the streaming response.
            # The thread reads from the response and pushes parsed
            # JSON events into the queue. It also signals the endpoint
            # event so we can extract the /message URL.
            self._legacy_sse_thread = threading.Thread(
                target=self._legacy_sse_reader, args=(resp,),
                daemon=True,
            )
            self._legacy_sse_thread.start()
            # Wait for the endpoint event
            if not self._legacy_endpoint.wait(timeout=self.timeout_s):
                raise BridgeProxyError("timed out waiting for /message endpoint")
            q = urlparse(self._legacy_post_url)
            params = parse_qs(q.query)
            if "sessionId" in params:
                self._session_id = params["sessionId"][0]
            # Initial tools/list to confirm the connection works
            result = self._raw_call("tools/list", {})
            log.info("bridge[%s] legacy handshake ok", self.name)
        except Exception as e:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            raise BridgeProxyError(
                f"failed to connect to legacy upstream {self.name} at {self.base_url}: {e}"
            )

    def _legacy_sse_reader(self, resp) -> None:
        """Background thread: reads from the streaming GET /sse
        response, parses each `data: ` line as a JSON event, and
        routes them to `_legacy_event_q` keyed by `id`. On the
        first 'endpoint' event, signals `_legacy_endpoint` and
        captures the /message URL.

        v0.5.8: BUFFER across chunks. v1.3 of x64DbgMCPServer chunks
        the GET /sse body at the TCP layer (1024-byte chunks); a
        single `data: <json>` line can be split across N chunks. The
        previous per-chunk `splitlines()` parsed a truncated JSON
        blob and silently dropped the rest of the event. We now
        accumulate into a buffer and split on SSE event boundaries
        (blank line, i.e. ``\\n\\n``)."""
        buf = b""
        try:
            for chunk in resp.iter_bytes():
                if not chunk:
                    break
                buf += chunk
                # Process complete SSE events (delimited by a blank
                # line). Keep the trailing partial event in the buf
                # for the next chunk.
                while b"\n\n" in buf:
                    event_bytes, buf = buf.split(b"\n\n", 1)
                    text = event_bytes.decode("utf-8", errors="replace")
                    data = None
                    for line in text.splitlines():
                        if line.startswith("data: "):
                            data = line[len("data: "):]
                            break
                    if data is None:
                        continue
                    if not self._legacy_endpoint.is_set():
                        # The first event is the endpoint URL.
                        base = f"http://127.0.0.1:{self.local_port}"
                        self._legacy_post_url = base + data if data.startswith("/") else base + "/" + data
                        self._legacy_endpoint.set()
                        log.info("bridge[%s] legacy POST URL: %s", self.name, self._legacy_post_url)
                        continue
                    # Subsequent events are JSON-RPC responses.
                    try:
                        obj = json.loads(data)
                        req_id = obj.get("id")
                        if req_id is not None:
                            self._legacy_event_q.put((req_id, obj))
                    except Exception:
                        pass
        except Exception as e:
            log.warning("bridge[%s] legacy SSE reader exited: %s", self.name, e)

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        # The legacy SSE subscriber thread is daemon=True so it'll die
        # with the process; we just signal the queue to stop.
        if self._legacy_event_q is not None:
            try:
                self._legacy_event_q.put_nowait(None)
            except Exception:
                pass

    def _raw_call_legacy(self, method: str, params: dict[str, Any]) -> dict:
        """Legacy transport: POST to the captured /message URL,
        wait on the queue for a response with the matching id."""
        if self._legacy_post_url is None:
            raise BridgeProxyError("legacy transport: post URL not established")
        req_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }
        resp = self._client.post(
            self._legacy_post_url,
            json=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            timeout=self.timeout_s,
        )
        resp.raise_for_status()
        # The response body might be the JSON-RPC result OR an ack
        # (the actual response comes back over the GET /sse stream).
        try:
            direct = resp.json()
            if "id" in direct and direct["id"] == req_id and "result" in direct:
                # Direct JSON response (some legacy upstreams)
                self._tool_count += 1
                return direct.get("result", direct)
        except Exception:
            pass
        # Wait for the SSE reader to push our response
        if self._legacy_event_q is None:
            raise BridgeProxyError("legacy transport: event queue not initialized")
        deadline = time.time() + self.timeout_s
        while time.time() < deadline:
            try:
                item = self._legacy_event_q.get(timeout=0.5)
            except Exception:
                continue
            if item is None:
                break
            rid, obj = item
            if rid == req_id:
                if "error" in obj and obj["error"]:
                    raise BridgeProxyError(f"upstream {self.name} error: {obj['error']}")
                self._tool_count += 1
                return obj.get("result", obj)
        raise BridgeProxyError(
            f"upstream {self.name} legacy: timed out waiting for response to id={req_id}"
        )

    @property
    def is_open(self) -> bool:
        return self._client is not None

    @property
    def age_sec(self) -> float:
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    def _headers(self) -> dict[str, str]:
        # The MCP Streamable-HTTP transport allows the server to
        # respond with EITHER application/json (one-shot) or
        # text/event-stream (long-lived). We accept both so the
        # upstream picks the better fit for the call.
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _raw_call(self, method: str, params: dict[str, Any]) -> dict:
        """Send one JSON-RPC call; return the `result` field."""
        if self._client is None and self._legacy_sse_thread is None:
            raise BridgeProxyError("not open")
        # Legacy transport: POST to /message?sessionId=...; response
        # comes back over the GET /sse subscriber thread.
        if self._transport == "sse-legacy":
            return self._raw_call_legacy(method, params)
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params,
        }
        # The MCP Streamable-HTTP transport returns a Mcp-Session-Id
        # header on the first successful POST; subsequent calls MUST
        # echo it back. We capture it on the first call and add it
        # to all subsequent headers.
        if self._session_id is None and method != "initialize":
            # Force an initialize call to establish the session.
            try:
                self._raw_call("initialize", {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "re-breaker-bridge", "version": "0.5.2"},
                })
            except BridgeProxyError:
                # Some upstreams (older idalib-mcp) don't require
                # initialize; tolerate that.
                pass
        headers = self._headers()
        if self._session_id is not None:
            headers["Mcp-Session-Id"] = self._session_id
        resp = self._client.post(self.base_url, json=payload, headers=headers)
        # Capture the session ID on the first successful response
        # (httpx headers are case-insensitive for get()).
        if self._session_id is None:
            sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
            if sid:
                self._session_id = sid
                log.info("bridge[%s] captured session id: %s", self.name, sid[:16])
        resp.raise_for_status()
        # The Streamable-HTTP transport allows the server to respond
        # with EITHER application/json (one-shot) or text/event-stream
        # (long-lived). Handle both.
        ctype = resp.headers.get("Content-Type", "").lower()
        if "application/json" in ctype:
            # One-shot JSON response.
            obj = resp.json()
            if "error" in obj and obj["error"]:
                raise BridgeProxyError(f"upstream {self.name} error: {obj['error']}")
            self._tool_count += 1
            return obj.get("result", obj)
        if "text/event-stream" in ctype:
            # SSE response; the first `data: ` line is the JSON-RPC result.
            try:
                from httpx_sse import EventSource
                es = EventSource(resp)
                for event in es.iter_sse():
                    if event.data:
                        obj = json.loads(event.data)
                        if "error" in obj and obj["error"]:
                            raise BridgeProxyError(f"upstream {self.name} error: {obj['error']}")
                        self._tool_count += 1
                        return obj.get("result", obj)
                raise BridgeProxyError(f"upstream {self.name} closed SSE without data")
            except ImportError:
                # Hand-rolled SSE parser
                data_line = None
                for line in resp.text.splitlines():
                    if line.startswith("data: "):
                        data_line = line[6:]
                        break
                if data_line is None:
                    raise BridgeProxyError(f"upstream {self.name} returned no SSE data")
                obj = json.loads(data_line)
                if "error" in obj and obj["error"]:
                    raise BridgeProxyError(f"upstream {self.name} error: {obj['error']}")
                self._tool_count += 1
                return obj.get("result", obj)
        # Unknown content type
        raise BridgeProxyError(
            f"upstream {self.name} returned unexpected Content-Type: {ctype!r}"
        )

    def call(self, tool: str, use_dbg_extension: bool = False, **kwargs) -> dict:
        """Call an MCP method by name. The MCP transport exposes a
        fixed method set (`initialize`, `tools/list`, `tools/call`,
        `notifications/...`, etc.). Pass the method name as `tool`
        and the method params as kwargs."""
        url = self.base_url
        if use_dbg_extension:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}ext=dbg"
        prev_url = self.base_url
        self.base_url = url
        try:
            # If `tool` is one of the standard MCP methods
            # (tools/list, initialize, etc.) the params are the
            # method params; otherwise it's a `tools/call` with
            # `{name: tool, arguments: kwargs}`.
            if tool in ("initialize", "tools/list", "ping"):
                return self._raw_call(tool, kwargs or {})
            return self._raw_call("tools/call", {"name": tool, "arguments": kwargs})
        finally:
            self.base_url = prev_url

    def stream(self, tool: str, **kwargs) -> Iterator[dict]:
        """Stream a long-running tool call (e.g. x64dbg continue_execution).
        Yields each SSE event as a dict."""
        if self._client is None:
            raise BridgeProxyError("not open")
        try:
            from httpx_sse import EventSource
        except ImportError:
            raise BridgeProxyError("httpx-sse required for streaming calls")
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {"name": tool, "arguments": kwargs},
        }
        headers = self._headers()
        if self._session_id is not None:
            headers["Mcp-Session-Id"] = self._session_id
        with self._client.stream("POST", self.base_url, json=payload, headers=headers) as resp:
            resp.raise_for_status()
            es = EventSource(resp)
            for event in es.iter_sse():
                if event.data:
                    obj = json.loads(event.data)
                    yield obj


# ----------------------------------------------------------------------------
# Convenience: a registry of named proxies
# ----------------------------------------------------------------------------

_REGISTRY: dict[str, BridgeProxy] = {}


def get_or_open(name: str, **kwargs) -> BridgeProxy:
    """Get an existing proxy by name, or open a new one with the
    given kwargs (forwarded to `BridgeProxy.__init__`)."""
    p = _REGISTRY.get(name)
    if p is not None and p.is_open:
        return p
    p = BridgeProxy(name=name, **kwargs)
    p.open()
    _REGISTRY[name] = p
    return p


def close(name: str) -> bool:
    p = _REGISTRY.pop(name, None)
    if p is None:
        return False
    p.close()
    return True


def list_open() -> list[dict[str, Any]]:
    return [
        {"name": n, "age_sec": p.age_sec, "tool_count": p._tool_count, "endpoint": p.base_url}
        for n, p in _REGISTRY.items()
        if p.is_open
    ]


__all__ = [
    "BridgeProxy",
    "BridgeProxyError",
    "get_or_open",
    "close",
    "list_open",
]
