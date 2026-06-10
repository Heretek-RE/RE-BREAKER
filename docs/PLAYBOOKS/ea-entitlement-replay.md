# Playbook: EA / Origin entitlement server replay (Lost In Random supplement)

**Target class**: EA-shipped games (LIR, Battlefield, FIFA, etc.) with an active Origin auth flow. This is the LIR supplement to `ea-origin-stub-drop.md` — for cases where the stub-drop doesn't satisfy the online entitlement re-check.

**Catalog entry**: `encrypted-vm.bytecode-interpreter.pattern-b` + `encrypted-vm.bytecode-interpreter.pattern-d`

**Expected runtime**: 120 minutes

**Success probability**: 0.4 (the EA auth protocol changes; replay is fragile)

**Tools**: `re-runtime-dump`, `re-frida`, `re-pcap`, `re-leak-scan`

## 0. Resolve the main binary (v0.3.0 NEW)

```bash
# For Unity IL2CPP launchers (FM26, HKIA, LIR, P3R)
re-il2cpp-triage --target=<launcher> --output=/tmp/<key>-il2cpp-triage.json

# For fresh targets (no prior analysis)
re-triage --target=<binary> --output=/tmp/<key>-triage.json
```

This step is required for the catalog match to return non-zero matches
on Unity IL2CPP targets (which it returned 0 for in v0.2.0). For
non-IL2CPP targets, it can be skipped.

## 1. Capture the Origin auth flow

```bash
# Use PCAP to capture the WinHTTP traffic from Core/Activation64.dll
sudo tcpdump -i any -w /tmp/lir-origin.pcap 'host auth.origin.com and tcp'

# Or use mitmproxy (RE-AI's re-mitm2swagger)
re-mitm2swagger --intercept --target=Core/Activation64.dll --output=/tmp/lir-mitm.flow
```

**Verify**:
- [ ] The Origin auth server URL is captured
- [ ] The request body has the entitlement token format
- [ ] The response has the entitlement grant

## 2. Document the entitlement token format

```bash
# The Origin entitlement token is typically:
# {
#   "client_id": "...",
#   "client_secret": "...",
#   "grant_type": "client_credentials",
#   "scope": "..."
# }
# Plus the entitlement grant:
# {
#   "entitlement_id": "...",
#   "user_id": "...",
#   "product_id": "...",
#   "entitled": true,
#   "expires_at": "..."
# }
```

**Verify**:
- [ ] The request body schema is documented
- [ ] The response body schema is documented
- [ ] The expiration semantics are understood (token lifetime, refresh logic)

## 3. Build a replay server

```python
# /tmp/replay_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class ReplayHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the request body
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        # Replay the captured response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {
            "access_token": "REPLAYED_TOKEN",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "REPLAYED_REFRESH",
        }
        self.wfile.write(json.dumps(response).encode())

HTTPServer(('127.0.0.1', 8080), ReplayHandler).serve_forever()
```

**Verify**:
- [ ] The replay server listens on 127.0.0.1:8080
- [ ] The replay server returns the same schema as the captured response

## 4. Configure the binary to use the replay server

```bash
# Use the hosts file to redirect auth.origin.com to 127.0.0.1
# (requires admin / root privileges)
echo "127.0.0.1 auth.origin.com" >> /etc/hosts

# Or use a proxy
mitmproxy --mode reverse:https://auth.origin.com --listen-port 8080
```

**Verify**:
- [ ] The binary's WinHTTP requests are routed to the replay server
- [ ] The entitlement check returns "entitled" (the replayed response)

## 5. Document the result

```bash
re-bypass-result --target=Core/Activation64.dll \
  --replay-server=/tmp/replay_server.py \
  --runtime-cost-minutes=120 \
  --catalog-match=encrypted-vm.bytecode-interpreter.pattern-d \
  --output=/tmp/lir-replay-bypass-result.md
```

## 6. Known limitations / next iterations

- [ ] **DRM-adjacent territory**. The LICENSE-OFFENSIVE.md clause applies; ensure your use case is authorized.
- [ ] The Origin auth protocol changes; the replay may break after Origin updates their auth flow.
- [ ] Online features (multiplayer, leaderboards) require additional entitlement checks beyond the launch entitlement.
- [ ] Some titles use a per-launch nonce; the replay needs to handle the nonce.
- [ ] Some titles use certificate pinning; the replay needs to provide a matching certificate.
- [ ] The replay is brittle; the stub-drop approach in `ea-origin-stub-drop.md` is more reliable.
