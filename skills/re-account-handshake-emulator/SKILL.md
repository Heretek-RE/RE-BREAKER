---
name: re-ioi-account-emulator
version: 0.1.0
status: implemented
family: entitlement
severity: medium
catalog_entry: entitlement.ioi-account-protocol-emulator
playbook: docs/PLAYBOOKS/entitlement-ioi-account.md
---

# re-ioi-account-emulator

**v0.1.0 implemented.** Detailed workflow for the IO Interactive's IOI Account protocol emulator. Defeats the IOI Account entitlement check at the launcher's network boundary. **In-lab use only** (per SOW-X §L.6).

## When to use this skill

The target is 007 First Light (SOW-X) — the only target in scope that uses IOI Account instead of Steam CEG or EOS. Triggers on phrases like:

- "IOI Account"
- "Glacier entitlement"
- "007 First Light login bypass"
- "account.ioi.dk"
- "IOI Account handshake"

## Gating — SOW-X §L.6

Per SOW-X §L.6, in-lab protocol analysis is in scope. **Production interaction with IOI Account services is PROHIBITED.** The emulator MUST only listen on `127.0.0.1` and MUST be routed via the Wine hosts file override. No traffic may leave the lab host.

## Tools invoked

- `python3 emulator.py` — start the emulator (Python 3.11 stdlib only)
- `openssl` — generate self-signed cert on first run
- Manual: hosts file edit, optional iptables port redirect
- `re-winedbg.set_breakpoint` on the URL builder in `ioi_account_client.dll`
- `re-winedbg.read_memory` — validation

## PoC artifact

`See the RE-BREAKER output directory.`

- `emulator.py` — Python HTTP server (~11 KB)
- `protocol.md` — IOI Account protocol reverse notes
- `hosts.txt` — Wine hosts file entries
- `README.md`, `embargo.json`, `SHA256SUMS`

## Endpoints implemented

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` and `/health` and `/account/v1/health` | liveness probes |
| POST | `/account/v1/auth` | username/password → session_token |
| POST | `/account/v1/auth/refresh` | token refresh |
| GET | `/account/v1/entitlement/lookup` | per-user entitlement list |
| GET | `/account/v1/entitlement/<title_id>` | per-title entitlement |
| POST | `/account/v1/telemetry/heartbeat` | in-game heartbeat |
| POST | `/account/v1/logout` | invalidate the session |

## Workflow

1. **Confirm the target uses IOI Account:**
   ```bash
   ls /Input/007\ First\ Light/Retail/ | grep -i "ioi\|account"
   strings /Input/007\ First\ Light/Retail/007FirstLight.exe | grep -i "ioi\.dk\|glacier"
   ```
2. **Start the emulator:**
   ```bash
   cd See the RE-BREAKER output directory.
   python3 emulator.py --bind 127.0.0.1 --port 8443
   ```
3. **Create the Wine prefix + add hosts entries:**
   ```bash
   PREFIX=/tmp/re-breaker-wine-007fl
   WINEDEBUG=-all wineboot -i
   cat hosts.txt >> "$PREFIX/drive_c/windows/system32/drivers/etc/hosts"
   ```
4. **(Optional) Install the self-signed cert** OR **patch the IOI Account client to skip cert validation** (re-patch-apply follow-up).
5. **(Optional) Redirect :443 to :8443** if the launcher hardcodes :443:
   ```bash
   sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443
   ```
6. **Spawn the target:**
   ```bash
   WINEDEBUG=-all wine /Input/007\ First\ Light/Retail/007FirstLight.exe
   ```

## What it defeats

- `POST /account/v1/auth` (the username/password handshake) → returns a valid session_token
- `GET /account/v1/entitlement/lookup` → returns the cached 007FL entitlement (owned)
- `POST /account/v1/telemetry/heartbeat` → returns 200 OK

## What it does NOT defeat

- Production IOI Account servers (per SOW-X §L.6, production interaction prohibited)
- IOI Account mTLS or response signature verification (if present; see `protocol.md` open questions)
- VAC / EAC / BattlEye / EAAC (different products)
- The AT (anti-tamper) layer — separate artifact (Glacier 2 shielding)

## Validation

- **Emulator log** — confirm `POST /account/v1/auth` and `GET /account/v1/entitlement/lookup` arrive
- **winedbg breakpoint on the URL builder** — confirm the emulator receives the request
- **No IOI Account login screen appears** after spawn (or login is auto-bypassed)
- **Binary proceeds to AT layer** (next gate, separate artifact)

## Limitations (per `protocol.md` open questions)

- mTLS not implemented (likely not needed; verify by reversing the client)
- Response signing not implemented (likely not needed; verify by reversing the client)
- Additional request headers accepted but not validated

## Legal carve-out

Per **SOW-X §L.6**:
- In-lab protocol analysis is in scope
- Production interaction with IOI Account services is PROHIBITED
- Emulator MUST listen on 127.0.0.1 (loopback only)
- No traffic may leave the lab host

The emulator logs a warning if `--bind` is not a loopback address.

## Embargo

180 days from Acceptance (default per MRTEA Part IV §1). See `embargo.json`.

## Related artifacts

- 007FL plan: `See the RE-BREAKER output directory.` (Step 0 includes IOI Account emulator)
- Orchestrator: `skills/re-entitlement-bypass/SKILL.md`
- Playbook: `docs/PLAYBOOKS/entitlement-ioi-account.md`
- WINE.md §4
- Glacier shielding playbook: `docs/PLAYBOOKS/ioi-glacier-shielding.md` (the AT layer)
