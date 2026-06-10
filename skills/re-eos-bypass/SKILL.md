---
name: re-eos-bypass
version: 0.1.0
status: implemented
family: entitlement
severity: high
catalog_entry: entitlement.eos-handshake-emulator
playbook: docs/PLAYBOOKS/entitlement-eos.md
---

# re-eos-bypass

**v0.1.0 implemented.** Detailed workflow for the Epic Online Services (EOS) handshake emulator. Defeats the EOS entitlement check at the launcher's network boundary. **Does NOT implement EOS Anti-Cheat (per SOW-X §Q.1 carve-out).**

## When to use this skill

The target's launcher is an EOS-titled binary and uses the EOS handshake for launch entitlement. Currently TWW3 (SOW-X) is the only target in scope that uses EOS. Triggers on phrases like:

- "EOS handshake"
- "Epic Online Services entitlement"
- "EOS_Initialize stub"
- "the EOS SDK is blocking the launcher"

## Gating — EOS Anti-Cheat carve-out

**This skill implements ONLY the EOS handshake entitlement bypass.** EOS Anti-Cheat (the AC product) is SOW-X's carve-out and is **NOT in scope** per SOW-X §Q.1. The emulator MUST NOT implement the EOS AC layer.

## Tools invoked

- `python3 emulator.py` — start the emulator (Python 3.11 stdlib only)
- `openssl` — generate self-signed cert on first run
- Manual: hosts file edit, optional iptables port redirect
- `re-winedbg.set_breakpoint` on `EOS_Initialize` in `EOSSDK-Win64-Shipping.dll`
- `re-winedbg.info_registers` — validation

## PoC artifact

`See the RE-BREAKER output directory.`

- `emulator.py` — Python HTTP server (~12 KB)
- `protocol.md` — EOS handshake protocol reverse notes
- `hosts.txt` — Wine hosts file entries
- `README.md`, `embargo.json`, `SHA256SUMS`

## Endpoints implemented

| Method | Path | EOS function | Purpose |
|--------|------|--------------|---------|
| GET | `/eos/v1/health` | (probe) | liveness |
| POST | `/eos/v1/auth/login` | `EOS_Auth_Login` | exchange external auth for access_token |
| GET | `/eos/v1/auth/verify` | `EOS_Auth_VerifyToken` | validate the access_token |
| POST | `/eos/v1/auth/logout` | `EOS_Auth_Logout` | invalidate the access_token |
| POST | `/eos/v1/connect/login` | `EOS_Connect_Login` | exchange auth for connect code |
| POST | `/eos/v1/connect/token` | `EOS_Connect_ExchangeCode` | exchange code for access_token |
| GET | `/eos/v1/ecom/entitlements` | `EOS_Ecom_QueryEntitlements` | per-user entitlement list |
| POST | `/eos/v1/plat/active` | `EOS_Plat_Active` | in-game heartbeat |

## Workflow

1. **Confirm the target uses EOS:**
   ```bash
   ls /path/to/<target>/EOSSDK-Win64-Shipping.dll
   strings /path/to/<target>/<launcher>.exe | grep -i "EOS_\|EOSSDK"
   ```
2. **Start the emulator:**
   ```bash
   cd See the RE-BREAKER output directory.
   python3 emulator.py --bind 127.0.0.1 --port 8443
   ```
3. **Create the Wine prefix + add hosts entries:**
   ```bash
   PREFIX=/tmp/re-breaker-wine-<target>
   WINEDEBUG=-all wineboot -i
   cat hosts.txt >> "$PREFIX/drive_c/windows/system32/drivers/etc/hosts"
   ```
4. **(Optional) Install the self-signed cert** OR **patch the SDK to skip cert validation** (re-patch-apply follow-up).
5. **(Optional) Redirect :443 to :8443** if the launcher hardcodes :443:
   ```bash
   sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443
   ```
6. **Spawn the target** (TWW3 also needs Steam CEG bypass):
   ```bash
   WINEDEBUG=-all WINEDLLOVERRIDES="steam_api64=n" \
       wine /path/to/<target>/<launcher>.exe
   ```

## What it defeats

- `EOS_Initialize` → returns `EOS_Success`
- `EOS_Auth_Login` → returns a valid access_token
- `EOS_Connect_Login` / `EOS_Connect_ExchangeCode` → returns a valid connect token
- `EOS_Ecom_QueryEntitlements` → returns the cached TWW3 entitlement (owned)
- `EOS_Plat_Active` → returns active=true

## What it does NOT defeat

- EOS Anti-Cheat (per SOW-X §Q.1 carve-out, NOT in scope)
- VAC / EAC / BattlEye / EAAC (different products)
- Production EOS servers (per SOW-X §K.2, production interaction prohibited)
- The AT (anti-tamper) layer — separate artifact (Warscape integrity)

## Validation

- **Emulator log** — confirm `POST /eos/v1/auth/login` arrives
- **winedbg breakpoint on `EOS_Initialize`** — confirm EAX=0
- **No EOS login dialog appears** after spawn
- **Binary proceeds to AT layer** (next gate, separate artifact)

## Limitations

- mTLS not implemented (likely not needed; verify by reversing the SDK)
- Response signing not implemented (likely not needed; verify by reversing the SDK)
- Additional request headers accepted but not validated
- Real TWW3 product_id is a placeholder (`ce66d76f4b1b4b2896a1b6cbd3`); reverse the SDK for the canonical ID

## Legal carve-out

Per **SOW-X §K.2** + **SOW-X §Q.1**:
- EOS handshake protocol analysis in scope
- EOS Anti-Cheat is SOW-X carve-out, NOT in scope
- Production EOS interaction prohibited
- Emulator MUST listen on 127.0.0.1 (loopback only)
- No traffic may leave the lab host

The emulator logs a warning if `--bind` is not a loopback address. The emulator does NOT implement any EOS AC layer.

## Embargo

180 days from Acceptance (default per MRTEA Part IV §1). See `embargo.json`.

## Related artifacts

- TWW3 plan: `See the RE-BREAKER output directory.` (Step 0 includes BOTH Steam CEG AND EOS bypass)
- Orchestrator: `skills/re-entitlement-bypass/SKILL.md`
- Steam CEG companion: `skills/re-steam-ceg-bypass/SKILL.md` (TWW3 needs both)
- Playbook: `docs/PLAYBOOKS/entitlement-eos.md`
- WINE.md §4
