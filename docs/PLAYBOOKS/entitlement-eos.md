# Playbook: Defeating EOS — Handshake entitlement bypass

**Target class:** Any EOS-titled binary that uses the EOS handshake for launch entitlement
**Catalog entry:** `entitlement.eos-handshake-emulator` (added v0.4.0)
**Expected runtime:** 30 minutes
**Success probability:** 0.85
**Tools:** `python3` (emulator), `re-winedbg` (validation), manual hosts file, `iptables` (port redirect)

## Gating — SOW-X EOS Anti-Cheat carve-out

**This playbook implements ONLY the EOS handshake entitlement bypass.** EOS Anti-Cheat (the AC product) is SOW-X's carve-out and is **NOT in scope** per SOW-X §Q.1. The emulator MUST NOT implement the EOS AC layer. Per SOW-X §K.2, the handshake protocol analysis is in scope; the AC protocol is not.

## 0. Resolve the main binary

The EOS handshake fires at the launcher's load of `EOSSDK-Win64-Shipping.dll`. Per-target:

| Target | SOW | Launcher | EOS? |
|--------|-----|----------|------|
| Total War: Warhammer 3 | Q | `Warhammer3.exe` | yes — siblings `EOSSDK-Win64-Shipping.dll`, `clockwork_crossplatform_eos.Release.x64.dll` |
| FM26, HKIA, P3R, CD, 007FL | M/N/P/O/L | (respective launchers) | **no** — these use Steam CEG or IOI Account |

## 1. Confirm the target uses EOS

```bash
# Confirm EOSSDK is a sibling of the launcher
ls -la /path/to/<target>/EOSSDK-Win64-Shipping.dll

# Confirm the launcher imports from EOSSDK
strings /path/to/<target>/<launcher>.exe | grep -i "EOS_\|EOSSDK" | head -10

# Run the launcher without the bypass — confirm the EOS dialog or entitlement failure
WINEDEBUG=-all wine /path/to/<target>/<launcher>.exe
```

## 2. Build the EOS emulator (PoC artifact)

The PoC is pre-built at `See the RE-BREAKER output directory.`. No compilation needed (Python stdlib only).

```bash
# Start the emulator
cd See the RE-BREAKER output directory.
python3 emulator.py --bind 127.0.0.1 --port 8443
# Self-signed cert generated automatically at cert.pem + key.pem
```

**Endpoints implemented (per `protocol.md`):**
- `GET /eos/v1/health` — liveness probe
- `POST /eos/v1/auth/login` — `EOS_Auth_Login` → returns access_token
- `GET /eos/v1/auth/verify` — `EOS_Auth_VerifyToken`
- `POST /eos/v1/auth/logout` — `EOS_Auth_Logout`
- `POST /eos/v1/connect/login` — `EOS_Connect_Login` → returns connect code
- `POST /eos/v1/connect/token` — `EOS_Connect_ExchangeCode`
- `GET /eos/v1/ecom/entitlements` — `EOS_Ecom_QueryEntitlements` → returns cached entitlement
- `POST /eos/v1/plat/active` — `EOS_Plat_Active` → heartbeat

## 3. Deploy the emulator + Wine routing

### 3a. Add hosts file entries to the Wine prefix

```bash
PREFIX=/tmp/re-breaker-wine-<target>
WINEDEBUG=-all wineboot -i
cat See the RE-BREAKER output directory. >> \
    "$PREFIX/drive_c/windows/system32/drivers/etc/hosts"
```

This routes `api.epicgames.dev` (and other EOS domains) to `127.0.0.1`.

### 3b. Optional: install the self-signed cert in the Wine cert store

```bash
# Add the self-signed cert to the Wine prefix's root CA store
wine reg add "HKCU\Software\Microsoft\SystemCertificates\Root\Certificates" \
    /v "EOS Emulator CA" /t REG_BINARY /d "$(base64 -w0 cert.pem)" /f
```

If the EOS SDK's cert pinning is strict and the launcher crashes on TLS handshake, **patch the SDK to skip cert validation** (re-patch-apply follow-up).

### 3c. Optional: redirect :443 to :8443 (if the launcher hardcodes :443)

```bash
sudo iptables -t nat -A OUTPUT -p tcp -d api.epicgames.dev --dport 443 \
    -j DNAT --to-destination 127.0.0.1:8443
```

## 4. Spawn the target

TWW3 also needs the Steam CEG bypass. See `entitlement-steam-ceg.md` for the Steam bypass; the two bypasses are independent and both are required.

```bash
# Steam CEG bypass (required for TWW3)
cd See the RE-BREAKER output directory.
PREFIX=/tmp/re-breaker-wine-tww3
cp steam_api64.dll "$PREFIX/drive_c/windows/system32/steam_api64.dll"

# Spawn with both bypasses
WINEDEBUG=-all WINEDLLOVERRIDES="steam_api64=n" \
    wine /Input/Total.War.Warhammer.III.v7.2.1/Total\ War\ WARHAMMER\ III/Warhammer3.exe
```

**Expected:** The Steam dialog AND the EOS login should NOT appear. The binary should proceed to the CA launcher / main menu.

## 5. Validate the bypass

### 5a. Emulator log

Check the emulator's stdout for the `POST /eos/v1/auth/login` request from the launcher.

### 5b. winedbg breakpoint on `EOS_Initialize`

```bash
$re-winedbg.start_winedbg_gdbserver(target="/path/to/Warhammer3.exe")
$re-winedbg.set_breakpoint(session="winedbg-tww3", address="EOSSDK-Win64-Shipping.EOS_Initialize")
$re-winedbg.continue_execution(session="winedbg-tww3")
$re-winedbg.info_registers(session="winedbg-tww3", group="general")
# EAX should be 0 (EOS_Success)
```

### 5c. Verify the entitlement lookup

```bash
curl -k https://127.0.0.1:8443/eos/v1/ecom/entitlements
# Should return the cached TWW3 entitlement
```

## 6. Failure modes

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| EOS SDK fails TLS handshake | Cert pinning rejection | Install self-signed cert OR patch SDK to skip cert validation |
| `EOS_Auth_Login` returns non-zero | The SDK expects a different auth flow (e.g., device code) | Reverse the SDK's `EOS_Auth_Login` impl; add the missing grant_type to the emulator |
| Entitlement lookup returns 404 | Wrong product_id | Reverse the SDK for the canonical TWW3 product_id; update `EMULATOR_ENTITLEMENT.product_id` in the emulator |
| Binary reaches AT layer but the AT detection is tripped | That's the next gate, separate artifact | See `ca-warscape-eos.md` for the AT bypass |

## 7. Known limitations

- The emulator does **not** implement EOS Anti-Cheat (SOW-X carve-out, NOT in scope).
- The emulator returns unsigned responses. If the SDK requires signed responses (JWT or similar), reverse the SDK's signature verification and add signing to the emulator.
- mTLS is not implemented (likely not needed for the entitlement handshake; verify by reversing the SDK).

## 8. Document the result

Per `See the RE-BREAKER output directory.` (SOW-X, Finding K-001, 180-day default embargo).

End of playbook.
