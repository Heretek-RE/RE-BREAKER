# Playbook: Defeating IOI Account — Protocol emulator (lab-only)

**Target class:** IO Interactive's IOI Account client in IOI-titled binaries
**Catalog entry:** `entitlement.ioi-account-protocol-emulator` (added v0.4.0)
**Expected runtime:** 45 minutes (includes protocol reverse for first use)
**Success probability:** 0.80
**Tools:** `python3` (emulator), `re-winedbg` (validation), manual hosts file

## Gating — SOW-X §L.6

Per SOW-X §L.6, in-lab protocol analysis is in scope. Production interaction with IOI Account services is **PROHIBITED**. The emulator MUST only listen on `127.0.0.1` and MUST be routed via the Wine hosts file override.

## 0. Resolve the main binary

The IOI Account handshake fires at the launcher's load of `ioi_account_client.dll` (or similar — name varies by Glacier 2 build). Per-target:

| Target | SOW | Launcher | IOI Account? |
|--------|-----|----------|--------------|
| 007 First Light | L | `007FirstLight.exe` | yes |
| All other targets | M/N/P/O/Q | (respective launchers) | **no** |

## 1. Confirm the target uses IOI Account

```bash
# Confirm ioi_account_client.dll is a sibling of the launcher
ls -la /Input/007\ First\ Light/Retail/ | grep -i "ioi\|account"

# Confirm the launcher imports from the IOI Account client
strings /Input/007\ First\ Light/Retail/007FirstLight.exe | grep -i "ioi\.dk\|ioi_account\|glacier" | head -10

# Run the launcher without the bypass — confirm the IOI login screen or entitlement failure
WINEDEBUG=-all wine /Input/007\ First\ Light/Retail/007FirstLight.exe
```

## 2. Build the IOI Account emulator (PoC artifact)

The PoC is pre-built at `See the RE-BREAKER output directory.`. No compilation needed (Python stdlib only).

```bash
cd See the RE-BREAKER output directory.
python3 emulator.py --bind 127.0.0.1 --port 8443
# Self-signed cert generated automatically at cert.pem + key.pem
```

**Endpoints implemented (per `protocol.md`):**
- `GET /` and `GET /health` and `GET /account/v1/health` — liveness probes
- `POST /account/v1/auth` — username/password → session_token
- `POST /account/v1/auth/refresh` — token refresh
- `GET /account/v1/entitlement/lookup` and `GET /account/v1/entitlement/<title_id>` — entitlement queries
- `POST /account/v1/telemetry/heartbeat` — in-game heartbeat
- `POST /account/v1/logout` — invalidate the session

## 3. Deploy the emulator + Wine routing

### 3a. Add hosts file entries to the Wine prefix

```bash
PREFIX=/tmp/re-breaker-wine-007fl
WINEDEBUG=-all wineboot -i
cat See the RE-BREAKER output directory. >> \
    "$PREFIX/drive_c/windows/system32/drivers/etc/hosts"
```

This routes `account.ioi.dk`, `api.ioi.dk`, `entitlement.ioi.dk`, `auth.ioi.dk`, `telemetry.ioi.dk` to `127.0.0.1`.

### 3b. Optional: install the self-signed cert in the Wine cert store

```bash
wine reg add "HKCU\Software\Microsoft\SystemCertificates\Root\Certificates" \
    /v "IOI Emulator CA" /t REG_BINARY /d "$(base64 -w0 cert.pem)" /f
```

If the IOI Account client does cert pinning and the launcher crashes on TLS handshake, **patch the client to skip cert validation** (re-patch-apply follow-up).

### 3c. Optional: redirect :443 to :8443 (if the launcher hardcodes :443)

```bash
sudo iptables -t nat -A OUTPUT -p tcp -d account.ioi.dk --dport 443 \
    -j DNAT --to-destination 127.0.0.1:8443
```

## 4. Spawn the target

```bash
WINEDEBUG=-all wine /Input/007\ First\ Light/Retail/007FirstLight.exe
```

**Expected:** The IOI Account login screen should appear with `en_redteam_lab` already logged in. Or the launcher may skip the login entirely and go straight to the main menu (depends on the launcher's flow).

## 5. Validate the bypass

### 5a. Emulator log

Check the emulator's stdout for the `POST /account/v1/auth` and `GET /account/v1/entitlement/lookup` requests from the launcher.

### 5b. winedbg breakpoint on the URL builder

```bash
$re-winedbg.start_winedbg_gdbserver(target="/path/to/007FirstLight.exe")
$re-winedbg.set_breakpoint(session="winedbg-007fl", address="ioi_account_client.<URL builder>")
$re-winedbg.continue_execution(session="winedbg-007fl")
$re-winedbg.read_memory(session="winedbg-007fl", address="<URL buffer>", size=256)
# Should show "https://127.0.0.1:8443/account/v1/auth" or similar
```

### 5c. Verify the entitlement lookup

```bash
curl -k https://127.0.0.1:8443/account/v1/entitlement/lookup
# Should return the cached 007FL entitlement
```

## 6. Failure modes

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| TLS handshake fails | Cert pinning rejection | Install self-signed cert OR patch client to skip cert validation |
| Launcher says "no network connection" | Hosts file entries not loaded | Check `$PREFIX/drive_c/windows/system32/drivers/etc/hosts` |
| Emulator logs the request but the launcher crashes | Response signature mismatch | See `protocol.md` open questions; add response signing |
| Binary reaches AT layer but the AT detection is tripped | That's the next gate, separate artifact | See `ioi-glacier-shielding.md` for the AT bypass |

## 7. Known limitations

- mTLS is not implemented (likely not needed for the entitlement handshake; verify by reversing the client).
- Response signing is not implemented (likely not needed; verify by reversing the client).
- Additional request headers (`X-IOI-Build`, etc.) are accepted but not validated.

## 8. Document the result

Per `See the RE-BREAKER output directory.` (SOW-X, Finding L-001, 180-day default embargo).

End of playbook.
