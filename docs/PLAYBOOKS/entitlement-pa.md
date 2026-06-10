# Playbook: Defeating Pearl Abyss internal entitlement — Protocol emulator (TBD)

**Target class:** Pearl Abyss internal entitlement in PA-titled binaries
**Catalog entry:** `entitlement.pa-internal-protocol` (added v0.4.0)
**Expected runtime:** 45 minutes (includes protocol reverse for first use)
**Success probability:** TBD
**Tools:** `python3` (emulator — TBD), `re-winedbg`, manual hosts file

## Status: SCAFFOLD ONLY (PoC emulator not yet built)

This playbook documents the **scope and approach** for the Pearl Abyss internal
entitlement bypass. The PoC emulator is **not yet built** — the per-target
plan for Crimson Desert (SOW-X) marks this as a follow-up.

The PA internal entitlement handshake is presumed to be a custom protocol
between the launcher and `pers.exe` (Pearl Abyss Reporting Service) or
`hermessdkcorewrapper_release.dll` (Pearl Abyss Hermes SDK). Per the
engagement's Input/ inventory, CD ships:

- `pers.exe` (Pearl Abyss telemetry / reporting)
- `hermessdkcorewrapper_release.dll` (Hermes SDK core wrapper)
- `sentry.dll`, `crashpad_handler.exe` (crash reporting)

## 0. Resolve the main binary

| Target | SOW | Launcher | PA internal? |
|--------|-----|----------|--------------|
| Crimson Desert | O | `CrimsonDesert.exe` | yes — siblings `pers.exe`, `hermessdkcorewrapper_release.dll` |
| All other targets | L/M/N/P/Q | (respective launchers) | **no** |

## 1. Confirm the target uses PA internal entitlement

```bash
# Confirm pers.exe and hermessdkcorewrapper_release.dll are siblings
ls -la /Input/proprietary_engine_target/steamapps/common/Crimson\ Desert/bin64/ | grep -i "pers\|hermes"

# Confirm the launcher talks to pers.exe or hermes
strings /Input/proprietary_engine_target/steamapps/common/Crimson\ Desert/bin64/CrimsonDesert.exe | grep -i "pers\.exe\|hermessdk\|pearlabyss" | head -10

# Run the launcher without the bypass — confirm the PA login / entitlement failure
WINEDEBUG=-all wine /Input/proprietary_engine_target/steamapps/common/Crimson\ Desert/bin64/CrimsonDesert.exe
```

## 2. Build the PA internal protocol emulator (PoC artifact — TBD)

**This PoC does not yet exist.** To build it, the next session should:

1. **Capture the PA handshake traffic.** Run the launcher with mitmproxy and
   observe the requests to `pers.exe` or `hermessdkcorewrapper_release.dll`
   endpoint.
2. **Reverse the protocol.** For each request/response pair, identify:
   - The URL (or named pipe / Unix socket path)
   - The request body schema (JSON, protobuf, custom binary?)
   - The response body schema
   - The auth / signature scheme
3. **Implement the emulator** in Python, mirroring the IOI Account + EOS
   emulators' structure.
4. **Place at** `See the RE-BREAKER output directory.`.

## 3. Deploy the emulator (when built)

The deployment pattern mirrors the IOI Account + EOS emulators:

```bash
PREFIX=/tmp/re-breaker-wine-cd
WINEDEBUG=-all wineboot -i
# Add hosts file entries to route PA domains to 127.0.0.1
# (depends on the protocol's transport)
```

## 4. Spawn the target with both bypasses

CD needs BOTH the Steam CEG bypass AND the PA internal bypass.

```bash
# Steam CEG bypass
cd See the RE-BREAKER output directory.
cp steam_api64.dll "$PREFIX/drive_c/windows/system32/steam_api64.dll"

# (Future) PA internal emulator
# cd ../pa-internal-protocol
# python3 emulator.py --bind 127.0.0.1 --port 8443 &

WINEDEBUG=-all WINEDLLOVERRIDES="steam_api64=n" \
    wine /Input/proprietary_engine_target/steamapps/common/Crimson\ Desert/bin64/CrimsonDesert.exe
```

## 5. Failure modes (anticipated)

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Steam dialog still appears | Steam CEG bypass not deployed | See `entitlement-steam-ceg.md` |
| Launcher says "PA login required" | PA internal protocol handshake fails | Implement the PA emulator (TBD) |
| Binary reaches AT layer but the AT detection is tripped | That's the next gate, separate artifact | See `pattern-a-vmt-blackspace.md` for the AT bypass |
| `pers.exe` is itself DRM-protected | PA's internal service is hardened | Reverse `pers.exe` to find the IPC mechanism; emulator must mimic the full IPC |

## 6. Open questions (per the engagement findings)

1. **What transport does `pers.exe` use?** HTTPS to a `pearlabyss.com`
   domain? Named pipe? Localhost-only IPC? The Input/ inventory shows
   `pers.exe` is a standalone Windows executable, so the protocol is
   likely either:
   - HTTPS to a `pearlabyss.com` domain (route to 127.0.0.1)
   - Named pipe / Unix socket between the launcher and `pers.exe`
   - Localhost-only HTTP on a random port (lsof / netstat while running)
2. **Does the launcher call `pers.exe` directly, or via the Hermes SDK wrapper?**
   The Hermes SDK is the likely interface; reverse `hermessdkcorewrapper_release.dll`
   for the function calls.
3. **Is the entitlement response signed?** If so, the emulator needs the
   signing key (or to bypass the signature check via re-patch-apply).

## 7. Legal carve-out

Per **SOW-X §O.7**:
- Pearl Abyss entitlement protocol analysis is in scope for protocol analysis
- Production interaction with Pearl Abyss entitlement services is **prohibited**
- The emulator MUST listen on `127.0.0.1`
- The emulator MUST be routed via the Wine hosts file (not real DNS)
- No traffic may leave the lab host

## 8. Document the result

When the PoC is built, create `See the RE-BREAKER output directory.` (SOW-X, Finding O-001, 180-day default embargo).

End of playbook (scaffold only).
