---
name: re-entitlement-bypass
version: 0.1.0
status: implemented
family: entitlement
severity: high
catalog_entry: entitlement.bypass-orchestrator
playbook: docs/PLAYBOOKS/entitlement-steam-ceg.md
---

# re-entitlement-bypass

**v0.1.0 implemented.** Generic orchestrator for entitlement-layer bypasses. Selects the right PoC artifact per target vendor and deploys it under Wine.

## When to use this skill

The target's launcher fires an entitlement dialog before the AT layer runs (Steam CEG for 5 of 6 SOW-bearing targets, EOS handshake for TWW3, IOI Account for 007FL, PA internal for CD). Triggers on phrases like:

- "bypass the entitlement check"
- "defeat Steam CEG"
- "skip the IOI login"
- "stub the EOS handshake"
- "the launcher is hitting a Steam dialog before our AT bypass runs"
- "the binary never reaches the AT layer"

## Tools invoked

- `mcp__re_entitlement_bypass.*` — re-entitlement-bypass (orchestrator; v0.1.0 plan-only)
- `re-c-injection-build.build_injection_library` — C library build (for hook specs)
- `re-winedbg.launch_under_wine` — Wine spawn
- `re-winedbg.set_breakpoint` + `info_registers` — validation
- Manual: `python3 emulator.py`, `cp steam_api64.dll`, hosts file edit, iptables

## Per-vendor mapping

| Vendor | SOW | PoC artifact | Entitlement layer |
|--------|-----|--------------|-------------------|
| Valve (Steam) | J | `See the RE-BREAKER output directory.` | Steam CEG |
| IO Interactive | L | `See the RE-BREAKER output directory.` | IOI Account |
| Epic Online Services | K | `See the RE-BREAKER output directory.` | EOS handshake |
| Pearl Abyss | O | (TBD) `See the RE-BREAKER output directory.` | PA internal protocol |

## Per-target deployment (5 of 6 SOW-bearing targets)

See `See the RE-BREAKER output directory.` for the per-target execution block.

## Workflow

1. **Identify the entitlement layer** — `strings <launcher>` for `SteamAPI_`, `EOS_`, `ioi_account`, or `pers.exe` imports.
2. **Select the PoC artifact** per the per-vendor mapping.
3. **Build / start the PoC**:
   - Steam CEG: `cd steam-ceg-bypass && make build`
   - IOI Account / EOS: `python3 emulator.py --bind 127.0.0.1 --port 8443 &`
4. **Create the Wine prefix** and deploy:
   - Steam CEG: `cp steam_api64.dll $WINEPREFIX/drive_c/windows/system32/`
   - IOI / EOS: append `hosts.txt` entries to `$WINEPREFIX/drive_c/windows/system32/drivers/etc/hosts`
5. **Spawn the target** with the bypass in place:
   - Steam CEG: `WINEDLLOVERRIDES="steam_api64=n" wine <launcher>.exe`
   - IOI / EOS: `wine <launcher>.exe` (hosts file routes to emulator)
6. **Validate** via winedbg breakpoint on the entitlement function (SteamAPI_Init, EOS_Initialize, etc.).

## Verification

- **No entitlement dialog appears** after spawn
- **winedbg breakpoint on the entitlement function** confirms the stub/emulator return value
- **Binary proceeds to AT layer** (next gate, separate artifact)

## Legal carve-out

- Steam CEG: SOW-X §J.3 in scope; bypass is abstract (defeats a class of CEG check, not a specific game)
- IOI Account: SOW-X §L.6 in scope; in-lab protocol analysis only; production interaction prohibited
- EOS handshake: SOW-X §K.2 in scope; EOS Anti-Cheat is SOW-X carve-out, NOT in scope
- PA internal: SOW-X §O.7 in scope; in-lab protocol analysis only

## Limitations

- The entitlement bypass does NOT defeat the AT layer. That's a separate artifact (Pattern A, A-DW, A-VMT, or C per the per-target plan).
- The entitlement bypass does NOT defeat VAC / EAC / BattlEye / EAAC (those are SOW carve-outs and NOT in scope).
- The entitlement bypass does NOT defeat Denuvo Anti-Cheat (separate product; SOW-X carve-out).

## Related artifacts

- 4 entitlement playbooks: `docs/PLAYBOOKS/entitlement-*.md`
- 3 PoC artifacts: `See the RE-BREAKER output directory.`
- Per-target plans: `See the RE-BREAKER output directory.`
- WINE.md §4: `docs/WINE.md` (entitlement-bypass stack documentation)
