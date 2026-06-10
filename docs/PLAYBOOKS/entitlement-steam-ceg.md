# Playbook: Defeating Steamworks CEG — Launch entitlement bypass

**Target class:** Any Steam-titled binary that uses Steamworks CEG for launch entitlement
**Catalog entry:** `entitlement.steam-ceg-launch-bypass` (added v0.4.0)
**Expected runtime:** 20 minutes
**Success probability:** 0.95
**Tools:** `re-c-injection-build` (or just `mingw-w64`), `re-winedbg.write_memory` (validation), manual `cp` to Wine system32

## 0. Resolve the main binary (v0.3.0 NEW)

The Steam CEG fires at the launcher's import of `steam_api64.dll`. Per-target:

| Target | SOW | Launcher | Steam SKU |
|--------|-----|----------|-----------|
| Football Manager 26 | M | `fm.exe` | yes |
| Hello Kitty Island Adventure | N | `Hello Kitty.exe` | yes |
| Persona 3 Reload | P | `P3R.exe` | yes |
| Crimson Desert | O | `CrimsonDesert.exe` | yes (Steam SKU) |
| Total War: Warhammer 3 | Q | `Warhammer3.exe` | yes (TWW3 also loads EOS — see `entitlement-eos.md`) |

007 First Light (SOW-X) does **not** use Steam CEG — see `entitlement-ioi-account.md` instead.

## 1. Confirm the target uses Steam CEG

```bash
# Confirm steam_api64.dll is a sibling of the launcher
ls -la /path/to/<target>/steam_api64.dll

# Confirm the launcher imports from steam_api64
strings /path/to/<target>/<launcher>.exe | grep -i "steam_api\|SteamAPI_" | head -10

# Run the launcher without the bypass — confirm the Steam dialog
WINEDEBUG=-all wine /path/to/<target>/<launcher>.exe
# Expected: "Unable to initialize SteamAPI" dialog
```

## 2. Build the steam_api64 stub (PoC artifact)

The PoC is pre-built at `See the RE-BREAKER output directory.`. To rebuild:

```bash
cd See the RE-BREAKER output directory.
make check      # verify mingw-w64 is installed
make clean build verify
```

**Expected output:** `steam_api64.dll` (~101 KB, 16 exports: `SteamAPI_Init`, `SteamAPI_RestartAppIfNecessary`, `SteamAPI_Shutdown`, `SteamAPI_RunCallbacks`, `SteamAPI_GetHSteamPipe`, `SteamAPI_GetHSteamUser`, `SteamAPI_RegisterCallback`, `SteamAPI_UnregisterCallback`, `SteamAPI_RegisterCallResult`, `SteamAPI_UnregisterCallResult`, `SteamAPI_IsSteamRunning`, `SteamAPI_InitFlat`, `SteamInternal_ContextInit`, `SteamInternal_CreateGlobalInterface`, `SteamInternal_FindOrCreateUserInterface`, `SteamInternal_FindOrCreateGameServerInterface`).

## 3. Deploy the stub into a Wine prefix

```bash
# Create a per-session Wine prefix
PREFIX=/tmp/re-breaker-wine-<target>
WINEDEBUG=-all wineboot -i

# Drop the stub into Wine's system32 (overriding the real steam_api64.dll)
cp See the RE-BREAKER output directory. \
   "$PREFIX/drive_c/windows/system32/steam_api64.dll"
```

## 4. Force the launcher to use the stub

The launcher will look for `steam_api64.dll` either next to itself (sibling-import) or via the Wine system search path. To force Wine to prefer the system32 copy:

```bash
export WINEDLLOVERRIDES="steam_api64=n"
# n = native (system32) first, then built-in (PE builtin)
```

If the launcher bundles its own `steam_api64.dll` (sibling-import), the stub needs to be dropped next to the launcher too:

```bash
cp See the RE-BREAKER output directory. \
   /path/to/<target>/steam_api64.dll
```

## 5. Spawn the target with the bypass

```bash
WINEDEBUG=-all WINEDLLOVERRIDES="steam_api64=n" \
    wine /path/to/<target>/<launcher>.exe
```

**Expected:** The Steam dialog should NOT appear. The binary should proceed to the AT layer (Glacier shielding, Warscape integrity, etc.) or the main menu / EOS handshake (TWW3).

## 6. Validate the bypass

### 6a. winedbg breakpoint on `SteamAPI_Init`

```bash
# Start a winedbg session on the launcher
$re-winedbg.launch_under_wine(target="/path/to/<launcher>.exe")
$re-winedbg.start_winedbg_gdbserver(target="/path/to/<launcher>.exe")
# Set breakpoint on SteamAPI_Init in the stub
$re-winedbg.set_breakpoint(session="winedbg-<target>", address="steam_api64.SteamAPI_Init")
$re-winedbg.continue_execution(session="winedbg-<target>")
$re-winedbg.info_registers(session="winedbg-<target>", group="general")
# EAX (or RAX) should be 0 = k_ESteamAPIInitResult_OK
```

### 6b. Check the binary's import table

```bash
# Confirm the launcher is using the stub, not the real Steam API
$re-winedbg.info_modules(session="winedbg-<target>")
# Look for steam_api64.dll in the module list
```

### 6c. Verify the entitlement flow

The launcher's internal SteamAPI call site should see:
- `SteamAPI_Init` returns 0
- `SteamAPI_RestartAppIfNecessary` returns 0 (false)
- `SteamInternal_CreateGlobalInterface` returns a vtable whose `BIsSubscribedApp` always returns 1
- `SteamAPI_RunCallbacks` is a no-op

## 7. Failure modes

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Steam dialog still appears | Launcher uses bundled `steam_api64.dll` | Copy stub next to launcher too |
| Launcher crashes on SteamAPI_Init | The stub exports don't match what the launcher expects | Check `x86_64-w64-mingw32-objdump -p steam_api64.dll` for missing exports; add to stub |
| The stub is loaded but the launcher fails later | Entitlement check is multi-stage (e.g., EAC handshake) | Check if the game uses a second entitlement layer (Denuvo, EAC, etc.) |
| Binary reaches AT layer but the AT detection is tripped | That's the next gate, separate artifact | See `encrypted-vm-bytecode-interpreter-pattern-a.md` for Pattern A targets, `pattern-a-dw-denuvo.md` for UE5+Denuvo, etc. |

## 8. Known limitations

- The stub does **not** implement VAC or VAC Live. If the target uses VAC, the bypass is incomplete (VAC is SOW-X §J.5 carve-out, NOT in scope).
- The stub does **not** implement Steamworks DRM (CEG-only entitlement is bypassed; the actual game-content encryption is separate).
- The stub returns 0 to all `SteamAPI_Init` calls regardless of AppID. If the launcher has a hard-coded AppID check, that check is downstream and not bypassed by this PoC.

## 9. Document the result

Per `See the RE-BREAKER output directory.` (SOW-X, Finding J-001, 180-day default embargo).

End of playbook.
