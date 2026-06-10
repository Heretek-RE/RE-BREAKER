---
name: re-steam-ceg-bypass
version: 0.1.0
status: implemented
family: entitlement
severity: high
catalog_entry: entitlement.steam-ceg-launch-bypass
playbook: docs/PLAYBOOKS/entitlement-steam-ceg.md
---

# re-steam-ceg-bypass

**v0.1.0 implemented.** Detailed workflow for building the `steam_api64.dll` stub that defeats Steamworks CEG entitlement checks at the launcher's import boundary.

## When to use this skill

The target's launcher is a Steam SKU (5 of 6 SOW-bearing targets: FM26, HKIA, P3R, CD, TWW3). The launcher's first action is `SteamAPI_Init` to verify the user owns the title; if that fails, the Steam dialog "Unable to initialize SteamAPI" appears. Triggers on phrases like:

- "Steam CEG"
- "Steamworks entitlement"
- "steam_api64 stub"
- "the Steam dialog is blocking the launcher"
- "Unable to initialize SteamAPI"

## Tools invoked

- `x86_64-w64-mingw32-gcc` — cross-compile the stub
- Manual: `cp steam_api64.dll $WINEPREFIX/drive_c/windows/system32/`
- `re-winedbg.launch_under_wine` — Wine spawn with `WINEDLLOVERRIDES="steam_api64=n"`
- `re-winedbg.set_breakpoint` + `info_registers` — validation

## PoC artifact

`See the RE-BREAKER output directory.`

- `steam_api64_stub.c` — 16-export stub (~6.5 KB)
- `Makefile` — cross-compile recipe (mingw-w64)
- `steam_api64.dll` — built artifact (~101 KB, 16 verified exports)
- `README.md`, `embargo.json`, `SHA256SUMS`

## Workflow

1. **Confirm the target uses Steam CEG:**
   ```bash
   ls /path/to/<target>/steam_api64.dll
   strings /path/to/<target>/<launcher>.exe | grep -i "steam_api\|SteamAPI_"
   ```
2. **Build the stub:**
   ```bash
   cd See the RE-BREAKER output directory.
   make check      # verify mingw-w64
   make clean build verify
   ```
3. **Create the Wine prefix:**
   ```bash
   PREFIX=/tmp/re-breaker-wine-<target>
   WINEDEBUG=-all wineboot -i
   ```
4. **Drop the stub into system32:**
   ```bash
   cp steam_api64.dll "$PREFIX/drive_c/windows/system32/steam_api64.dll"
   ```
5. **(If launcher bundles steam_api64.dll) drop the stub next to the launcher:**
   ```bash
   cp steam_api64.dll /path/to/<target>/steam_api64.dll
   ```
6. **Spawn with the override:**
   ```bash
   WINEDEBUG=-all WINEDLLOVERRIDES="steam_api64=n" \
       wine /path/to/<target>/<launcher>.exe
   ```

## What it defeats

- `SteamAPI_Init` → returns `k_ESteamAPIInitResult_OK` for ALL AppIDs
- `SteamAPI_RestartAppIfNecessary` → returns false (no re-launch needed)
- `SteamInternal_CreateGlobalInterface` → returns a vtable whose `BIsSubscribedApp` always returns true
- All other Steamworks exports → no-op stubs

## What it does NOT defeat

- VAC / VAC Live (SOW-X §J.5 carve-out, NOT in scope)
- Steamworks DRM (separate from CEG entitlement; game content encryption)
- EOS Anti-Cheat / EAC / BattlEye / EAAC (different products)
- The AT (anti-tamper) layer — separate artifact

## Validation

- **winedbg breakpoint on `SteamAPI_Init`** — confirm EAX=0 after continue
- **No Steam dialog appears** after spawn
- **Binary proceeds to AT layer** (next gate)
- `make verify` — confirms 16 expected exports

## Limitations

- The stub returns OK to all AppIDs. If the launcher has a hard-coded AppID check downstream, that's a separate bypass.
- The stub does not implement VAC or VAC Live. If the target uses VAC, the bypass is incomplete.
- The stub returns success for the entitlement flow but does not implement Steam Cloud, Steam Workshop, or any non-entitlement Steamworks features.

## Legal carve-out

Per **SOW-X §J.3**: Steamworks CEG bypass research is in scope. PoC is abstract (defeats a class of CEG check, not a specific game). Per **MRTEA Part V §3.1-3.2**: PoC does not name a specific game in identifiers or banners.

## Embargo

180 days from Acceptance (default per MRTEA Part IV §1). See `embargo.json`.

## Related artifacts

- 5 per-target plans: `See the RE-BREAKER output directory.` (each has a "Step 0 — entitlement bypass" section)
- Orchestrator: `skills/re-entitlement-bypass/SKILL.md`
- Playbook: `docs/PLAYBOOKS/entitlement-steam-ceg.md`
- WINE.md §4
