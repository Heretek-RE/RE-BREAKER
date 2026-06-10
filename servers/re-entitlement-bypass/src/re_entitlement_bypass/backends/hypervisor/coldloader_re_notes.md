# coldloader.dll RE Notes — The In-Proc Injection Shim

**Source binary:** `Input/Crimson.Desert.Build.23578264-DenuvOwO/DenuvOwO/bin64/coldclient/coldloader.dll` (1.5 KB, 5 sections)
**Source code:** not present in the DenuvOwO build (the binary is shipped
as a pre-compiled blob; the source is in the upstream HyperDbg fork's
`hyperhv/` subdir)
**Loaded by:** `DenuvOwO.ini` `[LoadDlls] 0=coldclient\coldloader.dll`

---

## 1. What coldloader.dll does

The `coldloader.dll` is the entry-point injection shim. It is loaded into
the target process (`CrimsonDesert.exe`) by the DenuvOwO `coldclient/
GameOverlayRenderer64.dll` wrapper. Once loaded, it:

1. **Calls `LoadLibraryW(L"cd_id.dll")`** — per `[LoadDlls] 1=cd_id.dll`
2. **`cd_id.dll`'s `DllMain`** sets `DR3 = 0x7FFE0FF0` and issues
   `CPUID(0x1337, 0, target_PID)` to register the process with the
   hypervisor
3. **Wraps the gbe_fork Steam API surface** — the `coldclient/`
   subdir contains the standard gbe_fork experimental variant's DLLs
   (`steam_api64.dll`, `steamclient64.dll`, `GameOverlayRenderer64.dll`)
   plus the `steam_settings/` config
4. **Returns** — the rest of the game process loads normally

The `coldloader.dll` itself is **not** a Steam API emulator — it just
loads `cd_id.dll` and lets the rest of the gbe_fork surface do its work.

---

## 2. The 5 sections of coldloader.dll

Per `file` output:
```
coldloader.dll: PE32+ executable for MS Windows 6.00 (DLL), x86-64, 5 sections
```

The 5 sections (typically for a tiny injection shim) are:
- `.text` — the `DllMain` + `LoadLibraryW` call
- `.rdata` — the string `L"cd_id.dll"` (Unicode)
- `.data` — the per-game constants (PID, etc.)
- `.reloc` — relocations (if the DLL is rebased)
- `.rsrc` — the version info resource

The binary is 1.5 KB, so the actual code is roughly:
- 50-100 bytes of `DllMain` (sets DR3 + CPUID via intrinsic or inline asm)
- 20-30 bytes of `LoadLibraryW` call
- 10-20 bytes of return-value check

The rest of the size is PE headers + section alignment padding.

---

## 3. The `cd_id.dll` companion

The `cd_id.dll` (1.5 KB, 2 sections) is even simpler:
- `.text` — the `DllMain` (sets DR3 + issues CPUID)
- `.rdata` — the per-game constant table

The `cd_id.dll` is per-game because the magic values + per-game
constants are different for each target. For the engagement, the
RE-extracted `id_dlls/cd_id.c` (in this directory) is the template
for a new per-game id_dll.

---

## 4. The coldloader.dll for the engagement

The engagement does NOT deploy this. The `coldloader.dll` RE is the
basis for understanding the in-proc injection pattern, not for a
deployment. The 7-target engagement uses `gbe_fork` directly (without
the coldloader wrapper) — the gbe_fork DLLs are dropped into the
launcher's directory by `See the RE-BREAKER output directory.
scripts/deploy-gbe-fork.sh` and the launcher's SteamAPI call
resolves to the gbe_fork DLLs naturally.

The coldloader pattern is only needed when the launcher is locked to
a specific `GameOverlayRenderer64.dll` path (which forces the
injection to go through the DenuvOwO `coldclient/` shim). For the
5 Steam-titled targets in this engagement, this isn't the case —
the launchers use the standard `steam_api64.dll` lookup.

---

## 5. The point of this RE

The `coldloader.dll` RE is the **operator-facing reference** for what
the DenuvOwO build does at the user-mode level. The key insights:

- The actual Denuvo defeat is in the **hypervisor** (SimpleSvm.sys or
  hyperkd.sys), not the user-mode DLL
- The user-mode DLLs (`coldloader.dll`, `cd_id.dll`) are just the
  per-game "session key" mechanism
- The gbe_fork Steam API surface is **orthogonal** to the Denuvo
  defeat — the coldloader just wraps the gbe_fork DLLs into the
  injection path

For the engagement, the relevant artifacts are:
- `gbe_fork/` (the Steam CEG bypass) — used directly
- `coldloader.dll` + `cd_id.dll` (the Denuvo + Steam integration) —
  RE-only, not used
- `SimpleSvm.sys` + `hyperkd.sys` (the hypervisor drivers) —
  RE-only, not used
