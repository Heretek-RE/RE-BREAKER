# Denuvo Bypass Technique Summary — How Attackers Defeat Denuvo

**Status:** RE-only on this engagement. No deploy, no build, no execution.

**Sources:**
- `simplesvm_re_notes.md` — the AMD-V path
- `hyperkd_re_notes.md` — the Intel VT-x path
- `coldloader_re_notes.md` — the in-proc injection shim
- `Input/Crimson.Desert.Build.23578264-DenuvOwO/` — the packaged attacker build
  (the entire RE basis)

This document is the **operator-facing** summary of the Denuvo bypass
technique, in the format of `docs/PLAYBOOKS/denuvo-hypervisor-technique.md`.

---

## 1. The high-level technique

Denuvo's anti-tamper (ATD) is implemented as a per-game thread that:
1. Issues CPUID + RDTSC + RDPMC to detect if the code is running under a
   hypervisor or debugger
2. Reads `KUSER_SHARED_DATA` (Windows' per-process read-only structure) to
   verify the OS environment hasn't been tampered with
3. Reads DR3 (a debug register) to identify the Denuvo thread itself
4. Issues `CPUID(0x1337, ...)` as a handshake to signal "ready to proceed"
5. Calls SteamAPI to verify the Steam CEG layer

The DenuvOwO technique defeats steps 1-4 by **interposing on CPUID and
KUSER_SHARED_DATA for the targeted process only**:
- The hypervisor loads on the host (a Type-2 hypervisor that runs beneath
  the Windows kernel)
- The hypervisor checks every CPUID exit: if `DR3 == 0x7FFE0FF0` (the
  Denuvo thread marker set by the per-game `cd_id.dll`), the hypervisor
  returns spoofed CPUID values
- The hypervisor also maps a fresh `KUSER_SHARED_DATA` page for the
  targeted process, populated with hard-coded "clean" values

The technique is the **same** on AMD-V (SimpleSvm) and Intel VT-x
(HyperDbg fork) — the only difference is the underlying hypervisor
technology.

---

## 2. The 5-step deploy on a Windows host

Per `DenuvOwO.nfo`, the operator must:

1. **Disable VBS / HVCI** — run `VBS.cmd` as administrator (this disables
   Virtualization-Based Security + Hypervisor-Protected Code Integrity,
   which would otherwise prevent the SimpleSvm / hyperkd drivers from
   loading)
2. **Copy the DenuvOwO folder to the game's directory** — the deploy
   expects `CrimsonDesert.exe` to be in the same directory as
   `DenuvOwO.ini`, `cd_id.dll`, and the `coldclient/` subdir
3. **Configure `DenuvOwO.ini`** — `Targets=CrimsonDesert.exe`,
   `AutoLoadHV=true`, `[LoadDlls]` lists the coldloader + id_dll
4. **Launch the game** — if `AutoLoadHV=true`, the hypervisor loads
   automatically; if false, the operator must `sc create SimpleSvm
   type=kernel binPath=...` and `sc start SimpleSvm`
5. **The game runs without Denuvo interference** — the per-game `cd_id.dll`
   sets `DR3=0x7FFE0FF0` and issues `CPUID(0x1337, 0, target_PID)` to
   register; the hypervisor then spoofs the CPUID + KUSER_SHARED_DATA
   for the targeted process only

---

## 3. The 3 components in detail

### 3.1 The hypervisor driver (`SimpleSvm.sys` or `hyperkd.sys`)

- **AMD path:** `SimpleSvm.sys` (Satoshi Tanda's SimpleSvm, MIT-licensed,
  ~3000 LOC, well-understood)
- **Intel path:** `hyperkd.sys` + `hyperhv.dll` + `hyperevade.dll`
  (HyperDbg fork, GPLv2, ~62K LOC, complex but well-documented upstream)
- Both interpose on CPUID, RDTSC, RDPMC, MSR (specifically LSTAR for
  syscall handling)
- Both check `DR3 == 0x7FFE0FF0` and `(DR7 & 0xF0000040) == 0x40` to
  identify the Denuvo thread
- Both spoof CPUID leaves 0x1, 0x80000002-0x80000004 (and the KUSER_SHARED_DATA)
  only for the tracked process

### 3.2 The per-game `cd_id.dll` (1.5 KB)

- A trivial DLL with no logic other than `DllMain` (which sets
  `DR3 = 0x7FFE0FF0` and issues `CPUID(0x1337, 0, target_PID)`)
- Per-game constants in the binary (the actual values are in the
  `cd_id.dll` shipped with the DenuvOwO build; we don't have the
  source — the RE basis is the binary's symbol table)
- Loaded via `[LoadDlls] 1=cd_id.dll` in `DenuvOwO.ini`

### 3.3 The `coldclient/coldloader.dll` (1.5 KB)

- The in-proc injection shim (also loaded via `[LoadDlls]`)
- Calls `LoadLibraryW(L"cd_id.dll")` to trigger the per-game handshake
- Wraps the gbe_fork Steam API surface (so the `steam_settings/`
  config works as expected)
- Has 5 sections per `file` output (the smallest section is the
  `cd_id.dll` indirect-load trampoline)

---

## 4. The per-target patch table

`DenuvOwO.ini` is the per-target config. The format is:

```ini
[Config]
Targets=CrimsonDesert.exe
AutoLoadHV=true
GoRevertMsg=true
Capcom=false

[LoadDlls]
0=coldclient\coldloader.dll
1=cd_id.dll

[Sections]
CrimsonDesert.exe=auto

[Patches:CrimsonDesert.exe]
; Format: <rva_as_hex>=<patch_as_hex_string>
123EC71B=48BBBA5600000100100190

[Hashes]
CrimsonDesert.exe=7126be19957462f7
```

For each new target, the operator must:
- Set `Targets=<game>.exe`
- Update `[LoadDlls]` to point to the per-game `id_dll`
- Update `[Patches:<game>.exe]` with the per-target patch RVA + bytes
  (the per-target patches are reverse-engineered from the binary)
- Update `[Hashes]` with the binary's SHA-256 prefix (for tamper detection)

The single CD patch `123EC71B=48BBBA5600000100100190` is a `mov rbx,
0x190110000000056ba` instruction — a Steam ID rewriter. Other targets
have different per-target patches depending on the engine (Denuvo's
patch surface is engine-specific).

---

## 5. Why this works (the deep technical reason)

Denuvo's anti-tamper runs in **user space** (in the game process) but
needs to make trust decisions about the **kernel + hypervisor** state.
The CPUID instruction is the canonical way to ask "is there a hypervisor
beneath me?" — but it's also a side-channel for "what CPU features does
this host have?". Denuvo uses both signals to detect tampering.

The DenuvOwO technique **lies** to the user-space Denuvo thread by:
1. Interposing on CPUID in the hypervisor (which is a higher privilege
   level than the user-space Denuvo thread can see)
2. Using the DR3 + DR7 magic as a "session key" to only spoof for the
   Denuvo thread (not for the rest of the system)
3. Using a per-game `id_dll` to set the DR3 magic at process start
4. Using `KUSER_SHARED_DATA` spoofing to hide the hypervisor's footprint
   from Denuvo's memory checks

This is the **canonical** user-space-to-hypervisor trust-bypass pattern.
It's been used by attackers for at least a decade (Denuvo-specific
variants since 2015; the DR3 magic + KUSER_SHARED_DATA spoof is in
multiple open-source hypervisor projects).

---

## 6. What this means for the engagement

Per the user's direction:
- **The DenuvOwO drivers are RE-only on this engagement.** No deploy, no
  build, no execution.
- The 7-target engagement does NOT need Denuvo bypass for any target:
  - P3R has Denuvo (confirmed via `data/wire_sigs/p3r.json`) but it's
    a contractual carve-out (SOW-X §P.1) — not in scope
  - CD has Denuvo (per the DenuvOwO packaged build) but the engagement
    stops at the entitlement-layer (Steam CEG); the Denuvo layer is
    out of scope
  - The other 5 targets (FM26, HKIA, 007FL, TWW3, LIR) do not have
    Denuvo at all
- The RE walkthrough is the **basis** for any future Windows-host
  engagement that needs Denuvo bypass
- The RE notes are the **threat model** for the 7-target engagement:
  the per-game id_dll approach + per-target patch table is the
  attacker technique we need to understand to defend against

---

## 7. The honest read

This technique is well-documented, mature, and broadly deployed by
attackers across the DRM-defeat ecosystem. The DenuvOwO packaged build
is just one example; similar techniques are in Empress, Steamless,
Goldberg, and various scene releases. The defense is not "we can hide
from the technique" — the defense is **server-side validation**:
- The Steam server can refuse to talk to a process whose CPUID brand
  string is "DenU OwOv CPU" (it can check the brand string at the
  CEG layer)
- The Windows kernel can refuse to load a driver whose hash isn't
  in the WHQL signature database
- Denuvo's ATD can be rewritten to use a more robust tamper check
  (e.g., check the actual CPU model + feature set against a
  per-user allowlist)

The technique will keep working as long as the attack surface (the
hypervisor abstraction) is itself a commodity. The defense is to
**not** rely on the CPUID brand string for trust decisions.

---

## 8. Pointers to the full RE walkthrough

- `simplesvm_re_notes.md` — the AMD-V path (SimpleSvm.cpp walkthrough)
- `hyperkd_re_notes.md` — the Intel VT-x path (HyperDbg fork overview)
- `coldloader_re_notes.md` — the in-proc injection shim
- `../patch_tables/crimson_desert.ini` — the per-target patch table
  (extracted from the DenuvOwO build's DenuvOwO.ini)
- `../id_dlls/cd_id.c` — the per-game id_dll C source (RE-extracted
  from the cd_id.dll binary)
- `docs/PLAYBOOKS/denuvo-hypervisor-technique.md` — the operator-facing
  playbook (links these notes together)
