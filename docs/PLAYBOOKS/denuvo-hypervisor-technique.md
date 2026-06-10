# Denuvo Hypervisor Bypass Technique (RE-only on this engagement)

**Status:** RE-only. No deploy, no build, no execution. The engagement
host is Wine (Linux). The DenuvOwO drivers require a real Windows host
+ admin + test signing.

**Origin:** The DenuvOwO packaged build at
`Input/Crimson.Desert.Build.23578264-DenuvOwO/` is the attacker build that
defeats CD's Denuvo. The RE walkthrough lives in
`servers/re-entitlement-bypass/src/re_entitlement_bypass/backends/hypervisor/*.md`.

---

## 1. How attackers defeat Denuvo (the 1-paragraph version)

A user-space hypervisor loads beneath the Windows kernel, identifies the
Denuvo thread via the DR3 debug register (set to magic value
`0x7FFE0FF0` by a per-game `cd_id.dll`), and spoofs CPUID + RDTSC + MSR +
`KUSER_SHARED_DATA` for that thread only. Denuvo's anti-tamper checks
return "clean" because the in-CPU values are falsified, but the actual
CPU is unmodified. The per-game `cd_id.dll` and the patch table in
`DenuvOwO.ini` are the per-target config.

---

## 2. The 5 components

| Component | Source | Role | Status |
|---|---|---|---|
| `SimpleSvm.sys` (AMD) | `DenuvOwO_SRC_V6/SimpleSvm/` (MIT) | AMD-V hypervisor driver | RE-only |
| `hyperkd.sys` + `hyperhv.dll` (Intel) | `DenuvOwO_SRC_V6/HypervisorSource/` (GPLv2) | Intel VT-x hypervisor | RE-only |
| `coldloader.dll` | `DenuvOwO/bin64/coldclient/` (1.5 KB, no source) | In-proc injection shim | RE-only |
| `cd_id.dll` (per-game) | `DenuvOwO/bin64/cd_id.dll` (1.5 KB, no source) | Per-game identity marker (sets DR3 + issues CPUID handshake) | RE-only |
| `DenuvOwO.ini` | `DenuvOwO/bin64/DenuvOwO.ini` (text config) | Per-target config: targets, LoadDlls, sections, patches, hashes | RE-only |

---

## 3. The 3 magic constants

| Magic | Value | Where | Purpose |
|---|---|---|---|
| `TargetDR3` | `0x7FFE0FF0` | `SimpleSvm.cpp:19` | Identifies the Denuvo thread (set by `cd_id.dll` at process start) |
| `SyscallBypassMagic` | `0x1337133713371337` | `SimpleSvm.cpp:20` | Placed in `KUSER_SHARED_DATA` at offset 0xFFC as the "ready to proceed" flag |
| `CPUID leaf 0x1337` | `0x1337` | `SimpleSvm.cpp:1104` | The handshake leaf: `CPUID(0x1337, 0, target_PID)` registers the process with the hypervisor |

The hypervisor checks every CPUID exit: if `DR3 == 0x7FFE0FF0` and
`(DR7 & 0xF0000040) == 0x40` and the call is in ring 3, the hypervisor
returns spoofed CPUID values for leaves `0x1`, `0x80000002`, `0x80000003`,
`0x80000004`. The spoofed values return the string "DenU OwOv CPU 1 @
73zHG" in the CPU brand string (which Denuvo's anti-VM check accepts
as "known-bad CPU").

---

## 4. The KUSER_SHARED_DATA spoofing

`KUSER_SHARED_DATA` is Windows' per-process read-only structure at
`0xFFFFF78000000000`. The hypervisor:
1. Allocates a new page (the "NewKuserSharedData")
2. Locks the original page with an MDL
3. Maps the new page at the same address for the targeted process
4. Fills the new page with hard-coded "clean" values
5. Writes `SyscallBypassMagic` at offset 0xFFC

The spoofed KUSER_SHARED_DATA includes `NtSystemRoot`, `ProcessorFeatures`,
and the system time fields. Denuvo's tamper checks see the spoofed
"clean" values.

---

## 5. The deploy on a real Windows host (5 steps)

1. **Disable VBS / HVCI** — run `VBS.cmd` as administrator
2. **Copy the DenuvOwO folder to the game's directory**
3. **Configure `DenuvOwO.ini`** — `Targets=CrimsonDesert.exe`, `AutoLoadHV=true`,
   `[LoadDlls]` lists the coldloader + id_dll
4. **Launch the game** — the hypervisor loads automatically (or via
   `sc create SimpleSvm type=kernel binPath=...` + `sc start SimpleSvm`)
5. **The game runs without Denuvo interference**

---

## 6. Per-target patch table (CD example)

`DenuvOwO.ini`:
```ini
[Patches:CrimsonDesert.exe]
; Format: <rva_as_hex>=<patch_as_hex_string>
123EC71B=48BBBA5600000100100190

[Hashes]
CrimsonDesert.exe=7126be19957462f7
```

The single CD patch is a `mov rbx, 0x190110000000056ba` (a Steam ID
rewriter). For each new target, the operator must:
- Update `Targets`
- Update `[LoadDlls]` for the per-game `id_dll`
- Update `[Patches:<target>.exe]` for the per-target patches
- Update `[Hashes]` for the binary's SHA-256 prefix (tamper detection)

---

## 7. RE walkthrough documents

| Document | Coverage |
|---|---|
| `backends/hypervisor/simplesvm_re_notes.md` | The AMD-V path (SimpleSvm.cpp walkthrough — the 3 magic constants, CPUID spoofing, KUSER_SHARED_DATA spoofing, process tracking) |
| `backends/hypervisor/hyperkd_re_notes.md` | The Intel VT-x path (HyperDbg fork overview — same technique, different hypervisor technology) |
| `backends/hypervisor/coldloader_re_notes.md` | The in-proc injection shim (coldloader.dll + cd_id.dll) |
| `backends/hypervisor/technique_summary.md` | The unified "how attackers defeat Denuvo" narrative |
| `backends/hypervisor/id_dlls/{template_id.c, cd_id.c}` | The per-game id_dll C source (RE-extracted) |
| `backends/hypervisor/patch_tables/{crimson_desert.ini, p3r_carveout.ini}` | The per-target patch tables |

---

## 8. The honest read

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

## 9. What this engagement uses

The 7-target engagement:
- **CD** uses DenuvOwO in the attacker build to defeat Denuvo — but
  the engagement does NOT deploy the DenuvOwO drivers (per the user's
  decision: no Windows host available)
- **P3R** has Denuvo (confirmed present per `data/wire_sigs/p3r.json`)
  but it's a contractual carve-out (SOW-X §P.1) — not in scope
- **The other 5 targets** (FM26, HKIA, 007FL, TWW3, LIR) do NOT have
  Denuvo

The RE walkthrough is the **threat model** for the engagement: the
per-game id_dll + per-target patch table is the attacker technique we
need to understand to defend against. The next session should:

1. Read the 4 RE walkthrough documents
2. Read the per-game id_dlls and patch tables
3. (Out of scope) Deploy the DenuvOwO hypervisor on a Win host

The RE walkthrough IS the deliverable. The deployment is a future plan
when a Win host is available.
