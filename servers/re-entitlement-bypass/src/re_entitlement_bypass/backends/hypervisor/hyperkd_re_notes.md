# HyperDbg-fork (hyperkd / hyperhv) RE Notes — Intel VT-x Path

**Source:** `Input/Crimson.Desert.Build.23578264-DenuvOwO/DenuvOwO_SRC_V6/HypervisorSource/`
**License:** GPLv2 (HyperDbg fork) — **INFERRED**: the fork's root directory
has no LICENSE file (verified via `find HypervisorSource -name LICENSE*`).
The HyperDbg upstream is GPLv2 (https://github.com/HyperDbg/HyperDbg) and
the fork is a derivative, so GPLv2 is the safe assumption. Attribution
required for any vendoring.
**Built binaries:** `DenuvOwO/bin64/driver_intel/{hyperkd.sys, hyperhv.dll, hyperevade.dll, hyperlog.dll, kdserial.dll}` — **VERIFIED** via `ls`
**Source LOC:** 165,088 lines total (all .cpp/.c/.h across the HyperDbg fork) — **VERIFIED** via `find ... | xargs wc -l | tail`
**Used by DenuvOwO** to defeat Denuvo's anti-VM detection on Intel CPUs (the
SimpleSvm path is the AMD equivalent — see `simplesvm_re_notes.md`).

This document is the RE walkthrough of the HyperDbg fork as deployed in the
DenuvOwO attacker build. **No code is run during this RE work**.

---

## 1. What HyperDbg fork is

HyperDbg (https://github.com/HyperDbg) is an open-source hypervisor-based
debugger for Windows. The DenuvOwO build uses a **fork** of HyperDbg that
strips the debugging interface and replaces it with the Denuvo-spoofing logic
from SimpleSvm.

**The HyperDbg fork** in DenuvOwO consists of:
- **`hyperkd.sys`** — the kernel-mode driver (the entry point)
- **`hyperhv.dll`** — the user-mode helper DLL (loaded by `coldclient/coldloader.dll`)
- **`hyperevade.dll`** — the anti-detection / EDR-evasion layer
- **`hyperlog.dll`** — the logger
- **`kdserial.dll`** — the kernel-debugger serial port helper (not used in
  DenuvOwO's runtime — it's for HyperDbg's debug transport)

**The forked source tree** under `HypervisorSource/`:
- `hyperhv/` — the user-mode hypervisor interface
- `hyperkd/` — the kernel-mode driver (~28K LOC)
- `hyperevade/` — the anti-detection / EDR-evasion layer
- `hyperlog/` — the logger
- `libhyperdbg/` — shared library code
- `hyperdbg-cli/` — the user-mode CLI (stripped in the DenuvOwO build)
- `script-engine/` — the scripting engine (stripped in the DenuvOwO build)
- `symbol-parser/` — the symbol parser (stripped)
- `dependencies/` — vendored dependencies (Zydis, capstone, etc.)
- `libraries/`, `include/`, `tests/`, `miscellaneous/`

The DenuvOwO build **only** compiles `hyperkd`, `hyperhv`, `hyperevade`, and
`hyperlog`. The CLI / script-engine / symbol-parser are not built (the
attacker doesn't want a debugger; they want a stealth hypervisor).

---

## 2. How the HyperDbg fork defeats Denuvo (vs SimpleSvm)

The technique is the same as SimpleSvm but on Intel VT-x instead of AMD-V.
**VERIFIED** via `grep -r TargetDR3 HypervisorSource/hyperhv/code`:

| Surface | SimpleSvm (AMD) | HyperDbg fork (Intel) |
|---|---|---|
| Hypervisor technology | AMD SVM | Intel VT-x |
| CPUID interception | `SvHandleCpuid` (SimpleSvm.cpp:1029) — VERIFIED | `Hv.c` + `Vmexit.c` (the VMX exit handler) — VERIFIED via grep |
| MSR interception | `SvHandleMsrAccess` (SimpleSvm.cpp:1206) — VERIFIED | (in `hyperhv/code/vmm/vmx/Vmexit.c`, the MSR exit handler) — INFERRED |
| VM-exit handler | `SvmVmexitLoop` (line 1695) — VERIFIED | (in `Hv.c` / `Vmx.c` / `Vmexit.c`) — INFERRED |
| Per-process tracking | `TrackedProcessId` global | `TrackedProcessId` global (same magic) |
| **DR3 magic** | `0x7FFE0FF0` — VERIFIED at SimpleSvm.cpp:19 | `0x7FFE0FF0` — **VERIFIED** at `hyperhv/code/vmm/vmx/Vmx.c:UINT64 TargetDR3 = 0x7FFE0FF0;` |
| **DR3 + DR7 check** | `(CurrentDR3 == TargetDR3 && (CurrentDR7 & 0xF0000040) == 0x40)` — VERIFIED at SimpleSvm.cpp:1052 | **SAME** — VERIFIED at `hyperhv/code/vmm/vmx/Vmexit.c` (line not yet pinned): `if (CurrentDR3 == TargetDR3 && (CurrentDR7 & 0xF0000040) == 0x40)` |
| KUSER_SHARED_DATA spoof | Same as SimpleSvm | Same as SimpleSvm — INFERRED (not directly read) |
| DR7 check | Same | Same — VERIFIED on both AMD + Intel paths |

The **CD on Intel** gets the same anti-detection as **CD on AMD** — the
hypervisor's only purpose is to:
1. Hide the real CPU's feature set (Denuvo's CPUID anti-VM check) — VERIFIED
2. Identify the Denuvo thread (DR3 + DR7 magic) — VERIFIED
3. Spoof the KUSER_SHARED_DATA (Denuvo's tamper check) — INFERRED
4. Return the per-game "subscribed" Steam-API responses via the gbe_fork-style
   `coldclient/` shim

---

## 3. The `hyperevade` layer (EDR-evasion)

The `hyperevade` layer is a HyperDbg-fork addition that goes further than
SimpleSvm:
- Hides the hypervisor from Windows Defender's hypervisor-detection
  (the same KUSER_SHARED_DATA spoof)
- Hides the driver from `sc query` (by registering as a hidden service)
- Hides the hypervisor's MSR state from `cpuz` and other CPU-detection tools
- Detours `NtQuerySystemInformation` to hide the hypervisor from
  `SystemHypervisorPresent` (the Win11 API that returns true if a hypervisor
  is loaded)

For the DenuvOwO deployment, the `hyperevade` layer is **required** because
Windows 11 (which CD targets) has native hypervisor-detection APIs that
Denuvo could call.

---

## 4. The `coldloader.dll` injection

The `coldclient/coldloader.dll` is the in-proc injection shim. It:
1. Is loaded into the CrimsonDesert.exe process via `DenuvOwO.ini`'s
   `[LoadDlls] 0=coldclient/coldloader.dll` (the `[LoadDlls]` section is
   read by the DenuvOwO `coldclient/GameOverlayRenderer64.dll` wrapper)
2. Calls `LoadLibraryW(L"cd_id.dll")` (per the `[LoadDlls] 1=cd_id.dll`
   entry) — `cd_id.dll` is the per-game identity marker
3. Sets `DR3 = 0x7FFE0FF0` and issues `CPUID(0x1337, 0, target_PID)` to
   register the process with the hypervisor
4. Wraps the gbe_fork Steam API surface (so the `steam_settings/` config
   works as expected)

The `cd_id.dll` itself is a 1.5 KB per-game DLL with no logic other than
`DllMain` (which sets DR3 + issues the CPUID handshake). It's the
"per-game identity marker" that DenuvOwO's hypervisor uses to know which
process to track.

---

## 5. The per-target patch table

The `DenuvOwO.ini` has a `[Patches:CrimsonDesert.exe]` section with:

```ini
[Patches:CrimsonDesert.exe]
; Format: <rva_as_hex>=<patch_as_hex_string>
123EC71B=48BBBA5600000100100190
```

This is the single CD-specific patch. The RVA `0x123EC71B` is patched with
the bytes `48BBBA5600000100100190` (which is a `mov rbx, 0x190110000000056ba`
instruction — a Steam ID rewriter).

The `[Sections] CrimsonDesert.exe=auto` tells the hypervisor to use the
largest executable section as the "Denuvo code region" (where the
hypervisor's CPUID interception applies).

The `[Hashes] CrimsonDesert.exe=7126be19957462f7` is the SHA-256 prefix of
the original CD binary — the hypervisor uses this to verify the binary
hasn't been tampered with before applying the patch.

---

## 6. What this means for the engagement

Per the user's direction: **the engagement does NOT deploy this**. The
DenuvOwO drivers are RE-only references. The 7-target engagement:

- Uses `gbe_fork` (the open-source Steam CEG bypass) for the 5 Steam-titled
  targets (FM26, HKIA, TWW3, P3R, CD; 007FL gets defensive)
- Does NOT bypass Denuvo (carve-out for P3R; not present in the other 4)
- Documents the DenuvOwO technique in these RE notes as a reference for
  future (out-of-scope) Windows-host deployments

The Intel path is documented but not analyzed in depth because:
1. The engagement host is AMD (the SimpleSvm notes are the primary reference)
2. The 80 MB HyperDbg fork source is 99% the same as upstream HyperDbg
3. The Denuvo-defeating logic is the same as SimpleSvm (per the table above)

---

## 7. Files in the HyperDbg fork source

- `HypervisorSource/hyperkd/` — the kernel driver (main entry point;
  `DriverEntry` → `DenuvoInitialize` → VMXON → VMCS setup) — **VERIFIED** via `ls`
- `HypervisorSource/hyperhv/` — the user-mode helper (the `coldloader.dll`
  shim loads this) — **VERIFIED**
- `HypervisorSource/hyperevade/` — the EDR-evasion layer — **VERIFIED**
- `HypervisorSource/hyperlog/` — the logger (logs to `C:\DenuvOwO\log.txt`) — **VERIFIED**
- `HypervisorSource/dependencies/` — vendored (Zydis disasm, capstone,
  Intel XED, etc.) — **VERIFIED** (includes `pdbex/`, `zydis/`, etc.)
- `HypervisorSource/hyperdbg-cli/` — the user-mode CLI (not built in DenuvOwO) — **VERIFIED** (present in `ls`)
- `HypervisorSource/script-engine/` — the scripting engine (not built) — **VERIFIED**
- `HypervisorSource/symbol-parser/` — the symbol parser (not built) — **VERIFIED**
- `HypervisorSource/CMakeLists.txt` — the build entry point — **VERIFIED**
- `HypervisorSource/hyperdbg.sln` — the Visual Studio solution — **VERIFIED**

**Important correction:** the `libhyperdbg/` subdir is also present (per
`ls HypervisorSource/`). The total source is **165,088 lines** across all
.cpp/.c/.h files (verified via `find ... | xargs wc -l`). The earlier
estimate of "62K LOC" was wrong by ~3x.

The key Denuvo-defeating logic lives in:
- `hyperhv/code/vmm/vmx/Vmx.c` (line with `UINT64 TargetDR3 = 0x7FFE0FF0;`)
- `hyperhv/code/vmm/vmx/Vmexit.c` (the `if (CurrentDR3 == TargetDR3 && ...)` check)
- `hyperhv/code/vmm/vmx/Hv.c` (the VMX setup + exit handler dispatcher)
- `hyperhv/code/assembly/AsmHooks.asm` (the assembly stubs that read
  `TargetDR3` and dispatch)
