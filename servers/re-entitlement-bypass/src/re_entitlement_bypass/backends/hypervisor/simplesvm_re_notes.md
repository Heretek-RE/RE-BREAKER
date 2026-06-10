# SimpleSvm RE Notes — How the AMD-V Hypervisor Defeats Denuvo

**Source:** `Input/Crimson.Desert.Build.23578264-DenuvOwO/DenuvOwO_SRC_V6/SimpleSvm/`
**License:** MIT (Satoshi Tanda, 2017-2020)
**Built binary:** `DenuvOwO/bin64/driver_amd/SimpleSvm.sys`
**Used by DenuvOwO** to defeat Denuvo's anti-VM detection on AMD CPUs.

This document is the RE walkthrough of the SimpleSvm source as deployed in
the DenuvOwO attacker build. **No code is run during this RE work** — the
goal is to understand the technique, not to deploy it.

---

## 1. What SimpleSvm is

SimpleSvm is a minimalistic educational hypervisor for Windows on AMD
processors. It uses AMD's Secure Virtual Machine (SVM) + Nested Page Tables
(NPT) to create a Type-2 hypervisor that runs beneath the Windows kernel.

**The DenuvOwO deployment** uses SimpleSvm to interpose on **specific CPUID
leaves and DR3 debug-register values** for a single tracked process. The
hypervisor's job is to:

1. Hide itself from Denuvo's anti-VM checks (so Denuvo's CPUID-based detection
   of "are we under a hypervisor?" returns the right answer for the targeted
   process only)
2. Allow the Denuvo thread to "register" itself via a CPUID handshake
3. Spoof the KUSER_SHARED_DATA structure (Windows kernel's per-process
   read-only data) for the targeted process so Denuvo's tamper checks see a
   "clean" Windows environment

---

## 2. The 3 magic constants (the protocol's identifying markers)

From `SimpleSvm.cpp` lines 17-20 (the 4 EXTERN_C declarations at the top
of the file; the `KUSER_SHARED_DATA_KERNELMODE` macro is on line 49):

```cpp
// SimpleSvm.cpp lines 17-20 — VERIFIED
EXTERN_C UINT64 TargetSysHandler = 0x0;                                    // line 17
EXTERN_C UINT64 OrigLstar = 0x0;                                          // line 18
EXTERN_C const UINT64 TargetDR3 = 0x7FFE0FF0;                              // line 19 — the Denuvo thread marker
EXTERN_C const UINT64 SyscallBypassMagic = 0x1337133713371337;            // line 20 — the syscall bypass magic

// SimpleSvm.cpp line 49 — VERIFIED
#define KUSER_SHARED_DATA_KERNELMODE 0xFFFFF78000000000                    // line 49
```

- **`TargetDR3 = 0x7FFE0FF0`** — the debug register DR3 is set to this magic
  value by the `cd_id.dll` (the per-game identity DLL) to identify the Denuvo
  thread. The hypervisor checks DR3 in every CPUID exit; only when
  `CurrentDR3 == TargetDR3` does it apply the spoof.

- **`SyscallBypassMagic = 0x1337133713371337`** — placed in `KUSER_SHARED_DATA`
  to mark the "ready to proceed" state for the Denuvo thread (line 955:
  `*(UINT32*)(NewKusdAddress + 0xFFC) = 0x13371337;`). This is a 32-bit magic
  at offset 0xFFC in the new (spoofed) KUSER_SHARED_DATA page.

- **CPUID leaf `0x1337`** — the handshake leaf. When the Denuvo thread issues
  `CPUID(0x1337, ...)` with `RDX = target_PID`, the hypervisor captures the
  PID and starts tracking that process. From line 1104-1111:

  ```cpp
  if (GuestContext->VpRegs->Rax == 0x1337) {
      if (!TrackedProcessId) {
          TargetProcessId = reinterpret_cast<HANDLE>(GuestContext->VpRegs->Rdx);
      }
      goto doCpuid;
  }
  ```

  This is the per-target `cd_id.dll`'s job: set `DR3 = 0x7FFE0FF0` and issue
  `CPUID(0x1337, 0, target_PID)`.

---

## 3. The CPUID spoofing (the core anti-detection)

When the tracked process issues a CPUID, the hypervisor:
1. Executes the real CPUID via `__cpuidex(registers, leaf, subLeaf)` (line 1045)
2. **If the process is in ring 3 (CPL == 0x3)** AND **`DR3 == 0x7FFE0FF0`** AND
   **`(DR7 & 0xF0000040) == 0x40`** (the specific debug-register state set
   by Denuvo), the hypervisor **replaces** the returned values for the
   following leaves:

   | Leaf | Real | Spoofed | Purpose |
   |------|------|---------|---------|
   | `0x1` | Real CPU features | `EAX=0x00A20F12, EBX=0x00100800\|..., ECX=0x7EF8320B & ~(FMA3\|AES\|XSAVE\|OSXSAVE\|AVX\|F16C\|RDRAND), EDX=0x178BFBFF` | Disables FMA3, AES, XSAVE, OSXSAVE, AVX, F16C, RDRAND so Denuvo can't fingerprint the CPU's full feature set |
   | `0x80000002` | Real CPU brand string | `EAX='uneD', EBX='OwOv', ECX='UPC ', EDX='1 @ '` | Reads as "DenU OwOv CPU 1 @ ..." in the registry — Denuvo's own anti-cheat string |
   | `0x80000003` | Real CPU brand string | `EAX=' 733', EBX='zHG', ECX=0, EDX=0` | Continues the "DenU OwOv CPU 1 @ 73zHG" pattern |
   | `0x80000004` | Real CPU brand string | `EAX=0, EBX=0, ECX=0, EDX=0` | Terminates the brand string |

   This is the "hide-the-real-CPU" trick. Denuvo's CPUID-based hypervisor
   detection looks for specific CPU feature combinations; the spoofed
   combinations make the in-process checks see a "known-bad" CPU (the
   "DenU OwOv CPU") and the Denuvo check is happy with the resulting value.

   For **all other processes** (non-tracked, or in ring 0), the CPUID returns
   the real values (lines 1118-1138 are the default `doCpuid` switch — they
   add `CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT` to indicate the presence
   of the hypervisor, but **only when not spoofing**).

---

## 4. The KUSER_SHARED_DATA spoofing (the tamper check)

From lines 646 (top comment `// KUSER_SHARED_DATA spoofing related functions below.`)
through 1008 (bottom comment `// KUSER_SHARED_DATA spoofing related functions above.`),
the hypervisor:
1. Allocates a new page (the "NewKuserSharedData") to hold the spoofed
   KUSER_SHARED_DATA structure
2. Locks the original KUSER_SHARED_DATA page (at `0xFFFFF78000000000`) using
   an MDL so the guest can't modify it
3. Maps the new page at the same address for the tracked process
4. Fills the new page with hard-coded "clean" values (the actual fills are
   in the function around line 898: `memcpy((void*)(NewKusdAddress + 0x30), ...)`,
   `*(UINT64*)(NewKusdAddress + 0x260) = 0x0100006658`, etc. — these are
   the per-field writes; the exact fields are inferred from the
   KUSER_SHARED_DATA structure in the WDK headers)
5. Writes `SyscallBypassMagic = 0x13371337` at offset 0xFFC — **VERIFIED**
   at `SimpleSvm.cpp:955`:
   `*(UINT32*)(NewKusdAddress + 0xFFC) = 0x13371337;` (the comment says
   "Indicate that the game process can proceed execution to avoid race
   condition on snail PCs")

The spoofed KUSER_SHARED_DATA includes:
- `NtSystemRoot` (the Windows install path) — inferred from the WDK headers
- `ProcessorFeatures` (the CPU feature flags — must match the CPUID spoof above) — inferred
- Various Nt* version fields — inferred
- The system time fields (to prevent time-based tamper checks) — inferred

**Status:** the function's existence + the 0xFFC magic + the "ready to
proceed" semantics are VERIFIED. The per-field writes (which fields get
which values) are INFERRED from the WDK headers and the variable names
in the source.

---

## 5. The MSR interposition

From line 1206 (`SvHandleMsrAccess`) — **VERIFIED**:
- MSR reads/writes are intercepted (the `OrigLstar` global at line 18 saves
  the original LSTAR value; the hypervisor presumably restores it on
  process exit)
- The hypervisor's `SvHandleMsrAccess` is called on every MSR exit
- The exact MSR filtering (which MSRs are hooked vs passed through) is
  inside `SvHandleMsrAccess` and is **INFERRED** from the source's
  variable names — I didn't trace the per-MSR switch

---

## 6. The process tracking lifecycle

From lines 792-867:
- The hypervisor registers a `PsSetCreateProcessNotifyRoutineEx` callback
- When the tracked process exits (`ProcessExitCleanup == TRUE`), the
  spoofed KUSER_SHARED_DATA is unmapped and the original is restored
- A counter thread (`CounterUpdater`) updates the spoofed system's uptime
  counter so time-based tamper checks don't detect a frozen clock

---

## 7. What this means for the engagement

Per the user's direction: **the engagement does NOT deploy this**. The
DenuvOwO drivers are RE-only references. The 7-target engagement notes that:

- **CD** uses DenuvOwO in the attacker build to defeat Denuvo
- The P3R Denuvo (confirmed present per `data/wire_sigs/p3r.json`) is
  carve-out (per SOW-X §P.1) and not analyzed
- The other 5 targets (FM26, HKIA, 007FL, TWW3, LIR) do NOT have Denuvo

The SimpleSvm RE walkthrough is the **basis for a future** Windows-host
deployment. The RE notes are the operator's reference when that deployment
becomes in-scope.

---

## 8. Files in the SimpleSvm source

- `SimpleSvm/SimpleSvm.cpp` — the main code (~3000 lines; this RE walkthrough
  covers the key 5 sections above)
- `SimpleSvm/SimpleSvm.hpp` — header with structures + constants
- `SimpleSvm/x64.asm` — assembly stubs for the VMRUN / VMLOAD / VMSAVE / VMEXIT
  primitives
- `SimpleSvm/utils.cpp` — utility functions (CR3 lookup by PID, etc.)
- `SimpleSvm/{amd,ia32,pte}.h` — AMD-specific header definitions — **VERIFIED**
  (`ls SimpleSvm/` returns these exact filenames)
- `SimpleSvm/SimpleSvm.sln` — Visual Studio solution — **VERIFIED**
- `README.md`, `LICENSE` — MIT license + project documentation — **VERIFIED**
  (LICENSE says "MIT License, Copyright (c) 2017-2018 Satoshi Tanda")

The LICENSE was verified directly:
```
MIT License

Copyright (c) 2017-2018 Satoshi Tanda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
...
```
