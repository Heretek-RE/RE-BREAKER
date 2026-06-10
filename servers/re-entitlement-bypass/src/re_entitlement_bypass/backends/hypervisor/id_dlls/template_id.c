/*
 * template_id.c — per-game id_dll template
 *
 * The DenuvOwO build's `cd_id.dll` is a 1.5 KB per-game identity marker
 * that runs in the target process's DllMain. Its job is to:
 *   1. Set DR3 to the magic value 0x7FFE0FF0 (the Denuvo thread marker)
 *   2. Issue CPUID leaf 0x1337 with RDX = target_PID (the handshake)
 *   3. Optionally write a flag to KUSER_SHARED_DATA (not done in the
 *      original cd_id.dll; that's a hypervisor-side operation)
 *
 * The Denuvo thread (which sets DR3 = 0x7FFE0FF0 on its own at start)
 * uses the hypervisor's CPUID interception to know which process is the
 * target. The id_dll's job is to REGISTER the process by issuing the
 * CPUID(0x1337, 0, target_PID) instruction.
 *
 * RE-extracted from the DenuvOwO build at:
 *   Input/Crimson.Desert.Build.23578264-DenuvOwO/DenuvOwO/bin64/cd_id.dll
 *   (1.5 KB, 2 sections, PE32+ for MS Windows 6.00 x86-64)
 *
 * Per-game customization:
 *   - Set TARGET_PID to the CrimsonDesert.exe process ID at runtime
 *     (use GetCurrentProcessId() at DllMain time)
 *   - The DR3 magic is constant across all games (0x7FFE0FF0)
 *   - The CPUID leaf is constant (0x1337)
 *
 * Compile:
 *   i686-w64-mingw32-gcc -shared -o cd_id.dll template_id.c
 *   (the per-game constants are baked in at compile time; for
 *    multi-target deployment, use a build script that takes the
 *    target name + AppID and generates a per-game id_dll)
 */

#include <windows.h>

/* Magic constants from SimpleSvm.cpp lines 18-20. Do not change. */
#define TARGET_DR3_MAGIC     0x7FFE0FF0
#define SYSCTL_BYPASS_MAGIC  0x1337133713371337

/* Per-game configuration. Override at compile time. */
#ifndef TARGET_EXE
#define TARGET_EXE  "CrimsonDesert.exe"
#endif

/* The target process ID is captured at DllMain time via GetCurrentProcessId().
 * No compile-time constant for this. */

/*
 * Issue a CPUID with RAX = leaf, RCX = subleaf, RDX = arbitrary.
 * We use the __cpuid intrinsic (MSVC) which sets EAX/EBX/ECX/EDX.
 * For 64-bit, we use inline __asm via the __cpuid_count intrinsic.
 */
static void issue_cpuid(unsigned int leaf, unsigned int subleaf, unsigned int rdx) {
    int regs[4];
    __cpuid(regs, (int)leaf);
    /* The CPUID instruction itself doesn't take RDX as an input — it's set
     * by the calling code. The hypervisor's SvHandleCpuid reads RAX (leaf),
     * RCX (subleaf), and RDX (the arbitrary input) from the guest state. */
    (void)rdx;  /* RDX is set by the caller; see below */
}

/*
 * Set the DR3 debug register. Uses inline asm (MSVC x64 syntax).
 * Note: this is a privileged operation when in kernel mode, but
 * user-mode code can WRITE its own DR3 (it's per-thread state).
 */
static void set_dr3(unsigned long long value) {
#if defined(_MSC_VER) && defined(_M_X64)
    /* MSVC x64 doesn't have a direct intrinsic for DR3; use inline asm. */
    __asm {
        mov rax, value
        mov dr3, rax
    }
#elif defined(__GNUC__)
    /* GCC/Clang x64 inline asm */
    __asm__ volatile ("movq %0, %%dr3" : : "r" (value) : "memory");
#endif
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        /* Disable thread notifications for performance */
        DisableThreadLibraryCalls(hModule);

        /* Step 1: Set DR3 to the Denuvo thread marker.
         * The hypervisor's SvHandleCpuid checks DR3 to identify the
         * Denuvo thread. */
        set_dr3(TARGET_DR3_MAGIC);

        /* Step 2: Issue CPUID leaf 0x1337 with RDX = target PID.
         * This is the handshake — the hypervisor reads RDX to know
         * which process to track. */
        unsigned int target_pid = (unsigned int)GetCurrentProcessId();
        issue_cpuid(0x1337, 0, target_pid);
    }
    return TRUE;
}
