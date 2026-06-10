// cpuid_zero_at_sites.c — NOP every CPUID (0x0F 0xA2) in the per-target site list.
// Per-target CPUID sites are typically rare (FM26 has 5); most CPUID detection
// happens in user-mode code that's not enumerated by the static analyzer.
// Defeats the enumerated subset.
#include "hook_engine.h"
void re_breaker_cpuid_zero_at_sites(void) {
    uint8_t orig[2] = {0x0F, 0xA2};
    uint8_t patched[2] = {0x90, 0x90};
    re_breaker_patch_opcode_at_sites(orig, 2, patched, 2);
}
