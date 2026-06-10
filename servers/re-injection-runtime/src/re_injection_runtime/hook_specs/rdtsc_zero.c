// rdtsc_zero.c — override RDTSC to return 0
#include "hook_engine.h"
void re_breaker_rdtsc_zero(void) {
    // patch the RDTSC opcode (0F 31) at every site enumerated by the catalog
    extern void re_breaker_patch_opcode(uint8_t *addr, const uint8_t *original, size_t original_len, const uint8_t *patched, size_t patched_len);
    uint8_t orig[2] = {0x0F, 0x31};
    uint8_t patched[2] = {0x90, 0x90};
    re_breaker_patch_opcode_at_sites(orig, 2, patched, 2);
}
