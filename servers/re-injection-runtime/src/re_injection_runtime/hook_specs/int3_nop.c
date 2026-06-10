// int3_nop.c — NOP every INT 3 (0xCC) in the per-target site list.
// Site list is populated by load_target_sites.py + hook_engine.c
// re_breaker_drain_sites_file() at runtime.
// INT 3 is a 1-byte opcode (0xCC); site RVAs point to a single byte.
#include "hook_engine.h"
void re_breaker_int3_nop(void) {
    uint8_t orig[1] = {0xCC};
    uint8_t patched[1] = {0x90};
    re_breaker_patch_opcode_at_sites(orig, 1, patched, 1);
}
