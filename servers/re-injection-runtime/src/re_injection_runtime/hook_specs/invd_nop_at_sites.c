// invd_nop_at_sites.c — NOP every INVD (0x0F 0x08) in the per-target site list.
// Distinct from invd_nop.c which is a no-op (the per-target site list for
// INVD is populated by the per-target triage; without that list, there are
// no sites to patch).
#include "hook_engine.h"
void re_breaker_invd_nop_at_sites(void) {
    uint8_t orig[2] = {0x0F, 0x08};
    uint8_t patched[2] = {0x90, 0x90};
    re_breaker_patch_opcode_at_sites(orig, 2, patched, 2);
}
