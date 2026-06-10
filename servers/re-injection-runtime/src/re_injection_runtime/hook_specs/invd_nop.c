// invd_nop.c — replace INVD with NOP NOP
#include "hook_engine.h"
void re_breaker_invd_nop(void) {
    uint8_t orig[2] = {0x0F, 0x08};
    uint8_t patched[2] = {0x90, 0x90};
    re_breaker_patch_opcode_at_sites(orig, 2, patched, 2);
}
