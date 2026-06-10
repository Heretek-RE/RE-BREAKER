// eos_init_zero.c — hook EOS_Initialize to return EOS_Success
// Defeats the EOS handshake entitlement check at the launcher's import boundary.
// Per SOW-K §K.2 + SOW-Q §Q.1: EOS handshake bypass is in scope; EOS AC is NOT in scope.
#include "hook_engine.h"

// EOS_Success = 0
typedef int EOS_EResult;

static EOS_EResult re_breaker_eos_initialize_replacement(void) {
    return 0;  // EOS_Success
}

void re_breaker_eos_init_zero(void) {
    re_breaker_install_hook("EOSSDK-Win64-Shipping", "EOS_Initialize",
                            (void *)re_breaker_eos_initialize_replacement);
}
