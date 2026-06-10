// cpuid_bare_metal.c — return bare-metal snapshot for CPUID leaf 1 ECX bit 31
#include "hook_engine.h"
void re_breaker_cpuid_spoof(void) {
    extern void re_breaker_register_cpuid_hook(void *handler);
    re_breaker_register_cpuid_hook(re_breaker_cpuid_spoof_handler);
}
static void re_breaker_cpuid_spoof_handler(void *ctx) {
    // zero bit 31 of ECX (hypervisor present)
    ((uint32_t *)ctx)[2] &= ~(1u << 31);
}
