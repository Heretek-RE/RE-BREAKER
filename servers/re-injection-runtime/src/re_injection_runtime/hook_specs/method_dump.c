// method_dump.c — at the encryption-stub entry, capture (input, output) and send to IPC
#include "hook_engine.h"
#include "decrypt_dump.h"
void re_breaker_method_dump(void) {
    extern void re_breaker_register_encryption_stub_hook(void *handler);
    re_breaker_register_encryption_stub_hook(re_breaker_method_dump_handler);
}
static void re_breaker_method_dump_handler(void *input, size_t in_size, void *output) {
    re_breaker_write_decrypted_region("method", (const uint8_t *)output, in_size);
    re_breaker_write_event("method.dump", "ok");
}
