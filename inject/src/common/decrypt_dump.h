/* RE-BREAKER decrypt-dump writer (v0.3.0). */
#ifndef RE_BREAKER_DECRYPT_DUMP_H
#define RE_BREAKER_DECRYPT_DUMP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int re_breaker_write_decrypted_region(const char *name, const uint8_t *buf, size_t size);
int re_breaker_write_event(const char *event_name, const char *payload);

#ifdef __cplusplus
}
#endif

#endif
