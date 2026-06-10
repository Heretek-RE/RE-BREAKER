/* RE-BREAKER IPC (v0.3.0): Windows named-pipe + Linux Unix-socket. */
#ifndef RE_BREAKER_IPC_H
#define RE_BREAKER_IPC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int re_breaker_ipc_init(int pid);
int re_breaker_ipc_send(const char *event, const char *payload);
int re_breaker_ipc_finalize(void);

#ifdef __cplusplus
}
#endif

#endif
