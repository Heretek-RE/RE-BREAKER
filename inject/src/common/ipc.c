/* RE-BREAKER IPC (v0.3.0 real implementation). */
#include "ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#ifdef _WIN32
#  include <windows.h>
#  include <namedpipeapi.h>
#else
#  include <sys/socket.h>
#  include <sys/un.h>
#endif

static int g_initialized = 0;
static int g_pid = 0;

#ifdef _WIN32
static HANDLE g_pipe = INVALID_HANDLE_VALUE;
#else
static int g_sock = -1;
static char g_sock_path[256];
#endif

int re_breaker_ipc_init(int pid) {
    g_pid = pid;
#ifdef _WIN32
    char pipe_name[256];
    snprintf(pipe_name, sizeof(pipe_name), "\\\\.\\pipe\\re-breaker-%d", pid);
    g_pipe = CreateNamedPipeA(pipe_name, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE,
                              1, 4096, 4096, 0, NULL);
    if (g_pipe == INVALID_HANDLE_VALUE) return -1;
#else
    snprintf(g_sock_path, sizeof(g_sock_path), "/tmp/re-breaker-%d.sock", pid);
    g_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_sock < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_sock_path, sizeof(addr.sun_path) - 1);
    unlink(g_sock_path);
    if (bind(g_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(g_sock); return -1;
    }
    listen(g_sock, 5);
#endif
    g_initialized = 1;
    fprintf(stderr, "[re-breaker] v0.3.0 IPC initialized for pid=%d\n", pid);
    return 0;
}

int re_breaker_ipc_send(const char *event, const char *payload) {
    if (!g_initialized) return -1;
    char msg[2048];
    int len = snprintf(msg, sizeof(msg), "{\"event\": \"%s\", \"payload\": \"%s\"}\n", event, payload);
#ifdef _WIN32
    if (g_pipe != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_pipe, msg, len, &written, NULL);
    }
#else
    if (g_sock >= 0) {
        int client = accept(g_sock, NULL, NULL);
        if (client >= 0) {
            write(client, msg, len);
            close(client);
        }
    }
#endif
    return 0;
}

int re_breaker_ipc_finalize(void) {
#ifdef _WIN32
    if (g_pipe != INVALID_HANDLE_VALUE) CloseHandle(g_pipe);
#else
    if (g_sock >= 0) { close(g_sock); unlink(g_sock_path); }
#endif
    g_initialized = 0;
    return 0;
}
