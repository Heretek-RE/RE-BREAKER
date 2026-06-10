// steam_api_init_zero.c — hook SteamAPI_Init to return k_ESteamAPIInitResult_OK
// Defeats the Steamworks CEG entitlement check at the launcher's import boundary.
// Per SOW-J §J.3: Steamworks CEG bypass research is in scope.
#include "hook_engine.h"

// k_ESteamAPIInitResult_OK = 0
typedef unsigned int ESteamAPIInitResult;

static ESteamAPIInitResult re_breaker_steamapi_init_replacement(void) {
    return 0u;  // k_ESteamAPIInitResult_OK
}

void re_breaker_steam_api_init_zero(void) {
    re_breaker_install_hook("steam_api64", "SteamAPI_Init",
                            (void *)re_breaker_steamapi_init_replacement);
}
