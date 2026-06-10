# re-frida-wine-runtime

RE-BREAKER Frida-on-Wine runtime (v0.4.0). Wine-spawn a Windows PE target, inject the frida-gadget into the Wine-hosted process, and attach from the Linux side via the in-process gadget's TCP listener.

The only known-working path to get Frida hooks on a Windows PE binary running under Wine on this Linux host.

See `src/re_frida_wine_runtime/server.py` for the 6 tools exposed.
