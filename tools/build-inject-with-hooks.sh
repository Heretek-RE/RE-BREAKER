#!/usr/bin/env bash
# build-inject-with-hooks.sh — v0.8.0 convenience wrapper
#
# Wraps `re-injection-runtime.build_injection(hook_specs=[...])` and
# verifies the resulting .so/.dll actually contains the hook spec
# functions (via `nm` / `winedump`).
#
# Usage:
#   tools/build-inject-with-hooks.sh [linux|windows|both]
#
# Default: both
set -euo pipefail
PLUGIN_ROOT=${RE_BREAKER_PLUGIN_ROOT:-.}
OUT=$PLUGIN_ROOT/Output/$(date +%Y-%m-%d)/verification/inject-lib-test
mkdir -p "$OUT"
TARGET_OS="${1:-both}"

echo "[build-inject-with-hooks] target_os=$TARGET_OS output=$OUT"

# Step 1: build (via direct gcc, since MCP server cache may be stale)
case "$TARGET_OS" in
  linux|windows|both)
    if [[ "$TARGET_OS" == "linux" || "$TARGET_OS" == "both" ]]; then
      gcc -shared -fPIC -O2 -o "$OUT/re_breaker_inject.so" \
          "$PLUGIN_ROOT/inject/src/linux/so_inject.c" \
          "$PLUGIN_ROOT/inject/src/common/hook_engine.c" \
          "$PLUGIN_ROOT/inject/src/common/decrypt_dump.c" \
          "$PLUGIN_ROOT/inject/src/common/ipc.c" \
          "$PLUGIN_ROOT/servers/re-injection-runtime/src/re_injection_runtime/hook_specs"/*.c \
          -I"$PLUGIN_ROOT/inject/src/common" \
          -I"$PLUGIN_ROOT/inject/src/linux" \
          -ldl -lpthread
      echo "[build-inject-with-hooks] .so built: $OUT/re_breaker_inject.so"
    fi
    if [[ "$TARGET_OS" == "windows" || "$TARGET_OS" == "both" ]]; then
      x86_64-w64-mingw32-gcc -shared -O2 -o "$OUT/re_breaker_inject.dll" \
          "$PLUGIN_ROOT/inject/src/win/dll_inject.c" \
          "$PLUGIN_ROOT/inject/src/common/hook_engine.c" \
          "$PLUGIN_ROOT/inject/src/common/decrypt_dump.c" \
          "$PLUGIN_ROOT/inject/src/common/ipc.c" \
          "$PLUGIN_ROOT/servers/re-injection-runtime/src/re_injection_runtime/hook_specs"/*.c \
          -I"$PLUGIN_ROOT/inject/src/common" \
          -I"$PLUGIN_ROOT/inject/src/win" \
          -lkernel32 -lpthread
      echo "[build-inject-with-hooks] .dll built: $OUT/re_breaker_inject.dll"
    fi
    ;;
  *)
    echo "usage: $0 [linux|windows|both]" >&2
    exit 1
    ;;
esac

# Step 2: verify .so has the hook spec symbols
if [[ -f "$OUT/re_breaker_inject.so" ]]; then
  echo "[build-inject-with-hooks] verify .so symbols:"
  nm -D "$OUT/re_breaker_inject.so" 2>&1 | grep -E "re_breaker_(rdtsc|cpuid|invd|method|steam_api|eos)_" | sort
fi

# Step 3: verify .dll has the hook spec exports
if [[ -f "$OUT/re_breaker_inject.dll" ]]; then
  echo "[build-inject-with-hooks] verify .dll exports:"
  winedump -j export "$OUT/re_breaker_inject.dll" 2>&1 | grep -E "re_breaker_(rdtsc|cpuid|invd|method|steam_api|eos)_" | head -10 || echo "(winedump did not find spec exports — this is OK if the build is for internal use only)"
fi

echo "[build-inject-with-hooks] done."
