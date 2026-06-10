#!/bin/bash
# build.sh — build the C/C++ injector
#
# v0.1.0: this is a placeholder that just compiles the stubs to
# verify the source tree is well-formed. The real implementation in
# v0.2.0 will build the full inline-hook engine.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${HERE}/src"
OUT="${HERE}/build"
mkdir -p "${OUT}"

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[build.sh] building Windows DLL (x86_64-mingw)..."
    x86_64-w64-mingw32-gcc -shared -o "${OUT}/re_breaker_inject.dll" \
        "${SRC}/win/dll_inject.c" \
        "${SRC}/common/hook_engine.c" \
        "${SRC}/common/decrypt_dump.c" \
        "${SRC}/common/ipc.c" \
        -lkernel32
    echo "[build.sh] built: ${OUT}/re_breaker_inject.dll"
fi

echo "[build.sh] building Linux SO (host gcc)..."
gcc -shared -fPIC -o "${OUT}/re_breaker_inject.so" \
    "${SRC}/linux/so_inject.c" \
    "${SRC}/common/hook_engine.c" \
    "${SRC}/common/decrypt_dump.c" \
    "${SRC}/common/ipc.c" \
    -ldl
echo "[build.sh] built: ${OUT}/re_breaker_inject.so"

# v0.4.1.7: also build the AppInit_DLLs test target host_appinit.exe
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[build.sh] building host_appinit.exe (AppInit_DLLs test target)..."
    mkdir -p "${HERE}/tests"
    x86_64-w64-mingw32-gcc -O2 -o "${HERE}/tests/host_appinit.exe" \
        "${HERE}/tests/host_appinit.c" \
        -lkernel32 -luser32 -ladvapi32
    echo "[build.sh] built: ${HERE}/tests/host_appinit.exe"
fi

echo "[build.sh] done"
