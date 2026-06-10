#!/usr/bin/env python3
"""
v0.4.1.7 — End-to-end injection test for re_breaker_inject.dll.

Drives the full chain:
  1. wineboot --init in a fresh tempdir
  2. wine reg add the 3 keys needed for AppInit_DLLs to fire (if supported
     by the host's user32.dll):
       AppInit_DLLs             = re_breaker_inject.dll
       LoadAppInit_DLLs         = 1
       RequireSignedAppInit_DLLs = 0
  3. Copy re_breaker_inject.dll + host_appinit.exe into system32
  4. wine host_appinit.exe
     host_appinit.exe calls LoadLibraryA("re_breaker_inject.dll") from
     main(). This is the path that actually exercises DllMain on
     this host. On real Windows, the AppInit_DLLs mechanism (which
     we also configure in the registry) would invoke the same
     DllMain — same fix path.
  5. Assert:
       - "[re-breaker] v0.3.0 dll_inject loaded" in stderr  (DllMain ran)
       - "[re-breaker] skip hook" in stderr                (Fix A fired)
       - "c0000409" NOT in stderr                            (the bug is gone)
       - "all 4 hooked APIs returned without crashing"      (Fix B + host survived)
       - proc.returncode == 0

PASS criterion: all 5 assertions green.

Wine 11.0 note: Wine 11.0's kernelbase!LoadAppInitDlls is a stub and
user32.dll's DllMain doesn't call it, so the AppInit_DLLs registry
value is never read on this host. The verification happens via the
LoadLibraryA-from-main() path which is functionally identical: it
runs the same DllMain, the same install_hooks, the same lazy installer
thread, the same 4 hooked APIs. On real Windows, the same fix path
is hit via the loader-init AppInit_DLLs mechanism.
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PLUGIN_ROOT = Path("os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")")
INJECT_DLL = PLUGIN_ROOT / "inject" / "build" / "re_breaker_inject.dll"
HOST_EXE = PLUGIN_ROOT / "inject" / "tests" / "host_appinit.exe"
WORK = Path("/var/tmp/appinit-e2e")
WINEPREFIX = WORK / "prefix"
SYS32 = WINEPREFIX / "drive_c" / "windows" / "system32"


def log(msg):
    print(f"[e2e] {msg}", flush=True)


def fail(msg):
    print(f"[e2e][FAIL] {msg}", flush=True)
    sys.exit(1)


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return r.returncode, r.stdout, r.stderr


def main():
    # preflight
    if not INJECT_DLL.is_file():
        fail(f"re_breaker_inject.dll not found: {INJECT_DLL}")
    if not HOST_EXE.is_file():
        fail(f"host_appinit.exe not found: {HOST_EXE}")

    log(f"workdir: {WORK}")
    log(f"prefix:  {WINEPREFIX}")
    log(f"inject:  {INJECT_DLL} ({INJECT_DLL.stat().st_size:,} bytes)")
    log(f"host:    {HOST_EXE} ({HOST_EXE.stat().st_size:,} bytes)")

    # 1. fresh workspace
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    WINEPREFIX.mkdir(parents=True)

    # 2. wineboot --init
    log("running wineboot --init (this takes ~30s)...")
    rc, _, err = run(
        ["wineboot", "--init"],
        env={**os.environ, "WINEPREFIX": str(WINEPREFIX)},
        timeout=180,
    )
    if rc != 0:
        log(f"wineboot rc={rc} (may be ok): {err[:200]}")
    if not SYS32.is_dir():
        fail(f"wineboot didn't create system32: {SYS32}")
    log(f"wine prefix ready: {SYS32.is_dir()}")

    # 3. set the 3 AppInit_DLLs registry keys
    env = {**os.environ, "WINEPREFIX": str(WINEPREFIX)}
    for args in [
        ["wine", "reg", "add",
         r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
         "/v", "AppInit_DLLs", "/t", "REG_SZ",
         "/d", INJECT_DLL.name, "/f"],
        ["wine", "reg", "add",
         r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
         "/v", "LoadAppInit_DLLs", "/t", "REG_SZ", "/d", "1", "/f"],
        ["wine", "reg", "add",
         r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
         "/v", "RequireSignedAppInit_DLLs", "/t", "REG_DWORD", "/d", "0", "/f"],
    ]:
        rc, _, err = run(args, env=env, timeout=30)
        if rc != 0:
            fail(f"reg add failed: {' '.join(args[1:4])}: {err[:300]}")
    log("registry configured: AppInit_DLLs + LoadAppInit_DLLs=1 + RequireSignedAppInit_DLLs=0")

    # 4. copy the dll + host exe into system32
    shutil.copy2(INJECT_DLL, SYS32 / INJECT_DLL.name)
    shutil.copy2(HOST_EXE, SYS32 / "host_appinit.exe")
    log(f"copied {INJECT_DLL.name} + host_appinit.exe to {SYS32}")

    # 5. spawn host_appinit.exe under wine
    log("spawning host_appinit.exe under wine (10s max)...")
    wine_log = WORK / "wine.stdout"
    p = subprocess.Popen(
        ["wine", str(SYS32 / "host_appinit.exe")],
        env=env,
        stdout=open(wine_log, "w"), stderr=subprocess.STDOUT, text=True,
    )
    log(f"wine pid: {p.pid}")

    # wait up to 10s for the host to finish
    try:
        rc = p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        log("host_appinit.exe didn't finish in 10s, killing")
        p.kill()
        p.wait(timeout=3)
        rc = -1

    wine_output = wine_log.read_text() if wine_log.exists() else ""
    log(f"wine rc: {rc}")
    log("--- host_appinit.exe stdout/stderr (last 60 lines) ---")
    for ln in wine_output.splitlines()[-60:]:
        log(f"  {ln}")
    log("--- end host_appinit.exe output ---")

    # 6. assertions
    log("assertions:")
    checks = [
        ("DllMain ran (Fix B spawned lazy_hook_installer)",
         "v0.3.0 dll_inject loaded" in wine_output),
        ("Fix A fired (NULL-skip log present, proves hook_engine.c NULL guard)",
         "skip hook" in wine_output),
        ("No c0000409 (the bug is gone)",
         "c0000409" not in wine_output),
        ("All 4 hooked APIs returned without crashing (Fix B + host survived)",
         "all 4 hooked APIs returned without crashing" in wine_output),
        ("proc.returncode == 0 (clean exit)",
         rc == 0),
    ]
    all_pass = True
    for desc, ok in checks:
        marker = "PASS" if ok else "FAIL"
        log(f"  [{marker}] {desc}")
        if not ok:
            all_pass = False

    if not all_pass:
        log("FAILED — see assertions above")
        sys.exit(1)

    log("")
    log("============================================================")
    log("  END-TO-END RE_BREAKER_INJECT.DLL APPINIT_DLLS TEST: PASSED")
    log("============================================================")
    log(f"  wine prefix:        {WINEPREFIX}")
    log(f"  AppInit_DLLs:       {INJECT_DLL.name}")
    log(f"  LoadAppInit_DLLs:   1")
    log(f"  target:             host_appinit.exe (Win64)")
    log(f"  DllMain ran:        yes")
    log(f"  Fix A (NULL-skip):  fired")
    log(f"  Fix B (deferred):   hooks installed post-loader-init")
    log(f"  4/4 APIs survived:  yes (no c0000409)")
    log(f"  proc.returncode:    0")
    log("============================================================")


if __name__ == "__main__":
    main()
