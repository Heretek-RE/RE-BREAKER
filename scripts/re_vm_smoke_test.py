#!/usr/bin/env python3
"""scripts/re_vm_smoke_test.py — end-to-end smoke test of the v0.5.0
VM toolchain (re-vm-control + re-vm-ssh only, since the other 6 are
scaffolds that return honest stubs).

Run from anywhere:
    python scripts/re_vm_smoke_test.py
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_RE_BREAKER_SRC))
from re_breaker.vm_client import (  # noqa: E402
    DEFAULT_VM_NAME, get_ssh, gdb_stub_alive, qemu_monitor_command,
    virsh,
)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--vm", default=DEFAULT_VM_NAME)
    p.add_argument("--skip-gdb-stub", action="store_true", help="don't call attach_gdb_stub (avoid VM reboot)")
    args = p.parse_args()

    results: list[tuple[str, bool, str]] = []

    def step(name: str, fn):
        try:
            out = fn()
            ok = bool(out) and "error" not in (out if isinstance(out, dict) else {})
            results.append((name, ok, str(out)[:300]))
            print(f"  [OK]   {name}" if ok else f"  [FAIL] {name}: {out}")
        except Exception as e:
            results.append((name, False, str(e)))
            print(f"  [FAIL] {name}: {e}")

    print("=" * 78)
    print(f"RE-BREAKER v0.5.0 smoke test — vm={args.vm}")
    print("=" * 78)

    print("\n[1] QMP round-trip (re-vm-control)")
    step("qemu-monitor-command query-status", lambda: qemu_monitor_command(args.vm, {"execute": "query-status"}))

    print("\n[2] virsh snapshot_list")
    step("virsh snapshot-list", lambda: virsh("snapshot-list", args.vm, timeout_s=10))

    print("\n[3] re-vm-ssh SSH + guest_status")
    sess = None
    def ssh_ok():
        global sess
        sess = get_ssh()
        i, o, e = sess.client.exec_command("whoami", timeout=5)
        return {"whoami": o.read().decode().strip(), "stderr": e.read().decode().strip()}
    step("ssh_exec whoami", ssh_ok)

    if sess is not None:
        step("ssh_exec tasklist count", lambda: {"count": sess.client.exec_command("tasklist /FO CSV /NH", timeout=10)[1].read().decode().count("\n")})

    print("\n[4] gdb stub")
    step("gdb_stub_alive", lambda: {"alive": gdb_stub_alive()})

    if not args.skip_gdb_stub and not gdb_stub_alive():
        print("\n[4a] attach_gdb_stub (one-time VM reboot) — re-run with --skip-gdb-stub to skip")
        out = virsh("dumpxml", args.vm, timeout_s=15)
        if f"-gdb tcp::1234" in out:
            print("  XML already has the gdb stub patch; just rebooting")
        step("virsh reboot (after manual XML patch — v0.5.1 will automate)",
             lambda: (virsh("reboot", args.vm, timeout_s=15), "rebooted")[1])

    print("\n" + "=" * 78)
    n_ok = sum(1 for _, ok, _ in results if ok)
    n_total = len(results)
    print(f"Result: {n_ok}/{n_total} steps passed")
    print("=" * 78)
    return 0 if n_ok == n_total else 1


if __name__ == "__main__":
    sys.exit(main())
