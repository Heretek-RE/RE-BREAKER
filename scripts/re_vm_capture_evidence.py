#!/usr/bin/env python3
"""scripts/re_vm_capture_evidence.py — capture VM state for analyst
review (v0.5.0 SCAFFOLD).

Bundles:
  - process list + loaded modules (via re-vm-ssh.ssh_exec tasklist)
  - SPICE screenshot (via re-vm-control.screenshot_via_spice)
  - last 30s of re-vm-launch events (v0.5.1 will read from the
    launch registry; v0.5.0 stub)

Writes `Output/<date>-vm-evidence/` with timestamped files and a
`REPORT.md` summary.
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_RE_BREAKER_SRC))
from re_breaker.vm_client import _plugin_root, DEFAULT_VM_NAME  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--vm", default=DEFAULT_VM_NAME)
    p.add_argument("--output", type=Path, help="output dir (default: <plugin>/Output/<date>-vm-evidence)")
    args = p.parse_args()

    plugin = _plugin_root()
    date = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    out = args.output or (plugin / "Output" / f"{date}-vm-evidence")
    out.mkdir(parents=True, exist_ok=True)

    print(f"RE-BREAKER v0.5.0 evidence capture (SCAFFOLD)")
    print(f"  vm    = {args.vm}")
    print(f"  out   = {out}")
    print()
    print("v0.5.0 SCAFFOLD — this script prints the would-call for each")
    print("step. v0.5.1 will actually run the SSH + virsh + QMP calls.")
    print()

    plan = [
        ("process_list.txt", "tasklist /v /FO LIST", "via re-vm-ssh.ssh_exec"),
        ("loaded_modules.txt", "wmic process get Name,ProcessId,CommandLine /FORMAT:LIST", "via re-vm-ssh.ssh_exec"),
        ("screen.ppm", "virsh screendump win11 screen.ppm", "via re-vm-control.screenshot_via_spice"),
        ("qmp_query_status.json", '{"execute":"query-status"}', "via re-vm-control.qemu_monitor_command"),
        ("launch_events.txt", "(read from re-vm-launch registry; v0.5.1)", "v0.5.1"),
    ]
    for fname, cmd, via in plan:
        print(f"  {fname:30s} ← {via}")
        print(f"      cmd: {cmd}")
    print()
    print(f"Next: implement in v0.5.1; until then, copy the above into")
    print(f"the equivalent tool calls.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
