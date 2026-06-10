#!/usr/bin/env python3
"""scripts/re_vm_manage_snapshots.py — thin CLI around re-vm-control
snapshot ops (v0.5.0 SCAFFOLD, plan-only).

Useful for analysts running the project without invoking the MCP
layer. Maps to:
  list   → re-vm-control.snapshot_list
  save   → re-vm-control.snapshot_create
  revert → re-vm-control.snapshot_revert
  delete → re-vm-control.snapshot_delete
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_RE_BREAKER_SRC))
from re_breaker.vm_client import DEFAULT_VM_NAME  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(prog="re_vm_manage_snapshots")
    p.add_argument("--vm", default=DEFAULT_VM_NAME)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list snapshots")

    save_p = sub.add_parser("save", help="create a snapshot")
    save_p.add_argument("name")
    save_p.add_argument("--description", default="")

    rev_p = sub.add_parser("revert", help="revert to a snapshot")
    rev_p.add_argument("name")
    rev_p.add_argument("--force", action="store_true", help="revert even if VM is running")

    del_p = sub.add_parser("delete", help="delete a snapshot")
    del_p.add_argument("name")

    args = p.parse_args()
    print(f"re_vm_manage_snapshots v0.5.0 SCAFFOLD — would call:")
    if args.cmd == "list":
        print(f"  re-vm-control.snapshot_list(vm={args.vm!r})")
    elif args.cmd == "save":
        print(f"  re-vm-control.snapshot_create(name={args.name!r}, vm={args.vm!r}, description={args.description!r})")
    elif args.cmd == "revert":
        print(f"  re-vm-control.snapshot_revert(name={args.name!r}, vm={args.vm!r}, force={args.force})")
    elif args.cmd == "delete":
        print(f"  re-vm-control.snapshot_delete(name={args.name!r}, vm={args.vm!r})")
    print()
    print(f"v0.5.0 SCAFFOLD — this CLI is a plan printer; v0.5.1 will")
    print(f"execute the calls via subprocess or by talking to the MCP")
    print(f"server over stdio.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
