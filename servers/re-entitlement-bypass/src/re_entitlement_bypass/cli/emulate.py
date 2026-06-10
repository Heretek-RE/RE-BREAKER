"""re-ee emulate — the unified entitlement-emulation orchestrator CLI.

Usage:
    re-ee emulate <target>
        --layers=steam_ceg,eos,sega_sso       # comma-sep subset (default: all in targets.json)
        --backend=dll|http|auto               # default: auto (HTTP for new layers, DLL for Steam CEG)
        --denuvo-hypervisor=off|on|re-only    # default: auto (on for CD; off for everything else; re-only = RE notes, no deploy)
        --wine-prefix=/path/to/prefix         # default: discover from ~/.cache/re-breaker-wine-<target>
        --dry-run                              # plan only
        --rollback                             # undo last deploy
        --audit                                # re-verify without re-deploying
        --override-sow-gate=I-understand-the-SOW-implications  # skip the SOW check
        --json                                  # machine-readable JSON output

Examples:
    # Plan FM26 with 3 layers
    re-ee emulate fm26 --dry-run --layers=steam_ceg,eos,sega_sso

    # Deploy FM26
    re-ee emulate fm26 --layers=steam_ceg,eos,sega_sso

    # Audit HKIA
    re-ee emulate hkia --audit

    # Roll back TWW3
    re-ee emulate tww3 --rollback

    # List all known targets
    re-ee emulate --list

    # Reverse-engineer Atlus wire format from P3R (Phase 1 RE)
    re-ee emulate p3r --re-wire

    # Document the Denuvo hypervisor technique (RE-only)
    re-ee emulate cd --denuvo-hypervisor=re-only
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

# v0.4.0: ensure RE-BREAKER's shared src/ is on the Python path
_RE_BREAKER_SRC = Path(__file__).resolve().parent.parent.parent.parent.parent.parent / "src"
if str(_RE_BREAKER_SRC) not in sys.path:
    sys.path.insert(0, str(_RE_BREAKER_SRC))

# Also ensure our own package is on the path
_PKG_PARENT = Path(__file__).resolve().parent.parent.parent
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("re-ee")

from re_entitlement_bypass.core.layer_base import LAYER_REGISTRY, get_deployer
from re_entitlement_bypass.core.sow_gate import SOWGate
from re_entitlement_bypass.core.status import DeployStatus, LayerDeployStatus
from re_entitlement_bypass.core.target_manifest import TargetManifest
from re_entitlement_bypass.core.wire_re import extract_url_patterns, extract_json_keys, extract_pipe_names, write_wire_sig

# Import the backends so they self-register in LAYER_REGISTRY
from re_entitlement_bypass.backends import http  # noqa: F401  (import for side effects)
from re_entitlement_bypass.backends import dll  # noqa: F401
from re_entitlement_bypass.backends.base import hypervisor_base  # noqa: F401
# Explicitly import the deployer modules so their @register decorators fire
from re_entitlement_bypass.backends.http import (  # noqa: F401
    eos_emulator, ioi_emulator, sega_sso_emulator, atlus_emulator, sunblink_emulator, pa_emulator, origin_emulator,
)
from re_entitlement_bypass.backends.dll import steam_ceg_dll, eos_sdk_dll  # noqa: F401


# Registry of all known targets (loaded from data/targets.json)
_MANIFEST = TargetManifest.load_default()


def _resolve_backend(layer: str, backend_arg: str) -> str:
    """Resolve the backend for a layer per the --backend flag.

    --backend=auto: DLL for steam_ceg, HTTP for everything else.
    --backend=dll: require DLL backend; error if not registered.
    --backend=http: require HTTP backend; error if not registered.
    """
    if backend_arg == "auto":
        return "dll" if layer == "steam_ceg" else "http"
    if backend_arg == "dll":
        registered = LAYER_REGISTRY.get(layer)
        if registered and registered.backend.startswith("dll/"):
            return "dll"
        raise SystemExit(f"Layer '{layer}' has no DLL backend registered (Phase 2 SCAFFOLD). Use --backend=http or --backend=auto.")
    if backend_arg == "http":
        registered = LAYER_REGISTRY.get(layer)
        if registered and registered.backend.startswith("http/"):
            return "http"
        raise SystemExit(f"Layer '{layer}' has no HTTP backend registered.")
    raise SystemExit(f"Unknown --backend={backend_arg}; expected auto|dll|http")


def cmd_list_targets(args: argparse.Namespace) -> int:
    """List all known targets + their layer configurations."""
    rows = []
    for key in _MANIFEST.target_keys:
        t = _MANIFEST.get(key)
        rows.append({
            "target": key,
            "sow": t.sow or "<none>",
            "exe": t.exe,
            "layers": t.layers,
            "denuvo_check": t.denuvo_check or "n/a",
            "denuvo_carveout": t.denuvo_carveout,
        })
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(f"{'Target':<8} {'SOW':<6} {'Layers':<40} {'Denuvo':<10} Notes")
        print("-" * 100)
        for r in rows:
            print(f"{r['target']:<8} {r['sow']:<6} {','.join(r['layers']):<40} {r['denuvo_check']:<10} {'(carve-out)' if r['denuvo_carveout'] else ''}")
    return 0


def cmd_re_wire(args: argparse.Namespace) -> int:
    """Reverse-engineer the wire format from the target's binaries.

    Runs the wire_re utilities (URL patterns, JSON keys, named-pipe names)
    against the target's directory tree, writes a wire_sigs/<target>.json,
    and reports the findings.
    """
    if not _MANIFEST.has(args.target):
        print(f"ERROR: unknown target '{args.target}'", file=sys.stderr)
        return 2
    target_dir = args.input_dir
    if target_dir is None:
        # Default to the Input/ tree next to the engagement root
        engagement_root = Path("os.environ.get("RE_BREAKER_PLUGIN_ROOT", ".")/Input")
        # The target key may differ from the dir name (e.g. "p3r" → "P3R")
        target_dir = engagement_root / args.target
        if not target_dir.exists():
            for candidate in engagement_root.iterdir():
                if candidate.is_dir() and candidate.name.lower() == args.target.lower():
                    target_dir = candidate
                    break
    if not target_dir.exists():
        print(f"ERROR: target dir does not exist: {target_dir}", file=sys.stderr)
        return 2
    print(f"RE-wiring {args.target} from {target_dir}...")
    urls = extract_url_patterns(target_dir)
    json_keys = extract_json_keys(target_dir)
    pipes = extract_pipe_names(target_dir)
    output_dir = Path(__file__).resolve().parent.parent / "data" / "wire_sigs"
    out = write_wire_sig(args.target, output_dir, urls, json_keys, pipes)
    print(f"Found: {len(urls)} URLs, {len(json_keys)} JSON keys, {len(pipes)} named-pipes")
    print(f"Wrote: {out}")
    if not args.json:
        if urls:
            print("\nURLs (first 10):")
            for u in urls[:10]:
                print(f"  {u}")
        if json_keys:
            print("\nJSON keys (first 20):")
            for k in json_keys[:20]:
                print(f"  {k}")
        if pipes:
            print("\nNamed-pipes:")
            for p in pipes:
                print(f"  \\\\.\\pipe\\{p}")
    return 0


def cmd_emulate(args: argparse.Namespace) -> int:
    """The main `emulate` command. Plan, deploy, rollback, or audit."""
    if not _MANIFEST.has(args.target):
        print(f"ERROR: unknown target '{args.target}'", file=sys.stderr)
        print(f"Valid targets: {_MANIFEST.target_keys}", file=sys.stderr)
        return 2
    target = _MANIFEST.get(args.target)
    wine_prefix = Path(args.wine_prefix) if args.wine_prefix else None

    # Resolve the layer list
    if args.layers:
        layers = [l.strip() for l in args.layers.split(",")]
    else:
        layers = target.layers

    # Validate layers
    known_layers = {layer for (layer, _) in LAYER_REGISTRY.keys()}
    for layer in layers:
        if layer not in known_layers:
            print(f"ERROR: no deployer registered for layer '{layer}'", file=sys.stderr)
            print(f"Known layers: {sorted(known_layers)}", file=sys.stderr)
            return 2

    # SOW gate check
    sow_gate_ok = True
    sow_gate_reason = None
    for layer in layers:
        allowed, reason = SOWGate.check(target.sow, layer, override=args.override_sow_gate)
        if not allowed:
            sow_gate_ok = False
            sow_gate_reason = reason
            break

    if not sow_gate_ok:
        status = DeployStatus(
            target=target.key,
            sow=target.sow,
            sow_gate="refused",
            sow_gate_reason=sow_gate_reason,
            dry_run=args.dry_run,
        )
        if args.json:
            print(status.to_json())
        else:
            print(f"REFUSED: {sow_gate_reason}", file=sys.stderr)
        return 3

    # Dispatch per layer
    layer_statuses: dict[str, LayerDeployStatus] = {}
    start = time.time()
    for layer in layers:
        backend_kind = _resolve_backend(layer, args.backend)
        deployer = get_deployer(layer, backend_kind=backend_kind)
        if args.rollback:
            layer_statuses[layer] = deployer.rollback(target, wine_prefix=wine_prefix)
        elif args.audit:
            layer_statuses[layer] = deployer.audit(target, wine_prefix=wine_prefix)
        elif args.dry_run:
            layer_statuses[layer] = deployer.plan(target, dry_run=True)
        else:
            layer_statuses[layer] = deployer.deploy(target, wine_prefix=wine_prefix)
    duration = time.time() - start

    status = DeployStatus(
        target=target.key,
        sow=target.sow,
        sow_gate="ok",
        layers=layer_statuses,
        dry_run=args.dry_run,
        duration_sec=duration,
    )

    if args.json:
        print(status.to_json())
    else:
        print(f"Target: {status.target} (SOW-{status.sow or 'none'})")
        print(f"SOW gate: {status.sow_gate}")
        print(f"Duration: {status.duration_sec:.2f}s")
        print(f"Mode: {'rollback' if args.rollback else 'audit' if args.audit else 'dry-run' if args.dry_run else 'deploy'}")
        print()
        for layer_name, layer_status in status.layers.items():
            print(f"  [{layer_status.status:<12}] {layer_name:<12} ({layer_status.backend})")
            if layer_status.bind:
                print(f"      bind:     {layer_status.bind}")
            if layer_status.hosts_lines:
                print(f"      hosts:    {len(layer_status.hosts_lines)} entries")
            if layer_status.sha256:
                print(f"      sha256:   {list(layer_status.sha256.values())[0][:16]}... ({len(layer_status.sha256)} files)")
            if layer_status.deployed_paths:
                print(f"      paths:    {len(layer_status.deployed_paths)} files")
                for p in layer_status.deployed_paths[:3]:
                    print(f"        - {p}")
                if len(layer_status.deployed_paths) > 3:
                    print(f"        ... ({len(layer_status.deployed_paths) - 3} more)")
            if layer_status.note:
                print(f"      note:     {layer_status.note}")
            if layer_status.error:
                print(f"      ERROR:    {layer_status.error}")
    return 0


def cmd_denuvo_re_only(args: argparse.Namespace) -> int:
    """Document the Denuvo hypervisor technique (RE-only on this engagement)."""
    print("Denuvo hypervisor bypass — RE-only on this engagement (no Windows host).")
    print()
    print("See the following documents for the technique walkthrough:")
    print("  - servers/re-entitlement-bypass/src/re_entitlement_bypass/backends/hypervisor/simplesvm_re_notes.md")
    print("  - servers/re-entitlement-bypass/src/re_entitlement_bypass/backends/hypervisor/hyperkd_re_notes.md")
    print("  - servers/re-entitlement-bypass/src/re_entitlement_bypass/backends/hypervisor/technique_summary.md")
    print("  - docs/PLAYBOOKS/denuvo-hypervisor-technique.md")
    print()
    print("Reference: DenuvOwO at Input/Crimson.Desert.Build.23578264-DenuvOwO/")
    print("  - DenuvOwO.ini: per-target patch table")
    print("  - coldloader.dll: in-process injection shim")
    print("  - cd_id.dll: per-game identity marker (sets DR3 magic)")
    print("  - DenuvOwO_SRC_V6/SimpleSvm/: AMD-V hypervisor source (BSD, Satoshi Tanda)")
    print("  - DenuvOwO_SRC_V6/HypervisorSource/: Intel VT-x hypervisor source (HyperDbg fork, GPLv2)")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """The main entry point for `re-ee emulate`."""
    # Pre-process argv: if first arg is not a known subcommand and not a flag,
    # prepend 'emulate' to make the default subcommand work.
    if argv is None:
        argv = sys.argv[1:]
    known_subcmds = ("emulate", "list", "re-wire", "denuvo")
    if argv and argv[0] not in known_subcmds and not argv[0].startswith("-"):
        argv = ["emulate"] + list(argv)

    parser = argparse.ArgumentParser(prog="re-ee emulate", description="RE-BREAKER unified entitlement-emulation orchestrator (v0.2.0)")
    sub = parser.add_subparsers(dest="subcmd", required=False)

    # emulate (default subcommand)
    p_emulate = sub.add_parser("emulate", help="emulate a target's entitlement layers")
    p_emulate.add_argument("target", help="target key (e.g. fm26, hkia, 007fl, tww3, p3r, lir, cd)")
    p_emulate.add_argument("--layers", help="comma-sep layer list (default: all in targets.json)")
    p_emulate.add_argument("--backend", choices=["auto", "dll", "http"], default="auto")
    p_emulate.add_argument("--denuvo-hypervisor", choices=["off", "on", "re-only"], default="auto")
    p_emulate.add_argument("--wine-prefix", help="WINEPREFIX path (default: discover from ~/.cache/re-breaker-wine-<target>)")
    p_emulate.add_argument("--dry-run", action="store_true", help="plan only, no writes")
    p_emulate.add_argument("--rollback", action="store_true", help="undo last deploy")
    p_emulate.add_argument("--audit", action="store_true", help="re-verify without re-deploying")
    p_emulate.add_argument("--override-sow-gate", action="store_true", help="skip the SOW ethical-wall check")
    p_emulate.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p_emulate.set_defaults(func=cmd_emulate)

    # list
    p_list = sub.add_parser("list", help="list known targets + their layer configurations")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list_targets)

    # re-wire
    p_rewire = sub.add_parser("re-wire", help="reverse-engineer a target's wire format (Phase 1 RE)")
    p_rewire.add_argument("target", help="target key")
    p_rewire.add_argument("--input-dir", help="target's binary dir (default: Input/<target>)")
    p_rewire.add_argument("--json", action="store_true")
    p_rewire.set_defaults(func=cmd_re_wire)

    # denuvo
    p_denuvo = sub.add_parser("denuvo", help="document the Denuvo hypervisor technique (RE-only)")
    p_denuvo.set_defaults(func=cmd_denuvo_re_only)

    args = parser.parse_args(argv)

    # If no subcommand, default to emulate with the first positional
    if args.subcmd is None:
        # Re-parse with emulate as the default
        if argv and argv[0] not in ("emulate", "list", "re-wire", "denuvo", "-h", "--help"):
            argv = ["emulate"] + list(argv)
        else:
            parser.print_help()
            return 0
        args = parser.parse_args(argv)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
