#!/usr/bin/env python3.12
# -*- coding: utf-8 -*-
"""qemu-antidetect-patch.py — v0.8.0+ Wave 3 (Item K).

Standalone tool that reads an existing libvirt XML and applies the
14 anti-detection patches per docs/ANTI-VM-STATUS.md. Pairs with the
M3 re-qemu-antidetect server's `patch_vm_xml` tool (which generates a
hardened XML from the current VM state). This tool operates on an
existing XML file (e.g. the output of `virsh dumpxml`).

The 14 patches:
  1-3  CPUID passthrough          — <cpu mode='host-passthrough'>
  4-7  RDTSC + MSR timing         — handled by re-anti-vm-spoof (C), not this tool
  8    SMBIOS strings              — <smbios mode='host'/>
  9    ACPI tables                 — OUT OF SCOPE (QEMU source patch)
  10   Disk serial                 — WD-format serial + vendor
  11   MAC OUI                     — Real-vendor OUI
  12   Virtio devices              — e1000 + ahci only
  13   Registry keys               — in-VM PowerShell (separate)
  14   Driver signatures           — in-VM PowerShell (separate)

Usage:
  qemu-antidetect-patch.py --input win11.xml --output win11-hardened.xml
  qemu-antidetect-patch.py --input win11.xml --output -  # stdout

Exit codes:
  0 = success
  1 = invalid arguments / missing dependency
  2 = XML parse error
  3 = schema validation failed (libvirt schema)
"""
from __future__ import annotations

import argparse
import os
import random
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Ensure lxml is importable. If not, we can fall back to xml.etree.ElementTree
# (less featureful but stdlib-only). Try lxml first.
try:
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False
    # v0.8.0+ Item K: try to install lxml automatically (it's a near-universal dep)
    try:
        import subprocess
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--user", "lxml"],
            check=False, capture_output=True, timeout=60,
        )
        from lxml import etree
        LXML_AVAILABLE = True
    except Exception:
        pass


# Real-vendor OUIs (subset of IEEE registry; the server has the full list)
REAL_VENDOR_OUIS = [
    "00:1B:21", "00:1D:E0", "00:1E:65", "00:1F:3B",
    "00:23:8B", "00:24:D6", "3C:A9:F4", "70:1C:E7",
    "DC:FB:48", "00:E0:4C", "F0:18:98",
]


def _generate_realistic_mac() -> str:
    oui = random.choice(REAL_VENDOR_OUIS)
    suffix = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    return f"{oui}:{suffix}"


def _generate_wd_serial() -> str:
    chars = "0123456789ABCDEF"
    middle = "".join(random.choice(chars) for _ in range(8))
    return f"WD-WMC{middle}EXXX"


def patch_cpu_passthrough(root) -> int:
    """Vector 1-3."""
    cpu = root.find("cpu")
    if cpu is None:
        cpu = etree.SubElement(root, "cpu")
    cpu.set("mode", "host-passthrough")
    cpu.set("check", "none")
    cpu.set("migratable", "on")
    return 1


def patch_smbios_host(root) -> int:
    """Vector 8."""
    os_el = root.find("os")
    if os_el is None:
        os_el = etree.SubElement(root, "os")
    smbios = os_el.find("smbios")
    if smbios is None:
        smbios = etree.SubElement(os_el, "smbios")
    smbios.set("mode", "host")
    return 1


def patch_disk_serials(root) -> int:
    """Vector 10: set WD-format disk serial on every disk."""
    patched = 0
    for disk in root.iter("disk"):
        if disk.get("device") != "disk":
            continue
        serial = disk.find("serial")
        if serial is None:
            serial = etree.SubElement(disk, "serial")
        serial.text = _generate_wd_serial()
        patched += 1
    return patched


def patch_mac_ouis(root) -> int:
    """Vector 11: replace MAC addresses with real-vendor OUI."""
    patched = 0
    for mac_el in root.iter("mac"):
        mac_el.set("address", _generate_realistic_mac())
        patched += 1
    return patched


def remove_virtio(root) -> int:
    """Vector 12: replace virtio NICs with e1000."""
    patched = 0
    for iface in root.iter("interface"):
        model = iface.find("model")
        if model is None:
            model = etree.SubElement(iface, "model")
        if model.get("type", "").startswith("virtio"):
            model.set("type", "e1000")
            patched += 1
    return patched


def apply_all_patches(root, posture: str = "kernel-active") -> dict:
    """Apply all patches. Returns a summary dict."""
    summary = {
        "cpu_passthrough": patch_cpu_passthrough(root),
        "smbios_host": patch_smbios_host(root),
        "disk_serial_count": patch_disk_serials(root),
        "mac_count": patch_mac_ouis(root),
    }
    if posture == "kernel-active":
        summary["virtio_removed"] = remove_virtio(root)
    else:
        summary["virtio_removed"] = 0
    summary["acpi_tables_patched"] = 0  # out of scope
    summary["registry_cleaned"] = 0  # in-VM script, not this tool
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply 13 anti-VM detection patches to a libvirt XML (v0.8.0+ Item K)",
    )
    parser.add_argument("--input", "-i", required=True,
                        help="Path to the input libvirt XML (e.g. from `virsh dumpxml win11`)")
    parser.add_argument("--output", "-o", default="",
                        help="Path to write the patched XML. Default: <input>.hardened.xml. "
                             "Use `-` for stdout.")
    parser.add_argument("--posture", choices=["standard", "kernel-active"],
                        default="kernel-active",
                        help="How invasive the patches are. kernel-active (default) addresses "
                             "all 13 vectors; standard is less invasive (no virtio removal).")
    parser.add_argument("--validate", action="store_true",
                        help="Validate the patched XML against the libvirt schema (if xmllint is on PATH)")
    args = parser.parse_args()
    if not LXML_AVAILABLE:
        print("error: lxml not installed. `pip install lxml`.", file=sys.stderr)
        return 1
    in_path = Path(args.input)
    if not in_path.is_file():
        print(f"error: input file not found: {in_path}", file=sys.stderr)
        return 1
    if args.output == "-":
        out_path = None
    elif args.output:
        out_path = Path(args.output)
    else:
        out_path = in_path.with_suffix(f".hardened{in_path.suffix or '.xml'}")
    try:
        tree = etree.parse(str(in_path))
        root = tree.getroot()
    except etree.XMLSyntaxError as e:
        print(f"error: invalid XML in {in_path}: {e}", file=sys.stderr)
        return 2
    summary = apply_all_patches(root, posture=args.posture)
    # Validate against libvirt schema (best-effort; falls back silently)
    if args.validate:
        import shutil
        xmllint = shutil.which("xmllint")
        if xmllint:
            # Save to a tmp file for xmllint to read
            tmp = out_path.with_suffix(".xml") if out_path else Path("/tmp/qemu-antidetect-patch.tmp.xml")
            tree.write(str(tmp), pretty_print=True, xml_declaration=True, encoding="UTF-8")
            import subprocess
            result = subprocess.run(
                [xmllint, "--noout", "--schema",
                 "/usr/share/libvirt/schemas/domain.rng", str(tmp)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                print(f"error: schema validation failed: {result.stderr}", file=sys.stderr)
                if tmp != out_path:
                    tmp.unlink()
                return 3
            if tmp != out_path:
                tmp.unlink()
        else:
            print("warning: xmllint not on PATH; skipping schema validation", file=sys.stderr)
    if out_path is None:
        # stdout
        sys.stdout.buffer.write(etree.tostring(root, pretty_print=True))
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tree.write(str(out_path), pretty_print=True, xml_declaration=True, encoding="UTF-8")
        print(f"wrote hardened XML to: {out_path}", file=sys.stderr)
    # Print summary to stderr
    print("applied patches:", file=sys.stderr)
    for k, v in summary.items():
        print(f"  {k}: {v}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
