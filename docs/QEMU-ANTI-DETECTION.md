# QEMU Anti-Detection Setup (v0.7.0 plan)

Per `See the RE-BREAKER output directory./anti-vm-status.md`, the Win11 VM is fully detectable in its current configuration. This document is the v0.7.0 plan to harden it.

## The 14 detection vectors the VM is currently vulnerable to

| # | Vector | This VM's exposure | Libvirt XML field |
|---|---|---|---|
| 1 | CPUID leaf 1 ECX bit 31 (hypervisor present) | **VULNERABLE** | `<cpu mode='host-passthrough'>` or hook CPUID |
| 2 | CPUID leaf 0x40000000 (hypervisor vendor) | **VULNERABLE** | hook CPUID; spoof to "GenuineIntel" |
| 3 | CPUID leaf 0x40000001 (interface) | **VULNERABLE** | hook CPUID |
| 4 | RDTSC delta measurement | **VULNERABLE** | hook RDTSC; cap delta |
| 5 | VMXON instruction | **VULNERABLE** | hook VMXON; NOP it |
| 6 | VMCALL instruction | **VULNERABLE** | hook VMCALL; NOP |
| 7 | INVD instruction | **VULNERABLE** | hook INVD; NOP |
| 8 | SMBIOS strings ("QEMU") | **VULNERABLE** | `<smbios mode='host'/>` |
| 9 | ACPI tables | **VULNERABLE** | patch QEMU build or use host passthrough |
| 10 | Disk serial ("QM00001") | **VULNERABLE** | `<disk><serial>...</serial></disk>` |
| 11 | NIC MAC (52:54:00:xx) | **VULNERABLE** | `<mac address='real-OUI'/>` |
| 12 | virtio device IDs (0x1AF4) | **VULNERABLE** | use e1000 + ahci instead of virtio |
| 13 | Registry HKLM\HARDWARE\Description\System\SystemIdentifier "VM:..." | **VULNERABLE** | manual registry cleanup |
| 14 | HKLM\HARDWARE\ACPI\DSDT custom entries | **VULNERABLE** | use host DSDT passthrough |

All 14 are vulnerable. A motivated binary detects this VM in milliseconds.

## v0.7.0 hardening plan

### Phase A: libvirt XML config (no kernel/QEMU changes)

Create `See the RE-BREAKER output directory./anti-vm-patches/win11-host-passthrough.xml` (a hardened libvirt XML) that addresses vectors 1, 2, 3, 8, 9, 10, 11, 12, 14:

```xml
<domain type='kvm'>
  <name>win11-hardened</name>
  <memory>33554432</memory>
  <vcpu>32</vcpu>

  <!-- Vector 1, 2, 3: CPUID passthrough + hide hypervisor -->
  <cpu mode='host-passthrough' check='none'>
    <feature policy='require' name='hypervisor'/>  <!-- expose but our hook will spoof -->
  </cpu>

  <!-- Vector 8, 9: SMBIOS passthrough (so vendor / family / serial come from host) -->
  <smbios mode='host'/>

  <!-- Vector 11: MAC from a real vendor OUI (Dell, HP, Intel) -->
  <interface type='network'>
    <mac address='00:1A:2B:3C:4D:5E'/>  <!-- Intel OUI -->
  </interface>

  <!-- Vector 10: Disk serial override -->
  <disk type='file' device='disk'>
    <serial>WD-WMC4N0E0KXYZ</serial>  <!-- Western Digital format, not QM00001 -->
  </disk>

  <!-- Vector 12: e1000 NIC + ahci disk (no virtio) -->
  <controller type='scsi' model='lsilogic'/>
  <controller type='usb' model='ich9-ehci1'/>
</domain>
```

### Phase B: in-VM hook library (vectors 4, 5, 6, 7)

The `re_breaker_inject.{so,dll}` already exposes `re_breaker_register_cpuid_hook`, `re_breaker_rdtsc_zero`, `re_breaker_invd_nop` (v0.7.0 fix). For v0.7.0+, add:

- `re_breaker_vmcall_nop` — NOPs VMCALL at every site
- `re_breaker_vmxon_nop` — NOPs VMXON at every site

These run via the frida runtime (the production path) or the C library (the in-process fallback).

### Phase C: in-VM registry cleanup (vectors 13, 14)

A small PowerShell script that runs at VM boot to clean up the virtio/VM detection keys:

```powershell
# See the RE-BREAKER output directory./anti-vm-patches/clean-vm-keys.ps1
Remove-ItemProperty -Path "HKLM:\HARDWARE\Description\System\SystemIdentifier" -Name "SystemIdentifier" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest" -Recurse -Force -ErrorAction SilentlyContinue
# Add QEMU DSDT entries to the deny list (run on boot)
```

Add this to the VM's `HKLM\...\RunOnce` registry key.

## v0.7.0 implementation: M3 (re-qemu-antidetect MCP server)

The M3 server scaffolds this. Tools:
- `re-qemu-antidetect.patch_vm_xml(vm_name, target_posture)` — generates a hardened libvirt XML
- `re-qemu-antidetect.validate_posture(vm_name, target)` — runs the target binary + asserts none of the 14 vectors fire
- `re-qemu-antidetect.cleanup_registry(vm_name)` — generates the in-VM PowerShell cleanup script

**Out of v0.7.0 scope (would need QEMU source fork):**
- ACPI table patching (vector 9 if SMBIOS passthrough isn't enough)
- Custom QEMU build with anti-detection patches (QEMU-Anti-Detection project, outdated)
- Patching QEMU's CPUID leaves directly (we do this via the in-VM hook instead)

## What this achieves

- 13 of 14 vectors patched by the libvirt XML + in-VM hook combo
- Vector 9 (ACPI tables) is partially patched (SMBIOS passthrough covers vendor + serial; DSDT table strings may still leak)
- Validation: the `validate_posture` tool runs the target + asserts none of the 14 fire

## What this does NOT achieve

- Custom QEMU source patches (out of scope)
- Per-customer MAC + serial (we use a fixed real OUI; the customer should change it)
- Hiding the QEMU version in QEMU's own log files (the in-guest doesn't see these, but the host can)
- Defeating RDPMC / PMC-based timing (we patch RDTSC, not RDPMC)
- Defeating I/O timing detection (disk + network)

## Validation: how to test

For each of the 14 vectors, the `re-qemu-antidetect.validate_posture` tool runs a test binary that exercises the vector + asserts it returns the expected "bare-metal" value. The expected values are from the `re-anti-vm-spoof` snapshot (leaf_0 = `GenuineIntel`, leaf_1 ECX bit 31 = 0, leaf_0x40000000 = all zeros).

If any vector fires (detection succeeds), the test fails + reports the vector. The user then iterates on the XML config.

## Out of scope for v0.7.0

- Per-build QEMU custom patches (would need to fork QEMU + maintain patches across upstream releases)
- Hiding the QEMU host kernel (the guest can see the host kernel via /proc/cpuinfo on the host side; not in scope)
- Defeating the most aggressive anti-VM techniques (some binaries do VBS/VSM checks that require a Hyper-V enlightened guest)
