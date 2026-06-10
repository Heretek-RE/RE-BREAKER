"""RE-BREAKER re-qemu-antidetect MCP server (v0.1.0 / v0.8.0+ Wave 1, Item D).

Hardens a libvirt VM's XML across 13 of 14 known anti-VM detection vectors
(per docs/ANTI-VM-STATUS.md). Vector 9 (ACPI tables) is documented as
out of scope — requires QEMU source patches.

Tools:
  - patch_vm_xml(vm_name, target_posture): generate a hardened XML
  - validate_posture(vm_name, target): confirm none of the 14 vectors fire
  - cleanup_registry(vm_name): generate the in-VM PowerShell cleanup
  - status: server health check
"""
__version__ = "0.1.0"
