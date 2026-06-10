#!/usr/bin/env python3
"""Build the full RE-BREAKER catalog (50 entries) and merge into data/catalog.json.

This script is run once at scaffold time and again whenever a new catalog
entry is added. The output is the canonical data/catalog.json that the
re-catalog-match MCP server reads at runtime.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT / "data" / "catalog.json"
# Header version for the rendered YARA file. Read from the catalog if
# present; otherwise hardcoded to the last-known version.
try:
    _CATALOG_VERSION = json.loads(CATALOG_PATH.read_text()).get("version", "0.5.0")
except (FileNotFoundError, json.JSONDecodeError):
    _CATALOG_VERSION = "0.5.0"


# ---- The 42 additional entries (8 encrypted-vm already in catalog.json) ----

ANTI_DEBUG_ENTRIES = [
    {
        "id": "anti-debug.rdtsc-timing-trap",
        "version": 1,
        "name": "RDTSC timing-trap (anti-debugger / anti-VM detection)",
        "family": "anti-debug",
        "aliases": ["RDTSC delta measurement", "TSC skew detection", "0F 31 opcode pattern"],
        "severity": "high",
        "defender": {
            "summary": "Reads the Time Stamp Counter twice and measures the delta. If the delta exceeds a threshold (typically 100-1000 cycles), the code assumes a debugger or VM is single-stepping.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "0F 31", "confidence": 0.5, "min_count": 5},
                {"type": "structural", "value": "rdtsc_pairs_in_function(min_count=1)", "confidence": 0.7}
            ],
            "false_positive_risks": ["Performance-counter usage is also legitimate. Confirm with the RDTSC-pair pattern."],
            "see_also": ["anti-vm.cpuid-leaf-1-ecx-bit-31", "anti-debug.int2d"]
        },
        "offender": {
            "summary": "Two strategies: (a) hook the RDTSC instruction to return a constant value (0x1000 = 'always 4096 cycles, regardless of actual TSC'); (b) at static-patch time, replace each `rdtsc` opcode (`0F 31`) with a `xor eax, eax; xor edx, edx` (8 bytes total: `33 C0 33 D2`). Strategy (b) is per-binary but reliable; strategy (a) is reusable.",
            "tools": ["re-anti-debug-patch", "re-frida"],
            "playbook": "playbooks/anti-debug-rdtsc.md",
            "expected_runtime_minutes": 20,
            "skill_complexity": "easy",
            "success_probability": 0.95,
            "limitations": ["Per-binary patching; the strategy needs to be re-applied per build."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-debug-primitives"},
            {"type": "other", "path_or_id": "See the RE-AI output directory.", "note": "007FL has 1966 RDTSC sites."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.int2d",
        "version": 1,
        "name": "INT 0x2d (anti-debugger trap)",
        "family": "anti-debug",
        "aliases": ["INT 2D", "0xCD 0x2D", "Kernel debugger notification"],
        "severity": "medium",
        "defender": {
            "summary": "Executes INT 0x2d. Under a kernel debugger, this triggers the debugger to gain control. Under a user-mode debugger (or no debugger), INT 0x2d is a no-op or raises EXCEPTION_BREAKPOINT.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "CD 2D", "confidence": 0.8, "min_count": 1}
            ],
            "false_positive_risks": ["Very low. INT 0x2d has no legitimate use in user-mode code."],
            "see_also": ["anti-debug.int3", "anti-debug.peb-beingdebugged"]
        },
        "offender": {
            "summary": "NOP-out the INT 0x2d (replace 2 bytes `CD 2D` with `90 90` = two NOPs). Or hook the exception handler to ignore EXCEPTION_BREAKPOINT.",
            "tools": ["re-anti-debug-patch", "re-patch"],
            "playbook": "playbooks/anti-debug-int2d.md",
            "expected_runtime_minutes": 5,
            "skill_complexity": "trivial",
            "success_probability": 1.0,
            "limitations": ["None."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-debug-primitives"},
            {"type": "other", "path_or_id": "See the RE-AI output directory.", "note": "P3R has 200+ INT 2D sites."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.int3",
        "version": 1,
        "name": "INT 3 (anti-debugger trap or padding)",
        "family": "anti-debug",
        "aliases": ["INT 3", "0xCC", "BREAKPOINT opcode", "Padding/alignment trap"],
        "severity": "low",
        "defender": {
            "summary": "Executes INT 3 (0xCC). Under a debugger, this triggers the debugger to gain control. As padding, 0xCC is the canonical x86 `int3` instruction used to fill unused space.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "CC", "confidence": 0.3, "min_count": 1}
            ],
            "false_positive_risks": ["VERY high. 0xCC is everywhere in x86 binaries as padding. Per-function disassembly is required to distinguish padding from anti-debug trap."],
            "see_also": ["anti-debug.int2d", "anti-debug.peb-beingdebugged"]
        },
        "offender": {
            "summary": "If a function entry-point or specific control-flow path has 0xCC, the function is a trap. Replace the 0xCC with 0x90 (NOP) and the function continues normally. If 0xCC is in a tail-padding region (post-RET), it's just padding — no action needed.",
            "tools": ["re-anti-debug-patch", "re-rizin"],
            "playbook": "playbooks/anti-debug-int3.md",
            "expected_runtime_minutes": 10,
            "skill_complexity": "easy",
            "success_probability": 0.9,
            "limitations": ["Requires per-function disassembly to identify which 0xCC bytes are traps vs padding. 0xCC is the most ambiguous primitive in x86."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-debug-primitives"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.cpuid-hypervisor-leaf-1-ecx-bit-31",
        "version": 1,
        "name": "CPUID leaf 1 ECX bit 31 (hypervisor present)",
        "family": "anti-debug",
        "aliases": ["CPUID.1.ECX.31", "HypervisorPresent bit", "0F A2 opcode followed by bt ecx, 0x1F"],
        "severity": "high",
        "defender": {
            "summary": "Executes CPUID with EAX=1, then tests bit 31 of ECX. If set, the CPU is running under a hypervisor. Used to detect VM/sandbox environments.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "0F A2", "confidence": 0.4, "min_count": 5},
                {"type": "structural", "value": "cpuid_leaf1_bit_31_test(min_count=1)", "confidence": 0.85}
            ],
            "false_positive_risks": ["CPUID is used legitimately for many purposes. Confirm with the bit-31-test pattern."],
            "see_also": ["anti-vm.cpuid-leaf-1-ecx-bit-31", "anti-vm.cpuid-leaf-0x40000000-vendor"]
        },
        "offender": {
            "summary": "Hook CPUID to return 0 for bit 31 of ECX when EAX=1. The 'bare-metal' CPUID snapshot is the source of the spoofed value.",
            "tools": ["re-anti-vm-spoof", "re-frida"],
            "playbook": "playbooks/anti-vm-cpuid.md",
            "expected_runtime_minutes": 15,
            "skill_complexity": "medium",
            "success_probability": 0.95,
            "limitations": ["Some protectors also check the timing of CPUID (CPUID should take ~100 cycles; under VM it can take 1000+). Combine with the RDTSC timing-trap bypass for full coverage."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.cpuid-hypervisor-leaf-0x40000000-vendor",
        "version": 1,
        "name": "CPUID leaf 0x40000000 (hypervisor vendor string)",
        "family": "anti-debug",
        "aliases": ["CPUID.0x40000000", "Hypervisor vendor", "VMWare/VBox/Hyper-V detection"],
        "severity": "high",
        "defender": {
            "summary": "Executes CPUID with EAX=0x40000000, returns the hypervisor vendor string in EBX/ECX/EDX (e.g. 'VMwareVMware' for VMware, 'VBoxVBoxVBoxVBox' for VirtualBox, 'Microsoft Hv' for Hyper-V).",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "0F A2 81", "confidence": 0.6},
                {"type": "structural", "value": "cpuid_leaf_0x40000000_call(min_count=1)", "confidence": 0.9}
            ],
            "false_positive_risks": ["Low. CPUID with EAX >= 0x40000000 has no legitimate use in user-mode code."],
            "see_also": ["anti-vm.cpuid-leaf-1-ecx-bit-31", "anti-vm.vmware-io-backdoor"]
        },
        "offender": {
            "summary": "Hook CPUID to return the bare-metal vendor string for EAX=0x40000000 (typically 12 zero bytes for no hypervisor). Some sophisticated protectors also test that the spoofed vendor string doesn't match the strings in the I/O port backdoor (see anti-vm.vmware-io-backdoor).",
            "tools": ["re-anti-vm-spoof", "re-frida"],
            "playbook": "playbooks/anti-vm-cpuid.md",
            "expected_runtime_minutes": 20,
            "skill_complexity": "medium",
            "success_probability": 0.9,
            "limitations": ["Some protectors also probe I/O ports 0x5658 ('VX') for VMware or magic MSRs for Hyper-V."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.vmxon-vmcs",
        "version": 1,
        "name": "VMXON / VMCS (Intel VT-x detection)",
        "family": "anti-debug",
        "aliases": ["VMXON", "0F C7", "VMCS, VMXON instruction"],
        "severity": "high",
        "defender": {
            "summary": "Attempts to execute VMXON (Intel VT-x virtualization). If the CPU supports VT-x and VMXON is not already in use, the CPU enters VMX operation. Used to detect the presence of a hypervisor and to fingerprint Intel VT-x capabilities.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "0F C7", "confidence": 0.3, "min_count": 5}
            ],
            "false_positive_risks": ["0F C7 is also the CMPXCHG16B opcode. Confirm with VMCS-region setup code."],
            "see_also": ["anti-debug.cpuid-hypervisor-leaf-1-ecx-bit-31", "anti-debug.vmcall"]
        },
        "offender": {
            "summary": "Hook the VMXON instruction to return #UD (undefined opcode). The binary's VMXON probe then sees 'VT-x not available' and treats the environment as bare-metal.",
            "tools": ["re-anti-vm-spoof", "re-frida"],
            "playbook": "playbooks/anti-vm-vmx.md",
            "expected_runtime_minutes": 30,
            "skill_complexity": "hard",
            "success_probability": 0.7,
            "limitations": ["VMXON can also be detected via CPUID VMX feature bits. Combine with the leaf-1-ECX-bit-31 bypass."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.vmcall",
        "version": 1,
        "name": "VMCALL (hypervisor call)",
        "family": "anti-debug",
        "aliases": ["VMCALL", "0F 01 C1", "Hyper-V hypercall"],
        "severity": "high",
        "defender": {
            "summary": "Executes VMCALL (0F 01 C1). If the CPU is in VMX non-root operation, VMCALL traps to the hypervisor. If the hypervisor doesn't handle the call, the CPU injects #UD. The probe is used to detect the presence of a hypervisor (and to fingerprint it via the hypercall number).",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "0F 01 C1", "confidence": 0.85, "min_count": 1}
            ],
            "false_positive_risks": ["Low. VMCALL has no legitimate use in user-mode code outside of VMX-aware tools."],
            "see_also": ["anti-debug.vmxon-vmcs", "anti-vm.hyper-v-tlfs"]
        },
        "offender": {
            "summary": "Hook VMCALL to return without trapping. Or use CPUID feature-bit masking to disable VMX (less common; most CPUs have VMX forced-on).",
            "tools": ["re-anti-vm-spoof", "re-frida"],
            "playbook": "playbooks/anti-vm-vmx.md",
            "expected_runtime_minutes": 30,
            "skill_complexity": "hard",
            "success_probability": 0.8,
            "limitations": ["Some protectors also probe VMCS magic numbers via RDMSR."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.invd",
        "version": 1,
        "name": "INVD (anti-emulator detection)",
        "family": "anti-debug",
        "aliases": ["INVD", "0F 08", "Invalidate cache, no-flush"],
        "severity": "medium",
        "defender": {
            "summary": "Executes INVD (invalidate caches, no flush). Real CPUs handle this in microcode. Some emulators (Speakeasy, QEMU without TCG acceleration, Unicorn) crash or behave incorrectly. Used to detect emulated execution.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "0F 08", "confidence": 0.5, "min_count": 1}
            ],
            "false_positive_risks": ["INVD has no legitimate use in user-mode code; if present, it's anti-emulator. False-positive rate is <5%."],
            "see_also": ["anti-debug.cpuid-hypervisor-leaf-1-ecx-bit-31"]
        },
        "offender": {
            "summary": "Hook INVD to be a NOP (or a benign no-op). For emulators: enable TCG acceleration or handle the INVD instruction in the emulator. For Frida: replace `INVD` with `NOP; NOP` (2 bytes).",
            "tools": ["re-anti-vm-spoof", "re-frida", "re-runtime-dump --mode=emulator"],
            "playbook": "playbooks/anti-debug-invd.md",
            "expected_runtime_minutes": 5,
            "skill_complexity": "trivial",
            "success_probability": 0.95,
            "limitations": ["If the emulator supports INVD natively (e.g. Speakeasy 1.5.11 does), no action is needed."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.peb-beingdebugged",
        "version": 1,
        "name": "PEB.BeingDebugged (Windows Process Environment Block)",
        "family": "anti-debug",
        "aliases": ["IsDebuggerPresent", "PEB.BeingDebugged", "kernel32!IsDebuggerPresent"],
        "severity": "low",
        "defender": {
            "summary": "Reads the PEB.BeingDebugged byte (offset 0x02 in the PEB on x64, 0x02 on x86). When the process is being debugged, this byte is 1. IsDebuggerPresent() is the canonical API that wraps this read.",
            "detection_signatures": [
                {"type": "string_match", "value": "IsDebuggerPresent", "confidence": 0.95},
                {"type": "byte_sequence", "value": "65 48 8B 04 25 60 00 00 00", "confidence": 0.7, "note": "mov rax, gs:[0x60] = read PEB on x64"}
            ],
            "false_positive_risks": ["Low. The IsDebuggerPresent string is almost always present in any Windows binary, including legitimate ones. Confirm with the actual read of PEB.BeingDebugged."],
            "see_also": ["anti-debug.ntqueryinformationprocess-debugport", "anti-debug.checkremotedebuggerpresent"]
        },
        "offender": {
            "summary": "Patch the PEB.BeingDebugged byte to 0. Or hook the IsDebuggerPresent function. Or use a tool like ScyllaHide (x64dbg plugin) to hide from PEB.BeingDebugged at debug-time.",
            "tools": ["re-anti-debug-patch", "re-patch", "x64dbg ScyllaHide (external)"],
            "playbook": "playbooks/anti-debug-peb.md",
            "expected_runtime_minutes": 5,
            "skill_complexity": "trivial",
            "success_probability": 1.0,
            "limitations": ["The protector may also check NtQueryInformationProcess(ProcessDebugPort), which is a different probe. Combine with that bypass for full coverage."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-debug-primitives"},
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.ntqueryinformationprocess-debugport",
        "version": 1,
        "name": "NtQueryInformationProcess(ProcessDebugPort) (Windows kernel debug detection)",
        "family": "anti-debug",
        "aliases": ["ProcessDebugPort", "NtQueryInformationProcess", "DebugPort = -1"],
        "severity": "medium",
        "defender": {
            "summary": "Calls NtQueryInformationProcess with the ProcessDebugPort information class. When the process is being debugged (kernel-mode debugger attached), the kernel returns a non-zero DebugPort (typically -1 on x64).",
            "detection_signatures": [
                {"type": "string_match", "value": "NtQueryInformationProcess", "confidence": 0.6},
                {"type": "byte_sequence", "value": "B8 07 00 00 00", "confidence": 0.3, "note": "mov eax, 7 = ProcessDebugPort info class on x86"}
            ],
            "false_positive_risks": ["Low. The pattern of NtQueryInformationProcess(ProcessDebugPort) is anti-debug."],
            "see_also": ["anti-debug.peb-beingdebugged", "anti-debug.checkremotedebuggerpresent"]
        },
        "offender": {
            "summary": "Hook NtQueryInformationProcess to return 0 for ProcessDebugPort. ScyllaHide and TitanHide do this automatically. Some protectors also check ProcessDebugObjectHandle, ProcessDebugFlags — combine with those bypasses for full coverage.",
            "tools": ["re-anti-debug-patch", "x64dbg ScyllaHide (external)"],
            "playbook": "playbooks/anti-debug-peb.md",
            "expected_runtime_minutes": 10,
            "skill_complexity": "easy",
            "success_probability": 0.95,
            "limitations": ["Some protectors also check ProcessDebugObjectHandle. Combine with that bypass for full coverage."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-debug-primitives"},
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-debug.checkremotedebuggerpresent",
        "version": 1,
        "name": "CheckRemoteDebuggerPresent (cross-process debugger detection)",
        "family": "anti-debug",
        "aliases": ["CheckRemoteDebuggerPresent", "kernel32!CheckRemoteDebuggerPresent"],
        "severity": "low",
        "defender": {
            "summary": "Calls CheckRemoteDebuggerPresent against the current process or a peer process. Returns true if a debugger is attached to the target process.",
            "detection_signatures": [
                {"type": "string_match", "value": "CheckRemoteDebuggerPresent", "confidence": 0.95}
            ],
            "false_positive_risks": ["Low. The string is almost always anti-debug-related."],
            "see_also": ["anti-debug.peb-beingdebugged", "anti-debug.ntqueryinformationprocess-debugport"]
        },
        "offender": {
            "summary": "Hook CheckRemoteDebuggerPresent to return FALSE. ScyllaHide handles this.",
            "tools": ["re-anti-debug-patch", "x64dbg ScyllaHide (external)"],
            "playbook": "playbooks/anti-debug-peb.md",
            "expected_runtime_minutes": 5,
            "skill_complexity": "trivial",
            "success_probability": 1.0,
            "limitations": ["None significant."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-debug-primitives"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    }
]


ANTI_VM_ENTRIES = [
    {
        "id": "anti-vm.smbios-dmidecode",
        "version": 1,
        "name": "SMBIOS / DMI table read (VM detection)",
        "family": "anti-vm",
        "aliases": ["SMBIOS", "DMI", "GetSystemFirmwareTable", "RSMB"],
        "severity": "high",
        "defender": {
            "summary": "Reads the SMBIOS (System Management BIOS) table, which contains firmware info, manufacturer, product name, etc. VM hypervisors often identify themselves in the SMBIOS (e.g. 'VMware Virtual Platform', 'VirtualBox', 'Microsoft Corporation' for Hyper-V, 'QEMU').",
            "detection_signatures": [
                {"type": "string_match", "value": "GetSystemFirmwareTable", "confidence": 0.85},
                {"type": "string_match", "value": "\\\\\\\\.\\\\\\\\SMBios", "confidence": 0.7}
            ],
            "false_positive_risks": ["Some legitimate firmware-info tools read SMBIOS. Confirm with the regex match on the manufacturer string."],
            "see_also": ["anti-vm.acpi-facp", "anti-vm.registry-key-entropy"]
        },
        "offender": {
            "summary": "Hook GetSystemFirmwareTable('RSMB', ...) to return a forged SMBIOS table with bare-metal manufacturer (e.g. 'American Megatrends Inc.' or 'Dell Inc.' or 'HP' instead of 'VMware, Inc.').",
            "tools": ["re-anti-vm-spoof", "re-frida"],
            "playbook": "playbooks/anti-vm-smbios.md",
            "expected_runtime_minutes": 25,
            "skill_complexity": "medium",
            "success_probability": 0.85,
            "limitations": ["Some protectors also checksum the SMBIOS table against known-good values. The forged SMBIOS must checksum correctly."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"},
            {"type": "other", "path_or_id": "See the RE-AI output directory.", "note": "All 4 main AAA binaries have 1 SMBIOS/ACPI keyword hit."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-vm.acpi-facp",
        "version": 1,
        "name": "ACPI FACP table (VM detection via hypervisor vendor)",
        "family": "anti-vm",
        "aliases": ["ACPI", "FACP", "Firmware ACPI Description Table", "OEMID"],
        "severity": "high",
        "defender": {
            "summary": "Reads the ACPI FADT (Fixed ACPI Description Table). The OEMID field is 6 bytes and identifies the firmware vendor. Hypervisors often set distinctive OEMIDs (e.g. 'VMWARE', 'VBOX', 'MS_HV').",
            "detection_signatures": [
                {"type": "string_match", "value": "ACPI", "confidence": 0.4},
                {"type": "byte_sequence", "value": "46 41 43 50 01", "confidence": 0.5, "note": "FACP signature"}
            ],
            "false_positive_risks": ["ACPI is used legitimately for power management. Confirm with the FADT-parsing code."],
            "see_also": ["anti-vm.smbios-dmidecode"]
        },
        "offender": {
            "summary": "Hook the ACPI table read to return a forged FADT with a bare-metal OEMID.",
            "tools": ["re-anti-vm-spoof", "re-frida"],
            "playbook": "playbooks/anti-vm-smbios.md",
            "expected_runtime_minutes": 30,
            "skill_complexity": "hard",
            "success_probability": 0.7,
            "limitations": ["The ACPI table is also reachable via the registry at HKLM\\HARDWARE\\ACPI; some protectors cross-check both sources."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-vm.registry-key-entropy",
        "version": 1,
        "name": "Registry-key entropy probe (HWID via registry)",
        "family": "anti-vm",
        "aliases": ["RegOpenKeyExW", "RegQueryValueExW", "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"],
        "severity": "medium",
        "defender": {
            "summary": "Reads 5-10 registry keys (HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion, HKLM\\SOFTWARE\\Microsoft\\Cryptography, etc.) and concatenates their values to form a hardware fingerprint. VMs often have predictable registry values.",
            "detection_signatures": [
                {"type": "string_match", "value": "RegOpenKeyExW", "confidence": 0.4},
                {"type": "string_match", "value": "RegQueryValueExW", "confidence": 0.4},
                {"type": "string_match", "value": "HKLM", "confidence": 0.3}
            ],
            "false_positive_risks": ["Registry reads are very common. Confirm with the entropy-concatenation pattern."],
            "see_also": ["anti-vm.smbios-dmidecode", "encrypted-vm.bytecode-interpreter.pattern-b"]
        },
        "offender": {
            "summary": "Hook the registry read functions to return a 'bare-metal' snapshot of the registry values. Alternatively, set the registry to the right values at the host level (persistent).",
            "tools": ["re-anti-vm-spoof", "re-frida", "host-level registry prep"],
            "playbook": "playbooks/anti-vm-registry.md",
            "expected_runtime_minutes": 40,
            "skill_complexity": "hard",
            "success_probability": 0.6,
            "limitations": ["The list of probed keys is per-binary; you need to identify the probed keys first."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-vm.network-adapter-mac-prefix",
        "version": 1,
        "name": "Network adapter MAC prefix (VM detection via MAC OUI)",
        "family": "anti-vm",
        "aliases": ["GetAdaptersAddresses", "MAC OUI", "00:0C:29 (VMware), 08:00:27 (VirtualBox), 00:1C:42 (Parallels)"],
        "severity": "high",
        "defender": {
            "summary": "Reads the network adapters' MAC addresses and checks the OUI (organizationally unique identifier) prefix against known VM vendors. Common VM OUIs: 00:0C:29 (VMware), 08:00:27 (VirtualBox), 00:1C:42 (Parallels), 00:50:56 (VMware again).",
            "detection_signatures": [
                {"type": "string_match", "value": "GetAdaptersAddresses", "confidence": 0.85}
            ],
            "false_positive_risks": ["GetAdaptersAddresses is used legitimately for many purposes. Confirm with the OUI-check pattern."],
            "see_also": ["anti-vm.smbios-dmidecode"]
        },
        "offender": {
            "summary": "At the host level, set the network adapter's MAC to a bare-metal OUI (e.g. an Intel OUI like 00:1B:21, 00:1D:E0, 00:23:6C, 00:24:D6, 00:26:5A, 00:26:C6, 00:26:F0, etc.). Alternatively, hook GetAdaptersAddresses at runtime to return the spoofed MAC.",
            "tools": ["re-anti-vm-spoof", "host-level MAC set"],
            "playbook": "playbooks/anti-vm-mac.md",
            "expected_runtime_minutes": 15,
            "skill_complexity": "easy",
            "success_probability": 0.95,
            "limitations": ["Host-level MAC set is the most reliable; runtime hook is a fallback."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"},
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md", "note": "MAC OUI list as referenced."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-vm.vmware-io-backdoor",
        "version": 1,
        "name": "VMware I/O backdoor (port 0x5658 'VX')",
        "family": "anti-vm",
        "aliases": ["VMWare I/O backdoor", "Port 0x5658", "IN 0x5658 'VX'", "Magic I/O port"],
        "severity": "high",
        "defender": {
            "summary": "Communicates with the VMware hypervisor via the magic I/O port 0x5658. IN EAX, 0x5658 with EAX='VX' (0x56415858) returns 'VMw' (0x564D7772) under VMware. This is the most reliable VMware detection.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "66 B8 58 56", "confidence": 0.7, "note": "mov ax, 0x5658"},
                {"type": "byte_sequence", "value": "ED", "confidence": 0.5, "note": "in al, dx"}
            ],
            "false_positive_risks": ["Low. Port 0x5658 reads are not used for legitimate purposes in user-mode code."],
            "see_also": ["anti-vm.cpuid-hypervisor-leaf-0x40000000-vendor"]
        },
        "offender": {
            "summary": "Hook the I/O port reads. Speakeasy and QEMU can intercept IN instructions; for native execution, use a hypervisor (HyperHide) or a custom kernel driver. Easiest: at the host level, change the VMware backdoor port or use HyperHide.",
            "tools": ["re-anti-vm-spoof", "HyperHide (external)"],
            "playbook": "playbooks/anti-vm-vmware.md",
            "expected_runtime_minutes": 60,
            "skill_complexity": "expert",
            "success_probability": 0.6,
            "limitations": ["Requires a kernel-mode handler. User-mode-only approaches are incomplete."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-vm.vbox-io-backdoor",
        "version": 1,
        "name": "VirtualBox I/O backdoor (port 0x5658 / VBoxGuest)",
        "family": "anti-vm",
        "aliases": ["VBoxGuest", "VBoxGuest.sys", "VBox I/O backdoor", "VBOX_CPUID"],
        "severity": "high",
        "defender": {
            "summary": "Similar to the VMware I/O backdoor, VirtualBox uses port 0x5658 (or via the VBoxGuest kernel driver). The VBOX_CPUID leaf can be used to detect VirtualBox.",
            "detection_signatures": [
                {"type": "string_match", "value": "VBoxGuest", "confidence": 0.95},
                {"type": "string_match", "value": "VBoxService", "confidence": 0.9},
                {"type": "byte_sequence", "value": "66 B8 58 56", "confidence": 0.5}
            ],
            "false_positive_risks": ["VBoxGuest is only present if VirtualBox guest additions are installed. Some VMs don't have it."],
            "see_also": ["anti-vm.vmware-io-backdoor"]
        },
        "offender": {
            "summary": "Uninstall VirtualBox guest additions. Or use HyperHide to hide VBoxGuest device.",
            "tools": ["HyperHide (external)"],
            "playbook": "playbooks/anti-vm-vbox.md",
            "expected_runtime_minutes": 10,
            "skill_complexity": "easy",
            "success_probability": 0.9,
            "limitations": ["Uninstalling guest additions is the most reliable approach."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-vm.hyper-v-tlfs",
        "version": 1,
        "name": "Hyper-V Top-Level Functional Specification (TLFS) probes",
        "family": "anti-vm",
        "aliases": ["Hyper-V", "TLFS", "CPUID 0x40000001", "Hyper-V interface"],
        "severity": "high",
        "defender": {
            "summary": "Reads Hyper-V-specific MSRs (IA32_FEATURE_CONTROL, HV_X64_MSR_GUEST_OS_ID, HV_X64_MSR_HYPERCALL) via RDMSR. Hyper-V exposes a 'Microsoft Hv' vendor string and a specific set of hypercall numbers.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "0F 32", "confidence": 0.4, "note": "RDMSR"},
                {"type": "string_match", "value": "Microsoft Hv", "confidence": 0.85}
            ],
            "false_positive_risks": ["RDMSR is used legitimately by some performance tools. Confirm with the Hyper-V-specific MSR numbers."],
            "see_also": ["anti-vm.vmware-io-backdoor", "anti-debug.vmxon-vmcs"]
        },
        "offender": {
            "summary": "Hook RDMSR to return zero for the Hyper-V MSRs. Or use HyperHide to mask the Hyper-V interface.",
            "tools": ["re-anti-vm-spoof", "HyperHide (external)"],
            "playbook": "playbooks/anti-vm-hyper-v.md",
            "expected_runtime_minutes": 45,
            "skill_complexity": "expert",
            "success_probability": 0.7,
            "limitations": ["RDMSR is privileged; user-mode hooks require a kernel-mode handler."]
        },
        "references": [
            {"type": "anti_tamper_taxonomy", "path_or_id": "ANTI-TAMPER-TAXONOMY.md#anti-vm"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    }
]


MBA_ENTRIES = [
    {
        "id": "mba.x_plus_y_equals_xor_xor_y_carry",
        "version": 1,
        "name": "MBA identity: x + y = (x XOR y) + 2*(x AND y)",
        "family": "mba",
        "aliases": ["Mixed Boolean-Arithmetic identity", "x + y = (x XOR y) + 2*(x AND y)", "Algebraic simplification"],
        "severity": "low",
        "defender": {
            "summary": "The identity x + y = (x XOR y) + 2*(x AND y) is the canonical MBA identity. Detected by finding the pattern of XOR + AND + LSL1 + ADD instructions.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "31 C0 23 C1", "confidence": 0.4, "note": "xor eax, eax; and eax, ecx"},
                {"type": "byte_sequence", "value": "31 C8 D1 E0", "confidence": 0.4, "note": "xor eax, ecx; shl eax, 1"}
            ],
            "false_positive_risks": ["The patterns are common in optimized code. Confirm with the algebraic structure."],
            "see_also": ["mba.x_plus_y_equals_x_and_y_plus_x_or_y"]
        },
        "offender": {
            "summary": "Use re-mba-deobfuscate skill or re-triton to symbolically simplify the expression. The pattern collapses back to `x + y` after simplification.",
            "tools": ["re-mba-deobfuscate", "re-triton"],
            "playbook": "playbooks/mba-simplify.md",
            "expected_runtime_minutes": 15,
            "skill_complexity": "medium",
            "success_probability": 0.95,
            "limitations": ["Some MBA identities are intentionally added to thwart symbolic execution. The Triton + Z3 constraint solver should still converge."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md", "note": "MBA simplification reference."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "mba.x_plus_y_equals_x_and_y_plus_x_or_y",
        "version": 1,
        "name": "MBA identity: x + y = (x AND y) + (x OR y)",
        "family": "mba",
        "aliases": ["Mixed Boolean-Arithmetic identity #2", "x + y = (x AND y) + (x OR y)"],
        "severity": "low",
        "defender": {
            "summary": "Another canonical MBA identity. Detected by finding the pattern of AND + OR + ADD.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "21 C1 09 C8", "confidence": 0.4, "note": "and ecx, eax; or eax, ecx"}
            ],
            "false_positive_risks": ["Common pattern. Confirm with algebraic structure."],
            "see_also": ["mba.x_plus_y_equals_xor_xor_y_carry"]
        },
        "offender": {
            "summary": "Same as mba.x_plus_y_equals_xor_xor_y_carry — simplify with re-mba-deobfuscate.",
            "tools": ["re-mba-deobfuscate"],
            "playbook": "playbooks/mba-simplify.md",
            "expected_runtime_minutes": 15,
            "skill_complexity": "medium",
            "success_probability": 0.95,
            "limitations": ["None significant."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "mba.xor-substitution",
        "version": 1,
        "name": "MBA identity: XOR via (a|b) - (a&b)",
        "family": "mba",
        "aliases": ["XOR via OR - AND", "XOR substitution"],
        "severity": "low",
        "defender": {
            "summary": "a XOR b = (a | b) - (a & b). Detected by finding the pattern of OR + AND + SUB.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "09 C1 21 C8 29 C8", "confidence": 0.5, "note": "or ecx, eax; and eax, ecx; sub ecx, eax"}
            ],
            "false_positive_risks": ["Less common pattern; fewer false positives."],
            "see_also": ["mba.x_plus_y_equals_xor_xor_y_carry"]
        },
        "offender": {
            "summary": "Simplify with re-mba-deobfuscate.",
            "tools": ["re-mba-deobfuscate"],
            "playbook": "playbooks/mba-simplify.md",
            "expected_runtime_minutes": 10,
            "skill_complexity": "easy",
            "success_probability": 1.0,
            "limitations": ["None."]
        },
        "references": [],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "mba.opaque-predicate-xor",
        "version": 1,
        "name": "Opaque predicate: (x XOR x) is always 0",
        "family": "mba",
        "aliases": ["Opaque predicate", "x XOR x = 0", "Control-flow obfuscation"],
        "severity": "low",
        "defender": {
            "summary": "An opaque predicate is an expression that always evaluates to a constant at runtime, but cannot be simplified at compile-time. The canonical example is (x XOR x) = 0 — but with MBA obfuscation, the predicate can be much more complex.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "33 C0", "confidence": 0.3, "note": "xor eax, eax"}
            ],
            "false_positive_risks": ["XOR reg, reg is used legitimately to zero a register. Confirm with the predicate usage pattern (always followed by a conditional branch)."],
            "see_also": ["mba.opaque-predicate-and", "obfuscation.control-flow-flattening"]
        },
        "offender": {
            "summary": "Use re-triton or re-angr with symbolic execution to evaluate the predicate symbolically. If it always evaluates to 0 (or always to 1), the predicate is opaque and the conditional branch can be removed.",
            "tools": ["re-triton", "re-angr", "re-mba-deobfuscate"],
            "playbook": "playbooks/opaque-predicate.md",
            "expected_runtime_minutes": 30,
            "skill_complexity": "hard",
            "success_probability": 0.7,
            "limitations": ["Some opaque predicates are intentionally complex; symbolic execution may not converge in reasonable time."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "mba.opaque-predicate-and",
        "version": 1,
        "name": "Opaque predicate: (x AND 0) is always 0",
        "family": "mba",
        "aliases": ["Opaque predicate (AND)", "x AND 0 = 0"],
        "severity": "low",
        "defender": {
            "summary": "Similar to the XOR variant. The predicate (x AND 0) is always 0 but is often obfuscated to (x AND ((y XOR y) | 0)) which is still 0.",
            "detection_signatures": [
                {"type": "byte_sequence", "value": "83 E0 00", "confidence": 0.3, "note": "and eax, 0"}
            ],
            "false_positive_risks": ["Same as the XOR variant."],
            "see_also": ["mba.opaque-predicate-xor"]
        },
        "offender": {
            "summary": "Same approach — symbolic evaluation with re-triton / re-angr.",
            "tools": ["re-triton", "re-angr"],
            "playbook": "playbooks/opaque-predicate.md",
            "expected_runtime_minutes": 30,
            "skill_complexity": "hard",
            "success_probability": 0.7,
            "limitations": ["Same as the XOR variant."]
        },
        "references": [],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "mba.ffmpeg-emu-cf",
        "version": 1,
        "name": "FFmpeg emulator control-flow MBA (inspiration: OLLVM)",
        "family": "mba",
        "aliases": ["OLLVM-style control-flow flattening", "MBA + control-flow flattening", "FLA"],
        "severity": "high",
        "defender": {
            "summary": "OLLVM (Obfuscator-LLVM) is the most widely deployed open-source obfuscator. Its 'control-flow flattening' pass transforms structured control flow into a single switch statement with an opaque-predicate-driven state variable. Combined with MBA, this is the strongest open-source obfuscation pattern.",
            "detection_signatures": [
                {"type": "structural", "value": "single_function.body_contains_switch_state_variable(min_count=1) AND switch_state_variable_opaque(min_count=1)",
                    "confidence": 0.8}
            ],
            "false_positive_risks": ["Some legitimate interpreters use a state machine. Confirm with the MBA + opaque-predicate combination."],
            "see_also": ["obfuscation.control-flow-flattening", "mba.opaque-predicate-xor"]
        },
        "offender": {
            "summary": "Use re-vtil's control-flow-unflatten pass (with the OLLVM catalog pass set) or re-angr's CFG recovery. The switch + state variable can be unflattened back to structured if/else/while.",
            "tools": ["re-vtil", "re-angr", "re-mba-deobfuscate"],
            "playbook": "playbooks/ollvm-cf-unflatten.md",
            "expected_runtime_minutes": 60,
            "skill_complexity": "hard",
            "success_probability": 0.6,
            "limitations": ["OLLVM's control-flow flattening can be combined with virtualization (FLA + VIR), which makes the unflatten + VIR-lift pipeline much harder."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md", "note": "MBA reference."},
            {"type": "other", "path_or_id": "https://github.com/obfuscator-llvm/obfuscator", "note": "The OLLVM upstream."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    }
]


ANTI_TAMPER_VENDORS_ENTRIES = [
    {
        "id": "anti-tamper-vendors.denuvo",
        "version": 1,
        "name": "Denuvo Anti-Tamper (Denuvo Anti-Cheat is a separate product)",
        "family": "anti-tamper-vendors",
        "aliases": ["Denuvo", "Denuvo Anti-Tamper", "DAT"],
        "severity": "critical",
        "defender": {
            "summary": "Denuvo is a commercial anti-tamper solution used by major AAA game titles. It uses a combination of encrypted-VM bytecode interpreter + POGO-based profile-guided-optimization triggers + online license validation. Per the v2.9.0 stress test, the canonical example is Persona 3 Reload (P3R.exe, 373MB, 19 sections).",
            "detection_signatures": [
                {"type": "string_match", "value": "denuvo", "confidence": 0.95, "note": "The string 'denuvo' typically appears in the binary (often in plaintext, sometimes in encrypted sections)."},
                {"type": "structural", "value": "section_set_intersects([.arch, .sbss, .xcode, .xpdata, .xtext, .xtls]) AND debug_directory.contains_pogo_entry(size >= 1000)",
                    "confidence": 0.9}
            ],
            "false_positive_risks": ["Low. POGO + .arch is a very specific signature."],
            "see_also": ["encrypted-vm.bytecode-interpreter.pattern-a-dw", "anti-debug.rdtsc-timing-trap"]
        },
        "offender": {
            "summary": "Months of per-title work. Denuvo is the hardest commercial ATD; there is no public bypass. The realistic approaches are: (a) dump decrypted regions + bypass the online license check (still requires the binary to phone home to Denuvo's server); (b) emulate the binary in a sandbox where the RDTSC trap is neutralized (the Denuvo VFS traps RDTSC anomalies with high confidence); (c) wait for Denuvo to retire the entitlement (publishers do this when they deprecate the game).",
            "tools": ["re-vm-decrypt", "re-runtime-dump", "re-encrypted-vm-bypass", "re-anti-debug-patch", "re-anti-vm-spoof"],
            "playbook": "playbooks/denuvo-bypass.md",
            "expected_runtime_minutes": 9999,
            "skill_complexity": "expert",
            "success_probability": 0.1,
            "limitations": ["Denuvo Anti-Tamper is the hardest commercial protection. No public bypass exists."]
        },
        "references": [
            {"type": "re_unleashed_doc", "path_or_id": "publishers/atlus-sega/persona-3-reload/", "note": "The P3R per-game doc (the canonical Denuvo ATD case)."},
            {"type": "other", "path_or_id": "See the RE-AI output directory.", "note": "P3R stress test (3 'denuvo' string hits + full A-DW section set)."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.vmprotect",
        "version": 1,
        "name": "VMProtect (encrypted-VM bytecode interpreter)",
        "family": "anti-tamper-vendors",
        "aliases": ["VMProtect", "VMP", "VMP3.5", "VMPSoft"],
        "severity": "critical",
        "defender": {
            "summary": "VMProtect is a commercial protector that uses an encrypted-VM bytecode interpreter to protect native code. VMP 3.x is the current major version. VMP-protected binaries have a distinct section layout (.vmp0, .vmp1) and a dispatcher that decrypts and executes one VM handler at a time.",
            "detection_signatures": [
                {"type": "string_match", "value": ".vmp0", "confidence": 0.95, "note": "VMP section name."},
                {"type": "string_match", "value": "VMProtect", "confidence": 0.95, "note": "VMP version string."}
            ],
            "false_positive_risks": ["Very low. VMP section names are highly specific."],
            "see_also": ["encrypted-vm.bytecode-interpreter.pattern-a", "anti-tamper-vendors.themida"]
        },
        "offender": {
            "summary": "The VMP open-source community has produced several tools: `void-stack/VMUnprotect`, `can1357/NoVmp`, `wallds/NoVmpy`, `fjqisba/VmpHelper`, `CabboShiba/VMPBypass`, `chramiq/de4vmp`, `Shhoya/MutantKiller`, `r3bb1t/vmp_analyzer`, `crowbar-team/vmp-import-resolver`, `nelj14/vmprotect-dumper`, `Thiviyan/VMProfiler-QT`, `keowu/birosca`. The approach: hook VMP's dispatcher, dump each VM handler as it executes.",
            "tools": ["re-vm-decrypt", "re-runtime-dump"],
            "playbook": "playbooks/vmprotect-bypass.md",
            "expected_runtime_minutes": 240,
            "skill_complexity": "expert",
            "success_probability": 0.4,
            "limitations": ["Per-build breakable. VMP 3.5+ uses rolling keys + custom handlers. The open-source tools are most effective against VMP 3.0-3.4."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://github.com/void-stack/VMUnprotect"},
            {"type": "other", "path_or_id": "https://github.com/can1357/NoVmp"},
            {"type": "other", "path_or_id": "https://github.com/wallds/NoVmpy"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.themida",
        "version": 1,
        "name": "Themida / WinLicense (encrypted-VM bytecode interpreter)",
        "family": "anti-tamper-vendors",
        "aliases": ["Themida", "WinLicense", "Oreans Technologies"],
        "severity": "critical",
        "defender": {
            "summary": "Themida and WinLicense are commercial protectors from Oreans Technologies. They use an encrypted-VM bytecode interpreter + advanced anti-debug tricks. The .themida and .winlice section names are the canonical identifier.",
            "detection_signatures": [
                {"type": "string_match", "value": ".themida", "confidence": 0.95, "note": "Themida section name."},
                {"type": "string_match", "value": ".winlice", "confidence": 0.95, "note": "WinLicense section name."}
            ],
            "false_positive_risks": ["Very low."],
            "see_also": ["anti-tamper-vendors.vmprotect"]
        },
        "offender": {
            "summary": "Similar to VMP — hook the dispatcher, dump each handler. Themida's open-source bypasses are less mature than VMP's. The `Keowu/birosca` project and a few others have partial success.",
            "tools": ["re-vm-decrypt", "re-runtime-dump"],
            "playbook": "playbooks/themida-bypass.md",
            "expected_runtime_minutes": 360,
            "skill_complexity": "expert",
            "success_probability": 0.3,
            "limitations": ["Themida's anti-debug is more aggressive than VMP's; some handlers have built-in debugger detection."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://github.com/keowu/birosca", "note": "Themida/WinLicense analysis project."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.starforce",
        "version": 1,
        "name": "StarForce (legacy disc-based + driver-based protection)",
        "family": "anti-tamper-vendors",
        "aliases": ["StarForce", "Star Force", "Protection Technology"],
        "severity": "high",
        "defender": {
            "summary": "StarForce is a legacy commercial protection solution that uses a kernel-mode driver + disc-based copy-protection. Newer titles rarely use it; older titles (mid-2000s) do.",
            "detection_signatures": [
                {"type": "string_match", "value": "StarForce", "confidence": 0.95},
                {"type": "string_match", "value": "protect\\.sys", "confidence": 0.85, "note": "StarForce kernel driver."}
            ],
            "false_positive_risks": ["Low."],
            "see_also": ["anti-tamper-vendors.denuvo"]
        },
        "offender": {
            "summary": "For legacy disc-based StarForce: emulate the disc-check via daemon tools + scsi emulation. For modern StarForce (rare): hook the driver at the kernel-mode level.",
            "tools": ["re-anti-vm-spoof", "daemon-tools"],
            "playbook": "playbooks/starforce-bypass.md",
            "expected_runtime_minutes": 120,
            "skill_complexity": "medium",
            "success_probability": 0.7,
            "limitations": ["StarForce is largely deprecated; modern titles use Denuvo/VMP/Themida instead."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://www.star-force.com/", "note": "StarForce homepage (now mostly marketing)."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.arxan",
        "version": 1,
        "name": "Arxan / Digital.ai (code-protection + app-shielding)",
        "family": "anti-tamper-vendors",
        "aliases": ["Arxan", "Digital.ai App Protection", "Guardsquare DexGuard", "Promon SHIELD"],
        "severity": "high",
        "defender": {
            "summary": "Arxan (now part of Digital.ai) is a commercial code-protection solution. Used in financial-services apps + some mobile games. The .arxan section name is the canonical identifier.",
            "detection_signatures": [
                {"type": "string_match", "value": "Arxan", "confidence": 0.95},
                {"type": "string_match", "value": ".arxan", "confidence": 0.95}
            ],
            "false_positive_risks": ["Low."],
            "see_also": ["anti-tamper-vendors.denuvo", "anti-tamper-vendors.vmprotect"]
        },
        "offender": {
            "summary": "Arxan's open-source bypasses are less mature than VMP/Themida. The approach: hook Arxan's integrity-check calls, dump decrypted regions. Some protectors use a JIT compiler that is harder to hook.",
            "tools": ["re-vm-decrypt", "re-runtime-dump"],
            "playbook": "playbooks/arxan-bypass.md",
            "expected_runtime_minutes": 240,
            "skill_complexity": "expert",
            "success_probability": 0.4,
            "limitations": ["Arxan is often used in mobile (Android/iOS) rather than desktop. The .dex bytecode makes the bypass different."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://digital.ai/app-protection"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.ezfuscator",
        "version": 1,
        "name": "Eazfuscator.NET (.NET obfuscator)",
        "family": "anti-tamper-vendors",
        "aliases": ["Eazfuscator.NET", "Eazfuscator"],
        "severity": "medium",
        "defender": {
            "summary": "Eazfuscator.NET is a commercial .NET obfuscator. The .NET metadata is preserved (so re-dotnet can still parse the type graph) but the IL is heavily obfuscated (string encryption, control-flow obfuscation, method-body encryption).",
            "detection_signatures": [
                {"type": "string_match", "value": "Eazfuscator", "confidence": 0.95},
                {"type": "string_match", "value": "{Eazfuscator}", "confidence": 0.95, "note": "Embedded as a custom attribute."}
            ],
            "false_positive_risks": ["Low."],
            "see_also": ["obfuscation.control-flow-flattening", "obfuscation.string-encryption-aes"]
        },
        "offender": {
            "summary": "For Eazfuscator.NET, use the open-source deobfuscators: `NotPrab/.NET-Deobfuscator`, `holly-hacker/EazFixer`, `Washi1337/AsmResolver`, `Col-E/Recaf`. The approach: deobfuscate the IL with the deobfuscator, then re-decompile with re-dotnet.",
            "tools": ["re-dotnet", "re-dotnet-patch", "EazFixer (external)"],
            "playbook": "playbooks/eazfuscator-bypass.md",
            "expected_runtime_minutes": 30,
            "skill_complexity": "easy",
            "success_probability": 0.85,
            "limitations": ["Some Eazfuscator features (string encryption with custom keys) require per-target key extraction."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://github.com/NotPrab/.NET-Deobfuscator"},
            {"type": "other", "path_or_id": "https://github.com/holly-hacker/EazFixer"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.code-virtualizer",
        "version": 1,
        "name": "Code Virtualizer / VMProtect (overlap)",
        "family": "anti-tamper-vendors",
        "aliases": ["Code Virtualizer", "CV"],
        "severity": "high",
        "defender": {
            "summary": "Code Virtualizer is a product similar to VMProtect. See anti-tamper-vendors.vmprotect for the analysis approach.",
            "detection_signatures": [
                {"type": "string_match", "value": "Code Virtualizer", "confidence": 0.9}
            ],
            "false_positive_risks": ["Low."],
            "see_also": ["anti-tamper-vendors.vmprotect"]
        },
        "offender": {
            "summary": "Same as VMProtect. The VMP open-source tools (`VMUnprotect`, `NoVmp`) are effective.",
            "tools": ["re-vm-decrypt", "re-runtime-dump"],
            "playbook": "playbooks/vmprotect-bypass.md",
            "expected_runtime_minutes": 240,
            "skill_complexity": "expert",
            "success_probability": 0.4,
            "limitations": ["Same as VMProtect."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://www.oreans.com/codevirtualizer.php"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.executioner-cpp-obfuscator",
        "version": 1,
        "name": "Executioner C++ Obfuscator (open-source C++ obfuscator)",
        "family": "anti-tamper-vendors",
        "aliases": ["Executioner", "executioner-cpp-obfuscator"],
        "severity": "medium",
        "defender": {
            "summary": "Executioner is an open-source C++ source-to-source obfuscator. The output binaries have control-flow flattening + string encryption + opaque predicates. Less protection than commercial VMP/Themida but commonly used by malware + some indie protectors.",
            "detection_signatures": [
                {"type": "string_match", "value": "Executioner", "confidence": 0.9, "note": "The string 'Executioner' may appear in the binary's debug info or in the .rdata."}
            ],
            "false_positive_risks": ["Low."],
            "see_also": ["obfuscation.control-flow-flattening"]
        },
        "offender": {
            "summary": "For Executioner, use re-vtil's control-flow-unflatten pass + re-mba-deobfuscate for the MBA simplification. The string encryption uses XOR with a constant key (per-build); extract the key from the .rdata, decrypt.",
            "tools": ["re-vtil", "re-mba-deobfuscate"],
            "playbook": "playbooks/executioner-bypass.md",
            "expected_runtime_minutes": 45,
            "skill_complexity": "medium",
            "success_probability": 0.8,
            "limitations": ["Some Executioner features (custom MBA identities) are per-target."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://github.com/33dotflag/Executioner-CPP-Obfsucator", "note": "Upstream."}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.intel-sgx-enclave",
        "version": 1,
        "name": "Intel SGX enclave (TEE-based protection)",
        "family": "anti-tamper-vendors",
        "aliases": ["Intel SGX", "SGX enclave", "TEE", "Trusted Execution Environment"],
        "severity": "high",
        "defender": {
            "summary": "Intel SGX (Software Guard Extensions) is a TEE that allows an application to execute code in a hardware-isolated 'enclave'. The enclave's contents are encrypted in DRAM; even the OS cannot read them. Used by some DRM + financial-services apps.",
            "detection_signatures": [
                {"type": "string_match", "value": "sgx_", "confidence": 0.7, "note": "sgx_* API prefixes."},
                {"type": "structural", "value": "binary.contains_sgx_metadata()", "confidence": 0.95}
            ],
            "false_positive_risks": ["Low. SGX enclaves are explicit in the binary."],
            "see_also": ["anti-tamper-vendors.apple-fairplay"]
        },
        "offender": {
            "summary": "SGX enclaves are designed to be unbreakable from outside. The realistic approaches: (a) side-channel attacks (e.g. Spectre, Foreshadow); (b) fault injection (e.g. voltage glitching); (c) extract the enclave's sealing key from the platform. None are software-only.",
            "tools": ["external side-channel tools", "external fault-injection tools"],
            "playbook": "playbooks/sgx-bypass.md",
            "expected_runtime_minutes": 9999,
            "skill_complexity": "expert",
            "success_probability": 0.05,
            "limitations": ["SGX is a hardware-isolated TEE. Software-only approaches are ineffective. Side-channel + fault-injection are the only paths."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "anti-tamper-vendors.apple-fairplay",
        "version": 1,
        "name": "Apple FairPlay (DRM-adjacent, not in 'drm/' category)",
        "family": "anti-tamper-vendors",
        "aliases": ["Apple FairPlay", "FairPlay Streaming", "FPS"],
        "severity": "high",
        "defender": {
            "summary": "Apple FairPlay is Apple's DRM for video streaming (FairPlay Streaming) and iOS apps (FairPlay). It's DRM, not anti-tamper, but it's mentioned here for completeness. Detected by the .fps, .fai, or .fpc section names + the 'Apple FairPlay' string.",
            "detection_signatures": [
                {"type": "string_match", "value": "FairPlay", "confidence": 0.9},
                {"type": "string_match", "value": ".fps", "confidence": 0.6}
            ],
            "false_positive_risks": ["The string 'FairPlay' may appear in legitimate Apple code; confirm with the section names."],
            "see_also": ["anti-tamper-vendors.intel-sgx-enclave"]
        },
        "offender": {
            "summary": "FairPlay is a DRM system. Bypassing it is not within RE-BREAKER's scope (DRM-bypass is a different threat model). The catalog entry is here for completeness.",
            "tools": [],
            "playbook": None,
            "expected_runtime_minutes": 0,
            "skill_complexity": "n/a",
            "success_probability": 0.0,
            "limitations": ["DRM bypass is out of scope for RE-BREAKER."]
        },
        "references": [
            {"type": "other", "path_or_id": "https://developer.apple.com/streaming/fps/"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry. Listed for completeness; out of RE-BREAKER's offense-research scope."}]
    }
]


OBFUSCATION_ENTRIES = [
    {
        "id": "obfuscation.control-flow-flattening",
        "version": 1,
        "name": "Control-flow flattening (OLLVM-style)",
        "family": "obfuscation",
        "aliases": ["CFF", "Control-flow flattening", "Switch-state variable obfuscation"],
        "severity": "medium",
        "defender": {
            "summary": "Transforms structured control flow (if/else/while) into a single switch statement with a state variable. The state variable is driven by an opaque predicate.",
            "detection_signatures": [
                {"type": "structural", "value": "single_function.body_contains_switch_state_variable(min_count=1)",
                    "confidence": 0.85}
            ],
            "false_positive_risks": ["Some legitimate interpreters use a state machine. Confirm with the opaque-predicate combination."],
            "see_also": ["mba.ffmpeg-emu-cf", "mba.opaque-predicate-xor"]
        },
        "offender": {
            "summary": "Use re-vtil's control-flow-unflatten pass (with the OLLVM catalog pass set) or re-angr's CFG recovery. The switch + state variable can be unflattened back to structured if/else/while.",
            "tools": ["re-vtil", "re-angr"],
            "playbook": "playbooks/cf-flattening.md",
            "expected_runtime_minutes": 45,
            "skill_complexity": "medium",
            "success_probability": 0.85,
            "limitations": ["Some CFG-recovery tools don't handle large functions (1000+ basic blocks) well."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "obfuscation.opaque-predicate",
        "version": 1,
        "name": "Opaque predicate (general)",
        "family": "obfuscation",
        "aliases": ["Opaque predicate", "Always-true / always-false expression"],
        "severity": "low",
        "defender": {
            "summary": "An expression that always evaluates to a constant at runtime, but cannot be simplified at compile-time. Used to obscure control flow.",
            "detection_signatures": [
                {"type": "structural", "value": "branch.condition_is_opaque_predicate(min_count=1)",
                    "confidence": 0.7}
            ],
            "false_positive_risks": ["Hard to detect statically. Confirm with symbolic execution."],
            "see_also": ["mba.opaque-predicate-xor", "mba.opaque-predicate-and"]
        },
        "offender": {
            "summary": "Use re-triton or re-angr with symbolic execution. The opaque predicate evaluates to 0 or 1; the conditional branch can then be removed.",
            "tools": ["re-triton", "re-angr"],
            "playbook": "playbooks/opaque-predicate.md",
            "expected_runtime_minutes": 30,
            "skill_complexity": "hard",
            "success_probability": 0.6,
            "limitations": ["Some opaque predicates are intentionally complex; symbolic execution may not converge."]
        },
        "references": [],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "obfuscation.virtualization-obfuscator",
        "version": 1,
        "name": "Virtualization obfuscator (general)",
        "family": "obfuscation",
        "aliases": ["Virtualization obfuscation", "Code virtualization", "VM-based obfuscation"],
        "severity": "high",
        "defender": {
            "summary": "The original code is converted to bytecode for a custom VM. The VM is then compiled into the protected binary. The VM's dispatcher interprets the bytecode one instruction at a time.",
            "detection_signatures": [
                {"type": "structural", "value": "function.body_contains_dispatcher_loop_with_dispatch_table(min_count=1)",
                    "confidence": 0.8}
            ],
            "false_positive_risks": ["Some legitimate interpreters use a similar pattern. Confirm with the encryption of the dispatch table."],
            "see_also": ["encrypted-vm.bytecode-interpreter.pattern-a", "anti-tamper-vendors.vmprotect"]
        },
        "offender": {
            "summary": "Same as for any encrypted-VM bytecode interpreter: hook the dispatcher, dump each VM handler as it executes, lift to readable IL.",
            "tools": ["re-vm-decrypt", "re-runtime-dump", "re-vtil"],
            "playbook": "playbooks/encrypted-vm-bytecode-interpreter-pattern-a.md",
            "expected_runtime_minutes": 120,
            "skill_complexity": "hard",
            "success_probability": 0.5,
            "limitations": ["Per-VM. The VM's specific handler semantics must be understood."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/02-vm-bytecode-interpreter.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "obfuscation.string-encryption-xor",
        "version": 1,
        "name": "String encryption: XOR with constant key",
        "family": "obfuscation",
        "aliases": ["String XOR encryption", "Static XOR key", "Common in malware + light protectors"],
        "severity": "low",
        "defender": {
            "summary": "String literals in the binary are XOR-encrypted with a constant key. The key is typically embedded in the binary as an immediate value or a small array of immediates.",
            "detection_signatures": [
                {"type": "structural", "value": "function.body_contains_xor_loop_over_string_table(min_count=1)",
                    "confidence": 0.7}
            ],
            "false_positive_risks": ["Many legitimate binaries use XOR for their own data."],
            "see_also": ["obfuscation.string-encryption-aes"]
        },
        "offender": {
            "summary": "Extract the XOR key from the binary (one immediate value or a small array). Run the XOR over the entire string table. Optionally use re-llm-decompile to feed the deobfuscated function to an LLM for explanation.",
            "tools": ["re-lief.categorize_strings", "re-llm-decompile"],
            "playbook": "playbooks/string-decrypt.md",
            "expected_runtime_minutes": 10,
            "skill_complexity": "trivial",
            "success_probability": 1.0,
            "limitations": ["None significant."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "obfuscation.string-encryption-aes",
        "version": 1,
        "name": "String encryption: AES (or other block cipher)",
        "family": "obfuscation",
        "aliases": ["String AES encryption", "Block cipher string encryption"],
        "severity": "low",
        "defender": {
            "summary": "String literals are AES-encrypted (typically AES-CBC or AES-CTR with a key derived from a constant + the binary's entropy). The decryption function is in the binary; calling it on a single encrypted block returns the plaintext.",
            "detection_signatures": [
                {"type": "structural", "value": "function.body_contains_aes_decrypt_call(min_count=1)",
                    "confidence": 0.7}
            ],
            "false_positive_risks": ["AES is used legitimately in many places. Confirm with the string-table decryption pattern."],
            "see_also": ["obfuscation.string-encryption-xor"]
        },
        "offender": {
            "summary": "Either (a) extract the AES key + IV from the binary, decrypt the string table directly; or (b) call the binary's own decryption function on each encrypted block. The Frida + RE approach: hook the decryption function, decrypt each string at runtime, log to a file.",
            "tools": ["re-frida", "re-llm-decompile"],
            "playbook": "playbooks/string-decrypt.md",
            "expected_runtime_minutes": 30,
            "skill_complexity": "medium",
            "success_probability": 0.9,
            "limitations": ["Some protectors use a per-string key derived from the binary's hash; the key extraction is per-target."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    },
    {
        "id": "obfuscation.import-hashing",
        "version": 1,
        "name": "Import hashing (API resolution by hash)",
        "family": "obfuscation",
        "aliases": ["API hashing", "IAT unhooking", "Manual API resolution"],
        "severity": "low",
        "defender": {
            "summary": "The binary does not import the Win32 APIs directly. Instead, it computes the API name's hash at runtime, walks the kernel32.dll / ntdll.dll export table, and matches the hash. This hides the API names from static analysis tools (the IAT is empty).",
            "detection_signatures": [
                {"type": "structural", "value": "function.body_contains_export_walk_with_hash_compare(min_count=1)",
                    "confidence": 0.8}
            ],
            "false_positive_risks": ["Some legitimate shellcode uses this pattern."],
            "see_also": ["obfuscation.string-encryption-xor"]
        },
        "offender": {
            "summary": "Hook the API-resolution function (the function that walks the export table). Log each resolved API name to a file. The re-frida approach: Interceptor.attach on the resolution function, capture arguments + return value.",
            "tools": ["re-frida", "re-anti-debug-patch"],
            "playbook": "playbooks/import-hashing.md",
            "expected_runtime_minutes": 20,
            "skill_complexity": "easy",
            "success_probability": 0.95,
            "limitations": ["Some protectors use a per-build hash; the resolution function must be identified per binary."]
        },
        "references": [
            {"type": "re_library_entry", "path_or_id": "content/anti-analysis/01-anti-debug.md"}
        ],
        "changelog": [{"version": 1, "date": "2026-06-07", "author": "RE-BREAKER seed", "change": "Initial entry."}]
    }
]


def yara_export(output_path: str = "") -> int:
    """Emit a YARA rules file deterministically rendered from data/catalog.json.

    The output is a 1:1 rendering of every catalog entry that has at least
    one byte_sequence or string_match detection_signature. Entries with
    only structural signatures are rendered as well (the structural
    condition is preserved verbatim), but require the YARA PE module at
    match time. Entries with no detection_signatures are skipped.

    The YARA identifier syntax uses single-`$` (named strings). YARA 3.x's
    anonymous-string `$$` prefix was removed in YARA 4.0; the
    `data/yara/techniques.yar` file should be regenerated with
    `--yara-export` going forward to keep it in sync with the catalog.

    Args:
        output_path: if non-empty, write to this file (relative to repo
            root, or absolute). Empty = write to stdout.

    Returns:
        0 on success, 1 on error.
    """
    if not CATALOG_PATH.exists():
        print(f"error: {CATALOG_PATH} not found", file=sys.stderr)
        return 1
    catalog = json.loads(CATALOG_PATH.read_text())
    entries = catalog.get("entries", [])

    # ---- Header ----
    lines: list[str] = [
        f"// RE-BREAKER YARA export — generated from data/catalog.json",
        f"// {len(entries)} entries across {len({e['family'] for e in entries})} families.",
        "// Auto-generated by: python scripts/build_catalog.py --yara-export > data/yara/techniques.yar",
        "// (the build_catalog.py script is the canonical source; this file is the rendered output).",
        "",
    ]

    n_emitted = 0
    for entry in entries:
        rule_text = _render_yara_rule(entry)
        if rule_text is None:
            continue  # no detection_signatures to render
        lines.append(rule_text)
        lines.append("")
        n_emitted += 1

    output = "\n".join(lines).rstrip() + "\n"
    if output_path:
        out = Path(output_path)
        if not out.is_absolute():
            out = ROOT / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output)
        print(f"wrote {n_emitted} YARA rules to {out}")
    else:
        sys.stdout.write(output)
    return 0


def _render_yara_rule(entry: dict) -> str | None:
    """Render a single catalog entry as a YARA rule.

    Returns None if the entry has no byte_sequence or string_match
    detection_signatures (we only render rules that YARA can match on
    its own; structural-only rules are documented in the catalog but
    are checked via Python at match time using the triage's section
    table).
    """
    eid = entry["id"]
    # Rule name: replace dashes and dots with underscores (e.g.
    # "anti-vm.smbios-dmidecode" -> "anti_vm_smbios_dmidecode"). Matches
    # the existing data/yara/techniques.yar naming convention.
    rule_name = eid.replace("-", "_").replace(".", "_")
    family = entry.get("family", "unknown")
    severity = entry.get("severity", "medium")
    name = entry.get("name", eid)
    catalog_version = entry.get("version", 1)
    catalog_meta = entry.get("defender", {})
    offender = entry.get("offender", {})

    sigs = catalog_meta.get("detection_signatures", [])
    byte_seqs = [s for s in sigs if s.get("type") == "byte_sequence"]
    string_matches = [s for s in sigs if s.get("type") == "string_match"]
    if not byte_seqs and not string_matches:
        # Structural-only rule — no YARA rendering
        return None

    meta_block = [
        f'    meta:',
        f'        id = "{eid}"',
        f'        version = {catalog_version}',
        f'        family = "{family}"',
        f'        severity = "{severity}"',
        f'        name = "{_escape_yara_str(name)}"',
        f'        catalog = "RE-BREAKER v{_CATALOG_VERSION}"',
    ]
    if catalog_meta.get("summary"):
        meta_block.append(f'        offender_summary = "{_escape_yara_str(catalog_meta["summary"])}"')
    if offender.get("tools"):
        meta_block.append(f'        offender_tools = "{_escape_yara_str(", ".join(offender["tools"]))}"')
    if offender.get("playbook"):
        meta_block.append(f'        offender_playbook = "{_escape_yara_str(offender["playbook"])}"')

    strings_block = ['    strings:']
    conditions: list[str] = []
    for i, sig in enumerate(byte_seqs):
        var = f"$bs{i}"
        # value is a hex string with spaces, e.g. "0F 31"
        hex_value = sig.get("value", "").replace(" ", " ")
        strings_block.append(f'        {var} = {{ {hex_value} }}')
        min_count = sig.get("min_count", 1)
        if min_count > 1:
            # YARA 4.x: count operator is `#name` (NOT `#$name` — the $
            # makes it "wrong use of anonymous string").
            bare_var = var.lstrip("$")
            conditions.append(f"#{bare_var} >= {min_count}")
        else:
            conditions.append(var)
    for i, sig in enumerate(string_matches):
        var = f"$sm{i}"
        value = sig.get("value", "")
        # Escape backslashes for YARA string literal; in YARA 4.x \. is
        # not a valid escape in string literals — dots are literal.
        # Same for the /\/ regex issue — the catalog value should not
        # have these by the time it gets here (the catalog migration in
        # v0.5.0 fixed them).
        yara_value = value.replace("\\", "\\\\").replace('"', '\\"')
        strings_block.append(f'        {var} = "{yara_value}" ascii')
        conditions.append(var)

    if conditions:
        condition_clause = "uint16(0) == 0x5A4D and (" + " or ".join(conditions) + ")"
    else:
        condition_clause = "uint16(0) == 0x5A4D"

    # Build the rule text. YARA 4.x requires `rule name {` on the same
    # line; do NOT put a newline between the rule name and the opening
    # brace.
    rule = (
        f"rule {rule_name} {{\n"
        + "\n".join(meta_block) + "\n"
        + "\n".join(strings_block) + "\n"
        + f"\n    condition:\n        {condition_clause}\n"
        + "}"
    )
    return rule


def _escape_yara_str(s: str) -> str:
    """Escape a string for inclusion in a YARA meta value (double-quoted)."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


_CATALALOG_VERSION = "0.5.0"  # updated by build_catalog.py when bumping the catalog


def main() -> int:
    # ---- CLI args ----
    import argparse
    parser = argparse.ArgumentParser(
        description="Build the RE-BREAKER catalog (merge in-source entries into data/catalog.json).",
    )
    parser.add_argument(
        "--yara-export",
        action="store_true",
        help=(
            "Instead of merging entries, emit data/yara/techniques.yar to stdout "
            "(deterministic catalog -> YARA render). Use this to keep "
            "data/yara/techniques.yar in sync with data/catalog.json."
        ),
    )
    parser.add_argument(
        "--yara-output",
        type=str,
        default="",
        help=(
            "If set with --yara-export, write the YARA file to this path "
            "instead of stdout. Path is relative to the repo root or absolute."
        ),
    )
    args = parser.parse_args()

    if args.yara_export:
        return yara_export(args.yara_output)

    # Load the existing catalog (8 encrypted-vm entries)
    if not CATALOG_PATH.exists():
        print(f"error: {CATALOG_PATH} not found", file=sys.stderr)
        return 1
    catalog = json.loads(CATALOG_PATH.read_text())
    existing_ids = {e["id"] for e in catalog["entries"]}
    print(f"existing: {len(existing_ids)} entries")

    # Append the new families
    new_entries = (
        ANTI_DEBUG_ENTRIES
        + ANTI_VM_ENTRIES
        + MBA_ENTRIES
        + ANTI_TAMPER_VENDORS_ENTRIES
        + OBFUSCATION_ENTRIES
    )
    new_ids = {e["id"] for e in new_entries}
    overlap = existing_ids & new_ids
    if overlap:
        print(f"warning: {len(overlap)} duplicate ids, skipping: {overlap}", file=sys.stderr)
        new_entries = [e for e in new_entries if e["id"] not in overlap]

    catalog["entries"].extend(new_entries)
    catalog["totals"] = {
        family: sum(1 for e in catalog["entries"] if e["family"] == family)
        for family in [
            "encrypted-vm-bytecode-interpreter",
            "anti-debug",
            "anti-vm",
            "mba",
            "anti-tamper-vendors",
            "obfuscation",
        ]
    }
    catalog["summary"] = (
        f"{len(catalog['entries'])} entries across 6 families: "
        + ", ".join(
            f"{family} ({count})"
            for family, count in catalog["totals"].items()
        )
        + "."
    )

    CATALOG_PATH.write_text(json.dumps(catalog, indent=2) + "\n")
    print(f"wrote: {len(catalog['entries'])} entries")
    print(f"breakdown: {catalog['totals']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
