// RE-BREAKER YARA export — generated 2026-06-08 from data/catalog.json
// 55 entries across 6 families.
// Re-generate with: python scripts/build_catalog.py --yara-export > data/yara/techniques.yar
// (the build_catalog.py script is the canonical source; this file is the rendered output).
rule encrypted_vm_bytecode_interpreter_pattern_a {
    meta:
        id = "encrypted-vm.bytecode-interpreter.pattern-a"
        version = 1
        family = "encrypted-vm-bytecode-interpreter"
        severity = "critical"
        name = "Pattern A: encrypted-VM bytecode interpreter (Unity IL2CPP target)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook the lazy-decrypt stub; dump each method's plaintext before execution. For IL2CPP targets, the runtime-decrypt typically happens once at boot."
        offender_tools = "re-vm-decrypt, re-frida, re-runtime-dump"
        offender_playbook = "playbooks/encrypted-vm-bytecode-interpreter-pattern-a.md"

    strings:
        $bs1 = {0F 31}

    condition:
        uint16(0) == 0x5A4D and
            (pe.sections[0].name == ".xtls" or pe.sections[1].name == ".xpdata" or pe.sections[2].name == ".xdata" or pe.sections[3].name == ".arch" or pe.sections[4].name == ".link" or pe.sections[5].name == ".sbss" or pe.sections[6].name == ".xcode") and
            #bs1 >= 50
}


rule encrypted_vm_bytecode_interpreter_pattern_a_dw {
    meta:
        id = "encrypted-vm.bytecode-interpreter.pattern-a-dw"
        version = 1
        family = "encrypted-vm-bytecode-interpreter"
        severity = "critical"
        name = "Pattern A-DW: encrypted-VM bytecode interpreter + Denuvo ATD (UE5 variant)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Bypass the POGO entry validation, then run the Pattern A bypass (lazy-decrypt + handler lift). The POGO bypass is the new attack surface introduced by the ATD layer."
        offender_tools = "re-anti-debug-patch, re-vm-decrypt, re-runtime-dump, re-encrypted-vm-bypass"
        offender_playbook = "playbooks/pattern-a-dw-denuvo.md"

    strings:
        $bs2 = {0F 01 C1}

    condition:
        uint16(0) == 0x5A4D and
            (pe.sections[0].name == ".arch" or pe.sections[1].name == ".sbss" or pe.sections[2].name == ".xcode" or pe.sections[3].name == ".xpdata" or pe.sections[4].name == ".xtext" or pe.sections[5].name == ".xtls") and
            #bs2 >= 30
}


rule encrypted_vm_bytecode_interpreter_pattern_a_vmt {
    meta:
        id = "encrypted-vm.bytecode-interpreter.pattern-a-vmt"
        version = 1
        family = "encrypted-vm-bytecode-interpreter"
        severity = "critical"
        name = "Pattern A-VMT: encrypted-VM handler-table dispatch (BlackSpace engine)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Read the .xcode dispatch table (16-byte big-endian entries [u32 id][u32 reserved=0][u64 target]); resolve the handler targets in .link (BSS); lift the handler bodies in .arch. Reconstruct the full han"
        offender_tools = "re-vm-decrypt, re-frida, re-runtime-dump, re-encrypted-vm-bypass"
        offender_playbook = "playbooks/pattern-a-vmt-blackspace.md"

    condition:
        uint16(0) == 0x5A4D and (pe.sections[0].name == ".arch" or pe.sections[1].name == ".link" or pe.sections[2].name == ".xcode" or pe.sections[3].name == ".xtext" or pe.sections[4].name == ".sbss")
}


rule encrypted_vm_bytecode_interpreter_pattern_b {
    meta:
        id = "encrypted-vm.bytecode-interpreter.pattern-b"
        version = 1
        family = "encrypted-vm-bytecode-interpreter"
        severity = "high"
        name = "Pattern B: hardware-fingerprinting + anti-debug in third-party launcher activation library"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Stub-drop: replace the ordinal-imported function body with a return-0 stub. The launcher never knows the difference."
        offender_tools = "re-runtime-dump, re-patch"
        offender_playbook = "playbooks/ea-origin-stub-drop.md"

    strings:
        $sm1 = "RegOpenKeyExW AND GetAdaptersAddresses AND CreateFileW" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm1
}


rule encrypted_vm_bytecode_interpreter_pattern_c {
    meta:
        id = "encrypted-vm.bytecode-interpreter.pattern-c"
        version = 1
        family = "encrypted-vm-bytecode-interpreter"
        severity = "critical"
        name = "Pattern C: encrypted-VM bytecode interpreter (proprietary-engine target)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Per-engine bypass. The runtime-decrypt happens at engine init, not at lazy-decrypt. Hook the engine init function."
        offender_tools = "re-vm-decrypt, re-runtime-dump, re-encrypted-vm-bypass"
        offender_playbook = "playbooks/ca-warscape-eos.md"

    condition:
        uint16(0) == 0x5A4D and (pe.sections[0].name == ".arch" or pe.sections[1].name == ".link" or pe.sections[2].name == ".xcode" or pe.sections[3].name == ".xtext" or pe.sections[4].name == ".sbss")
}


rule encrypted_vm_bytecode_interpreter_pattern_d {
    meta:
        id = "encrypted-vm.bytecode-interpreter.pattern-d"
        version = 1
        family = "encrypted-vm-bytecode-interpreter"
        severity = "medium"
        name = "Pattern D: publisher telemetry pipeline leak (attack surface)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Document the leak. The leak is itself the attack surface — you can use it to find related infrastructure, additional internal docs, or build a targeted social-engineering pretext. The leak is also use"
        offender_tools = "re-catalog-match, re-leak-scan"
        offender_playbook = "None"

    strings:
        $sm0 = "https://[a-z0-9-]+.atlassian.net" ascii
        $rx1 = /https:\/\/[^\/]*sentry[^\/]*\/[0-9]+/ ascii
        $rx2 = /AKIA[0-9A-Z]{16}/ ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $rx1 and
            $rx2
}


rule encrypted_vm_bytecode_interpreter_unity_shielding_pdb_leak {
    meta:
        id = "encrypted-vm.bytecode-interpreter.unity-shielding-pdb-leak"
        version = 1
        family = "encrypted-vm-bytecode-interpreter"
        severity = "high"
        name = "Unity 'shielding' PDB path leak (007FL-specific)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "The PDB path tells you the project name, which tells you where the vendor's internal docs live. From there, you can use the Confluence / SharePoint / etc. leak to find the design docs for the protecti"
        offender_tools = "re-pdb, re-catalog-match, manual search"
        offender_playbook = "playbooks/ioi-glacier-shielding.md"

    strings:
        $rx0 = /[A-Z][a-zA-Z]+_shielding\\.pdb/ ascii
        $rx1 = /[A-Z][a-zA-Z]+_protection\\.pdb/ ascii

    condition:
        uint16(0) == 0x5A4D and
            $rx0 and
            $rx1
}


rule encrypted_vm_bytecode_interpreter_eos_overlay_bypass {
    meta:
        id = "encrypted-vm.bytecode-interpreter.eos-overlay-bypass"
        version = 1
        family = "encrypted-vm-bytecode-interpreter"
        severity = "medium"
        name = "EOS overlay launch entitlement bypass (TWW3-specific)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Drop a .eos side-file in the game directory. The dev-mode escape hatch is documented. No on-disk patch to the EOSSDK or the game binary is required."
        offender_tools = "re-runtime-dump, manual side-file write"
        offender_playbook = "playbooks/ca-warscape-eos.md"

    strings:
        $sm1 = "EOS_Platform_TryInitialize" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm1
}


rule anti_debug_rdtsc_timing_trap {
    meta:
        id = "anti-debug.rdtsc-timing-trap"
        version = 1
        family = "anti-debug"
        severity = "high"
        name = "RDTSC timing-trap (anti-debugger / anti-VM detection)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Two strategies: (a) hook the RDTSC instruction to return a constant value (0x1000 = 'always 4096 cycles, regardless of actual TSC'); (b) at static-patch time, replace each `rdtsc` opcode (`0F 31`) wit"
        offender_tools = "re-anti-debug-patch, re-frida"
        offender_playbook = "playbooks/anti-debug-rdtsc.md"

    strings:
        $bs0 = {0F 31}

    condition:
        uint16(0) == 0x5A4D and
            #bs0 >= 5
}


rule anti_debug_int2d {
    meta:
        id = "anti-debug.int2d"
        version = 1
        family = "anti-debug"
        severity = "medium"
        name = "INT 0x2d (anti-debugger trap)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "NOP-out the INT 0x2d (replace 2 bytes `CD 2D` with `90 90` = two NOPs). Or hook the exception handler to ignore EXCEPTION_BREAKPOINT."
        offender_tools = "re-anti-debug-patch, re-patch"
        offender_playbook = "playbooks/anti-debug-int2d.md"

    strings:
        $bs0 = {CD 2D}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule anti_debug_int3 {
    meta:
        id = "anti-debug.int3"
        version = 1
        family = "anti-debug"
        severity = "low"
        name = "INT 3 (anti-debugger trap or padding)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "If a function entry-point or specific control-flow path has 0xCC, the function is a trap. Replace the 0xCC with 0x90 (NOP) and the function continues normally. If 0xCC is in a tail-padding region (pos"
        offender_tools = "re-anti-debug-patch, re-rizin"
        offender_playbook = "playbooks/anti-debug-int3.md"

    strings:
        $bs0 = {CC}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule anti_debug_cpuid_hypervisor_leaf_1_ecx_bit_31 {
    meta:
        id = "anti-debug.cpuid-hypervisor-leaf-1-ecx-bit-31"
        version = 1
        family = "anti-debug"
        severity = "high"
        name = "CPUID leaf 1 ECX bit 31 (hypervisor present)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook CPUID to return 0 for bit 31 of ECX when EAX=1. The 'bare-metal' CPUID snapshot is the source of the spoofed value."
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-cpuid.md"

    strings:
        $bs0 = {0F A2}

    condition:
        uint16(0) == 0x5A4D and
            #bs0 >= 5
}


rule anti_debug_cpuid_hypervisor_leaf_0x40000000_vendor {
    meta:
        id = "anti-debug.cpuid-hypervisor-leaf-0x40000000-vendor"
        version = 1
        family = "anti-debug"
        severity = "high"
        name = "CPUID leaf 0x40000000 (hypervisor vendor string)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook CPUID to return the bare-metal vendor string for EAX=0x40000000 (typically 12 zero bytes for no hypervisor). Some sophisticated protectors also test that the spoofed vendor string doesn't match t"
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-cpuid.md"

    strings:
        $bs0 = {0F A2 81}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule anti_debug_vmxon_vmcs {
    meta:
        id = "anti-debug.vmxon-vmcs"
        version = 1
        family = "anti-debug"
        severity = "high"
        name = "VMXON / VMCS (Intel VT-x detection)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook the VMXON instruction to return #UD (undefined opcode). The binary's VMXON probe then sees 'VT-x not available' and treats the environment as bare-metal."
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-vmx.md"

    strings:
        $bs0 = {0F C7}

    condition:
        uint16(0) == 0x5A4D and
            #bs0 >= 5
}


rule anti_debug_vmcall {
    meta:
        id = "anti-debug.vmcall"
        version = 1
        family = "anti-debug"
        severity = "high"
        name = "VMCALL (hypervisor call)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook VMCALL to return without trapping. Or use CPUID feature-bit masking to disable VMX (less common; most CPUs have VMX forced-on)."
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-vmx.md"

    strings:
        $bs0 = {0F 01 C1}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule anti_debug_invd {
    meta:
        id = "anti-debug.invd"
        version = 1
        family = "anti-debug"
        severity = "medium"
        name = "INVD (anti-emulator detection)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook INVD to be a NOP (or a benign no-op). For emulators: enable TCG acceleration or handle the INVD instruction in the emulator. For Frida: replace `INVD` with `NOP; NOP` (2 bytes)."
        offender_tools = "re-anti-vm-spoof, re-frida, re-runtime-dump --mode=emulator"
        offender_playbook = "playbooks/anti-debug-invd.md"

    strings:
        $bs0 = {0F 08}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule anti_debug_peb_beingdebugged {
    meta:
        id = "anti-debug.peb-beingdebugged"
        version = 1
        family = "anti-debug"
        severity = "low"
        name = "PEB.BeingDebugged (Windows Process Environment Block)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Patch the PEB.BeingDebugged byte to 0. Or hook the IsDebuggerPresent function. Or use a tool like ScyllaHide (x64dbg plugin) to hide from PEB.BeingDebugged at debug-time."
        offender_tools = "re-anti-debug-patch, re-patch, x64dbg ScyllaHide (external)"
        offender_playbook = "playbooks/anti-debug-peb.md"

    strings:
        $sm0 = "IsDebuggerPresent" ascii
        $bs1 = {65 48 8B 04 25 60 00 00 00}

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $bs1
}


rule anti_debug_ntqueryinformationprocess_debugport {
    meta:
        id = "anti-debug.ntqueryinformationprocess-debugport"
        version = 1
        family = "anti-debug"
        severity = "medium"
        name = "NtQueryInformationProcess(ProcessDebugPort) (Windows kernel debug detection)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook NtQueryInformationProcess to return 0 for ProcessDebugPort. ScyllaHide and TitanHide do this automatically. Some protectors also check ProcessDebugObjectHandle, ProcessDebugFlags — combine with t"
        offender_tools = "re-anti-debug-patch, x64dbg ScyllaHide (external)"
        offender_playbook = "playbooks/anti-debug-peb.md"

    strings:
        $sm0 = "NtQueryInformationProcess" ascii
        $bs1 = {B8 07 00 00 00}

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $bs1
}


rule anti_debug_checkremotedebuggerpresent {
    meta:
        id = "anti-debug.checkremotedebuggerpresent"
        version = 1
        family = "anti-debug"
        severity = "low"
        name = "CheckRemoteDebuggerPresent (cross-process debugger detection)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook CheckRemoteDebuggerPresent to return FALSE. ScyllaHide handles this."
        offender_tools = "re-anti-debug-patch, x64dbg ScyllaHide (external)"
        offender_playbook = "playbooks/anti-debug-peb.md"

    strings:
        $sm0 = "CheckRemoteDebuggerPresent" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0
}


rule anti_vm_smbios_dmidecode {
    meta:
        id = "anti-vm.smbios-dmidecode"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "SMBIOS / DMI table read (VM detection)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook GetSystemFirmwareTable('RSMB', ...) to return a forged SMBIOS table with bare-metal manufacturer (e.g. 'American Megatrends Inc.' or 'Dell Inc.' or 'HP' instead of 'VMware, Inc.')."
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-smbios.md"

    strings:
        $sm0 = "GetSystemFirmwareTable" ascii
        $sm1 = "\\\\\\\\.\\\\\\\\SMBios" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule anti_vm_acpi_facp {
    meta:
        id = "anti-vm.acpi-facp"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "ACPI FACP table (VM detection via hypervisor vendor)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook the ACPI table read to return a forged FADT with a bare-metal OEMID."
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-smbios.md"

    strings:
        $sm0 = "ACPI" ascii
        $bs1 = {46 41 43 50 01}

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $bs1
}


rule anti_vm_registry_key_entropy {
    meta:
        id = "anti-vm.registry-key-entropy"
        version = 1
        family = "anti-vm"
        severity = "medium"
        name = "Registry-key entropy probe (HWID via registry)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook the registry read functions to return a 'bare-metal' snapshot of the registry values. Alternatively, set the registry to the right values at the host level (persistent)."
        offender_tools = "re-anti-vm-spoof, re-frida, host-level registry prep"
        offender_playbook = "playbooks/anti-vm-registry.md"

    strings:
        $sm0 = "RegOpenKeyExW" ascii
        $sm1 = "RegQueryValueExW" ascii
        $sm2 = "HKLM" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1 and
            $sm2
}


rule anti_vm_network_adapter_mac_prefix {
    meta:
        id = "anti-vm.network-adapter-mac-prefix"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "Network adapter MAC prefix (VM detection via MAC OUI)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "At the host level, set the network adapter's MAC to a bare-metal OUI (e.g. an Intel OUI like 00:1B:21, 00:1D:E0, 00:23:6C, 00:24:D6, 00:26:5A, 00:26:C6, 00:26:F0, etc.). Alternatively, hook GetAdapter"
        offender_tools = "re-anti-vm-spoof, host-level MAC set"
        offender_playbook = "playbooks/anti-vm-mac.md"

    strings:
        $sm0 = "GetAdaptersAddresses" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0
}


rule anti_vm_vmware_io_backdoor {
    meta:
        id = "anti-vm.vmware-io-backdoor"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "VMware I/O backdoor (port 0x5658 'VX')"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook the I/O port reads. Speakeasy and QEMU can intercept IN instructions; for native execution, use a hypervisor (HyperHide) or a custom kernel driver. Easiest: at the host level, change the VMware b"
        offender_tools = "re-anti-vm-spoof, HyperHide (external)"
        offender_playbook = "playbooks/anti-vm-vmware.md"

    strings:
        $bs0 = {66 B8 58 56}
        $bs1 = {ED}

    condition:
        uint16(0) == 0x5A4D and
            $bs0 and
            $bs1
}


rule anti_vm_vbox_io_backdoor {
    meta:
        id = "anti-vm.vbox-io-backdoor"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "VirtualBox I/O backdoor (port 0x5658 / VBoxGuest)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Uninstall VirtualBox guest additions. Or use HyperHide to hide VBoxGuest device."
        offender_tools = "HyperHide (external)"
        offender_playbook = "playbooks/anti-vm-vbox.md"

    strings:
        $sm0 = "VBoxGuest" ascii
        $sm1 = "VBoxService" ascii
        $bs2 = {66 B8 58 56}

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1 and
            $bs2
}


rule anti_vm_hyper_v_tlfs {
    meta:
        id = "anti-vm.hyper-v-tlfs"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "Hyper-V Top-Level Functional Specification (TLFS) probes"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook RDMSR to return zero for the Hyper-V MSRs. Or use HyperHide to mask the Hyper-V interface."
        offender_tools = "re-anti-vm-spoof, HyperHide (external)"
        offender_playbook = "playbooks/anti-vm-hyper-v.md"

    strings:
        $bs0 = {0F 32}
        $sm1 = "Microsoft Hv" ascii

    condition:
        uint16(0) == 0x5A4D and
            $bs0 and
            $sm1
}


rule mba_x_plus_y_equals_xor_xor_y_carry {
    meta:
        id = "mba.x_plus_y_equals_xor_xor_y_carry"
        version = 1
        family = "mba"
        severity = "low"
        name = "MBA identity: x + y = (x XOR y) + 2*(x AND y)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Use re-mba-deobfuscate skill or re-triton to symbolically simplify the expression. The pattern collapses back to `x + y` after simplification."
        offender_tools = "re-mba-deobfuscate, re-triton"
        offender_playbook = "playbooks/mba-simplify.md"

    strings:
        $bs0 = {31 C0 23 C1}
        $bs1 = {31 C8 D1 E0}

    condition:
        uint16(0) == 0x5A4D and
            $bs0 and
            $bs1
}


rule mba_x_plus_y_equals_x_and_y_plus_x_or_y {
    meta:
        id = "mba.x_plus_y_equals_x_and_y_plus_x_or_y"
        version = 1
        family = "mba"
        severity = "low"
        name = "MBA identity: x + y = (x AND y) + (x OR y)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Same as mba.x_plus_y_equals_xor_xor_y_carry — simplify with re-mba-deobfuscate."
        offender_tools = "re-mba-deobfuscate"
        offender_playbook = "playbooks/mba-simplify.md"

    strings:
        $bs0 = {21 C1 09 C8}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule mba_xor_substitution {
    meta:
        id = "mba.xor-substitution"
        version = 1
        family = "mba"
        severity = "low"
        name = "MBA identity: XOR via (a|b) - (a&b)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Simplify with re-mba-deobfuscate."
        offender_tools = "re-mba-deobfuscate"
        offender_playbook = "playbooks/mba-simplify.md"

    strings:
        $bs0 = {09 C1 21 C8 29 C8}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule mba_opaque_predicate_xor {
    meta:
        id = "mba.opaque-predicate-xor"
        version = 1
        family = "mba"
        severity = "low"
        name = "Opaque predicate: (x XOR x) is always 0"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Use re-triton or re-angr with symbolic execution to evaluate the predicate symbolically. If it always evaluates to 0 (or always to 1), the predicate is opaque and the conditional branch can be removed"
        offender_tools = "re-triton, re-angr, re-mba-deobfuscate"
        offender_playbook = "playbooks/opaque-predicate.md"

    strings:
        $bs0 = {33 C0}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule mba_opaque_predicate_and {
    meta:
        id = "mba.opaque-predicate-and"
        version = 1
        family = "mba"
        severity = "low"
        name = "Opaque predicate: (x AND 0) is always 0"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Same approach — symbolic evaluation with re-triton / re-angr."
        offender_tools = "re-triton, re-angr"
        offender_playbook = "playbooks/opaque-predicate.md"

    strings:
        $bs0 = {83 E0 00}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule mba_ffmpeg_emu_cf {
    meta:
        id = "mba.ffmpeg-emu-cf"
        version = 1
        family = "mba"
        severity = "high"
        name = "FFmpeg emulator control-flow MBA (inspiration: OLLVM)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Use re-vtil's control-flow-unflatten pass (with the OLLVM catalog pass set) or re-angr's CFG recovery. The switch + state variable can be unflattened back to structured if/else/while."
        offender_tools = "re-vtil, re-angr, re-mba-deobfuscate"
        offender_playbook = "playbooks/ollvm-cf-unflatten.md"

    condition:
        uint16(0) == 0x5A4D
}


rule anti_tamper_vendors_denuvo {
    meta:
        id = "anti-tamper-vendors.denuvo"
        version = 1
        family = "anti-tamper-vendors"
        severity = "critical"
        name = "Denuvo Anti-Tamper (Denuvo Anti-Cheat is a separate product)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Months of per-title work. Denuvo is the hardest commercial ATD; there is no public bypass. The realistic approaches are: (a) dump decrypted regions + bypass the online license check (still requires th"
        offender_tools = "re-vm-decrypt, re-runtime-dump, re-encrypted-vm-bypass, re-anti-debug-patch, re-anti-vm-spoof"
        offender_playbook = "playbooks/denuvo-bypass.md"

    strings:
        $sm0 = "denuvo" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            (pe.sections[0].name == ".arch" or pe.sections[1].name == ".sbss" or pe.sections[2].name == ".xcode" or pe.sections[3].name == ".xpdata" or pe.sections[4].name == ".xtext" or pe.sections[5].name == ".xtls")
}


rule anti_tamper_vendors_vmprotect {
    meta:
        id = "anti-tamper-vendors.vmprotect"
        version = 1
        family = "anti-tamper-vendors"
        severity = "critical"
        name = "VMProtect (encrypted-VM bytecode interpreter)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "The VMP open-source community has produced several tools: `void-stack/VMUnprotect`, `can1357/NoVmp`, `wallds/NoVmpy`, `fjqisba/VmpHelper`, `CabboShiba/VMPBypass`, `chramiq/de4vmp`, `Shhoya/MutantKille"
        offender_tools = "re-vm-decrypt, re-runtime-dump"
        offender_playbook = "playbooks/vmprotect-bypass.md"

    strings:
        $sm0 = ".vmp0" ascii
        $sm1 = "VMProtect" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule anti_tamper_vendors_themida {
    meta:
        id = "anti-tamper-vendors.themida"
        version = 1
        family = "anti-tamper-vendors"
        severity = "critical"
        name = "Themida / WinLicense (encrypted-VM bytecode interpreter)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Similar to VMP — hook the dispatcher, dump each handler. Themida's open-source bypasses are less mature than VMP's. The `Keowu/birosca` project and a few others have partial success."
        offender_tools = "re-vm-decrypt, re-runtime-dump"
        offender_playbook = "playbooks/themida-bypass.md"

    strings:
        $sm0 = ".themida" ascii
        $sm1 = ".winlice" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule anti_tamper_vendors_starforce {
    meta:
        id = "anti-tamper-vendors.starforce"
        version = 1
        family = "anti-tamper-vendors"
        severity = "high"
        name = "StarForce (legacy disc-based + driver-based protection)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "For legacy disc-based StarForce: emulate the disc-check via daemon tools + scsi emulation. For modern StarForce (rare): hook the driver at the kernel-mode level."
        offender_tools = "re-anti-vm-spoof, daemon-tools"
        offender_playbook = "playbooks/starforce-bypass.md"

    strings:
        $sm0 = "StarForce" ascii
        $sm1 = "protect\\.sys" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule anti_tamper_vendors_arxan {
    meta:
        id = "anti-tamper-vendors.arxan"
        version = 1
        family = "anti-tamper-vendors"
        severity = "high"
        name = "Arxan / Digital.ai (code-protection + app-shielding)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Arxan's open-source bypasses are less mature than VMP/Themida. The approach: hook Arxan's integrity-check calls, dump decrypted regions. Some protectors use a JIT compiler that is harder to hook."
        offender_tools = "re-vm-decrypt, re-runtime-dump"
        offender_playbook = "playbooks/arxan-bypass.md"

    strings:
        $sm0 = "Arxan" ascii
        $sm1 = ".arxan" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule anti_tamper_vendors_ezfuscator {
    meta:
        id = "anti-tamper-vendors.ezfuscator"
        version = 1
        family = "anti-tamper-vendors"
        severity = "medium"
        name = "Eazfuscator.NET (.NET obfuscator)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "For Eazfuscator.NET, use the open-source deobfuscators: `NotPrab/.NET-Deobfuscator`, `holly-hacker/EazFixer`, `Washi1337/AsmResolver`, `Col-E/Recaf`. The approach: deobfuscate the IL with the deobfusc"
        offender_tools = "re-dotnet, re-dotnet-patch, EazFixer (external)"
        offender_playbook = "playbooks/eazfuscator-bypass.md"

    strings:
        $sm0 = "Eazfuscator" ascii
        $sm1 = "{Eazfuscator}" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule anti_tamper_vendors_code_virtualizer {
    meta:
        id = "anti-tamper-vendors.code-virtualizer"
        version = 1
        family = "anti-tamper-vendors"
        severity = "high"
        name = "Code Virtualizer / VMProtect (overlap)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Same as VMProtect. The VMP open-source tools (`VMUnprotect`, `NoVmp`) are effective."
        offender_tools = "re-vm-decrypt, re-runtime-dump"
        offender_playbook = "playbooks/vmprotect-bypass.md"

    strings:
        $sm0 = "Code Virtualizer" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0
}


rule anti_tamper_vendors_executioner_cpp_obfuscator {
    meta:
        id = "anti-tamper-vendors.executioner-cpp-obfuscator"
        version = 1
        family = "anti-tamper-vendors"
        severity = "medium"
        name = "Executioner C++ Obfuscator (open-source C++ obfuscator)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "For Executioner, use re-vtil's control-flow-unflatten pass + re-mba-deobfuscate for the MBA simplification. The string encryption uses XOR with a constant key (per-build); extract the key from the .rd"
        offender_tools = "re-vtil, re-mba-deobfuscate"
        offender_playbook = "playbooks/executioner-bypass.md"

    strings:
        $sm0 = "Executioner" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0
}


rule anti_tamper_vendors_intel_sgx_enclave {
    meta:
        id = "anti-tamper-vendors.intel-sgx-enclave"
        version = 1
        family = "anti-tamper-vendors"
        severity = "high"
        name = "Intel SGX enclave (TEE-based protection)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "SGX enclaves are designed to be unbreakable from outside. The realistic approaches: (a) side-channel attacks (e.g. Spectre, Foreshadow); (b) fault injection (e.g. voltage glitching); (c) extract the e"
        offender_tools = "external side-channel tools, external fault-injection tools"
        offender_playbook = "playbooks/sgx-bypass.md"

    strings:
        $sm0 = "sgx_" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0
}


rule anti_tamper_vendors_apple_fairplay {
    meta:
        id = "anti-tamper-vendors.apple-fairplay"
        version = 1
        family = "anti-tamper-vendors"
        severity = "high"
        name = "Apple FairPlay (DRM-adjacent, not in 'drm/' category)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "FairPlay is a DRM system. Bypassing it is not within RE-BREAKER's scope (DRM-bypass is a different threat model). The catalog entry is here for completeness."
        offender_tools = ""
        offender_playbook = "None"

    strings:
        $sm0 = "FairPlay" ascii
        $sm1 = ".fps" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule obfuscation_control_flow_flattening {
    meta:
        id = "obfuscation.control-flow-flattening"
        version = 1
        family = "obfuscation"
        severity = "medium"
        name = "Control-flow flattening (OLLVM-style)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Use re-vtil's control-flow-unflatten pass (with the OLLVM catalog pass set) or re-angr's CFG recovery. The switch + state variable can be unflattened back to structured if/else/while."
        offender_tools = "re-vtil, re-angr"
        offender_playbook = "playbooks/cf-flattening.md"

    condition:
        uint16(0) == 0x5A4D
}


rule obfuscation_opaque_predicate {
    meta:
        id = "obfuscation.opaque-predicate"
        version = 1
        family = "obfuscation"
        severity = "low"
        name = "Opaque predicate (general)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Use re-triton or re-angr with symbolic execution. The opaque predicate evaluates to 0 or 1; the conditional branch can then be removed."
        offender_tools = "re-triton, re-angr"
        offender_playbook = "playbooks/opaque-predicate.md"

    condition:
        uint16(0) == 0x5A4D
}


rule obfuscation_virtualization_obfuscator {
    meta:
        id = "obfuscation.virtualization-obfuscator"
        version = 1
        family = "obfuscation"
        severity = "high"
        name = "Virtualization obfuscator (general)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Same as for any encrypted-VM bytecode interpreter: hook the dispatcher, dump each VM handler as it executes, lift to readable IL."
        offender_tools = "re-vm-decrypt, re-runtime-dump, re-vtil"
        offender_playbook = "playbooks/encrypted-vm-bytecode-interpreter-pattern-a.md"

    condition:
        uint16(0) == 0x5A4D
}


rule obfuscation_string_encryption_xor {
    meta:
        id = "obfuscation.string-encryption-xor"
        version = 1
        family = "obfuscation"
        severity = "low"
        name = "String encryption: XOR with constant key"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Extract the XOR key from the binary (one immediate value or a small array). Run the XOR over the entire string table. Optionally use re-llm-decompile to feed the deobfuscated function to an LLM for ex"
        offender_tools = "re-lief.categorize_strings, re-llm-decompile"
        offender_playbook = "playbooks/string-decrypt.md"

    condition:
        uint16(0) == 0x5A4D
}


rule obfuscation_string_encryption_aes {
    meta:
        id = "obfuscation.string-encryption-aes"
        version = 1
        family = "obfuscation"
        severity = "low"
        name = "String encryption: AES (or other block cipher)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Either (a) extract the AES key + IV from the binary, decrypt the string table directly; or (b) call the binary's own decryption function on each encrypted block. The Frida + RE approach: hook the decr"
        offender_tools = "re-frida, re-llm-decompile"
        offender_playbook = "playbooks/string-decrypt.md"

    condition:
        uint16(0) == 0x5A4D
}


rule obfuscation_import_hashing {
    meta:
        id = "obfuscation.import-hashing"
        version = 1
        family = "obfuscation"
        severity = "low"
        name = "Import hashing (API resolution by hash)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook the API-resolution function (the function that walks the export table). Log each resolved API name to a file. The re-frida approach: Interceptor.attach on the resolution function, capture argumen"
        offender_tools = "re-frida, re-anti-debug-patch"
        offender_playbook = "playbooks/import-hashing.md"

    condition:
        uint16(0) == 0x5A4D
}


rule anti_tamper_vendors_eac {
    meta:
        id = "anti-tamper-vendors.eac"
        version = 1
        family = "anti-tamper-vendors"
        severity = "high"
        name = "Easy Anti-Cheat (Epic / Kamu)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Per MRTEA SOW-F, NO PoC Exploit that demonstrates a Bypass of EAC against a specific game or specific player. The primary deliverable for AC Findings is a defensive recommendation, not a PoC Exploit."
        offender_tools = "re-vendor-anti-tamper (eac), re-catalog-match"
        offender_playbook = "playbooks/pattern-d.md"

    strings:
        $sm0 = "EasyAntiCheat" ascii
        $sm1 = "EasyAntiCheat_x64.dll" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule anti_tamper_vendors_battleye {
    meta:
        id = "anti-tamper-vendors.battleye"
        version = 1
        family = "anti-tamper-vendors"
        severity = "high"
        name = "BattlEye Anti-Cheat (BattlEye Innovations)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Per MRTEA SOW-G, NO cheat, hack, or similar tool against any game using BattlEye. Defensive-utility guidance only."
        offender_tools = "re-vendor-anti-tamper (be), re-catalog-match"
        offender_playbook = "playbooks/pattern-d.md"

    strings:
        $sm0 = "BattlEye" ascii
        $sm1 = "BEClient" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0 and
            $sm1
}


rule anti_debug_isdebuggerpresent {
    meta:
        id = "anti-debug.isdebuggerpresent"
        version = 1
        family = "anti-debug"
        severity = "low"
        name = "IsDebuggerPresent Win32 API"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Hook IsDebuggerPresent to return FALSE. The hook can be at the IAT level (Windows) or GOT/PLT level (Linux via Wine)."
        offender_tools = "re-anti-debug-patch, re-frida-runtime"
        offender_playbook = "playbooks/encrypted-vm-bytecode-interpreter-pattern-a.md"

    strings:
        $sm0 = "IsDebuggerPresent" ascii

    condition:
        uint16(0) == 0x5A4D and
            $sm0
}


rule obfuscation_control_flow_flattening_pattern_c {
    meta:
        id = "obfuscation.control-flow-flattening-pattern-c"
        version = 1
        family = "obfuscation"
        severity = "high"
        name = "Control-flow flattening (Pattern C proprietary-engine variant)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Use RE-AI's re-vtil to lift the dispatcher + each basic block. Reconstruct the original control flow by inverting the CFF: collapse the dispatcher + the state-variable update into a direct basic-block"
        offender_tools = "re-vm-decrypt, re-vtil, re-runtime-dump"
        offender_playbook = "playbooks/ioi-glacier-shielding.md"

    strings:
        $bs0 = {FF 24 85}
        $bs1 = {FF 24 C5}

    condition:
        uint16(0) == 0x5A4D and
            $bs0 and
            $bs1
}


rule obfuscation_import_hashing_pattern_c {
    meta:
        id = "obfuscation.import-hashing-pattern-c"
        version = 1
        family = "obfuscation"
        severity = "medium"
        name = "Import hashing (Pattern C proprietary-engine variant)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Build a hash-to-API map for the target by computing the same hash function over each Win32 API name. Replace the custom resolver with a direct IAT lookup. Use RE-AI's re-lief to extract the import nam"
        offender_tools = "re-il2cpp-triage, re-triage, re-vm-decrypt"
        offender_playbook = "playbooks/ioi-glacier-shielding.md"

    strings:
        $bs0 = {C1 E0 02}
        $sm1 = "PEB_LDR_DATA" ascii

    condition:
        uint16(0) == 0x5A4D and
            #bs0 >= 5 and
            $sm1
}


rule obfuscation_string_encryption_pattern_c {
    meta:
        id = "obfuscation.string-encryption-pattern-c"
        version = 1
        family = "obfuscation"
        severity = "medium"
        name = "String encryption (Pattern C proprietary-engine variant)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Identify the decryption stub (a small function called at first reference of every string). Hook it to capture the decrypted strings as they pass through. Use RE-AI's re-frida + a Frida script that int"
        offender_tools = "re-frida-runtime, re-vm-decrypt"
        offender_playbook = "playbooks/ioi-glacier-shielding.md"

    strings:
        $bs0 = {30 04 30 4C 30 04}

    condition:
        uint16(0) == 0x5A4D and
            $bs0
}


rule anti_vm_timing_trap_pattern_a_dw {
    meta:
        id = "anti-vm.timing-trap-pattern-a-dw"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "Timing-trap detection (Pattern A-DW Denuvo ATD variant)"
        catalog = "RE-BREAKER v0.2.0"
        offender_summary = "Cap the RDTSC delta to a configurable threshold (default 1000 cycles). Any delta > cap returns the cap value, defeating the bimodal distribution. Use RE-AI's re-frida + a CPUID/RDTSC hook with delta c"
        offender_tools = "re-anti-vm-spoof, re-frida-runtime"
        offender_playbook = "playbooks/pattern-a-dw-denuvo.md"

    strings:
        $bs0 = {0F 31}

    condition:
        uint16(0) == 0x5A4D and
            #bs0 >= 200
}

rule anti_vm_driver_file_handle_probe {
    meta:
        id = "anti-vm.driver-file-handle-probe"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "VM-driver file/handle probe (vboxguest/vmci/vmhgfs + device paths)"
        catalog = "RE-BREAKER v0.5.0"
        offender_summary = "Strip the driver-name table from the binary. For runtime probes (CreateFileW on \\\\VBoxGuest), use re-anti-vm-spoof's frida hook to redirect the open to a fake device that returns ERROR_FILE_NOT_FOUND."
        offender_tools = "re-anti-vm-spoof, re-frida, re-anti-debug-patch"
        offender_playbook = "playbooks/anti-vm-driver-handle.md"

    strings:
        $sm0 = "vboxguest" ascii
        $sm1 = "vmci" ascii
        $sm2 = "vmhgfs" ascii
        $sm3 = "vboxmouse" ascii
        $sm4 = "vboxsf" ascii
        $sm5 = "vmusbmouse" ascii
        $sm6 = "VBoxHook.dll" ascii
        $sm7 = "vmtools.dll" ascii
        $sm8 = "\\\\.\\VBoxGuest" ascii
        $sm9 = "\\\\.\\VMCI" ascii
        $sm10 = "\\\\.\\VMware" ascii

    condition:
        uint16(0) == 0x5A4D and
            ($sm0 or $sm1 or $sm2 or $sm3 or $sm4 or $sm5 or $sm6 or $sm7 or $sm8 or $sm9 or $sm10)
}


rule anti_vm_process_module_name_enumeration {
    meta:
        id = "anti-vm.process-module-name-enumeration"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "VM-related process/module enumeration (vmtoolsd/vboxservice/prl_cc/xenservice)"
        catalog = "RE-BREAKER v0.5.0"
        offender_summary = "Strip the process-name table, or use re-anti-vm-spoof's frida hook to make Process32FirstW skip any process whose name matches the VM list."
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-process-module.md"

    strings:
        $sm0 = "vmtoolsd.exe" ascii
        $sm1 = "vboxservice.exe" ascii
        $sm2 = "vboxtray.exe" ascii
        $sm3 = "vmusrvc.exe" ascii
        $sm4 = "prl_tools.exe" ascii
        $sm5 = "prl_cc.exe" ascii
        $sm6 = "xenservice.exe" ascii

    condition:
        uint16(0) == 0x5A4D and
            ($sm0 or $sm1 or $sm2 or $sm3 or $sm4 or $sm5 or $sm6)
}


rule anti_vm_window_class_title_probe {
    meta:
        id = "anti-vm.window-class-title-probe"
        version = 1
        family = "anti-vm"
        severity = "medium"
        name = "VM window class/title probe (VBoxTrayToolWndClass, VmwareUserWnd)"
        catalog = "RE-BREAKER v0.5.0"
        offender_summary = "Strip the class-name string. If the probe is via FindWindowW, use re-anti-vm-spoof's frida hook to return NULL for the matching class."
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-window.md"

    strings:
        $sm0 = "VBoxTrayToolWndClass" ascii
        $sm1 = "VmwareUserWnd" ascii
        $sm2 = "VMwareWindow" ascii
        $sm3 = "ProxSpace" ascii

    condition:
        uint16(0) == 0x5A4D and
            ($sm0 or $sm1 or $sm2 or $sm3)
}


rule anti_vm_descriptor_table_redpill {
    meta:
        id = "anti-vm.descriptor-table-redpill"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "Descriptor-table side-channel detection (SIDT/SGDT/SLDT/STR red-pill)"
        catalog = "RE-BREAKER v0.5.0"
        offender_summary = "Virtualize the IDT base in the VMM (Hyper-V, KVM) so the user-mode SIDT returns 0x80xxxx. For VBox/VMware/VirtualBox, the IDT base is set on VMX-VMCS-write and must be intercepted on the host side. Use re-anti-vm-spoof's frida hook to overwrite the SIDT return value at the call site."
        offender_tools = "re-anti-vm-spoof, re-frida, re-qemu-antidetect"
        offender_playbook = "playbooks/anti-vm-redpill.md"

    strings:
        $bs0 = { 0F 01 0D }
        $bs1 = { 0F 01 1D }
        $bs2 = { 0F 00 0D }
        $bs3 = { 0F 00 1D }

    condition:
        uint16(0) == 0x5A4D and
            (#bs0 >= 1 or #bs1 >= 1 or #bs2 >= 1 or #bs3 >= 1)
}


rule anti_vm_wine_get_version_probe {
    meta:
        id = "anti-vm.wine-get-version-probe"
        version = 1
        family = "anti-vm"
        severity = "high"
        name = "Wine detection via wine_get_version/wine_get_build_id import"
        catalog = "RE-BREAKER v0.5.0"
        offender_summary = "Use re-anti-vm-spoof's frida hook to return NULL from GetProcAddress(ntdll, 'wine_get_version') and the binary will believe it's on Windows. Note: the probe may be runtime GetProcAddress, not a static import -- the frida hook must intercept GetProcAddress."
        offender_tools = "re-anti-vm-spoof, re-frida"
        offender_playbook = "playbooks/anti-vm-wine.md"

    strings:
        $sm0 = "wine_get_version" ascii
        $sm1 = "wine_get_build_id" ascii

    condition:
        uint16(0) == 0x5A4D and
            ($sm0 or $sm1)
}


rule anti_tamper_vendors_ea_spear_anticheat {
    meta:
        id = "anti-tamper-vendors.ea-spear-anticheat"
        version = 1
        family = "anti-tamper-vendors"
        severity = "critical"
        name = "EA SPEAR AntiCheat (EAAntiCheat.GameServiceLauncher + EAAntiCheat.Installer + antitamperdiagnosis endpoint)"
        catalog = "RE-BREAKER v0.5.0"
        offender_summary = "Spoof wine_get_version -> NULL. The AC will refuse to escalate to kernel-mode without a Wine positive. EA AC also calls the Denuvo ATD's heartbeat -- must spoof both."
        offender_tools = "re-anti-vm-spoof, re-frida, re-traffic-capture"
        offender_playbook = "playbooks/ea-spear-anticheat.md"

    strings:
        $sm0 = "EAAntiCheat" ascii
        $sm1 = "EA SPEAR" ascii
        $sm2 = "EAAntiCheat.GameServiceLauncher" ascii
        $sm3 = "EAAntiCheat.Installer" ascii
        $sm4 = "antitamperdiagnosis" ascii
        $sm5 = "AntiCheatServiceOperation" ascii

    condition:
        uint16(0) == 0x5A4D and
            ($sm0 or $sm1 or $sm2 or $sm3 or $sm4 or $sm5)
}


rule anti_tamper_vendors_ea_anticheat_preloader_l_injector {
    meta:
        id = "anti-tamper-vendors.ea-anticheat-preloader-l-injector"
        version = 1
        family = "anti-tamper-vendors"
        severity = "critical"
        name = "InsaneRamZes crack-time preloader (preloader_l.dll, /work/preloader.pdb, full process-injection surface)"
        catalog = "RE-BREAKER v0.5.0"
        offender_summary = "Hash-list the preloader. Add the SHA-256 of preloader_l.dll (and any rebuild) to the AC's blocked-modules list. Alternatively, the AppInit_DLLs registry key can be set to load an anti-preloader DLL that blocks the preloader from running. The defender has the advantage: the preloader is a per-build static binary, while the protected game changes with every patch."
        offender_tools = "re-traffic-capture, re-vendor-anti-tamper"
        offender_playbook = "playbooks/insaneramzes-preloader.md"

    strings:
        $sm0 = "/work/preloader.pdb" ascii
        $sm1 = "preloader.unsigned.dll" ascii
        $sm2 = "preloader_link_func" ascii

    condition:
        uint16(0) == 0x5A4D and
            ($sm0 or $sm1 or $sm2)
}


rule anti_tamper_vendors_denuvo_eac_joint {
    meta:
        id = "anti-tamper-vendors.denuvo-eac-joint"
        version = 1
        family = "anti-tamper-vendors"
        severity = "critical"
        name = "Denuvo ATD + EA SPEAR AntiCheat + Wine detection joint surface (F1 25 / FC 25 / future EA SPORTS)"
        catalog = "RE-BREAKER v0.5.0"
        offender_summary = "The joint surface requires spoofing all three layers: Denuvo (the vfs, separate playbook), EAC (wine_get_version -> NULL), and the Wine import. The Denuvo bypass is the hardest (months of per-title work); the EAC layer is medium; the Wine layer is trivial."
        offender_tools = "re-encrypted-vm-bypass, re-vendor-anti-tamper, re-anti-vm-spoof"
        offender_playbook = "playbooks/denuvo-eac-joint.md"

    strings:
        $sm0 = "Denuvo" ascii
        $sm1 = "denuvo_atd" ascii
        $sm2 = "EAAntiCheat" ascii
        $sm3 = "wine_get_version" ascii

    condition:
        uint16(0) == 0x5A4D and
            ($sm0 and $sm2) and
            ($sm1 or $sm3)
}


