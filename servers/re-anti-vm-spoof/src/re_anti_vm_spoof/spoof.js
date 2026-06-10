// v0.8.0+ Wave 1 (Item C) — RE-BREAKER anti-VM spoofing frida script.
//
// Fills the dangling `spoof.js` path that re-anti-vm-spoof has been
// advertising since v0.2.0. The script reads the bare-metal CPUID
// snapshot + RDTSC delta cap from a JSON file passed via stdin (the
// `re_anti_vm_spoof.spoof_runtime` Python wrapper writes the file
// to /tmp/re-spoof-input-{pid}.json, then invokes frida with this
// script). Hooks are installed for the per-primitive offsets the
// target's triage identified.
//
// v0.8.0+ design: this script is the runtime companion to
// re-anti-vm-spoof.spoof_target() (which builds the plan).
// The Python wrapper — `re_anti_vm_spoof.spoof_runtime()` — invokes
// frida with this script as the inline JS, then waits for the
// session to be detached after `timeout_s`.
//
// Hook strategy (per primitive):
//   - CPUID (0F A2): onEnter reads the requested leaf via context.eax,
//     computes the spoofed values from the snapshot, then onLeave
//     overwrites context.eax/ebx/ecx/edx with the snapshot values.
//   - RDTSC (0F 31): onLeave overwrites the return value (edx:eax) so
//     that the delta vs the baseline is capped to `rdtsc_cap` cycles.
//   - VMCALL (0F 01 C1): onEnter NOPs the call by replacing the
//     return value with the caller's expected non-hypervisor result.
//   - VMXON (0F C7 /6): onEnter NOPs the call (same as VMCALL).
//   - INVD (0F 08): onEnter NOPs the call by returning without
//     invalidating the cache (the cache is consistent on bare metal).
//
// References:
//   - re-anti-vm-spoof.spoof_target(): builds the plan + snapshot
//   - re-frida-runtime.frida_attach(): generic frida attach harness
//   - docs/ANTI-VM-STATUS.md: the 14 detection vectors this defeats

'use strict';

// === Read the snapshot + offsets from stdin ===
const snapshot = JSON.parse(readFileSync('/dev/stdin', 'utf8'));
const log = (msg) => send({event: 'log', msg: msg});

log('v0.8.0+ anti-VM spoof: snapshot loaded, ' + Object.keys(snapshot).length + ' fields');

// === CPUID hypervisor-presence bit defeat (leaf 1, ECX bit 31) ===
// Spoof leaf 0, leaf 1, and leaf 0x40000000 to the bare-metal values.
if (snapshot.cpuid_offset) {
    const cpuid_addr = ptr(snapshot.cpuid_offset);
    log('installing CPUID hook at ' + cpuid_addr);
    Interceptor.attach(cpuid_addr, {
        onEnter: function (args) {
            this.leaf = this.context.eax;
        },
        onLeave: function (retval) {
            const ctx = this.context;
            // Spoof leaf 0 (vendor string)
            if (this.leaf === 0 && snapshot.leaf_0) {
                ctx.eax = snapshot.leaf_0.eax;
                ctx.ebx = snapshot.leaf_0.ebx;
                ctx.ecx = snapshot.leaf_0.ecx;
                ctx.edx = snapshot.leaf_0.edx;
            }
            // Spoof leaf 1 (feature flags; clear bit 31 of ECX = no hypervisor)
            else if (this.leaf === 1 && snapshot.leaf_1) {
                ctx.eax = snapshot.leaf_1.eax;
                ctx.ebx = snapshot.leaf_1.ebx;
                ctx.ecx = snapshot.leaf_1.ecx & ~(1 << 31);  // clear hypervisor-present
                ctx.edx = snapshot.leaf_1.edx;
            }
            // Spoof leaf 0x40000000 (hypervisor vendor string → zeroed)
            else if (this.leaf === 0x40000000 && snapshot.leaf_0x40000000) {
                ctx.eax = snapshot.leaf_0x40000000.eax;
                ctx.ebx = snapshot.leaf_0x40000000.ebx;
                ctx.ecx = snapshot.leaf_0x40000000.ecx;
                ctx.edx = snapshot.leaf_0x40000000.edx;
            }
        }
    });
}

// === RDTSC delta cap ===
// Bare-metal RDTSC ticks forward at the host's TSC rate. The trap is a
// bimodal distribution: inside-VMX has small deltas (TSC trapped),
// outside-VMX has large deltas. We cap the delta to a value the target
// would observe on bare metal.
if (snapshot.rdtsc_offset && snapshot.rdtsc_cap) {
    const rdtsc_addr = ptr(snapshot.rdtsc_offset);
    log('installing RDTSC cap=' + snapshot.rdtsc_cap + ' hook at ' + rdtsc_addr);
    let last_rdtsc = snapshot.rdtsc_baseline || 0;
    Interceptor.attach(rdtsc_addr, {
        onLeave: function (retval) {
            // retval is the 64-bit TSC value (edx:eax)
            const tsc = retval.toUInt32() | (0);  // 32-bit only; edx upper is OK to ignore for cap
            const delta = Math.abs(tsc - last_rdtsc);
            if (delta > snapshot.rdtsc_cap) {
                // Cap the delta: pretend TSC advanced by exactly `cap` cycles
                const new_tsc = (last_rdtsc + snapshot.rdtsc_cap) >>> 0;
                this.context.eax = new_tsc;
            }
            last_rdtsc = this.context.eax | 0;
        }
    });
}

// === VMCALL defeat (Pattern A only) ===
// VMCALL is "VM Call" — exits to hypervisor. On bare metal, the opcode
// is invalid and raises #UD. We NOP the call by jumping over it.
if (snapshot.vmcall_offset) {
    const vmcall_addr = ptr(snapshot.vmcall_offset);
    log('installing VMCALL NOP hook at ' + vmcall_addr);
    Interceptor.attach(vmcall_addr, {
        onEnter: function (args) {
            // Patch the in-memory bytes to 0x90 0x90 0x90 (3 bytes for VMCALL)
            vmcall_addr.writeByteArray([0x90, 0x90, 0x90]);
        }
    });
}

// === VMXON defeat (Pattern A only) ===
// VMXON enters VMX operation. Same approach as VMCALL.
if (snapshot.vmxon_offset) {
    const vmxon_addr = ptr(snapshot.vmxon_offset);
    log('installing VMXON NOP hook at ' + vmxon_addr);
    Interceptor.attach(vmxon_addr, {
        onEnter: function (args) {
            // VMXON is 0xF3 0x0F 0xC7 /6 (4 bytes) — NOP them all
            vmxon_addr.writeByteArray([0x90, 0x90, 0x90, 0x90]);
        }
    });
}

// === INVD defeat ===
// INVD invalidates all caches without writing back. The bare-metal
// equivalent (WBINVD) is much slower; INVD is the trap. We NOP.
if (snapshot.invd_offset) {
    const invd_addr = ptr(snapshot.invd_offset);
    log('installing INVD NOP hook at ' + invd_addr);
    Interceptor.attach(invd_addr, {
        onEnter: function (args) {
            invd_addr.writeByteArray([0x90, 0x90]);
        }
    });
}

log('v0.8.0+ anti-VM spoof: all hooks installed');
send({event: 'ready', snapshot_keys: Object.keys(snapshot)});
