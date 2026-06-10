# Playbook: Defeating Pattern A-DW + Denuvo Anti-Tamper (UE5 + Denuvo ATD)

**Target class**: UE5 titles with Pattern A-DW (encrypted-VM bytecode interpreter + Denuvo Anti-Tamper trigger-arm). Examples: **Persona 3 Reload** (P3R — the canonical A-DW + Denuvo case from the v2.9.0 stress test).

**Catalog entry**: `encrypted-vm.bytecode-interpreter.pattern-a-dw`

**Expected runtime**: 240 minutes (per-target static + dynamic; the Denuvo bypass is the long pole)

**Success probability**: 0.2 (Denuvo is the hardest commercial ATD; no public bypass)

**Tools**: `re-anti-debug-patch`, `re-vm-decrypt`, `re-runtime-dump`, `re-encrypted-vm-bypass`, `re-static-triage`, `re-anti-analysis`, `re-hypervisor-detect`, `re-pdb`

## 0. Resolve the main binary (v0.3.0 NEW)

```bash
# For Unity IL2CPP launchers (FM26, HKIA, LIR, P3R)
re-il2cpp-triage --target=<launcher> --output=/tmp/<key>-il2cpp-triage.json

# For fresh targets (no prior analysis)
re-triage --target=<binary> --output=/tmp/<key>-triage.json
```

This step is required for the catalog match to return non-zero matches
on Unity IL2CPP targets (which it returned 0 for in v0.2.0). For
non-IL2CPP targets, it can be skipped.

## 1. Confirm the target matches the pattern

```bash
re-static-triage --target=P3R.exe --output=/tmp/p3r-triage.json
re-anti-analysis --target=P3R.exe --output=/tmp/p3r-anti.json
re-hypervisor-detect --target=P3R.exe --output=/tmp/p3r-hyp.json
re-lief --get-debug-directory --target=P3R.exe
```

**Verify**:
- [ ] Section set intersects [`.arch`, `.sbss`, `.xcode`, `.xpdata`, `.xtext`, `.xtls`] (the FULL A-DW section set)
- [ ] Debug directory contains a POGO entry (type 10) of size >= 1000 bytes — this is the Pattern A-DW differentiator from base Pattern A
- [ ] `re-anti-analysis` reports ≥ 30 VMCALL sites (Denuvo ATD characteristic)
- [ ] `re-anti-analysis` reports ≥ 100 VMXON sites
- [ ] `re-hypervisor-detect` reports `kernel-active` posture with 100+ VMX-EPT hits

**Catalog match**:
```bash
re-catalog-match --triage=/tmp/p3r-triage.json --intent=both
# Expect: encrypted-vm.bytecode-interpreter.pattern-a-dw (high confidence)
# Expect: anti-tamper-vendors.denuvo (very high confidence if 'denuvo' string is present)
```

## 2. Establish the dynamic baseline (with GPU + Steam token)

```bash
# Wine + winedbg + gdb on Wine 11.0
re-winedbg --target=P3R.exe --port=0 --session=p3r-baseline

# Set RVA-aware breakpoint on the first RDTSC site
re-winedbg-set-bp --target=P3R.exe --rva=<first_rdtsc_rva> --session=p3r-baseline
re-winedbg-continue --session=p3r-baseline --timeout=15
re-winedbg-read-registers --session=p3r-baseline
```

**Verify**:
- [ ] The breakpoint at the first RDTSC site hits before the anti-debug layer triggers
- [ ] The RDTSC delta histogram (over 1000 samples) shows a bimodal distribution (normal + trapped)
- [ ] The trapped population is at the high-delta end (typically 1000+ cycles)

## 3. Bypass the POGO entry validation

```bash
# POGO entry is at image offset 84470104 (per the debug-directory read)
# The POGO entry is the trigger-arm signature; bypass by patching the entry's
# return-value check to always return 0 (success)
re-patch --target=P3R.exe --offset=84470104 --strategy=pogo-bypass
```

**Verify**:
- [ ] The POGO entry's return-value check is patched (the binary now returns 0 unconditionally)
- [ ] The patched binary boots without triggering Denuvo's POGO-based exit

## 4. Patch the anti-debug primitives

```bash
# Identify and patch the first 10 RDTSC sites
for offset in $(jq -r '.byte_sequences[] | select(.primitive == "RDTSC") | .matches[:10] | .[]' /tmp/p3r-anti.json); do
  re-anti-debug-patch --target=P3R.exe --offset=$offset --strategy=rdtsc-zero
done

# Identify and patch the first 5 VMCALL sites
for offset in $(jq -r '.byte_sequences[] | select(.primitive == "VMCALL") | .matches[:5] | .[]' /tmp/p3r-anti.json); do
  re-anti-debug-patch --target=P3R.exe --offset=$offset --strategy=vmcall-noop
done
```

**Verify**:
- [ ] All 10 RDTSC sites patched to return 0
- [ ] All 5 VMCALL sites patched to be no-ops
- [ ] The patched binary boots without the RDTSC delta-trap triggering

## 5. Spoof the hypervisor detection

```bash
re-anti-vm-spoof --snapshot-bare-metal --output=/tmp/cpuid-snapshot.json
re-anti-vm-spoof --target=P3R.exe --snapshot=/tmp/cpuid-snapshot.json --mode=frida
```

**Verify**:
- [ ] All CPUID-leaf-1-ECX-bit-31 reads return 0
- [ ] All CPUID-leaf-0x40000000-vendor reads return bare-metal vendor
- [ ] All VMCALL probes are no-op'd
- [ ] The POGO entry's hypervisor check (if any) is satisfied

## 6. Lift the encrypted-VM dispatcher

```bash
re-rizin --target=P3R.exe --find-dispatcher --encrypted-vm-family=pattern-a-dw
re-vtil --target=P3R.exe --dispatcher=<dispatcher_rva> --output=/tmp/p3r-dispatcher.il
re-vtil --il=/tmp/p3r-dispatcher.il --simplify=ollvm-default --output=/tmp/p3r-dispatcher-simplified.il
```

**Verify**:
- [ ] The lifted IL has fewer than 2000 instructions (per-dispatcher for P3R's encrypted-VM is larger than Pattern A base)
- [ ] The simplified IL has at least 30% fewer instructions than the raw lift
- [ ] The simplified IL has named basic blocks

## 7. The Denuvo license check

```bash
# Denuvo's online license check is at the network level. The bypass primitive:
# (a) host-level firewall to block the Denuvo entitlement server
# (b) run the binary in an offline state
# (c) the binary's Denuvo layer will detect the offline state and exit
# (d) the realistic alternative: patch the license check to return "entitled"
re-anti-debug-patch --target=P3R.exe --offset=<license_check_rva> --strategy=license-bypass
```

**Verify**:
- [ ] The Denuvo license check returns "entitled" (the patched return value)
- [ ] The binary continues past the license check
- [ ] The binary does NOT phone home to the Denuvo entitlement server (verify by network capture)

## 8. Document the result

```bash
re-bypass-result --target=P3R.exe \
  --dispatcher-il=/tmp/p3r-dispatcher-simplified.il \
  --runtime-cost-minutes=240 \
  --catalog-match=encrypted-vm.bytecode-interpreter.pattern-a-dw \
  --output=/tmp/p3r-bypass-result.md
```

**Write** `per-binary/<target>/bypass-result.md` with:
- Which primitives were neutralized (RDTSC sites patched, VMCALL sites no-op'd, POGO entry bypassed)
- Which sections were decrypted (the .arch / .xcode / .xtls payload)
- What the runtime cost was
- What was NOT possible (e.g. online license check was NOT bypassed; the binary's UE5 splash screen still requires a valid license from the publisher's server)

## 9. Known limitations / next iterations

- [ ] **Denuvo ATD is the hardest commercial protection**. The 0.2 success_probability reflects this — per-title bypass is months of work, no general solution.
- [ ] POGO entry payload is opaque; the public documentation of POGO is sparse. Future iterations need the vendor's POGO interpreter.
- [ ] Online entitlement check is still required; the binary's UE5 splash screen still requires a valid license from the publisher's server.
- [ ] Per-build breakable; needs re-run on every patch.
- [ ] If the runtime-decrypted region is larger than 200MB (P3R's is borderline), the lift may take 4-6 hours.
- [ ] Denuvo's ATD layer may also detect the POGO bypass and exit. The realistic alternative is to *not* bypass the POGO entry but instead to *emulate* the POGO entry's return value in a sandbox.
