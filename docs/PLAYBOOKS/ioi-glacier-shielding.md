# Playbook: IOI Glacier "shielding" subsystem (007 First Light)

**Target class**: IO Interactive Glacier 2 / 007 First Light (and likely the rest of IOI's recent titles).

**Catalog entry**: `encrypted-vm.bytecode-interpreter.unity-shielding-pdb-leak` + `encrypted-vm.bytecode-interpreter.pattern-a`

**Expected runtime**: 120 minutes

**Success probability**: 0.5 (the .tls section is anomalously large at 274MB; the lift is non-trivial)

**Tools**: `re-static-triage`, `re-anti-analysis`, `re-hypervisor-detect`, `re-vm-decrypt`, `re-frida`, `re-pdb`, `re-anti-debug-patch`

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

## 1. The "shielding" PDB leak

```bash
# The launcher PDB path is the canonical finding
re-lief --categorize-strings --target=007FirstLight.exe --output=/tmp/007fl-strings.json
# Look for "WindowsLauncher_shielding.pdb" in the output
grep "shielding" /tmp/007fl-strings.json
```

**Verify**:
- [ ] The PDB path is `3. WindowsLauncher_shielding.pdb` (or similar — the project name is "shielding")
- [ ] The compiler is MSVC 14.29 (Visual Studio 2019)
- [ ] The binary was built in 2026 (the build timestamp)

## 2. The Confluence URL leak (Pattern D side-effect)

```bash
grep "ioicloud" /tmp/007fl-strings.json
# Expect: https://ioicloud.atlassian.net/wiki/spaces/TECH/pages/5618628/Base+Tag+Reference
```

**Verify**:
- [ ] The Confluence URL is found
- [ ] The URL is in the `TECH` space (IOI's internal Atlassian wiki)
- [ ] The page ID is 5618628 (the "Base Tag Reference" page)

## 3. Confirm the protection surface

```bash
re-static-triage --target=007FirstLight.exe --output=/tmp/007fl-triage.json
re-anti-analysis --target=007FirstLight.exe --output=/tmp/007fl-anti.json
re-hypervisor-detect --target=007FirstLight.exe --output=/tmp/007fl-hyp.json
```

**Verify**:
- [ ] 1966 RDTSC sites (the v2.9.0 stress test finding)
- [ ] 200+ CPUID sites
- [ ] 200+ VMXON sites
- [ ] 28 VMCALL sites
- [ ] kernel-active hypervisor posture
- [ ] 274MB .tls section (the anomalous size)
- [ ] .data1 section with entropy 7.19 (encrypted)

## 4. Patch the anti-debug primitives

The 1966 RDTSC sites are too many to patch one-by-one. The strategy is pattern-based:

```bash
# Patch ALL RDTSC sites (not just the first 10)
re-anti-debug-patch --target=007FirstLight.exe --strategy=rdtsc-zero-all
# Patch ALL VMXON sites
re-anti-debug-patch --target=007FirstLight.exe --strategy=vmxon-noop-all
# Patch ALL CPUID sites
re-anti-debug-patch --target=007FirstLight.exe --strategy=cpuid-spoof-all
```

**Verify**:
- [ ] The patched binary is 007FirstLight-patched.exe with ~2000+ patched sites
- [ ] The patched binary boots without SIGABRT in the early-boot trace

## 5. Lift the encrypted-VM dispatcher

```bash
re-rizin --target=007FirstLight.exe --find-dispatcher --encrypted-vm-family=pattern-a
re-vtil --target=007FirstLight.exe --dispatcher=<dispatcher_rva> --output=/tmp/007fl-dispatcher.il
re-vtil --il=/tmp/007fl-dispatcher.il --simplify=ollvm-default --output=/tmp/007fl-dispatcher-simplified.il
```

**Verify**:
- [ ] The lifted IL has fewer than 1500 instructions (per-dispatcher for 007FL)
- [ ] The simplified IL has at least 50% fewer instructions than the raw lift

## 6. Document the result

```bash
re-bypass-result --target=007FirstLight.exe \
  --dispatcher-il=/tmp/007fl-dispatcher-simplified.il \
  --runtime-cost-minutes=120 \
  --catalog-match=encrypted-vm.bytecode-interpreter.unity-shielding-pdb-leak \
  --output=/tmp/007fl-bypass-result.md
```

## 7. Known limitations / next iterations

- [ ] The 274MB .tls section is anomalously large. May be a static-decrypted region that requires a different runtime hook.
- [ ] The IOI entitlement server (contacted via WinHTTP) is out of scope for this playbook.
- [ ] The .data1 section entropy 7.19 indicates encrypted data; runtime decryption is the only way to read it.
- [ ] Per-build breakable.
