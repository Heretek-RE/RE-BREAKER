# Playbook: Defeating Pattern A — encrypted-VM bytecode interpreter (Unity IL2CPP target)

**Target class**: Unity 6 / Unity 2022.3 LTS / older Unity games with an encrypted-VM bytecode interpreter layer on top of the standard IL2CPP runtime. Examples: **Football Manager 26** (FM26), **Hello Kitty Island Adventure** (HKIA), **Lost In Random** (LIR — but with Origin stub-drop instead of bypass).

**Catalog entry**: `encrypted-vm.bytecode-interpreter.pattern-a`

**Expected runtime**: 45 minutes (per-target static + dynamic)

**Success probability**: 0.7 (per-target success varies; some are easier than others)

**Tools**: `re-vm-decrypt`, `re-frida`, `re-runtime-dump`, `re-encrypted-vm-bypass`, `re-static-triage`, `re-anti-analysis`, `re-hypervisor-detect`

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
# Static triage
re-static-triage --target=GameAssembly.dll --output=/tmp/fm26-triage.json

# Anti-analysis scan
re-anti-analysis --target=GameAssembly.dll --output=/tmp/fm26-anti.json

# Hypervisor posture
re-hypervisor-detect --target=GameAssembly.dll --output=/tmp/fm26-hyp.json
```

**Verify**:
- [ ] Section set intersects [`.xtls`, `.xpdata`, `.xdata`, `.arch`, `.link`, `.sbss`, `.xcode`]
- [ ] `re-anti-analysis` reports ≥ 50 RDTSC sites
- [ ] `re-anti-analysis` reports ≥ 50 CPUID sites
- [ ] `re-anti-analysis` reports ≥ 50 VMXON sites
- [ ] `re-hypervisor-detect` reports `kernel-active` or `static-probes-only`

**Catalog match**:
```bash
re-catalog-match --triage=/tmp/fm26-triage.json --intent=both
# Expect: encrypted-vm.bytecode-interpreter.pattern-a (high confidence)
# Expect: anti-debug.rdtsc-timing-trap (medium-high confidence)
# Expect: anti-vm.cpuid-leaf-1-ecx-bit-31 (medium-high confidence)
```

## 2. Establish the dynamic baseline

```bash
# Speakeasy emulation
re-runtime-dump --target=GameAssembly.dll --mode=emulator --output=/tmp/fm26-emu/ --license-acknowledge --timeout=300
```

**Verify**:
- [ ] `/tmp/fm26-emu/decrypted/` has at least 1 file (the lazy-decrypted region)
- [ ] The decrypted file size is between 1MB and 100MB (typical for a Unity GameAssembly's runtime-decrypted code)
- [ ] The `speakeasy-trace.json` shows at least 1 anti-debug API call (IsDebuggerPresent or RDTSC)

## 3. Patch the anti-debug primitives

```bash
# Identify the first 5 RDTSC sites
jq '.byte_sequences[] | select(.primitive == "RDTSC") | .matches[:5]' /tmp/fm26-anti.json

# Patch each RDTSC site to return 0
for offset in $(jq -r '.byte_sequences[] | select(.primitive == "RDTSC") | .matches[:5] | .[]' /tmp/fm26-anti.json); do
  re-anti-debug-patch --target=GameAssembly.dll --offset=$offset --strategy=rdtsc-zero
done
```

**Verify**:
- [ ] The patched binary boots without crashing (verify by attempting a 30s speakeasy run after patching)
- [ ] No anti-debug API calls are intercepted after patching (verify by re-running speakeasy)

## 4. Spoof the hypervisor detection

```bash
# Snapshot a bare-metal CPUID profile (run on a known-bare-metal host)
re-anti-vm-spoof --snapshot-bare-metal --output=/tmp/cpuid-snapshot.json

# Apply the snapshot at runtime
re-anti-vm-spoof --target=GameAssembly.dll --snapshot=/tmp/cpuid-snapshot.json --mode=frida
```

**Verify**:
- [ ] All CPUID-leaf-1-ECX-bit-31 reads return 0
- [ ] All CPUID-leaf-0x40000000-vendor reads return the bare-metal vendor string
- [ ] All VMCALL probes are no-op'd (or return 0)

## 5. Lift the encrypted-VM dispatcher

```bash
# Identify the dispatcher candidate
re-rizin --target=GameAssembly.dll --find-dispatcher

# Lift the dispatcher's IL
re-vtil --target=GameAssembly.dll --dispatcher=<dispatcher_rva> --output=/tmp/fm26-dispatcher.il

# Simplify the lifted IL with the d810-ng pass set
re-vtil --il=/tmp/fm26-dispatcher.il --simplify=ollvm-default --output=/tmp/fm26-dispatcher-simplified.il
```

**Verify**:
- [ ] The lifted IL has fewer than 1000 instructions (per-dispatcher)
- [ ] The simplified IL has at least 50% fewer instructions than the raw lift
- [ ] The simplified IL has named basic blocks (not just block_0, block_1, ...)

## 6. Document the result

```bash
# Generate the bypass result document
re-bypass-result --target=GameAssembly.dll \
  --dispatcher-il=/tmp/fm26-dispatcher-simplified.il \
  --runtime-cost-minutes=42 \
  --catalog-match=encrypted-vm.bytecode-interpreter.pattern-a \
  --output=/tmp/fm26-bypass-result.md
```

**Write** `per-binary/<key>/bypass-result.md` with:
- Which anti-debug primitives were neutralized (RDTSC sites patched, CPUID sites spoofed, etc.)
- Which sections were decrypted (the .xtls / .xpdata payload)
- What the runtime cost was (how long the bypass took)
- What was NOT possible (e.g. license-token forgery, online entitlement bypass)

## 7. Known limitations / next iterations

- [ ] The online entitlement check (Origin / Steam / EOS) still requires a valid publisher account, unless you also apply the corresponding launch-entitlement bypass (`re-origin-stub-drop` / `re-eos-bypass` / etc.)
- [ ] The bypass is per-target; each new build of the same game requires re-running the playbook
- [ ] Some encrypted-VM bytecode interpreters have built-in anti-tamper that detects the patch + exits; in that case, use the Frida-only approach (`--mode=frida`) instead of the static-patch approach
- [ ] If the runtime-decrypted region is larger than 100MB, the lift may take 1-2 hours (consider `re-triton` symbolic execution as a faster alternative)
