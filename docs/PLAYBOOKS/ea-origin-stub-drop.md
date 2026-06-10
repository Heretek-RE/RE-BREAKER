# Playbook: EA Origin Stub-Drop (Lost In Random activation bypass)

**Target class**: EA-shipped games with the Origin activation gate. Example: **Lost In Random** (LIR). The launcher imports only 2 functions, both from `Core/Activation64.dll` ordinals 100 and 101.

**Catalog entry**: `encrypted-vm.bytecode-interpreter.pattern-b`

**Expected runtime**: 30 minutes (one of the easiest playbooks)

**Success probability**: 0.9 (very high; the only blocker is the online entitlement re-check)

**Tools**: `re-runtime-dump`, `re-patch`, `re-static-triage`, `re-dotnet`

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
re-static-triage --target=Core/Activation64.dll --output=/tmp/lir-activation-triage.json
re-dotnet --parse-assembly --target=Core/Activation64.dll
# Expect: "PE image does not have metadata" - confirms it's NATIVE C++, not .NET
re-lief --get-imports-exports --target="Lost In Random.exe" --max_imports=10
# Expect: only 2 imports, both from Core/Activation64.dll ordinals 100 and 101
re-lief --classify-native-protection --target=Core/Activation64.dll
# Expect: "anti-debug-wrapped"
```

**Verify**:
- [ ] The launcher imports ONLY 2 functions, both from `Core/Activation64.dll` ordinals 100 and 101
- [ ] `Core/Activation64.dll` is a NATIVE C++ DLL (not .NET — re-dotnet returns "PE image does not have metadata")
- [ ] `Core/Activation64.dll` is classified as `anti-debug-wrapped`

## 2. Establish the dynamic baseline

```bash
# Capture the pre-patch SHA-256
re-patch --sha256-manifest --target=Core/Activation64.dll
# Record the SHA-256 to override-scope.md as the pre-patch baseline

# Spy on the entitlement check at runtime (Frida approach)
re-runtime-dump --target=Core/Activation64.dll --mode=frida --output=/tmp/lir-frida-baseline/ --license-acknowledge --timeout=60
```

**Verify**:
- [ ] The pre-patch SHA-256 is recorded in `override-scope.md`
- [ ] The Frida baseline shows `Core/Activation64.dll!ord 100` being called once at launch, returning 0 (entitled) after a WinHTTP round-trip to the Origin auth server

## 3. Locate ordinal 100's function body

```bash
# Find the function body at ordinal 100
re-rizin --target=Core/Activation64.dll --find-export --ordinal=100
# Note: the function body RVA is the address returned by the export lookup

# Disassemble the function body
re-rizin --target=Core/Activation64.dll --disassemble-function --rva=<function_rva>
```

**Verify**:
- [ ] The function body at ordinal 100 is a C++ member function (not a forwarder to a separate DLL)
- [ ] The function body's prologue is `push rbp; mov rbp, rsp; sub rsp, ...` (or similar MSVC x64 convention)
- [ ] The function body's epilogue is `add rsp, ...; pop rbp; ret` (or similar)

## 4. Patch the function body to return 0

```bash
# Strategy: replace the function body with `mov rax, 0; ret` (8 bytes)
# This makes ordinal 100 return 0 (entitled) without contacting Origin
re-patch --target=Core/Activation64.dll \
  --offset=<function_body_rva> \
  --strategy=return-zero \
  --dst=/tmp/lir-patched/Core/Activation64.dll
```

**Verify**:
- [ ] The patched file is 8 bytes larger at the offset (the original function body is replaced)
- [ ] The patched file's SHA-256 is recorded (this is the new SHA, will be used for rollback)
- [ ] The first 8 bytes at the function body RVA are `48 31 C0 C3` (xor rax, rax; ret) — or equivalent `mov rax, 0; ret` = `48 C7 C0 00 00 00 00 C3`

## 5. Apply the patch

```bash
# Replace the original file
cp /tmp/lir-patched/Core/Activation64.dll <installation_path>/Core/Activation64.dll
# Or: use re-patch to write directly (it has an --in-place flag)
```

**Verify**:
- [ ] The patched file is in place at `<installation_path>/Core/Activation64.dll`
- [ ] The original file is backed up to `Core/Activation64.dll.bak` (the user already had this, per the Input/ inventory)

## 6. Test the launch

```bash
# Launch the game
wine "/path/to/Lost In Random.exe"
# Or: native Windows launch
```

**Verify**:
- [ ] The game launches without contacting the Origin auth server (verify by network capture)
- [ ] The game starts in single-player mode (Origin entitlement is satisfied)
- [ ] If the game requires online (multiplayer, leaderboards), those features may not work (this is expected; the Origin entitlement is what authenticates them)

## 7. Rollback plan

```bash
# If something goes wrong, restore from the .bak file
cp Core/Activation64.dll.bak Core/Activation64.dll

# Or: use re-patch.restore_original
re-patch --restore-original \
  --original=Core/Activation64.dll.bak \
  --restore-target=Core/Activation64.dll \
  --expected-sha256=<original_sha256>
```

**Verify**:
- [ ] The restored file's SHA-256 matches the pre-patch baseline
- [ ] The game launches normally (with the original entitlement check)

## 8. Document the result

```bash
re-bypass-result --target=Core/Activation64.dll \
  --runtime-cost-minutes=15 \
  --catalog-match=encrypted-vm.bytecode-interpreter.pattern-b \
  --output=/tmp/lir-activation-bypass-result.md
```

**Write** `per-binary/<target>/activation-bypass-result.md` with:
- The pre-patch SHA-256 (for rollback)
- The patched function body (8 bytes: `48 31 C0 C3` or equivalent)
- The catalog match (Pattern B, third-party launcher activation library)
- The runtime cost (how long the patch took)
- What was NOT possible (online entitlement re-check; the game's online features may not work)

## 9. Known limitations / next iterations

- [ ] The Origin entitlement check is bypassed, but the EA / Origin account itself is still required for online features (multiplayer, leaderboards, etc.)
- [ ] The patch is per-binary; each new build of LIR requires re-running the playbook
- [ ] If Origin updates their entitlement protocol, the patched function may not satisfy the new protocol — the binary would crash on launch
- [ ] The stub-drop is a "launch entitlement" bypass, not a "DRM bypass". The GameAssembly.dll's encrypted-VM bytecode interpreter (with 200+ RDTSC + 200+ VMXON + 32 VMCALL) is still intact.
