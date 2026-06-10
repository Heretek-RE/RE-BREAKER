# Playbook: Pattern A-VMT (BlackSpace Engine handler-table dispatch)

**Target class**: Pearl Abyss BlackSpace Engine titles. Example: **Crimson Desert** (CD — the canonical Pattern A-VMT case from the v2.9.0 stress test).

**Catalog entry**: `encrypted-vm.bytecode-interpreter.pattern-a-vmt`

**Expected runtime**: 180 minutes

**Success probability**: 0.5 (the .link BSS runtime-decrypted handler targets are the hard part)

**Tools**: `re-vm-decrypt`, `re-frida`, `re-runtime-dump`, `re-encrypted-vm-bypass`, `re-lief`

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
re-static-triage --target=CrimsonDesert.exe --output=/tmp/cd-triage.json
re-lief --classify-native-protection --target=CrimsonDesert.exe
# Expect: "encrypted-vm-handler-table-dispatch" (the new Pattern A-VMT class)
```

**Verify**:
- [ ] Section set intersects [`.arch`, `.link`, `.xcode`, `.xtext`, `.sbss`]
- [ ] `.xcode` has the dual-regime signature: low-entropy head (dispatch table) + high-entropy tail (encrypted metadata)
- [ ] Debug directory contains a POGO entry AND an ILTCG entry (the dual-tell is the A-VMT differentiator from A-DW)

## 2. Read the .xcode dispatch table

```bash
# Extract the .xcode section
re-lief --extract-section --target=CrimsonDesert.exe --section=.xcode --output=/tmp/cd-xcode.bin

# The dispatch table is in the low-entropy head. The entries are 16-byte big-endian:
#   [u32 handler_id][u32 reserved=0][u64 target]
# Use re-triton or a simple script to parse the table
python3 -c "
import struct
data = open('/tmp/cd-xcode.bin', 'rb').read()
for i in range(0, min(8192, len(data)), 16):
    hid, reserved, target = struct.unpack('>IIQ', data[i:i+16])
    if hid == 0 and reserved == 0 and target == 0:
        break
    print(f'  handler {hid}: target 0x{target:x}')
"
```

**Verify**:
- [ ] The first N entries have a non-zero `handler_id` and a non-zero `target`
- [ ] The `target` values are RVA-like (typically in the range 0x10000000-0xFFFFFFFF for a 32-bit RVA, or 0x140000000+ for a 64-bit RVA)

## 3. Resolve the handler targets in .link (the hard part)

```bash
# The .link section contains the runtime-decrypted handler bodies
# At boot, BlackSpace decrypts .arch (the handler bodies) and patches them into .link
# To capture the runtime-decrypted .link, use Frida
re-runtime-dump --target=CrimsonDesert.exe --mode=frida --output=/tmp/cd-link-decrypted/ --license-acknowledge --timeout=600
```

**Verify**:
- [ ] The Frida trace shows `CreateFileW` being called on `data.xpac` or similar
- [ ] The .link section at runtime is writable (it was read-only on disk; the runtime decryption patches it in-place)
- [ ] The decrypted handler bodies are between 4KB and 100KB each

## 4. Reconstruct the handler table

```bash
# For each handler in the dispatch table, look up the corresponding decrypted body in .link
python3 -c "
import struct
xcode = open('/tmp/cd-xcode.bin', 'rb').read()
link_decrypted = open('/tmp/cd-link-decrypted/decrypted.bin', 'rb').read()

# The target in the dispatch table is a RVA. Resolve it to a .link offset
# (this is engine-specific; check BlackSpace's source or just brute-force)

for i in range(0, min(8192, len(xcode)), 16):
    hid, reserved, target_rva = struct.unpack('>IIQ', xcode[i:i+16])
    if hid == 0:
        break
    # Map target_rva to link_decrypted offset
    body = link_decrypted[target_rva:target_rva+8192]
    # Write the handler body to a separate file
    with open(f'/tmp/cd-handler-{hid:04x}.bin', 'wb') as f:
        f.write(body)
    print(f'  handler {hid:04x}: rva 0x{target_rva:x}, wrote {len(body)} bytes')
"
```

**Verify**:
- [ ] Each handler body is at least 4KB (handlers smaller than this are likely placeholders or stub)
- [ ] No two handlers have identical bodies (this would indicate a deduplication scheme, which BlackSpace doesn't use)

## 5. Lift each handler to readable IL

```bash
# Lift each handler to IL
for hid in $(ls /tmp/cd-handler-*.bin); do
  re-vtil --target=$hid --output=${hid%.bin}.il --simplify=ollvm-default
done

# Aggregate the lifted IL into a single handler-table view
re-runtime-dump --aggregate-handlers --input=/tmp/cd-handler-*.il --output=/tmp/cd-handler-table.md
```

**Verify**:
- [ ] The aggregated handler-table view has all 4096 (or however many) handlers listed
- [ ] Each handler is named in the view (e.g. "handler_0001: addition", "handler_0002: subtraction", ...)
- [ ] The handler-table view is human-readable

## 6. Document the result

```bash
re-bypass-result --target=CrimsonDesert.exe \
  --handler-table=/tmp/cd-handler-table.md \
  --runtime-cost-minutes=180 \
  --catalog-match=encrypted-vm.bytecode-interpreter.pattern-a-vmt \
  --output=/tmp/cd-bypass-result.md
```

**Write** `per-binary/<target>/bypass-result.md` with the full handler table.

## 7. Known limitations / next iterations

- [ ] The .link runtime-decryption requires GPU + valid Pearl Abyss account (librdkafka telemetry publishes a handshake at boot). Need a fully-functional environment for the lift to succeed.
- [ ] Hermes SDK + librdkafka telemetry surface: capture the publish topics and payloads as a side-effect of the bypass (see Pattern D catalog entry).
- [ ] The .arch section (73.7MB) is the static x86_64 code; the .link is the runtime-decrypted data. The two together form the full BlackSpace engine.
