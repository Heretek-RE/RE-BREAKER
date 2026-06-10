# Playbook: CA Warscape light VM + EOS overlay (Total War Warhammer III v7.2.1)

**Target class**: Creative Assembly Warscape / Empire engine titles with Epic Online Services overlay. Example: **Total War Warhammer III v7.2.1** (TWW3).

**Catalog entries**: `encrypted-vm.bytecode-interpreter.pattern-c`, `encrypted-vm.bytecode-interpreter.eos-overlay-bypass`

**Expected runtime**: 90 minutes (the EOS bypass is trivial; the CA Warscape bypass is medium)

**Success probability**: 0.6 (the .pack archive decryption via libled.dll is the hard part)

**Tools**: `re-runtime-dump`, `re-frida`, `re-format-decode`, `re-anti-debug-patch`, `re-encrypted-vm-bypass`

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

## 1. Bypass the EOS overlay (the easy part)

```bash
# Drop a .eos side-file in the game directory
echo "DEV_MODE=1" > "<installation_path>/game.eos"
# Or use the documented dev-mode escape hatch
```

**Verify**:
- [ ] The game launches without contacting the EOS auth server
- [ ] Single-player mode is available without an EOS login

## 2. Confirm the CA Warscape light VM

```bash
re-static-triage --target=Warhammer3.exe --output=/tmp/tww3-triage.json
re-lief --classify-native-protection --target=Warhammer3.exe
# Expect: "encrypted-vm-bytecode-interpreter" with 3-section subset
```

**Verify**:
- [ ] Section set intersects [`.link`, `.sbss`, `.xcode`]
- [ ] The binary has `libled.dll` sibling (the CA "Light Encryption Driver" runtime-decryption loader)
- [ ] The binary has `EOSSDK-Win64-Shipping.dll` sibling (19MB)

## 3. Decrypt the .pack archives via libled.dll

```bash
# libled.dll's runtime-decryption entry point: hook it
re-runtime-dump --target=Warhammer3.exe --mode=frida --output=/tmp/tww3-pack-decrypted/ --license-acknowledge --timeout=600

# The Frida hook:
# 1. Hook the libled.dll decryption function
# 2. Capture the AES key + IV + input path
# 3. Capture the decrypted output buffer
# 4. Write the decrypted .pack contents to /tmp/tww3-pack-decrypted/
```

**Verify**:
- [ ] The first .pack file decrypted is `data/boot.pack` (42KB)
- [ ] The decrypted `boot.pack` has the CA Archive version-5 header
- [ ] The `boot.pack` contains 30 timestamped files (per the v2.9.0 honest-read finding)

## 4. Write a Kaitai .ksy for the .pack format

```bash
# Use the boot.pack header as the .ksy template
# The .pack format: [magic 4B][version 4B][file_count 4B][toc_offset 4B][toc_size 4B][flags 4B][TOC][files]
# Write the .ksy:
cat > /tmp/tww3-pack.ksy << 'EOF'
seq:
  - id: magic
    contents: 'PACK'
  - id: version
    type: u4le
  - id: file_count
    type: u4le
  - id: toc_offset
    type: u4le
  - id: toc_size
    type: u4le
  - id: flags
    type: u4le
  - id: toc
    type: toc_entry
    repeat: expr
    repeat-expr: file_count
types:
  toc_entry:
    seq:
      - id: filename
        type: strz
      - id: offset
        type: u8le
      - id: size
        type: u8le
      - id: flags
        type: u4le
EOF

# Compile the .ksy
kaitai-struct-compiler --target python /tmp/tww3-pack.ksy

# Apply the .ksy to data/boot.pack
kaitai-struct-compiler --target python /tmp/tww3-pack.ksy
python3 -c "
from tww3_pack import Tww3Pack
import json
p = Tww3Pack.from_file('/tmp/tww3-pack-decrypted/boot.pack')
print(json.dumps(p, indent=2, default=str))
"
```

**Verify**:
- [ ] The .ksy parses `data/boot.pack` successfully
- [ ] The parsed file_count matches the .pack's actual entry count (30 for boot.pack)

## 5. Apply the .ksy to data/data.pack

```bash
# The big one: data/data.pack is 408MB and contains 13159 files
python3 -c "
from tww3_pack import Tww3Pack
p = Tww3Pack.from_file('/tmp/tww3-pack-decrypted/data.pack')
print(f'file_count: {p.file_count}')
print(f'toc_offset: {p.toc_offset}')
print(f'toc_size: {p.toc_size}')
"
```

**Verify**:
- [ ] The .ksy parses `data/data.pack` successfully
- [ ] The file_count is 13159 (per the v2.9.0 honest-read finding)
- [ ] The TOC offset is reasonable (typically 0x100-0x10000)

## 6. Document the result

```bash
re-bypass-result --target=Warhammer3.exe \
  --pack-decrypted=/tmp/tww3-pack-decrypted/ \
  --ksy=/tmp/tww3-pack.ksy \
  --runtime-cost-minutes=90 \
  --catalog-match=encrypted-vm.bytecode-interpreter.pattern-c \
  --output=/tmp/tww3-bypass-result.md
```

**Write** `per-binary/<target>/bypass-result.md` with:
- The .eos side-file content
- The .ksy for the .pack format
- The decrypted `data/data.pack` index (13159 files)
- The runtime cost

## 7. Known limitations / next iterations

- [ ] The CA Clockwork mod-loading framework is intact. Bypassing its mod-allow/deny decision is trivial (it's a developer-mode flag, not a security feature).
- [ ] The `bypass_time.txt` flag disables the server-side time-limit check (this is a separate opt-in, not part of the EOS bypass).
- [ ] The CA Warscape light VM is a 3-section subset of the full encrypted-VM bytecode interpreter family. The .text section is 65.7MB and the .impdata section is 138.5MB (W^X). A full lift is medium-complexity.
- [ ] Per-patch breakable; needs re-run on every CA update.
