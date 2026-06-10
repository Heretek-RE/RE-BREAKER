---
name: re-runtime-frida
version: 0.3.0
status: implemented
family: workflow
catalog_entry: null
playbook: docs/PLAYBOOKS/pattern-a.md
pattern_yaml: data/patterns/runtime-frida.yml
---

# re-runtime-frida

**v0.3.0 implemented.** Workflow for actually attaching Frida to a running target, installing the per-Pattern hook set, and capturing decrypted payloads. Closes G2 (runtime execution was dry-run in v0.2.0).

## When to use this skill

Invoke when:
- The catalog match returned encrypted-VM entries (Pattern A, A-DW, A-VMT, B, C, D)
- The operator wants to actually capture the decrypted method bodies (or the entitlement check stub for Pattern B)
- The frida Python package is installed in the host's venv (or Wine is set up for Windows-target Frida attach)

## Tools invoked

- `mcp__re-frida-runtime.frida_attach(target, pid=None, hooks=[], pattern="A", output="/tmp/<key>/decrypted/")` — actually attaches Frida + installs hooks + captures payloads

## Workflow

1. **Verify frida is available.** Call `mcp__re-frida-runtime.frida_attach(target=target, pattern="<the-pattern>")` and check the `frida_available` field. If false, install `frida>=17.0` via `pip install frida frida-tools`.
2. **If frida is not available, the response includes the hook script.** Write the hook script to disk + use it with `frida -f <target> -l <hook-script>` manually. The hook script is generated per-Pattern:
   - **Pattern A**: hook the encryption-stub entry
   - **Pattern A-DW**: hook the encryption-stub + the POGO entry validator
   - **Pattern A-VMT**: hook the .xcode handler dispatch
   - **Pattern B**: hook the activation DLL's ordinal 100/101
3. **If frida is available, the tool actually attaches** (via `frida.spawn([target])` + `frida.attach(pid)` + `script.load()`) + captures the payloads + writes them to `output/decrypted/`.
4. **Verify the captured payloads.** Each captured payload is a per-method binary. The number of methods + the size of each are recorded in the response.

## What this skill does NOT do

- Does not bypass kernel-mode anti-debug (some Denuvo ATD layers detect Frida via kernel-mode integrity checks). For hardened targets, use `re-c-injection-build` + the in-process DLL/SO instead.
- Does not interact with EAC or BattlEye in a way that violates MRTEA Part V §5. Use `re-bypass-eac` / `re-bypass-be` for defensive-utility only.

## Known limitations

- The frida Python package must be installed in the host's venv. On Linux, `pip install frida` works for native Linux targets. For Windows targets, the host must have either (a) a Wine install of frida-server, or (b) a Windows VM with frida-server running.
- The per-Pattern hook scripts use placeholder RVAs (`0xDEADBEEF`). For real use, the operator must enumerate the actual encryption-stub RVA + the POGO validator RVA via the in-tree re-anti-debug-patch + re-vm-decrypt + re-frida-wine-runtime first, then substitute into the hook script.

## Test cases

- **LIR (Pattern B)**: hook `Core/Activation64.dll` ordinal 100 + 101, capture the entitlement-check stub. (Test requires the .dll to be loadable; under Wine or a real Windows process.)
- **P3R (Pattern A-DW)**: hook the encryption-stub + the POGO entry validator, capture each method's plaintext. (Test requires Windows host + executed SOW-X.)
- **CD (Pattern A-VMT)**: hook the .xcode handler dispatch, reconstruct the handler table. (Test requires Windows host.)

## See also

- [RE-BREAKER README](../../README.md)
- [re-frida-runtime server](../../servers/re-frida-runtime/)
- [Pattern A playbook](../../docs/PLAYBOOKS/encrypted-vm-bytecode-interpreter-pattern-a.md)
- [Pattern A-DW + Denuvo playbook](../../docs/PLAYBOOKS/pattern-a-dw-denuvo.md)
- [Pattern A-VMT (BlackSpace) playbook](../../docs/PLAYBOOKS/pattern-a-vmt-blackspace.md)
- [EA Origin stub-drop playbook](../../docs/PLAYBOOKS/ea-origin-stub-drop.md)
