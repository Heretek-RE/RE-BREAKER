---
name: re-bypass-pattern-b
version: 0.2.0
status: implemented
family: encrypted-vm-bytecode-interpreter
pattern: B
severity: high
catalog_entry: encrypted-vm.bytecode-interpreter.pattern-b
playbook: docs/PLAYBOOKS/ea-origin-stub-drop.md
---

# re-bypass-pattern-b

**v0.2.0 implemented.** Pattern B = third-party activation library
(Origin, Steam, EOS overlay, EA DRM, BattlEye integration SDK, etc.).
The bypass recipe is a **stub-drop** on the entitlement-check ordinal
in the activation DLL. The DLL is a small native C++ binary that
exposes a small number of ordinals (typically 100-105) where ordinal
100 is the entitlement check.

## When to use this skill

Invoke when `re-catalog-match` returns `encrypted-vm.bytecode-interpreter.pattern-b`
for the target. Typical fingerprints:

- The target has a `Core/Activation*.dll` (EA / Origin convention) or
  a `libled.dll` (CA "Light Encryption Driver" convention) or a
  `steam_api*.dll` that's the entitlement-token consumer (not the
  Steamworks SDK).
- The activation DLL has a small number of exported ordinals.
- The launcher's `.ooa` (or equivalent) section contains the
  entitlement token blob (typically entropy 3.0-3.5, 1-4 KB).
- `Activation*.dll.bak` exists alongside the live DLL (analyst
  has previously instrumented it).

## Tools invoked

- `mcp__re-catalog-match.match_catalog(target, intent="offender")` — confirm Pattern B is the right match.
- `mcp__re-runtime-dump.dump_target(target, mode="inject")` — inject the C/C++ DLL into the target process and hook the activation DLL's ordinal 100/101.
- `mcp__re-encrypted-vm-bypass.bypass_pattern(target, pattern="B")` — orchestrate the stub-drop end-to-end.

## Workflow

1. **Confirm Pattern B is the right match.** Run `re-catalog-match` and verify the match is `encrypted-vm.bytecode-interpreter.pattern-b` with high confidence.
2. **Fingerprint the activator.** LIEF-load the activation DLL, enumerate its exports. Look for the entitlement-check ordinal (typically ordinal 100 = `Activate`, 101 = `ActivateEx`).
3. **Acquire the license-acknowledgement cache.** The CLI's `--license-acknowledge` flag must be set on every invocation. The cache lives at `~/.re-breaker/acknowledged-targets/<sha256>.ack` and is keyed by SHA-256 + timestamp + `os.getlogin()`.
4. **Build the C/C++ injection library** if not already built. The library is in `inject/src/` and builds with `bash inject/build.sh`. Outputs to `inject/build/re_breaker_inject.{dll,so}`.
5. **Inject the DLL** into a copy of the target (NEVER the live one) via `CreateRemoteThread` (Windows) or `LD_PRELOAD` (Linux). The DLL installs an inline-trampoline hook on the activation DLL's ordinal 100/101.
6. **Verify the stub-drop** by reading the patched activation DLL's exports and confirming ordinal 100/101 now NOPs to a constant-success return.
7. **Write the per-target `bypass-result.md`** to `See the RE-AI output directory.` documenting: activator DLL SHA-256, ordinals stub-dropped, success probability, runtime cost.

## Known limitations

- The bypass does **not** produce a valid entitlement token. It only short-circuits the entitlement check; the launcher's downstream code path will still need to handle the "no real token" case (typically: skip the multiplayer/online check and continue in offline mode).
- The bypass is **per-build**: a publisher-pushed update that recompiles the activation DLL will require a re-run. Expected lifetime: until the next game patch.
- The bypass does **not** defeat hardware-binding. If the entitlement check reads TPM-bound keys, the stub-drop is detected on the next launch. Workaround: stub-drop the hardware-binding check too, but this requires identifying the specific TPM-call ordinals (typically a follow-on Pattern B engagement).
- The bypass is **lab-only** per MRTEA §4. Lab-only default. Production deployment is prohibited without an executed SOW.

## Test cases

- **LIR (Lost In Random)** — EA / Origin activation gate. Activation64.dll ordinal 100/101 stub-drop. Per the honest-read, the `.ooa` section entropy 3.02 / 2048B is the entitlement token. `Activation64.dll.bak` exists. **In scope this cycle.**
- **TWW3 (Total War Warhammer III)** — CA Warscape + EOS overlay. `libled.dll` runtime-decryption loader; `clockwork_*.dll` mod framework; `bypass_time.txt` opt-in flag. **In scope this cycle** (SOW-X covers the EOS portion).
- **P3R (Persona 3 Reload)** — UE5 + Steamworks. The Steamworks SDK is integrated; entitlement check is via Steam's CEG (Custom Executable Generation). Out-of-scope this cycle (per-vendor Steamworks bypass requires SOW-X).

## See also

- [RE-BREAKER README](../../README.md)
- [Threat model](../../THREAT-MODEL.md)
- [License + Offensive-Research-Use clause](../../LICENSE-OFFENSIVE.md)
- [Catalog entry this skill implements](../../data/catalog.json) — `encrypted-vm.bytecode-interpreter.pattern-b`
- [EA Origin stub-drop playbook](../../docs/PLAYBOOKS/ea-origin-stub-drop.md)
- [EA entitlement-replay playbook](../../docs/PLAYBOOKS/ea-entitlement-replay.md) — for the long-tail entitlement server replay
