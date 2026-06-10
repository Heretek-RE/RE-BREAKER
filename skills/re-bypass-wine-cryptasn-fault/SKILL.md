# re-bypass-wine-cryptasn-fault

**v0.4.2.0 documented** (per `docs/PLAYBOOKS/cross-target-entitlement-bypass.md` §2). Closes the 007FL / CD Wine `cryptasn:CryptDecodeObjectEx` page fault.

## When to use this skill

Invoke when:
- A target crashes in `cryptasn:CryptDecodeObjectEx` with a SEGV
- The crash happens during `WinVerifyTrust` → `SoftpubCleanup` → `wintrust+0x1a001` → `cryptasn+CryptDecodeObjectEx`
- The OID is `1.3.6.1.4.1.311.2.1.4` (spcSpAgencyInfo — Software Publishing Certificate's "agency information")
- Affects: **007 First Light** (Glacier 2 / IOI), **Crimson Desert** (BlackSpace / Pearl Abyss)

## The failure mode

```
Unhandled exception: page fault on read access to 0x00000000 in 32-bit code (0x7e8a5abc).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:7e8a5abc ESP:0064cbf0 EBP:0064cc18 EFLAGS:00010202(  R- --  I  - - - )
Backtrace:
=>0 0x7e8a5abc cryptasn+CryptDecodeObjectEx
  0x7e8a5f12 cryptasn+CryptDecodeObjectEx+0x76
  0x7e85a001 wintrust+0x1a001
  0x7e85b202 wintrust+SoftpubCleanup
  0x7e85a4c0 wintrust+0x1a4c0
  0x7e857000 wintrust+WinVerifyTrust
```

Wine's `dlls/cryptasn/cert.c` does not implement the SPC structure decoder. When the target calls `CryptDecodeObjectEx` with `X509_ASN_ENCODING` + `1.3.6.1.4.1.311.2.1.4`, the function jumps to a NULL function pointer.

## Workaround stack (in order of preference)

1. **Vendor-signed Authenticode certificate chain emulation** — `re-entitlement-bypass` can emulate the cert chain. The target's `WinVerifyTrust` returns SUCCESS without needing the actual cryptasn decoder.
2. **Patch Wine's `dlls/cryptasn/cert.c`** — add the `spcSpAgencyInfo` decoder. The structure is:
   ```c
   typedef struct _SPC_SPK_ESS {
       LPWSTR pwszProviderName;
       LPWSTR pwszProviderInfo;
   } SPC_SPK_ESS;
   ```
   The decoder needs to handle the `X509_ASN_ENCODING | PKCS_7_ASN_ENCODING` input. This is a Wine source fork, out of v0.7.0 scope.
3. **Patch the target to skip Authenticode verification** — the target calls `WinVerifyTrust` early in the boot. If we can hook it (via the inject library's `re_breaker_install_hook("wintrust.dll", "WinVerifyTrust", ...)`), the target can skip verification. But `WinVerifyTrust` is called before our DllMain runs in some cases (loader-time Authenticode check).

## Tools invoked

- `mcp__re-winedbg.start_winedbg_gdbserver(target)` — attach gdb to the Wine-hosted target
- `mcp__re-winedbg.gef_vmmap(session)` — find the cryptasn.dll base address
- `mcp__re-winedbg.gef_xinfo(session, address)` — inspect the function at the crash site
- `mcp__re-injection-runtime.inject(target, hook_specs=[...])` — inject the auth chain emulator
- (out of scope) `mcp__re-vendor-anti-tamper.run_vendor_tool(vendor="wine-patch", ...)` — would need a new vendor entry for "wine-patch"

## Workflow

1. **Reproduce the crash.** Launch the target under Wine, observe the SEGV in `cryptasn:CryptDecodeObjectEx` for OID `1.3.6.1.4.1.311.2.1.4`.
2. **Try the cert chain emulation.** Deploy a fake Authenticode cert chain that `WinVerifyTrust` will accept. The chain is installed via the Wine registry + the `~/.wine/certs/` directory.
3. **Try the inject library hook.** Add `re_breaker_install_hook("wintrust.dll", "WinVerifyTrust", my_replacement)` where `my_replacement` returns `ERROR_SUCCESS` (0). This is the cleanest workaround for v0.7.0.
4. **Document the gap.** The Wine source patch is out of v0.7.0 scope. Add a note to the per-engagement status doc that runtime on this target is blocked by the Wine fork.

## What this skill does NOT do

- Does not patch Wine's source (would need a fork + maintain against upstream)
- Does not work for the 32-bit variant of the same SEGV (different OID, different `spcSpAgencyInfo` structure size)
- Does not bypass the Denuvo ATD layer (the cert chain check is before Denuvo runs)

## Effort estimate

- v0.7.0: inject library hook is ~1 day
- v0.8.0: Wine source patch is ~1 week (depends on Wine version compat)

## Why this matters

007FL and CD are both blocked by this. Until the Wine `cryptasn` is patched (or the inject library is used to skip `WinVerifyTrust`), the runtime attack on these targets cannot proceed past the Authenticode check. The inject library approach is the v0.7.0 stopgap.
