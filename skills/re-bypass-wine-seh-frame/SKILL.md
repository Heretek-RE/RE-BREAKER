# re-bypass-wine-seh-frame

**v0.4.2.0 documented** (per `docs/PLAYBOOKS/cross-target-entitlement-bypass.md` §3). Closes the TWW3 Wine `EXCEPTION_INVALID_FRAME` SEH.

## When to use this skill

Invoke when:
- A target crashes with `EXCEPTION_INVALID_FRAME` (0xC0000028)
- The crash is under Wine's `kernelbase!RtlUnwindEx`
- The target has ≥ 10 VMCALL sites (TWW3 has 18, which is the trigger)
- Affects: **Total War: Warhammer III** (CA / Microsoft, Warscape engine)

## The failure mode

Under Wine, the SEH (Structured Exception Handling) unwind for VMCALL-heavy binaries fails. The exception's target frame is in a region that Wine's `RtlUnwindEx` doesn't know how to walk. The result: `EXCEPTION_INVALID_FRAME`, and the process terminates.

Real Windows handles this correctly because the OS has a full SEH chain walker. Wine's implementation is partial.

## Workaround stack (in order of preference)

1. **Pre-empt the SEH in the entitlement emulator** — if the entitlement check happens BEFORE the VMCALL-heavy code path, the entitlement emulator can return early, before the SEH unwind fails.
2. **Patch Wine's `dlls/kernelbase/exception.c` `RtlUnwindEx`** — add a handler for the VMCALL-stack-frame case. Out of v0.7.0 scope.
3. **Patch the target to not use SEH for the VMCALL stack frame** — would need per-build RE. Out of v0.7.0 scope.
4. **Use a real Windows host** — bypasses the Wine SEH issue entirely.

## Tools invoked

- `mcp__re-winedbg.start_winedbg_gdbserver(target)` — attach gdb
- `mcp__re-winedbg.gef_vmmap(session)` — find the VMCALL-site stack frames
- `mcp__re-vendor-anti-tamper.run_vendor_tool(vendor="wine-patch", ...)` — would need a new vendor entry for "wine-patch"

## Workflow

1. **Reproduce the SEGV.** Launch the target under Wine, observe the `EXCEPTION_INVALID_FRAME` from `kernelbase!RtlUnwindEx`.
2. **Try the entitlement pre-emption.** Verify the entitlement check is the FIRST thing that runs. If it is, the entitlement emulator can return SUCCESS before the VMCALL chain unwinds.
3. **Try the EOS handshake emulator.** `mcp__re-entitlement-bypass.bypass_entitlement(target="tww3", vendor="eos", mode="emulator")` — the TWW3 entitlement layer uses EOS. The emulator at `servers/re-entitlement-bypass/.../eos_emulator.py` is real.
4. **Document the gap.** Wine source patch is out of v0.7.0 scope. The v0.7.0 stopgap is to use a real Windows host for TWW3.

## What this skill does NOT do

- Does not patch Wine's source (would need a fork)
- Does not bypass the entitlement layer (separate step)
- Does not work without the EOS emulator (TWW3-specific)

## Effort estimate

- v0.7.0: EOS emulator deployment is ~1 day
- v0.8.0: Wine source patch is ~1 week
