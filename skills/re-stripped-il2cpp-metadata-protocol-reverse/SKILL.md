# re-hkia-protocol-reverse

**v0.7.0 NEW.** Closes G8 (HKIA stripped metadata). Novel research target.

## When to use this skill

Invoke when:
- The target is a Unity IL2CPP game that has stripped `global-metadata.dat`
- Vanilla IL2CPP tooling (Il2CppInspector, Il2CppDumper) fails to load the metadata
- The catalog match for the .dll returns matches but the entitlement layer is SCAFFOLD
- The publisher is Sunblink (HKIA), or any Unity IL2CPP game with custom Sunblink protection

## The finding

Per the 2026-06-09 stress test, `Input/Hello Kitty Island Adventure/Hello Kitty_Data/il2cpp_data/Metadata/global-metadata.dat` does **not exist**. Both FM26 and LIR ship the standard metadata file. HKIA does not. The IL2CPP triage reports `is_stripped_metadata: true` and `metadata.version: null`.

The Sunblink emulator (`servers/re-entitlement-bypass/.../sunblink_emulator.py`) is SCAFFOLD:
```python
"""Sunblink / EGS / XOG emulator — SCAFFOLD.
Per SOW-X (Sunblink): HKIA is the target. The server-reachability dialog is
the gate (per v0.4.1.9). The exact wire format was not captured (the dialog
blocks before the calls land).
Phase 1's RE work: reverse the Sunblink SDK from the HKIA binary.
"""
```

The wire format is not in the static HKIA binary — the entitlement dialog blocks before the calls land. We need runtime observation.

## Workflow

1. **Run IL2CPP triage to find Sunblink SDK methods.**
   ```
   mcp__re-il2cpp-triage.triage_il2cpp(launcher_path=".../Hello Kitty.exe")
   ```
   The triage should find the `SunblinkSDK` assembly (or similar) + a method list. The methods of interest:
   - `SunblinkAuth_Init` (or `XOGAuth_Init`, etc.)
   - `SunblinkEntitlement_Check`
   - `SunblinkTelemetry_Heartbeat`
   - The HTTP request dispatcher

2. **Use frida to hook these methods.**
   ```
   mcp__re-frida-runtime.frida_attach(target=".../Hello Kitty.exe", pattern="C", output=".../hkia-sunblink-hooks/")
   ```
   With custom hooks on the Sunblink methods. Capture the actual HTTP request bodies, TLS cert, request URL, response.

3. **Extract the wire format.** From the captured requests/responses:
   - HTTP method + URL
   - Request body schema (likely JSON or Protobuf)
   - Response body schema
   - TLS cert chain (extract from captured TLS session)
   - Any HMAC / JWT signing keys

4. **Update the Sunblink emulator.**
   ```
   # Edit servers/re-entitlement-bypass/.../sunblink_emulator.py
   # Replace the SCAFFOLD routes with the real endpoints
   # Replace the placeholder cert/key with the real ones
   ```

5. **Add tests.**
   ```
   # tests/test_sunblink_emulator.py — round-trip the captured requests
   ```

6. **Verify.**
   ```
   mcp__re-catalog-match.match_catalog(target=".../Hello Kitty.exe", triage_json_path=...)  # should now include sunblink entitlement
   mcp__re-entitlement-bypass.bypass_entitlement(target=".../Hello Kitty.exe", vendor="sunblink", mode=emulator)  # the vendor enum needs a fix first
   ```

## Tools invoked

- `mcp__re-il2cpp-triage.triage_il2cpp(launcher_path=...)` — locate the Sunblink SDK
- `mcp__re-frida-runtime.frida_attach(target=..., pattern="C", hooks=[...])` — runtime hook
- `mcp__re-traffic-capture.capture(target=..., wine_prefix=...)` — capture HTTP traffic as backup
- Manual: edit `servers/re-entitlement-bypass/.../sunblink_emulator.py` to fill in the real endpoints

## What this skill does NOT do

- Does not recover the stripped `global-metadata.dat` (separate problem — that's `re-hkia-metadata-decrypt`, v0.7.0 follow-up)
- Does not bypass the Sunblink server-reachability dialog (different problem — that's the dialog that blocks the wire format from being captured in the first place; would need a network-level MITM)
- Does not provide a one-click fix — this is real reverse engineering, multiple weeks of work

## Effort estimate

- 1-2 days: locate Sunblink methods via IL2CPP triage + frida hooks
- 3-5 days: capture the wire format (need to bypass the dialog blocker)
- 2-3 days: implement the emulator routes
- 1-2 days: test + verify

Total: 1-2 weeks.

## Why this matters

HKIA is a high-profile game on Apple Arcade + Steam + Sunblink's own platform. The custom metadata encryption is novel — Sunblink has applied protection beyond vanilla Unity. The wire format RE feeds back into the entitlement emulator, which is the first gate the live-fire engagement hit (per the 2026-06-08 live-fire ENGAGEMENT-SUMMARY).

A successful Sunblink protocol reverse unblocks:
- HKIA runtime attack
- Reusable pattern for any other Sunblink-protected game (e.g., Apple Arcade exclusives)
- Updates to the existing entitlement emulator infrastructure (the Atlus + Origin + IOI + PA + SEGA SSO emulators all use the same pattern)
