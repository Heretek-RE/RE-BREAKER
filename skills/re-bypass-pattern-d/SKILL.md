---
name: re-bypass-pattern-d
version: 0.2.0
status: implemented
family: encrypted-vm-bytecode-interpreter
pattern: D
severity: medium
catalog_entry: encrypted-vm.bytecode-interpreter.pattern-d
playbook: docs/PLAYBOOKS/ea-entitlement-replay.md
---

# re-bypass-pattern-d

**v0.2.0 implemented.** Pattern D = publisher telemetry attack
surface. The publisher's analytics / crash-reporting / observability
stack (Sentry, Crashpad, librdkafka, Hermes SDK, GfSDK Aftermath,
Steam Telemetry, EOS telemetry, etc.) is an in-process attack
surface: a Frida hook on the telemetry sender can rewrite the
event body, strip user-identifying fields, or block the send
entirely. The bypass doesn't disable the protection; it
neutralizes the publisher's visibility into the operator's lab.

## When to use this skill

Invoke when the target ships one or more of:
- `sentry.dll` (Sentry crash reporting SDK)
- `crashpad_handler.exe` + `crashpad.dll` (Google Crashpad)
- `librdkafka.dll` (librdkafka message bus, used by Pearl Abyss)
- `hermessdkcorewrapper_*.dll` (Pearl Abyss Hermes SDK)
- `gfsdk_aftermath_lib.x64.dll` (NVIDIA Aftermath GPU crash dumps)
- `EOSSDK-Win64-Shipping.dll` (Epic Online Services — also covers entitlements)
- `steam_api64.dll` (Steamworks — covers both entitlement + telemetry)

## Tools invoked

- `mcp__re-catalog-match.match_catalog(target, intent="offender")` — confirm Pattern D is the right match.
- `mcp__re-runtime-dump.dump_target(target, mode="frida")` — attach Frida to the running target and install telemetry hooks.
- `mcp__re-anti-vm-spoof.spoof_target(target, mode="frida", cpuid_strategy="bare-metal-snapshot")` — concurrent spoof for kernel-active targets.

## Workflow

1. **Confirm Pattern D is the right match.** Run `re-catalog-match` and verify the match is `encrypted-vm.bytecode-interpreter.pattern-d` with high confidence. The defender-side fingerprint: the binary statically links / dynamically loads one or more telemetry SDKs and the launch traces show 1+ outbound network connections to the publisher's telemetry endpoints.
2. **List the telemetry SDKs** loaded by the target. Use `re-anti-analysis-scan` to enumerate the imports; the SDK .dlls are usually in the top-10 largest imports.
3. **Identify the telemetry sender API** for each SDK. Common patterns:
   - Sentry: `sentry_capture_event`, `sentry_capture_message`, `sentry_user_consent_given` (gate the consent).
   - Crashpad: `crashpad::CrashpadClient::DumpAndCrash` / `DumpWithoutCrash` / `SetHandlerIPCPipe` (gate the handler pipe).
   - librdkafka: `rd_kafka_produce` / `rd_kafka_producev` (rewrite the topic to a sinkhole).
   - Hermes SDK: `hermes_publish`, `hermes_publish_async` (block the publish).
   - NVIDIA Aftermath: `GFSDK_Aftermath_Enable` / `GFSDK_Aftermath_DumpShaderBinary` (gate the dump).
   - EOS: `EOS_Logging_SetLogLevel` (set to off) + `EOS_Reporting_SetCallback` (sinkhole the callback).
4. **Build the Frida hook script** that intercepts each sender API. For each hook, either (a) return 0/success-no-op, (b) rewrite the event body to strip PII, or (c) sinkhole the network send.
5. **Attach Frida** to a copy of the target (NEVER the live one). Inject the script. Confirm the target continues to run and that no telemetry is sent (verify with Wireshark on a tap of the network — see the test cases below).
6. **Write the per-target `bypass-result.md`** to `See the RE-AI output directory.` documenting: SDKs hooked, sender APIs blocked/rewritten, success probability, runtime cost, network verification.

## Known limitations

- The bypass does **not** prevent the publisher from receiving telemetry if the publisher has multiple telemetry paths (e.g. a backup crash-reporting path that doesn't go through the SDKs listed). Always verify with Wireshark that the target emits no outbound network traffic to publisher-controlled endpoints.
- The bypass is **lab-only** per MRTEA §4. Production deployment is prohibited without an executed SOW.
- Some telemetry SDKs (notably Sentry) have native anti-tamper: the SDK verifies its own integrity before sending. If detected, the SDK falls back to a "no-op" mode that silently drops events — which is the desired outcome but may not be obvious from the target's behavior.

## Test cases

- **Crimson Desert (CD)** — Pearl Abyss BlackSpace engine. Statically-linked OpenSSL + Hermes SDK + librdkafka. Pattern D: hook `hermes_publish` (block) + `rd_kafka_produce` (rewrite topic to sinkhole). Sentry (`sentry.dll`) also present. **In scope this cycle** as document-only (publisher not in MRTEA vendor list).
- **P3R** — UE5 + Steamworks + Sentry (per stress-test findings). Pattern D: hook Steam Telemetry + Sentry. **Document-only** (publisher not in MRTEA vendor list).
- **TWW3** — EOS overlay (`EOSSDK-Win64-Shipping.dll`). Pattern D: sinkhole `EOS_Logging_SetLogLevel` + `EOS_Reporting_SetCallback`. **In scope this cycle** (SOW-X covers the EOS portion).
- **HKIA** — Sentry only. Pattern D: hook `sentry_capture_event` to strip PII. **Document-only.**

## See also

- [RE-BREAKER README](../../README.md)
- [Threat model](../../THREAT-MODEL.md)
- [License + Offensive-Research-Use clause](../../LICENSE-OFFENSIVE.md)
- [Catalog entry this skill implements](../../data/catalog.json) — `encrypted-vm.bytecode-interpreter.pattern-d`
- [EA entitlement-replay playbook](../../docs/PLAYBOOKS/ea-entitlement-replay.md) — Pattern D is the long-tail companion to Pattern B
- [CA Warscape + EOS playbook](../../docs/PLAYBOOKS/ca-warscape-eos.md)
