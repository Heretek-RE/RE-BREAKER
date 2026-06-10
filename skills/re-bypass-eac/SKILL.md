---
name: re-bypass-eac
version: 0.2.0
status: implemented
family: anti-cheat
severity: high
catalog_entry: anti-tamper-vendors.eac
playbook: docs/PLAYBOOKS/pattern-d.md
pattern_yaml: data/patterns/pattern-d.yml
---

# re-bypass-eac

**v0.2.0 implemented.** Easy Anti-Cheat (EAC) is an anti-cheat
(AC) product, not an anti-tamper (AT) product. Per MRTEA Part V
§5, NO weaponized PoC Exploits are produced. This skill is
**defensive-utility only**: it returns the catalog entry + the
defensive recommendation, never a weaponized PoC.

## When to use this skill

The target ships one of:
- The EAC kernel driver (EasyAntiCheat.sys or analogous)
- The EAC user-mode service (EasyAntiCheat_x64.dll or analogous)
- The EAC integration SDK (in a target's binary imports)
- EOS Anti-Cheat (Epic's product, which is EAC-based)

For each, the skill returns a defensive-utility recommendation:
- Detection rule (YARA, Sigma, Snort, Suricata, behavioral heuristic)
- Hardening guide (e.g. enable PatchGuard, Credential Guard, HVCI)
- Architectural recommendation (e.g. move entitlement check into the
  kernel driver instead of the user-mode service)

## Tools invoked

- `mcp__re-catalog-match.match_catalog(target, intent="defender")` — confirm the EAC match.
- `mcp__re-vendor-anti-tamper.run_vendor_tool(vendor="eac", target)` — return the catalog entry + the defensive-utility guidance.
- `mcp__re-catalog-match.match_catalog(target, intent="offender")` is **prohibited** per MRTEA Part V §5.



## v0.3.0 pre-step: Resolve the main binary

**Add this step to the existing workflow before Step 1.**

0. **Resolve the main binary.** If the target is a Unity IL2CPP launcher
   (a small ~660KB .exe with a companion `GameAssembly.dll` in the same
   dir), call `mcp__re-il2cpp-triage.triage_il2cpp(launcher_path=target)` to
   redirect the analysis to `GameAssembly.dll` (which contains the
   encrypted-VM bytecode interpreter). If the target has no prior triage,
   call `mcp__re-triage.triage_target(target)` to compute the triage
   on-the-fly. **Then pass `main_binary` to the catalog match**:
   `mcp__re-catalog-match.match_catalog(target=target, main_binary="<resolved-main>")`.

This pre-step is required for FM26 / HKIA / LIR (Unity IL2CPP launchers).
For non-IL2CPP targets (P3R / 007FL / CD / TWW3) it can be skipped.

## Workflow

1. **Confirm the EAC match.** Run `mcp__re-catalog-match.match_catalog(target, intent="defender")` and verify the match is `anti-tamper-vendors.eac`.
2. **Build the defensive recommendation.** Run `mcp__re-vendor-anti-tamper.run_vendor_tool(vendor="eac", target)`. The response includes the catalog entry + the defensive recommendations from the recipe.
3. **Cross-reference with RE-Library** for the public-facing docs on EAC (EAC is named in `RE-Library/drm/` as a DRM-system denylist entry).
4. **Document the result** as a defensive-utility Finding (per MRTEA Article 7) — NOT a bypass PoC.

## What this skill does NOT do

- Per MRTEA SOW-X §F.4: no PoC Exploit that demonstrates a Bypass of EAC against a specific game or specific player.
- Per MRTEA Part V §5.2: no distribution to cheat developers, cheat forums, or game-hacking communities.
- Per MRTEA SOW-X §F.5: no weaponized PoC. PoC Exploits are abstract (defeating a class of detection) and do not name a specific game beyond what's necessary.

## Known limitations

- EAC's anti-cheat protocols (EAC communication with EAC servers) are in scope for protocol analysis but not for traffic injection or impersonation against production servers (SOW-X §F.2).
- EAC kernel-mode vulnerabilities (e.g. local privilege escalation in the EAC driver) are subject to a default 180-day Coordinated Disclosure Period, with a Vendor-elected right to extend to 12 months for driver-level fixes that require OS-vendor coordination (SOW-X §F.6).

## Test cases

- **P3R** — UE5 game with EAC integration. The EAC user-mode service is loaded; the kernel driver is loaded by the EAC launcher. **In scope for defensive-utility only** (SOW-X covers the EAC product line; Atlus is not in the MRTEA vendor list, so the game-specific findings are document-only).
- **007 First Light** — IOI / EAC integration. EAC driver + user-mode service. **Document-only** (IOI not in MRTEA vendor list).
- **Crimson Desert** — BlackSpace engine with Pearl Abyss's internal anti-cheat. NOT EAC. The `re-bypass-eac` skill is NOT the right skill here.

## See also

- [RE-BREAKER README](../../README.md)
- [Threat model](../../THREAT-MODEL.md)
- [License + Offensive-Research-Use clause](../../LICENSE-OFFENSIVE.md)
- [RE-BREAKER CHARTER](../../docs/CHARTER.md) — "What this is not for: Cheating"
- [Engagement scope] — full SOW
- [MRTEA Part V §5 — Standards for PoC Exploits Involving Anti-Cheat](../../docs/RED-TEAM-MASTER-AGREEMENT.md)
- [Pattern D playbook](../../docs/PLAYBOOKS/pattern-d.md) — publisher telemetry attack surface (related)
