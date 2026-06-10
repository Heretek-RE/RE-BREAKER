---
name: re-bypass-be
version: 0.2.0
status: implemented
family: anti-cheat
severity: high
catalog_entry: anti-tamper-vendors.battleye
playbook: docs/PLAYBOOKS/pattern-d.md
pattern_yaml: data/patterns/pattern-d.yml
---

# re-bypass-be

**v0.2.0 implemented.** BattlEye (BE) is an anti-cheat (AC)
product. Per MRTEA Part V §5, NO weaponized PoC Exploits are
produced. This skill is **defensive-utility only** — same as
`re-bypass-eac` but for BattlEye's product line.

## When to use this skill

The target ships one of:
- `BEClient_x64.dll` + `BEService_x64.exe` (BattlEye user-mode)
- `BEDaisy.sys` or analogous kernel driver
- The BattlEye integration in the target's anti-cheat launcher

For each, the skill returns a defensive-utility recommendation (same
as EAC: detection rule, hardening guide, architectural recommendation).

## Tools invoked

- `mcp__re-catalog-match.match_catalog(target, intent="defender")` — confirm the BE match.
- `mcp__re-vendor-anti-tamper.run_vendor_tool(vendor="be", target)` — return the catalog entry + the defensive-utility guidance.



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

1. **Confirm the BE match.** Run `mcp__re-catalog-match.match_catalog(target, intent="defender")` and verify the match is `anti-tamper-vendors.battleye` (or related).
2. **Build the defensive recommendation.** Run `mcp__re-vendor-anti-tamper.run_vendor_tool(vendor="be", target)`. The response includes the catalog entry + the defensive recommendations.
3. **Cross-reference with RE-Library** for the public-facing docs on BattlEye.
4. **Document the result** as a defensive-utility Finding (per MRTEA Article 7) — NOT a bypass PoC.

## What this skill does NOT do

- Per MRTEA SOW-X §G.4: no PoC Exploit that demonstrates a Bypass of BattlEye against any specific game using BattlEye.
- Per MRTEA Part V §5.2: no distribution to cheat developers.
- Per MRTEA SOW-X §G.5: BattlEye may, on request, provide a test account and a protected binary for testing purposes, under a separate test license.

## Known limitations

- BattlEye's kernel driver shall be loaded only in isolated Lab VMs (SOW-X §G.1).
- BattlEye's communication protocol (between client and BattlEye server) is in scope for protocol analysis but not for interaction with production BattlEye servers (SOW-X §G.2).
- Findings that affect BattlEye's ability to detect cheats across multiple titles are subject to a default 180-day Coordinated Disclosure Period (SOW-X §G.3).

## Test cases

- **DayZ, Arma, PUBG, Fortnite (EAC), Rainbow Six Siege (when BattlEye is used)** — these titles use BattlEye. Each is covered by the per-Vendor SOW-X framework.
- For 007 First Light (IOI) and P3R (Atlus) and TWW3 (CA), the BE integration is via the publisher's launcher, not the game binary itself. Document-only unless an executed SOW-X is in place.

## See also

- [RE-BREAKER README](../../README.md)
- [Threat model](../../THREAT-MODEL.md)
- [License + Offensive-Research-Use clause](../../LICENSE-OFFENSIVE.md)
- [RE-BREAKER CHARTER](../../docs/CHARTER.md) — "What this is not for: Cheating"
- [Engagement scope] — full SOW
- [MRTEA Part V §5 — Standards for PoC Exploits Involving Anti-Cheat](../../docs/RED-TEAM-MASTER-AGREEMENT.md)
- [Pattern D playbook](../../docs/PLAYBOOKS/pattern-d.md) — publisher telemetry attack surface (related)
