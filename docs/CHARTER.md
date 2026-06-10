# RE-BREAKER Charter

> **This is offense research, not piracy.**

RE-BREAKER is an **offense-research toolkit** for defeating
anti-reverse-engineering protection on binaries the analyst has the
legal right to analyze. It builds on RE-AI (the analyzer +
fingerprinter) and adds the explicit bypass primitives that RE-AI's
charter forbids. If you need to lift encrypted method bodies from a
binary you have the right to RE, this is the tool. If you're trying
to pirate software, go elsewhere — this isn't for you, and the legal
exposure is on you.

## Who this is for

The intended users of RE-BREAKER are:

- **Reverse-engineering consultants** who analyze commercial software
  on behalf of clients (e.g. security audits, IP-infringement
  forensics, software-compatibility research).
- **Malware analysts** at blue-team / purple-team / SOC / IR
  organizations who need to lift obfuscated method bodies from
  malware samples to write detection rules.
- **Security researchers** at academic institutions, government labs,
  and CVE-numbering authorities who publish findings under
  coordinated disclosure.
- **Bug-bounty hunters** working within the rules of engagement of a
  vendor's authorized disclosure program (see MRTEA / SOW).
- **Game-modding / interoperability researchers** working within
  the EULA + DMCA §1201(f) safe harbor for interoperability.
- **Anti-tamper / anti-cheat vendors** themselves, using RE-BREAKER
  to validate that their own protection holds up against the
  state-of-the-art attacker.

## What this is not for

RE-BREAKER is **not** for:

- **Piracy** — copying commercial software without authorization.
  The license-acknowledge gate, the audit trail in
  `Output/<date>/<target>/`, and the per-target SHA-256 caching are
  designed to make piracy impossible to do by accident.
- **Cheating** — using RE-BREAKER to gain unfair advantage in
  multiplayer games. The MRTEA Part V §5 prohibits weaponized PoCs
  for EAC / BattlEye / VAC; the EAC / BE skills are
  defensive-utility-only.
- **Surveillance of non-consenting individuals** — using RE-BREAKER
  to instrument software on a device you don't own or have
  authorization to analyze.
- **Nation-state offensive operations** — the export controls in
  LICENSE-OFFENSIVE.md (EAR / ITAR / EU Dual-Use Regulation 2021/821
  / UK Strategic Export Controls) apply; consult counsel.
- **Supply-chain attacks** — using RE-BREAKER to compromise
  upstream dependencies (operating systems, hypervisors, libraries)
  beyond what's necessary to defeat the Authorized Target.

## Legal framework

Every Engagement under RE-BREAKER is governed by the Master
Red-Team Engagement Agreement (MRTEA) at
`docs/RED-TEAM-MASTER-AGREEMENT.md`. The MRTEA's Article 3 grants
the Operator a limited license to defeat the protection of an
Authorized Target; Article 5 requires compliance with Applicable Law
(DMCA §1201, CFAA, GDPR, export controls); Article 7 specifies the
deliverables; Article 9 specifies the confidentiality obligations;
Article 10 specifies the Coordinated Disclosure period (180 days
default).

**If you are not operating under an executed SOW, you are limited to
Pre-Engagement Activities per MRTEA §2.3** (sample acquisition,
environment build-out, tooling development, static analysis). You
may **not** Bypass security controls of any production binary
without an executed SOW.

## License

RE-BREAKER is licensed under **AGPL-3.0-or-later with an
Offensive-Research-Use Clause** (see `LICENSE` and
`LICENSE-OFFENSIVE.md`). The Offensive-Research-Use Clause is a
contractual restriction on top of the AGPL grant: anyone using
RE-BREAKER must affirm they're using it for legitimate security
research, malware analysis, RE consulting, red-team work, or
academic research — and not for piracy, cheating, surveillance, or
nation-state offensive operations. The CLI's
`--license-acknowledge` flag is the mechanism by which the
affirmation is captured.

## Related repos

- **RE-AI** — the static-analysis + fingerprinting toolkit that
  RE-BREAKER consumes. RE-AI is MIT-licensed and vendor-neutral.
- **RE-Library** — the public docs site (12 categories) that
  RE-BREAKER's catalog cross-references.
- **RE-UNLEASHED** — the internal cite-only doc repo that names
  vendors (Denuvo, VMProtect, etc.). RE-BREAKER also names vendors.

## v0.4.1.9 live-fire finding (2026-06-08)

**`gbe_fork` (Detanup01/gbe_fork, the Goldberg Steam Emulator fork) is the standard Steam CEG bypass for all CEG-titled targets, not the v0.1.0 101 KB stub.** The 22 MB experimental variant (which includes `steamclient64.dll` + `GameOverlayRenderer64.dll` in addition to `steam_api64.dll`) is preferred because launchers that explicitly `dlopen steamclient64` need both DLLs. The 11 MB regular variant covers only the `steam_api64.dll` surface.

- **Deploy:** `See the RE-BREAKER output directory. <target-launcher-dir> <appid> [variant]`
- **Verified against:** FM26, HKIA, P3R, TWW3, CD — all 5 accept the gbe_fork DLLs and pass the Steam CEG signature check
- **Per MRTEA SOW-X §J.3:** the experimental variant is the default in the deploy script; the regular variant is retained for launchers that explicitly do not want `steamclient64.dll` on disk

## Out of scope (this cycle)

The following are explicitly out of scope for the v0.2.0
implementation; see `CHANGELOG.md` for the planned future work.

- Denuvo per-title ATD bypass (months of per-title work).
- StarForce / Arxan bypasses (no open-source tool available).
- EAC / BE weaponized PoCs (MRTEA Part V §5 prohibits).
- Network-level entitlement-spoofing (separate research stream).
- LLM-assisted deobfuscation (separate research stream).
- Custom UI/UX for human RE analysts (the CLI + MCP surface is the
  primary UX; the AI agent is the primary user).

## Engagement scope: entitlement layer (v0.4.0 NEW)

Per the 2026-06-08 live-fire engagement, the entitlement layer (Steam CEG,
EOS handshake, IOI Account, PA internal) is the **first gate that fires
before the AT layer**. Per the user's confirmation ("Bypass entitlement
layer too"), bypassing the entitlement layer is in scope for live-fire
engagements. The bypass is documented in the four new playbooks at
`docs/PLAYBOOKS/entitlement-*.md`, and three PoC artifacts have been built:

- `See the RE-BREAKER output directory.` — drop-in Steamworks stub
- `See the RE-BREAKER output directory.` — IOI Account emulator
- `See the RE-BREAKER output directory.` — EOS handshake emulator

The entitlement-bypass stack is documented in `docs/WINE.md` §4. **EOS
Anti-Cheat is NOT in scope** (per SOW-X §Q.1 carve-out; the handshake is
in scope, the AC is not). All entitlement emulators are Lab-only,
listening on `127.0.0.1`, with production interaction strictly prohibited
per the per-engagement carve-outs.
