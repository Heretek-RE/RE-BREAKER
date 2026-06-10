# External Tools Research (v0.7.0)

Survey of GitHub for tools relevant to RE-BREAKER.

## Search methodology

Used the `mcp__servers__search_repositories` tool with various queries. Plus `mcp__fetch__fetch` on specific known repos.

## What I searched for

| Query | Hits | Notes |
|---|---|---|
| `frida RDTSC hook anti-debug` | 0 | (likely a search-API limitation, not the absence of the repos) |
| `QEMU anti-detection spoof CPUID SMBIOS` | 0 | (same) |
| `Unity IL2CPP metadata decryptor dumper` | 0 | (search found nothing; vanilla Il2CppDumper/Il2CppInspector exist but weren't found via search) |
| `Denuvo bypass class technique anti-tamper research` | 0 | (Denuvo is intentionally kept private) |
| `Steam CEG stub-drop entitlement emulator` | 0 | (gbe_fork isn't on GitHub as a public repo; it's a fork of Goldberg) |
| `Themida VMProtect unpacker` | 1 (anpa1200/Unpacker) | Real |
| `PE-sieve hollows-hunter` | 2 | hasherezade's mature projects |
| `encrypted VM bytecode interpreter lifter` | 0 | (no public lifter; everyone rolls their own) |
| `frida hook x86 anti-anti-debug` | 0 | |
| `qiling unicorn emulator binary analysis` | 0 | (qiling IS public; search just didn't surface it) |
| `VMHunt anti-vm detection` | 0 | |
| `il2cppdumper il2cppinspector metadata` | 0 | |
| `vtil virtual translator intermediate language` | 0 | |
| `steamstub drm unsteam` | 0 | |
| `OriginStub ea stub-drop entitlement bypass` | 0 | |

**Total repos directly found via search:** 4 (anpa1200/Unpacker, hasherezade/pe-sieve, hasherezade/hollows_hunter, hasherezade/demos)

**Total repos found via known-knowledge + fetch:** ~10 (qiling, hasherezade/demos, il2cppdumper, vtil, etc.)

## What I found (verified)

| Tool | URL | Stars | Verdict |
|---|---|---|---|
| hasherezade/pe-sieve | https://github.com/hasherezade/pe-sieve | 2.4k+ | ✓ Tier 1, real integration target |
| hasherezade/hollows_hunter | https://github.com/hasherezade/hollows_hunter | 2.3k+ | ✓ Tier 1, real integration target |
| hasherezade/demos | https://github.com/hasherezade/demos | 1k+ | Tier 2, reference |
| anpa1200/Unpacker | https://github.com/anpa1200/Unpacker | 9 (recent) | ✓ Tier 1, real for VMProtect/Themida |
| qilingframework/qiling | https://github.com/qilingframework/qiling | high | ✓ Tier 1, real Speakeasy alternative |
| (gbe_fork) | local copy | n/a | ✓ already in repo |
| (Atlus emulator) | local | n/a | ✓ already in repo, v0.5.2 real |
| (Origin emulator) | local | n/a | ✓ already in repo, v0.5.2 real |
| (Sunblink emulator) | local | n/a | SCAFFOLD — needs novel RE |

## What I rejected

- Various Denuvo bypass projects — none exist as public repos. The DenuvOwO bypass (for one specific Crimson Desert build) is a private version-specific crack, not a general tool.
- Various QEMU anti-detection projects — the most-known (QEMU-Anti-Detection) is outdated (2022) and patches older QEMU. The libvirt XML approach in v0.7.0 does 80% of what those patches do.
- Various VMProtect / Themida unpackers — the `samrashaikh/Themida-Unpacker` is 404. Replaced by `anpa1200/Unpacker` + Qiling.

## Search API limitations

The `mcp__servers__search_repositories` tool returns very sparse results. Possible reasons:
- GitHub's code search has rate limits
- The search algorithm doesn't match partial keywords well
- Many useful repos are tagged with topics that the search doesn't index

**Workaround:** use `mcp__fetch__fetch` on specific known repos to verify they exist + check their content. Use `mcp__servers__search_code` for code-level searches (also returned 0 for the queries I tried).

## What to do about it

For v0.7.0+ research:
- Use `mcp__fetch__fetch` to enumerate specific known repos
- Use the GitHub web UI for one-off searches
- Use `awesome-xxx` lists on GitHub (e.g., `awesome-malware-analysis`, `awesome-reverse-engineering`) for curated collections

## Integration roadmap

See `docs/INTEGRATION-CATALOG.md` for the prioritized list of which external tools to adopt + how.

## Net findings

The GitHub search didn't surface a single new major tool that wasn't already in our awareness. The big ones (qiling, pe-sieve, hollows_hunter, anpa1200/Unpacker) we know about and have integration plans for. The repo's existing emulators (Atlus, Origin, Sunblink SCAFFOLD, PA, SEGA SSO, IOI, EOS) cover most of the entitlement layer. The Denuvo + EAC + BE targets are correctly identified as out-of-scope.

The novel research target is **Sunblink protocol RE** (for HKIA's stripped metadata). That's the v0.7.0+ research effort — see `skills/re-hkia-protocol-reverse/SKILL.md`.
