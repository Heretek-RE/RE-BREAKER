# RE-BREAKER Threat Model

This document enumerates the threat model for RE-BREAKER. It answers the question: **who is this tool for, and what attacks does it defend against vs enable?**

## Intended users (defender side)

| User | Use case | Justification |
|---|---|---|
| Reverse-engineering consultant with signed engagement | Analyzes the client's binary to find vulnerabilities, extract embedded secrets, document third-party code, or assess the binary's protection surface. | Signed engagement letter is the "legal right to analyze" the binary. |
| Malware analyst at EDR / antivirus company | Analyzes malware samples to extract IOCs, write detection signatures, understand the malware's TTPs, develop removal tools. | Sample is collected by the organization from the wild. The analyst is operating in their role as defender. |
| Blue-team / purple-team staff | Analyzes binaries the organization already has on its endpoints (corporate software, suspicious files, sanctioned tools) to verify the binaries are what they claim to be and to assess their security posture. | The organization owns the binary or has license to use it. |
| Security researcher (academic / public) | Analyzes published software (closed-source + open-source) to find and report vulnerabilities, write detection rules, publish reverse-engineering techniques, or develop defensive tooling. | Academic-fair-use / security-research carve-outs in most jurisdictions' copyright law. |
| Authorized penetration tester | During a red-team engagement, analyzes the target's custom software to find vulnerabilities that the engagement scope allows. | Authorized by the engagement scope + the rules-of-engagement document. |
| CTF / wargame participant | Analyzes the challenge binary to solve the challenge. | The CTF / wargame organizers have granted consent. |
| Bug-bounty hunter | Analyzes the target's software to find in-scope vulnerabilities for submission under the bug-bounty program. | Authorized by the bug-bounty program's scope document. |
| Rights holder analyzing own software | Analyzes the software they wrote / own to find vulnerabilities, extract functionality, or document. | The rights holder has full authority over their own work. |

## Out-of-scope users (attacker side; explicitly forbidden by LICENSE)

| User | Use case | Why forbidden |
|---|---|---|
| Person trying to pirate commercial software | Bypassing the license check / DRM to use the software without payment. | Unauthorized reproduction + DMCA §1201 anti-circumvention. |
| Person redistributing cracked software | Distributing the bypassed binary or bypass techniques. | Contributory copyright infringement. |
| Person trying to access a system they don't own | Using the bypass primitives to gain unauthorized access. | CFAA / UK CMA / equivalent. |
| Unscrupulous consultant | Bypassing the rights holder's entitlement to redistribute to a non-paying client. | Same as piracy. |
| Nation-state offensive operator | Using the bypass primitives as part of a state-sponsored attack. | The LICENSE-OFFENSIVE.md §5 explicitly prohibits weapons use. |
| Surveillance operator | Using the bypass primitives to surveil non-consenting individuals. | LICENSE-OFFENSIVE.md §6 explicitly prohibits surveillance of non-consenting individuals. |

## Attacks RE-BREAKER enables (offense side)

The tools in RE-BREAKER enable the following technical capabilities. The intended-use clause (LICENSE-OFFENSIVE.md) restricts *who* can use them and *for what*, but the technical capabilities themselves are:

1. **Bypassing encrypted-VM bytecode interpreters** (Pattern A, A-DW, A-VMT, C, B). The runtime-dump CLI can lift the encrypted method bodies from a running encrypted-VM bytecode interpreter.
2. **Neutralizing anti-debug primitives** (RDTSC, CPUID, INT 2D, INT 3, VMCALL, VMXON, INVD, PEB.BeingDebugged, NtQueryInformationProcess). The anti-debug-patch server can NOP or constant-replace these primitives at the function level.
3. **Spoofing anti-VM detection** (CPUID hypervisor leaves, SMBIOS, ACPI, registry keys, MAC prefixes). The anti-vm-spoof server can pre-cache "bare-metal" snapshots and replay them.
4. **Defeating per-vendor anti-tamper** (Denuvo, VMProtect, Themida, StarForce, Arxan, EAC, BE). The vendor-anti-tamper server shells out to the right per-vendor open-source tool (or RE-BREAKER's own runtime primitives) for each.
5. **Bypassing managed-launcher entitlement gates** (Origin, EOS, Steam). The runtime-dump CLI can stub-drop the entitlement check, allowing the game to launch without an active connection to the entitlement server.

## Attacks RE-BREAKER defends against (defender side)

The same technical capabilities, when applied to *defending* software, are:

1. **Reverse-engineering malware** to extract IOCs, write detection signatures, understand TTPs.
2. **Auditing third-party software** (closed-source or open-source) for vulnerabilities, embedded secrets, and backdoors.
3. **Validating anti-tamper claims** — vendors who claim their product uses "Denuvo-grade protection" can have that claim independently verified.
4. **Building defensive tooling** that detects when its own binary is being analyzed (using the same anti-debug / anti-VM primitives the attacker would use).
5. **Training defensive analysts** on the techniques they need to recognize.
6. **Developing malware classification systems** that fingerprint malware based on the anti-RE techniques it uses.

## Out of scope (not in RE-BREAKER, not in RE-AI, not in this roadmap)

| Capability | Why not | Where to look instead |
|---|---|---|
| Network-level interception + spoofing of entitlement servers (e.g. Denuvo ticketing C2) | Different threat model; requires a separate legal review. | Out of scope for this cycle. See the plan's §7 "Out of scope." |
| Real-time patching of binaries in a production environment | RE-BREAKER's injection is for offline analysis, not production. | The patch primitive (`re-patch`) is in RE-AI; the runtime-dump is offline-only. |
| Cracking copy-protection mechanisms for the purpose of redistribution | Explicitly forbidden by LICENSE-OFFENSIVE.md. | — |
| Exploiting the bypass techniques as zero-days against deployed systems | Same as above. | — |
| Speculative side-channel attacks (Spectre, Meltdown, etc.) | Different research area. | `RE-UNLEASHED/engines/` has the existing side-channel docs. |

## Risk acknowledgment

The contributors acknowledge that:

1. The technical capabilities in RE-BREAKER are dual-use: the same tool that lifts encrypted method bodies for malware analysis can also lift them for piracy. The LICENSE-OFFENSIVE.md clause is the legal mechanism to keep the use within the intended scope, but it cannot physically prevent misuse.
2. The AGPL-3.0 license is the strongest copyleft available; it forces any modifications to also be AGPL. This is by design: the contributors want any improvements to the bypass techniques to be shared back with the community, not proprietary-forked.
3. The "no warranty" + "limitation of liability" terms in the LICENSE are intentional. The contributors provide this tool to enable legitimate security research; they do not warrant that the tool is suitable for any particular use case, and they do not accept liability for misuse.
4. The contributors may, at their discretion, revoke access to the RE-BREAKER repository or to the AGPL license grant for individual users who violate the LICENSE-OFFENSIVE.md clause. (The AGPL-3.0 itself is irrevocable; the additional clause enforcement is via the contributors' right to refuse to provide updates, support, or the LICENSE file in future distributions.)

## Conclusion

RE-BREAKER is a tool for the defensive + offensive research community. The threat model is the same as for any powerful RE tool (IDA Pro, Ghidra, Binary Ninja, angr, Cutter, x64dbg, etc.): the tool enables legitimate research when used by legitimate researchers on legitimate targets. The LICENSE-OFFENSIVE.md clause is the contractual mechanism to keep the use within scope.

The contributors stand behind the tool. We believe the defensive use cases (malware analysis, vulnerability research, defensive tool development) are valuable enough to justify the offense-use risk. We have implemented the offensive-research-use clause to keep the offense-use risk within bounds.

If you have questions about whether your use case is appropriate, see `LICENSE-OFFENSIVE.md` §"Contact."
