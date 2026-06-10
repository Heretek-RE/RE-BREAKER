# Offensive-Research-Use Clause Acknowledgement

**Read this file before your first RE-BREAKER run.**

The RE-BREAKER CLI (`re-dump`, `re-catalog-match`, `re-anti-debug-patch`, `re-runtime-dump`, etc.) requires you to acknowledge the offensive-research-use clause before it will execute. You acknowledge by passing `--license-acknowledge` to the CLI.

The CLI will `cat` this file in full on first run, then prompt you to type `I AGREE` (or pass `--license-acknowledge` to skip the prompt).

## What you're agreeing to

You are affirming, under penalty of perjury, that:

1. **You have the legal right** to reverse-engineer the target binary. This means:
   - The binary is your own (you wrote it, you own the copyright)
   - You have a signed engagement letter from the rights holder
   - The binary's license expressly permits RE (e.g. educational, OSS)
   - The binary is malware you have authorization to analyze
   - You are operating under a bug-bounty / coordinated-disclosure scope
   - You are operating under an authorized penetration-testing scope
   - You are a security researcher publishing under responsible-disclosure
   - The rights holder has otherwise granted written consent

2. **You will not use this tool** for piracy, unauthorized access, surveillance of non-consenting individuals, weapons development, or any other unauthorized use enumerated in `LICENSE`.

3. **You will comply with all applicable laws** in your jurisdiction, including but not limited to: copyright law (DMCA §1201 anti-circumvention exemptions, EU InfoSoc Directive Art. 6, etc.), computer-misuse law (CFAA, UK CMA, etc.), export-control law (EAR, ITAR, etc.), and any sector-specific regulation (HIPAA, PCI-DSS, etc.).

4. **You will not redistribute** the bypassed method bodies / decrypted regions / patched binaries in a way that enables unauthorized use.

5. **You accept the no-warranty / limitation-of-liability** terms in `LICENSE`.

## What this means in practice

If you are:

- **A malware analyst at an EDR company analyzing a sample**: YES, you have the right. Pass `--license-acknowledge`.
- **A security consultant with a signed engagement letter for the target**: YES, you have the right. Pass `--license-acknowledge`.
- **An academic researcher publishing a paper on encrypted-VM bytecode interpreters**: YES, you typically have the right (under fair-use / academic-fair-dealing). Pass `--license-acknowledge`. Cite this clause in your paper.
- **A CTF / wargame participant analyzing a challenge binary**: Yes, the CTF organizers have granted consent. Pass `--license-acknowledge`.
- **A gamer trying to pirate a AAA title**: NO. The CLI refuses to run.
- **An unscrupulous consultant trying to bypass a vendor's entitlement to redistribute to a non-paying client**: NO. The CLI refuses to run.
- **Someone trying to access a system they don't own**: NO. The CLI refuses to run.

## Why this clause exists

The legal landscape around RE tooling is... complicated. The DMCA §1201 anti-circumvention provisions (and their equivalents worldwide) make it illegal to circumvent technological protection measures for the purpose of accessing copyrighted work without authorization. The EU's InfoSoc Directive Article 6 has similar provisions. The Computer Fraud and Abuse Act (US) and the UK Computer Misuse Act make unauthorized access to systems illegal regardless of the bypass mechanism.

These laws are not absolute — they have research, security, and interoperability exceptions — but they require the analyst to *demonstrate* the exception applies to their use case. This clause is a contractual mechanism to ensure that RE-BREAKER is used only in contexts where the exception applies.

We are not lawyers. This is not legal advice. If you have questions about whether your use case qualifies, consult a lawyer in your jurisdiction.

## Acknowledgement mechanism

The CLI's `--license-acknowledge` flag sets a per-process state that allows the bypass primitives to execute. Without the flag, the CLI prints this file in full and exits with code 77 ("permission denied").

The first time you use `--license-acknowledge` on a given target, the CLI writes a record to `~/.re-breaker/acknowledged-targets/` with the target's SHA-256 + the timestamp + your username (from `os.getlogin()` or `getpass.getuser()`). Subsequent runs against the same target with `--license-acknowledge` use the cached acknowledgement.

You can clear the acknowledgement cache with `re-dump --clear-acknowledgements`.

## Liability

If you use RE-BREAKER for an unauthorized purpose, the LICENSE terms say the contributors are not liable. But the law of your jurisdiction may hold you personally liable regardless of what the LICENSE says. Use this tool responsibly.

## Contact

If you have questions about whether your use case is appropriate, contact: redacted-for-public-readme (see the AGPL-3.0 source for the actual maintainer contact).

---

**By passing `--license-acknowledge` to any RE-BREAKER CLI command, you acknowledge that you have read this file in full, that you understand its terms, and that you agree to be bound by them.**
