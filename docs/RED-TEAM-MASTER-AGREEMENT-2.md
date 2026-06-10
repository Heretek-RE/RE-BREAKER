# MASTER RED-TEAM ENGAGEMENT AGREEMENT (MRTEA-2)

**Multipart Authorized Reverse-Engineering, Red-Team, and Proof-of-Concept Research Agreement — Volume II**

**Targeted Vendors:** Electronic Arts Inc., Codemasters, Ubisoft Entertainment, Gearbox Entertainment, 2K Games, Take-Two Interactive, and related counterparties.

---

| Field | Value |
|---|---|
| Document ID | `MRTEA-2026-002` |
| Effective Date | _____________________________ |
| Term | 36 months from Effective Date, auto-renewing for 12-month terms unless either party gives 90 days' written notice of non-renewal |
| Governing Law | State of Delaware, USA (anti-piracy, IP, and computer-misuse statutes) |
| Forum | JAMS Arbitration, San Francisco, CA |
| Classification | **CONFIDENTIAL — ATTORNEY-CLIENT PRIVILEGED** |
| Companion Document | MRTEA-2026-001 (the "Volume I" master, governing Vendors SOW-X through SOW-X). This Volume II is parallel, severable, and independently effective. |

---

## PARTIES

**HERETEK-AI, INC.**, a Delaware corporation with principal offices at _____________________________ ("**Operator**" or "**Heretek**"), represented by its Chief Executive Officer, and counsel of record at _____________________________.

**and**

Each of the following Counterparties (each a "**Vendor**"; collectively "**Vendors**"):

| # | Vendor | Authorized Subsidiary/Entity | SOW Addendum | Principal Product(s) |
|---|---|---|---|---|
| 1 | **Electronic Arts Inc.** (F1 25 line) | EA, EA Sports, EA Codemasters | SOW-X | F1 25 (Iconic Edition), F1 24, F1 Life (mobile), EA AntiCheat, EA DRM, EA license server |
| 2 | **Codemasters Software Company Limited** (joint with EA Sports) | Codemasters, EA Sports | SOW-X | F1 25, F1 24, DiRT, GRID, ONRUSH, EGOS engine protection layer |
| 3 | **Ubisoft Entertainment S.A.** (BGE 20AE line) | Ubisoft, Ubisoft Montpellier, Ubisoft Milan | SOW-X | Beyond Good and Evil - 20th Anniversary Edition, Anvil / Snowdrop / Disrupt engine protection, Uplay/Ubisoft Connect, Uplay DRM, Ubisoft Anti-Cheat |
| 4 | **Ubisoft Entertainment S.A.** (POP:TC line) | Ubisoft, Ubisoft Montpellier | SOW-X | Prince of Persia: The Lost Crown, Uplay/Ubisoft Connect, Ubisoft Anti-Cheat, custom AT for POP:TC |
| 5 | **Gearbox Entertainment, L.P.** (Borderlands 4) | Gearbox, Gearbox Software | SOW-X | Borderlands 4, Unreal Engine protection layer, Gearbox custom anti-tamper, SHiFT code system |
| 6 | **2K Games, Inc.** (Borderlands 4 publisher) | 2K, Take-Two Interactive | SOW-X | 2K Launcher, 2K entitlement / license flow, 2K-published titles |
| 7 | **Take-Two Interactive Software, Inc.** (parent of 2K and Gearbox Publishing) | Take-Two, Rockstar, 2K, Gearbox Publishing, Private Division | SOW-X | Parent-level corporate authorization, cross-publisher coordination |

> **Note on counterparty overlap and parent relationships.** EA is the parent of Codemasters; SOW-X (EA direct) and SOW-X (Codemasters joint) are operative and severable. Ubisoft appears twice — SOW-X (BGE 20AE) and SOW-X (POP:TC) — because the protections on the two titles differ (BGE 20AE is an Unreal/Anvil/Dunia-class engine with heavy Uplay DRM; POP:TC is Unity-based with lighter Ubisoft integration). Take-Two is the parent of both 2K and Gearbox Publishing; SOW-X (2K) and SOW-X (Gearbox) and SOW-X (Take-Two parent) form a coordinated set. Where the same Finding affects multiple Vendors under this Volume II, the cross-Vendor coordinated-disclosure procedures in Part IV govern.

---

## RECITALS

**WHEREAS**, each Vendor markets, licenses, or operates a software product whose intended purpose is to resist unauthorized modification, reverse engineering, tampering, piracy, or cheating (each, an "**Authorized Target**" as enumerated in Exhibit A to its SOW);

**WHEREAS**, the Authorized Targets enumerated in Part II of this Agreement include, **without limitation**:

  (a) the racing simulation title **F1 25 Iconic Edition** published by EA / Codemasters and protected by EA Anti-Cheat, EA DRM, and the proprietary EGOS engine protection layer;

  (b) the action-adventure remaster **Beyond Good and Evil - 20th Anniversary Edition** published by Ubisoft and protected by Uplay / Ubisoft Connect, Ubisoft DRM, and the Anvil / Snowdrop / Disrupt engine family protection layer;

  (c) the looter-shooter **Borderlands 4** published by 2K / Take-Two and developed by Gearbox, protected by the 2K Launcher, Gearbox custom anti-tamper, SHiFT code system, and the underlying Unreal Engine protection layer; and

  (d) the action-platformer **Prince of Persia: The Lost Crown** published by Ubisoft and developed by Ubisoft Montpellier, built on a Unity-based engine stack and protected by Uplay / Ubisoft Connect, Ubisoft DRM, and Ubisoft Anti-Cheat;

**WHEREAS**, Operator is a security research firm specializing in offensive reverse engineering, anti-tamper and anti-cheat bypass research, symbolic execution, and vulnerability discovery, and operates a controlled laboratory environment (the "**Lab**") suitable for safely executing proof-of-concept ("**PoC**") exploits against binary targets;

**WHEREAS**, the Vendors' End-User License Agreements (EULAs), Terms of Service, and Acceptable Use Policies ("**Vendor Policies**") ordinarily prohibit the very activities contemplated by this Agreement — including reverse engineering, decompilation, disassembly, modification, tampering, automated probing, and the circumvention of technical protection measures — and the activities contemplated by this Agreement are also regulated by 17 U.S.C. § 1201 (DMCA), 18 U.S.C. § 1030 (CFAA), Directive 2009/24/EC (EU Software Directive), national implementations of Article 6 of the EU Copyright Directive (2019/790), the French Code pénal art. 323-1 et seq. (notably applicable to Ubisoft, whose corporate seat is in France), the UK Computer Misuse Act 1990 (notably applicable to Codemasters, whose corporate seat is in the United Kingdom, and to Gearbox's UK operations), and analogous laws of other jurisdictions (collectively, "**Applicable Law**");

**WHEREAS**, the parties acknowledge that the activities contemplated by this Agreement would, absent the express authorizations granted herein, constitute violations of Vendor Policies and, depending on facts and circumstances, may implicate Applicable Law, and that the parties have a mutual interest in ensuring that any such activities are conducted under controlled, documented, and legally defensible conditions;

**WHEREAS**, Operator wishes to undertake one or more engagements (each, an "**Engagement**") against the Authorized Targets for the purposes of (i) identifying vulnerabilities, (ii) producing PoC exploits, (iii) producing technical reports, and (iv) making findings available to Vendors in a manner that allows remediation before any public disclosure;

**WHEREAS**, each Vendor, in its sole discretion, wishes to authorize Operator to undertake one or more Engagements against its Authorized Targets, and to receive the deliverables described herein, on the terms set forth in this Agreement and the applicable SOW;

**NOW, THEREFORE**, in consideration of the mutual covenants, fee structures, releases, and authorizations set forth herein, and for other good and valuable consideration, the receipt and sufficiency of which are hereby acknowledged, the parties agree as follows.

---

# PART I — MASTER RED-TEAM ENGAGEMENT AGREEMENT

## Article 1. Definitions

For purposes of this Agreement, the following capitalized terms have the meanings ascribed below. Definitions specific to a particular SOW are set forth in that SOW and govern that SOW in the event of conflict. Capitalized terms not defined in this Agreement have the meanings given in MRTEA-2026-001 (Volume I).

1.1 **"Affiliate"** means, with respect to a party, any entity controlling, controlled by, or under common control with such party, where "control" means ownership of more than 50% of the voting securities or the power to direct management.

1.2 **"Anti-Tamper"** or **"AT"** means the protection layer implemented in a Vendor's binary that resists patching, hooking, introspection, and analysis, including but not limited to integrity checks, code virtualization, white-box cryptography, hardware-binding, and similar mechanisms.

1.3 **"Anti-Cheat"** or **"AC"** means the runtime component that monitors a game client and/or kernel for indicators of cheating, tampering, injection, or unauthorized memory access.

1.4 **"Authorized Target"** has the meaning given in the Recitals and is enumerated in Exhibit A to each SOW.

1.5 **"Bypass"** means a working PoC exploit that defeats, evades, neutralizes, or substantially weakens a security control of an Authorized Target.

1.6 **"CVE"** means a Common Vulnerabilities and Exposures identifier assigned by MITRE.

1.7 **"Coordinated Disclosure Period"** has the meaning given in Part IV.

1.8 **"Embargo"** means the period during which Operator shall not publicly disclose Findings, as specified in the applicable SOW or in Part IV.

1.9 **"Engagement"** means a specific, scoped, and authorized research activity against an Authorized Target, as described in a SOW.

1.10 **"Findings"** means all information, observations, vulnerabilities, PoC exploits, technical analyses, samples, screen captures, network traces, and derivatives thereof, produced by Operator in the course of an Engagement.

1.11 **"Lab"** has the meaning given in the Recitals and is described in Exhibit C.

1.12 **"Lab Personnel"** means Operator's employees, contractors, and Affiliates' personnel who (i) have signed Operator's standard confidentiality agreement, (ii) have completed Operator's background-check and training program, and (iii) are listed in Exhibit D.

1.13 **"PoC Exploit"** means a piece of software, hardware description, written procedure, or other artifact that demonstrates a Bypass or vulnerability, subject to the standards in Part V.

1.14 **"Sensitive Personal Data"** means any data relating to an identified or identifiable natural person, special-category data under GDPR Art. 9, or any data subject to heightened protection under Applicable Law.

1.15 **"Vendor Systems"** means any production, staging, telemetry, license-server, anti-cheat server, or customer-facing infrastructure owned, operated, or controlled by a Vendor or its Affiliates, except as expressly identified as in-scope in the applicable SOW.

1.16 **"Heretek Products"** means the products, services, tools, models, datasets, and offerings developed, marketed, licensed, or used internally by Operator (Heretek-AI, Inc.), including without limitation offensive and defensive security tools, anti-tamper and anti-cheat technologies, detection rule sets, threat intelligence feeds, security orchestration platforms, machine-learning models, and research frameworks, in each case whether or not offered commercially to third parties.

1.17 **"Volume I"** means MRTEA-2026-001 and all SOWs executed thereunder (SOW-X through SOW-X). This Volume II is parallel to and severable from Volume I. References to "SOW-X" herein refer to SOWs of this Volume II, not Volume I.

1.18 **"Volume II"** or **"this Agreement"** means this MRTEA-2026-002, including all SOWs executed hereunder (SOW-X through SOW-X) and all Exhibits.

## Article 2. Scope and Engagement Mechanism

2.1 **Master framework.** This Agreement establishes the master legal, security, and procedural framework under which one or more Engagements against the Volume II Authorized Targets (F1 25, BGE 20AE, Borderlands 4, POP:TC, and any related enumerated targets) may be undertaken. No Engagement is authorized until both parties have executed a SOW substantially in the form of Part II.

2.2 **SOW precedence.** Each SOW is incorporated by reference and is severable. In the event of a conflict between this Master Agreement and a SOW, the SOW controls with respect to that Engagement only. In the event of a conflict between two SOWs under this Volume, the later-executed SOW controls. In the event of a conflict between this Volume II and Volume I, each Volume governs its own Engagements; cross-Volume Findings are coordinated as set forth in Section 2.5 below.

2.3 **Pre-engagement activities.** Operator may undertake pre-engagement scoping, sample acquisition, environment build-out, and tooling development ("**Pre-Engagement Activities**") without a SOW, provided that such activities do not interact with Vendor Systems, do not Bypass security controls of any production binary, and do not constitute unauthorized access under Applicable Law.

2.4 **Lab-only default.** Each SOW shall, by default, restrict all Engagement activities to Operator's Lab. Field testing, live-service interaction, customer-impacting testing, and any testing against production endpoints or production users are prohibited unless expressly authorized in the SOW.

2.5 **Cross-Volume coordination.** Where the same Finding (or a closely related Finding) implicates a Vendor under Volume I and a Vendor under Volume II, the parties shall coordinate under Part IV of this Agreement. Where a Finding arises from a shared upstream component (e.g., a common Unreal Engine subsystem affecting Borderlands 4 and a Volume I title), the parties shall follow the cross-Vendor coordination procedures in this Volume II and, where applicable, the parallel procedures in Volume I.

## Article 3. Authorizations, Releases, and Non-Assertion

3.1 **Limited license to Authorized Targets.** Each Vendor grants Operator a **limited, non-exclusive, non-transferable, revocable, royalty-free license**, for the term of the applicable Engagement and solely within the scope of the SOW, to:

  (a) install, execute, copy, and store the Authorized Target on Operator's Lab systems;

  (b) reverse engineer, decompile, disassemble, and analyze the Authorized Target, including for the purpose of identifying vulnerabilities and producing Bypasses;

  (c) modify, patch, instrument, and tamper with copies of the Authorized Target, including in memory at runtime within the Lab;

  (d) develop, test, and refine PoC Exploits against the Authorized Target; and

  (e) communicate Findings to the Vendor as described herein.

3.2 **Waiver of EULA restrictions.** To the extent the Authorized Target's EULA, ToS, AUP, or any shrink-wrap, click-wrap, or browse-wrap agreement (each, a "**Vendor Policy**") prohibits any of the activities described in Section 3.1, the Vendor waives enforcement of such restrictions **solely against Operator and only for the activities expressly authorized in the SOW**. Operator acknowledges that this waiver is a personal right of Operator, is non-transferable, and does not extend to any third party.

3.3 **DMCA § 1201 anti-circumvention release.** Each Vendor, as the rightsholder (or duly authorized licensee of the rightsholder) of the Authorized Target and the technical protection measures therein, **shall not assert, and hereby releases Operator from, any claim under 17 U.S.C. § 1201** based on Operator's circumvention of a technological measure protecting a work of that Vendor, where such circumvention is undertaken (i) in good faith, (ii) within the scope of an executed SOW, (iii) for the purposes described in Section 3.1, and (iv) without further distribution of the circumvention means to any third party not bound by this Agreement. This release is the functional equivalent of a § 1201(j) good-faith security testing exception where one is available, and is intended to supplement rather than replace any statutory exception.

3.4 **CFAA / analogous-statute covenant.** Each Vendor covenants that, for activities undertaken strictly within the scope of an executed SOW and within the boundaries of the Authorized Target enumerated in Exhibit A, it shall not refer, report, complain, or otherwise initiate any action against Operator or Lab Personnel under 18 U.S.C. § 1030, the UK Computer Misuse Act 1990 (notably applicable to Codemasters and Gearbox UK operations), the German StGB §§ 202a–c, 269, 303a, the French Code pénal art. 323-1 et seq. (notably applicable to Ubisoft Entertainment S.A. and its French subsidiaries), the EU Directive 2013/40/EU on attacks against information systems (and national implementations), or analogous statutes of any other jurisdiction, and shall, upon reasonable request, confirm this covenant in writing to any prosecuting authority that inquires. This covenant does not extend to activities outside the SOW, to activities that exceed the scope of Exhibit A, to activities that touch Vendor Systems not enumerated in the SOW, or to Operator's bad-faith conduct.

3.5 **Non-assertion of Vendor Policies.** Each Vendor covenants that, for activities within the scope of an executed SOW, it shall not (a) terminate or threaten to terminate Operator's license to the Authorized Target on the basis of such activities, (b) impose technical countermeasures against Operator (other than the normal operation of the Authorized Target's protections, which Operator is expected to defeat), (c) refer Operator to any anti-piracy working group, IP-protection consortium, or trade association, or (d) publish or cause to be published any allegation that Operator engaged in unauthorized access or piracy.

3.6 **Reservation of rights against third parties.** Nothing in this Agreement constitutes a license, waiver, or release in favor of any person other than Operator and Lab Personnel. Each Vendor expressly reserves all rights and remedies against any third party that engages in any activity described in Section 3.1 without authorization.

3.7 **Right to revoke.** Each Vendor may revoke its authorization under this Article 3 with respect to a specific Engagement by written notice to Operator. Revocation is effective upon receipt. After revocation, Operator shall (i) cease all in-scope activities, (ii) preserve Findings already produced, (iii) deliver Findings to the Vendor as required by Article 7, and (iv) certify destruction of all Lab copies of the Authorized Target and any PoC Exploits within 30 days.

3.8 **No authorization to harm users.** Nothing in this Agreement authorizes Operator to interact with, attack, intercept, impersonate, or affect any end user, customer, or third party of a Vendor's products, or to publish or distribute any tool, code, or instructions that would enable such interaction by a third party.

3.9 **Right to use Findings to improve Heretek Products.** The provisions of Volume I § 3.9 (right to use Findings to improve Heretek Products) are incorporated herein by reference and govern each Engagement under this Volume II, **mutatis mutandis**, with the following Volume II-specific clarifications:

  (a) For the avoidance of doubt, "Heretek Products" includes, without limitation, the Operator's research output, detection rule sets, training datasets, and offensive and defensive tools, and may incorporate Findings from F1 25, BGE 20AE, Borderlands 4, and POP:TC in the manner contemplated by Volume I § 3.9(b)–(e).

  (b) The "no whole-product Bypass commercialization" restriction in Volume I § 3.9(c)(v) applies with full force to Findings against F1 25, BGE 20AE, Borderlands 4, and POP:TC. Operator shall not commercialize any Whole-Product Bypass against these titles.

  (c) The "no cross-Vendor contamination" restriction in Volume I § 3.9(c)(iii) applies across both Volumes; a Finding from a Volume I Vendor (e.g., SOW-X Denuvo findings) shall not be incorporated into a Heretek Product in a manner that would defeat a Volume II Vendor's protections (e.g., a 2K- or Ubisoft-specific protection), and vice versa.

  (d) The "permitted improvements" enumeration in Volume I § 3.9(d) (generic detection rules, hardening guides, model training, abstracted PoC variants, test fixtures, threat-intelligence aggregation) applies to Findings under this Volume II.

## Article 4. Lab Environment, Personnel, and Controls

4.1 **Lab description.** The Lab consists of isolated physical and virtual infrastructure described in Exhibit C, including (i) air-gapped analysis hosts, (ii) instrumented dynamic-analysis enclaves, (iii) license-server emulators (including dedicated emulators for EA's license servers, Uplay/Ubisoft Connect, the 2K Launcher, and the SHiFT code system), (iv) test harnesses, and (v) encrypted evidence storage.

4.2 **Network isolation.** All Lab systems are physically or cryptographically isolated from the public internet and from any Vendor Systems, except as expressly permitted by a SOW. Where a SOW permits limited network interaction (e.g., for EA license-server emulation, for Ubisoft Connect entitlement-token flow analysis, for 2K Launcher emulation, or for SHiFT code redemption in a controlled test harness), that interaction shall be (a) clearly identified in the SOW, (b) rate-limited and logged, (c) routed through authenticated reverse proxies, and (d) terminated at the close of the Engagement.

4.3 **Personnel controls.** Lab Personnel are bound by (i) employment or contractor agreements containing confidentiality, IP-assignment, and acceptable-use covenants, (ii) this Agreement, and (iii) Operator's internal information-security policy. Operator maintains a current roster in Exhibit D and shall update Exhibit D within 5 business days of any change.

4.4 **Background checks.** Lab Personnel with access to Findings have completed, prior to such access, a criminal background check covering the preceding 7 years and a right-to-work verification in their jurisdiction of employment.

4.5 **Need-to-know.** Findings are accessible only to Lab Personnel with a documented, role-based need. Operator shall maintain an access log reflecting additions, removals, and access events.

4.6 **Logging.** All Lab systems emit tamper-evident audit logs of authentication, file access, network egress (where permitted), and tool execution. Logs are retained for 3 years and are available to the Vendor on request.

4.7 **Tooling provenance.** All tools used in an Engagement are either (a) developed by Operator, (b) obtained from the Vendor in the course of the Engagement, (c) publicly available open-source tools, or (d) commercial off-the-shelf tools. Operator shall not use in an Engagement any tool whose provenance is unknown or that has been obtained through unauthorized access.

4.8 **No malware, no implants.** Operator shall not, in the course of an Engagement, develop, deploy, or test any self-propagating code, network worm, ransomware, supply-chain implant, or persistent remote-access tool against any Vendor System. PoC Exploits are limited to controlled, ephemeral demonstration against Authorized Targets within the Lab.

4.9 **Insurance.** Operator shall maintain, in force throughout the term, (a) commercial general liability of at least $5,000,000 per occurrence, (b) cyber liability / technology E&O of at least $10,000,000 per occurrence, (c) errors and omissions of at least $5,000,000 per occurrence, (d) crime/fidelity of at least $1,000,000, and (e) workers' compensation as required by law. Certificates of insurance are annexed as Exhibit E and shall be updated annually.

## Article 5. Compliance with Applicable Law

5.1 **General compliance.** Operator shall comply with all Applicable Law in the conduct of Engagements, including export-control regimes (EAR, ITAR, EU Dual-Use Regulation 2021/821, UK Strategic Export Controls), sanctions regimes (OFAC, EU, UK, UN), data-protection law (GDPR, UK GDPR, CCPA/CPRA, LGPD), and computer-misuse law (CFAA, UK CMA 1990, French Code pénal art. 323-1 et seq., German StGB §§ 202a–c, 269, 303a).

5.2 **Specific to the Volume II Vendors.** The parties acknowledge the following jurisdiction-specific considerations:

  (a) **France (Ubisoft).** Ubisoft Entertainment S.A. is a French *société anonyme*. French criminal law on attacks against information systems (Code pénal art. 323-1 et seq.) and on the violation of trust and breach of automated data-processing systems may apply. The covenant in Section 3.4 covers French law expressly.

  (b) **United Kingdom (Codemasters, Gearbox UK).** Codemasters Software Company Limited is a UK company. The UK Computer Misuse Act 1990 (sections 1, 2, 3, 3ZA) is expressly covered by Section 3.4. The UK GDPR and the Data Protection Act 2018 also apply to any incidental personal data.

  (c) **United States (EA, 2K, Take-Two, Gearbox US).** The CFAA (18 U.S.C. § 1030), DMCA (17 U.S.C. § 1201), state computer-misuse laws (notably California Penal Code § 502), and the CCPA/CPRA apply. California, Delaware, and New York are the most likely fora for incidental disputes.

  (d) **Cross-border data flows.** Where Engagements under this Volume II produce Findings that include data subjects from multiple jurisdictions (e.g., a multiplayer cheat against Borderlands 4 that incidentally encounters EU player identifiers), Operator shall apply the most protective applicable standard.

5.3 **Export classification.** The parties acknowledge that offensive security tooling may be subject to export controls, including ECCN 5D002, 5D991, or national equivalents. Operator is responsible for determining and complying with the export classification of any tool or technique it develops. Operator shall not export, re-export, or transfer any such tool or technique to a country, entity, or person subject to U.S. sanctions or to a country or person listed in EU/UK sanctions annexes, without prior license or authorization. Special attention is drawn to the export of cryptographic tools (which may implicate both U.S. BIS and French *ANSSI* regimes for France-based analysts).

5.4 **Sanctions screening.** Operator screens Lab Personnel against OFAC SDN, EU consolidated, UK OFSI, and UN sanctions lists at hire and quarterly thereafter. No person on such a list shall participate in an Engagement.

5.5 **Data protection.** If an Engagement incidentally processes personal data, the parties shall execute a Data Processing Addendum (DPA) in the form of Exhibit F, identifying the lawful basis, retention period, processor instructions, and security measures. Operator shall not knowingly target, harvest, or retain personal data; where personal data is incidentally encountered (for example, in F1 25 telemetry traces, in Borderlands 4 SHiFT code redemption logs, or in Ubisoft Connect entitlement tokens), Operator shall minimize, pseudonymize, and purge it.

5.6 **Anti-bribery.** Each party warrants that it has not, and shall not, offer or accept any bribe, kickback, or thing of value in connection with this Agreement, and shall comply with the U.S. FCPA, UK Bribery Act 2010, French *Loi Sapin II*, and analogous statutes.

5.7 **National-security carve-outs.** This Agreement does not authorize any activity that would constitute a violation of national-security law, FISA, EO 12333, or any classified-program rules. If an Engagement requires access to classified or controlled unclassified information, the parties shall negotiate a separate government-specific addendum.

## Article 6. Fees, Payment, and Expense Reimbursement

6.1 **Fee structure.** Each SOW specifies a fee structure, which may include any of the following components, in any combination:

  (a) **Retainer** — a fixed monthly or quarterly fee for standing capacity;

  (b) **Per-Engagement fee** — a fixed fee per Engagement, with milestone payments;

  (c) **Per-Finding bounty** — a fee per accepted Finding meeting the SOW's severity rubric;

  (d) **Hourly / daily rate** — for time-and-materials work;

  (e) **Subscription** — a fee for ongoing access to Operator's research output, dashboards, or continuous PoC pipeline.

6.2 **Currency and taxes.** All fees are in U.S. dollars, exclusive of applicable sales, use, value-added, goods-and-services, or withholding taxes, which are the responsibility of the Vendor. Where the Vendor is a French entity (Ubisoft), French VAT rules and the EU 2018/1912 VAT reform apply; where the Vendor is a UK entity (Codemasters), UK VAT rules apply.

6.3 **Expenses.** Pre-approved, reasonable, and documented expenses (travel, hardware, third-party data, court reporter fees for deposition prep) are reimbursed at cost.

6.4 **Invoicing and payment.** Operator invoices monthly in arrears. Each invoice is due net 30 days. Disputed amounts are addressed in good faith; undisputed amounts are paid while dispute resolution proceeds.

6.5 **No bounty for prohibited work.** No fee is payable for any Finding produced (a) outside the scope of a SOW, (b) by unauthorized means, (c) in violation of Applicable Law, or (d) in violation of the Authorized Target's underlying third-party open-source licenses.

## Article 7. Deliverables, Reports, and Findings

7.1 **Standard deliverables.** Each Engagement produces, at minimum, the following deliverables (formats in SOW):

  (a) **Executive Summary** — non-technical summary, ≤ 3 pages;

  (b) **Technical Report** — full reproduction steps, root-cause analysis, affected versions, severity rating (CVSS v3.1 or v4.0), and recommended remediations;

  (c) **PoC Exploit** — code, instructions, or artifacts demonstrating the Bypass, conforming to Part V;

  (d) **Disclosure Schedule** — proposed CVSS score, CVE application, and disclosure timing;

  (e) **Evidence Package** — logs, traces, crash dumps, and reproduction artifacts, hashed (SHA-256) and stored for the retention period in the SOW.

7.2 **Severity rubric.** Severity is rated using CVSS v3.1 (or v4.0 by mutual agreement) with a Vendor-specific Environmental Score reflecting the deployed posture of the Authorized Target. The Vendor may rebut a severity rating in writing within 14 days; absent timely rebuttal, the rating is final.

7.3 **Quality bar.** Each report is reviewed by a senior engineer not involved in the original Finding (the "**Reviewer**") and signed off before delivery. The Reviewer verifies: (i) reproducibility, (ii) root cause, (iii) scope, (iv) remediation quality, and (v) non-inclusion of incidental data.

7.4 **Acceptance.** A Finding is "**Accepted**" when the Vendor confirms in writing the validity of the technical content, regardless of whether the Vendor concurs with severity or remediation timeline. A Finding that the Vendor disputes on technical grounds shall be discussed in good faith for 30 days; unresolved disputes proceed to Article 15.

7.5 **CVE assignment.** Operator assigns CVE numbers through an authorized CVE Numbering Authority (CNA) or coordinates assignment through the Vendor's CNA. The Vendor is the canonical CNA for vulnerabilities in its own Authorized Targets unless the parties otherwise agree.

7.6 **Reproduction support.** Operator provides reasonable reproduction support, by secure channel, for 12 months after Acceptance. Reproduction support includes answering procedural questions, providing updated PoC variants for patched versions, and joining scheduled working sessions.

7.7 **Multi-Vendor Findings.** Where a Finding from a Volume II SOW implicates a Vendor under Volume I (e.g., a Finding against Borderlands 4 that implicates a shared Unreal Engine subsystem also affecting a Volume I title using UE), the parties shall coordinate to (a) ensure consistent technical content, (b) respect each Vendor's Coordinated Disclosure Period, and (c) avoid cross-Vendor contamination in the technical narrative.

## Article 8. Intellectual Property

8.1 **Vendor IP.** Each Vendor retains all right, title, and interest in and to its Authorized Target, including any modifications, patches, derivative works, and PoC Exploits created by Operator that incorporate or are based on Vendor IP. Operator's PoC Exploits are derivative works of the Authorized Target solely to the extent they load, link to, or call Vendor-provided APIs or formats; the parties acknowledge that independent research methodologies and operator-authored code are not Vendor IP.

8.2 **Operator IP.** Operator retains all right, title, and interest in and to (a) its pre-existing tools, methodologies, and know-how, (b) the Lab and its configuration, (c) generic reverse-engineering and symbolic-execution techniques, and (d) PoC Exploits that do not incorporate Vendor IP. Subject to Section 8.3, Operator may use its methodologies and generic tooling in engagements with other clients.

8.3 **No cross-Vendor contamination.** Operator shall not, in any PoC Exploit, Finding, or report, incorporate code, techniques, or know-how that is specific to a different Vendor's Authorized Target in a manner that would (a) be reasonably likely to cause cross-leakage of one Vendor's IP into another Vendor's deliverable, (b) enable a third party to defeat one Vendor's protections using another's PoC, or (c) breach Section 12. The "no cross-contamination" obligation is enforceable by any aggrieved Vendor, and applies across both Volume I and Volume II.

8.4 **Tooling license-back.** Operator grants each Vendor a **perpetual, irrevocable, worldwide, royalty-free, non-exclusive license** to use, modify, embed, and distribute any tooling, harness, or methodology specifically created for that Vendor's Engagement, **solely for the Vendor's internal use in developing, testing, and securing its Authorized Targets**, and not for resale or stand-alone commercialization. The license is sublicensable only to the Vendor's Affiliates and to bona fide contractors engaged in the Vendor's product security.

8.5 **Residual knowledge.** Nothing in this Agreement restricts either party from using **residual general skills, ideas, concepts, and know-how** retained in the unaided memory of personnel who have not intentionally memorized Confidential Information, provided that this clause does not constitute a license under any patent, copyright, trade secret, or other IP right of the disclosing party.

8.6 **Open-source hygiene.** Each party warrants that any code contributed to a joint deliverable is either (a) the contributor's original work, (b) properly licensed open-source code with disclosed license, or (c) third-party code with a documented chain of title. The parties shall specify license terms (preferably MIT, BSD-2-Clause, or Apache-2.0) for any joint deliverable intended for external release.

8.7 **Engine third-party IP.** The parties acknowledge that Authorized Targets under this Volume II incorporate third-party engine technology (e.g., Unreal Engine for Borderlands 4, Unity for POP:TC, and the Anvil / Snowdrop / Disrupt engine family for BGE 20AE). Findings about the engine itself, where the engine is licensed to the Vendor under a separate engine EULA, are out-of-scope of this Agreement and shall be redirected to the engine licensor's disclosure program with the Vendor's consent. Findings about how the Vendor *integrates* the engine (e.g., a Vendor-specific anti-tamper wrapper around UE) remain in-scope.

## Article 9. Confidentiality

9.1 **Confidential Information.** "**Confidential Information**" means non-public information disclosed by one party ("**Discloser**") to the other ("**Recipient**") in connection with an Engagement, whether oral, written, visual, or electronic, that is (a) marked or identified as confidential at the time of disclosure, (b) of a nature that a reasonable person would understand to be confidential, or (c) of a type that the Recipient knows or should know is confidential. Findings, PoC Exploits, Authorized Target binaries, technical reports, source code, and disclosure schedules are Confidential Information of the originating Vendor, regardless of marking.

9.2 **Standard of care.** Recipient shall protect Confidential Information using at least the same degree of care it uses for its own confidential information of like importance, and in no event less than a **reasonable** standard of care.

9.3 **Permitted disclosures.** Recipient may disclose Confidential Information (a) to its employees, contractors, Affiliates, and professional advisors who have a need to know and are bound by written confidentiality obligations no less protective than this Article, (b) as required by law, regulation, or valid order of a court of competent jurisdiction, after giving the Discloser prompt notice (where lawful) and reasonable cooperation to seek a protective order, and (c) as expressly permitted in writing by the Discloser.

9.4 **Government / regulator requests.** If a government or regulator requests Confidential Information, Recipient shall (a) promptly notify Discloser, (b) provide Discloser an opportunity to challenge the request, (c) narrow the response to what is legally required, and (d) not voluntarily disclose more than is required. For French regulators (notably CNIL for data protection and ANSSI for cyber), the procedures of Section 9.4 shall be coordinated with the Vendor's French counsel.

9.5 **Disclosure of vulnerabilities to third parties.** Operator shall not disclose a Finding to any third party (including researchers, journalists, regulators, or customers) prior to the expiration of the Coordinated Disclosure Period specified in Part IV or in the SOW, without the prior written consent of the Vendor.

9.6 **Trade secret status.** Findings, PoC Exploits, and Authorized Target internals are **trade secrets** of the originating Vendor under the Defend Trade Secrets Act of 2016, the EU Trade Secrets Directive (2016/943), and French *Code de la propriété intellectuelle* art. L. 621-1 et seq. (for the Ubisoft-originated Findings), and analogous law, regardless of whether the Vendor has filed a registration. Recipient shall not use or disclose trade-secret Confidential Information except as expressly authorized.

9.7 **Term of confidentiality.** The confidentiality obligations survive termination of this Agreement for a period of **7 years** from the date of disclosure for general Confidential Information, and **for as long as the information remains a trade secret** for trade-secret Confidential Information.

9.8 **No public statements without consent.** Neither party shall make any public statement (press release, blog post, conference talk, social media post, regulatory filing, marketing material) regarding the existence, terms, or subject matter of an Engagement, the existence of this Agreement, or the relationship between the parties, without the prior written consent of the other party, except as required by law. Either party may disclose the existence of a vendor-engagement program on a no-names basis, with prior approval of any specific characterization.

9.9 **Pre-release / non-GA binaries.** Where Operator receives a pre-release or non-GA build of an Authorized Target (e.g., a pre-release F1 26 build shared by EA in advance of public launch), the pre-release build is Confidential Information and is subject to heightened protection. Operator shall not retain pre-release builds beyond the period specified in the SOW, and shall not publicly disclose any Finding based on a pre-release build prior to the build's public release, regardless of the Coordinated Disclosure Period otherwise applicable.

## Article 10. Coordinated Disclosure

10.1 **Coordinated Disclosure Period.** The default Coordinated Disclosure Period is **180 days** from Acceptance of a Finding, subject to extension in the SOW or by mutual written agreement. The Vendor may elect an **accelerated 90-day** period by written notice within 30 days of Acceptance; the Vendor may also request a longer period (up to 24 months) for Findings that require architectural changes, with operator's reasonable consent.

10.2 **Drafts and pre-publication review.** Operator shall provide the Vendor with a draft of any public disclosure (report, blog post, conference talk, CVE record) at least **30 days** before public release. The Vendor may (a) request redactions of Confidential Information and trade secrets, (b) request a delay of up to 90 days if a remediation is in active deployment, and (c) request correction of factual errors. Operator is not required to delay disclosure beyond 90 days from draft delivery.

10.3 **Embargoed information.** Until public disclosure, all PoC Exploits, technical details, root-cause analyses, and reproducer instructions are Embargoed Information. Operator shall not share Embargoed Information with any third party not bound by this Agreement.

10.4 **Counter-notices and takedown coordination.** If a third party publishes Findings during the Embargo, the parties shall (a) coordinate takedown requests under DMCA § 512(c) or analogous law (including Article 6 of the EU Copyright Directive 2019/790 implementing acts), (b) consider joint public statements, and (c) discuss accelerated or modified disclosure.

10.5 **Public CVE records.** Once public, the Vendor's CVE record is canonical. Operator may cross-reference or summarize publicly disclosed Findings in research output, with appropriate attribution to the Vendor.

10.6 **No sale or commercialization of unreleased Findings.** Operator shall not sell, license, transfer, or otherwise commercialize unreleased Findings, PoC Exploits, or technical details to any third party, including brokers, vulnerability-acquisition platforms, bug-bounty intermediaries, or governmental procurement programs, without the Vendor's prior written consent. This clause does not prohibit Operator from retaining PoC Exploits in evidence storage as required by Article 11.

10.7 **Coordinated disclosure of Findings from cross-product research.** Where a single Operator research activity produces Findings against multiple Vendors (e.g., a common cryptographic primitive used in several Authorized Targets under this Volume II, or across both Volumes), Operator shall notify each affected Vendor, and the Coordinated Disclosure Period for each Finding runs independently against each Vendor.

10.8 **Specific to multiplayer / live-service titles.** Borderlands 4 and F1 25 are live-service titles. Operator acknowledges that Findings affecting live-service components (e.g., EA's matchmaking, SHiFT code redemption, Borderlands 4's online services) require heightened coordination with the Vendor's live-service team. The Vendor may request that PoC Exploits against live-service components be limited to Vendor-supplied test environments for the duration of the Coordinated Disclosure Period, with public PoC release only after Vendor sign-off and a Vendor-elected safety window (typically 30 additional days).

## Article 11. Data Handling, Retention, and Destruction

11.1 **Encryption at rest and in transit.** All Findings, PoC Exploits, evidence, and Authorized Target copies are encrypted at rest using AES-256-GCM (or equivalent) with keys held in an HSM or KMS, and encrypted in transit using TLS 1.3 (or equivalent).

11.2 **Access logging.** All access to Findings is logged and auditable. Logs include user, timestamp, file, and action.

11.3 **Retention.** Operator retains Findings, PoC Exploits, and evidence for the period specified in the SOW, defaulting to **3 years** from Acceptance. After retention, Operator shall (a) cryptographically shred the encrypted data (destroy the key), or (b) physically destroy the storage media, with a written certification of destruction provided to the Vendor on request.

11.4 **Incident response.** In the event of a security incident affecting Findings or PoC Exploits, Operator shall (a) notify the Vendor within 72 hours (and, where required under GDPR Art. 33, the relevant supervisory authority within 72 hours, with the Vendor's cooperation), (b) provide a written incident report within 7 days, (c) cooperate with the Vendor's investigation, and (d) take reasonable remediation steps.

11.5 **No transfer to third parties.** Operator shall not transfer Findings or PoC Exploits to any third party (including cloud providers, subcontractors, or Affiliates) without (a) the Vendor's prior written consent and (b) a written agreement with the third party imposing confidentiality obligations no less protective than this Agreement.

11.6 **Subprocessors.** Operator maintains a list of subprocessors in Exhibit G. The Vendor may object to a subprocessor on reasonable grounds (e.g., conflict of interest, prior breach, jurisdiction-specific concerns), and the parties shall work in good faith to find an alternative.

11.7 **Cross-border data transfer.** Where Findings, PoC Exploits, or evidence contain personal data subject to cross-border transfer restrictions (e.g., GDPR Chapter V), Operator shall implement appropriate safeguards (Standard Contractual Clauses, adequacy decisions, or BCRs) as required by Applicable Law.

## Article 12. Conflicts of Interest; Non-Disparagement; Ethical Walls

12.1 **Conflicts.** Operator warrants that, as of the Effective Date, no Lab Personnel are subject to a non-compete, non-solicit, or confidentiality obligation owed to a competitor of any Vendor that would prevent their participation in the Engagements. Operator shall promptly disclose any actual or potential conflict of interest, including the engagement of an Operator employee or contractor by a competitor, a competitor's lawsuit against Operator, or the receipt by Operator of confidential information about a competitor from a current or former employee of that competitor.

12.2 **Ethical walls.** Where Operator conducts Engagements for two or more Vendors whose Authorized Targets are technically overlapping (e.g., multiple AC vendors, multiple AT vendors, multiple titles using the same engine), Operator shall erect **ethical walls** to prevent any Lab Personnel from working on both Engagements simultaneously. The ethical wall is described in Exhibit H.

  (a) **Volume II specific.** The following pairings are particularly subject to ethical-wall requirements under this Volume II:

    (i) **EA (SOW-X) ↔ Codemasters (SOW-X)** — given EA's ownership of Codemasters, the two SOWs may share technical substrate (the EGOS engine, EA's anti-cheat). Operator shall erect an ethical wall between the two Engagement teams.

    (ii) **Ubisoft BGE 20AE (SOW-X) ↔ Ubisoft POP:TC (SOW-X)** — same parent Vendor, different studios and engine stacks. An ethical wall is required only where the two Engagements share a technical overlap (e.g., a common Ubisoft Connect DRM flow); otherwise, parallel work is permitted.

    (iii) **Gearbox Borderlands 4 (SOW-X) ↔ 2K Launcher (SOW-X) ↔ Take-Two (SOW-X)** — the three SOWs are coordinated; an ethical wall is required where the Finding is title-specific to one SOW and would not be appropriate to leak into another.

    (iv) **Borderlands 4 (UE-based) ↔ Volume I UE-based titles** — where a Finding from Borderlands 4 (SOW-X) implicates a Volume I UE-based Authorized Target, ethical walls are erected between the two Engagement teams, and the cross-Vendor coordination procedures in Part IV govern.

12.3 **No disparagement.** During the term and for 2 years thereafter, neither party shall make any false or misleading statement about the other, the other party's products, or the security posture of the other party's Authorized Targets. Nothing in this clause restricts either party from making accurate, good-faith statements about resolved vulnerabilities, public CVEs, or publicly disclosed Findings.

12.4 **Independent judgment.** The Vendor is solely responsible for decisions about its products, including whether to patch, when to patch, and what to disclose. Operator's findings are advisory. The Vendor's decision to accept or reject a finding is its own.

12.5 **No poaching.** During the term and for 12 months thereafter, neither party shall solicit for employment any Lab Personnel of the other who materially participated in an Engagement. General job postings, recruiter outreach, and applications initiated by the individual are not solicitations.

12.6 **No cheats / hacks / piracy tools.** Notwithstanding any other provision of this Agreement, Operator warrants that it shall not, in the course of an Engagement against F1 25, BGE 20AE, Borderlands 4, or POP:TC, develop, test, refine, or distribute any cheat, hack, aimbot, wallhack, ESP, or similar tool whose primary purpose is to gain an unfair in-game advantage. PoC Exploits are limited to demonstrating Bypasses of the protection layer and shall not include gameplay manipulation.

## Article 13. Representations and Warranties

13.1 **Mutual.** Each party represents and warrants that (a) it has full corporate power and authority to enter into this Agreement, (b) the execution and performance of this Agreement does not violate any other agreement to which it is a party, and (c) it shall comply with all Applicable Law in its performance.

13.2 **Operator additional.** Operator represents and warrants that (a) it operates the Lab, (b) Lab Personnel have the skills and authority to perform Engagements, (c) Operator has not been convicted of any computer-misuse, fraud, or export-control offense in the preceding 10 years, (d) Operator is not on any U.S., EU, UK, French, or UN sanctions list, and (e) Operator maintains the insurance required by Section 4.9.

13.3 **Vendor additional.** Each Vendor represents and warrants that (a) it has the right and authority to grant the licenses and waivers in Article 3, (b) the Authorized Target is not, in whole or in part, misappropriated from a third party, (c) the Engagement does not contravene any law applicable to the Vendor (including anti-trust law and law applicable to its regulated products), and (d) where the Vendor is a French entity (Ubisoft) or a UK entity (Codemasters), the Vendor has obtained any internal or external authorizations required by French or UK law to bind itself to this Agreement.

13.4 **Disclaimer.** EXCEPT AS EXPRESSLY SET FORTH HEREIN, EACH PARTY DISCLAIMS ALL WARRANTIES, EXPRESS, IMPLIED, OR STATUTORY, INCLUDING THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. FINDINGS AND POC EXPLOITS ARE PROVIDED "AS IS" AND OPERATOR DOES NOT WARRANT THAT THE AUTHORIZED TARGET IS FREE OF VULNERABILITIES OR THAT THE POC EXPLOITS WILL FUNCTION ON ANY PARTICULAR CONFIGURATION.

13.5 **No guarantee of security.** The Vendor acknowledges that no security product is invulnerable. The Engagement is intended to identify and remediate vulnerabilities; it is not a guarantee that no vulnerabilities exist or will be discovered in the future.

## Article 14. Indemnification, Limitation of Liability, and Disclaimers

14.1 **Mutual indemnification.** Each party (as "**Indemnitor**") shall defend, indemnify, and hold harmless the other party and its Affiliates, officers, directors, employees, and agents (as "**Indemnitees**") from and against any third-party claim, demand, suit, action, or proceeding (a "**Claim**") arising out of (i) the Indemnitor's breach of this Agreement, (ii) the Indemnitor's gross negligence or willful misconduct, or (iii) the Indemnitor's violation of Applicable Law, and shall pay any losses, damages, fines, settlements, and reasonable legal fees finally awarded or agreed in settlement.

14.2 **Operator additional indemnification.** Operator shall additionally indemnify each Vendor Indemnitee against any Claim by a third party (including an end user, a regulator, or a competing vendor) arising directly from Operator's (i) breach of the SOW scope, (ii) unauthorized interaction with Vendor Systems (including EA's matchmaking, Ubisoft Connect entitlement, 2K Launcher, or SHiFT code systems), (iii) unauthorized distribution of PoC Exploits, or (iv) violation of the § 1201 release in Section 3.3.

14.3 **Vendor additional indemnification.** Each Vendor shall additionally indemnify Operator and Lab Personnel against any Claim by a third party (including a competing vendor, a trade group, or an anti-piracy organization) arising directly from the Vendor's (i) revocation of authorization in bad faith, (ii) breach of the covenant in Section 3.4, or (iii) unauthorized disclosure of Findings to a third party.

14.4 **Procedure.** The Indemnitee shall (a) promptly notify the Indemnitor of any Claim, (b) tender control of the defense and settlement to the Indemnitor (with counsel reasonably acceptable to the Indemnitee), and (c) provide reasonable cooperation. The Indemnitor shall not settle any Claim in a manner that imposes any non-monetary obligation on the Indemnitee or that includes any admission of wrongdoing by the Indemnitee, without the Indemnitee's prior written consent.

14.5 **Consequential damages disclaimer.** EXCEPT FOR (i) BREACH OF CONFIDENTIALITY UNDER ARTICLE 9, (ii) BREACH OF INTELLECTUAL PROPERTY UNDER ARTICLE 8, (iii) INDEMNIFICATION OBLIGATIONS UNDER SECTIONS 14.1, 14.2, AND 14.3, (iv) GROSS NEGLIGENCE OR WILLFUL MISCONDUCT, AND (v) BREACH OF ARTICLE 12 (CONFLICTS), IN NO EVENT SHALL EITHER PARTY BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, LOST REVENUE, LOSS OF GOODWILL, OR LOSS OF DATA, REGARDLESS OF THE THEORY OF LIABILITY AND EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

14.6 **Cap on liability.** EXCEPT FOR THE EXCLUSIONS IN SECTION 14.5, EACH PARTY'S AGGREGATE LIABILITY UNDER THIS AGREEMENT SHALL NOT EXCEED THE GREATER OF (a) THE TOTAL FEES PAID OR PAYABLE BY THE VENDOR TO OPERATOR UNDER THE APPLICABLE SOW IN THE 12 MONTHS PRECEDING THE CLAIM, OR (b) $5,000,000. THE PARTIES ACKNOWLEDGE THAT THE ALLOCATION OF RISK IN THIS ARTICLE 14 IS A MATERIAL PART OF THE BARGAIN.

14.7 **Insurance backstop.** The indemnification obligations are supported by the insurance maintained pursuant to Section 4.9, and Operator shall not, without the Vendor's prior written consent, materially reduce or cancel such insurance during the term.

## Article 15. Term, Termination, and Survival

15.1 **Term.** This Master Agreement begins on the Effective Date and continues for 36 months, automatically renewing for successive 12-month terms unless terminated in accordance with this Article 15.

15.2 **Termination for convenience.** Either party may terminate this Master Agreement or any SOW for convenience on 90 days' written notice. Termination of the Master Agreement does not automatically terminate a SOW unless the SOW itself is terminated.

15.3 **Termination for cause.** Either party may terminate this Master Agreement or any SOW for cause on 30 days' written notice if the other party materially breaches and fails to cure within the notice period. Material breaches include, without limitation, (a) breach of confidentiality, (b) breach of scope by Operator, (c) breach of authorization by Vendor, (d) insolvency or bankruptcy of either party, (e) change of control of either party to a competitor, and (f) violation of sanctions or export-control law.

15.4 **Suspension.** Each Vendor may suspend Operator's authorization with respect to its SOW on 24 hours' notice if, in the Vendor's reasonable judgment, Operator is conducting an activity that (a) endangers Vendor Systems or customers, (b) exceeds the scope of the SOW, or (c) is reasonably likely to cause reputational or security harm to the Vendor. Operator shall cooperate with the suspension, including immediate cessation of in-scope activity and preservation of state for forensic review.

15.5 **Effect of termination.** Upon termination of a SOW:

  (a) all in-scope Engagement activities cease, except as required to wind down in an orderly manner;

  (b) Operator delivers all unpaid Findings, PoC Exploits, and reports to the Vendor;

  (c) Operator destroys or returns all copies of the Authorized Target, PoC Exploits, and evidence, except as required for ongoing Coordinated Disclosure obligations or legal-hold purposes;

  (d) the Coordinated Disclosure Period for Findings already Accepted continues;

  (e) the Vendor remains obligated to pay undisputed fees for work performed prior to termination.

15.6 **Survival.** The following provisions survive termination: Articles 1 (Definitions), 3.6 (Reservation), 7.4 (Acceptance of pre-termination Findings), 8 (Intellectual Property), 9 (Confidentiality), 10 (Coordinated Disclosure), 11 (Data Handling), 12 (Conflicts), 13.4–13.5 (Disclaimers), 14 (Liability), 15.6, and 16 (General).

## Article 16. General Provisions

16.1 **Independent contractors.** The parties are independent contractors. Nothing in this Agreement creates a partnership, joint venture, agency, or employment relationship.

16.2 **Assignment.** Neither party may assign this Agreement without the other party's prior written consent, except that either party may assign to an Affiliate or to a successor in interest in connection with a merger, acquisition, or sale of substantially all assets, with notice to the other party. Any purported assignment in violation of this section is void.

16.3 **Notices.** Notices shall be in writing and delivered by hand, certified mail (return receipt requested), reputable overnight courier, or encrypted email to the addresses on the cover page. Notice is effective upon receipt.

16.4 **Force majeure.** Neither party is liable for delay or failure in performance (other than payment obligations) due to causes beyond its reasonable control, including acts of God, war, terrorism, civil unrest, government action, pandemic, internet failures, or large-scale cyber incidents affecting third-party infrastructure. The affected party shall give prompt notice and use commercially reasonable efforts to mitigate.

16.5 **Severability.** If any provision is held unenforceable, the remainder continues in effect, and the unenforceable provision shall be reformed to the minimum extent necessary to be enforceable.

16.6 **No waiver.** Failure or delay in exercising any right is not a waiver. A waiver in one instance does not waive the right in any other instance.

16.7 **Entire agreement.** This Agreement (Volume II), together with Volume I for the Vendors enumerated therein, constitutes the entire agreement between the parties with respect to the subject matter and supersedes all prior or contemporaneous agreements, oral or written, regarding the subject matter. For the avoidance of doubt, a Vendor's execution of this Volume II does not constitute a waiver of any rights under Volume I, and vice versa.

16.8 **Amendments.** Amendments must be in writing and signed by authorized representatives of both parties.

16.9 **Counterparts; e-signature.** This Agreement may be executed in counterparts, each of which is an original and which together constitute one instrument. E-signature (DocuSign, Adobe Sign, or analogous) is permitted and has the same effect as ink signature. For French entities, e-signature is permitted under the French *Code civil* art. 1366 et seq. and EU Regulation 910/2014 (eIDAS) when compliant.

16.10 **Headings.** Headings are for convenience only and do not affect interpretation.

16.11 **Construction.** "Including" means "including without limitation." "Days" means calendar days unless "business days" is specified. "Written" includes electronic writing.

16.12 **No third-party beneficiaries.** This Agreement is for the benefit of the parties only and creates no rights in any third party, except that Lab Personnel are third-party beneficiaries of Sections 3.3 and 3.4 and Article 9 with respect to their own conduct.

16.13 **Anti-piracy carve-out for academic research.** Notwithstanding any other provision, the parties acknowledge that bona fide academic research published in peer-reviewed venues, conducted without use of Vendor property beyond what is publicly available, and not involving circumvention of technical protection measures, is not within the scope of this Agreement and is not authorized hereunder. Vendor Policies continue to apply to such research.

16.14 **Language.** This Agreement is executed in English. Where the Vendor requires a French translation (for Ubisoft, pursuant to French *Code civil* art. 1366 et seq. for consumer-facing terms; this Agreement is B2B and not subject to the French consumer-language rule, but a courtesy translation may be provided), the English version controls in the event of conflict. For UK Vendors (Codemasters), the English version is canonical.

---

# PART II — STATEMENTS OF WORK (SOWs)

> Each SOW is incorporated by reference when executed by the parties. The SOWs share the structure of the Volume I SOW Template (Part II of MRTEA-2026-001); the SOWs below are filled in per Vendor.

## SOW-X — ELECTRONIC ARTS (F1 25 — Anti-Tamper, Anti-Cheat, EA DRM)

**Counterparty:** **Electronic Arts Inc.** ("EA") and its relevant Affiliates, including EA Sports.

**Authorized Targets:**

| Target ID | Product | Version Scope | Notes |
|---|---|---|---|
| F1-AT-01 | F1 25 (Iconic Edition) — main executable (Windows x64) | Latest GA + N-1 | Primary SKU |
| F1-AT-02 | F1 25 (Steam Deck / Linux via Proton) | Latest GA | Compatibility layer |
| F1-AT-03 | F1 25 (macOS, where supported) | Latest GA | Lab analysis |
| F1-AT-04 | F1 25 (PS5 / Xbox Series X\|S) | Latest GA | Static + dynamic in Lab on test hardware |
| F1-AT-05 | F1 25 mobile companion (F1 Life, F1 Clash, F1 Manager Mobile) | Latest GA | Lab analysis |
| F1-AT-06 | EA DRM layer ("DRMProtect" or successor) on F1 25 | Latest GA | Per-binary |
| F1-AC-01 | EA AntiCheat ("EAAC") on F1 25 | Latest GA | Kernel + user-mode |
| F1-EX-01 | EA license server / entitlement flow for F1 25 | Lab only | Emulator targets |
| F1-EX-02 | EA matchmaking / live-service endpoints for F1 25 | Lab only | Protocol analysis |

**Special Provisions:**

R.1 F1 25 is published by EA Sports / Codemasters under the EA umbrella. The Codemasters-specific engine layer (EGOS) is in-scope under SOW-X. The EA-specific protection layers (EAAC, DRMProtect, EA license server) are in-scope under this SOW. Findings that span both shall be coordinated.

R.2 F1 25 contains **multiplayer components**: ranked F1 World (online), league play, two-player career. Anti-cheat findings (EAAC) for the multiplayer component are in scope. The Vendor's live-service team shall be included in pre-publication review for any Finding affecting live-service components (per Article 10.8).

R.3 F1 25 uses the EGOS engine (Codemasters-developed). The EGOS engine protection layer is a Codemasters-developed technology; EGOS-specific findings flow through SOW-X. Where a Finding arises from the EA-wrapping of EGOS (e.g., a DRM call into the EGOS engine), it flows through this SOW.

R.4 EAAC's kernel-mode component, where present in F1 25, shall be loaded only in isolated Lab VMs. Production kernels are not in scope.

R.5 F1 25's "Iconic Edition" content is licensed under separate agreements (e.g., Formula 1 driver likeness rights, FIA branding, manufacturer IP). The protection layer is in-scope; the licensed content is out-of-scope and shall not be exposed in any public deliverable.

R.6 EA's internal codenames (e.g., pre-release codenames for F1 25's annual release, EAAC module names, internal class names) shall be redacted in any public deliverable.

R.7 The EA license / entitlement flow is in-scope for protocol analysis in the Lab. Production interaction with EA's Origin / EA app entitlement services is prohibited.

R.8 Where F1 25 includes a "Connected Single Player" mode (F1 World), PoC Exploits that affect the entitlement or progression flow of F1 World shall be subject to heightened publication scrutiny (Part V §3) and shall be released only with a defensive utility.

R.9 Operator shall not publish PoC Exploits that demonstrate a Bypass against a specific F1 25 player, EA Account, or live-service session. PoC Exploits are abstract or use a Vendor-supplied test binary.

R.10 Console SKUs (PS5, Xbox Series X|S) are in-scope for static and dynamic analysis on platform-supplied test hardware, in the Lab. The platform security boundary is out-of-scope; findings shall be redirected to the platform vendor with the Vendor's consent.

---

## SOW-X — CODEMASTERS (F1 25 — EGOS Engine Protection Layer)

**Counterparty:** **Codemasters Software Company Limited** ("Codemasters"), a UK company and wholly-owned subsidiary of Electronic Arts Inc. Codemasters and EA are joint and several counterparties; EA is the lead counterparty for IP and licensing; Codemasters is the lead counterparty for engine-level technical content.

**Authorized Targets:**

| Target ID | Product | Version Scope | Notes |
|---|---|---|---|
| F1-EGOS-01 | F1 25 — EGOS engine (Windows) | Latest GA + N-1 | Engine-level protection |
| F1-EGOS-02 | F1 25 — EGOS engine (PS5 / Xbox) | Latest GA | Lab analysis on test hardware |
| F1-EGOS-03 | F1 24, F1 23, F1 22 (legacy EGOS) | Each Latest GA | For version-delta and regression testing |
| F1-EGOS-04 | EGOS engine protection primitives (custom VM, integrity checks, anti-debug) | Latest GA | Engine-level |
| F1-EGOS-05 | Codemasters' custom anti-tamper / anti-debug layer ("CM Guard" or similar) | Latest GA | Proprietary |

**Special Provisions:**

S.1 Codemasters' proprietary engine-level protection — the EGOS engine's integrity checks, anti-debug routines, custom code virtualization (where present), and similar — is in-scope as a separate Authorized Target. Internal codenames (e.g., "CM Guard") shall be redacted in any public deliverable.

S.2 Where F1 25 uses Denuvo, the Denuvo-specific findings flow through SOW-X of Volume I. Codemasters' non-Denuvo protections are in-scope under this SOW.

S.3 Where F1 25 uses VMProtect, the VMProtect-specific findings flow through SOW-X of Volume I.

S.4 Codemasters is a UK company. UK law applies; Section 5.2(b) of Part I is incorporated herein by reference. The UK Computer Misuse Act 1990 is expressly covered by the covenant in Section 3.4.

S.5 The EGOS engine's lineage includes the EGO engine (used in DiRT, GRID, ONRUSH, F1 2017–2021). Findings specific to the legacy EGO engine are out-of-scope of this SOW and shall be redirected to a separate engagement if the Vendor wishes. Findings specific to EGOS (the successor) are in-scope.

S.6 Codemasters' pre-release codenames for F1 25 (e.g., internal project names, internal class names) shall be redacted in any public deliverable.

S.7 The F1 25 telemetry and physics-replay layer is in-scope for analysis. Production interaction with Codemasters' telemetry endpoints is prohibited.

S.8 Operator shall not publish PoC Exploits that demonstrate a Bypass against a specific F1 25 save file, race replay, or licensed content (e.g., licensed driver likeness). PoC Exploits are limited to Bypasses of the protection layer.

S.9 EA is the lead counterparty for IP and licensing, including any licensed F1, FIA, Formula 1 driver, or manufacturer IP. Findings about the licensed IP (driver names, livery, team liveries, etc.) are out-of-scope and shall not be included in any deliverable.

S.10 Where a Finding arises from a shared EGOS subsystem also affecting a non-F1 Codemasters title (e.g., DiRT Rally, GRID Legends), the parties shall coordinate with the title publisher; the EGOS engine layer itself is in-scope of this SOW, but the title-specific content is not.

---

## SOW-X — UBISOFT (Beyond Good and Evil - 20th Anniversary Edition)

**Counterparty:** **Ubisoft Entertainment S.A.** ("Ubisoft"), a French *société anonyme* with corporate seat in Saint-Mandé, France, and its relevant Affiliates, including Ubisoft Montpellier (the development studio) and Ubisoft Milan (involved in the remaster).

**Authorized Targets:**

| Target ID | Product | Version Scope | Notes |
|---|---|---|---|
| BGE-AT-01 | Beyond Good and Evil - 20th Anniversary Edition (Windows x64) | Latest GA + N-1 | Primary SKU (remaster) |
| BGE-AT-02 | Beyond Good and Evil - 20th Anniversary Edition (PS5 / Xbox Series X\|S) | Latest GA | Static + dynamic in Lab on test hardware |
| BGE-AT-03 | Beyond Good and Evil - 20th Anniversary Edition (Switch 2 / Switch) | Latest GA | Static + dynamic in Lab on test hardware |
| BGE-AT-04 | BGE 20AE engine stack (Dunia / Anvil lineage) | Latest GA | Engine-level |
| BGE-AT-05 | Ubisoft DRM layer (Uplay / Ubisoft Connect) on BGE 20AE | Latest GA | Per-binary |
| BGE-AT-06 | Ubisoft Anti-Cheat (where present on BGE 20AE) | Latest GA | User-mode |
| BGE-EX-01 | Ubisoft Connect entitlement / license flow for BGE 20AE | Lab only | Protocol analysis |

**Special Provisions:**

T.1 Beyond Good and Evil - 20th Anniversary Edition is a 2024 remaster of the 2003 original. The protection layer is the **2024 retail protection**, not the 2003 original's protection (which is no longer in production). The 2003 original's protection is out-of-scope.

T.2 Ubisoft Entertainment S.A. is a French *société anonyme*. French law applies; Section 5.2(a) of Part I is incorporated herein by reference. French *Code pénal* art. 323-1 et seq. and French *Code de la propriété intellectuelle* are expressly covered by the covenants in Sections 3.4 and 9.6.

T.3 The remaster is built on a Dunia / Anvil-lineage engine. The engine-level protection (custom anti-debug, custom integrity checks, runtime mutation) is in-scope. Engine licensor IP (where any engine technology is licensed from a third party) is out-of-scope and shall be redirected to the engine licensor with the Vendor's consent.

T.4 Where BGE 20AE uses Denuvo, the Denuvo-specific findings flow through SOW-X of Volume I.

T.5 Ubisoft Connect (formerly Uplay / Uplay+ / Ubisoft+) is the entitlement / DRM platform. The BGE 20AE integration with Ubisoft Connect is in-scope for protocol analysis in the Lab. Production interaction with Ubisoft Connect entitlement services is prohibited.

T.6 Where Ubisoft Anti-Cheat is present on BGE 20AE, its user-mode and (where applicable) kernel-mode components are in-scope for Lab analysis. The kernel driver, where present, shall be loaded only in isolated Lab VMs.

T.7 BGE 20AE is a single-player title. The "multiplayer" component of the original BGE (which was largely unused) is not present in the remaster; AC findings (if any) are limited to AC integration SDK calls, not gameplay-side AC.

T.8 Ubisoft's internal codenames (e.g., pre-release project names for BGE 20AE, internal class names, internal Ubisoft Connect module names) shall be redacted in any public deliverable.

T.9 The Michel Ancel / Raymond Pagès / Frédéric Raynal creative-team IP is acknowledged. Operator shall not, in any deliverable, expose creative-team codenames, internal studio designations, or internal creative-process documents beyond what is necessary to demonstrate a Bypass.

T.10 The BGE IP (characters, locations, music, narrative) is acknowledged; Operator shall not, in any public deliverable, include BGE character names, location names, or plot details beyond what is strictly necessary to identify the Authorized Target version. The title "Beyond Good and Evil - 20th Anniversary Edition" may be used for context.

T.11 Operator shall not publish PoC Exploits that demonstrate a Bypass against a specific BGE 20AE save file, player profile, or Ubisoft Connect account. PoC Exploits are abstract or use a Vendor-supplied test binary.

T.12 BGE 20AE is a 2024 remaster; findings specific to the remaster's protection may cross-reference the original 2003 protection for educational context, but the original protection is out-of-scope and shall not be analyzed as part of this Engagement.

---

## SOW-X — UBISOFT (Prince of Persia: The Lost Crown)

**Counterparty:** **Ubisoft Entertainment S.A.** ("Ubisoft") and its relevant Affiliates, including Ubisoft Montpellier (the development studio). This SOW is parallel to and severable from SOW-X.

**Authorized Targets:**

| Target ID | Product | Version Scope | Notes |
|---|---|---|---|
| POP-AT-01 | Prince of Persia: The Lost Crown (Windows) | Latest GA + N-1 | Primary SKU |
| POP-AT-02 | Prince of Persia: The Lost Crown (PS5 / Xbox Series X\|S) | Latest GA | Lab analysis on test hardware |
| POP-AT-03 | Prince of Persia: The Lost Crown (Switch) | Latest GA | Lab analysis on test hardware |
| POP-AT-04 | POP:TC engine stack (Unity-based, custom shaders) | Latest GA | Engine-level + Unity layer |
| POP-AT-05 | Ubisoft DRM layer (Ubisoft Connect) on POP:TC | Latest GA | Per-binary |
| POP-AT-06 | Ubisoft Anti-Cheat (where present on POP:TC) | Latest GA | User-mode |
| POP-AT-07 | Ubisoft IL2CPP metadata / managed-code wrapping (where present) | Latest GA | Unity-side |
| POP-EX-01 | Ubisoft Connect entitlement / license flow for POP:TC | Lab only | Protocol analysis |

**Special Provisions:**

U.1 Prince of Persia: The Lost Crown is built on a **Unity-based engine stack**. Unity-Engine-specific findings (e.g., IL2CPP-managed-code wrapping, Unity Asset Bundle integrity) are in-scope. Findings about the **Unity Engine itself** (out-of-scope as third-party engine IP, per Section 8.7) shall be redirected to Unity's disclosure program with the Vendor's consent.

U.2 Ubisoft is the lead counterparty; Ubisoft Montpellier is the development studio. Ubisoft's internal codenames (e.g., pre-release project names for POP:TC, internal class names) shall be redacted in any public deliverable.

U.3 Where POP:TC uses Denuvo, the Denuvo-specific findings flow through SOW-X of Volume I. As of the Effective Date, POP:TC is not known to use Denuvo; if it does, the parties shall consult.

U.4 Ubisoft Connect integration is in-scope for protocol analysis in the Lab. Production interaction with Ubisoft Connect entitlement services is prohibited.

U.5 POP:TC is a single-player title. There is no multiplayer anti-cheat. AC findings (if any) are limited to AC integration SDK calls, not gameplay-side AC.

U.6 The POP franchise IP (the Prince, time-manipulation mechanics, Mount Damavand, etc.) is acknowledged; Operator shall not, in any public deliverable, include franchise IP beyond what is strictly necessary to identify the Authorized Target version. The title "Prince of Persia: The Lost Crown" may be used for context.

U.7 Operator shall not publish PoC Exploits that target a specific POP:TC save file, player progression, or Ubisoft Connect account. PoC Exploits are limited to Bypasses of the protection layer.

U.8 Where POP:TC uses Unity Asset Bundle encryption, custom-shader integrity checks, or similar engine-level protection specific to Ubisoft's wrapping, that wrapping is in-scope. The underlying Unity mechanisms are out-of-scope.

U.9 The Lost Crown is a 2024 release; pre-release codenames (e.g., internal Ubisoft Montpellier project names) shall be redacted.

U.10 The French-law and ethical-wall provisions of SOW-X (Section T.2 and Section 12.2(a)(ii) of Part I) apply to this SOW.

U.11 Cross-SOW coordination (SOW-X ↔ SOW-X): because both SOWs are Ubisoft, findings that span both BGE 20AE and POP:TC (e.g., a common Ubisoft Connect DRM flow, a common Ubisoft Anti-Cheat SDK call) shall be coordinated. The SOW that first identifies the Finding governs the technical narrative; the second SOW cross-references the Finding.

---

## SOW-X — GEARBOX (Borderlands 4 — Engine and Custom Anti-Tamper)

**Counterparty:** **Gearbox Entertainment, L.P.** ("Gearbox"), the developer of Borderlands 4. Gearbox Software is the development studio; Gearbox Publishing (a Take-Two subsidiary) is the publisher of record. This SOW covers the engine-level and custom anti-tamper layers.

**Authorized Targets:**

| Target ID | Product | Version Scope | Notes |
|---|---|---|---|
| BL4-AT-01 | Borderlands 4 main executable (Windows x64) | Latest GA + N-1 | Primary SKU |
| BL4-AT-02 | Borderlands 4 (Steam Deck / Linux via Proton) | Latest GA | Compatibility layer |
| BL4-AT-03 | Borderlands 4 (PS5 / Xbox Series X\|S) | Latest GA | Lab analysis on test hardware |
| BL4-AT-04 | Borderlands 4 (macOS, where supported) | Latest GA | Lab analysis |
| BL4-AT-05 | Unreal Engine protection layer on Borderlands 4 | Latest GA | UE-version-specific |
| BL4-AT-06 | Gearbox custom anti-tamper ("GBX Guard" or similar) | Latest GA | Proprietary |
| BL4-AT-07 | Borderlands 4 entitlement / SHiFT code system | Lab only | Protocol analysis |
| BL4-EX-01 | Borderlands 4 matchmaking / live-service endpoints | Lab only | Protocol analysis |

**Special Provisions:**

V.1 Borderlands 4 is built on **Unreal Engine** (UE-version to be specified in the executed SOW). The engine-level protection (UE-packaged binaries, UE integrity checks, UE anti-debug) is in-scope. The UE engine itself is out-of-scope as third-party engine IP (per Section 8.7) and shall be redirected to Epic's disclosure program with the Vendor's consent.

V.2 Gearbox's custom anti-tamper ("GBX Guard" or similar internal codename) is in-scope as a separate Authorized Target. Internal codenames shall be redacted in any public deliverable.

V.3 Where Borderlands 4 uses Denuvo, the Denuvo-specific findings flow through SOW-X of Volume I.

V.4 Where Borderlands 4 uses VMProtect, the VMProtect-specific findings flow through SOW-X of Volume I.

V.5 Where Borderlands 4 uses EAC (Easy Anti-Cheat), the EAC-specific findings flow through SOW-X of Volume I.

V.6 Where Borderlands 4 uses BattlEye, the BattlEye-specific findings flow through SOW-X of Volume I.

V.7 The SHiFT code system is Gearbox's entitlement / promotional-code platform. The SHiFT protocol is in-scope for protocol analysis in the Lab. Production interaction with the SHiFT redemption endpoint is prohibited.

V.8 Borderlands 4 is a **live-service, multiplayer title** with online co-op and competitive endgame. Anti-cheat findings for the multiplayer component are in scope. The Vendor's live-service team shall be included in pre-publication review for any Finding affecting live-service components (per Article 10.8). PoC Exploits against live-service components are subject to the heightened publication scrutiny in Part V §3.

V.9 Gearbox Software has UK operations (Gearbox Software London, formerly People Can Fly London / additional studio) and US operations (Frisco, Texas; Quincy, Massachusetts). Both jurisdictions are covered by Section 5.2(c) (US) and Section 5.2(b) (UK).

V.10 The Borderlands franchise IP (Vault Hunters, the Vaults, Pandora, characters) is acknowledged; Operator shall not, in any public deliverable, include franchise IP beyond what is strictly necessary to identify the Authorized Target version. The title "Borderlands 4" may be used for context.

V.11 Operator shall not publish PoC Exploits that demonstrate a Bypass against a specific Borderlands 4 player, SHiFT account, or live-service session. PoC Exploits are abstract or use a Vendor-supplied test binary.

V.12 The 2K Launcher (SOW-X) is the launch platform for Borderlands 4 on PC. Launcher-specific findings flow through SOW-X; game-specific findings flow through this SOW. Where a Finding spans both, the parties shall coordinate.

V.13 Console SKUs (PS5, Xbox Series X|S) are in-scope for static and dynamic analysis on platform-supplied test hardware, in the Lab. The platform security boundary is out-of-scope; findings shall be redirected to the platform vendor with the Vendor's consent.

V.14 The Borderlands series' lineage includes Borderlands (2009), Borderlands 2 (2012), Borderlands: The Pre-Sequel (2014), Borderlands 3 (2019), and Tiny Tina's Wonderlands (2022). Findings specific to legacy titles are out-of-scope of this SOW and shall be redirected to a separate engagement if the Vendor wishes.

---

## SOW-X — 2K GAMES (Borderlands 4 — 2K Launcher, 2K Entitlement)

**Counterparty:** **2K Games, Inc.** ("2K"), a wholly-owned subsidiary of Take-Two Interactive Software, Inc. 2K is the publisher of Borderlands 4 (alongside Gearbox Publishing).

**Authorized Targets:**

| Target ID | Product | Version Scope | Notes |
|---|---|---|---|
| BL4-2K-01 | 2K Launcher (Windows) | Latest GA | Launcher-specific |
| BL4-2K-02 | 2K Launcher (macOS, where supported) | Latest GA | Launcher-specific |
| BL4-2K-03 | 2K entitlement / license flow for Borderlands 4 | Lab only | Protocol analysis |
| BL4-2K-04 | 2K DRM layer (where separate from launcher) | Latest GA | Per-binary |
| BL4-2K-05 | 2K cloud-save / cross-progression flow | Lab only | Protocol analysis |
| BL4-2K-06 | 2K-published titles (excluding Borderlands 4 game-side) | N/A | Out-of-scope (separate engagement if Vendor wishes) |

**Special Provisions:**

W.1 The 2K Launcher is the entitlement / DRM launch platform for Borderlands 4 on PC. Launcher-specific findings (e.g., launcher-level integrity checks, launcher-level entitlement-token handling) are in-scope under this SOW.

W.2 Where the 2K Launcher wraps the Borderlands 4 game executable and the 2K Launcher applies an entitlement-binding check, the entitlement-binding check is in-scope. The game-side protection is in-scope under SOW-X (Gearbox).

W.3 2K is a Take-Two subsidiary. The parent-level coordination in SOW-X (Take-Two) applies.

W.4 The 2K Launcher is also used for other 2K titles (e.g., NBA 2K, Civilization, BioShock, XCOM). Findings specific to other 2K titles' launcher integration are out-of-scope of this SOW and shall be redirected to a separate engagement if 2K wishes.

W.5 2K's internal codenames (e.g., pre-release project names for Borderlands 4, internal launcher module names) shall be redacted in any public deliverable.

W.6 2K's entitlement flow is in-scope for protocol analysis in the Lab. Production interaction with 2K's entitlement services is prohibited.

W.7 Operator shall not publish PoC Exploits that demonstrate a Bypass against a specific 2K account, Borderlands 4 cross-progression data, or 2K launcher license. PoC Exploits are abstract or use a Vendor-supplied test binary.

W.8 The 2K Launcher is a 2K product; findings about the launcher are 2K IP. Operator shall not incorporate the 2K Launcher Findings into any Heretek Product in a manner that would enable a third party to bypass 2K launcher protections (per Section 3.9(c)(iv) of Part I, as incorporated by Section 3.9 of this Agreement).

---

## SOW-X — TAKE-TWO INTERACTIVE (Parent-Level Coordination)

**Counterparty:** **Take-Two Interactive Software, Inc.** ("Take-Two"), the parent company of 2K Games, Gearbox Publishing, Rockstar Games, Private Division, and other subsidiaries. This SOW is a parent-level coordination SOW, not a separate Authorized Target.

**Special Provisions:**

X.1 Take-Two is not a direct counterparty for any specific Authorized Target under this Volume II. Take-Two is the parent of 2K (SOW-X) and Gearbox Publishing (which co-publishes Borderlands 4 with 2K; the developer-side SOW is SOW-X with Gearbox Entertainment, L.P.). This SOW establishes parent-level coordination, IP rights flow-down, and cross-subsidiary Findings handling.

X.2 Take-Two's role is limited to: (a) confirming that 2K and Gearbox Publishing have the corporate authority to grant the licenses and waivers in Article 3 with respect to Borderlands 4, (b) coordinating cross-subsidiary Findings where the same Finding implicates 2K and Gearbox Publishing, and (c) coordinating with other Take-Two subsidiaries (e.g., Rockstar) where the Finding has cross-publisher implications.

X.3 Take-Two's internal codenames (e.g., pre-release codenames for Borderlands 4 at the corporate level, internal Take-Two security-team designations) shall be redacted in any public deliverable.

X.4 Take-Two does not, by signing this SOW, authorize any new Findings or Engagements beyond the cross-subsidiary coordination described in X.2. The SOWs of record for Borderlands 4 are SOW-X (Gearbox developer-side), SOW-X (2K publisher-side), and, where applicable, SOWs in Volume I (Denuvo, EAC, BattlEye, etc.).

X.5 Take-Two is the canonical CN-authority coordinator for cross-subsidiary CVEs; Operator shall coordinate CVE assignment through Take-Two's central security team where the same Finding affects multiple Take-Two subsidiaries.

X.6 This SOW may be terminated by Take-Two for convenience on 30 days' notice; the SOWs of record (SOW-X, SOW-X) remain in effect.

---

# PART III — MASTER RULES OF ENGAGEMENT (RoE)

The Master Rules of Engagement apply to all Engagements under this Volume II absent specific deviation in a SOW. The RoE of MRTEA-2026-001 (Volume I) Part III § 1–6 are incorporated herein by reference and govern the Engagements under this Volume II, **mutatis mutandis**, with the following Volume II-specific elaborations:

## §1. Engagement Lifecycle

1.1 **Initiation.** SOW execution → scoping call (10 business days) → pre-engagement package (15 business days) → kickoff → Engagement.

1.2 **Conduct.** Engagement in accordance with SOW, RoE, and Operator's internal security policy.

1.3 **Reporting.** Findings delivered on rolling or final basis, per SOW.

1.4 **Reproduction.** Vendor has 30 days to attempt reproduction.

1.5 **Acceptance.** Vendor accepts or disputes within 30 days.

1.6 **Disclosure.** Coordinated Disclosure Period begins on Acceptance.

1.7 **Closure.** Findings remediated, disclosed publicly, and Engagement closed.

## §2. Test Environment

2.1 **Default environment.** Lab-only, isolated from production.

2.2 **Test binaries.** Vendor provides test binaries where applicable; otherwise, Operator acquires from legitimate channels (purchased retail, public EA Account / Ubisoft Connect / Steam / EGS account, etc.).

2.3 **Test infrastructure.** Test license servers, telemetry endpoints, etc., may be emulated in the Lab. The following test emulators are explicitly in-scope for this Volume II, subject to SOW and Vendor approval:

  (a) **EA license server emulator** — for F1 25 EAAC / EA DRM / EA entitlement (SOW-X);

  (b) **Ubisoft Connect emulator** — for BGE 20AE and POP:TC Ubisoft Connect entitlement (SOW-X, SOW-X);

  (c) **2K Launcher / 2K entitlement emulator** — for Borderlands 4 (SOW-X);

  (d) **SHiFT code redemption emulator** — for Borderlands 4 (SOW-X);

  (e) **EAAC server emulator** — for F1 25 EAAC, where applicable (SOW-X).

2.4 **Hardware.** Lab includes physical and virtual hardware, including:
  - air-gapped Windows x64 workstations (instrumented with WinDbg, HyperDbg, etc.)
  - Linux x64 / ARM64 (instrumented with GDB + GEF, perf, eBPF)
  - macOS / iOS test devices (jailbroken, with Frida, etc.)
  - Android test devices (rooted, with Frida, etc.)
  - PlayStation 5 test hardware (where available under a separate Sony developer-license agreement)
  - Xbox Series X|S test hardware (where available under a separate Microsoft developer-license agreement)
  - Switch / Switch 2 test hardware (where available under a separate Nintendo developer-license agreement)
  - License-server emulators (EA, Ubisoft Connect, 2K, SHiFT, as enumerated in 2.3)
  - TPM / Secure Enclave / HSM emulators as needed
  - Network-isolated cluster for symbolic execution (Triton, angr, KLEE)

2.5 **Cryptographic / hardware.** Where Authorized Targets use hardware roots of trust (TPM, Secure Enclave, TrustZone, console secure boot), Operator may use software emulators or test hardware provided by the Vendor; production hardware is not required.

## §3. Communication

3.1 **Primary channel.** Encrypted email (PGP / S/MIME) and a designated secure portal.

3.2 **Real-time channel.** Encrypted chat (Signal with disappearing messages, or a Vendor-provided Slack/Teams with end-to-end encryption).

3.3 **Vulnerability disclosure channel.** Vendor's preferred intake. For the Volume II Vendors:
  - EA: security@ea.com (or the EA Bug Bounty program if Vendor elects to use it)
  - Codemasters: security@codemasters.com (or as designated in the executed SOW)
  - Ubisoft: Ubisoft's bug-bounty platform (e.g., Intigriti / Bugcrowd / direct intake)
  - Gearbox: security@gearboxsoftware.com (or as designated in the executed SOW)
  - 2K: security@2k.com (or as designated in the executed SOW)
  - Take-Two: security@take2games.com (parent-level escalation only)

3.4 **Escalation.** In case of a critical Finding, Operator shall escalate to Vendor's CISO or designated security lead within **24 hours** of confirmation. For live-service titles (F1 25 multiplayer, Borderlands 4 multiplayer), escalation includes the Vendor's live-service team.

## §4. Emergency Stop

4.1 **Right to stop.** Each party may invoke an emergency stop on 0-hour notice if it reasonably believes the Engagement is causing or is about to cause material harm.

4.2 **Effect.** All in-scope activity halts. The parties convene within 24 hours to discuss. The SOW resumes only on written agreement.

4.3 **Preservation.** On emergency stop, all state is preserved (logs, traces, partial results) for joint forensic review.

## §5. Out-of-Bounds Behavior

5.1 **Prohibited without exception.** The following are prohibited regardless of SOW scope:

  (a) attacks on Vendor production infrastructure (EA's matchmaking, Ubisoft Connect entitlement, 2K Launcher, SHiFT code system, etc.);

  (b) attacks on Vendor employees (social engineering, phishing, physical);

  (c) attacks on third-party upstream dependencies (operating systems, hypervisors, libraries) beyond what's necessary to defeat the Authorized Target;

  (d) attacks on the Vendor's other customers, end users, or licensees (e.g., other F1 25 players, other BGE 20AE players, other Borderlands 4 players, other POP:TC players);

  (e) exfiltration, sale, or transfer of any Finding, PoC Exploit, or Confidential Information to any third party not bound by this Agreement;

  (f) modification, destruction, or degradation of Vendor Systems;

  (g) denial-of-service testing;

  (h) ransomware or destructive payload development;

  (i) supply-chain compromise;

  (j) weaponization of any Finding in a manner that would enable a third party to defeat a Vendor's protection;

  (k) **specific to F1 25:** any use of a PoC Exploit to enter a competitive F1 World / F1 25 ranked match;

  (l) **specific to Borderlands 4:** any use of a PoC Exploit in a public Borderlands 4 co-op or competitive session, or in a session that includes other players' progression data;

  (m) **specific to BGE 20AE and POP:TC:** any use of a PoC Exploit against a Ubisoft Connect-linked session or against a save file containing other players' progression data (where applicable).

5.2 **Permitted with care.** The following are permitted under controlled conditions:

  (a) static and dynamic analysis of the Authorized Target in the Lab;

  (b) symbolic execution, taint analysis, and constraint solving against the Authorized Target;

  (c) patching / hooking / instrumentation of Authorized Target copies in the Lab;

  (d) side-channel analysis on the Vendor's own binaries (cache, branch, power, EM) in the Lab;

  (e) emulation of Vendor-provided test hardware in the Lab;

  (f) development of PoC Exploits that demonstrate Bypass under controlled conditions;

  (g) **specific to F1 25:** analysis of the EAAC kernel driver in the Lab, with the driver loaded only in an isolated Lab VM;

  (h) **specific to Borderlands 4:** analysis of the SHiFT code redemption flow against an emulated SHiFT endpoint, in the Lab.

5.3 **Permitted with notice.** The following require 24-hour notice to the Vendor and Vendor's written approval:

  (a) any interaction with a Vendor-controlled environment (e.g., EA license server, Ubisoft Connect entitlement, 2K Launcher entitlement, SHiFT code redemption) beyond pure protocol analysis;

  (b) any testing that requires multiple concurrent sessions on a Vendor's live service;

  (c) any testing that may generate notable telemetry on a Vendor's live service.

5.4 **Right to inspect the Lab.** Each Vendor may, on 30 days' notice and not more than once per year, send a representative (bound by confidentiality obligations no less protective than this Agreement) to inspect the Lab, the Lab's audit logs, and the Lab's controls. The inspection is at the Vendor's expense and subject to Operator's reasonable security policies.

## §6. Specific to the Authorized Targets in this Volume II

6.1 **F1 25 (SOW-X, SOW-X).** F1 25 is a flagship annual racing title published by EA Sports. The annual release cadence means Findings from F1 24 may regress in F1 25 and vice versa; the SOWs shall specify a "delta" component for year-over-year version-delta testing.

6.2 **BGE 20AE (SOW-X).** BGE 20AE is a 2024 remaster of a 2003 title. The remaster's protection is in-scope; the original 2003 title's protection is out-of-scope. The remaster includes both legacy content and new content (the Anniversary content); both are part of the same Authorized Target binary and the SOW covers both.

6.3 **POP:TC (SOW-X).** POP:TC is built on a Unity-based engine stack. Unity-specific findings (where the Finding is about the integration rather than the engine itself) are in-scope; pure Unity-Engine findings are out-of-scope.

6.4 **Borderlands 4 (SOW-X, SOW-X, SOW-X).** Borderlands 4 is a live-service, multiplayer title with cross-progression and online co-op. Findings affecting live-service components require heightened coordination (per Article 10.8). The 2K Launcher integration (SOW-X) is the launch-time DRM; the Gearbox custom anti-tamper (SOW-X) is the runtime protection; both are in-scope of their respective SOWs.

---

# PART IV — COORDINATED DISCLOSURE (CROSS-VENDOR)

The default Coordinated Disclosure rules of MRTEA-2026-001 (Volume I) Part IV govern. This Part IV supplements those rules for cross-Vendor Findings, where the same Finding (or a closely related Finding) implicates multiple Vendors within this Volume II, or across this Volume II and Volume I.

## §1. Default

1.1 The default Coordinated Disclosure Period is 180 days from Acceptance, with Vendor-elected acceleration to 90 days, and Vendor-elected extension (with Operator's reasonable consent) to 24 months.

## §2. Cross-Vendor Findings under this Volume II

2.1 **Identification.** When Operator identifies a Finding that affects multiple Vendors under this Volume II, Operator shall notify each affected Vendor in writing, with a clear description of the Finding, the affected Authorized Target(s), and the proposed technical narrative.

2.2 **Independent clocks.** Each Vendor's Coordinated Disclosure Period runs independently. A Vendor's acceptance or rejection does not bind any other Vendor.

2.3 **Consistent narrative.** The parties shall use commercially reasonable efforts to ensure that the technical narrative is consistent across Vendors, subject to each Vendor's right to redact its own Confidential Information and internal codenames.

2.4 **Public release.** Public release is permitted only when the latest-expiring Coordinated Disclosure Period has expired, unless all affected Vendors consent in writing to earlier release.

## §3. Cross-Volume Findings

3.1 Where a Finding under this Volume II implicates a Vendor under Volume I, the parties shall follow the procedures in this Part IV and the parallel procedures in Volume I.

3.2 The Operator is responsible for tracking which Volume / which SOW covers each affected Vendor.

3.3 Example: a Finding about Unreal Engine integrity checks in Borderlands 4 (SOW-X) that also affects a Volume I title built on the same UE version — the parties (Gearbox and the Volume I Vendor) shall coordinate the public release date as the later of the two Vendor's Coordinated Disclosure Periods.

## §4. CVE Coordination

4.1 Operator assigns CVEs through an authorized CVE Numbering Authority (CNA) or coordinates assignment through the Vendor's CNA. For cross-Vendor Findings, a single CVE may be assigned with multiple affected products, or multiple CVEs may be assigned (one per Vendor), at the Operator's election and with each Vendor's consent.

## §5. Special-Purpose Coordinated Disclosure Triggers

5.1 **Live-service critical Findings.** For Findings affecting F1 25 multiplayer, Borderlands 4 live-service, or BGE 20AE / POP:TC Ubisoft Connect, the Coordinated Disclosure Period may be reduced to **30 days** with Vendor election, due to the immediate exposure of players.

5.2 **Catastrophic Findings.** For Findings that, in the Vendor's reasonable judgment, are catastrophic (e.g., a complete bypass of the entire protection scheme in a single shot, with a working public PoC, and active exploitation in the wild), the Coordinated Disclosure Period may be reduced to **0 days** by mutual written agreement, with public release coordinated in real time.

5.3 **Slow-track for architectural changes.** For Findings that require architectural changes (e.g., a Finding that requires Ubisoft to redesign the Ubisoft Connect DRM flow), the Coordinated Disclosure Period may be extended to **24 months** with the Operator's reasonable consent, and the Vendor shall provide quarterly progress updates to the Operator.

## §6. Embargo

6.1 Until public release, all Findings, PoC Exploits, and technical details are Embargoed Information. The Operator shall not share Embargoed Information with any third party not bound by this Agreement (or, for cross-Volume Findings, by both this Volume II and Volume I).

6.2 Each Vendor may, in writing, release the Operator from the Embargo with respect to a specific Finding, in whole or in part. The release may be conditional (e.g., the release applies only to abstract PoC variants, not to full PoC Exploits).

---

# PART V — POC EXPLOIT STANDARDS

The default PoC Exploit standards of MRTEA-2026-001 (Volume I) Part V are incorporated herein by reference and govern, **mutatis mutandis**. The following Volume II-specific elaborations apply.

## §1. Whole-Product Bypass

1.1 A "**Whole-Product Bypass**" is a Bypass that defeats the entire protection scheme of an Authorized Target in a single, easily reproducible step. Examples in this Volume II include:

  (a) a single PoC that fully removes EA DRM from F1 25 and produces a fully playable offline copy;

  (b) a single PoC that fully removes Ubisoft Connect DRM from BGE 20AE and produces a fully playable offline copy;

  (c) a single PoC that fully removes Ubisoft Connect DRM from POP:TC and produces a fully playable offline copy;

  (d) a single PoC that fully removes the 2K Launcher / Gearbox custom AT from Borderlands 4 and produces a fully playable offline copy.

1.2 Whole-Product Bypasses are subject to the heightened publication scrutiny in Section 3 of Part V. Whole-Product Bypasses may be **delivered to the Vendor only** and shall not be published publicly without the Vendor's express written consent.

1.3 The Whole-Product Bypass commercialization restriction in Volume I § 3.9(c)(v) (incorporated by Section 3.9 of this Agreement) applies with full force to Findings under this Volume II.

## §2. Anti-Cheat Findings — Specific to this Volume II

2.1 Anti-Cheat Findings (e.g., EAAC Bypass on F1 25, EAC Bypass on Borderlands 4, BattlEye Bypass on Borderlands 4, Ubisoft Anti-Cheat Bypass on BGE 20AE / POP:TC) are subject to heightened publication scrutiny (Section 3 of Part V).

2.2 AC Findings may, at the Vendor's election, be subject to a **defensive-utility requirement**: the PoC Exploit shall be released with a defensive utility (e.g., a detection rule, a hardening guide, a defender-side tool) that vendors may distribute to other AC clients or to players.

2.3 AC Findings that defeat an entire AC vendor's product (e.g., a Bypass that works against EAC in any game, not just Borderlands 4) are cross-Vendor Findings and are coordinated with the AC vendor's SOW (SOW-X for EAC, SOW-X for BattlEye, SOW-X for VAC, SOW-X for EOS AC, SOW-X for EAAC).

## §3. Heightened Publication Scrutiny — Specific to this Volume II

3.1 The following Findings are subject to heightened publication scrutiny (i.e., the PoC Exploit is delivered to the Vendor only, and public release requires Vendor's express written consent, and the PoC Exploit is released only with a defensive utility):

  (a) Findings that affect live-service components of F1 25, Borderlands 4, BGE 20AE (where live-service applies), or POP:TC (where live-service applies);

  (b) Findings that affect Ubisoft Connect entitlement flow in a manner that could enable a third party to gain access to other Ubisoft Connect-protected titles;

  (c) Findings that affect the 2K Launcher / 2K entitlement flow in a manner that could enable a third party to gain access to other 2K-published titles;

  (d) Findings that affect the SHiFT code redemption flow in a manner that could enable a third party to gain unauthorized entitlement across multiple Gearbox titles;

  (e) Findings that affect EA's anti-cheat in a manner that could be applied to non-F1 25 EA titles.

3.2 The default publication format is **abstract or Vendor-supplied test binary** (per the no-targeting rule in Section 5.1 of Part V of Volume I). The Vendor may, in writing, approve a more specific publication format.

## §4. Specific to Single-Player Titles (BGE 20AE, POP:TC)

4.1 BGE 20AE and POP:TC are single-player titles. The no-targeting rule (per the corresponding clauses in SOW-X and SOW-X) prohibits PoC Exploits that target a specific save file, player profile, or progression state. Abstract or Vendor-supplied test binary PoCs are the default.

4.2 Single-player Findings are not subject to the heightened publication scrutiny in Section 3.1(a) (no live-service components), but may be subject to Section 3.1(b) or (c) where the Finding spans the Ubisoft Connect or 2K Launcher entitlement flow.

## §5. Specific to Live-Service Titles (F1 25, Borderlands 4)

5.1 F1 25 and Borderlands 4 are live-service, multiplayer titles. Findings affecting live-service components are subject to Section 3.1(a). The Vendor's live-service team shall be included in pre-publication review (per Article 10.8).

5.2 PoC Exploits against live-service components shall be limited to Vendor-supplied test environments for the duration of the Coordinated Disclosure Period, with public PoC release only after Vendor sign-off and a Vendor-elected safety window (typically 30 additional days, per Article 10.8).

5.3 Operator warrants that it shall not, in the course of an Engagement against F1 25 or Borderlands 4, develop, test, refine, or distribute any cheat, hack, aimbot, wallhack, ESP, or similar tool whose primary purpose is to gain an unfair in-game advantage (per Section 12.6 of Part I).

---

# PART VI — SIGNATURES

**HERETEK-AI, INC.**

By: ______________________________
Name: ______________________________
Title: ______________________________
Date: ______________________________

**Electronic Arts Inc.** (SOW-X)

By: ______________________________
Name: ______________________________
Title: ______________________________
Date: ______________________________

**Codemasters Software Company Limited** (SOW-X)

By: ______________________________
Name: ______________________________
Title: ______________________________
Date: ______________________________

**Ubisoft Entertainment S.A.** (SOW-X, SOW-X)

By: ______________________________
Name: ______________________________
Title: ______________________________
Date: ______________________________

**Gearbox Entertainment, L.P.** (SOW-X)

By: ______________________________
Name: ______________________________
Title: ______________________________
Date: ______________________________

**2K Games, Inc.** (SOW-X)

By: ______________________________
Name: ______________________________
Title: ______________________________
Date: ______________________________

**Take-Two Interactive Software, Inc.** (SOW-X, parent-level coordination)

By: ______________________________
Name: ______________________________
Title: ______________________________
Date: ______________________________

---

# ANNEX — NEGOTIATION CHECKLIST

The following items are commonly negotiated points that vendors may wish to amend from the template defaults above.

## A. Master Agreement

- [ ] Term length (default 36 months)
- [ ] Renewal mechanism (default: auto-renew with 90-day notice)
- [ ] Insurance limits (defaults in Section 4.9)
- [ ] Coordinated Disclosure Period (default 180 days; can be 90, 120, 270, 365)
- [ ] Pre-publication review period (default 30 days)
- [ ] Survival periods (confidentiality default 7 years; can be 5, 7, 10, perpetual-for-trade-secret)
- [ ] Cap on liability (defaults in Section 14.6)
- [ ] Consequential damages exclusions
- [ ] Indemnification scope
- [ ] Choice of law and forum (default: Delaware, JAMS San Francisco; alternative: Paris for Ubisoft, London for Codemasters)
- [ ] E-signature acceptance (eIDAS-compliant for EU entities)
- [ ] Right to use Findings for Heretek Product improvement (Section 3.9) — scope, exclusions, and revocability
- [ ] Whole-Product Bypass commercialization restriction (Section 3.9(c)(v) of Volume I, incorporated)
- [ ] Coordinated-disclosure tie-in for product improvements (Section 3.9(c)(ii) of Volume I, incorporated)
- [ ] Notice-of-material-improvement mechanism (Section 3.9(e) of Volume I, incorporated)
- [ ] **Volume II-specific:** French-language courtesy translation for Ubisoft (per Section 16.14)
- [ ] **Volume II-specific:** UK-jurisdiction carve-outs for Codemasters (per Section 5.2(b))
- [ ] **Volume II-specific:** US-jurisdiction carve-outs for EA, 2K, Take-Two, Gearbox US (per Section 5.2(c))

## B. SOW

- [ ] Authorized Target list (specific versions, builds, configurations)
- [ ] Out-of-scope systems
- [ ] Specific techniques permitted/prohibited
- [ ] Fee structure (retainer vs. bounty vs. hourly vs. hybrid)
- [ ] Per-Finding bounty amounts by severity
- [ ] Reproducibility window
- [ ] Acceptance criteria
- [ ] Vendor-specific codename handling
- [ ] White-box key handling
- [ ] Anti-cheat-specific restrictions
- [ ] Cross-Vendor coordination (if applicable)
- [ ] **SOW-X specific:** F1 25 live-service coordination
- [ ] **SOW-X specific:** EGOS engine version-delta testing
- [ ] **SOW-X specific:** BGE 20AE remaster scope clarification
- [ ] **SOW-X specific:** Unity-engine scope clarification
- [ ] **SOW-X specific:** Borderlands 4 live-service coordination
- [ ] **SOW-X specific:** 2K Launcher scope clarification
- [ ] **SOW-X specific:** Take-Two parent-level coordination scope

## C. Coordinated Disclosure

- [ ] Default period
- [ ] Fast-track trigger (90 days)
- [ ] Slow-track mechanism (up to 24 months)
- [ ] Cross-Vendor synchronization (Volume I ↔ Volume II)
- [ ] Public release format
- [ ] Defensive utility requirements
- [ ] Embargo exceptions for regulators / law enforcement

## D. PoC Standards

- [ ] Vendor-specific codename redaction requirements
- [ ] White-box key handling
- [ ] Anti-cheat-specific restrictions
- [ ] Hardware-roots-of-trust restrictions
- [ ] Whole-product Bypass handling
- [ ] Public release format and review
- [ ] **Volume II-specific:** Live-service PoC restrictions (F1 25, Borderlands 4)
- [ ] **Volume II-specific:** Engine-third-party IP redirection (UE, Unity, Dunia)

---

# ANNEX — DOCUMENT CONTROL

| Version | Date | Author | Notes |
|---|---|---|---|
| 0.1 | 2026-06-10 | Heretek-AI Legal | Initial draft. Volume II companion to MRTEA-2026-001. Targets F1 25 (EA + Codemasters), BGE 20AE (Ubisoft), Borderlands 4 (Gearbox + 2K + Take-Two parent), and POP:TC (Ubisoft). Includes 7 SOWs (SOW-X through SOW-X) and per-Vendor special provisions. |

---

**End of Master Red-Team Engagement Agreement, Volume II (MRTEA-2026-002).**

---

*This document is a legal template and does not constitute legal advice. Heretek-AI, Inc. and any prospective Vendor should obtain independent legal review before execution. Coordinated-disclosure and § 1201 release provisions should be reviewed against the current state of U.S., UK, French, EU, and applicable foreign law. The Companion Document MRTEA-2026-001 (Volume I) is incorporated by reference for terms not separately defined in this Volume II.*
