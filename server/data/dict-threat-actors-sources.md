# Threat Actor Dictionary — Primary Sources

**Dataset:** `dict-threat-actors.json`  
**Compiled:** June 2025  
**Entries:** 100 threat actor groups

---

## Primary Authoritative Sources

### 1. MITRE ATT&CK Groups Database
- **URL:** https://attack.mitre.org/groups/
- **Usage:** Canonical group names, MITRE IDs (Gxxxx), and formally verified alias lists for all groups tracked in ATT&CK. This was the primary source for resolving canonical names and confirming alias cross-references across vendor naming conventions.

### 2. Microsoft Threat Intelligence — Threat Actor Naming
- **URL:** https://learn.microsoft.com/en-us/unified-secops/microsoft-threat-actor-naming
- **Usage:** Microsoft's unified naming taxonomy (Blizzard/Typhoon/Sandstorm/Sleet/Tempest/Storm) mapped to all relevant groups. Provided MSTIC designations for all Russian, Chinese, Iranian, North Korean, and cybercriminal actors.

### 3. Mandiant / Google Threat Intelligence — APT & FIN Groups
- **URL:** https://www.mandiant.com/resources/insights/apt-groups  
- **Usage:** APT numbered designations (APT28–APT44), FIN group classifications (FIN6–FIN13), and UNC cluster aliases. Mandiant "graduated" Sandworm to APT44 in 2024.

### 4. CrowdStrike Adversary Universe
- **URL:** https://www.crowdstrike.com/adversaries/  
- **Usage:** SPIDER/PANDA/BEAR/KITTEN/CHOLLIMA naming conventions. Key aliases include GOLD MYSTIC (LockBit), Indrik Spider (Evil Corp), Wizard Spider (Conti/TrickBot), Carbon Spider (FIN7), Scattered Spider, and Vanguard Panda (Volt Typhoon).

### 5. Malpedia Threat Actor Database (Fraunhofer FKIE)
- **URL:** https://malpedia.caad.fkie.fraunhofer.de/actors
- **Usage:** Cross-vendor alias consolidation for APT28, APT29, APT41, Turla, Wizard Spider, FIN11, FIN6, and others. Used to validate multi-vendor alias overlaps.

### 6. CISA #StopRansomware Advisories
- **URL:** https://www.cisa.gov/stopransomware  
- **Key advisories used:**
  - Black Basta (IC3/CISA, May 2024)
  - BlackSuit/Royal (IC3/CISA, August 2024)
  - Play Ransomware (IC3/CISA, June 2025)
  - AvosLocker (FBI/CISA, October 2023)
  - BianLian (FBI/CISA, 2023)

### 7. Picus Security Threat Intelligence Blog
- **URL:** https://www.picussecurity.com/resource/blog/
- **Usage:** Comprehensive alias lists for APT28, APT29, APT41, Turla, MuddyWater, LockBit, and top ransomware groups of 2025.

### 8. Black Kite 2025 Ransomware Report
- **URL:** https://blackkite.com/report/2025-ransomware-report/top-groups
- **Usage:** Activity rankings and victim counts for RansomHub, Akira, Qilin, LockBit, and Play ransomware groups for 2024-2025.

### 9. Picus Security — Top 10 Ransomware Groups 2025
- **URL:** https://www.picussecurity.com/resource/blog/top-10-ransomware-groups-of-2025
- **Usage:** Current activity data confirming Qilin (946 victims), Akira (717 victims), RansomHub, CLOP, Lynx, INC Ransom rankings.

### 10. Wikipedia — Group Articles
- **URLs used:**
  - https://en.wikipedia.org/wiki/APT29 (Cozy Bear)
  - https://en.wikipedia.org/wiki/Sandworm_(hacker_group)
  - https://en.wikipedia.org/wiki/Lazarus_Group
  - https://en.wikipedia.org/wiki/Kimsuky
  - https://en.wikipedia.org/wiki/Volt_Typhoon
  - https://en.wikipedia.org/wiki/Salt_Typhoon
  - https://en.wikipedia.org/wiki/BlackCat_(cyber_gang)
  - https://en.wikipedia.org/wiki/LockBit
  - https://en.wikipedia.org/wiki/Charming_Kitten
  - https://en.wikipedia.org/wiki/Anonymous_Sudan
  - https://en.wikipedia.org/wiki/Rhysida_(hacker_group)
  - https://en.wikipedia.org/wiki/Hive_(ransomware)
  - https://en.wikipedia.org/wiki/FIN7
  - https://en.wikipedia.org/wiki/Wizard_Spider
- **Usage:** Cross-reference and secondary validation for aliases; event timelines.

### 11. Threat Intelligence Reports (Secondary Sources)
- **Barracuda Networks — BlackSuit ransomware lineage:** https://blog.barracuda.com/2024/10/29/blacksuit-ransomware--8-years--6-names--1-cybercrime-syndicate
- **AttackIQ — Salt Typhoon emulation:** https://www.attackiq.com/2025/03/19/emulating-salt-typhoon/
- **WTOP — Salt Typhoon/GhostEmperor/FamousSparrow:** https://wtop.com/j-j-green-national/2024/12/the-worst-telecommunications-hack-in-us-history-chinese-cyber-group-salt-typhoon-intrusions-likely-started-years-ago/
- **CYFIRMA — APT43/Kimsuky profile:** https://www.cyfirma.com/research/apt-profile-apt43/
- **Quorum Cyber — Lace Tempest/MOVEit:** https://www.quorumcyber.com/threat-intelligence/the-month-of-moveit/
- **Canadian Centre for Cyber Security — TA505/Cl0p profile:** https://www.cyber.gc.ca/en/guidance/profile-ta505-cl0p-ransomware
- **HHS — FIN11 threat profile:** https://www.hhs.gov/sites/default/files/threat-profile-june-2023.pdf
- **Blackpoint Cyber — APT29 threat profile:** https://blackpointcyber.com/wp-content/uploads/2024/06/Threat-Profile-APT29_Blackpoint-Adversary-Pursuit-Group-APG_2024.pdf
- **CrowdStrike — CARBON SPIDER/DarkSide/BlackMatter evolution:** https://www.crowdstrike.com/en-us/blog/carbon-spider-embraces-big-game-hunting-part-2/
- **BranDefense — Turla APT:** https://brandefense.io/blog/turla-apt-group/
- **BranDefense — Wizard Spider:** https://brandefense.io/blog/wizard-spider-apt-group/
- **BranDefense — APT35 (Charming Kitten):** https://brandefense.io/blog/apt35-charming-kitten/
- **Resecurity — Qilin ransomware:** https://www.resecurity.com/blog/article/qilin-ransomware-and-the-ghost-bulletproof-hosting-conglomerate
- **The Hacker News — RansomHub/Qilin/DragonForce:** https://thehackernews.com/2025/04/ransomhub-went-dark-april-1-affiliates.html
- **FortiGuard Labs — RansomHub:** https://www.fortiguard.com/threat-actor/6346/ransomhub-ransomware
- **FortiGuard Labs — Volt Typhoon:** https://www.fortiguard.com/threat-actor/5564/volt-typhoon
- **Push Security — Scattered Spider TTPs 2025:** https://pushsecurity.com/blog/scattered-spider-ttp-evolution-in-2025
- **Resecurity — LAPSUS$/ShinyHunters/Scattered Spider alliance:** https://www.resecurity.com/blog/article/trinity-of-chaos-the-lapsus-shinyhunters-and-scattered-spider-alliance-embarks-on-global-cybercrime-spree
- **US Commerce Dept — NSO Group entity listing:** https://www.commerce.gov/news/press-releases/2021/11/commerce-adds-nso-group-and-other-foreign-companies-entity-list
- **TerraZone — APT41 complete guide:** https://terrazone.io/apt41-china-cyber-threat-group/
- **Picus Security — MuddyWater/DEV-1084:** https://www.picussecurity.com/resource/dev-1084-and-mercury-inside-irans-darkbit-ransomware-operations
- **Trend Micro — Qilin/Agenda ransomware:** https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-agenda

### 12. MITRE ATT&CK Individual Group Pages (Direct Fetch)
Full alias tables verified from official MITRE pages for:
- G0016 APT29, G0007 APT28, G0034 Sandworm Team, G0010 Turla
- G0032 Lazarus Group, G0094 Kimsuky, G0046 FIN7, G0037 FIN6
- G0119 Indrik Spider, G0102 Wizard Spider, G0115 GOLD SOUTHFIELD
- G0129 Mustang Panda, G0059 Magic Hound, G0069 MuddyWater
- G0096 APT41, G1015 Scattered Spider, G1017 Volt Typhoon
- G1045 Salt Typhoon, G1033 Star Blizzard, G1053 Storm-0501
- G1046 Storm-1811, G1032 INC Ransom, G1024 Akira, G1040 Play
- G0117 Fox Kitten, G1004 LAPSUS$, G0138 Andariel, G1030 Agrius
- G1027 CyberAv3ngers, G1055 VOID MANTICORE (Handala)

---

## Alias Validation Methodology

All aliases were required to be confirmed by **at least one** of the following:
1. Listed in the MITRE ATT&CK "Associated Groups" table for the group
2. Named in a vendor blog post with explicit attribution (e.g., "also tracked as", "aka", "known as")
3. Confirmed in a government advisory (FBI, CISA, HHS, DOJ, Treasury OFAC)
4. Cross-referenced in at least two independent security vendor reports

Aliases that appeared in only one low-credibility source or that could not be traced to a primary source were omitted.

---

## Notes on Alias Overlap

Several groups share aliases or have contested boundaries:
- **APT34/OilRig**: MITRE canonical is OilRig (G0049); APT34 is a Mandiant designation used as alias
- **Lazarus/APT38/Bluenoroff/Andariel**: MITRE tracks as separate groups but some vendors consolidate all under Lazarus; this dataset follows MITRE sub-group distinctions
- **FIN7/Carbanak**: Distinct groups with operational overlap; Carbon Spider (CrowdStrike) is the FIN7 designation; Carbanak/Anunak is tracked separately by some vendors but shares infrastructure
- **TA505/FIN11/Cl0p**: Broadly used interchangeably; Cl0p is the ransomware brand operated by TA505; some vendors treat FIN11 as a subset
- **Magic Hound/APT35/Charming Kitten/Phosphorus**: All refer to the same IRGC group; MITRE canonical is Magic Hound (G0059)
