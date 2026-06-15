# Sources: Top 100 Exploited Technologies Dictionary

This document lists the primary threat intelligence sources used to compile and validate `dict-technologies.json`.

---

## Primary Sources

### 1. CISA Known Exploited Vulnerabilities (KEV) Catalog
- **URL:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Analysis:** Top vendors and products by KEV entry count were used as the primary quantitative signal. In 2024, the top vendors by KEV additions were Microsoft (34–36), Ivanti (11), Google Chromium (9), Adobe (8), Apple (7), Android (6), Cisco (6), D-Link (6), Palo Alto Networks (6), and VMware (5). The top products included Microsoft Windows (22 CVEs), Google Chrome/Chromium (9), Cisco ASA/FTD (5), Apple iOS (5), VMware vCenter (4), and Linux Kernel (4).
- **Secondary analysis:** https://vulncheck.com/blog/comparing-kevs-jupyter (VulnCheck KEV analysis, Dec 2024)

### 2. Mandiant M-Trends 2024 (Google Threat Intelligence Group)
- **URL:** https://services.google.com/fh/files/misc/m-trends-2024.pdf
- **Analysis:** Identified most-prevalent exploited CVEs in 2023 IR engagements: CVE-2023-34362 (MOVEit Transfer, #1), CVE-2022-21587 (Oracle E-Business Suite, #2), CVE-2023-2868 (Barracuda ESG, #3). Also identified BEACON (Cobalt Strike) as the #1 observed malware family (10% of all intrusions).

### 3. Mandiant M-Trends 2025 (via CyberScoop reporting)
- **URL:** https://cyberscoop.com/mandiant-m-trends-2025/
- **Analysis:** In 2024 IR engagements, the most exploited CVEs were: #1 CVE-2024-3400 (Palo Alto PAN-OS GlobalProtect), #2–#3 CVE-2023-46805 / CVE-2024-21887 (Ivanti Connect Secure), #4 CVE-2023-48788 (Fortinet FortiClient EMS). Edge devices dominated initial access vectors.

### 4. CrowdStrike 2024 Global Threat Report
- **URL:** https://www.crowdstrike.com/en-us/resources/reports/crowdstrike-2024-global-threat-report/
- **Executive Summary:** https://www.crowdstrike.com/wp-content/uploads/2024/02/crowdstrike-2024-global-threat-report-executive-summary.pdf
- **Analysis:** Reported 75% increase in cloud intrusions, identity-based attacks as the dominant vector, 583% increase in Kerberoasting, and third-party/supply chain exploitation as a key theme. Highlighted Cobalt Strike/Sliver/Brute Ratel C2 usage patterns.

### 5. Microsoft Digital Defense Report 2024
- **URL:** https://www.microsoft.com/en-us/security/security-insider/threat-landscape/microsoft-digital-defense-report-2024
- **Full PDF:** https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/Microsoft%20Digital%20Defense%20Report%202024%20(1).pdf
- **Analysis:** Identified password-based identity attacks (600M+ daily attempts), AiTM phishing bypassing MFA, Teams-based phishing (APT29), and 2.75x increase in human-operated ransomware with unmanaged device exploitation.

### 6. Verizon 2024 Data Breach Investigations Report (DBIR)
- **URL:** https://www.verizon.com/business/resources/reports/2024-dbir-data-breach-investigations-report.pdf
- **Analysis:** Documented a 180% increase in vulnerability exploitation as an initial access vector, driven primarily by MOVEit Transfer exploitation. Web applications remain the most targeted asset type. Ransomware and extortion techniques accounted for 32% of all breaches.

### 7. Rapid7 2024 Attack Intelligence Report
- **URL:** https://www.rapid7.com/research/report/2024-attack-intelligence-report/
- **Blog Summary:** https://www.rapid7.com/blog/post/2024/12/16/2024-threat-landscape-statistics-ransomware-activity-vulnerability-exploits-and-attack-trends/
- **Analysis:** 36% of widely exploited vulnerabilities in 2024 were in network edge technologies; 60%+ of those were zero-days. FortiManager CVE-2024-47575 and Palo Alto PAN-OS CVE-2024-0012/9474 were prominent zero-day examples. Veeam involved in 20%+ of 2024 IR cases.

### 8. MITRE ATT&CK Framework
- **URL:** https://attack.mitre.org
- **Groups:** https://attack.mitre.org/groups/
- **Analysis:** Software and technique usage attributed to tracked threat groups (APT29, APT41, Lazarus, Sandworm, FIN7, etc.) provided cross-referencing signals for tool and product inclusion. PowerShell (T1059.001), WMI (T1047), and Cobalt Strike are top-ranked techniques/tools.

### 9. Arctic Wolf 2024 Top 25 Exploited Vulnerabilities
- **URL:** https://arcticwolf.com/the-most-exploited-vulnerabilities-of-the-year/
- **Analysis:** Confirmed Ivanti Connect Secure, Palo Alto PAN-OS, ConnectWise ScreenConnect, SonicWall, Veeam, and Cleo MFT as the most-exploited products in 2024.

### 10. VulnCheck — Exploring Network Edge Devices (2025)
- **URL:** https://wwv.vulncheck.com/hubfs/Research/Exploring-Network-Edge-Devices-VulnCheck-State-of-Exploitation-2026.pdf
- **Analysis:** Confirmed Fortinet (FortiOS/FortiProxy), SonicWall (SonicOS), and Ivanti (Connect Secure, ZTA) as the top edge device KEV targets in 2025; botnet disproportionately exploits end-of-life devices.

### 11. Red Canary Threat Detection Report
- **URL:** https://redcanary.com/threat-detection-report/trends/c2-frameworks/
- **Analysis:** Confirmed Cobalt Strike and Metasploit as the most prevalent C2/post-exploitation frameworks observed in enterprise environments; emerging frameworks include Brute Ratel, Sliver, and Mythic.

### 12. AlphaHunt — Top C2 Frameworks 2024
- **URL:** https://blog.alphahunt.io/research-top-5-most-popular-command-and-control-c2-frameworks-used-by-threat-actors-in-2024/
- **Analysis:** Ranked Cobalt Strike, PowerShell Empire, Sliver, Havoc, and Brute Ratel C4 as the most prevalent threat-actor-abused C2 frameworks in 2024.

### 13. The Record / Recorded Future — CISA KEV + Veeam Reporting
- **URL:** https://therecord.media/veam-vulnerability-exploited-ransomware-cisa-kev
- **Analysis:** Confirmed CVE-2024-40711 (Veeam Backup & Replication) exploitation in Akira, Fog, and Frag ransomware campaigns; CISA added to KEV October 2024.

### 14. DFIR Report — Confluence Exploit Leads to LockBit
- **URL:** https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/
- **Analysis:** Detailed chain from CVE-2023-22527 (Atlassian Confluence) through Mimikatz, Metasploit, and AnyDesk to LockBit ransomware deployment; validated multiple tool entries.

### 15. Palo Alto Networks — 3CX Supply Chain Attack
- **URL:** https://www.paloaltonetworks.com/blog/security-operations/the-3cx-supply-chain-attack-when-trusted-software-turns-malicious/
- **Analysis:** Documented the first cascading supply chain attack (X_Trader → 3CX); validated 3CX Desktop App and supply chain category entries.

---

## Notes on Curation Methodology

- **Inclusion threshold:** Each entry must appear in at least one major threat intelligence report (CISA KEV, Mandiant M-Trends, CrowdStrike GTR, Verizon DBIR, Rapid7, or MITRE ATT&CK) as an explicitly named exploitation target, abused tool, or high-value attack surface.
- **Exclusion criteria:** Generic language constructs (e.g., "JavaScript", "HTTP"), products with only theoretical CVEs but no observed exploitation, and vendor marketing names not used in analyst tagging were excluded.
- **Omissions due to 100-item cap:** The following categories were trimmed to stay within 100 entries while preserving the highest-signal items: Comms/Messaging (kept Telegram only; removed Discord), Office/Productivity (kept Microsoft Office / M365; removed Google Workspace as a standalone tag), Hypervisors (removed Hyper-V; ESXi/vCenter are dominant), Programming Runtimes (removed Ruby on Rails), App Servers (removed IBM WebSphere as lower modern prevalence vs WebLogic/JBoss).
