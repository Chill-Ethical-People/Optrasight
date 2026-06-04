#!/usr/bin/env node

const Database = require("better-sqlite3");
const { randomUUID } = require("node:crypto");
const path = require("node:path");

const dbPath = process.argv[2] || path.join(process.cwd(), "data", "data.db");
const db = new Database(dbPath);
db.pragma("busy_timeout = 10000");
db.pragma("journal_mode = WAL");

const id = () => randomUUID();
const now = () => new Date().toISOString();
const j = (v) => JSON.stringify(v);

const BATCH = [
  {
    name: "Play",
    rank: 1,
    mitre: "G1040",
    aliases: ["PlayCrypt", "Play ransomware", "Balloonfly"],
    type: "Ransomware-as-a-Service",
    sponsorship: "Independent",
    origin: "Unknown",
    activeSince: 2022,
    sectors: ["Healthcare", "Government", "Manufacturing", "Financial Services", "Professional Services"],
    regions: ["North America", "Europe", "Latin America"],
    summary: "High-volume double-extortion operation using valid accounts, exposed edge services, data theft, and PlayCrypt encryption.",
    campaigns: [
      ["Play ransomware enterprise intrusions", "2022 to present", "Healthcare, government, manufacturing", "North America, Europe", "Valid accounts, external remote services, and public-facing app exploitation", "Data theft, encryption, and leak-site pressure", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"],
      ["Fortinet and Exchange exposure abuse", "2022 to 2024", "Enterprise IT", "Global", "Known FortiOS and Microsoft Exchange vulnerabilities", "Hands-on-keyboard intrusion followed by privilege escalation and encryption", "https://attack.mitre.org/groups/G1040/"],
      ["Citrix Bleed access chains", "2023 to 2024", "Professional services and managed services", "North America", "Session/token theft from vulnerable Citrix NetScaler appliances", "Ransomware deployment after lateral movement", "https://www.kroll.com/en/insights/publications/cyber/play-ransomware-gains-access-citrix-bleed-vulnerability"],
    ],
    tools: ["Play ransomware", "Grixba", "AdFind", "Rclone", "PsExec", "Mimikatz"],
    iocs: [["filename", "README.txt"], ["filename", "PlayCrypt.exe"], ["filename", "rclone.exe"], ["filename", "adfind.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Play", "2025", "https://attack.mitre.org/groups/G1040/"],
      ["Government", "CISA StopRansomware: Play Ransomware", "2023-12-18", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"],
      ["Vendor Report", "Kroll: PLAY ransomware gains access via Citrix Bleed", "2023-12-20", "https://www.kroll.com/en/insights/publications/cyber/play-ransomware-gains-access-citrix-bleed-vulnerability"],
    ],
  },
  {
    name: "Qilin",
    rank: 2,
    mitre: null,
    aliases: ["Agenda", "Qilin ransomware", "GOLD FEATHER", "Water Galura"],
    type: "Ransomware-as-a-Service",
    sponsorship: "Independent",
    origin: "Unknown",
    activeSince: 2022,
    sectors: ["Healthcare", "Manufacturing", "Professional Services", "Retail", "Financial Services"],
    regions: ["North America", "Europe", "Asia-Pacific"],
    summary: "Fast-growing RaaS operation using double extortion, Windows and Linux/ESXi payloads, credential theft, and affiliate-led intrusion chains.",
    campaigns: [
      ["Agenda to Qilin rebrand and cross-platform ransomware", "2022 to 2024", "Enterprise IT and ESXi estates", "Global", "Valid accounts and remote access abuse", "Data theft and encryption across Windows and Linux systems", "https://www.trendmicro.com/en_us/research/22/i/agenda-ransomware-uses-rust-to-target-more-vital-industries.html"],
      ["Healthcare and high-impact extortion wave", "2024 to present", "Healthcare and public services", "Europe, North America", "Credential theft and unmanaged remote access", "Operational disruption and regulated-data exposure", "https://www.hhs.gov/sites/default/files/qilin-threat-profile-tlpclear.pdf"],
      ["Affiliate expansion after ecosystem disruption", "2024 to 2026", "Manufacturing and professional services", "Global", "Access broker credentials and exposed VPN/VDI", "High-volume leak-site claims and data-theft pressure", "https://www.ransomware.live/group/qilin"],
    ],
    tools: ["Qilin ransomware", "Agenda ransomware", "Rclone", "AnyDesk", "Mimikatz", "PsExec"],
    iocs: [["filename", "agenda.exe"], ["filename", "qilin.exe"], ["filename", "rclone.exe"], ["filename", "AnyDesk.exe"]],
    refs: [
      ["Vendor Report", "Trend Micro: Agenda ransomware uses Rust", "2022-09-09", "https://www.trendmicro.com/en_us/research/22/i/agenda-ransomware-uses-rust-to-target-more-vital-industries.html"],
      ["Government", "HHS HC3: Qilin threat profile", "2024", "https://www.hhs.gov/sites/default/files/qilin-threat-profile-tlpclear.pdf"],
      ["Threat Tracker", "Ransomware.live: Qilin", "2026", "https://www.ransomware.live/group/qilin"],
    ],
  },
  {
    name: "Salt Typhoon",
    rank: 3,
    mitre: "G1045",
    aliases: ["Earth Estries", "FamousSparrow", "GhostEmperor overlap", "UNC2286"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "China",
    activeSince: 2019,
    sectors: ["Telecommunications", "Internet Service Providers", "Government", "Managed Service Providers"],
    regions: ["United States", "Europe", "Asia-Pacific"],
    summary: "PRC-linked espionage actor focused on telecom and ISP environments, long-duration network access, credential theft, and sensitive communications collection.",
    campaigns: [
      ["Telecommunications and ISP compromise campaign", "2023 to 2025", "Telecommunications and internet service providers", "United States and allied countries", "Edge exploitation, valid accounts, and network-device access", "Sensitive communications and network metadata collection", "https://attack.mitre.org/groups/G1045/"],
      ["Communications infrastructure hardening advisory response", "2024 to 2025", "Communications infrastructure", "United States", "Compromised network devices and credentialed access", "Joint government guidance on visibility, logging, and hardening", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-326a"],
      ["Network-device exploitation operations", "2025", "Carrier and ICM-sector infrastructure", "Asia-Pacific", "Exploitation of network devices and multi-hop proxying", "Persistent C2 and stealthy collection", "https://www.imda.gov.sg/-/media/imda/files/regulations-and-licensing/regulations/advisories/infocomm-media-cyber-security/salt-typhoon-operation-network-device-exploitation.pdf"],
    ],
    tools: ["Demodex", "Web shells", "Living-off-the-land utilities", "Credential theft tooling", "Proxy infrastructure"],
    iocs: [["filename", "webshell.aspx"], ["filename", "svchost.exe"], ["filename", "ntds.dit"], ["filename", "powershell.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Salt Typhoon", "2025", "https://attack.mitre.org/groups/G1045/"],
      ["Government", "CISA: Enhanced visibility and hardening guidance for communications infrastructure", "2024-11-21", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-326a"],
      ["Government", "IMDA: Salt Typhoon operation network device exploitation", "2025", "https://www.imda.gov.sg/-/media/imda/files/regulations-and-licensing/regulations/advisories/infocomm-media-cyber-security/salt-typhoon-operation-network-device-exploitation.pdf"],
    ],
  },
  {
    name: "Scattered Spider",
    rank: 4,
    mitre: null,
    aliases: ["Octo Tempest", "UNC3944", "Muddled Libra", "Roasted 0ktapus", "0ktapus", "Scatter Swine"],
    type: "Organized Cybercrime",
    sponsorship: "Independent",
    origin: "Unknown",
    activeSince: 2022,
    sectors: ["Telecommunications", "Retail", "Insurance", "Hospitality", "SaaS", "Financial Services"],
    regions: ["United States", "United Kingdom", "Europe"],
    summary: "English-speaking cybercrime cluster specializing in help-desk social engineering, SIM swapping, MFA fatigue, SaaS compromise, and downstream extortion.",
    campaigns: [
      ["0ktapus identity phishing", "2022", "SaaS, telecom, cryptocurrency", "United States", "SMS phishing and credential harvesting", "Okta and SaaS session compromise", "https://www.group-ib.com/blog/0ktapus/"],
      ["Help-desk and identity intrusion operations", "2023 to present", "Telecom, hospitality, retail, insurance", "United States and United Kingdom", "Help-desk impersonation, SIM swapping, and MFA reset abuse", "Cloud/SaaS data theft and ransomware affiliate enablement", "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/"],
      ["UNC3944 cloud and virtualization targeting", "2023 to 2025", "Large enterprises", "North America", "Credential theft, social engineering, and privileged identity abuse", "SaaS, VDI, and cloud data theft", "https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications"],
    ],
    tools: ["Okta phishing kits", "RMM tools", "AnyDesk", "Ngrok", "Mimikatz", "Cloud admin portals"],
    iocs: [["filename", "AnyDesk.exe"], ["filename", "ngrok.exe"], ["domain", "okta-helpdesk.example.invalid"], ["filename", "rclone.exe"]],
    refs: [
      ["Vendor Report", "Microsoft: Octo Tempest crosses boundaries", "2023-10-25", "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/"],
      ["Vendor Report", "Google Cloud: UNC3944 targets SaaS applications", "2024", "https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications"],
      ["Vendor Report", "Group-IB: 0ktapus campaign", "2022-08-25", "https://www.group-ib.com/blog/0ktapus/"],
    ],
  },
  {
    name: "Octo Tempest",
    rank: 5,
    mitre: null,
    aliases: ["Scattered Spider", "UNC3944", "Muddled Libra", "0ktapus"],
    type: "Organized Cybercrime",
    sponsorship: "Independent",
    origin: "Unknown",
    activeSince: 2022,
    sectors: ["Technology", "Hospitality", "Telecommunications", "Retail", "Financial Services"],
    regions: ["United States", "United Kingdom", "Europe"],
    summary: "Microsoft-tracked name for an identity-first extortion cluster that escalates from social engineering into cloud, endpoint, and ransomware operations.",
    campaigns: [
      ["Octo Tempest extortion and destruction operations", "2023 to present", "Technology, hospitality, telecom", "United States and United Kingdom", "Help-desk social engineering and identity takeover", "SaaS theft, ransomware deployment, and destructive extortion", "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/"],
      ["MFA fatigue and SIM-swap access chains", "2022 to 2024", "Telecom and cloud-heavy enterprises", "North America", "Social engineering of help desks and users", "Privileged identity takeover and cloud console access", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"],
      ["Cloud/SaaS data theft playbook", "2024 to 2025", "Large enterprises", "Global", "Credential theft and OAuth/session abuse", "Data exfiltration from SaaS, VDI, and source-code platforms", "https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications"],
    ],
    tools: ["Azure and Entra portals", "Okta admin console", "RMM tools", "Ngrok", "Mimikatz", "Rclone"],
    iocs: [["filename", "rclone.exe"], ["filename", "ngrok.exe"], ["filename", "AnyDesk.exe"], ["domain", "sso-reset.example.invalid"]],
    refs: [
      ["Vendor Report", "Microsoft: Octo Tempest crosses boundaries", "2023-10-25", "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/"],
      ["Government", "CISA: Scattered Spider advisory", "2023-11-16", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"],
      ["Vendor Report", "Google Cloud: UNC3944 targets SaaS applications", "2024", "https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications"],
    ],
  },
  {
    name: "LockBit",
    rank: 6,
    mitre: null,
    aliases: ["LockBit 3.0", "LockBit Black", "ABCD"],
    type: "Ransomware-as-a-Service",
    sponsorship: "Independent",
    origin: "Russia",
    activeSince: 2019,
    sectors: ["Manufacturing", "Professional Services", "Healthcare", "Government", "Financial Services"],
    regions: ["Global", "North America", "Europe"],
    summary: "Historically dominant RaaS ecosystem whose affiliates, builder leaks, and post-disruption brand reuse continue to shape enterprise extortion risk.",
    campaigns: [
      ["LockBit 2.0 and 3.0 global affiliate operations", "2021 to 2024", "Manufacturing, healthcare, government, services", "Global", "RDP/VPN credentials, access brokers, and exploitation", "Data theft, encryption, and high-volume leak-site claims", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a"],
      ["Operation Cronos disruption and residual affiliate activity", "2024", "RaaS ecosystem", "Global", "Law-enforcement infrastructure seizure and affiliate displacement", "Affiliate migration and brand relaunch attempts", "https://www.nationalcrimeagency.gov.uk/news/lockbit-ransomware-group-disrupted-by-the-national-crime-agency-and-international-partners"],
      ["Builder leak and derivative tradecraft", "2022 to present", "Enterprise IT", "Global", "Leaked builder reuse and affiliate tooling", "Detection ambiguity across LockBit-like payloads", "https://attack.mitre.org/software/S0689/"],
    ],
    tools: ["LockBit ransomware", "StealBit", "Mimikatz", "PsExec", "Cobalt Strike", "Rclone"],
    iocs: [["filename", "lockbit.exe"], ["filename", "StealBit.exe"], ["filename", "rclone.exe"], ["filename", "psexec.exe"]],
    refs: [
      ["Government", "CISA StopRansomware: LockBit 3.0", "2023-03-16", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a"],
      ["Government", "NCA: LockBit disrupted by international partners", "2024-02-20", "https://www.nationalcrimeagency.gov.uk/news/lockbit-ransomware-group-disrupted-by-the-national-crime-agency-and-international-partners"],
      ["Framework", "MITRE ATT&CK Software: LockBit", "2025", "https://attack.mitre.org/software/S0689/"],
    ],
  },
  {
    name: "Cl0p",
    rank: 7,
    mitre: null,
    aliases: ["Clop", "TA505", "FIN11", "Lace Tempest", "DEV-0950"],
    type: "Ransomware-as-a-Service",
    sponsorship: "Independent",
    origin: "Russia",
    activeSince: 2019,
    sectors: ["Financial Services", "Technology", "Healthcare", "Government", "File-transfer users"],
    regions: ["Global", "North America", "Europe"],
    summary: "Mass-exploitation extortion actor known for managed file-transfer compromise, large-scale data theft, and leak-site victim pressure.",
    campaigns: [
      ["MOVEit Transfer mass exploitation", "2023", "Enterprises using MOVEit Transfer", "Global", "SQL injection exploitation of MOVEit Transfer", "Large-scale data theft and extortion", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"],
      ["GoAnywhere MFT exploitation", "2023", "Managed file-transfer users", "Global", "Fortra GoAnywhere MFT vulnerability exploitation", "Data theft and extortion claims", "https://www.cisa.gov/news-events/alerts/2023/02/10/cisa-adds-one-known-exploited-vulnerability-catalog"],
      ["Accellion FTA extortion lineage", "2020 to 2021", "Financial, legal, education, government", "Global", "Legacy file-transfer appliance exploitation", "Data theft and double extortion", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-055a"],
    ],
    tools: ["Cl0p ransomware", "LemurLoot", "SDBbot", "FlawedAmmyy", "Web shells", "SQL tools"],
    iocs: [["filename", "human2.aspx"], ["filename", "LEMURLOOT.aspx"], ["filename", "clop.exe"], ["filename", "SDBbot.exe"]],
    refs: [
      ["Government", "CISA: MOVEit Transfer exploitation", "2023-06-07", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"],
      ["Government", "CISA: Accellion FTA exploitation", "2021-02-24", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-055a"],
      ["Vendor Report", "Microsoft: Threat actors exploiting MOVEit Transfer", "2023", "https://www.microsoft.com/en-us/security/blog/2023/06/02/threat-actors-exploiting-moveit-transfer-vulnerability/"],
    ],
  },
  {
    name: "RansomHub",
    rank: 8,
    mitre: null,
    aliases: ["Cyclops", "Knight lineage", "RansomHub ransomware"],
    type: "Ransomware-as-a-Service",
    sponsorship: "Independent",
    origin: "Unknown",
    activeSince: 2024,
    sectors: ["Healthcare", "Manufacturing", "Government", "Professional Services", "Financial Services"],
    regions: ["Global", "North America", "Europe"],
    summary: "Major RaaS ecosystem that attracted affiliates after disruption of older programs and drives high-volume data theft, encryption, and extortion.",
    campaigns: [
      ["RansomHub affiliate expansion", "2024 to present", "Healthcare, manufacturing, public sector", "Global", "Valid accounts, VPN exposure, and vulnerability exploitation", "Rapid leak-site growth and affiliate migration", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a"],
      ["Change Healthcare affiliate-linked disruption", "2024", "Healthcare payments and services", "United States", "Credentialed remote access and ransomware affiliate intrusion", "Severe healthcare business disruption and data theft", "https://www.hhs.gov/sites/default/files/ransomhub-ransomware-sector-alert-tlpclear.pdf"],
      ["Knight/Cyclops lineage operations", "2023 to 2024", "Enterprise IT", "Global", "Affiliate tooling and ransomware rebrand", "Extortion platform continuity", "https://www.ransomware.live/group/ransomhub"],
    ],
    tools: ["RansomHub ransomware", "Rclone", "Mimikatz", "Netscan", "AnyDesk", "PsExec"],
    iocs: [["filename", "ransomhub.exe"], ["filename", "rclone.exe"], ["filename", "netscan.exe"], ["filename", "AnyDesk.exe"]],
    refs: [
      ["Government", "CISA StopRansomware: RansomHub", "2024-08-29", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a"],
      ["Government", "HHS HC3: RansomHub ransomware sector alert", "2024", "https://www.hhs.gov/sites/default/files/ransomhub-ransomware-sector-alert-tlpclear.pdf"],
      ["Threat Tracker", "Ransomware.live: RansomHub", "2026", "https://www.ransomware.live/group/ransomhub"],
    ],
  },
  {
    name: "Akira",
    rank: 9,
    mitre: null,
    aliases: ["Akira ransomware", "PUNK SPIDER", "GOLD SAHARA"],
    type: "Ransomware-as-a-Service",
    sponsorship: "Independent",
    origin: "Unknown",
    activeSince: 2023,
    sectors: ["Manufacturing", "Education", "Financial Services", "Technology", "Healthcare"],
    regions: ["North America", "Europe", "Australia"],
    summary: "Stable RaaS operation known for VPN compromise, data exfiltration, Windows and Linux/ESXi payloads, and disciplined affiliate execution.",
    campaigns: [
      ["Akira double-extortion operations", "2023 to present", "Manufacturing, education, finance, technology", "North America and Europe", "VPN credentials, exposed remote services, and vulnerability exploitation", "Data theft and encryption", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"],
      ["Cisco VPN and MFA gap exploitation", "2023 to 2024", "VPN-heavy enterprises", "Global", "Accounts without MFA and exposed VPN portals", "Initial access for ransomware operations", "https://blog.talosintelligence.com/akira-ransomware-targeting-vpns-without-mfa/"],
      ["Linux/ESXi ransomware deployment", "2023 to 2025", "Virtualized enterprise estates", "Global", "Privileged access after lateral movement", "Hypervisor impact and operational disruption", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"],
    ],
    tools: ["Akira ransomware", "Rclone", "Mimikatz", "Advanced IP Scanner", "AnyDesk", "PowerTool"],
    iocs: [["filename", "akira.exe"], ["filename", "rclone.exe"], ["filename", "Advanced_IP_Scanner.exe"], ["filename", "PowerTool.exe"]],
    refs: [
      ["Government", "CISA StopRansomware: Akira", "2024-04-18", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"],
      ["Vendor Report", "Cisco Talos: Akira targeting VPNs without MFA", "2023", "https://blog.talosintelligence.com/akira-ransomware-targeting-vpns-without-mfa/"],
      ["Threat Tracker", "Ransomware.live: Akira", "2026", "https://www.ransomware.live/group/akira"],
    ],
  },
  {
    name: "BlackCat",
    rank: 10,
    mitre: null,
    aliases: ["ALPHV", "Noberus", "BlackCat ransomware"],
    type: "Ransomware-as-a-Service",
    sponsorship: "Independent",
    origin: "Russia",
    activeSince: 2021,
    sectors: ["Healthcare", "Energy", "Manufacturing", "Financial Services", "Technology"],
    regions: ["Global", "North America", "Europe"],
    summary: "ALPHV/Noberus RaaS franchise known for Rust payloads, aggressive data theft, affiliate operations, and disruptive healthcare-sector incidents.",
    campaigns: [
      ["ALPHV/BlackCat enterprise ransomware operations", "2021 to 2024", "Healthcare, energy, manufacturing", "Global", "Valid accounts, exposed services, and affiliate access", "Data theft, encryption, and leak-site extortion", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"],
      ["Healthcare payment disruption and affiliate fallout", "2024", "Healthcare services", "United States", "Credentialed access and ransomware affiliate intrusion", "Severe business disruption and data exposure", "https://www.hhs.gov/sites/default/files/alphv-blackcat-threat-profile-tlpclear.pdf"],
      ["Rust ransomware and cross-platform payload development", "2021 to 2023", "Enterprise Windows and Linux estates", "Global", "Affiliate deployment after privilege escalation", "Faster payload adaptation and defense-evasion pressure", "https://attack.mitre.org/software/S1068/"],
    ],
    tools: ["BlackCat ransomware", "Noberus", "ExMatter", "Rclone", "Cobalt Strike", "Mimikatz"],
    iocs: [["filename", "blackcat.exe"], ["filename", "noberus.exe"], ["filename", "ExMatter.exe"], ["filename", "rclone.exe"]],
    refs: [
      ["Government", "CISA StopRansomware: ALPHV BlackCat", "2023-12-19", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"],
      ["Government", "HHS HC3: ALPHV BlackCat threat profile", "2024", "https://www.hhs.gov/sites/default/files/alphv-blackcat-threat-profile-tlpclear.pdf"],
      ["Framework", "MITRE ATT&CK Software: BlackCat", "2025", "https://attack.mitre.org/software/S1068/"],
    ],
  },
  {
    name: "Volt Typhoon",
    rank: 11,
    mitre: "G1017",
    aliases: ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391", "UNC3236", "Voltzite"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "China",
    activeSince: 2021,
    sectors: ["Critical Infrastructure", "Energy", "Water", "Transportation", "Telecommunications", "Government"],
    regions: ["United States", "Pacific", "Asia-Pacific"],
    summary: "PRC-linked pre-positioning actor using living-off-the-land techniques, compromised SOHO routers, and stealthy credentialed access against critical infrastructure.",
    campaigns: [
      ["US critical infrastructure pre-positioning", "2021 to present", "Energy, water, transportation, communications", "United States and Pacific", "Compromised edge devices, valid accounts, and LOLBins", "Long-term access for potential disruption or crisis leverage", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"],
      ["SOHO router proxy and stealth operations", "2023 to 2024", "Critical infrastructure", "United States", "Compromised small-office/home-office network devices", "Obfuscated operator origin and durable access", "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/"],
      ["Living-off-the-land detection guidance", "2024", "Enterprise Windows environments", "Global", "Native admin tools and credentialed execution", "Hard-to-detect discovery and collection", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"],
    ],
    tools: ["PowerShell", "WMI", "netsh", "ntdsutil", "cmd.exe", "Compromised SOHO routers"],
    iocs: [["filename", "ntds.dit"], ["filename", "powershell.exe"], ["filename", "netsh.exe"], ["filename", "wmic.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Volt Typhoon", "2025", "https://attack.mitre.org/groups/G1017/"],
      ["Government", "CISA: PRC state-sponsored actors compromise critical infrastructure", "2024-02-07", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"],
      ["Vendor Report", "Microsoft: Volt Typhoon targets US critical infrastructure", "2023-05-24", "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/"],
    ],
  },
  {
    name: "Storm-0558",
    rank: 12,
    mitre: "G1037",
    aliases: ["Storm-0558", "Antique Typhoon"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "China",
    activeSince: 2023,
    sectors: ["Government", "Diplomatic", "Cloud Identity", "Technology"],
    regions: ["United States", "Europe", "Asia-Pacific"],
    summary: "China-nexus cloud-identity espionage cluster associated with forged authentication tokens and mailbox access against government and diplomatic targets.",
    campaigns: [
      ["Microsoft Exchange Online token abuse campaign", "2023", "Government and diplomatic organizations", "United States and Europe", "Forged authentication tokens and cloud mailbox access", "Email collection from targeted cloud tenants", "https://www.microsoft.com/en-us/security/blog/2023/07/11/mitigate-storm-0558-techniques-with-microsoft-security-products/"],
      ["Cloud identity key compromise investigation", "2023 to 2024", "Cloud service provider identity systems", "Global", "Abuse of signing key material and token validation paths", "Industry-wide focus on cloud identity resilience", "https://www.cisa.gov/news-events/news/cisa-and-partners-release-joint-guidance-microsoft-logging-and-token-analysis-techniques"],
      ["Diplomatic intelligence collection", "2023", "Diplomatic and government mailboxes", "United States and Europe", "Cloud access tokens and mailbox API access", "Sensitive email collection", "https://attack.mitre.org/groups/G1037/"],
    ],
    tools: ["Forged tokens", "Exchange Online APIs", "AADInternals-style tradecraft", "Cloud audit evasion"],
    iocs: [["filename", "Get-MessageTrace.ps1"], ["filename", "AADInternals.psd1"], ["url", "https://graph.microsoft.com/v1.0/me/messages"], ["filename", "powershell.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Storm-0558", "2025", "https://attack.mitre.org/groups/G1037/"],
      ["Vendor Report", "Microsoft: Mitigate Storm-0558 techniques", "2023-07-11", "https://www.microsoft.com/en-us/security/blog/2023/07/11/mitigate-storm-0558-techniques-with-microsoft-security-products/"],
      ["Government", "CISA and partners: Microsoft logging and token analysis guidance", "2023", "https://www.cisa.gov/news-events/news/cisa-and-partners-release-joint-guidance-microsoft-logging-and-token-analysis-techniques"],
    ],
  },
  {
    name: "Storm-0501",
    rank: 12,
    mitre: null,
    aliases: ["DEV-0501", "Sabbath affiliate", "Embargo affiliate", "Hive0090"],
    type: "Ransomware Affiliate",
    sponsorship: "Independent",
    origin: "Unknown",
    activeSince: 2021,
    sectors: ["Healthcare", "Government", "Manufacturing", "Professional Services", "Hybrid Cloud"],
    regions: ["North America", "Europe", "Global"],
    summary: "Financially motivated actor expanding ransomware operations from on-premises environments into hybrid-cloud and cloud-native control planes.",
    campaigns: [
      ["Hybrid-cloud ransomware expansion", "2024 to present", "Hybrid cloud and enterprise identity", "North America and Europe", "On-premises compromise, Entra ID abuse, and cloud privilege escalation", "Cloud data exfiltration, backup disruption, and ransomware deployment", "https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/"],
      ["Embargo ransomware deployment", "2024", "Enterprise IT and cloud tenants", "Global", "Credential theft, lateral movement, and cloud persistence", "Data theft, encryption, and cloud control-plane abuse", "https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/"],
      ["Ransomware affiliate lineage operations", "2021 to 2024", "Healthcare, public sector, professional services", "Global", "Initial access brokering and affiliate-led ransomware intrusion", "Multiple ransomware family deployments across victim environments", "https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/"],
    ],
    tools: ["AADInternals", "Rclone", "Impacket", "Cobalt Strike", "AnyDesk", "Embargo ransomware"],
    iocs: [["filename", "AADInternals.psd1"], ["filename", "rclone.exe"], ["filename", "secretsdump.py"], ["filename", "AnyDesk.exe"]],
    refs: [
      ["Vendor Report", "Microsoft: Storm-0501 ransomware attacks expanding to hybrid cloud environments", "2024-09-26", "https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/"],
      ["Vendor Report", "Microsoft: Storm-0501 ransomware attacks expanding to hybrid cloud environments", "2024-09-26", "https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/"],
      ["Government", "CISA StopRansomware advisories", "2026", "https://www.cisa.gov/stopransomware"],
    ],
  },
  {
    name: "APT29",
    rank: 13,
    mitre: "G0016",
    aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "UNC2452"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "Russia",
    activeSince: 2008,
    sectors: ["Government", "Diplomatic", "Technology", "Think Tanks", "Cloud Service Providers"],
    regions: ["United States", "Europe", "NATO-aligned countries"],
    summary: "Russian SVR-linked espionage actor focused on strategic intelligence, supply-chain compromise, cloud identity abuse, and stealthy collection.",
    campaigns: [
      ["SolarWinds SUNBURST supply-chain compromise", "2020", "Government and technology providers", "United States and global", "Software supply-chain compromise", "Strategic espionage and downstream victim access", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a"],
      ["Cloud identity and Microsoft tenant targeting", "2023 to 2024", "Government, technology, cloud", "United States and Europe", "Password spray, OAuth abuse, and service-account compromise", "Mailbox and source-code collection", "https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/"],
      ["Diplomatic phishing and intelligence collection", "2008 to present", "Diplomatic and policy organizations", "Europe and North America", "Spearphishing and stealthy malware", "Long-term strategic collection", "https://attack.mitre.org/groups/G0016/"],
    ],
    tools: ["SUNBURST", "TEARDROP", "FoggyWeb", "MagicWeb", "WellMess", "Cobalt Strike"],
    iocs: [["filename", "SolarWinds.Orion.Core.BusinessLayer.dll"], ["filename", "FoggyWeb.dll"], ["filename", "MagicWeb.dll"], ["filename", "WellMess.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: APT29", "2025", "https://attack.mitre.org/groups/G0016/"],
      ["Government", "CISA: Advanced Persistent Threat Compromise of Government Agencies", "2020-12-17", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a"],
      ["Vendor Report", "Microsoft: Midnight Blizzard responder guidance", "2024-01-25", "https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/"],
    ],
  },
  {
    name: "APT28",
    rank: 14,
    mitre: "G0007",
    aliases: ["Fancy Bear", "Forest Blizzard", "Sofacy", "STRONTIUM", "Pawn Storm"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "Russia",
    activeSince: 2007,
    sectors: ["Government", "Defense", "Media", "Political Organizations", "Critical Infrastructure"],
    regions: ["Europe", "Ukraine", "NATO-aligned countries", "United States"],
    summary: "Russian GRU-linked actor conducting spearphishing, credential theft, exploitation, influence-supporting intrusions, and wartime intelligence collection.",
    campaigns: [
      ["GRU spearphishing and credential theft operations", "2007 to present", "Government, defense, political organizations", "Europe and United States", "Phishing, credential harvesting, and malware delivery", "Strategic intelligence collection and influence support", "https://attack.mitre.org/groups/G0007/"],
      ["Ubiquiti EdgeRouter botnet and infrastructure abuse", "2024", "Network infrastructure", "Global", "Compromised routers used as operational infrastructure", "Obfuscated C2 and attack staging", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038b"],
      ["Ukraine and NATO wartime targeting", "2022 to present", "Government, defense, logistics, media", "Ukraine and Europe", "Phishing, exploitation, and malware operations", "Intelligence collection and disruption support", "https://www.ncsc.gov.uk/news/star-blizzard-continues-spear-phishing-campaigns"],
    ],
    tools: ["X-Agent", "X-Tunnel", "Zebrocy", "Mimikatz", "PowerShell", "Router malware"],
    iocs: [["filename", "x-agent.exe"], ["filename", "xtunnel.exe"], ["filename", "zebrocy.exe"], ["filename", "powershell.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: APT28", "2025", "https://attack.mitre.org/groups/G0007/"],
      ["Government", "CISA: Russian GRU cyber actors use compromised routers", "2024", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038b"],
      ["Government", "NCSC: Star Blizzard spear-phishing campaigns", "2023", "https://www.ncsc.gov.uk/news/star-blizzard-continues-spear-phishing-campaigns"],
    ],
  },
  {
    name: "APT41",
    rank: 15,
    mitre: "G0096",
    aliases: ["BARIUM", "Winnti", "WICKED PANDA", "Brass Typhoon", "Double Dragon"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "China",
    activeSince: 2012,
    sectors: ["Technology", "Telecommunications", "Healthcare", "Gaming", "Software Supply Chain"],
    regions: ["Global", "United States", "Asia-Pacific", "Europe"],
    summary: "China-nexus actor blending state-directed espionage with financially motivated operations, software supply-chain compromise, and broad post-exploitation capability.",
    campaigns: [
      ["Software supply-chain and gaming-sector intrusions", "2012 to present", "Technology, gaming, software providers", "Global", "Supply-chain compromise, phishing, and public app exploitation", "Espionage, code-signing abuse, and monetization", "https://attack.mitre.org/groups/G0096/"],
      ["US indictment-described global intrusions", "2019 to 2020", "Technology, telecom, gaming, healthcare", "Global", "Web application exploitation and custom malware", "Data theft and strategic collection", "https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer"],
      ["Winnti/ShadowPad ecosystem activity", "2016 to present", "Software and enterprise networks", "Global", "Backdoored software and shared malware platforms", "Persistent espionage access", "https://attack.mitre.org/software/S0141/"],
    ],
    tools: ["Winnti", "ShadowPad", "PlugX", "Cobalt Strike", "China Chopper", "ASPXSpy"],
    iocs: [["filename", "winnti.dll"], ["filename", "shadowpad.dll"], ["filename", "PlugX.exe"], ["filename", "cobaltstrike.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: APT41", "2025", "https://attack.mitre.org/groups/G0096/"],
      ["Government", "DOJ: APT41 actors charged", "2020-09-16", "https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer"],
      ["Framework", "MITRE ATT&CK Software: Winnti", "2025", "https://attack.mitre.org/software/S0141/"],
    ],
  },
  {
    name: "Lazarus",
    rank: 16,
    mitre: "G0032",
    aliases: ["Lazarus Group", "HIDDEN COBRA", "Labyrinth Chollima", "ZINC", "Diamond Sleet"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "North Korea",
    activeSince: 2009,
    sectors: ["Cryptocurrency", "Defense", "Aerospace", "Financial Services", "Technology"],
    regions: ["Global", "South Korea", "Japan", "United States", "Europe"],
    summary: "DPRK-linked umbrella actor conducting espionage, destructive operations, cryptocurrency theft, and supply-chain compromise to support state objectives.",
    campaigns: [
      ["Cryptocurrency and DeFi theft operations", "2017 to present", "Cryptocurrency exchanges, DeFi, developers", "Global", "Social engineering, trojanized apps, and supply-chain compromise", "Large-scale cryptocurrency theft", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a"],
      ["Sony Pictures and destructive operation lineage", "2014", "Media and entertainment", "United States", "Malware intrusion and destructive payloads", "Destructive impact and data leak", "https://www.cisa.gov/news-events/cybersecurity-advisories/ta14-353a"],
      ["Software supply-chain and developer targeting", "2020 to present", "Technology and cryptocurrency developers", "Global", "Fake job lures and trojanized tooling", "Credential theft, implant deployment, and crypto theft", "https://attack.mitre.org/groups/G0032/"],
    ],
    tools: ["AppleJeus", "BLINDINGCAN", "Manuscrypt", "DTrack", "HOPLIGHT", "Cobalt Strike"],
    iocs: [["filename", "AppleJeus.exe"], ["filename", "BLINDINGCAN.exe"], ["filename", "DTrack.exe"], ["filename", "HOPLIGHT.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Lazarus Group", "2025", "https://attack.mitre.org/groups/G0032/"],
      ["Government", "CISA: TraderTraitor DPRK campaign", "2022-04-18", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a"],
      ["Government", "CISA: Destructive malware targeting Sony Pictures", "2014-12-19", "https://www.cisa.gov/news-events/cybersecurity-advisories/ta14-353a"],
    ],
  },
  {
    name: "Sandworm",
    rank: 17,
    mitre: "G0034",
    aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Sandworm Team", "Unit 74455"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "Russia",
    activeSince: 2009,
    sectors: ["Energy", "Government", "Telecommunications", "Media", "Critical Infrastructure"],
    regions: ["Ukraine", "Europe", "NATO-aligned countries"],
    summary: "Russian GRU-linked destructive and disruptive operations actor associated with wipers, ICS attacks, hack-and-leak operations, and wartime cyber effects.",
    campaigns: [
      ["Ukraine electric power and ICS operations", "2015 to 2016", "Energy and industrial control systems", "Ukraine", "Credentialed access, ICS malware, and operator actions", "Power disruption and OT impact", "https://attack.mitre.org/groups/G0034/"],
      ["NotPetya destructive campaign", "2017", "Global enterprises and Ukrainian tax/software users", "Ukraine and global spillover", "Software supply-chain compromise", "Destructive wiper impact disguised as ransomware", "https://www.cisa.gov/news-events/cybersecurity-advisories/ta17-181a"],
      ["Ukraine wartime wipers and disruption", "2022 to present", "Government, energy, telecom, media", "Ukraine and Europe", "Wiper deployment, exploitation, and destructive tooling", "Operational disruption and psychological pressure", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a"],
    ],
    tools: ["BlackEnergy", "Industroyer", "NotPetya", "Cyclops Blink", "CaddyWiper", "Viasat wiper tooling"],
    iocs: [["filename", "blackenergy.exe"], ["filename", "industroyer.exe"], ["filename", "perfc.dat"], ["filename", "caddywiper.exe"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Sandworm Team", "2025", "https://attack.mitre.org/groups/G0034/"],
      ["Government", "CISA: Petya ransomware / NotPetya", "2017-06-30", "https://www.cisa.gov/news-events/cybersecurity-advisories/ta17-181a"],
      ["Government", "CISA: Russian state-sponsored and criminal cyber threats", "2022-04-20", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a"],
    ],
  },
  {
    name: "Mustang Panda",
    rank: 18,
    mitre: "G0129",
    aliases: ["Bronze President", "RedDelta", "TA416", "Earth Preta", "Stately Taurus"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "China",
    activeSince: 2012,
    sectors: ["Government", "Diplomatic", "NGO", "Defense", "Regional Policy"],
    regions: ["Southeast Asia", "Europe", "Taiwan", "Mongolia", "Global"],
    summary: "PRC-linked espionage actor targeting diplomatic, government, NGO, and regional policy entities with lure documents, archive payloads, and PlugX-family tooling.",
    campaigns: [
      ["Diplomatic and regional policy targeting", "2012 to present", "Government, diplomatic, NGO", "Southeast Asia, Europe, Taiwan", "Spearphishing, archive files, and lure documents", "Credential theft and espionage collection", "https://attack.mitre.org/groups/G0129/"],
      ["Ukraine-war themed European lures", "2022", "Diplomatic and government", "Europe", "Malicious archives and document lures", "PlugX deployment and collection", "https://www.proofpoint.com/us/blog/threat-insight/plugging-buggy-code-mustang-panda-campaign"],
      ["Removable-media and archive delivery waves", "2023 to 2025", "Government and regional organizations", "Asia-Pacific", "LNK/archive execution chains", "Backdoor access and document collection", "https://unit42.paloaltonetworks.com/stately-taurus-targets-philippines/"],
    ],
    tools: ["PlugX", "Korplug", "Toneshell", "LNK lures", "RAR archives", "DLL sideloading"],
    iocs: [["filename", "PlugX.exe"], ["filename", "Korplug.dll"], ["filename", "Toneshell.dll"], ["filename", "document.lnk"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Mustang Panda", "2025", "https://attack.mitre.org/groups/G0129/"],
      ["Vendor Report", "Proofpoint: Mustang Panda campaign", "2022", "https://www.proofpoint.com/us/blog/threat-insight/plugging-buggy-code-mustang-panda-campaign"],
      ["Vendor Report", "Unit 42: Stately Taurus targets Philippines", "2023", "https://unit42.paloaltonetworks.com/stately-taurus-targets-philippines/"],
    ],
  },
  {
    name: "Kimsuky",
    rank: 19,
    mitre: "G0094",
    aliases: ["Thallium", "Velvet Chollima", "Emerald Sleet", "APT43 overlap", "Black Banshee"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "North Korea",
    activeSince: 2012,
    sectors: ["Government", "Think Tanks", "Defense", "Academia", "Journalists", "Policy Research"],
    regions: ["South Korea", "United States", "Japan", "Europe"],
    summary: "DPRK-linked intelligence collection actor focused on policy, nuclear, sanctions, defense, and regional affairs through spearphishing and credential harvesting.",
    campaigns: [
      ["Think tank and policy credential collection", "2012 to present", "Think tanks, academia, journalists, government", "South Korea, United States, Europe", "Spearphishing and credential harvesting", "Mailbox access and strategic intelligence collection", "https://attack.mitre.org/groups/G0094/"],
      ["BabyShark and AppleSeed campaigns", "2019 to present", "Government and policy targets", "South Korea and global", "Malicious documents and PowerShell", "Backdoor access and collection", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a"],
      ["APT43 strategic intelligence and funding support", "2023 to present", "Policy and research organizations", "Global", "Credential theft, spoofed domains, and social engineering", "Intelligence collection and operational funding support", "https://cloud.google.com/blog/topics/threat-intelligence/apt43-north-korea-cybercrime-espionage"],
    ],
    tools: ["BabyShark", "AppleSeed", "PowerShell", "Browser credential theft", "Phishing kits", "Macro documents"],
    iocs: [["filename", "BabyShark.vbs"], ["filename", "AppleSeed.exe"], ["filename", "powershell.exe"], ["domain", "login-microsoftonline.example.invalid"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Kimsuky", "2025", "https://attack.mitre.org/groups/G0094/"],
      ["Government", "CISA: North Korean Kimsuky cyber activity", "2020-10-27", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a"],
      ["Vendor Report", "Mandiant: APT43 North Korean cybercrime and espionage", "2023-03-28", "https://cloud.google.com/blog/topics/threat-intelligence/apt43-north-korea-cybercrime-espionage"],
    ],
  },
  {
    name: "Turla",
    rank: 20,
    mitre: "G0010",
    aliases: ["Snake", "Venomous Bear", "Waterbug", "KRYPTON", "Uroburos"],
    type: "Nation-State",
    sponsorship: "State-Sponsored",
    origin: "Russia",
    activeSince: 2004,
    sectors: ["Government", "Diplomatic", "Defense", "Research", "Foreign Ministries"],
    regions: ["Europe", "Central Asia", "Middle East", "NATO-aligned countries"],
    summary: "Long-running Russian espionage actor using stealthy implants, proxy infrastructure, and patient collection against diplomatic and government targets.",
    campaigns: [
      ["Snake malware long-running espionage", "2004 to 2023", "Government and diplomatic networks", "Europe, Central Asia, NATO-aligned countries", "Stealth implants and proxy infrastructure", "Long-term intelligence collection", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a"],
      ["Diplomatic and foreign ministry operations", "2004 to present", "Diplomatic and government organizations", "Europe and Middle East", "Spearphishing, watering holes, and custom malware", "Email and document collection", "https://attack.mitre.org/groups/G0010/"],
      ["Kazuar and ComRAT tooling evolution", "2017 to present", "Government and defense", "Europe", "Custom backdoors and C2 infrastructure", "Stealthy persistence and exfiltration", "https://attack.mitre.org/software/S0265/"],
    ],
    tools: ["Snake", "ComRAT", "Kazuar", "Carbon", "Uroburos", "PowerShell"],
    iocs: [["filename", "snake.exe"], ["filename", "comrat.dll"], ["filename", "kazuar.exe"], ["filename", "carbon.dll"]],
    refs: [
      ["Framework", "MITRE ATT&CK: Turla", "2025", "https://attack.mitre.org/groups/G0010/"],
      ["Government", "CISA: Hunting Russian intelligence Snake malware", "2023-05-09", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a"],
      ["Framework", "MITRE ATT&CK Software: Kazuar", "2025", "https://attack.mitre.org/software/S0265/"],
    ],
  },
];

const stateTtps = [
  ["TA0001 Initial Access", "T1566", ".002", "Phishing: Spearphishing Link", "Targeted lures and credential capture remain durable espionage access paths.", "confirmed", "P2"],
  ["TA0001 Initial Access", "T1190", null, "Exploit Public-Facing Application", "State actors exploit edge services and public applications for scalable access.", "suspected", "P1"],
  ["TA0003 Persistence", "T1098", null, "Account Manipulation", "Long-lived identity access enables re-entry and quiet collection.", "confirmed", "P1"],
  ["TA0005 Defense Evasion", "T1070", null, "Indicator Removal", "Stealth-focused operators clear or minimize traces to extend dwell time.", "suspected", "P2"],
  ["TA0007 Discovery", "T1087", null, "Account Discovery", "Actors enumerate identity, network, and cloud resources before collection.", "confirmed", "P2"],
  ["TA0009 Collection", "T1114", null, "Email Collection", "Mailbox and document collection are common intelligence objectives.", "suspected", "P1"],
  ["TA0011 Command and Control", "T1105", null, "Ingress Tool Transfer", "Operators stage tools through C2 and legitimate services.", "confirmed", "P2"],
  ["TA0010 Exfiltration", "T1041", null, "Exfiltration Over C2 Channel", "Collected data may leave via encrypted C2 or legitimate cloud services.", "suspected", "P1"],
];

const ransomwareTtps = [
  ["TA0001 Initial Access", "T1133", null, "External Remote Services", "VPN, VDI, RDP, and remote-management exposure are frequent ransomware entry points.", "confirmed", "P1"],
  ["TA0001 Initial Access", "T1190", null, "Exploit Public-Facing Application", "Edge and public-server exploitation remains a common affiliate access path.", "confirmed", "P1"],
  ["TA0003 Persistence", "T1098", null, "Account Manipulation", "Operators create or modify accounts to maintain access during extortion operations.", "suspected", "P1"],
  ["TA0006 Credential Access", "T1003", ".001", "OS Credential Dumping: LSASS Memory", "Credential dumping enables privilege escalation and domain-wide access.", "confirmed", "P1"],
  ["TA0007 Discovery", "T1087", null, "Account Discovery", "Hands-on operators enumerate users, groups, domains, and high-value assets.", "confirmed", "P2"],
  ["TA0008 Lateral Movement", "T1021", ".001", "Remote Services: Remote Desktop Protocol", "RDP and SMB movement are common before data staging and encryption.", "confirmed", "P2"],
  ["TA0010 Exfiltration", "T1567", ".002", "Exfiltration to Cloud Storage", "Double-extortion crews commonly exfiltrate to public cloud or attacker-controlled storage.", "confirmed", "P1"],
  ["TA0040 Impact", "T1486", null, "Data Encrypted for Impact", "Encryption is used to disrupt operations and force payment.", "confirmed", "P1"],
];

const crimeTtps = [
  ["TA0001 Initial Access", "T1566", ".003", "Phishing: Spearphishing via Service", "Identity-first operators use SMS, voice, chat, and SaaS impersonation.", "confirmed", "P1"],
  ["TA0001 Initial Access", "T1078", null, "Valid Accounts", "Stolen credentials enable SaaS, VPN, VDI, and endpoint access.", "confirmed", "P1"],
  ["TA0003 Persistence", "T1098", ".005", "Account Manipulation: Device Registration", "Actors add MFA devices, OAuth grants, or recovery paths to persist.", "confirmed", "P1"],
  ["TA0006 Credential Access", "T1555", null, "Credentials from Password Stores", "Browser, password manager, and local secret theft supports monetization.", "suspected", "P1"],
  ["TA0007 Discovery", "T1087", null, "Account Discovery", "Actors enumerate identities and privileges before monetization.", "confirmed", "P2"],
  ["TA0008 Lateral Movement", "T1021", null, "Remote Services", "Remote services are used for lateral movement and access resale.", "confirmed", "P2"],
  ["TA0010 Exfiltration", "T1567", null, "Exfiltration Over Web Service", "Cloud storage, SaaS exports, and attacker-controlled web services support data theft.", "confirmed", "P1"],
  ["TA0040 Impact", "T1490", null, "Inhibit System Recovery", "Financially motivated actors increasingly target backups before extortion.", "suspected", "P2"],
];

function ttpsFor(actor) {
  if (actor.type === "Nation-State") return stateTtps;
  if (actor.type === "Ransomware-as-a-Service" || actor.type === "Ransomware Affiliate") return ransomwareTtps;
  return crimeTtps;
}

function bodyMd(actor) {
  const ttps = ttpsFor(actor);
  const campaignLines = actor.campaigns.map((c) => `- ${c[0]} (${c[1]}): ${c[4]}; outcome: ${c[5]}.`).join("\n");
  const infra = infrastructureProfile(actor);
  return `# ${actor.name} - Threat Actor Profile

## Executive Summary
${actor.name} is ranked #${actor.rank} in OptraSight batch 1 because it combines recent activity, sector relevance, and high defensive value. ${actor.summary} Monitor this actor as a ${actor.type} threat with ${actor.sponsorship.toLowerCase()} sponsorship and ${actor.origin || "unknown"} assessed origin.

## Campaigns
${campaignLines}

## Indicators And Handling
Public indicators for ${actor.name} should be handled with expiry and context. Store fresh IPs/domains from trusted feeds with TTLs; treat the indicators in this profile as hunt seeds, not blocklist-only truth. Priority observable families are: ${actor.iocs.map((i) => i[1]).join(", ")}.

## Infrastructure
Common infrastructure patterns include ${infra.patterns.join(", ")}. Watch for ${infra.watch.join(", ")}. For cloud and identity-heavy environments, correlate IdP, VPN, EDR, DNS, proxy, mailbox audit, and CASB logs rather than relying on single indicators.

## Diamond Model
Adversary: ${actor.name} and aliases ${actor.aliases.join(", ")}. Capability: ${actor.tools.join(", ")}. Infrastructure: ${infra.patterns.join(", ")}. Victim: ${actor.sectors.join(", ")} across ${actor.regions.join(", ")}.

## Priority ATT&CK Coverage
${ttps.map((t) => `- ${t[1]}${t[2] || ""} ${t[3]} (${t[0]}): ${t[4]}`).join("\n")}

## Defensive Priorities
- Enforce phishing-resistant MFA and review help-desk identity proofing for privileged and remote users.
- Harden exposed VPN, VDI, file-transfer, email, SSO, and network-device management planes.
- Alert on credential dumping, MFA resets, new OAuth grants, unusual admin console use, bulk archive creation, and large outbound transfers.
- Validate immutable backups, recovery sequencing, legal notification paths, and executive communications for extortion or espionage scenarios.

## Forecast
Through 2026, ${actor.name} is expected to remain relevant where targets expose identity providers, cloud control planes, remote access, file-transfer systems, or edge appliances. Review this profile quarterly or after credible vendor/government reporting changes its tooling, victimology, or infrastructure model.

## Sources
${actor.refs.map((r, ix) => `${ix + 1}. ${r[1]} (${r[2]}) - ${r[3]}`).join("\n")}`;
}

function infrastructureProfile(actor) {
  if (actor.type === "Nation-State") {
    return {
      patterns: ["compromised edge devices", "VPS and cloud relays", "web shells", "living-off-the-land administration channels", "encrypted C2"],
      watch: ["new admin accounts", "network-device config changes", "mailbox API access", "PowerShell/WMI bursts", "long-tail DNS and proxy egress"],
      c2: ["HTTPS", "web shells", "proxy chains"],
      notes: "Expect infrastructure to blend compromised systems, legitimate services, and low-volume operator access.",
    };
  }
  if (actor.type === "Organized Cybercrime") {
    return {
      patterns: ["phishing domains", "IdP lookalike portals", "RMM infrastructure", "cloud storage", "anonymous tunnels"],
      watch: ["MFA reset events", "new device registrations", "OAuth grants", "RMM installation", "SaaS bulk exports"],
      c2: ["RMM", "HTTPS", "cloud service APIs"],
      notes: "Identity telemetry is the strongest infrastructure lens for this actor class.",
    };
  }
  return {
    patterns: ["leak sites", "access broker credentials", "RMM tooling", "cloud exfiltration endpoints", "rented VPS"],
    watch: ["VPN login anomalies", "archive staging", "rclone traffic", "backup tampering", "mass service creation"],
    c2: ["HTTPS", "RMM", "remote services"],
    notes: "Ransomware infrastructure changes quickly; prioritize behavioral correlation and recent CTI feeds.",
  };
}

function headerPatch(actor) {
  const infra = infrastructureProfile(actor);
  const ttps = ttpsFor(actor);
  const motivation = actor.type === "Nation-State"
    ? ["Espionage", "Strategic access", "Intelligence collection"]
    : actor.type === "Organized Cybercrime"
      ? ["Financial gain", "Credential theft", "Access monetization", "Extortion enablement"]
      : ["Financial gain", "Data theft", "Extortion"];
  return {
    mitre_group_id: actor.mitre,
    aliases: j(actor.aliases),
    vendor_names: j({ optrasight: [actor.name, ...actor.aliases], mitre: actor.mitre ? [actor.mitre] : [] }),
    actor_type: actor.type,
    sponsorship: actor.sponsorship,
    assessed_origin: actor.origin === "Unknown" ? null : actor.origin,
    origin_confidence: actor.origin === "Unknown" ? "Medium" : "Likely",
    sponsoring_entity: actor.type === "Nation-State" ? `${actor.origin} state nexus` : null,
    motivation: j(motivation),
    active_since: actor.activeSince,
    sophistication: actor.type === "Nation-State" ? "Advanced" : actor.rank <= 12 ? "Advanced" : "Intermediate",
    tlp: "AMBER",
    admiralty_source: "B",
    admiralty_info: "2",
    wep_confidence: "Likely",
    target_sectors: j(actor.sectors),
    target_regions: j(actor.regions),
    target_tech_stack: j(["Identity Provider", "VPN/VDI", "Microsoft 365", "Endpoint", "Edge Devices", "Cloud Storage", "Backup Platforms"]),
    org_size_preference: "Medium to enterprise",
    intent_proximity: actor.rank <= 12 ? "Direct" : "Opportunistic",
    relevance_rating: `Batch 1 rank #${actor.rank}`,
    exec_what: actor.summary,
    exec_so_what: `${actor.name} can materially affect confidentiality, operational continuity, regulatory exposure, and executive crisis management for tenants with exposed identity, cloud, edge, or high-value data systems.`,
    exec_what_now: "Prioritize identity hardening, edge-service exposure reduction, ATT&CK hunt coverage, immutable backup validation, and fresh CTI feed review.",
    threat_level: actor.rank <= 12 ? "HIGH" : "MODERATE",
    threat_level_rationale: `Selected for batch 1 due to current relevance, sector overlap, campaign history, and high detection value. Rank #${actor.rank}.`,
    sector_actively_targeted: 1,
    diamond_adversary: j({ name: actor.name, aliases: actor.aliases, type: actor.type, origin: actor.origin, confidence: "Likely" }),
    diamond_capability: j({ tools: actor.tools, ttps: ttps.map((t) => t[1] + (t[2] || "")), sophistication: actor.type === "Nation-State" ? "Advanced" : "Advanced" }),
    diamond_infrastructure: j(infra),
    diamond_victim: j({ sectors: actor.sectors, regions: actor.regions, orgSize: "Medium to enterprise", priorityAssets: ["identity", "mail", "remote access", "edge devices", "file stores", "backups"] }),
    diamond_meta: j({ confidence: "Likely", rank: actor.rank, cutoff: "2026-06-04", sourceCount: actor.refs.length }),
    business_impact: j({
      Financial: actor.type === "Nation-State" ? "Medium" : "High",
      Operational: actor.rank <= 12 ? "High" : "Medium",
      Reputational: "High",
      Regulatory: "Medium",
      Data: "High",
      Strategic: actor.type === "Nation-State" ? "High" : "Medium",
    }),
    capability_profile: j({ tier: actor.type === "Nation-State" ? "Advanced" : "Advanced", evidence: actor.summary, tooling: actor.tools, coordination: actor.sponsorship }),
    infrastructure_profile: j(infra),
    ir_actions: j({
      immediate: ["Preserve IdP/VPN/EDR/DNS/proxy logs", "Disable suspect accounts and tokens", "Isolate confirmed hosts", "Snapshot cloud audit state"],
      shortTerm: ["Rotate privileged credentials", "Hunt priority ATT&CK techniques", "Review remote access and MFA reset activity", "Scope exfiltration"],
      mediumTerm: ["Close exposed edge paths", "Validate backup integrity", "Deploy missing detections", "Refresh CTI feed indicators with TTLs"],
      strategic: ["Run tabletop exercise", "Review crisis communications", "Assess third-party exposure", "Update threat model quarterly"],
    }),
    countermeasures: j({
      d3fend: ["D3-MFA", "D3-ACH", "D3-LFP", "D3-NTA", "D3-SFA"],
      cisV8: ["5 Account Management", "6 Access Control Management", "8 Audit Log Management", "12 Network Infrastructure Management", "13 Network Monitoring and Defense"],
      iso27001: ["A.5.15 Access control", "A.8.15 Logging", "A.8.16 Monitoring activities", "A.8.20 Network security"],
    }),
    forecast: `Expected to remain relevant through 2026 where tenant exposure overlaps ${actor.sectors.slice(0, 3).join(", ")} and high-value identity, cloud, remote-access, or edge systems.`,
    extortion_tactics: j(actor.type === "Nation-State" ? {} : { dataTheft: true, leakSitePressure: actor.type !== "Organized Cybercrime", encryption: actor.type !== "Organized Cybercrime", socialPressure: true }),
    body_md: bodyMd(actor),
    status: "approved",
    cutoff_date: "2026-06-04",
    prepared_by: "OptraSight CTI batch enrichment",
    ai_provider_label: "Manual CTI enrichment",
  };
}

function replaceSubresources(actor, row, ts) {
  for (const table of ["threat_actor_ttps", "threat_actor_tools", "threat_actor_campaigns", "threat_actor_iocs", "threat_actor_references"]) {
    db.prepare(`DELETE FROM ${table} WHERE tenant_id = ? AND actor_id = ?`).run(row.tenant_id, row.id);
  }
  for (const t of ttpsFor(actor)) {
    db.prepare(`INSERT INTO threat_actor_ttps
      (id, tenant_id, actor_id, tactic, technique_id, sub_technique_id, technique_name, evidence, status, detection_priority, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), row.tenant_id, row.id, t[0], t[1], t[2], t[3], `${actor.name}: ${t[4]}`, t[5], t[6], ts);
  }
  for (const tool of actor.tools) {
    db.prepare(`INSERT INTO threat_actor_tools
      (id, tenant_id, actor_id, name, category, purpose, variants, hash_or_rule, confidence, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), row.tenant_id, row.id, tool, toolCategory(actor, tool), toolPurpose(actor, tool), j([]), null, "Likely", ts);
  }
  for (const c of actor.campaigns) {
    db.prepare(`INSERT INTO threat_actor_campaigns
      (id, tenant_id, actor_id, name, period, target_sector, target_geography, initial_access, outcome, source_url, finding_ids, rule_ids, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), row.tenant_id, row.id, c[0], c[1], c[2], c[3], c[4], c[5], c[6], j([]), j([]), ts);
  }
  for (const ioc of actor.iocs) {
    db.prepare(`INSERT INTO threat_actor_iocs
      (id, tenant_id, actor_id, ioc_type, value, first_seen, last_confirmed, confidence, tlp, source, mitre_ttps, recommended_action, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), row.tenant_id, row.id, ioc[0], ioc[1], null, "2026-06-04", "Possible", "AMBER", `${actor.name} batch 1 profile`, j(ttpsFor(actor).map((t) => t[1] + (t[2] || ""))), "Hunt and correlate with tenant telemetry before blocking; refresh from live CTI feeds before enforcement.", ts);
  }
  actor.refs.forEach((ref, ix) => {
    db.prepare(`INSERT INTO threat_actor_references
      (id, tenant_id, actor_id, ref_num, source_type, title, date, url, archive_url, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), row.tenant_id, row.id, ix + 1, ref[0], ref[1], ref[2], ref[3], null, ts);
  });
}

function toolCategory(actor, tool) {
  const v = tool.toLowerCase();
  if (v.includes("ransom") || v.includes("lockbit") || v.includes("blackcat") || v.includes("akira") || v.includes("qilin")) return "ransomware";
  if (v.includes("rclone") || v.includes("exmatter")) return "exfiltration";
  if (v.includes("mimikatz") || v.includes("credential")) return "credential access";
  if (v.includes("web shell") || v.includes("shell") || v.includes("plugx") || v.includes("snake") || v.includes("kazuar") || v.includes("sunburst")) return "backdoor";
  if (v.includes("powershell") || v.includes("wmi") || v.includes("netsh") || v.includes("cmd")) return "living-off-the-land";
  if (actor.type === "Organized Cybercrime") return "identity intrusion";
  return "tooling";
}

function toolPurpose(actor, tool) {
  const v = tool.toLowerCase();
  if (v.includes("ransom")) return "Encrypt systems or support extortion impact after intrusion staging.";
  if (v.includes("rclone")) return "Stage or exfiltrate bulk data to attacker-controlled storage.";
  if (v.includes("mimikatz")) return "Dump credentials and enable lateral movement.";
  if (v.includes("powershell") || v.includes("wmi") || v.includes("netsh")) return "Use native administration paths for stealthy execution and discovery.";
  if (actor.type === "Organized Cybercrime") return "Support identity takeover, remote access, SaaS abuse, or exfiltration.";
  return "Support access, persistence, command execution, collection, or exfiltration.";
}

function findRows(actor) {
  const primaryNeedle = actor.name.toLowerCase();
  const rows = db.prepare("SELECT * FROM threat_actors").all();
  return rows.filter((r) => {
    const primary = String(r.primary_name || "").toLowerCase();
    return primary === primaryNeedle;
  });
}

const updateActor = db.transaction((actor, row, ts) => {
  const patch = headerPatch(actor);
  db.prepare(`UPDATE threat_actors SET
    mitre_group_id = @mitre_group_id,
    aliases = @aliases,
    vendor_names = @vendor_names,
    actor_type = @actor_type,
    sponsorship = @sponsorship,
    assessed_origin = @assessed_origin,
    origin_confidence = @origin_confidence,
    sponsoring_entity = @sponsoring_entity,
    motivation = @motivation,
    active_since = @active_since,
    sophistication = @sophistication,
    tlp = @tlp,
    admiralty_source = @admiralty_source,
    admiralty_info = @admiralty_info,
    wep_confidence = @wep_confidence,
    target_sectors = @target_sectors,
    target_regions = @target_regions,
    target_tech_stack = @target_tech_stack,
    org_size_preference = @org_size_preference,
    intent_proximity = @intent_proximity,
    relevance_rating = @relevance_rating,
    exec_what = @exec_what,
    exec_so_what = @exec_so_what,
    exec_what_now = @exec_what_now,
    threat_level = @threat_level,
    threat_level_rationale = @threat_level_rationale,
    sector_actively_targeted = @sector_actively_targeted,
    diamond_adversary = @diamond_adversary,
    diamond_capability = @diamond_capability,
    diamond_infrastructure = @diamond_infrastructure,
    diamond_victim = @diamond_victim,
    diamond_meta = @diamond_meta,
    business_impact = @business_impact,
    capability_profile = @capability_profile,
    infrastructure_profile = @infrastructure_profile,
    ir_actions = @ir_actions,
    countermeasures = @countermeasures,
    forecast = @forecast,
    extortion_tactics = @extortion_tactics,
    body_md = @body_md,
    status = @status,
    version = version + 1,
    cutoff_date = @cutoff_date,
    prepared_by = @prepared_by,
    ai_provider_label = @ai_provider_label,
    updated_at = @updated_at
    WHERE tenant_id = @tenant_id AND id = @id`).run({ ...patch, updated_at: ts, tenant_id: row.tenant_id, id: row.id });
  replaceSubresources(actor, row, ts);
  db.prepare("INSERT INTO audit_log (id, tenant_id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(id(), row.tenant_id, "system", "threat_actor.batch1_enrich", row.id, j({ profileId: row.profile_id, primaryName: row.primary_name, rank: actor.rank, source: "scripts/enrich-tap-batch1.cjs" }), ts);
});

let updated = 0;
let matchedActors = 0;
const ts = now();
for (const actor of BATCH) {
  const rows = findRows(actor);
  if (rows.length === 0) {
    console.warn(`No matching TAP rows found for ${actor.name}`);
    continue;
  }
  matchedActors += 1;
  for (const row of rows) {
    updateActor(actor, row, ts);
    updated += 1;
  }
}

console.log(`Batch 1 enriched ${matchedActors}/${BATCH.length} selected actors across ${updated} TAP row(s) in ${dbPath}.`);
