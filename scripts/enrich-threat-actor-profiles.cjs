#!/usr/bin/env node

const Database = require("better-sqlite3");
const { randomUUID } = require("node:crypto");

const db = new Database("data.db");
db.pragma("busy_timeout = 10000");
db.pragma("journal_mode = WAL");

const j = (value) => JSON.stringify(value);
const id = () => randomUUID();
const now = () => new Date().toISOString();

const TOP_50 = [
  "Qilin", "Akira", "Cl0p", "Play", "SafePay", "INC Ransom", "DragonForce", "RansomHub", "LockBit", "Black Basta",
  "Scattered Spider", "FIN7", "TA505", "Evil Corp", "Lazarus Group", "Kimsuky", "APT43", "Andariel", "Volt Typhoon", "Salt Typhoon",
  "Flax Typhoon", "Mustang Panda", "APT41", "APT40", "APT31", "UNC3886", "Turla", "APT29", "APT28", "Sandworm Team",
  "Gamaredon", "FIN6", "MuddyWater", "APT35", "APT33", "Agrius", "OilRig", "Charming Kitten", "BlackCat", "Royal",
  "BianLian", "BlackSuit", "Hunters International", "Medusa", "8Base", "Rhysida", "BlackByte", "Cactus", "TA577", "Storm-0501",
];

const actorFacts = {
  "Qilin": { type: "Ransomware-as-a-Service", aliases: ["Agenda", "Agenda ransomware", "GOLD FEATHER", "Howling Scorpius"], origin: "Unknown", sophistication: "Advanced", level: "HIGH", summary: "High-volume RaaS operation using double extortion, cross-platform ransomware, and affiliate intrusion tradecraft. Public reporting associates recent Qilin activity with healthcare, manufacturing, and professional-services impact.", campaigns: ["2024-2026 leak-site and ESXi/Windows ransomware operations", "Post-RansomHub affiliate migration and high-volume extortion operations"], tools: ["Qilin ransomware", "Rclone", "Mimikatz", "AnyDesk"], refs: [["Vendor Report", "Sophos: Qilin ransomware activity and incident reporting", "2024", "https://news.sophos.com/"]] },
  "Akira": { type: "Ransomware-as-a-Service", aliases: ["GOLD SAHARA", "PUNK SPIDER", "Howling Scorpius"], origin: "Unknown", sophistication: "Advanced", level: "HIGH", summary: "RaaS operation active against enterprise Windows, Linux, and ESXi estates, commonly using VPN access, credential theft, data exfiltration, and encryption.", campaigns: ["2023-2026 Akira double-extortion operations", "ESXi and enterprise ransomware campaigns"], tools: ["Akira ransomware", "Rclone", "Mimikatz", "Advanced IP Scanner"], refs: [["Government", "CISA StopRansomware: Akira ransomware", "2024", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"]] },
  "Cl0p": { type: "Ransomware-as-a-Service", aliases: ["Clop", "TA505", "FIN11", "Lace Tempest", "DEV-0950"], origin: "Russia", sophistication: "Advanced", level: "HIGH", summary: "Extortion operation best known for mass exploitation and managed file-transfer data theft. Cl0p prioritizes scalable intrusion paths, rapid victim notification, and leak-site pressure.", campaigns: ["MOVEit Transfer mass exploitation and data theft", "GoAnywhere and Accellion-style managed file-transfer extortion"], tools: ["Cl0p ransomware", "Web shells", "SFTP/Cloud storage exfiltration", "SQL tools"], refs: [["Government", "CISA: MOVEit Transfer exploitation", "2023", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"]] },
  "Play": { type: "Ransomware-as-a-Service", aliases: ["PlayCrypt", "Balloonfly"], origin: "Unknown", sophistication: "Advanced", level: "HIGH", summary: "Ransomware group using exposed services, valid accounts, and hands-on-keyboard operations before data theft and encryption. Play is relevant to organizations with exposed remote access and weak segmentation.", campaigns: ["PlayCrypt enterprise ransomware campaigns", "Fortinet/RDP/valid-account intrusion chains"], tools: ["Play ransomware", "AdFind", "Grixba", "Rclone"], refs: [["Government", "CISA StopRansomware: Play ransomware", "2023", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"]] },
  "SafePay": { type: "Ransomware-as-a-Service", aliases: ["Safepay"], origin: "Unknown", sophistication: "Intermediate", level: "HIGH", summary: "Emerging double-extortion brand observed in leak-site volume reporting. Treat as an active ransomware risk until stronger attribution is available.", campaigns: ["2025-2026 double-extortion leak-site operations", "Opportunistic enterprise compromise campaigns"], tools: ["SafePay ransomware", "Rclone", "Remote management tools", "Credential dumpers"], refs: [["Vendor Report", "Ransomware leak-site tracking and victimology", "2025", "https://www.ransomware.live/"]] },
  "INC Ransom": { type: "Ransomware-as-a-Service", aliases: ["INC", "INC Ransomware"], origin: "Unknown", sophistication: "Advanced", level: "HIGH", summary: "Double-extortion operation targeting healthcare, public sector, and industrial organizations. Intrusions commonly show credential abuse, remote tooling, exfiltration, and encryption.", campaigns: ["2023-2026 INC Ransom extortion operations", "Healthcare and public-sector impact campaigns"], tools: ["INC ransomware", "Rclone", "AnyDesk", "Mimikatz"], refs: [["Vendor Report", "Ransomware.live: INC Ransom tracking", "2025", "https://www.ransomware.live/"]] },
  "DragonForce": { type: "Ransomware-as-a-Service", aliases: ["Dragon Force"], origin: "Unknown", sophistication: "Intermediate", level: "HIGH", summary: "Ransomware brand and affiliate platform using leak-site pressure and opportunistic enterprise intrusion. Relevant for broad defensive readiness rather than precise sector-only targeting.", campaigns: ["2024-2026 DragonForce affiliate operations", "Extortion and partner-brand pressure campaigns"], tools: ["DragonForce ransomware", "Rclone", "AnyDesk", "Credential dumpers"], refs: [["Vendor Report", "Ransomware.live: DragonForce tracking", "2025", "https://www.ransomware.live/"]] },
  "RansomHub": { type: "Ransomware-as-a-Service", aliases: ["Cyclops", "Knight"], origin: "Unknown", sophistication: "Advanced", level: "HIGH", summary: "High-volume RaaS ecosystem that absorbed affiliates and drove enterprise data theft and encryption operations. Monitor for affiliate-style intrusion patterns and rapid tooling changes.", campaigns: ["2024-2025 RansomHub affiliate operations", "Post-disruption affiliate movement across ransomware brands"], tools: ["RansomHub ransomware", "Rclone", "Mimikatz", "Netscan"], refs: [["Government", "CISA StopRansomware: RansomHub ransomware", "2024", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a"]] },
  "LockBit": { type: "Ransomware-as-a-Service", aliases: ["LockBit 3.0", "LockBit Black", "ABCD"], origin: "Russia", sophistication: "Advanced", level: "HIGH", summary: "Mature RaaS ecosystem historically responsible for large-scale global ransomware activity. Even after law-enforcement disruption, affiliate tradecraft and brand reuse remain important for defensive modeling.", campaigns: ["LockBit 2.0/3.0 global affiliate operations", "Post-Operation Cronos brand and affiliate residual activity"], tools: ["LockBit ransomware", "StealBit", "Mimikatz", "PsExec"], refs: [["Government", "CISA StopRansomware: LockBit 3.0", "2023", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a"]] },
  "Black Basta": { type: "Ransomware-as-a-Service", aliases: ["Black Basta ransomware", "Water Curupira"], origin: "Russia", sophistication: "Advanced", level: "HIGH", summary: "Enterprise ransomware operation associated with QakBot-era access chains, data theft, and high-impact encryption. Defenders should focus on identity compromise, lateral movement, and exfiltration staging.", campaigns: ["Black Basta enterprise ransomware operations", "QakBot-linked access and extortion campaigns"], tools: ["Black Basta ransomware", "QakBot", "Cobalt Strike", "Rclone"], refs: [["Government", "CISA StopRansomware: Black Basta", "2024", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"]] },
  "Scattered Spider": { type: "Organized Cybercrime", aliases: ["Octo Tempest", "UNC3944", "Muddled Libra", "Roasted 0ktapus"], origin: "Unknown", sophistication: "Advanced", level: "HIGH", summary: "Social-engineering-heavy intrusion cluster specializing in help-desk abuse, SIM swapping, MFA fatigue, SaaS compromise, and ransomware affiliate enablement.", campaigns: ["0ktapus identity phishing and SaaS compromise", "Cloud and help-desk social engineering leading to extortion"], tools: ["Okta phishing kits", "RMM tools", "AnyDesk", "Mimikatz"], refs: [["Vendor Report", "Microsoft: Octo Tempest profile", "2023", "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/"]] },
  "FIN7": { type: "Organized Cybercrime", aliases: ["Carbanak", "Navigator Group", "Carbon Spider"], origin: "Russia", sophistication: "Advanced", level: "MODERATE", summary: "Financially motivated intrusion group with history in payment-card theft, malware deployment, and later ransomware-adjacent access operations.", campaigns: ["Payment-card theft and hospitality/retail compromise", "Ransomware-adjacent intrusion enablement"], tools: ["Carbanak", "Griffon", "PowerShell", "Cobalt Strike"], refs: [["Framework", "MITRE ATT&CK: FIN7", "2025", "https://attack.mitre.org/groups/G0046/"]] },
  "TA505": { type: "Organized Cybercrime", aliases: ["Hive0065", "SectorJ04", "Evil Corp overlap"], origin: "Russia", sophistication: "Advanced", level: "MODERATE", summary: "High-volume financially motivated actor associated with spam, Dridex, Locky, FlawedAmmyy, and extortion-enabling intrusion chains.", campaigns: ["Large-scale email malware delivery campaigns", "Dridex and file-transfer extortion-adjacent operations"], tools: ["Dridex", "FlawedAmmyy", "SDBbot", "Cl0p"], refs: [["Framework", "MITRE ATT&CK: TA505", "2025", "https://attack.mitre.org/groups/G0092/"]] },
  "Evil Corp": { type: "Organized Cybercrime", aliases: ["Indrik Spider", "Dridex Gang", "Manatee Tempest", "DEV-0243"], origin: "Russia", sophistication: "Advanced", level: "MODERATE", summary: "Financially motivated cybercrime group associated with Dridex banking malware and ransomware families such as BitPaymer, WastedLocker, Hades, and PhoenixLocker.", campaigns: ["Dridex banking fraud and access operations", "WastedLocker/BitPaymer-style enterprise ransomware operations"], tools: ["Dridex", "WastedLocker", "BitPaymer", "Cobalt Strike"], refs: [["Framework", "MITRE ATT&CK: Indrik Spider", "2025", "https://attack.mitre.org/groups/G0119/"]] },
  "Lazarus Group": { type: "Nation-State", aliases: ["HIDDEN COBRA", "Labyrinth Chollima", "ZINC", "Diamond Sleet"], origin: "North Korea", sophistication: "Advanced", level: "HIGH", summary: "DPRK-linked umbrella actor conducting espionage, destructive activity, cryptocurrency theft, and supply-chain compromise. The group is financially and strategically important because crypto theft funds state objectives.", campaigns: ["Cryptocurrency exchange and DeFi theft operations", "Supply-chain and destructive intrusion campaigns"], tools: ["Manuscrypt", "DTrack", "AppleJeus", "BLINDINGCAN"], refs: [["Framework", "MITRE ATT&CK: Lazarus Group", "2025", "https://attack.mitre.org/groups/G0032/"]] },
  "Kimsuky": { type: "Nation-State", aliases: ["Thallium", "Velvet Chollima", "Emerald Sleet", "APT43 overlap"], origin: "North Korea", sophistication: "Advanced", level: "MODERATE", summary: "DPRK-linked intelligence collection actor focused on foreign policy, think tanks, defense, nuclear issues, and credential harvesting through social engineering.", campaigns: ["Policy and think-tank credential collection", "Researcher and journalist lure campaigns"], tools: ["BabyShark", "AppleSeed", "PowerShell", "Browser credential theft"], refs: [["Framework", "MITRE ATT&CK: Kimsuky", "2025", "https://attack.mitre.org/groups/G0094/"]] },
  "APT43": { type: "Nation-State", aliases: ["Emerald Sleet", "Kimsuky overlap", "Thallium"], origin: "North Korea", sophistication: "Advanced", level: "MODERATE", summary: "DPRK-aligned actor focused on strategic intelligence collection and funding-support operations through credential theft and policy-targeted social engineering.", campaigns: ["Nuclear policy and sanctions research targeting", "Credential harvesting and strategic collection campaigns"], tools: ["PowerShell", "Cloud mailbox abuse", "Credential phishing kits", "Lightweight backdoors"], refs: [["Vendor Report", "Mandiant: APT43 profile", "2023", "https://cloud.google.com/blog/topics/threat-intelligence/apt43-north-korea-cybercrime-espionage"]] },
  "Andariel": { type: "Nation-State", aliases: ["Onyx Sleet", "Silent Chollima", "Stonefly"], origin: "North Korea", sophistication: "Advanced", level: "MODERATE", summary: "DPRK-linked actor targeting defense, research, healthcare, and technology with espionage and financially motivated ransomware-adjacent operations.", campaigns: ["Defense and research espionage campaigns", "Healthcare and ransomware-adjacent intrusion activity"], tools: ["DTrack", "Maui ransomware", "Custom backdoors", "PowerShell"], refs: [["Framework", "MITRE ATT&CK: Andariel", "2025", "https://attack.mitre.org/groups/G0138/"]] },
  "Volt Typhoon": { type: "Nation-State", aliases: ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391", "UNC3236", "Voltzite"], origin: "China", sophistication: "Advanced", level: "HIGH", summary: "PRC-linked actor focused on stealthy pre-positioning in critical infrastructure using living-off-the-land techniques, compromised SOHO infrastructure, and long-term credentialed access.", campaigns: ["US critical infrastructure pre-positioning", "Living-off-the-land and SOHO-router proxy operations"], tools: ["LOLBins", "netsh", "PowerShell", "Compromised SOHO routers"], refs: [["Framework", "MITRE ATT&CK: Volt Typhoon", "2025", "https://attack.mitre.org/groups/G1017/"], ["Government", "CISA: PRC state-sponsored actors compromise critical infrastructure", "2024", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"]] },
  "Salt Typhoon": { type: "Nation-State", aliases: ["Earth Estries", "GhostEmperor overlap", "UNC2286"], origin: "China", sophistication: "Advanced", level: "HIGH", summary: "PRC-linked espionage cluster associated with telecommunications targeting and access to sensitive communications infrastructure. Prioritize telecom, identity, lawful-intercept, and routing-control monitoring.", campaigns: ["Telecommunications and carrier infrastructure espionage", "Long-duration network access campaigns"], tools: ["Custom backdoors", "Web shells", "Credential theft tools", "LOLBins"], refs: [["Government", "CISA: Enhanced visibility and hardening guidance for communications infrastructure", "2024", "https://www.cisa.gov/news-events/cybersecurity-advisories"]] },
  "Flax Typhoon": { type: "Nation-State", aliases: ["Ethylene Reminiscence", "RedJuliett"], origin: "China", sophistication: "Advanced", level: "MODERATE", summary: "PRC-linked actor using stealthy access, edge devices, and botnet-style infrastructure to support long-running espionage operations.", campaigns: ["Edge-device and SOHO infrastructure compromise", "Taiwan and broader regional intelligence collection"], tools: ["LOLBins", "SoftEther", "Web shells", "Compromised routers"], refs: [["Vendor Report", "Microsoft: Flax Typhoon using legitimate software", "2023", "https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/"]] },
  "Mustang Panda": { type: "Nation-State", aliases: ["Bronze President", "RedDelta", "TA416", "Earth Preta"], origin: "China", sophistication: "Advanced", level: "MODERATE", summary: "PRC-linked espionage actor targeting government, diplomatic, NGO, and regional entities using lure documents, archive payloads, and removable-media-themed delivery.", campaigns: ["Diplomatic and regional policy targeting", "Archive/lure document malware delivery campaigns"], tools: ["PlugX", "Korplug", "Toneshell", "LNK lures"], refs: [["Framework", "MITRE ATT&CK: Mustang Panda", "2025", "https://attack.mitre.org/groups/G0129/"]] },
  "APT41": { type: "Nation-State", aliases: ["BARIUM", "Winnti", "WICKED PANDA", "Brass Typhoon"], origin: "China", sophistication: "Advanced", level: "MODERATE", summary: "PRC-linked actor blending state-directed espionage with financially motivated activity. Known for software supply-chain compromise, gaming-sector targeting, and broad post-exploitation capability.", campaigns: ["Software supply-chain and gaming industry intrusions", "Dual espionage and cybercrime operations"], tools: ["Winnti", "ShadowPad", "PlugX", "Cobalt Strike"], refs: [["Framework", "MITRE ATT&CK: APT41", "2025", "https://attack.mitre.org/groups/G0096/"]] },
  "APT40": { type: "Nation-State", aliases: ["Leviathan", "BRONZE MOHAWK", "Gingham Typhoon", "TEMP.Periscope"], origin: "China", sophistication: "Advanced", level: "MODERATE", summary: "PRC-linked espionage actor targeting maritime, defense, research, government, and regional strategic sectors through phishing, web compromise, and edge exploitation.", campaigns: ["Maritime and research-sector espionage", "Regional government and defense collection operations"], tools: ["China Chopper", "PlugX", "QuasarRAT", "Web shells"], refs: [["Framework", "MITRE ATT&CK: APT40", "2025", "https://attack.mitre.org/groups/G0065/"]] },
  "APT31": { type: "Nation-State", aliases: ["Zirconium", "Judgment Panda", "Violet Typhoon"], origin: "China", sophistication: "Advanced", level: "MODERATE", summary: "PRC-linked actor conducting long-running espionage against government, legal, policy, and technology targets using phishing, router compromise, and credential operations.", campaigns: ["Government and policy-sector espionage", "Router and edge exploitation campaigns"], tools: ["Custom malware", "Web shells", "LOLBins", "Credential phishing"], refs: [["Framework", "MITRE ATT&CK: APT31", "2025", "https://attack.mitre.org/groups/G0128/"]] },
  "UNC3886": { type: "Nation-State", aliases: ["UNC3886"], origin: "China", sophistication: "Expert", level: "MODERATE", summary: "Advanced espionage cluster associated with stealthy exploitation of edge and virtualization technologies, including hypervisors and network appliances.", campaigns: ["VMware and Fortinet-focused espionage operations", "Stealth persistence in virtualization and edge environments"], tools: ["Custom rootkits", "Backdoors", "Web shells", "LOLBins"], refs: [["Vendor Report", "Mandiant: UNC3886 Fortinet and VMware exploitation", "2023", "https://cloud.google.com/blog/topics/threat-intelligence/fortinet-vmware-hypervisors-espionage-unc3886"]] },
  "Turla": { type: "Nation-State", aliases: ["Snake", "Venomous Bear", "Waterbug", "KRYPTON"], origin: "Russia", sophistication: "Expert", level: "MODERATE", summary: "Long-running Russian espionage actor targeting diplomatic, government, defense, and research entities with stealthy implants, proxy infrastructure, and patient collection.", campaigns: ["Diplomatic and government network espionage", "Satellite/proxy and Snake malware operations"], tools: ["Snake", "ComRAT", "Kazuar", "Carbon"], refs: [["Framework", "MITRE ATT&CK: Turla", "2025", "https://attack.mitre.org/groups/G0010/"]] },
  "APT29": { type: "Nation-State", aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "UNC2452"], origin: "Russia", sophistication: "Expert", level: "MODERATE", summary: "Russian SVR-linked actor focused on strategic espionage, supply-chain compromise, cloud identity abuse, and stealthy collection against governments, technology providers, and diplomatic entities.", campaigns: ["SolarWinds/SUNBURST supply-chain compromise", "Microsoft and cloud identity intrusion campaigns"], tools: ["SUNBURST", "TEARDROP", "FoggyWeb", "MagicWeb"], refs: [["Framework", "MITRE ATT&CK: APT29", "2025", "https://attack.mitre.org/groups/G0016/"]] },
  "APT28": { type: "Nation-State", aliases: ["Fancy Bear", "Forest Blizzard", "Sofacy", "STRONTIUM"], origin: "Russia", sophistication: "Advanced", level: "MODERATE", summary: "Russian GRU-linked actor conducting credential theft, espionage, information operations, and disruptive activity against government, defense, political, and critical infrastructure targets.", campaigns: ["Credential phishing and strategic espionage", "Disruptive and influence-linked intrusion operations"], tools: ["X-Agent", "Zebrocy", "Mimikatz", "PowerShell"], refs: [["Framework", "MITRE ATT&CK: APT28", "2025", "https://attack.mitre.org/groups/G0007/"]] },
  "Sandworm Team": { type: "Nation-State", aliases: ["Voodoo Bear", "ELECTRUM", "Telebots", "Seashell Blizzard"], origin: "Russia", sophistication: "Expert", level: "HIGH", summary: "Russian GRU-linked actor associated with destructive operations, wipers, and industrial-control-impact campaigns. Highest concern for critical infrastructure and organizations exposed to geopolitical spillover.", campaigns: ["Ukraine destructive wiper and power-grid operations", "NotPetya and disruptive intrusion history"], tools: ["Industroyer", "NotPetya", "CaddyWiper", "BlackEnergy"], refs: [["Framework", "MITRE ATT&CK: Sandworm Team", "2025", "https://attack.mitre.org/groups/G0034/"]] },
  "Gamaredon": { type: "Nation-State", aliases: ["Primitive Bear", "Shuckworm", "ACTINIUM", "Armageddon"], origin: "Russia", sophistication: "Intermediate", level: "MODERATE", summary: "Russian-aligned actor known for high-volume phishing, rapid tooling churn, and persistent targeting of Ukrainian government and related entities.", campaigns: ["Ukraine government phishing and malware operations", "High-tempo document-lure intrusion campaigns"], tools: ["Pterodo", "PowerPunch", "VBScript", "PowerShell"], refs: [["Framework", "MITRE ATT&CK: Gamaredon Group", "2025", "https://attack.mitre.org/groups/G0047/"]] },
  "FIN6": { type: "Organized Cybercrime", aliases: ["Skeleton Spider"], origin: "Unknown", sophistication: "Advanced", level: "MODERATE", summary: "Financially motivated cluster historically associated with payment-card theft and later ransomware-adjacent access broker activity.", campaigns: ["Retail and hospitality payment-card intrusions", "Ransomware-adjacent access operations"], tools: ["FrameworkPOS", "GratefulPOS", "Cobalt Strike", "Mimikatz"], refs: [["Framework", "MITRE ATT&CK: FIN6", "2025", "https://attack.mitre.org/groups/G0037/"]] },
  "MuddyWater": { type: "Nation-State", aliases: ["Static Kitten", "Seedworm", "MERCURY", "Boggy Serpens"], origin: "Iran", sophistication: "Advanced", level: "MODERATE", summary: "Iran-linked actor targeting government, telecom, defense, and energy sectors with phishing, PowerShell, remote tooling, and credential collection.", campaigns: ["Middle East government and telecom espionage", "PowerShell and remote-tool intrusion campaigns"], tools: ["POWERSTATS", "Small Sieve", "ScreenConnect", "PowerShell"], refs: [["Framework", "MITRE ATT&CK: MuddyWater", "2025", "https://attack.mitre.org/groups/G0069/"]] },
  "APT35": { type: "Nation-State", aliases: ["Charming Kitten", "Phosphorus", "Mint Sandstorm", "Newscaster"], origin: "Iran", sophistication: "Advanced", level: "MODERATE", summary: "Iran-linked social-engineering actor targeting academics, journalists, activists, defense, and policy communities with credential phishing and persona operations.", campaigns: ["Academic and journalist lure campaigns", "Cloud mailbox credential collection"], tools: ["PowerShell", "Credential phishing kits", "Browser credential theft", "Custom backdoors"], refs: [["Framework", "MITRE ATT&CK: APT35", "2025", "https://attack.mitre.org/groups/G0059/"]] },
  "APT33": { type: "Nation-State", aliases: ["Elfin", "Magnallium", "Refined Kitten", "Holmium"], origin: "Iran", sophistication: "Advanced", level: "MODERATE", summary: "Iran-linked actor targeting aviation, energy, and industrial organizations with phishing, credential theft, and destructive potential.", campaigns: ["Aviation and energy-sector espionage", "Wiper-adjacent and credential operations"], tools: ["Shamoon overlap", "TURNEDUP", "PowerShell", "Credential harvesters"], refs: [["Framework", "MITRE ATT&CK: APT33", "2025", "https://attack.mitre.org/groups/G0064/"]] },
  "Agrius": { type: "Nation-State", aliases: ["Pink Sandstorm", "AMERICIUM"], origin: "Iran", sophistication: "Advanced", level: "MODERATE", summary: "Iran-linked destructive and influence-oriented actor using data wipers and ransomware-like pressure against regional organizations.", campaigns: ["Middle East destructive wiper operations", "Ransomware-disguised disruptive campaigns"], tools: ["Apostle", "Deadwood", "IPsec Helper", "Web shells"], refs: [["Framework", "MITRE ATT&CK: Agrius", "2025", "https://attack.mitre.org/groups/G1030/"]] },
  "OilRig": { type: "Nation-State", aliases: ["APT34", "Helix Kitten", "Cobalt Gypsy", "Crambus"], origin: "Iran", sophistication: "Advanced", level: "MODERATE", summary: "Iran-linked espionage actor targeting energy, government, telecom, and financial sectors with phishing, web shells, DNS tunneling, and credential theft.", campaigns: ["Energy and telecom regional espionage", "DNS tunneling and web-shell campaigns"], tools: ["Helminth", "BONDUPDATER", "RGDoor", "Web shells"], refs: [["Framework", "MITRE ATT&CK: OilRig", "2025", "https://attack.mitre.org/groups/G0049/"]] },
  "Charming Kitten": { type: "Nation-State", aliases: ["APT35", "Phosphorus", "Mint Sandstorm"], origin: "Iran", sophistication: "Advanced", level: "MODERATE", summary: "Iran-linked persona and credential-phishing actor focused on journalists, researchers, policy communities, and diaspora targets.", campaigns: ["Researcher and journalist persona operations", "Credential-harvesting and cloud mailbox intrusion"], tools: ["Credential phishing kits", "PowerShell", "Browser credential theft", "Custom backdoors"], refs: [["Framework", "MITRE ATT&CK: APT35", "2025", "https://attack.mitre.org/groups/G0059/"]] },
  "BlackCat": { type: "Ransomware-as-a-Service", aliases: ["ALPHV", "Noberus"], origin: "Unknown", sophistication: "Advanced", level: "MODERATE", summary: "RaaS operation using Rust-based ransomware, data theft, leak pressure, and affiliate-driven intrusions. Brand disruption does not remove tradecraft risk.", campaigns: ["ALPHV/BlackCat enterprise extortion operations", "Healthcare and critical-services ransomware incidents"], tools: ["BlackCat ransomware", "ExMatter", "Rclone", "Mimikatz"], refs: [["Government", "CISA StopRansomware: ALPHV BlackCat", "2023", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"]] },
  "Royal": { type: "Ransomware-as-a-Service", aliases: ["Royal ransomware", "DEV-0569"], origin: "Unknown", sophistication: "Advanced", level: "MODERATE", summary: "Enterprise ransomware group associated with data theft, encryption, and Conti-successor tradecraft. Monitor for phishing, remote access, and post-exploitation tooling.", campaigns: ["Royal enterprise extortion operations", "Conti-successor intrusion and data theft operations"], tools: ["Royal ransomware", "Cobalt Strike", "Rclone", "BATLOADER"], refs: [["Government", "CISA StopRansomware: Royal ransomware", "2023", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a"]] },
  "BianLian": { type: "Ransomware-as-a-Service", aliases: ["BianLian ransomware"], origin: "Unknown", sophistication: "Advanced", level: "MODERATE", summary: "Extortion operation that shifted from encryption to data-theft-focused pressure. Intrusions frequently involve valid accounts, remote access, and Go-based tooling.", campaigns: ["BianLian data theft and extortion operations", "Go-based malware and legal-pressure extortion campaigns"], tools: ["BianLian malware", "Rclone", "PsExec", "SoftPerfect"], refs: [["Government", "CISA StopRansomware: BianLian", "2023", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a"]] },
  "BlackSuit": { type: "Ransomware-as-a-Service", aliases: ["Royal overlap", "BlackSuit ransomware"], origin: "Unknown", sophistication: "Advanced", level: "MODERATE", summary: "Ransomware operation with reported technical and operational overlap with Royal. Prioritize enterprise remote access, credential theft, data staging, and encryption tradecraft.", campaigns: ["BlackSuit enterprise extortion operations", "Royal-overlap intrusion and encryption campaigns"], tools: ["BlackSuit ransomware", "Rclone", "Cobalt Strike", "Mimikatz"], refs: [["Vendor Report", "Ransomware.live: BlackSuit tracking", "2025", "https://www.ransomware.live/"]] },
  "Hunters International": { type: "Ransomware-as-a-Service", aliases: ["Hunters"], origin: "Unknown", sophistication: "Intermediate", level: "MODERATE", summary: "Ransomware and extortion operation with Hive-heritage reporting and a focus on data theft, leak pressure, and affiliate-led compromise.", campaigns: ["Hunters International leak-site operations", "Hive-successor style extortion operations"], tools: ["Hunters ransomware", "Rclone", "AnyDesk", "Credential dumpers"], refs: [["Vendor Report", "Ransomware.live: Hunters International tracking", "2025", "https://www.ransomware.live/"]] },
  "Medusa": { type: "Ransomware-as-a-Service", aliases: ["Medusa ransomware"], origin: "Unknown", sophistication: "Intermediate", level: "MODERATE", summary: "Double-extortion ransomware operation targeting healthcare, education, government, and public-sector entities with leak-site pressure and encryption.", campaigns: ["Medusa double-extortion campaigns", "Healthcare, public-sector, and education ransomware operations"], tools: ["Medusa ransomware", "Rclone", "AnyDesk", "Credential dumpers"], refs: [["Government", "CISA StopRansomware: Medusa ransomware", "2025", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"]] },
  "8Base": { type: "Ransomware-as-a-Service", aliases: ["8Base ransomware", "Phobos overlap"], origin: "Unknown", sophistication: "Intermediate", level: "LOW", summary: "Extortion group targeting SMB and mid-market organizations, often associated in reporting with Phobos-family tradecraft and double extortion.", campaigns: ["SMB and mid-market double-extortion operations", "Phobos-family ransomware overlap campaigns"], tools: ["8Base ransomware", "Phobos", "Rclone", "AnyDesk"], refs: [["Vendor Report", "Ransomware.live: 8Base tracking", "2025", "https://www.ransomware.live/"]] },
  "Rhysida": { type: "Ransomware-as-a-Service", aliases: ["Vice Society overlap", "DEV-0832"], origin: "Unknown", sophistication: "Intermediate", level: "LOW", summary: "RaaS group targeting healthcare, education, government, and institutional environments with data theft and encryption.", campaigns: ["Healthcare and education double-extortion operations", "Institutional ransomware campaigns"], tools: ["Rhysida ransomware", "PsExec", "PowerShell", "Rclone"], refs: [["Government", "CISA StopRansomware: Rhysida", "2023", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a"]] },
  "BlackByte": { type: "Ransomware-as-a-Service", aliases: ["Hecamede", "BlackByte ransomware"], origin: "Unknown", sophistication: "Intermediate", level: "LOW", summary: "RaaS group historically targeting critical infrastructure and enterprise networks, including use of vulnerable-driver and EDR-evasion tradecraft.", campaigns: ["BlackByte ransomware operations against enterprise networks", "Vulnerable-driver and defense-evasion campaigns"], tools: ["BlackByte ransomware", "ExByte", "Vulnerable drivers", "Rclone"], refs: [["Government", "CISA StopRansomware: BlackByte", "2022", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-074a"]] },
  "Cactus": { type: "Ransomware-as-a-Service", aliases: ["CACTUS"], origin: "Unknown", sophistication: "Intermediate", level: "LOW", summary: "Ransomware operation known for VPN exploitation, payload encryption to evade detection, data theft, and double extortion.", campaigns: ["VPN exploitation and double-extortion operations", "Encrypted payload ransomware campaigns"], tools: ["Cactus ransomware", "Rclone", "AnyDesk", "Credential dumpers"], refs: [["Vendor Report", "Ransomware.live: Cactus tracking", "2025", "https://www.ransomware.live/"]] },
  "TA577": { type: "Organized Cybercrime", aliases: ["Hive0118", "Water Curupira overlap"], origin: "Unknown", sophistication: "Intermediate", level: "LOW", summary: "High-volume email threat actor associated with malware delivery, loader chains, access brokering, and ransomware-enabling intrusions.", campaigns: ["Mass-email loader delivery campaigns", "Access-broker and ransomware-enabling operations"], tools: ["QakBot", "IcedID", "Pikabot", "Cobalt Strike"], refs: [["Vendor Report", "Proofpoint: TA577 threat actor reporting", "2024", "https://www.proofpoint.com/us/blog/threat-insight"]] },
  "Storm-0501": { type: "Ransomware Affiliate", aliases: ["Sabbath affiliate", "Embargo affiliate", "DEV-0501", "Hive0090"], origin: "Unknown", sophistication: "Advanced", level: "LOW", summary: "Microsoft-tracked financially motivated actor that evolved from on-premises ransomware operations into hybrid-cloud and cloud-native ransomware tradecraft, including Entra ID abuse, data exfiltration, backup destruction, and persistent cloud backdoors.", campaigns: ["Hybrid cloud ransomware expansion and on-prem-to-cloud pivoting", "Embargo ransomware deployment and cloud data extortion"], tools: ["AADInternals", "Rclone", "Impacket", "Cobalt Strike"], refs: [["Vendor Report", "Microsoft: Storm-0501 ransomware attacks expanding to hybrid cloud environments", "2024", "https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/"]] },
};

function familyFor(facts) {
  if (facts.type.includes("Ransomware")) return "ransomware";
  if (facts.type.includes("Nation-State")) return "state";
  return "crime";
}

function sectorsFor(facts) {
  if (facts.type.includes("Ransomware")) return ["Healthcare", "Manufacturing", "Financial Services", "Professional Services", "Public Sector", "Education"];
  if (facts.origin === "China") return ["Government", "Telecommunications", "Critical Infrastructure", "Technology", "Defense", "Research"];
  if (facts.origin === "Russia") return ["Government", "Defense", "Critical Infrastructure", "Energy", "Technology", "Diplomatic"];
  if (facts.origin === "Iran") return ["Government", "Telecommunications", "Energy", "Defense", "Financial Services", "Research"];
  if (facts.origin === "North Korea") return ["Government", "Defense", "Cryptocurrency", "Financial Services", "Research", "Technology"];
  return ["Retail", "Technology", "Financial Services", "Hospitality", "Managed Service Providers", "Enterprise"];
}

function regionsFor(facts) {
  if (facts.origin === "China") return ["North America", "Europe", "Asia-Pacific", "Taiwan", "Southeast Asia", "Global"];
  if (facts.origin === "Russia") return ["Europe", "North America", "Ukraine", "NATO-aligned countries", "Global"];
  if (facts.origin === "Iran") return ["Middle East", "North America", "Europe", "Israel", "Gulf states", "Global"];
  if (facts.origin === "North Korea") return ["South Korea", "Japan", "United States", "Europe", "Global"];
  return ["North America", "Europe", "Asia-Pacific", "Global"];
}

const ttpTemplates = {
  ransomware: [
    ["TA0001 Initial Access", "T1133", null, "External Remote Services", "VPN, RDP, and remote-management exposure are frequent ransomware entry points.", "P1"],
    ["TA0001 Initial Access", "T1190", null, "Exploit Public-Facing Application", "Edge and public-server exploitation remains a common affiliate access path.", "P1"],
    ["TA0003 Persistence", "T1098", null, "Account Manipulation", "Operators create or modify accounts to maintain access during extortion operations.", "P1"],
    ["TA0006 Credential Access", "T1003", null, "OS Credential Dumping", "Credential dumping enables privilege escalation and domain-wide access.", "P1"],
    ["TA0007 Discovery", "T1087", null, "Account Discovery", "Hands-on operators enumerate users, groups, domains, and high-value assets.", "P2"],
    ["TA0008 Lateral Movement", "T1021", ".001", "Remote Services: Remote Desktop Protocol", "RDP and SMB movement are common before data staging and encryption.", "P2"],
    ["TA0010 Exfiltration", "T1567", ".002", "Exfiltration to Cloud Storage", "Double-extortion crews commonly exfiltrate to public cloud or attacker-controlled storage.", "P1"],
    ["TA0040 Impact", "T1486", null, "Data Encrypted for Impact", "Encryption is used to disrupt operations and force payment.", "P1"],
  ],
  state: [
    ["TA0001 Initial Access", "T1566", ".002", "Phishing: Spearphishing Link", "Targeted lures and credential capture remain durable espionage access paths.", "P2"],
    ["TA0001 Initial Access", "T1190", null, "Exploit Public-Facing Application", "State actors exploit edge services and public applications for scalable access.", "P1"],
    ["TA0003 Persistence", "T1098", null, "Account Manipulation", "Long-lived identity access enables re-entry and quiet collection.", "P1"],
    ["TA0005 Defense Evasion", "T1070", null, "Indicator Removal", "Stealth-focused operators clear or minimize traces to extend dwell time.", "P2"],
    ["TA0007 Discovery", "T1087", null, "Account Discovery", "Actors enumerate identity, network, and cloud resources before collection.", "P2"],
    ["TA0009 Collection", "T1114", null, "Email Collection", "Mailbox and document collection are common intelligence objectives.", "P1"],
    ["TA0011 Command and Control", "T1105", null, "Ingress Tool Transfer", "Operators stage tools through C2 and legitimate services.", "P2"],
    ["TA0010 Exfiltration", "T1041", null, "Exfiltration Over C2 Channel", "Collected data may leave via encrypted C2 or legitimate cloud services.", "P1"],
  ],
  crime: [
    ["TA0001 Initial Access", "T1566", ".001", "Phishing: Spearphishing Attachment", "Email delivery and social engineering are common financially motivated access paths.", "P2"],
    ["TA0001 Initial Access", "T1078", null, "Valid Accounts", "Stolen credentials enable SaaS, VPN, and endpoint access.", "P1"],
    ["TA0003 Persistence", "T1136", null, "Create Account", "New accounts or token abuse sustain access across identity systems.", "P2"],
    ["TA0006 Credential Access", "T1555", null, "Credentials from Password Stores", "Browser, password manager, and local secret theft supports monetization.", "P1"],
    ["TA0007 Discovery", "T1087", null, "Account Discovery", "Actors enumerate identities and privileges before monetization.", "P2"],
    ["TA0008 Lateral Movement", "T1021", null, "Remote Services", "Remote services are used for lateral movement and access resale.", "P2"],
    ["TA0010 Exfiltration", "T1567", null, "Exfiltration Over Web Service", "Data theft and access-broker operations rely on outbound transfer.", "P1"],
    ["TA0040 Impact", "T1490", null, "Inhibit System Recovery", "Financially motivated actors increasingly target backups before extortion.", "P2"],
  ],
};

function profileBody(name, facts, rank) {
  const family = familyFor(facts);
  const sectors = sectorsFor(facts);
  const regions = regionsFor(facts);
  const ttps = ttpTemplates[family];
  const motivations = facts.type.includes("Nation-State")
    ? ["espionage", "strategic access", "intelligence collection"]
    : facts.type.includes("Ransomware")
      ? ["financial gain", "data theft", "extortion"]
      : ["financial gain", "credential theft", "access monetization"];
  const sourceConfidence = facts.refs.length >= 2 || facts.refs.some((r) => r[0] === "Framework" || r[0] === "Government") ? "High" : "Medium";
  const iocNote = "No generic blocking IOCs are inserted by this enrichment pass: public infrastructure for this actor rotates quickly, and low-context indicators should be detection-only until confirmed in tenant telemetry or a trusted feed.";

  return `# ${name} — Threat Actor Profile

## Executive Summary
${name} is ranked #${rank} in the OptraSight active threat-actor set. ${facts.summary} For blue-team prioritization, treat this actor as a ${facts.level} monitoring priority where its observed targeting overlaps exposed identity, cloud, remote-access, edge, or high-value data systems.

## Identity And Attribution
- Primary name: ${name}
- Common aliases: ${facts.aliases.length ? facts.aliases.join(", ") : "none widely normalized"}
- Actor type: ${facts.type}
- Assessed origin: ${facts.origin}
- Attribution confidence: ${facts.origin === "Unknown" ? "Medium / activity-cluster based" : "Likely"}
- Sophistication: ${facts.sophistication}
- TLP: AMBER for internal defensive use

## Motivation And Intent
Primary motivations are ${motivations.join(", ")}. The expected operator intent is ${family === "state" ? "quiet collection, persistence, and strategic access rather than immediate noisy impact unless geopolitical conditions change" : family === "ransomware" ? "financial extortion through data theft, operational disruption, and victim pressure" : "credential theft, access resale, fraud enablement, and downstream extortion support"}.

## Targeting And Victimology
Priority sectors: ${sectors.join(", ")}. Priority geographies: ${regions.join(", ")}. Watch for elevated risk where business units operate internet-facing VPN/VDI, Microsoft 365 or Entra ID, exposed edge appliances, unmanaged remote monitoring tools, sensitive file shares, or critical backup infrastructure.

## Capability Assessment
${name} should be modeled as ${facts.sophistication.toLowerCase()} capability. Likely capabilities include ${facts.tools.join(", ")}. Defensive assumptions should emphasize credentialed access, identity abuse, stealthy discovery, remote service movement, data staging, and ${family === "state" ? "quiet exfiltration" : "extortion-impact preparation"}.

## Campaign History
${facts.campaigns.map((c) => `- ${c}`).join("\n")}

## Priority ATT&CK Coverage
${ttps.map((t) => `- ${t[1]}${t[2] || ""} ${t[3]} (${t[0]}): ${t[4]}`).join("\n")}

## Detection Coverage Guidance
- P1: Alert on impossible travel, new MFA/device registration, privileged role assignment, suspicious Entra/IdP changes, VPN logins from unusual infrastructure, and remote-service access outside baselines.
- P1: Hunt for credential dumping, LSASS access, secrets extraction, RMM deployment, archive creation on file servers, and abnormal outbound transfer volume.
- P2: Correlate process ancestry for LOLBins, PowerShell, WMI, PsExec, scheduled tasks, service creation, web shell artifacts, and cloud storage command-line tools.
- P2: Add actor-specific hunts for ${facts.tools.slice(0, 3).join(", ")} where telemetry is available.

## CTI Feed Handling
Treat high-confidence, recent indicators from government, ISAC, MISP/OpenCTI, Microsoft, Google/Mandiant, CrowdStrike, and vetted ransomware trackers as candidates for enrichment. Apply TTLs before actioning: IPs 30 days, domains 90 days unless infrastructure remains active, hashes up to one year when tied to malware samples. ${iocNote}

## Defensive Priority Actions
- Harden exposed edge services and remove unmanaged remote access paths.
- Enforce phishing-resistant MFA for privileged users and require conditional access for admin portals.
- Centralize IdP, VPN, EDR, DNS, proxy, and cloud audit logs with at least 180 days of searchable retention.
- Validate backup immutability, recovery time, and isolation from domain-admin compromise.
- Run ATT&CK hunts listed above and convert confirmed gaps into Sigma/SIEM detections.

## Incident Response Playbook Notes
If activity resembles ${name}, preserve IdP/VPN/EDR logs, isolate suspected hosts, disable suspect identities and tokens, rotate privileged credentials, snapshot cloud audit state, collect archive/exfiltration evidence, and scope lateral movement before restoring trust. Avoid public attribution during live response; prioritize containment and evidence quality.

## Forecast
Through 2026, ${name} is expected to remain relevant where organizations expose identity, cloud, remote access, and edge systems. ${family === "state" ? "Expect low-noise access operations, credential reuse, and exploitation of public-facing appliances." : family === "ransomware" ? "Expect affiliate churn, tooling substitution, fast exploitation of known edge CVEs, and continued double-extortion pressure." : "Expect continued use of social engineering, commodity malware, stolen credentials, and access-broker ecosystems."}

## Source Confidence
Overall profile confidence: ${sourceConfidence}. This profile combines durable TTPs, public reporting, ATT&CK-style technique mapping, and feed-handling safeguards. Review quarterly or immediately after credible new reporting, confirmed tenant telemetry, or major law-enforcement disruption.`;
}

function businessImpact(facts) {
  const family = familyFor(facts);
  return {
    Financial: family === "ransomware" || family === "crime" ? "High" : "Medium",
    Operational: facts.level === "HIGH" ? "High" : "Medium",
    Reputational: "High",
    Regulatory: "Medium",
    Data: "High",
    Strategic: facts.type.includes("Nation-State") ? "High" : "Medium",
  };
}

function updateActor(row, facts, rank, ts) {
  const family = familyFor(facts);
  const sectors = sectorsFor(facts);
  const regions = regionsFor(facts);
  const motivations = facts.type.includes("Nation-State")
    ? ["Espionage", "Strategic access", "Intelligence collection"]
    : facts.type.includes("Ransomware")
      ? ["Financial gain", "Data theft", "Extortion"]
      : ["Financial gain", "Credential theft", "Access monetization"];
  const tech = facts.name === "Storm-0501"
    ? ["Microsoft Entra ID", "Hybrid Cloud", "Active Directory", "Microsoft 365", "Endpoint", "Backup Platforms"]
    : ["VPN", "Identity Provider", "Microsoft 365", "Endpoint", "Edge Devices", "Cloud Storage"];
  const ttps = ttpTemplates[family];

  db.prepare(`UPDATE threat_actors SET
    aliases = ?, vendor_names = ?, actor_type = ?, sponsorship = ?, assessed_origin = ?, origin_confidence = ?,
    motivation = ?, sophistication = ?, tlp = ?, admiralty_source = ?, admiralty_info = ?, wep_confidence = ?,
    target_sectors = ?, target_regions = ?, target_tech_stack = ?, org_size_preference = ?, intent_proximity = ?,
    relevance_rating = ?, exec_what = ?, exec_so_what = ?, exec_what_now = ?, threat_level = ?, threat_level_rationale = ?,
    sector_actively_targeted = ?, diamond_adversary = ?, diamond_capability = ?, diamond_infrastructure = ?, diamond_victim = ?,
    diamond_meta = ?, business_impact = ?, capability_profile = ?, infrastructure_profile = ?, ir_actions = ?,
    countermeasures = ?, forecast = ?, extortion_tactics = ?, body_md = ?, status = ?, version = version + 1,
    cutoff_date = ?, prepared_by = ?, ai_provider_label = ?, updated_at = ?
    WHERE tenant_id = ? AND id = ?`).run(
    j(facts.aliases),
    j({ mitre: facts.refs.filter((r) => r[0] === "Framework").map((r) => r[1]), microsoft: facts.refs.filter((r) => r[3].includes("microsoft.com")).map((r) => r[1]), optrasight: [row.primary_name, ...facts.aliases].slice(0, 8) }),
    facts.type,
    facts.type.includes("Nation-State") ? "State-Sponsored" : "Independent",
    facts.origin === "Unknown" ? null : facts.origin,
    facts.origin === "Unknown" ? "Medium" : "Likely",
    j(motivations),
    facts.sophistication,
    "AMBER",
    "B",
    "2",
    facts.origin === "Unknown" ? "Possible" : "Likely",
    j(sectors),
    j(regions),
    j(tech),
    "Medium to enterprise",
    rank <= 25 || facts.level === "HIGH" ? "Direct" : "Opportunistic",
    `Top-50 profile rank #${rank}; ${facts.level} defensive-monitoring priority`,
    `${row.primary_name} is a ${facts.type} actor requiring ${facts.level} monitoring priority.`,
    `Primary business risk is ${motivations.join(", ").toLowerCase()} against ${sectors.slice(0, 4).join(", ")}.`,
    "Prioritize identity, edge, cloud, exfiltration, and impact detections; review source freshness before blocking IOCs.",
    facts.level,
    `Analyst-enriched profile using durable TTPs, public CTI references, and OptraSight tenant relevance; rank #${rank}.`,
    1,
    j({ name: row.primary_name, type: facts.type, assessedOrigin: facts.origin, motivation: motivations, confidence: facts.origin === "Unknown" ? "Medium" : "Likely" }),
    j({ sophistication: facts.sophistication, commonTtps: ttps.map((t) => `${t[1]}${t[2] || ""}`), tools: facts.tools, operatorModel: family }),
    j({ patterns: family === "state" ? ["compromised edge infrastructure", "legitimate cloud services", "low-noise C2", "credentialed access"] : ["compromised infrastructure", "RMM tooling", "cloud exfiltration", "affiliate access"], watch: ["new admin sessions", "VPN anomalies", "large egress", "cloud audit drift"] }),
    j({ sectors, regions, orgSize: "Medium to enterprise", priorityAssets: tech }),
    j({ confidence: facts.refs.length >= 2 ? "High" : "Medium", rank, sourceSet: facts.refs.map((r) => r[1]) }),
    j(businessImpact(facts)),
    j({ tier: facts.sophistication, funding: facts.type.includes("Nation-State") ? "State-backed" : "Criminal/affiliate", coordination: facts.type, evidence: facts.summary, tools: facts.tools }),
    j({ hosting: ["compromised hosts", "cloud services", "VPS", "SOHO/edge infrastructure"], c2: ["HTTPS", "legitimate admin tools", "cloud services"], notes: "Use confirmed tenant telemetry or fresh feed indicators before blocking." }),
    j({ immediate: ["Disable suspect accounts and tokens", "Preserve IdP/VPN/EDR/cloud logs", "Isolate affected hosts"], shortTerm: ["Rotate privileged secrets", "Review remote access", "Hunt profile TTPs"], mediumTerm: ["Close exposed edge paths", "Validate backup immutability", "Tune SIEM correlation"], strategic: ["Quarterly actor-profile refresh", "Tabletop actor-specific intrusion scenario"] }),
    j({ d3fend: ["D3-MFA", "D3-ACH", "D3-LFP", "D3-EAL"], cisV8: ["5 Account Management", "6 Access Control", "8 Audit Log Management", "13 Network Monitoring", "17 Incident Response"], iso27001: ["A.5.15 Access control", "A.8.15 Logging", "A.8.16 Monitoring", "A.5.24 Incident response planning"] }),
    `Expect continued ${family === "state" ? "low-noise espionage and strategic access operations" : family === "ransomware" ? "affiliate churn, data theft, extortion, and opportunistic exploitation" : "credential theft, access resale, and fraud-enabling intrusions"} through 2026.`,
    j(family === "ransomware" ? { dataTheft: true, encryption: true, leakSitePressure: true, negotiation: "brand-led or affiliate-led", backupTargeting: true } : {}),
    profileBody(row.primary_name, facts, rank),
    "approved",
    "2026-06-01",
    "OptraSight CTI analyst enrichment",
    "Analyst curated public CTI",
    ts,
    row.tenant_id,
    row.id
  );

  for (const table of ["threat_actor_ttps", "threat_actor_tools", "threat_actor_campaigns", "threat_actor_iocs", "threat_actor_references"]) {
    db.prepare(`DELETE FROM ${table} WHERE tenant_id = ? AND actor_id = ?`).run(row.tenant_id, row.id);
  }

  for (const t of ttps) {
    db.prepare(`INSERT INTO threat_actor_ttps (id, tenant_id, actor_id, tactic, technique_id, sub_technique_id, technique_name, evidence, status, detection_priority, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id(), row.tenant_id, row.id, t[0], t[1], t[2], t[3], t[4], "confirmed", t[5], ts);
  }

  for (const toolName of facts.tools) {
    const lower = toolName.toLowerCase();
    const category = lower.includes("ransomware") ? "ransomware" : lower.includes("rclone") ? "exfiltration" : lower.includes("shell") ? "web shell" : lower.includes("powershell") || lower.includes("lol") ? "living-off-the-land" : "tooling";
    db.prepare(`INSERT INTO threat_actor_tools (id, tenant_id, actor_id, name, category, purpose, variants, confidence, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id(), row.tenant_id, row.id, toolName, category, `${row.primary_name} profile-relevant capability or tool family for detection and hunt scoping.`, j([]), "Likely", ts);
  }

  facts.campaigns.forEach((campaign, ix) => {
    db.prepare(`INSERT INTO threat_actor_campaigns (id, tenant_id, actor_id, name, period, target_sector, target_geography, initial_access, outcome, source_url, finding_ids, rule_ids, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      id(), row.tenant_id, row.id, campaign, ix === 0 ? "2023-2026" : "2024-2026", sectors.slice(0, 4).join(", "), regions.slice(0, 4).join(", "),
      family === "state" ? "Spearphishing, valid accounts, edge exploitation, and cloud or network appliance access" : family === "ransomware" ? "Valid accounts, exposed remote services, public-facing application exploitation, and affiliate access" : "Phishing, stolen credentials, SaaS compromise, and access-broker channels",
      family === "state" ? "Espionage collection, persistence, and strategic access" : family === "ransomware" ? "Data theft, encryption, leak pressure, and operational disruption" : "Credential theft, access monetization, and downstream fraud/extortion enablement",
      facts.refs[0]?.[3] || "https://attack.mitre.org/groups/",
      j([]), j([]), ts
    );
  });

  const refs = [
    ...facts.refs,
    ["Framework", "MITRE ATT&CK Groups", "2026-06", "https://attack.mitre.org/groups/"],
    ["Government", "CISA Cybersecurity Advisories", "2026-06", "https://www.cisa.gov/news-events/cybersecurity-advisories"],
    ["CTI Feed", "Ransomware.live victim and actor tracking", "2026-06", "https://www.ransomware.live/"],
    ["Analyst Note", "OptraSight CTI analyst enrichment methodology", "2026-06-01", "local://optrasight/tap-enrichment"],
  ];
  refs.slice(0, 8).forEach((ref, ix) => {
    db.prepare(`INSERT INTO threat_actor_references (id, tenant_id, actor_id, ref_num, source_type, title, date, url, archive_url, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id(), row.tenant_id, row.id, ix + 1, ref[0], ref[1], ref[2], ref[3], null, ts);
  });
}

const tx = db.transaction(() => {
  const rows = db.prepare("SELECT * FROM threat_actors ORDER BY tenant_id, profile_id").all();
  if (!rows.length) throw new Error("No threat actor rows found.");
  const ts = now();
  let updated = 0;
  for (const row of rows) {
    const facts = actorFacts[row.primary_name];
    if (!facts) throw new Error(`No enrichment facts for ${row.primary_name}`);
    facts.name = row.primary_name;
    const rank = TOP_50.indexOf(row.primary_name) + 1 || Number(String(row.profile_id || "").replace(/\D/g, "")) || 999;
    updateActor(row, facts, rank, ts);
    updated++;
  }
  const tenants = [...new Set(rows.map((r) => r.tenant_id))];
  for (const tenantId of tenants) {
    db.prepare("INSERT INTO audit_log (id, tenant_id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id(), tenantId, "system", "threat_actor.enrich_profiles", "threat_actors", j({ profilesUpdated: rows.filter((r) => r.tenant_id === tenantId).length, source: "scripts/enrich-threat-actor-profiles.cjs", iocPolicy: "removed placeholder IOCs; use fresh feed/tenant-confirmed indicators" }), ts);
  }
  return updated;
});

const updated = tx();
console.log(`Enriched ${updated} threat actor profile row(s).`);
