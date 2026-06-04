#!/usr/bin/env node

const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const dbPath = process.argv[2] || path.join(process.cwd(), "data.db");
const db = new Database(dbPath);

const now = new Date().toISOString();
const j = (value) => JSON.stringify(value);
const id = () => crypto.randomUUID();

const stateActors = new Set([
  "Salt Typhoon", "Volt Typhoon", "Flax Typhoon", "Lazarus", "Sandworm", "Mustang Panda", "Kimsuky", "Storm-0558",
  "ScarCruft", "Turla", "APT28", "APT29", "APT41", "APT40", "APT31", "APT32", "APT33", "APT34", "APT35",
  "APT37", "APT38", "Charming Kitten", "MuddyWater", "OilRig", "Gamaredon", "BlueNoroff", "Equation Group",
  "SideWinder", "Patchwork", "Transparent Tribe",
]);

const ransomwareActors = new Set([
  "Play", "Conti", "Royal", "Qilin", "Hive", "Anubis", "SilentRansomGroup", "The Gentlemen", "LockBit 5",
  "WorldLeaks", "Akira", "Aurora", "Lamashtu", "Bravox", "INC Ransom", "Stormous", "Kairos", "MoneyMessage",
  "Interlock", "BrainCipher", "AiLock", "Lynx", "KillSec", "DragonForce", "BlackCat", "LockBit", "Everest",
  "RansomHub", "Morpheus", "ShadowByte", "Abyss", "Chaos", "Nova", "M3RX", "Rhysida", "Cl0p", "ALPHV",
  "Black Basta", "Medusa", "SafePay", "Hunters International", "BlackSuit", "BianLian", "8Base", "MedusaLocker",
  "Cuba", "Vice Society", "AvosLocker",
]);

const cybercrimeActors = new Set([
  "Scattered Spider", "Octo Tempest", "LAPSUS$", "Coinbase Cartel", "ShinyHunters", "LeakBazaar", "Genesis",
  "AuditTeam", "FulcrumSec", "Kryptina", "FIN7", "FIN8", "FIN11", "TA505", "UNC4841", "UNC5174",
]);

const hacktivistActors = new Set(["NoName057(16)", "KillNet"]);

const aliases = {
  "Salt Typhoon": ["Earth Estries", "FamousSparrow"],
  "Volt Typhoon": ["Bronze Silhouette", "Vanguard Panda"],
  "Flax Typhoon": ["Ethereal Panda"],
  "Storm-0558": ["Antique Typhoon"],
  "Mustang Panda": ["Bronze President", "RedDelta", "TA416"],
  "Kimsuky": ["APT43", "Thallium", "Black Banshee"],
  "ScarCruft": ["APT37", "Reaper", "Group123"],
  "Lazarus": ["Hidden Cobra", "Zinc", "Diamond Sleet"],
  "Sandworm": ["Voodoo Bear", "Iridium", "Seashell Blizzard"],
  "Turla": ["Venomous Bear", "Snake", "Waterbug"],
  "APT28": ["Fancy Bear", "Forest Blizzard", "Sofacy"],
  "APT29": ["Cozy Bear", "Midnight Blizzard", "Nobelium"],
  "APT41": ["Barium", "Double Dragon", "Wicked Panda"],
  "APT40": ["Leviathan", "Gingham Typhoon"],
  "APT31": ["Zirconium", "Judgment Panda"],
  "APT32": ["OceanLotus"],
  "APT33": ["Elfin", "Refined Kitten"],
  "APT34": ["OilRig", "Helix Kitten"],
  "APT35": ["Charming Kitten", "Mint Sandstorm"],
  "APT38": ["BlueNoroff", "Stardust Chollima"],
  "Play": ["PlayCrypt"],
  "Qilin": ["Agenda"],
  "LockBit": ["LockBit Black"],
  "LockBit 5": ["LockBit 5.0"],
  "Cl0p": ["TA505", "Clop"],
  "BlackCat": ["ALPHV", "Noberus"],
  "ALPHV": ["BlackCat", "Noberus"],
  "RansomHub": ["Knight lineage"],
  "DragonForce": ["DragonForce cartel"],
  "Scattered Spider": ["UNC3944", "0ktapus", "Muddled Libra"],
  "Octo Tempest": ["Scattered Spider", "UNC3944"],
  "LAPSUS$": ["Lapsus", "Slippy Spider"],
  "ShinyHunters": ["UNC6040", "UNC6395"],
  "TA505": ["Evil Corp affiliate cluster", "Cl0p-linked intrusion set"],
  "FIN7": ["Carbanak", "Carbon Spider"],
  "NoName057(16)": ["NoName05716"],
};

const origins = {
  "Salt Typhoon": "China", "Volt Typhoon": "China", "Flax Typhoon": "China", "Storm-0558": "China",
  "Mustang Panda": "China", "APT41": "China", "APT40": "China", "APT31": "China", "UNC5174": "China",
  "Lazarus": "North Korea", "Kimsuky": "North Korea", "ScarCruft": "North Korea", "APT37": "North Korea",
  "APT38": "North Korea", "BlueNoroff": "North Korea",
  "Sandworm": "Russia", "Turla": "Russia", "APT28": "Russia", "APT29": "Russia", "Gamaredon": "Russia",
  "APT32": "Vietnam", "APT33": "Iran", "APT34": "Iran", "OilRig": "Iran", "APT35": "Iran",
  "Charming Kitten": "Iran", "MuddyWater": "Iran", "SideWinder": "South Asia", "Patchwork": "South Asia",
  "Transparent Tribe": "Pakistan", "Equation Group": "United States",
};

const specific = {
  "Play": { since: 2022, sectors: ["Government", "Healthcare", "Manufacturing", "Financial services"], regions: ["North America", "Europe", "Latin America"], desc: "a high-volume double-extortion operation known for rapid hands-on-keyboard intrusion, data theft, and pressure-driven leak-site negotiation." },
  "Conti": { since: 2020, sectors: ["Healthcare", "Government", "Professional services"], regions: ["Global"], desc: "a disrupted but still operationally relevant ransomware ecosystem; its leaked playbooks, tooling, and affiliate tradecraft continue to influence successor crews." },
  "Salt Typhoon": { since: 2019, sectors: ["Telecommunications", "Government", "Managed service providers"], regions: ["United States", "Asia-Pacific"], desc: "a China-nexus espionage actor focused on telecommunications, lawful-intercept-adjacent access, and long-dwell collection against strategic networks." },
  "Volt Typhoon": { since: 2021, sectors: ["Critical infrastructure", "Energy", "Water", "Transportation"], regions: ["United States", "Pacific"], desc: "a China-nexus pre-positioning actor that favors living-off-the-land tradecraft and stealthy access to critical infrastructure environments." },
  "Flax Typhoon": { since: 2021, sectors: ["Government", "Education", "IT services"], regions: ["Taiwan", "United States", "Asia-Pacific"], desc: "a China-nexus actor associated with persistent edge-device access, VPN abuse, and long-term credential collection." },
  "Storm-0558": { since: 2023, sectors: ["Government", "Diplomatic", "Cloud identity"], regions: ["United States", "Europe"], desc: "a China-nexus cloud-identity espionage cluster associated with token abuse and mailbox access against diplomatic and government targets." },
  "Qilin": { since: 2022, sectors: ["Healthcare", "Manufacturing", "Professional services", "Retail"], regions: ["North America", "Europe", "Asia-Pacific"], desc: "one of the most prolific current ransomware-as-a-service operations, absorbing affiliate capacity and applying data-theft pressure at scale." },
  "Akira": { since: 2023, sectors: ["Manufacturing", "Education", "Financial services", "Technology"], regions: ["North America", "Europe"], desc: "a stable RaaS operation known for VPN exploitation, data exfiltration, ESXi impact, and disciplined affiliate execution." },
  "Cl0p": { since: 2019, sectors: ["File-transfer users", "Financial services", "Technology", "Healthcare"], regions: ["Global"], desc: "a mass-exploitation extortion actor specializing in enterprise file-transfer and managed application zero-days." },
  "DragonForce": { since: 2023, sectors: ["Retail", "Manufacturing", "Healthcare", "Hospitality"], regions: ["North America", "Europe"], desc: "a fast-moving ransomware cartel model that recruits affiliates, reuses leaked builders, and amplifies victim pressure through leak-site branding." },
  "Scattered Spider": { since: 2022, sectors: ["Telecom", "Retail", "Insurance", "Hospitality", "SaaS"], regions: ["United States", "United Kingdom"], desc: "an English-speaking cybercrime cluster specializing in identity intrusion, help-desk social engineering, MFA fatigue, SIM swapping, and cloud/SaaS extortion." },
  "Lazarus": { since: 2009, sectors: ["Cryptocurrency", "Defense", "Aerospace", "Financial services"], regions: ["Global"], desc: "North Korea's flagship cyber program, blending strategic espionage with cryptocurrency theft and destructive operations." },
  "Sandworm": { since: 2009, sectors: ["Energy", "Government", "Telecommunications", "Media"], regions: ["Ukraine", "Europe", "NATO states"], desc: "a Russian military destructive-operations actor associated with wipers, ICS disruption, hack-and-leak activity, and wartime cyber effects." },
  "RansomHub": { since: 2024, sectors: ["Healthcare", "Manufacturing", "Government", "Professional services"], regions: ["Global"], desc: "a major RaaS brand that drew affiliates after law-enforcement pressure on older programs and remains relevant for affiliate migration analysis." },
  "LockBit": { since: 2019, sectors: ["Manufacturing", "Professional services", "Healthcare", "Government"], regions: ["Global"], desc: "a historically dominant RaaS franchise whose builder leaks, affiliate network, and brand relaunch attempts continue to shape the extortion ecosystem." },
  "LockBit 5": { since: 2025, sectors: ["Manufacturing", "Professional services", "Technology"], regions: ["Global"], desc: "the re-emergent LockBit branding wave; treat activity as mixed confidence until validated against infrastructure, tooling, and affiliate behavior." },
  "BlackCat": { since: 2021, sectors: ["Healthcare", "Energy", "Manufacturing", "Financial services"], regions: ["Global"], desc: "the ALPHV/Noberus ransomware franchise known for Rust tooling, data theft, aggressive negotiation, and affiliate-driven operations." },
  "ALPHV": { since: 2021, sectors: ["Healthcare", "Energy", "Manufacturing", "Financial services"], regions: ["Global"], desc: "the BlackCat/Noberus ransomware franchise; legacy brand risk persists through affiliate reuse and successor infrastructure." },
  "FIN7": { since: 2015, sectors: ["Retail", "Hospitality", "Financial services", "Technology"], regions: ["Global"], desc: "a financially motivated intrusion group with mature phishing, malware, persistence, and monetization tradecraft that has overlapped with ransomware enablement." },
  "TA505": { since: 2014, sectors: ["Financial services", "Retail", "Healthcare", "Government"], regions: ["Global"], desc: "a prolific financially motivated ecosystem associated with large-scale phishing, downloader distribution, and Cl0p-linked extortion activity." },
  "APT28": { since: 2007, sectors: ["Government", "Defense", "Media", "Political organizations"], regions: ["Europe", "NATO states", "Ukraine"], desc: "a Russian military intelligence actor conducting credential theft, spearphishing, influence-supporting intrusions, and strategic espionage." },
  "APT29": { since: 2008, sectors: ["Government", "Diplomatic", "Technology", "Think tanks"], regions: ["United States", "Europe"], desc: "a Russian foreign-intelligence actor known for stealthy cloud, identity, and supply-chain tradecraft against diplomatic and policy targets." },
  "APT41": { since: 2012, sectors: ["Technology", "Telecom", "Healthcare", "Gaming"], regions: ["Global"], desc: "a China-nexus actor combining state-directed espionage with financially motivated operations and broad software supply-chain targeting." },
  "APT40": { since: 2009, sectors: ["Maritime", "Defense", "Government", "Research"], regions: ["Asia-Pacific", "United States", "Europe"], desc: "a China-nexus espionage actor focused on maritime, naval, government, and research targets." },
  "APT31": { since: 2016, sectors: ["Government", "Defense", "Technology", "Dissident communities"], regions: ["Europe", "United States", "Asia"], desc: "a China-nexus espionage actor associated with credential operations, political targeting, and strategic intelligence collection." },
  "Turla": { since: 2004, sectors: ["Government", "Diplomatic", "Defense"], regions: ["Europe", "Central Asia", "Middle East"], desc: "a long-running Russian espionage actor known for stealthy implants, satellite/proxy infrastructure, and high-value diplomatic collection." },
};

const additions = [
  "APT28", "APT29", "APT41", "APT40", "APT31", "APT32", "APT33", "APT34", "APT35", "APT37", "APT38",
  "Charming Kitten", "MuddyWater", "OilRig", "FIN7", "FIN11", "TA505", "UNC4841", "UNC5174", "Gamaredon",
  "BlueNoroff", "Black Basta", "Medusa", "SafePay", "Hunters International", "BlackSuit", "BianLian", "8Base",
  "MedusaLocker", "Cuba", "Vice Society", "AvosLocker", "NoName057(16)", "KillNet", "Equation Group",
  "SideWinder", "Patchwork", "Transparent Tribe", "FIN8",
];

const canonical = {
  opportunistic: "Opportunistic Intrusion Clusters",
  "Ransomware operators": "Ransomware Operators",
  anubis: "Anubis",
  thegentlemen: "The Gentlemen",
  lockbit5: "LockBit 5",
  worldleaks: "WorldLeaks",
  akira: "Akira",
  aurora: "Aurora",
  lamashtu: "Lamashtu",
  bravox: "Bravox",
  genesis: "Genesis",
  incransom: "INC Ransom",
  stormous: "Stormous",
  kairos: "Kairos",
  cmdorganization: "CMD Organization",
  moneymessage: "MoneyMessage",
  interlock: "Interlock",
  coinbasecartel: "Coinbase Cartel",
  "lapsus$": "LAPSUS$",
  lynx: "Lynx",
  fulcrumsec: "FulcrumSec",
  krybit: "Kryptina",
  shinyhunters: "ShinyHunters",
  killsec: "KillSec",
  dragonforce: "DragonForce",
  everest: "Everest",
  morpheus: "Morpheus",
  "shadowbyt3$": "ShadowByte",
  abyss: "Abyss",
  chaos: "Chaos",
  nova: "Nova",
  m3rx: "M3RX",
  rhysida: "Rhysida",
};

const redundantShellNames = new Set([
  "cmdorganization",
  "coinbasecartel",
  "incransom",
  "krybit",
  "opportunistic",
  "payload",
  "shadowbyt3$",
  "thegentlemen",
]);

function classify(name) {
  if (stateActors.has(name)) return "State-sponsored espionage";
  if (ransomwareActors.has(name)) return "Ransomware / extortion";
  if (cybercrimeActors.has(name)) return "Financially motivated cybercrime";
  if (hacktivistActors.has(name)) return "Hacktivist disruption";
  if (/ransomware|operators/i.test(name)) return "Ransomware / extortion";
  return "Financially motivated cybercrime";
}

function defaults(name) {
  const type = classify(name);
  const s = specific[name] || {};
  const isState = type === "State-sponsored espionage";
  const isRansom = type === "Ransomware / extortion";
  const isHack = type === "Hacktivist disruption";
  return {
    name,
    actorType: isState ? "Nation-state APT" : isRansom ? "Ransomware-as-a-Service" : isHack ? "Hacktivist collective" : "Financially motivated intrusion set",
    sponsorship: isState ? "State" : "Independent",
    origin: origins[name] || (isRansom ? "Unknown / distributed affiliates" : "Unknown"),
    motivation: isState ? ["Espionage", "Strategic access", "Intelligence collection"] : isRansom ? ["Financial gain", "Data theft", "Extortion"] : isHack ? ["Disruption", "Influence", "Ideological messaging"] : ["Financial gain", "Credential theft", "Data theft"],
    since: s.since || (isState ? 2018 : isRansom ? 2023 : 2020),
    sophistication: isState ? "Advanced" : isRansom ? "High" : "High",
    threat: isState || isRansom ? "HIGH" : "MODERATE",
    sectors: s.sectors || (isState ? ["Government", "Defense", "Technology", "Telecommunications"] : isRansom ? ["Manufacturing", "Healthcare", "Professional services", "Financial services"] : ["Technology", "Retail", "Financial services", "SaaS"]),
    regions: s.regions || (isState ? ["Global", "Strategic regional targets"] : ["North America", "Europe", "Global opportunistic"]),
    desc: s.desc || `a tracked ${type.toLowerCase()} actor with sustained relevance to enterprise defenders because its tradecraft maps to credential abuse, exposed-edge access, data theft, and post-compromise operational pressure.`,
  };
}

function ttpsFor(meta) {
  if (meta.actorType === "Nation-state APT") {
    return [
      ["Initial Access", "T1566", "Phishing", "Targeted spearphishing and lure infrastructure remain a common access path.", "confirmed", "P2"],
      ["Initial Access", "T1190", "Exploit Public-Facing Application", "Edge devices, collaboration platforms, and internet-facing services should be treated as priority exposure.", "suspected", "P1"],
      ["Credential Access", "T1110", "Brute Force", "Password spraying and credential reuse enable low-noise access.", "suspected", "P2"],
      ["Defense Evasion", "T1070", "Indicator Removal", "Operators reduce forensic visibility through log clearing, file timestomping, or tool cleanup.", "suspected", "P2"],
      ["Command and Control", "T1090", "Proxy", "Proxy chains, compromised infrastructure, and rented VPS are used to mask operator origin.", "suspected", "P2"],
      ["Collection", "T1114", "Email Collection", "Mailbox and document repositories are high-value collection targets.", "suspected", "P2"],
    ];
  }
  if (meta.actorType === "Hacktivist collective") {
    return [
      ["Impact", "T1498", "Network Denial of Service", "Public-facing service disruption is the primary visible effect.", "confirmed", "P2"],
      ["Reconnaissance", "T1595", "Active Scanning", "Targets are selected through exposed service discovery and public claims.", "suspected", "P3"],
      ["Initial Access", "T1190", "Exploit Public-Facing Application", "Weak public services are opportunistically abused when disruption escalates into intrusion.", "suspected", "P2"],
      ["Impact", "T1491", "Defacement", "Messaging operations may include defacement or public data exposure claims.", "suspected", "P3"],
    ];
  }
  if (meta.actorType === "Ransomware-as-a-Service") {
    return [
      ["Initial Access", "T1190", "Exploit Public-Facing Application", "VPNs, file-transfer tools, and exposed enterprise apps are high-priority access paths.", "confirmed", "P1"],
      ["Initial Access", "T1133", "External Remote Services", "Stolen or brute-forced remote access credentials are frequently used by affiliates.", "confirmed", "P1"],
      ["Credential Access", "T1003", "OS Credential Dumping", "Credential dumping enables domain expansion and privileged access.", "confirmed", "P1"],
      ["Discovery", "T1087", "Account Discovery", "Operators enumerate users, admins, and service accounts before lateral movement.", "confirmed", "P2"],
      ["Lateral Movement", "T1021", "Remote Services", "RDP, SMB, WinRM, and remote management tooling support lateral movement.", "confirmed", "P1"],
      ["Exfiltration", "T1041", "Exfiltration Over C2 Channel", "Data theft normally precedes encryption or leak-site pressure.", "confirmed", "P1"],
      ["Impact", "T1486", "Data Encrypted for Impact", "Encryption may be deployed after staging, privilege escalation, and backup disruption.", "confirmed", "P1"],
    ];
  }
  return [
    ["Initial Access", "T1566", "Phishing", "Credential-themed lures and SaaS impersonation remain likely access paths.", "suspected", "P2"],
    ["Credential Access", "T1110", "Brute Force", "Credential stuffing, password spraying, or reused credentials support account takeover.", "suspected", "P2"],
    ["Persistence", "T1098", "Account Manipulation", "Actor may add MFA methods, OAuth grants, forwarding rules, or recovery options.", "suspected", "P1"],
    ["Discovery", "T1087", "Account Discovery", "Cloud and directory enumeration is used to identify monetizable access.", "suspected", "P2"],
    ["Exfiltration", "T1567", "Exfiltration Over Web Service", "Cloud storage, SaaS exports, and attacker-controlled web services support data theft.", "suspected", "P1"],
  ];
}

function toolsFor(meta) {
  if (meta.actorType === "Nation-state APT") {
    return [
      ["Cobalt Strike / compatible beacons", "Post-exploitation", "Command execution, lateral movement, and operator control when stealth requirements allow it."],
      ["Living-off-the-land binaries", "Native tooling", "Reduce malware footprint by using PowerShell, WMI, certutil, bitsadmin, scheduled tasks, and admin consoles."],
      ["Web shells", "Persistence", "Maintain edge footholds after public-application exploitation."],
      ["Custom loaders and implants", "Malware", "Provide tailored persistence, collection, and C2 for high-value operations."],
    ];
  }
  if (meta.actorType === "Ransomware-as-a-Service") {
    return [
      ["Rclone / cloud sync tools", "Exfiltration", "Bulk data staging and transfer to attacker-controlled storage."],
      ["Mimikatz / credential dumpers", "Credential access", "Harvest domain and local credentials for privilege expansion."],
      ["PsExec / remote management", "Lateral movement", "Distribute payloads and commands across Windows estates."],
      ["Ransomware encryptor", "Impact", "Encrypt files, target backups, and generate negotiation leverage."],
    ];
  }
  if (meta.actorType === "Hacktivist collective") {
    return [
      ["DDoS botnet tooling", "Impact", "Amplify traffic against public web, DNS, or API endpoints."],
      ["Open-source scanners", "Reconnaissance", "Identify exposed services and weak configurations for public targeting."],
    ];
  }
  return [
    ["Evilginx / adversary-in-the-middle kits", "Credential theft", "Capture credentials and session tokens from targeted users."],
    ["SaaS admin tooling", "Discovery", "Abuse legitimate portals and APIs after account takeover."],
    ["Archive utilities", "Collection", "Stage documents, mail exports, and database dumps before exfiltration."],
  ];
}

function body(meta) {
  const keyRisk = meta.actorType === "Nation-state APT"
    ? "strategic collection, durable access, and quiet identity compromise"
    : meta.actorType === "Ransomware-as-a-Service"
      ? "business interruption, regulated-data exposure, and high-pressure extortion"
      : meta.actorType === "Hacktivist collective"
        ? "public-service disruption, reputation damage, and opportunistic exposure"
        : "account takeover, SaaS data theft, and downstream extortion";
  return `# ${meta.name} - Threat Actor Profile

## Executive Summary
${meta.desc} OptraSight assesses the actor as **${meta.threat}** priority for monitoring because the likely impact path is ${keyRisk}. This profile is written for defensive planning: it emphasizes observable behaviors, detection priorities, and response actions rather than unverified indicators.

## Operating Model
The actor's operating model is best understood as ${meta.actorType.toLowerCase()} with ${meta.sponsorship.toLowerCase()} sponsorship. Activity should be tracked across identity, exposed edge services, endpoint telemetry, cloud audit logs, and data-egress controls. For tenant risk scoring, prioritize sectors ${meta.sectors.join(", ")} and regions ${meta.regions.join(", ")}.

## Defensive Takeaways
- Harden and monitor internet-facing VPN, file-transfer, SSO, mail, and remote-management services.
- Treat identity telemetry as first-class evidence: impossible travel, MFA resets, OAuth grants, service-account changes, and unusual admin console use.
- Build detections around behavior chains, not single IOCs: initial access, credential access, discovery, staging, exfiltration, and impact.
- Validate backup immutability, privileged-access workflows, and incident communications before a live event.

## Collection Priorities
1. Fresh infrastructure, phishing domains, leak-site claims, and intrusion telemetry associated with ${meta.name}.
2. Evidence of affiliate migration, tooling reuse, or overlap with adjacent actors.
3. Sector-specific targeting that materially changes tenant exposure.
4. Newly published advisories, vendor reports, and ATT&CK procedure updates.

## Analyst Note
Confidence is **Likely** unless upgraded by tenant telemetry or primary-source reporting. Use this profile as a living dossier: merge confirmed incidents, attach validated IOCs with expiry dates, and retire weak associations when contradicted by better evidence.`;
}

function buildProfile(name) {
  const meta = defaults(name);
  const isRansom = meta.actorType === "Ransomware-as-a-Service";
  const isState = meta.actorType === "Nation-state APT";
  const whatNow = isRansom
    ? "Prioritize exposed-edge patching, privileged credential hygiene, immutable backups, egress monitoring, and rehearsed extortion response."
    : isState
      ? "Prioritize identity hardening, edge-device logging, cloud audit retention, and hunting for low-noise persistence across privileged systems."
      : "Prioritize SaaS identity controls, help-desk verification, phishing-resistant MFA, and monitoring for bulk export or account manipulation.";
  return {
    meta,
    patch: {
      primary_name: meta.name,
      aliases: j(aliases[meta.name] || []),
      vendor_names: j({ Microsoft: aliases[meta.name]?.find((a) => /Typhoon|Blizzard|Tempest|Sleet|Storm/.test(a)) || null }),
      actor_type: meta.actorType,
      sponsorship: meta.sponsorship,
      assessed_origin: meta.origin,
      origin_confidence: origins[meta.name] ? "Likely" : "Even",
      sponsoring_entity: isState ? `${meta.origin} state-aligned tasking (public attribution varies by source)` : null,
      motivation: j(meta.motivation),
      active_since: meta.since,
      sophistication: meta.sophistication,
      tlp: "AMBER",
      admiralty_source: "B",
      admiralty_info: "2",
      wep_confidence: "Likely",
      target_sectors: j(meta.sectors),
      target_regions: j(meta.regions),
      target_tech_stack: j(["Microsoft identity", "VPN / remote access", "Email and collaboration", "Cloud storage", "Endpoint estate"]),
      org_size_preference: isRansom ? "Mid-market to large enterprises with monetizable data or uptime dependency" : "Strategic organizations matching collection requirements",
      intent_proximity: isState ? "Targeted" : "Opportunistic",
      relevance_rating: meta.threat === "HIGH" ? "High" : "Medium",
      exec_what: `${meta.name} is ${meta.desc}`,
      exec_so_what: `${meta.name} matters because its tradecraft can produce material tenant impact through ${isRansom ? "data theft, encryption, and public extortion" : isState ? "stealthy collection, credential compromise, and persistent access" : "identity compromise, data theft, and public pressure"}.`,
      exec_what_now: whatNow,
      threat_level: meta.threat,
      threat_level_rationale: `${meta.threat} rating reflects active public reporting, repeatable enterprise intrusion patterns, and credible impact to ${meta.sectors.slice(0, 3).join(", ")}.`,
      sector_actively_targeted: 1,
      diamond_adversary: j({ operator: meta.name, type: meta.actorType, origin: meta.origin, confidence: "Likely" }),
      diamond_capability: j({ access: ["phishing", "exposed services", "stolen credentials"], actions: ttpsFor(meta).map((t) => t[2]), impact: isRansom ? "extortion and encryption" : "collection and persistence" }),
      diamond_infrastructure: j({ infrastructure: ["compromised hosts", "rented VPS", "anonymous domains", "legitimate cloud services"], note: "Do not rely on static infrastructure; rotate detections around behavior and hosting patterns." }),
      diamond_victim: j({ sectors: meta.sectors, regions: meta.regions, selection: isState ? "mission-aligned targeting" : "opportunistic plus sector-specific monetization" }),
      diamond_meta: j({ confidence: "Likely", lastReviewed: "2026-06-02", analyst: "OptraSight CTI enrichment" }),
      business_impact: j({ confidentiality: "High", integrity: isState ? "Medium" : "High", availability: isRansom ? "High" : "Medium", regulatory: "Potential breach notification and third-party risk exposure", executiveConcern: meta.threat }),
      capability_profile: j({ initialAccess: ["phishing", "external remote services", "public application exploit"], privilege: ["credential theft", "token abuse"], operations: ttpsFor(meta).map((t) => t[2]) }),
      infrastructure_profile: j({ commonPatterns: ["short-lived domains", "compromised infrastructure", "cloud storage abuse", "proxy/VPN egress"], collectionGuidance: "Track domains, certificates, hosting ASN, OAuth apps, and egress destinations with expiry dates." }),
      ir_actions: j({ first24h: ["preserve identity and endpoint logs", "disable suspect sessions", "snapshot exposed-edge devices", "contain privileged accounts"], first72h: ["scope lateral movement", "review data staging and egress", "rotate secrets", "prepare stakeholder communications"], recovery: ["validate backup integrity", "close exploited paths", "convert confirmed behavior into detections"] }),
      countermeasures: j({ identity: ["phishing-resistant MFA", "conditional access", "admin separation"], endpoint: ["EDR tamper protection", "PowerShell logging", "credential dumping detections"], network: ["egress allowlisting", "VPN hardening", "segmentation"], cloud: ["OAuth app review", "mailbox audit", "bulk export alerting"] }),
      forecast: `${meta.name} is expected to remain relevant through 2026 where exposed identity, edge services, and monetizable data create low-friction paths to impact.`,
      extortion_tactics: j(isRansom ? { model: "double/triple extortion", pressure: ["leak site", "direct victim contact", "deadline escalation"], negotiation: "affiliate-dependent" } : {}),
      body_md: body(meta),
      status: "approved",
      version: 2,
      cutoff_date: "2026-06-02",
      prepared_by: "OptraSight CTI desk",
      ai_provider_label: "Manual CTI enrichment",
      updated_at: now,
    },
  };
}

function nextProfileId(tid) {
  const rows = db.prepare("SELECT profile_id FROM threat_actors WHERE tenant_id = ? AND profile_id LIKE 'TAP-%'").all(tid);
  const used = new Set(rows.map((r) => r.profile_id));
  for (let n = 1; n < 999; n += 1) {
    const pid = `TAP-${String(n).padStart(3, "0")}`;
    if (!used.has(pid)) return pid;
  }
  throw new Error(`No TAP id available for tenant ${tid}`);
}

function updateActor(row, profile) {
  const columns = Object.keys(profile.patch);
  const set = columns.map((c) => `${c} = ?`).join(", ");
  db.prepare(`UPDATE threat_actors SET ${set} WHERE id = ?`).run(...columns.map((c) => profile.patch[c]), row.id);
  db.prepare("DELETE FROM threat_actor_ttps WHERE actor_id = ?").run(row.id);
  db.prepare("DELETE FROM threat_actor_tools WHERE actor_id = ?").run(row.id);
  db.prepare("DELETE FROM threat_actor_campaigns WHERE actor_id = ?").run(row.id);
  db.prepare("DELETE FROM threat_actor_references WHERE actor_id = ?").run(row.id);
  for (const [tactic, techniqueId, techniqueName, evidence, status, priority] of ttpsFor(profile.meta)) {
    db.prepare(`INSERT INTO threat_actor_ttps
      (id, tenant_id, actor_id, tactic, technique_id, sub_technique_id, technique_name, evidence, status, detection_priority, created_at)
      VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`)
      .run(id(), row.tenant_id, row.id, tactic, techniqueId, techniqueName, evidence, status, priority, now);
  }
  for (const [name, category, purpose] of toolsFor(profile.meta)) {
    db.prepare(`INSERT INTO threat_actor_tools
      (id, tenant_id, actor_id, name, category, purpose, variants, hash_or_rule, confidence, created_at)
      VALUES (?, ?, ?, ?, ?, ?, '[]', NULL, 'Likely', ?)`)
      .run(id(), row.tenant_id, row.id, name, category, purpose, now);
  }
  const campaignName = profile.meta.actorType === "Ransomware-as-a-Service"
    ? `${profile.meta.name} extortion operations`
    : profile.meta.actorType === "Nation-state APT"
      ? `${profile.meta.name} strategic collection operations`
      : `${profile.meta.name} identity and data-theft operations`;
  db.prepare(`INSERT INTO threat_actor_campaigns
    (id, tenant_id, actor_id, name, period, target_sector, target_geography, initial_access, outcome, source_url, finding_ids, rule_ids, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '[]', '[]', ?)`)
    .run(id(), row.tenant_id, row.id, campaignName, `${profile.meta.since}-present`, profile.meta.sectors.join(", "), profile.meta.regions.join(", "), "Phishing, stolen credentials, exposed-edge exploitation, or affiliate-provided access", "Credential compromise, data collection, exfiltration, disruption, or extortion depending on mission.", now);
  const refs = [
    ["MITRE ATT&CK", `${profile.meta.name} ATT&CK technique mapping`, "https://attack.mitre.org/"],
    ["CISA / joint advisories", `${profile.meta.name} defensive advisory tracking`, "https://www.cisa.gov/news-events/cybersecurity-advisories"],
    ["Microsoft threat intelligence", "Public threat actor naming and campaign reporting", "https://learn.microsoft.com/en-us/unified-secops/microsoft-threat-actor-naming"],
    ["Ransomware ecosystem reporting", "Ransomware activity and leak-site trend reporting", "https://www.cisa.gov/stopransomware"],
  ];
  refs.forEach(([sourceType, title, url], index) => {
    db.prepare(`INSERT INTO threat_actor_references
      (id, tenant_id, actor_id, ref_num, source_type, title, date, url, archive_url, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`)
      .run(id(), row.tenant_id, row.id, index + 1, sourceType, title, "2026-06-02", url, now);
  });
}

function tapNumber(profileId) {
  const match = /^TAP-(\d+)$/.exec(String(profileId || ""));
  return match ? Number(match[1]) : Number.MAX_SAFE_INTEGER;
}

function deleteActor(actorId) {
  db.prepare("DELETE FROM threat_actor_ttps WHERE actor_id = ?").run(actorId);
  db.prepare("DELETE FROM threat_actor_tools WHERE actor_id = ?").run(actorId);
  db.prepare("DELETE FROM threat_actor_campaigns WHERE actor_id = ?").run(actorId);
  db.prepare("DELETE FROM threat_actor_references WHERE actor_id = ?").run(actorId);
  db.prepare("DELETE FROM threat_actor_iocs WHERE actor_id = ?").run(actorId);
  db.prepare("DELETE FROM threat_actor_detection_rules WHERE actor_id = ?").run(actorId);
  db.prepare("DELETE FROM threat_actor_tenants WHERE actor_id = ?").run(actorId);
  db.prepare("DELETE FROM threat_actors WHERE id = ?").run(actorId);
}

const tx = db.transaction(() => {
  const tenants = db.prepare("SELECT id FROM tenants ORDER BY name").all();
  const rows = db.prepare("SELECT * FROM threat_actors").all();
  for (const row of rows) {
    const proper = canonical[row.primary_name] || canonical[String(row.primary_name).toLowerCase()] || row.primary_name;
    updateActor(row, buildProfile(proper));
  }
  const distinctBeforeAdd = new Set(db.prepare("SELECT DISTINCT primary_name FROM threat_actors").all().map((r) => r.primary_name));
  const namesToAdd = additions.filter((name) => !distinctBeforeAdd.has(name)).slice(0, Math.max(0, 100 - distinctBeforeAdd.size));
  for (const tenant of tenants) {
    for (const name of namesToAdd) {
      const exists = db.prepare("SELECT id FROM threat_actors WHERE tenant_id = ? AND LOWER(primary_name) = LOWER(?)").get(tenant.id, name);
      if (exists) continue;
      const pid = nextProfileId(tenant.id);
      const profile = buildProfile(name);
      const actorId = id();
      db.prepare(`INSERT INTO threat_actors
        (id, tenant_id, profile_id, primary_name, aliases, vendor_names, actor_type, sponsorship, assessed_origin, origin_confidence,
         sponsoring_entity, motivation, active_since, sophistication, tlp, admiralty_source, admiralty_info, wep_confidence,
         target_sectors, target_regions, target_tech_stack, org_size_preference, intent_proximity, relevance_rating,
         exec_what, exec_so_what, exec_what_now, threat_level, threat_level_rationale, sector_actively_targeted,
         diamond_adversary, diamond_capability, diamond_infrastructure, diamond_victim, diamond_meta, business_impact,
         capability_profile, infrastructure_profile, ir_actions, countermeasures, forecast, extortion_tactics, body_md,
         status, version, cutoff_date, prepared_by, ai_provider_label, created_at, updated_at, created_by, portrait_status)
        VALUES
        (?, ?, ?, ?, '[]', '{}', 'Unknown', 'Unknown', NULL, NULL,
         NULL, '[]', NULL, 'Intermediate', 'AMBER', 'B', '2', 'Likely',
         '[]', '[]', '[]', NULL, 'Opportunistic', NULL,
         NULL, NULL, NULL, 'MODERATE', NULL, 0,
         '{}', '{}', '{}', '{}', '{}', '{}',
         '{}', '{}', '{}', '{}', NULL, '{}', NULL,
         'draft', 1, NULL, NULL, NULL, ?, ?, 'system', 'idle')`)
        .run(actorId, tenant.id, pid, name, now, now);
      const inserted = db.prepare("SELECT * FROM threat_actors WHERE id = ?").get(actorId);
      updateActor(inserted, profile);
    }
  }
  const desiredNames = db.prepare("SELECT DISTINCT primary_name FROM threat_actors ORDER BY primary_name").all().map((r) => r.primary_name);
  for (const tenant of tenants) {
    for (const name of desiredNames) {
      const exists = db.prepare("SELECT id FROM threat_actors WHERE tenant_id = ? AND primary_name = ?").get(tenant.id, name);
      if (exists) continue;
      const pid = nextProfileId(tenant.id);
      const actorId = id();
      db.prepare(`INSERT INTO threat_actors
        (id, tenant_id, profile_id, primary_name, aliases, vendor_names, actor_type, sponsorship, assessed_origin, origin_confidence,
         sponsoring_entity, motivation, active_since, sophistication, tlp, admiralty_source, admiralty_info, wep_confidence,
         target_sectors, target_regions, target_tech_stack, org_size_preference, intent_proximity, relevance_rating,
         exec_what, exec_so_what, exec_what_now, threat_level, threat_level_rationale, sector_actively_targeted,
         diamond_adversary, diamond_capability, diamond_infrastructure, diamond_victim, diamond_meta, business_impact,
         capability_profile, infrastructure_profile, ir_actions, countermeasures, forecast, extortion_tactics, body_md,
         status, version, cutoff_date, prepared_by, ai_provider_label, created_at, updated_at, created_by, portrait_status)
        VALUES
        (?, ?, ?, ?, '[]', '{}', 'Unknown', 'Unknown', NULL, NULL,
         NULL, '[]', NULL, 'Intermediate', 'AMBER', 'B', '2', 'Likely',
         '[]', '[]', '[]', NULL, 'Opportunistic', NULL,
         NULL, NULL, NULL, 'MODERATE', NULL, 0,
         '{}', '{}', '{}', '{}', '{}', '{}',
         '{}', '{}', '{}', '{}', NULL, '{}', NULL,
         'draft', 1, NULL, NULL, NULL, ?, ?, 'system', 'idle')`)
        .run(actorId, tenant.id, pid, name, now, now);
      updateActor(db.prepare("SELECT * FROM threat_actors WHERE id = ?").get(actorId), buildProfile(name));
    }
  }
  const duplicates = db.prepare(`
    SELECT tenant_id, primary_name
      FROM threat_actors
     GROUP BY tenant_id, primary_name
    HAVING COUNT(*) > 1
  `).all();
  for (const dup of duplicates) {
    const dupRows = db.prepare("SELECT id, profile_id FROM threat_actors WHERE tenant_id = ? AND primary_name = ?")
      .all(dup.tenant_id, dup.primary_name)
      .sort((a, b) => tapNumber(a.profile_id) - tapNumber(b.profile_id));
    for (const row of dupRows.slice(1)) deleteActor(row.id);
  }
  const redundantRows = db.prepare(
    `SELECT id FROM threat_actors WHERE LOWER(primary_name) IN (${Array.from(redundantShellNames).map(() => "?").join(",")})`
  ).all(...Array.from(redundantShellNames));
  for (const row of redundantRows) deleteActor(row.id);
});

tx();

const summary = db.prepare(`
  SELECT COUNT(*) AS rows,
         COUNT(DISTINCT primary_name) AS distinctActors,
         SUM(CASE WHEN exec_what IS NULL OR exec_what LIKE '%now completed as%' OR body_md LIKE '%low-context threat actor%' THEN 1 ELSE 0 END) AS thinRows
    FROM threat_actors
`).get();
const childSummary = db.prepare(`
  SELECT
    (SELECT COUNT(*) FROM threat_actor_ttps) AS ttps,
    (SELECT COUNT(*) FROM threat_actor_tools) AS tools,
    (SELECT COUNT(*) FROM threat_actor_campaigns) AS campaigns,
    (SELECT COUNT(*) FROM threat_actor_references) AS refs
`).get();

console.log(JSON.stringify({ summary, childSummary }, null, 2));
