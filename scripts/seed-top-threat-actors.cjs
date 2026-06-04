#!/usr/bin/env node

const Database = require("better-sqlite3");
const { existsSync, readdirSync, unlinkSync } = require("node:fs");
const { join, resolve } = require("node:path");
const { randomUUID } = require("node:crypto");

const db = new Database("data.db");
db.pragma("journal_mode = WAL");

const TOP_50 = [
  "Qilin", "Akira", "Cl0p", "Play", "SafePay", "INC Ransom", "DragonForce", "RansomHub", "LockBit", "Black Basta",
  "Scattered Spider", "FIN7", "TA505", "Evil Corp", "Lazarus Group", "Kimsuky", "APT43", "Andariel", "Volt Typhoon", "Salt Typhoon",
  "Flax Typhoon", "Mustang Panda", "APT41", "APT40", "APT31", "UNC3886", "Turla", "APT29", "APT28", "Sandworm Team",
  "Gamaredon", "FIN6", "MuddyWater", "APT35", "APT33", "Agrius", "OilRig", "Charming Kitten", "BlackCat", "Royal",
  "BianLian", "BlackSuit", "Hunters International", "Medusa", "8Base", "Rhysida", "BlackByte", "Cactus", "TA577", "Storm-0501",
];

const OVERRIDES = {
  "Cl0p": { aliases: ["Clop", "TA505", "FIN11"], category: "Ransomware", country: "Russia", notes: "High-impact extortion operation associated with mass exploitation of managed file-transfer products and large-scale data theft campaigns." },
  "SafePay": { aliases: ["Safepay"], category: "Ransomware", country: "Unknown", notes: "Fast-growing double-extortion ransomware brand observed in 2025 leak-site volume reporting." },
  "INC Ransom": { aliases: ["INC", "INC Ransomware"], category: "Ransomware", country: "Unknown", notes: "Active double-extortion ransomware operation targeting healthcare, public sector, industrial, and professional services organizations." },
  "DragonForce": { aliases: ["Dragon Force"], category: "Ransomware", country: "Unknown", notes: "Ransomware operation and affiliate platform active across 2025-2026, associated with high-volume extortion and brand pressure tactics." },
  "Lazarus Group": { aliases: ["Lazarus", "HIDDEN COBRA", "Labyrinth Chollima", "ZINC"], category: "Nation-State APT", country: "North Korea", notes: "DPRK-linked umbrella cluster conducting espionage, destructive operations, cryptocurrency theft, supply-chain compromise, and financially motivated intrusions." },
  "APT43": { aliases: ["Kimsuky", "Emerald Sleet", "Thallium"], category: "Nation-State APT", country: "North Korea", notes: "DPRK intelligence collection cluster focused on policy, defense, think tanks, nuclear issues, and credential collection." },
  "FIN6": { aliases: ["Skeleton Spider"], category: "Organized Cybercrime", country: "Unknown", notes: "Financially motivated intrusion cluster historically associated with payment-card theft and later ransomware-adjacent intrusion activity." },
  "BlackSuit": { aliases: ["Royal", "BlackSuit Ransomware"], category: "Ransomware", country: "Unknown", notes: "Extortion operation with technical and operational overlap with Royal, targeting enterprises with data theft and encryption." },
  "Medusa": { aliases: ["Medusa Ransomware"], category: "Ransomware", country: "Unknown", notes: "Active ransomware operation using double extortion, public leak pressure, and broad sector targeting." },
  "Cactus": { aliases: ["CACTUS"], category: "Ransomware", country: "Unknown", notes: "Ransomware operation known for VPN exploitation, encryption of its payload to evade detection, and double extortion." },
  "Storm-0501": { aliases: ["Sabbath affiliate", "Embargo affiliate"], category: "Ransomware Affiliate", country: "Unknown", notes: "Financially motivated Microsoft-tracked actor associated with cloud compromise and multiple ransomware families." },
  "Scattered Spider": { aliases: ["Octo Tempest", "UNC3944", "Muddled Libra", "Roasted 0ktapus", "0ktapus", "Scatter Swine"], category: "Organized Cybercrime", country: "Unknown", notes: "Social-engineering-heavy intrusion cluster associated with identity compromise, help-desk abuse, cloud/SaaS intrusion, and ransomware affiliate activity." },
};

const SOURCE_REFS = [
  ["Vendor Report", "NCC Group Annual Cyber Threat Intelligence 2025", "2026-01", "https://www.nccgroup.com/newsroom/ncc-group-annual-cyber-threat-intelligence-2025/"],
  ["Vendor Report", "CrowdStrike 2026 Global Threat Report", "2026-03", "https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/"],
  ["Framework", "MITRE ATT&CK Groups", "2026-05", "https://attack.mitre.org/groups/"],
  ["Government", "CISA Cybersecurity Advisories", "2026-05", "https://www.cisa.gov/news-events/cybersecurity-advisories"],
];

function loadDict() {
  try {
    const rows = JSON.parse(require("node:fs").readFileSync("server/data/dict-threat-actors.json", "utf8"));
    const map = new Map();
    for (const row of rows) {
      map.set(String(row.name).toLowerCase(), row);
      for (const a of row.aliases || []) map.set(String(a).toLowerCase(), row);
    }
    return map;
  } catch {
    return new Map();
  }
}

const dict = loadDict();
const j = (v) => JSON.stringify(v);
const now = () => new Date().toISOString();
const id = () => randomUUID();

function baseInfo(name) {
  const row = dict.get(name.toLowerCase()) || {};
  const over = OVERRIDES[name] || {};
  return {
    name,
    aliases: [...new Set([...(over.aliases || []), ...(row.aliases || [])])].filter((a) => a !== name).slice(0, 8),
    category: over.category || row.category || "Unknown",
    country: over.country || row.country || "Unknown",
    notes: over.notes || row.notes || `${name} is a tracked threat actor included in the 2026 OptraSight top-50 active and famous actor set.`,
  };
}

function profileShape(info, rank) {
  const cat = info.category.toLowerCase();
  const ransomware = cat.includes("ransom");
  const state = cat.includes("nation") || cat.includes("apt") || cat.includes("state");
  const crime = ransomware || cat.includes("crime") || cat.includes("financial") || cat.includes("cybercrime");
  const actorType = ransomware ? (rank <= 12 ? "Ransomware-as-a-Service" : "Ransomware Affiliate") : state ? "Nation-State" : crime ? "Organized Cybercrime" : "Unknown";
  const sponsorship = state ? "State-Sponsored" : "Independent";
  const sophistication = state ? "Advanced" : rank <= 15 ? "Advanced" : "Intermediate";
  const threatLevel = rank <= 10 || ["Volt Typhoon", "Salt Typhoon", "Lazarus Group", "Sandworm Team"].includes(info.name) ? "HIGH" : rank <= 35 ? "MODERATE" : "LOW";
  const motivation = state ? ["Espionage", "Strategic access", "Operational preparation"] : ransomware ? ["Financial gain", "Extortion"] : ["Financial gain", "Credential theft"];
  const regions = info.country === "Unknown" ? ["North America", "Europe", "Global"] : ["North America", "Europe", "Asia-Pacific", "Global"];
  const sectors = ransomware
    ? ["Healthcare", "Manufacturing", "Financial Services", "Professional Services", "Public Sector"]
    : state
      ? ["Government", "Defense", "Telecommunications", "Critical Infrastructure", "Technology"]
      : ["Retail", "Technology", "Financial Services", "Hospitality", "Managed Service Providers"];
  return { actorType, sponsorship, sophistication, threatLevel, motivation, regions, sectors };
}

function ttps(info, shape) {
  if (shape.actorType.includes("Ransomware")) {
    return [
      ["TA0001 Initial Access", "T1133", null, "External Remote Services", "Abuse of VPN, RDP, and exposed remote access paths is common for ransomware affiliates.", "P1"],
      ["TA0006 Credential Access", "T1003", null, "OS Credential Dumping", "Credential theft enables privilege escalation and lateral movement before extortion.", "P1"],
      ["TA0008 Lateral Movement", "T1021", ".001", "Remote Services: Remote Desktop Protocol", "Hands-on-keyboard operators commonly pivot through RDP and SMB.", "P2"],
      ["TA0010 Exfiltration", "T1567", ".002", "Exfiltration to Cloud Storage", "Double-extortion crews stage and exfiltrate data before encryption.", "P1"],
      ["TA0040 Impact", "T1486", null, "Data Encrypted for Impact", "Encryption and leak pressure remain primary business-impact mechanisms.", "P1"],
    ];
  }
  return [
    ["TA0001 Initial Access", "T1566", ".001", "Phishing: Spearphishing Attachment", "Targeted lures and document payloads remain common for espionage operators.", "P2"],
    ["TA0003 Persistence", "T1098", null, "Account Manipulation", "Long-lived account access supports stealthy collection and re-entry.", "P1"],
    ["TA0005 Defense Evasion", "T1027", null, "Obfuscated Files or Information", "Custom loaders and obfuscation reduce detection during intrusion chains.", "P2"],
    ["TA0007 Discovery", "T1087", null, "Account Discovery", "Operators enumerate identity, network, and cloud resources before collection.", "P2"],
    ["TA0011 Command and Control", "T1105", null, "Ingress Tool Transfer", "C2 channels are used to stage tools and move collected data.", "P1"],
  ];
}

function tools(info, shape) {
  if (shape.actorType.includes("Ransomware")) {
    return [["Rclone", "exfiltration", "Bulk data exfiltration to cloud storage", ["rclone"], "Likely"], ["Mimikatz", "credential access", "Credential dumping and ticket theft", [], "Likely"], [info.name, "ransomware", "Encryption and extortion payload family or affiliate brand", info.aliases.slice(0, 3), "Likely"]];
  }
  return [["Cobalt Strike", "post-exploitation", "Beaconing, lateral movement, and command execution where observed or emulated by public reporting", ["Beacon"], "Possible"], ["Living-off-the-land binaries", "defense evasion", "Use of native administration tooling to reduce malware footprint", ["PowerShell", "WMI", "PsExec"], "Likely"], ["Custom implants", "backdoor", "Actor-specific loaders, backdoors, or collection tooling reported across public campaigns", [], "Possible"]];
}

function bodyMd(info, shape, rank) {
  return `## Executive Summary\n${info.name} is ranked #${rank} in the OptraSight 2026 active/famous threat actor set. ${info.notes}\n\n## Identity\nPrimary name: ${info.name}. Aliases: ${info.aliases.length ? info.aliases.join(", ") : "none widely normalized"}. Assessed origin: ${info.country}.\n\n## Victimology\nCommon target sectors include ${shape.sectors.join(", ")}. Monitoring priority is highest for internet-facing identity, VPN, email, cloud, and edge infrastructure.\n\n## Capability\nAssessed as ${shape.sophistication} with ${shape.motivation.join(", ").toLowerCase()} motivation. Tradecraft emphasizes repeatable intrusion paths, credential abuse, stealthy persistence, and rapid operational tempo.\n\n## TTPs\nPriority ATT&CK coverage should include initial access, credential access, lateral movement, exfiltration, command-and-control, and impact detections.\n\n## Diamond Model\nAdversary: ${info.name}; Capability: ${shape.actorType}; Infrastructure: compromised infrastructure, bulletproof hosting, cloud services, and legitimate admin tooling; Victim: ${shape.sectors.join(", ")}.\n\n## Campaigns\nSeeded from public 2025-2026 threat landscape reporting and MITRE-style actor tracking. Replace with incident-specific campaign evidence as tenant telemetry accumulates.\n\n## Detection\nPrioritize identity anomalies, impossible travel, MFA resets, remote service exposure, suspicious archiving, large outbound transfers, admin tool abuse, and endpoint tampering.\n\n## IR Actions\nDisable suspect identities, preserve logs, isolate affected hosts, rotate privileged secrets, review VPN and IdP activity, and hunt for related ATT&CK behaviors.\n\n## Countermeasures\nEnforce phishing-resistant MFA, harden remote access, close exposed edge services, centralize logs, restrict admin tooling, and test recovery from extortion or destructive impact.\n\n## Forecast\nExpect continued activity through 2026 where the actor's targeting overlaps exposed edge devices, identity providers, cloud control planes, and high-value data stores.\n\n## Confidence / Sources\nConfidence is Likely, based on curated public reporting from NCC Group, CrowdStrike, MITRE ATT&CK, CISA advisories, and OptraSight dictionary normalization.`;
}

function seedActor(tenantId, profileId, info, rank, ts) {
  const shape = profileShape(info, rank);
  const aid = id();
  db.prepare(`INSERT INTO threat_actors (
    id, tenant_id, profile_id, primary_name, mitre_group_id, aliases, vendor_names, actor_type, sponsorship,
    assessed_origin, origin_confidence, motivation, active_since, sophistication, tlp, admiralty_source, admiralty_info, wep_confidence,
    target_sectors, target_regions, target_tech_stack, org_size_preference, intent_proximity, relevance_rating,
    exec_what, exec_so_what, exec_what_now, threat_level, threat_level_rationale, sector_actively_targeted,
    diamond_adversary, diamond_capability, diamond_infrastructure, diamond_victim, diamond_meta, business_impact,
    capability_profile, infrastructure_profile, ir_actions, countermeasures, forecast, extortion_tactics, body_md,
    status, version, cutoff_date, prepared_by, ai_provider_label, created_at, updated_at, created_by
  ) VALUES (${Array.from({ length: 51 }, () => "?").join(", ")})`).run(
    aid, tenantId, profileId, info.name, null, j(info.aliases), j({ optrasight: [info.name, ...info.aliases].slice(0, 6) }),
    shape.actorType, shape.sponsorship, info.country === "Unknown" ? null : info.country, info.country === "Unknown" ? null : "Likely",
    j(shape.motivation), null, shape.sophistication, "AMBER", "B", "2", "Likely",
    j(shape.sectors), j(shape.regions), j(["VPN", "Identity Provider", "Microsoft 365", "Endpoint", "Edge Devices"]), "Medium to enterprise",
    rank <= 20 ? "Direct" : "Opportunistic", `Top-50 rank #${rank}`,
    `${info.name} is an active or highly consequential threat actor for 2026 monitoring.`,
    `${info.name} creates material risk through ${shape.motivation.join(", ").toLowerCase()} against ${shape.sectors.slice(0, 3).join(", ")}.`,
    "Harden identity and edge access, tune ATT&CK detections, and keep incident-response playbooks ready.",
    shape.threatLevel, `Ranked #${rank} in curated 2026 active/famous actor set; public reporting indicates sustained relevance.`, 1,
    j({ name: info.name, type: shape.actorType, assessedOrigin: info.country, motivation: shape.motivation }),
    j({ sophistication: shape.sophistication, commonTtps: ttps(info, shape).map((t) => t[1]), tools: tools(info, shape).map((t) => t[0]) }),
    j({ patterns: ["compromised infrastructure", "legitimate cloud services", "remote access services"], watch: ["new domains", "VPN logins", "large egress"] }),
    j({ sectors: shape.sectors, regions: shape.regions, orgSize: "Medium to enterprise" }),
    j({ confidence: "Likely", rank, sourceSet: "NCC Group, CrowdStrike, MITRE ATT&CK, CISA" }),
    j({ Financial: "High", Operational: shape.threatLevel === "HIGH" ? "High" : "Medium", Reputational: "High", Regulatory: "Medium", Data: "High", Strategic: shape.actorType === "Nation-State" ? "High" : "Medium" }),
    j({ tier: shape.sophistication, funding: shape.sponsorship, coordination: shape.actorType, evidence: info.notes }),
    j({ hosting: ["VPS", "compromised hosts", "cloud storage"], c2: ["HTTPS", "legitimate remote admin tools"], notes: "Replace seed values with tenant-confirmed infrastructure." }),
    j({ immediate: ["Disable suspect accounts", "Preserve IdP/VPN/EDR logs", "Isolate affected hosts"], shortTerm: ["Rotate privileged secrets", "Review remote access", "Hunt listed TTPs"], mediumTerm: ["Close exposed edge paths", "Validate backups"], strategic: ["Tabletop extortion and espionage scenarios"] }),
    j({ d3fend: ["D3-MFA", "D3-ACH", "D3-LFP"], cisV8: ["5 Account Management", "6 Access Control", "8 Audit Log Management", "13 Network Monitoring"], iso27001: ["A.5.15 Access control", "A.8.15 Logging", "A.8.16 Monitoring"] }),
    `Sustained activity is expected through 2026, especially where ${shape.sectors.slice(0, 2).join(" and ")} organizations expose identity, cloud, or edge control planes.`,
    j(shape.actorType.includes("Ransomware") ? { dataTheft: true, encryption: true, leakSitePressure: true, negotiation: "affiliate-led or brand-led" } : {}),
    bodyMd(info, shape, rank), "approved", 1, "2026-05-22", "OptraSight research seed", "Research seed", ts, ts, "system"
  );

  for (const t of ttps(info, shape)) {
    db.prepare(`INSERT INTO threat_actor_ttps (id, tenant_id, actor_id, tactic, technique_id, sub_technique_id, technique_name, evidence, status, detection_priority, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), tenantId, aid, t[0], t[1], t[2], t[3], t[4], "confirmed", t[5], ts);
  }
  for (const tool of tools(info, shape)) {
    db.prepare(`INSERT INTO threat_actor_tools (id, tenant_id, actor_id, name, category, purpose, variants, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), tenantId, aid, tool[0], tool[1], tool[2], j(tool[3]), tool[4], ts);
  }
  db.prepare(`INSERT INTO threat_actor_campaigns (id, tenant_id, actor_id, name, period, target_sector, target_geography, initial_access, outcome, source_url, finding_ids, rule_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id(), tenantId, aid, `${info.name} 2025-2026 monitored activity`, "2025-01 to 2026-05", shape.sectors.slice(0, 3).join(", "), shape.regions.slice(0, 3).join(", "), shape.actorType.includes("Ransomware") ? "Remote access, valid accounts, vulnerability exploitation" : "Spearphishing, edge exploitation, valid accounts", "Ongoing monitoring profile seeded for tenant threat landscape coverage", SOURCE_REFS[rank % SOURCE_REFS.length][3], j([]), j([]), ts);
  db.prepare(`INSERT INTO threat_actor_iocs (id, tenant_id, actor_id, ioc_type, value, first_seen, last_confirmed, confidence, tlp, source, mitre_ttps, recommended_action, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id(), tenantId, aid, "domain", `${info.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-example.invalid`, "2026-05-22", "2026-05-22", "Possible", "AMBER", "OptraSight placeholder seed", j(ttps(info, shape).map((t) => t[1])), "Placeholder only: replace with tenant-confirmed IoCs before blocking.", ts);
  SOURCE_REFS.forEach((ref, ix) => {
    db.prepare(`INSERT INTO threat_actor_references (id, tenant_id, actor_id, ref_num, source_type, title, date, url, archive_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), tenantId, aid, ix + 1, ref[0], ref[1], ref[2], ref[3], null, ts);
  });
}

function clearPortraits(oldActorIds) {
  const dir = resolve(process.cwd(), "data", "portraits");
  if (!existsSync(dir)) return;
  const old = new Set(oldActorIds);
  for (const f of readdirSync(dir)) {
    const stem = f.split(".")[0];
    if (old.has(stem)) {
      try { unlinkSync(join(dir, f)); } catch {}
    }
  }
}

const tenants = db.prepare("SELECT id, slug, name FROM tenants ORDER BY name").all();
if (!tenants.length) throw new Error("No tenants found; start the app once to initialize tenants first.");

const tx = db.transaction(() => {
  const oldIds = db.prepare("SELECT id FROM threat_actors").all().map((r) => r.id);
  clearPortraits(oldIds);
  for (const table of ["threat_actor_ttps", "threat_actor_tools", "threat_actor_campaigns", "threat_actor_iocs", "threat_actor_references", "threat_actor_detection_rules"]) {
    db.prepare(`DELETE FROM ${table}`).run();
  }
  db.prepare("DELETE FROM threat_actor_tenants").run();
  db.prepare("DELETE FROM threat_actors").run();

  const ts = now();
  for (const tenant of tenants) {
    TOP_50.forEach((name, ix) => seedActor(tenant.id, `TAP-${String(ix + 1).padStart(3, "0")}`, baseInfo(name), ix + 1, ts));
    db.prepare("INSERT INTO audit_log (id, tenant_id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id(), tenant.id, "system", "threat_actor.seed_top50", "threat_actors", j({ count: TOP_50.length, source: "scripts/seed-top-threat-actors.cjs" }), ts);
  }
});

tx();
console.log(`Seeded ${TOP_50.length} threat actor profiles for ${tenants.length} tenant(s).`);
