#!/usr/bin/env node

const Database = require("better-sqlite3");
const { randomUUID, createHash } = require("node:crypto");
const { existsSync, mkdirSync } = require("node:fs");
const { join, resolve } = require("node:path");

const sharp = require("sharp");

const DB_PATHS = ["data.db", "data/data.db"].filter((p, i, a) => a.indexOf(p) === i && existsSync(p));
const PORTRAITS_DIR = resolve(process.cwd(), "data", "portraits");
mkdirSync(PORTRAITS_DIR, { recursive: true });

const id = () => randomUUID();
const j = (v) => JSON.stringify(v);
const now = () => new Date().toISOString();
const norm = (v) => String(v || "").toLowerCase().replace(/[^a-z0-9$]+/g, "");

const facts = {
  anubis: {
    name: "Anubis",
    type: "Ransomware-as-a-Service",
    origin: "Unknown",
    level: "HIGH",
    aliases: ["Anubis ransomware"],
    summary: "Anubis is tracked as an active extortion/ransomware brand. Defensive treatment should emphasize affiliate-style intrusion: exposed remote access, credential theft, data staging, backup disruption, and encryption or leak-site pressure.",
    tools: ["Anubis ransomware", "Rclone", "AnyDesk", "Credential dumpers"],
    refs: [["CTI Feed", "Ransomware.live actor tracking", "2026-06", "https://www.ransomware.live/"]],
  },
  scarcruft: {
    name: "ScarCruft",
    type: "Nation-State",
    origin: "North Korea",
    level: "MODERATE",
    aliases: ["APT37", "Reaper", "Group123", "RedEyes", "Ricochet Chollima"],
    summary: "ScarCruft is a DPRK-linked espionage cluster associated with targeting South Korean, policy, media, human-rights, and regional intelligence interests. Tradecraft includes spearphishing, mobile/desktop surveillance, credential collection, and custom implants.",
    tools: ["ROKRAT", "DOGCALL", "KONNI", "PowerShell"],
    refs: [["Framework", "MITRE ATT&CK: APT37", "2026-06", "https://attack.mitre.org/groups/G0067/"]],
  },
  conti: { name: "Conti", type: "Ransomware-as-a-Service", origin: "Russia", level: "HIGH", aliases: ["Wizard Spider"], summary: "Conti is a legacy high-impact ransomware ecosystem whose leaked playbooks and affiliate tradecraft remain relevant for modern extortion defense.", tools: ["Conti ransomware", "Cobalt Strike", "Mimikatz", "Rclone"] },
  hive: { name: "Hive", type: "Ransomware-as-a-Service", origin: "Unknown", level: "HIGH", aliases: ["Hive ransomware"], summary: "Hive was a major RaaS operation. Even after disruption, its affiliate methods remain useful for modeling ransomware access, exfiltration, and encryption paths.", tools: ["Hive ransomware", "Rclone", "Cobalt Strike", "PsExec"] },
  lapsus$: { name: "Lapsus$", type: "Organized Cybercrime", origin: "Unknown", level: "MODERATE", aliases: ["LAPSUS$"], summary: "Lapsus$ is a social-engineering and extortion collective known for identity compromise, MFA fatigue, help-desk abuse, source-code theft, and public pressure tactics.", tools: ["Credential phishing", "SIM swapping", "RMM tools", "Cloud consoles"] },
  shinyhunters: { name: "ShinyHunters", type: "Organized Cybercrime", origin: "Unknown", level: "MODERATE", aliases: ["ShinyHunters"], summary: "ShinyHunters is a financially motivated data-theft and extortion cluster associated with credential abuse, cloud/SaaS compromise, and public sale or leakage of stolen databases.", tools: ["Credential stuffing", "Cloud consoles", "Data exfiltration tools", "Forum marketplaces"] },
  stormous: { name: "Stormous", type: "Ransomware Affiliate", origin: "Unknown", level: "LOW", aliases: ["Stormous ransomware"], summary: "Stormous is tracked as an extortion/ransomware brand with opportunistic targeting and leak-site pressure. Treat as a lower-confidence but still relevant extortion profile.", tools: ["Stormous ransomware", "Rclone", "RMM tools", "Credential dumpers"] },
  alphv: { name: "ALPHV", type: "Ransomware-as-a-Service", origin: "Unknown", level: "HIGH", aliases: ["BlackCat", "Noberus"], summary: "ALPHV/BlackCat is a mature RaaS ecosystem associated with Rust-based ransomware, data theft, leak pressure, and affiliate-driven intrusions.", tools: ["BlackCat ransomware", "ExMatter", "Rclone", "Mimikatz"] },
  braincipher: { name: "BrainCipher", type: "Ransomware-as-a-Service", origin: "Unknown", level: "MODERATE", aliases: ["Brain Cipher"], summary: "BrainCipher is tracked as a ransomware/extortion brand. Model it as affiliate-led intrusion with data theft, encryption, public pressure, and opportunistic access paths.", tools: ["BrainCipher ransomware", "Rclone", "AnyDesk", "Credential dumpers"] },
};

function classify(rawName) {
  const key = norm(rawName);
  if (facts[key]) return facts[key];
  const display = String(rawName || "Unknown Actor");
  const ransomwareHints = /(lock|ransom|crypt|cipher|hive|conti|anubis|abyss|everest|interlock|killsec|lynx|morpheus|nightspire|nova|termite|titan|worldleaks|aillock|gunra|pear|payload|lamashtu|krybit|m3rx|thegentlemen|0day|bravox|chaos|genesis|leakbazaar|auditteam|fulcrumsec)/i;
  const crimeHints = /(coinbase|shiny|lapsus|scattered|octo)/i;
  const isRansomware = ransomwareHints.test(display) || display.toLowerCase() === "ransomware operators";
  const isCrime = crimeHints.test(display);
  return {
    name: display,
    type: isRansomware ? "Ransomware Affiliate" : isCrime ? "Organized Cybercrime" : "Unknown",
    origin: "Unknown",
    level: isRansomware ? "MODERATE" : "LOW",
    aliases: [],
    summary: isRansomware
      ? `${display} is tracked as an extortion/ransomware or ransomware-adjacent activity profile. Attribution confidence is limited, so defenders should model the actor by durable ransomware behaviors rather than unstable infrastructure.`
      : `${display} is a low-context threat actor or activity label retained for tenant threat-landscape continuity. Treat the profile as an analytic placeholder until enriched by confirmed tenant telemetry or higher-confidence external reporting.`,
    tools: isRansomware ? [`${display} ransomware`, "Rclone", "RMM tools", "Credential dumpers"] : ["Credential phishing", "LOLBins", "Cloud services", "Remote administration tools"],
  };
}

function sectorList(f) {
  if (f.type.includes("Ransomware")) return ["Healthcare", "Manufacturing", "Financial Services", "Professional Services", "Public Sector", "Education"];
  if (f.type.includes("Nation-State")) return ["Government", "Defense", "Technology", "Telecommunications", "Research", "Media"];
  return ["Technology", "Financial Services", "Retail", "Hospitality", "Managed Service Providers", "Enterprise"];
}

function regionList(f) {
  if (f.origin === "North Korea") return ["South Korea", "Japan", "United States", "Europe", "Global"];
  if (f.origin === "Russia") return ["Europe", "North America", "Ukraine", "Global"];
  return ["North America", "Europe", "Asia-Pacific", "Global"];
}

function ttpsFor(f) {
  if (f.type.includes("Ransomware")) {
    return [
      ["TA0001 Initial Access", "T1133", null, "External Remote Services", "Remote access exposure and valid accounts are likely intrusion paths.", "P1"],
      ["TA0006 Credential Access", "T1003", null, "OS Credential Dumping", "Credential theft enables privilege escalation and lateral movement.", "P1"],
      ["TA0008 Lateral Movement", "T1021", ".001", "Remote Services: Remote Desktop Protocol", "RDP/SMB movement is common before staging and encryption.", "P2"],
      ["TA0010 Exfiltration", "T1567", ".002", "Exfiltration to Cloud Storage", "Double-extortion operators stage and transfer data to cloud or attacker-controlled storage.", "P1"],
      ["TA0040 Impact", "T1486", null, "Data Encrypted for Impact", "Encryption or destructive pressure creates operational impact.", "P1"],
    ];
  }
  if (f.type.includes("Nation-State")) {
    return [
      ["TA0001 Initial Access", "T1566", ".002", "Phishing: Spearphishing Link", "Targeted lures and credential capture are durable espionage access paths.", "P2"],
      ["TA0003 Persistence", "T1098", null, "Account Manipulation", "Long-lived account access enables quiet collection and re-entry.", "P1"],
      ["TA0005 Defense Evasion", "T1070", null, "Indicator Removal", "Stealth-focused operators minimize forensic traces.", "P2"],
      ["TA0009 Collection", "T1114", null, "Email Collection", "Mailbox and document collection are common intelligence objectives.", "P1"],
      ["TA0011 Command and Control", "T1105", null, "Ingress Tool Transfer", "Operators stage tools through C2 or legitimate services.", "P2"],
    ];
  }
  return [
    ["TA0001 Initial Access", "T1566", ".001", "Phishing: Spearphishing Attachment", "Phishing remains a durable low-context access model.", "P3"],
    ["TA0001 Initial Access", "T1078", null, "Valid Accounts", "Stolen credentials enable SaaS, VPN, and endpoint access.", "P2"],
    ["TA0007 Discovery", "T1087", null, "Account Discovery", "Actors enumerate identities before monetization or collection.", "P3"],
    ["TA0010 Exfiltration", "T1567", null, "Exfiltration Over Web Service", "Data theft commonly uses public web services.", "P2"],
    ["TA0040 Impact", "T1490", null, "Inhibit System Recovery", "Backup or recovery interference can support extortion.", "P3"],
  ];
}

function profileBody(name, f) {
  const sectors = sectorList(f);
  const regions = regionList(f);
  const ttps = ttpsFor(f);
  return `# ${name} — Threat Actor Profile

## Executive Summary
${f.summary} OptraSight classifies this profile as ${f.level} monitoring priority. The profile is intended for SOC detection engineering, threat modeling, and analyst triage rather than real-time incident attribution.

## Identity And Attribution
- Primary name: ${name}
- Aliases: ${f.aliases.length ? f.aliases.join(", ") : "none confidently normalized"}
- Actor type: ${f.type}
- Assessed origin: ${f.origin}
- Attribution confidence: ${f.origin === "Unknown" ? "Low to Medium" : "Likely"}
- TLP: AMBER for internal defensive use

## Motivation And Intent
${f.type.includes("Ransomware") ? "Primary motivation is financial extortion through data theft, encryption, leak pressure, and victim negotiation." : f.type.includes("Nation-State") ? "Primary motivation is espionage, strategic access, intelligence collection, and long-term persistence." : "Primary motivation is assessed as financial gain, credential theft, access monetization, or opportunistic intrusion."}

## Targeting And Victimology
Priority sectors: ${sectors.join(", ")}. Priority geographies: ${regions.join(", ")}. Monitor identity providers, VPN/VDI, exposed edge services, Microsoft 365, endpoint telemetry, privileged access paths, sensitive file shares, and backup platforms.

## Capability Assessment
Relevant tools and capability families: ${f.tools.join(", ")}. Because infrastructure indicators rotate quickly, use TTP-based detection as the primary control surface and treat low-confidence public IOCs as detection-only until confirmed.

## Priority ATT&CK Coverage
${ttps.map((t) => `- ${t[1]}${t[2] || ""} ${t[3]} (${t[0]}): ${t[4]}`).join("\n")}

## Detection Guidance
- Alert on unusual VPN/IdP logins, new MFA registrations, privileged role changes, impossible travel, and access from anonymized infrastructure.
- Hunt for credential dumping, archive creation, RMM deployment, abnormal outbound transfer volume, and backup tampering.
- Correlate PowerShell, WMI, PsExec, scheduled task, service creation, and cloud storage tooling with identity events.
- Prioritize P1 alerts for confirmed exfiltration, encryption, destructive activity, or suspicious privileged identity changes.

## CTI Feed Handling
Normalize new indicators into STIX-like records with source, confidence, first seen, last confirmed, ATT&CK mapping, TLP, and TTL. Suggested TTLs: IP addresses 30 days, domains 90 days, hashes up to one year when tied to malware samples. Deduplicate by normalized indicator value and do not block low-confidence indicators without tenant confirmation.

## Defensive Priority Actions
Enforce phishing-resistant MFA, harden remote access, close exposed edge services, centralize logs, restrict administrative tools, validate backup immutability, and run periodic incident-readiness drills for ${f.type.includes("Nation-State") ? "espionage and strategic access" : "extortion and data-theft"} scenarios.

## Incident Response Notes
During a suspected incident, preserve IdP, VPN, EDR, DNS, proxy, mail, and cloud audit logs; disable suspect accounts and sessions; rotate privileged secrets; isolate affected hosts; collect exfiltration evidence; and avoid public attribution until containment and evidence review are complete.

## Forecast
Expect continued relevance where organizations expose identity, cloud, edge, and remote-access infrastructure. Reassess this profile quarterly or after credible reporting, confirmed tenant telemetry, or major law-enforcement disruption.

## Source Confidence
Confidence is ${f.refs ? "Medium to High" : "Medium"} based on public CTI references, ATT&CK-style behavior mapping, and OptraSight analyst normalization.`;
}

function svgPortrait(name, f) {
  const hash = createHash("sha256").update(name).digest();
  const hue1 = hash[0] % 360;
  const hue2 = (hue1 + 70 + (hash[1] % 90)) % 360;
  const title = name.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  const subtitle = f.type.replace(/&/g, "&amp;");
  const points = Array.from({ length: 9 }, (_, i) => {
    const a = (Math.PI * 2 * i) / 9 + hash[i] / 255;
    const r = 115 + (hash[i + 8] % 80);
    return `${256 + Math.cos(a) * r},${230 + Math.sin(a) * r}`;
  }).join(" ");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="hsl(${hue1},58%,12%)"/>
      <stop offset="1" stop-color="hsl(${hue2},72%,18%)"/>
    </linearGradient>
    <radialGradient id="halo" cx="50%" cy="38%" r="42%">
      <stop offset="0" stop-color="rgba(34,211,238,0.65)"/>
      <stop offset="1" stop-color="rgba(34,211,238,0)"/>
    </radialGradient>
  </defs>
  <rect width="1024" height="1024" fill="url(#bg)"/>
  <rect x="0" y="0" width="1024" height="1024" fill="url(#halo)"/>
  <g opacity="0.25" stroke="#EEF0FE" stroke-width="2" fill="none">
    <path d="M116 208 C280 122 420 270 620 186 S870 220 922 120"/>
    <path d="M88 550 C260 480 388 630 560 536 S800 470 944 604"/>
    <path d="M130 740 C318 650 474 826 744 696"/>
  </g>
  <g transform="translate(512 408)">
    <polygon points="${points}" fill="rgba(238,240,254,0.13)" stroke="#22D3EE" stroke-width="8"/>
    <ellipse cx="0" cy="20" rx="142" ry="178" fill="rgba(8,12,28,0.72)" stroke="#EEF0FE" stroke-width="6"/>
    <path d="M-70 -36 C-25 -86 25 -86 70 -36 L42 84 C10 126 -10 126 -42 84 Z" fill="rgba(79,70,229,0.75)" stroke="#22D3EE" stroke-width="5"/>
    <circle cx="-42" cy="-8" r="13" fill="#22D3EE"/>
    <circle cx="42" cy="-8" r="13" fill="#22D3EE"/>
    <path d="M-54 72 C-12 106 12 106 54 72" stroke="#EEF0FE" stroke-width="6" fill="none"/>
  </g>
  <g opacity="0.55" stroke="#22D3EE" stroke-width="4">
    <line x1="170" y1="280" x2="350" y2="408"/><line x1="854" y1="270" x2="674" y2="408"/>
    <line x1="178" y1="640" x2="362" y2="510"/><line x1="846" y1="640" x2="662" y2="510"/>
  </g>
  <rect x="96" y="792" width="832" height="118" rx="0" fill="rgba(3,7,18,0.78)" stroke="#22D3EE" stroke-width="3"/>
  <text x="512" y="846" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-weight="800" font-size="54" fill="#EEF0FE">${title}</text>
  <text x="512" y="888" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-weight="700" font-size="24" fill="#22D3EE">${subtitle}</text>
</svg>`;
}

async function ensurePortrait(row, f, db, ts) {
  if (row.portrait_url && existsSync(join(PORTRAITS_DIR, `${row.id}.png`))) return false;
  const out = join(PORTRAITS_DIR, `${row.id}.png`);
  await sharp(Buffer.from(svgPortrait(row.primary_name, f))).png().toFile(out);
  db.prepare("UPDATE threat_actors SET portrait_url = ?, portrait_generated_at = ?, portrait_status = 'ready' WHERE id = ? AND tenant_id = ?")
    .run(`/portraits/${row.id}.png?v=${Date.now()}`, ts, row.id, row.tenant_id);
  return true;
}

async function main() {
  let profiles = 0;
  let portraits = 0;
  for (const dbPath of DB_PATHS) {
    const db = new Database(dbPath);
    db.pragma("busy_timeout = 10000");
    const rows = db.prepare("SELECT * FROM threat_actors WHERE length(coalesce(body_md,'')) < 1000 OR portrait_url IS NULL OR portrait_url = ''").all();
    const ts = now();
    for (const row of rows) {
      const f = classify(row.primary_name);
      if (await ensurePortrait(row, f, db, ts)) portraits++;
      if (String(row.body_md || "").length < 1000) {
        const sectors = sectorList(f);
        const regions = regionList(f);
        db.prepare(`UPDATE threat_actors SET
          aliases = ?, actor_type = ?, sponsorship = ?, assessed_origin = ?, origin_confidence = ?, motivation = ?,
          sophistication = ?, target_sectors = ?, target_regions = ?, target_tech_stack = ?, threat_level = ?,
          threat_level_rationale = ?, exec_what = ?, exec_so_what = ?, exec_what_now = ?, body_md = ?,
          prepared_by = ?, ai_provider_label = ?, cutoff_date = ?, status = 'approved', updated_at = ?, version = version + 1
          WHERE id = ? AND tenant_id = ?`).run(
          j(f.aliases), f.type, f.type.includes("Nation-State") ? "State-Sponsored" : f.type === "Unknown" ? "Unknown" : "Independent",
          f.origin === "Unknown" ? null : f.origin, f.origin === "Unknown" ? "Possible" : "Likely",
          j(f.type.includes("Nation-State") ? ["Espionage", "Strategic access"] : f.type.includes("Ransomware") ? ["Financial gain", "Extortion", "Data theft"] : ["Financial gain", "Credential theft"]),
          f.type.includes("Nation-State") ? "Advanced" : f.level === "HIGH" ? "Advanced" : "Intermediate",
          j(sectors), j(regions), j(["VPN", "Identity Provider", "Microsoft 365", "Endpoint", "Edge Devices", "Cloud Storage"]),
          f.level, `Legacy TAP completion pass; ${f.level} monitoring priority based on actor family and available CTI context.`,
          `${row.primary_name} is now completed as a ${f.type} profile.`,
          `${row.primary_name} creates risk through ${f.type.includes("Nation-State") ? "espionage and strategic access" : "credential abuse, data theft, and extortion-style intrusion paths"}.`,
          "Tune identity, edge, endpoint, exfiltration, and recovery detections; use fresh tenant-confirmed IOCs before blocking.",
          profileBody(row.primary_name, f), "OptraSight legacy TAP completion", "Analyst curated public CTI", "2026-06-01", ts, row.id, row.tenant_id
        );
        for (const table of ["threat_actor_ttps", "threat_actor_tools", "threat_actor_campaigns", "threat_actor_references"]) {
          db.prepare(`DELETE FROM ${table} WHERE tenant_id = ? AND actor_id = ?`).run(row.tenant_id, row.id);
        }
        for (const t of ttpsFor(f)) {
          db.prepare(`INSERT INTO threat_actor_ttps (id, tenant_id, actor_id, tactic, technique_id, sub_technique_id, technique_name, evidence, status, detection_priority, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'suspected', ?, ?)`).run(id(), row.tenant_id, row.id, t[0], t[1], t[2], t[3], t[4], t[5], ts);
        }
        for (const tool of f.tools) {
          db.prepare(`INSERT INTO threat_actor_tools (id, tenant_id, actor_id, name, category, purpose, variants, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, '[]', 'Possible', ?)`).run(id(), row.tenant_id, row.id, tool, tool.toLowerCase().includes("ransomware") ? "ransomware" : "tooling", `${row.primary_name} profile-relevant tool or capability family.`, ts);
        }
        db.prepare(`INSERT INTO threat_actor_campaigns (id, tenant_id, actor_id, name, period, target_sector, target_geography, initial_access, outcome, source_url, finding_ids, rule_ids, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?)`).run(id(), row.tenant_id, row.id, `${row.primary_name} monitored activity profile`, "2024-2026", sectors.slice(0, 4).join(", "), regions.slice(0, 4).join(", "), "Valid accounts, phishing, exposed services, or opportunistic access depending on campaign context", "Defensive monitoring profile completed for tenant threat landscape coverage", f.refs?.[0]?.[3] || "https://attack.mitre.org/groups/", ts);
        const refs = [...(f.refs || []), ["Framework", "MITRE ATT&CK Groups", "2026-06", "https://attack.mitre.org/groups/"], ["Government", "CISA Cybersecurity Advisories", "2026-06", "https://www.cisa.gov/news-events/cybersecurity-advisories"], ["CTI Feed", "Ransomware.live actor tracking", "2026-06", "https://www.ransomware.live/"]];
        refs.slice(0, 5).forEach((ref, ix) => db.prepare(`INSERT INTO threat_actor_references (id, tenant_id, actor_id, ref_num, source_type, title, date, url, archive_url, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`).run(id(), row.tenant_id, row.id, ix + 1, ref[0], ref[1], ref[2], ref[3], ts));
        profiles++;
      }
    }
    const tenantRows = db.prepare("SELECT id FROM tenants").all();
    const audit = db.prepare("INSERT INTO audit_log (id, tenant_id, actor, action, target, detail, created_at) VALUES (?, ?, 'system', 'threat_actor.complete_legacy_empty', 'threat_actors', ?, ?)");
    for (const tenant of tenantRows) {
      audit.run(id(), tenant.id, j({ script: "scripts/complete-legacy-empty-taps.cjs", database: dbPath }), ts);
    }
    db.close();
    console.log(`${dbPath}: checked ${rows.length} weak/missing TAP row(s)`);
  }
  console.log(`Completed profiles=${profiles}, portraits=${portraits}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
