#!/usr/bin/env node
// Generate detection rules for all threat actor profiles across all platform languages.
// Each actor gets one detection rule per tenant, with queries in all 8 SIEM/EDR languages
// plus Sigma YAML. Rules are linked to actors via threat_actor_detection_rules bridge table.

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

function parseJson(value, fallback) {
  try { const p = JSON.parse(value || ""); return p == null ? fallback : p; } catch { return fallback; }
}

// ─── IOC Collectors ──────────────────────────────────────────────────────────

function getActorIocs(actorId, tenantId) {
  return db.prepare("SELECT ioc_type, value, source FROM threat_actor_iocs WHERE actor_id = ? AND tenant_id = ?").all(actorId, tenantId);
}

function getActorTtps(actorId, tenantId) {
  return db.prepare("SELECT technique_id, sub_technique_id, technique_name, tactic FROM threat_actor_ttps WHERE actor_id = ? AND tenant_id = ? ORDER BY technique_id").all(actorId, tenantId);
}

function getActorTools(actorId, tenantId) {
  return db.prepare("SELECT name, category FROM threat_actor_tools WHERE actor_id = ? AND tenant_id = ?").all(actorId, tenantId);
}

// ─── IOC Partitioner ─────────────────────────────────────────────────────────

function partitionIocs(iocs) {
  const hashes = { sha256: [], md5: [], sha1: [] };
  const network = { domains: [], ips: [], urls: [] };
  const host = { filenames: [], filepaths: [], commands: [], regkeys: [], mutexes: [] };
  const tools = [];
  for (const ioc of iocs) {
    switch (ioc.ioc_type) {
      case "sha256": hashes.sha256.push(ioc.value); break;
      case "md5": hashes.md5.push(ioc.value); break;
      case "sha1": hashes.sha1.push(ioc.value); break;
      case "domain": network.domains.push(ioc.value); break;
      case "ipv4": case "ipv6": network.ips.push(ioc.value); break;
      case "url": network.urls.push(ioc.value); break;
      case "filename": host.filenames.push(ioc.value); break;
      case "filepath": host.filepaths.push(ioc.value); break;
      case "command_line": host.commands.push(ioc.value); break;
      case "regkey": host.regkeys.push(ioc.value); break;
      case "mutex": host.mutexes.push(ioc.value); break;
      case "tool": tools.push(ioc.value); break;
    }
  }
  return { hashes, network, host, tools };
}

// ─── Escaping helpers ────────────────────────────────────────────────────────

function esc(s) { return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"'); }
function escRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function yaraEsc(s) { return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"'); }
function q(vals) { return vals.map(v => `"${esc(v)}"`).join(", "); }

// ─── MITRE tag helpers ───────────────────────────────────────────────────────

function mitreTags(ttps) {
  const tags = new Set();
  for (const t of ttps) {
    const tid = (t.sub_technique_id || t.technique_id || "").toLowerCase();
    if (tid) tags.add(`attack.${tid}`);
    const tactic = (t.tactic || "").replace(/^TA\d+\s+/i, "").toLowerCase().replace(/\s+/g, "_");
    if (tactic) tags.add(`attack.${tactic}`);
  }
  return [...tags].slice(0, 15);
}

function mitreTechniquesJson(ttps) {
  return ttps.slice(0, 10).map(t => ({
    id: t.sub_technique_id || t.technique_id,
    name: t.technique_name,
    tactic: t.tactic,
  }));
}

// ─── Severity mapper ─────────────────────────────────────────────────────────

function severityFromThreatLevel(threatLevel) {
  switch (threatLevel) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MODERATE": return "medium";
    case "LOW": return "low";
    default: return "medium";
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE GENERATORS — one per language
// ═══════════════════════════════════════════════════════════════════════════════

function genSigma(actor, p, ttps, severity, ts) {
  const allHashes = [...p.hashes.sha256, ...p.hashes.md5, ...p.hashes.sha1];
  const lines = [];
  lines.push(`title: "${actor.primary_name} — Threat Actor Hunt Rule"`);
  lines.push(`id: optrasight-tap-${actor.profile_id.toLowerCase()}`);
  lines.push(`status: stable`);
  lines.push(`description: "Detect indicators associated with ${actor.primary_name} (${actor.actor_type}). Auto-generated from OptraSight TAP IOC database."`);
  lines.push(`author: OptraSight CTI`);
  lines.push(`date: ${ts.slice(0, 10).replace(/-/g, "/")}`);
  lines.push(`tags:`);
  for (const tag of mitreTags(ttps)) lines.push(`  - ${tag}`);
  lines.push(`logsource:`);
  lines.push(`  product: windows`);
  lines.push(`  category: process_creation`);
  lines.push(`detection:`);

  let condParts = [];

  if (p.host.commands.length > 0) {
    lines.push(`  selection_cmdline:`);
    lines.push(`    CommandLine|contains:`);
    for (const cmd of p.host.commands.slice(0, 20)) lines.push(`      - '${cmd.replace(/'/g, "''")}'`);
    condParts.push("selection_cmdline");
  }

  if (p.host.filenames.length > 0) {
    lines.push(`  selection_filename:`);
    lines.push(`    Image|endswith:`);
    for (const fn of p.host.filenames.slice(0, 20)) lines.push(`      - '\\${fn.replace(/'/g, "''")}'`);
    condParts.push("selection_filename");
  }

  if (allHashes.length > 0) {
    lines.push(`  selection_hash:`);
    if (p.hashes.sha256.length > 0) {
      lines.push(`    Hashes|contains:`);
      for (const h of p.hashes.sha256.slice(0, 15)) lines.push(`      - '${h}'`);
    }
    if (p.hashes.md5.length > 0) {
      lines.push(`    md5:`);
      for (const h of p.hashes.md5.slice(0, 10)) lines.push(`      - '${h}'`);
    }
    condParts.push("selection_hash");
  }

  if (condParts.length === 0) {
    lines.push(`  selection_tool:`);
    lines.push(`    CommandLine|contains:`);
    for (const t of p.tools.slice(0, 10)) lines.push(`      - '${t.replace(/'/g, "''")}'`);
    condParts.push("selection_tool");
  }

  lines.push(`  condition: ${condParts.join(" or ")}`);
  lines.push(`falsepositives:`);
  lines.push(`  - Legitimate admin tool usage matching tool name strings`);
  lines.push(`level: ${severity}`);
  return lines.join("\n");
}

function genSplunk(actor, p, severity) {
  const lines = [];
  lines.push(`// OptraSight TAP Detection Rule — ${actor.primary_name}`);
  lines.push(`// Actor type: ${actor.actor_type} | Severity: ${severity}`);
  lines.push(`// Auto-generated from threat actor IOC database`);
  lines.push(`index=* sourcetype IN ("WinEventLog:*","xmlwineventlog:microsoft-windows-sysmon/operational","linux_secure","aws:cloudtrail")`);
  lines.push(`  earliest=-30d`);

  const orClauses = [];
  if (p.host.commands.length > 0) {
    const cmds = p.host.commands.slice(0, 15).map(c => `"*${esc(c)}*"`).join(", ");
    orClauses.push(`process_command_line IN (${cmds})`);
  }
  if (p.host.filenames.length > 0) {
    const fns = p.host.filenames.slice(0, 15).map(f => `"*${esc(f)}"`).join(", ");
    orClauses.push(`(process_path IN (${fns}) OR file_name IN (${fns}))`);
  }
  if (p.hashes.sha256.length > 0) {
    orClauses.push(`file_hash IN (${q(p.hashes.sha256.slice(0, 15))})`);
  }
  if (p.hashes.md5.length > 0) {
    orClauses.push(`md5 IN (${q(p.hashes.md5.slice(0, 10))})`);
  }
  if (p.network.domains.length > 0) {
    orClauses.push(`query IN (${q(p.network.domains.slice(0, 15))}) OR dest IN (${q(p.network.domains.slice(0, 15))})`);
  }
  if (p.network.ips.length > 0) {
    orClauses.push(`dest_ip IN (${q(p.network.ips.slice(0, 15))})`);
  }
  if (p.network.urls.length > 0) {
    orClauses.push(`url IN (${q(p.network.urls.slice(0, 10))})`);
  }
  if (p.host.regkeys.length > 0) {
    const rks = p.host.regkeys.slice(0, 5).map(r => `"*${esc(r)}*"`).join(", ");
    orClauses.push(`registry_path IN (${rks})`);
  }
  if (orClauses.length === 0 && p.tools.length > 0) {
    const tls = p.tools.slice(0, 10).map(t => `"*${esc(t)}*"`).join(", ");
    orClauses.push(`process_command_line IN (${tls})`);
  }

  lines.push(`  AND (`);
  lines.push(`    ${orClauses.join("\n    OR ")}`);
  lines.push(`  )`);
  lines.push(`| eval threat_actor="${esc(actor.primary_name)}"`);
  lines.push(`| stats count, values(src_ip) AS src, values(dest_ip) AS dst, values(user) AS users, values(host) AS hosts BY threat_actor, process_command_line, file_name`);
  lines.push(`| where count >= 1`);
  lines.push(`| sort - count`);
  return lines.join("\n");
}

function genKqlElk(actor, p) {
  const lines = [];
  lines.push(`// OptraSight TAP Detection Rule — ${actor.primary_name}`);
  lines.push(`// ELK / Kibana KQL`);
  lines.push(`@timestamp >= now-30d`);
  lines.push(`and (`);

  const clauses = [];
  if (p.host.commands.length > 0) {
    const cmds = p.host.commands.slice(0, 15).map(c => `"*${c}*"`).join(" or ");
    clauses.push(`  process.command_line : (${cmds})`);
  }
  if (p.host.filenames.length > 0) {
    const fns = p.host.filenames.slice(0, 15).map(f => `"*${f}"`).join(" or ");
    clauses.push(`  (process.executable : (${fns}) or file.name : (${fns}))`);
  }
  if (p.hashes.sha256.length > 0) {
    clauses.push(`  file.hash.sha256 : (${p.hashes.sha256.slice(0, 15).map(h => `"${h}"`).join(" or ")})`);
  }
  if (p.hashes.md5.length > 0) {
    clauses.push(`  file.hash.md5 : (${p.hashes.md5.slice(0, 10).map(h => `"${h}"`).join(" or ")})`);
  }
  if (p.network.domains.length > 0) {
    clauses.push(`  dns.question.name : (${p.network.domains.slice(0, 15).map(d => `"${d}"`).join(" or ")})`);
  }
  if (p.network.ips.length > 0) {
    clauses.push(`  destination.ip : (${p.network.ips.slice(0, 15).map(ip => `"${ip}"`).join(" or ")})`);
  }
  if (p.network.urls.length > 0) {
    clauses.push(`  url.full : (${p.network.urls.slice(0, 10).map(u => `"${u}"`).join(" or ")})`);
  }
  if (clauses.length === 0 && p.tools.length > 0) {
    const tls = p.tools.slice(0, 10).map(t => `"*${t}*"`).join(" or ");
    clauses.push(`  process.command_line : (${tls})`);
  }

  lines.push(clauses.join("\n  or\n"));
  lines.push(`)`);
  return lines.join("\n");
}

function genDefender(actor, p) {
  const lines = [];
  lines.push(`// OptraSight TAP Detection Rule — ${actor.primary_name}`);
  lines.push(`// Microsoft Defender / Sentinel KQL`);
  lines.push(`union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents`);
  lines.push(`| where Timestamp > ago(30d)`);

  const whereClauses = [];
  if (p.host.commands.length > 0) {
    const cmds = p.host.commands.slice(0, 15).map(c => `"${esc(c)}"`).join(", ");
    whereClauses.push(`ProcessCommandLine has_any (${cmds})`);
  }
  if (p.host.filenames.length > 0) {
    const fns = p.host.filenames.slice(0, 15).map(f => `"${esc(f)}"`).join(", ");
    whereClauses.push(`FileName has_any (${fns})`);
  }
  if (p.hashes.sha256.length > 0) {
    const hashes = p.hashes.sha256.slice(0, 15).map(h => `"${h}"`).join(", ");
    whereClauses.push(`SHA256 in~ (${hashes})`);
  }
  if (p.hashes.md5.length > 0) {
    const hashes = p.hashes.md5.slice(0, 10).map(h => `"${h}"`).join(", ");
    whereClauses.push(`MD5 in~ (${hashes})`);
  }
  if (p.network.domains.length > 0) {
    const doms = p.network.domains.slice(0, 15).map(d => `"${esc(d)}"`).join(", ");
    whereClauses.push(`RemoteUrl has_any (${doms})`);
  }
  if (p.network.ips.length > 0) {
    const ips = p.network.ips.slice(0, 15).map(ip => `"${ip}"`).join(", ");
    whereClauses.push(`RemoteIP in (${ips})`);
  }
  if (whereClauses.length === 0 && p.tools.length > 0) {
    const tls = p.tools.slice(0, 10).map(t => `"${esc(t)}"`).join(", ");
    whereClauses.push(`ProcessCommandLine has_any (${tls})`);
  }

  lines.push(`| where ${whereClauses.join("\n    or ")}`);
  lines.push(`| extend ThreatActor = "${esc(actor.primary_name)}"`);
  lines.push(`| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, RemoteUrl, RemoteIP, SHA256, ThreatActor`);
  lines.push(`| sort by Timestamp desc`);
  return lines.join("\n");
}

function genCrowdstrike(actor, p) {
  const lines = [];
  lines.push(`// OptraSight TAP Detection Rule — ${actor.primary_name}`);
  lines.push(`// CrowdStrike Falcon LogScale (CQL)`);
  lines.push(`#event_simpleName=/ProcessRollup2|NetworkConnect|DnsRequest|FileWritten/`);

  const filters = [];
  if (p.host.commands.length > 0) {
    const pattern = p.host.commands.slice(0, 10).map(c => escRegex(c)).join("|");
    filters.push(`regex(field=CommandLine, regex="(?i)(${pattern})")`);
  }
  if (p.host.filenames.length > 0) {
    const fns = p.host.filenames.slice(0, 15).map(f => `"${esc(f)}"`).join(", ");
    filters.push(`in(field=ImageFileName, values=[${fns}], ignoreCase=true)`);
  }
  if (p.hashes.sha256.length > 0) {
    const hashes = p.hashes.sha256.slice(0, 10).map(h => `"${h}"`).join(", ");
    filters.push(`in(field=SHA256HashData, values=[${hashes}])`);
  }
  if (p.network.domains.length > 0) {
    const doms = p.network.domains.slice(0, 15).map(d => `"${esc(d)}"`).join(", ");
    filters.push(`in(field=DomainName, values=[${doms}], ignoreCase=true)`);
  }
  if (p.network.ips.length > 0) {
    const ips = p.network.ips.slice(0, 15).map(ip => `"${ip}"`).join(", ");
    filters.push(`in(field=RemoteAddressIP4, values=[${ips}])`);
  }
  if (filters.length === 0 && p.tools.length > 0) {
    const pattern = p.tools.slice(0, 8).map(t => escRegex(t)).join("|");
    filters.push(`regex(field=CommandLine, regex="(?i)(${pattern})")`);
  }

  lines.push(`| ${filters.join("\n   OR ")}`);
  lines.push(`| groupby([ComputerName, UserName, ImageFileName, CommandLine])`);
  lines.push(`| sort(field=_count, order=desc)`);
  return lines.join("\n");
}

function genCortexXdr(actor, p) {
  const lines = [];
  lines.push(`// OptraSight TAP Detection Rule — ${actor.primary_name}`);
  lines.push(`// Palo Alto Cortex XDR (XQL)`);
  lines.push(`dataset = xdr_data`);
  lines.push(`| filter event_type in (PROCESS, NETWORK, FILE)`);

  const filters = [];
  if (p.host.commands.length > 0) {
    const pattern = p.host.commands.slice(0, 10).map(c => escRegex(c)).join("|");
    filters.push(`actor_process_command_line ~= "(?i)(${pattern})"`);
  }
  if (p.host.filenames.length > 0) {
    const fns = p.host.filenames.slice(0, 15).map(f => `"${esc(f)}"`).join(", ");
    filters.push(`action_process_image_name in (${fns})`);
  }
  if (p.hashes.sha256.length > 0) {
    const hashes = p.hashes.sha256.slice(0, 10).map(h => `"${h}"`).join(", ");
    filters.push(`action_file_sha256 in (${hashes})`);
  }
  if (p.network.domains.length > 0) {
    const doms = p.network.domains.slice(0, 15).map(d => `"${esc(d)}"`).join(", ");
    filters.push(`action_remote_url contains_any (${doms})`);
  }
  if (p.network.ips.length > 0) {
    const ips = p.network.ips.slice(0, 15).map(ip => `"${ip}"`).join(", ");
    filters.push(`action_remote_ip in (${ips})`);
  }
  if (filters.length === 0 && p.tools.length > 0) {
    const pattern = p.tools.slice(0, 8).map(t => escRegex(t)).join("|");
    filters.push(`actor_process_command_line ~= "(?i)(${pattern})"`);
  }

  lines.push(`| filter (`);
  lines.push(`    ${filters.join("\n    or ")}`);
  lines.push(`  )`);
  lines.push(`| fields _time, agent_hostname, actor_process_image_name, action_process_image_command_line, action_remote_url, action_remote_ip, action_file_sha256`);
  lines.push(`| sort desc _time`);
  return lines.join("\n");
}

function genChronicle(actor, p, severity) {
  const ruleName = `optrasight_tap_${actor.primary_name.replace(/[^A-Za-z0-9]/g, "_").toLowerCase()}`;
  const sevMap = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };
  const lines = [];
  lines.push(`rule ${ruleName} {`);
  lines.push(`  meta:`);
  lines.push(`    author      = "OptraSight CTI"`);
  lines.push(`    severity    = "${sevMap[severity] || "MEDIUM"}"`);
  lines.push(`    description = "Hunt for ${actor.primary_name} (${actor.actor_type}) indicators"`);
  lines.push(`  events:`);
  lines.push(`    $e.metadata.event_type = "NETWORK_HTTP" or $e.metadata.event_type = "PROCESS_LAUNCH" or $e.metadata.event_type = "NETWORK_DNS"`);
  lines.push(`    $e.principal.hostname != ""`);

  const conditions = [];
  if (p.host.commands.length > 0) {
    const pattern = p.host.commands.slice(0, 8).map(c => escRegex(c)).join("|");
    conditions.push(`    re.regex($e.target.process.command_line, \`(?i)(${pattern})\`)`);
  }
  if (p.host.filenames.length > 0) {
    const pattern = p.host.filenames.slice(0, 10).map(f => escRegex(f)).join("|");
    conditions.push(`    re.regex($e.target.process.file.full_path, \`(?i)(${pattern})\`)`);
  }
  if (p.hashes.sha256.length > 0) {
    for (const h of p.hashes.sha256.slice(0, 5)) {
      conditions.push(`    $e.target.file.sha256 = "${h}"`);
    }
  }
  if (p.network.domains.length > 0) {
    const pattern = p.network.domains.slice(0, 10).map(d => escRegex(d)).join("|");
    conditions.push(`    re.regex($e.network.dns.questions.name, \`(?i)(${pattern})\`)`);
  }
  if (p.network.ips.length > 0) {
    for (const ip of p.network.ips.slice(0, 5)) {
      conditions.push(`    $e.target.ip = "${ip}"`);
    }
  }
  if (conditions.length === 0 && p.tools.length > 0) {
    const pattern = p.tools.slice(0, 6).map(t => escRegex(t)).join("|");
    conditions.push(`    re.regex($e.target.process.command_line, \`(?i)(${pattern})\`)`);
  }

  if (conditions.length > 1) {
    lines.push(`    (`);
    lines.push(conditions.join(" or\n"));
    lines.push(`    )`);
  } else if (conditions.length === 1) {
    lines.push(conditions[0]);
  }

  lines.push(`  condition: $e`);
  lines.push(`}`);
  return lines.join("\n");
}

function genYara(actor, p, severity) {
  const ruleName = `OptraSight_TAP_${actor.primary_name.replace(/[^A-Za-z0-9]/g, "_")}`;
  const lines = [];
  lines.push(`rule ${ruleName}`);
  lines.push(`{`);
  lines.push(`  meta:`);
  lines.push(`    author      = "OptraSight CTI"`);
  lines.push(`    description = "Detect artifacts associated with ${actor.primary_name} (${actor.actor_type})"`);
  lines.push(`    actor       = "${actor.primary_name}"`);
  lines.push(`    severity    = "${severity}"`);
  lines.push(`    generated   = "${new Date().toISOString()}"`);
  lines.push(`  strings:`);

  let strIdx = 1;
  const hashVars = [];
  const fileVars = [];
  const cmdVars = [];
  const domVars = [];
  const toolVars = [];

  for (const fn of p.host.filenames.slice(0, 15)) {
    const vn = `$file${strIdx++}`;
    lines.push(`    ${vn} = "${yaraEsc(fn)}" ascii nocase wide`);
    fileVars.push(vn);
  }
  for (const cmd of p.host.commands.slice(0, 10)) {
    const vn = `$cmd${strIdx++}`;
    lines.push(`    ${vn} = "${yaraEsc(cmd)}" ascii nocase`);
    cmdVars.push(vn);
  }
  for (const dom of p.network.domains.slice(0, 10)) {
    const vn = `$dom${strIdx++}`;
    lines.push(`    ${vn} = "${yaraEsc(dom)}" ascii nocase`);
    domVars.push(vn);
  }
  if (p.tools.length > 0 && fileVars.length === 0 && cmdVars.length === 0) {
    for (const t of p.tools.slice(0, 8)) {
      const vn = `$tool${strIdx++}`;
      lines.push(`    ${vn} = "${yaraEsc(t)}" ascii nocase wide`);
      toolVars.push(vn);
    }
  }

  const allVars = [...fileVars, ...cmdVars, ...domVars, ...hashVars, ...toolVars];
  lines.push(`  condition:`);
  if (allVars.length > 0) {
    if (p.hashes.sha256.length > 0) {
      const hashConds = p.hashes.sha256.slice(0, 5).map(h => {
        const upper = h.toUpperCase();
        const lower = h.toLowerCase();
        return `hash.sha256(0, filesize) == "${lower === upper ? lower : lower}"`;
      });
      lines.push(`    (${hashConds.join(" or ")})`);
      lines.push(`    or any of them`);
    } else {
      lines.push(`    any of them`);
    }
  } else if (p.hashes.sha256.length > 0) {
    const hashConds = p.hashes.sha256.slice(0, 10).map(h => `hash.sha256(0, filesize) == "${h.toLowerCase()}"`);
    lines.push(`    ${hashConds.join("\n    or ")}`);
  } else {
    lines.push(`    false`);
  }
  lines.push(`}`);
  return lines.join("\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN TRANSACTION
// ═══════════════════════════════════════════════════════════════════════════════

const tx = db.transaction(() => {
  const ts = now();
  const actors = db.prepare("SELECT * FROM threat_actors").all();
  const createdBy = db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").get()?.id || "system";

  let rulesCreated = 0;
  let linksCreated = 0;
  let skipped = 0;

  // Group actors by (tenant_id, primary_name) to avoid duplicates
  const seen = new Set();

  for (const actor of actors) {
    const key = `${actor.tenant_id}:${actor.primary_name}`;
    if (seen.has(key)) { skipped++; continue; }
    seen.add(key);

    const iocs = getActorIocs(actor.id, actor.tenant_id);
    if (iocs.length === 0) { skipped++; continue; }

    const ttps = getActorTtps(actor.id, actor.tenant_id);
    const tools = getActorTools(actor.id, actor.tenant_id);
    const p = partitionIocs(iocs);
    const severity = severityFromThreatLevel(actor.threat_level);

    // Check if a rule already exists for this actor in this tenant
    const existing = db.prepare(
      "SELECT rule_id FROM threat_actor_detection_rules WHERE tenant_id = ? AND actor_id = ?"
    ).get(actor.tenant_id, actor.id);
    if (existing) { skipped++; continue; }

    // Generate all query languages
    const queries = {};
    queries.splunk = genSplunk(actor, p, severity);
    queries.kql_elk = genKqlElk(actor, p);
    queries.defender = genDefender(actor, p);
    queries.crowdstrike = genCrowdstrike(actor, p);
    queries.cortex_xdr = genCortexXdr(actor, p);
    queries.chronicle = genChronicle(actor, p, severity);
    queries.yara = genYara(actor, p, severity);

    const sigmaYaml = genSigma(actor, p, ttps, severity, ts);

    const mitreTechs = mitreTechniquesJson(ttps);
    const affectedTech = [];
    if (p.network.domains.length > 0 || p.network.ips.length > 0) affectedTech.push("network");
    if (p.host.commands.length > 0 || p.host.filenames.length > 0) affectedTech.push("endpoint");
    if (p.host.regkeys.length > 0) affectedTech.push("windows");

    const ruleId = id();
    db.prepare(`INSERT INTO detection_rules
      (id, tenant_id, title, description, source_finding_ids, status, severity,
       mitre_techniques, affected_tech, threat_actors, sigma_yaml, queries,
       notes, version, ai_provider_label, created_at, updated_at, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        ruleId,
        actor.tenant_id,
        `${actor.primary_name} — Threat Actor IOC Hunt`,
        `Detect indicators of compromise associated with ${actor.primary_name} (${actor.actor_type}). Covers file hashes, network IOCs, command-line patterns, and tool signatures from sourced threat intelligence. Auto-generated from OptraSight TAP IOC database.`,
        j([]),
        "reviewed",
        severity,
        j(mitreTechs),
        j(affectedTech),
        j([actor.primary_name]),
        sigmaYaml,
        j(queries),
        `Auto-generated from ${iocs.length} IOCs and ${ttps.length} TTPs for ${actor.primary_name}. Review and tune thresholds before deployment. Tool-name matches may produce false positives in environments where these tools are used legitimately.`,
        1,
        "OptraSight CTI batch generation",
        ts,
        ts,
        createdBy,
      );

    // Create bridge link
    const priority = severity === "critical" ? "P1" : severity === "high" ? "P2" : "P3";
    db.prepare(`INSERT OR IGNORE INTO threat_actor_detection_rules
      (id, tenant_id, actor_id, rule_id, priority, notes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(id(), actor.tenant_id, actor.id, ruleId, priority, `Auto-linked: ${actor.primary_name} IOC hunt rule`, ts);

    // Audit log
    db.prepare("INSERT INTO audit_log (id, tenant_id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id(), actor.tenant_id, "system", "detection_rule.tap_generated", ruleId, j({
        source: "scripts/generate-tap-detection-rules.cjs",
        actor: actor.primary_name,
        iocCount: iocs.length,
        ttpCount: ttps.length,
        languages: Object.keys(queries),
      }), ts);

    rulesCreated++;
    linksCreated++;
  }

  return { rulesCreated, linksCreated, skipped };
});

const result = tx();
console.log(`Detection rule generation complete: created ${result.rulesCreated} rules, ${result.linksCreated} actor links, skipped ${result.skipped}. DB=${dbPath}`);
