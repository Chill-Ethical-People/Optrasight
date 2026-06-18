#!/usr/bin/env node
/*
 * Export OptraSight runtime data into GitHub-safe public databases plus a
 * private client workspace database.
 *
 * Public outputs intentionally remove tenant ids, client scope, analyst
 * annotations, provider secrets, sessions, jobs, reports, investigations,
 * detection deployments, and exercise participants.
 */
const Database = require("better-sqlite3");
const { existsSync, mkdirSync, rmSync } = require("node:fs");
const path = require("node:path");

const ROOT = process.cwd();
const sourceArg = process.argv[2];
const sourcePath = path.resolve(ROOT, sourceArg || (existsSync("data.db") ? "data.db" : "data/data.db"));
const publicDir = path.resolve(ROOT, "data", "public");
const privateDir = path.resolve(ROOT, "data", "private");
const threatIntelPath = path.join(publicDir, "optrasight-threat-intel-public.db");
const threatActorsPath = path.join(publicDir, "optrasight-threat-actors-public.db");
const privateWorkspacePath = path.join(privateDir, "optrasight-client-workspace-private.db");

if (!existsSync(sourcePath)) {
  console.error(`[export-public-dbs] source DB not found: ${sourcePath}`);
  process.exit(1);
}

mkdirSync(publicDir, { recursive: true });
mkdirSync(privateDir, { recursive: true });

for (const out of [threatIntelPath, threatActorsPath, privateWorkspacePath]) {
  if (existsSync(out)) rmSync(out);
  for (const suffix of ["-wal", "-shm", "-journal"]) {
    const sidecar = `${out}${suffix}`;
    if (existsSync(sidecar)) rmSync(sidecar);
  }
}

const source = new Database(sourcePath, { readonly: true });
const exportedAt = new Date().toISOString();

function hasTable(db, table) {
  return Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table));
}

function tableSql(db, table) {
  return db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?").get(table)?.sql || null;
}

function q(name) {
  return `"${String(name).replaceAll('"', '""')}"`;
}

function createManifest(db, kind) {
  db.exec(`
    CREATE TABLE export_manifest (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
  const insert = db.prepare("INSERT INTO export_manifest (key, value) VALUES (?, ?)");
  insert.run("kind", kind);
  insert.run("source_basename", path.basename(sourcePath));
  insert.run("exported_at", exportedAt);
  insert.run("privacy_model", "public databases strip tenant/client identifiers and analyst/provider operational fields; private workspace output is ignored by git");
}

function insertRows(db, table, columns, rows) {
  if (!rows.length) return 0;
  const marks = columns.map(() => "?").join(", ");
  const stmt = db.prepare(`INSERT INTO ${q(table)} (${columns.map(q).join(", ")}) VALUES (${marks})`);
  const tx = db.transaction((items) => {
    for (const row of items) stmt.run(...columns.map((c) => row[c]));
  });
  tx(rows);
  return rows.length;
}

function jsonValue(value, fallback) {
  if (value == null || value === "") return fallback;
  try {
    const parsed = JSON.parse(value);
    return JSON.stringify(parsed);
  } catch {
    return fallback;
  }
}

function normalizeText(value) {
  return String(value || "").trim().toLowerCase();
}

function exportThreatIntel() {
  const db = new Database(threatIntelPath);
  db.pragma("journal_mode = DELETE");
  createManifest(db, "public_threat_intel");
  db.exec(`
    CREATE TABLE osint_sources (
      id TEXT PRIMARY KEY,
      category TEXT NOT NULL,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      language TEXT NOT NULL DEFAULT 'en',
      region TEXT,
      reliability TEXT NOT NULL DEFAULT 'B',
      enabled INTEGER NOT NULL DEFAULT 1,
      last_fetched_at TEXT
    );

    CREATE TABLE osint_findings_public (
      id TEXT PRIMARY KEY,
      source_id TEXT NOT NULL,
      title TEXT NOT NULL,
      url TEXT,
      published_at TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium',
      cve_ids TEXT NOT NULL DEFAULT '[]',
      affected_tech TEXT NOT NULL DEFAULT '[]',
      threat_actors TEXT NOT NULL DEFAULT '[]',
      intel_category TEXT,
      attack_techniques TEXT,
      sectors TEXT,
      regions TEXT,
      cluster_id TEXT,
      iocs TEXT NOT NULL DEFAULT '{}',
      content_hash TEXT,
      summary TEXT,
      raw_snippet TEXT,
      ai_summary TEXT,
      ai_analyzed_at TEXT,
      ai_provider_label TEXT,
      source_fetched_at TEXT,
      cirt_analysis TEXT,
      cirt_analyzed_at TEXT,
      cirt_provider_label TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX idx_public_osint_published ON osint_findings_public(published_at DESC);
    CREATE INDEX idx_public_osint_source ON osint_findings_public(source_id);
    CREATE INDEX idx_public_osint_hash ON osint_findings_public(content_hash);
  `);

  let sourceCount = 0;
  if (hasTable(source, "osint_sources")) {
    const rows = source.prepare("SELECT * FROM osint_sources ORDER BY category, name").all();
    sourceCount = insertRows(db, "osint_sources", [
      "id", "category", "name", "url", "language", "region", "reliability", "enabled", "last_fetched_at",
    ], rows);
  }

  let findingCount = 0;
  if (hasTable(source, "osint_findings")) {
    const rawRows = source.prepare(`
      SELECT
        id, source_id, title, url, published_at, severity, cve_ids, affected_tech,
        threat_actors, intel_category, attack_techniques, sectors, regions,
        cluster_id, iocs, content_hash, summary, raw_snippet, ai_summary,
        ai_analyzed_at, ai_provider_label, NULL AS source_fetched_at, NULL AS cirt_analysis,
        NULL AS cirt_analyzed_at, NULL AS cirt_provider_label, created_at
      FROM osint_findings
      WHERE COALESCE(intel_category, 'threat_intel') != 'advertisement'
      ORDER BY published_at DESC, created_at DESC
    `).all();

    const seen = new Set();
    const rows = [];
    for (const row of rawRows) {
      const key = normalizeText(row.content_hash || row.url || `${row.title}|${row.published_at}`);
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({
        ...row,
        cve_ids: jsonValue(row.cve_ids, "[]"),
        affected_tech: jsonValue(row.affected_tech, "[]"),
        threat_actors: jsonValue(row.threat_actors, "[]"),
        attack_techniques: row.attack_techniques ? jsonValue(row.attack_techniques, "[]") : null,
        sectors: row.sectors ? jsonValue(row.sectors, "[]") : null,
        regions: row.regions ? jsonValue(row.regions, "[]") : null,
        iocs: jsonValue(row.iocs, "{}"),
      });
    }
    findingCount = insertRows(db, "osint_findings_public", [
      "id", "source_id", "title", "url", "published_at", "severity",
      "cve_ids", "affected_tech", "threat_actors", "intel_category",
      "attack_techniques", "sectors", "regions", "cluster_id", "iocs",
      "content_hash", "summary", "raw_snippet", "ai_summary", "ai_analyzed_at",
      "ai_provider_label", "source_fetched_at", "cirt_analysis",
      "cirt_analyzed_at", "cirt_provider_label", "created_at",
    ], rows);
  }

  db.prepare("INSERT INTO export_manifest (key, value) VALUES (?, ?)").run("osint_sources_count", String(sourceCount));
  db.prepare("INSERT INTO export_manifest (key, value) VALUES (?, ?)").run("osint_findings_public_count", String(findingCount));
  db.close();
  return { sourceCount, findingCount };
}

function actorRank(actor) {
  const statusRank = { approved: 4, reviewed: 3, draft: 2, archived: 1 };
  return statusRank[actor.status] || 0;
}

function exportThreatActors() {
  const db = new Database(threatActorsPath);
  db.pragma("journal_mode = DELETE");
  createManifest(db, "public_threat_actors");
  db.exec(`
    CREATE TABLE threat_actor_profiles (
      id TEXT PRIMARY KEY,
      profile_id TEXT NOT NULL,
      primary_name TEXT NOT NULL,
      mitre_group_id TEXT,
      aliases TEXT NOT NULL DEFAULT '[]',
      vendor_names TEXT NOT NULL DEFAULT '{}',
      actor_type TEXT NOT NULL DEFAULT 'Unknown',
      sponsorship TEXT NOT NULL DEFAULT 'Unknown',
      assessed_origin TEXT,
      origin_confidence TEXT,
      sponsoring_entity TEXT,
      motivation TEXT NOT NULL DEFAULT '[]',
      active_since INTEGER,
      sophistication TEXT NOT NULL DEFAULT 'Intermediate',
      tlp TEXT NOT NULL DEFAULT 'AMBER',
      admiralty_source TEXT NOT NULL DEFAULT 'B',
      admiralty_info TEXT NOT NULL DEFAULT '2',
      wep_confidence TEXT NOT NULL DEFAULT 'Likely',
      target_sectors TEXT NOT NULL DEFAULT '[]',
      target_regions TEXT NOT NULL DEFAULT '[]',
      target_tech_stack TEXT NOT NULL DEFAULT '[]',
      org_size_preference TEXT,
      intent_proximity TEXT NOT NULL DEFAULT 'Opportunistic',
      exec_what TEXT,
      exec_so_what TEXT,
      exec_what_now TEXT,
      threat_level TEXT NOT NULL DEFAULT 'MODERATE',
      threat_level_rationale TEXT,
      diamond_adversary TEXT NOT NULL DEFAULT '{}',
      diamond_capability TEXT NOT NULL DEFAULT '{}',
      diamond_infrastructure TEXT NOT NULL DEFAULT '{}',
      diamond_victim TEXT NOT NULL DEFAULT '{}',
      diamond_meta TEXT NOT NULL DEFAULT '{}',
      business_impact TEXT NOT NULL DEFAULT '{}',
      capability_profile TEXT NOT NULL DEFAULT '{}',
      infrastructure_profile TEXT NOT NULL DEFAULT '{}',
      ir_actions TEXT NOT NULL DEFAULT '{}',
      countermeasures TEXT NOT NULL DEFAULT '{}',
      forecast TEXT,
      extortion_tactics TEXT NOT NULL DEFAULT '{}',
      body_md TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      version INTEGER NOT NULL DEFAULT 1,
      cutoff_date TEXT,
      ai_provider_label TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_ttps_public (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      tactic TEXT NOT NULL,
      technique_id TEXT NOT NULL,
      sub_technique_id TEXT,
      technique_name TEXT NOT NULL,
      evidence TEXT,
      status TEXT NOT NULL DEFAULT 'suspected',
      detection_priority TEXT NOT NULL DEFAULT 'P3',
      created_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_tools_public (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT,
      purpose TEXT,
      variants TEXT NOT NULL DEFAULT '[]',
      hash_or_rule TEXT,
      confidence TEXT NOT NULL DEFAULT 'Likely',
      created_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_campaigns_public (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      name TEXT NOT NULL,
      period TEXT,
      target_sector TEXT,
      target_geography TEXT,
      initial_access TEXT,
      outcome TEXT,
      source_url TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_iocs_public (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      ioc_type TEXT NOT NULL,
      value TEXT NOT NULL,
      first_seen TEXT,
      last_confirmed TEXT,
      confidence TEXT NOT NULL DEFAULT 'Likely',
      tlp TEXT NOT NULL DEFAULT 'AMBER',
      source TEXT,
      mitre_ttps TEXT NOT NULL DEFAULT '[]',
      recommended_action TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_references_public (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      ref_num INTEGER NOT NULL,
      source_type TEXT,
      title TEXT NOT NULL,
      date TEXT,
      url TEXT,
      archive_url TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX idx_public_tap_name ON threat_actor_profiles(primary_name);
    CREATE INDEX idx_public_ttp_actor ON threat_actor_ttps_public(actor_id);
    CREATE INDEX idx_public_ioc_actor ON threat_actor_iocs_public(actor_id);
  `);

  if (!hasTable(source, "threat_actors")) {
    db.close();
    return { actorCount: 0 };
  }

  const rawActors = source.prepare("SELECT * FROM threat_actors ORDER BY updated_at DESC").all();
  const best = new Map();
  for (const actor of rawActors) {
    const key = normalizeText(actor.mitre_group_id || actor.primary_name);
    const existing = best.get(key);
    if (!existing || actorRank(actor) > actorRank(existing) || String(actor.updated_at || "") > String(existing.updated_at || "")) {
      best.set(key, actor);
    }
  }
  const actors = Array.from(best.values()).sort((a, b) => normalizeText(a.primary_name).localeCompare(normalizeText(b.primary_name)));
  const actorIds = new Set(actors.map((a) => a.id));

  const actorColumns = [
    "id", "profile_id", "primary_name", "mitre_group_id", "aliases", "vendor_names",
    "actor_type", "sponsorship", "assessed_origin", "origin_confidence",
    "sponsoring_entity", "motivation", "active_since", "sophistication",
    "tlp", "admiralty_source", "admiralty_info", "wep_confidence",
    "target_sectors", "target_regions", "target_tech_stack",
    "org_size_preference", "intent_proximity", "exec_what", "exec_so_what",
    "exec_what_now", "threat_level", "threat_level_rationale",
    "diamond_adversary", "diamond_capability", "diamond_infrastructure",
    "diamond_victim", "diamond_meta", "business_impact", "capability_profile",
    "infrastructure_profile", "ir_actions", "countermeasures", "forecast",
    "extortion_tactics", "body_md", "status", "version", "cutoff_date",
    "ai_provider_label", "created_at", "updated_at",
  ];
  const actorCount = insertRows(db, "threat_actor_profiles", actorColumns, actors.map((a) => ({
    ...a,
    aliases: jsonValue(a.aliases, "[]"),
    vendor_names: jsonValue(a.vendor_names, "{}"),
    motivation: jsonValue(a.motivation, "[]"),
    target_sectors: jsonValue(a.target_sectors, "[]"),
    target_regions: jsonValue(a.target_regions, "[]"),
    target_tech_stack: jsonValue(a.target_tech_stack, "[]"),
    diamond_adversary: jsonValue(a.diamond_adversary, "{}"),
    diamond_capability: jsonValue(a.diamond_capability, "{}"),
    diamond_infrastructure: jsonValue(a.diamond_infrastructure, "{}"),
    diamond_victim: jsonValue(a.diamond_victim, "{}"),
    diamond_meta: jsonValue(a.diamond_meta, "{}"),
    business_impact: jsonValue(a.business_impact, "{}"),
    capability_profile: jsonValue(a.capability_profile, "{}"),
    infrastructure_profile: jsonValue(a.infrastructure_profile, "{}"),
    ir_actions: jsonValue(a.ir_actions, "{}"),
    countermeasures: jsonValue(a.countermeasures, "{}"),
    extortion_tactics: jsonValue(a.extortion_tactics, "{}"),
  })));

  function childRows(table, orderBy) {
    if (!hasTable(source, table)) return [];
    return source.prepare(`SELECT * FROM ${q(table)} ORDER BY ${orderBy}`).all().filter((r) => actorIds.has(r.actor_id));
  }

  const ttpCount = insertRows(db, "threat_actor_ttps_public", [
    "id", "actor_id", "tactic", "technique_id", "sub_technique_id",
    "technique_name", "evidence", "status", "detection_priority", "created_at",
  ], childRows("threat_actor_ttps", "actor_id, tactic, technique_id"));
  const toolCount = insertRows(db, "threat_actor_tools_public", [
    "id", "actor_id", "name", "category", "purpose", "variants",
    "hash_or_rule", "confidence", "created_at",
  ], childRows("threat_actor_tools", "actor_id, name").map((r) => ({ ...r, variants: jsonValue(r.variants, "[]") })));
  const campaignCount = insertRows(db, "threat_actor_campaigns_public", [
    "id", "actor_id", "name", "period", "target_sector", "target_geography",
    "initial_access", "outcome", "source_url", "created_at",
  ], childRows("threat_actor_campaigns", "actor_id, period DESC, created_at DESC"));
  const iocCount = insertRows(db, "threat_actor_iocs_public", [
    "id", "actor_id", "ioc_type", "value", "first_seen", "last_confirmed",
    "confidence", "tlp", "source", "mitre_ttps", "recommended_action", "created_at",
  ], childRows("threat_actor_iocs", "actor_id, ioc_type, value").map((r) => ({ ...r, mitre_ttps: jsonValue(r.mitre_ttps, "[]") })));
  const refCount = insertRows(db, "threat_actor_references_public", [
    "id", "actor_id", "ref_num", "source_type", "title", "date", "url",
    "archive_url", "created_at",
  ], childRows("threat_actor_references", "actor_id, ref_num"));

  const manifest = db.prepare("INSERT INTO export_manifest (key, value) VALUES (?, ?)");
  manifest.run("threat_actor_profiles_count", String(actorCount));
  manifest.run("threat_actor_ttps_public_count", String(ttpCount));
  manifest.run("threat_actor_tools_public_count", String(toolCount));
  manifest.run("threat_actor_campaigns_public_count", String(campaignCount));
  manifest.run("threat_actor_iocs_public_count", String(iocCount));
  manifest.run("threat_actor_references_public_count", String(refCount));
  db.close();
  return { actorCount, ttpCount, toolCount, campaignCount, iocCount, refCount };
}

function copyPrivateTable(target, table) {
  const sql = tableSql(source, table);
  if (!sql) return 0;
  target.exec(sql);
  const rows = source.prepare(`SELECT * FROM ${q(table)}`).all();
  if (!rows.length) return 0;
  return insertRows(target, table, Object.keys(rows[0]), rows);
}

function exportPrivateWorkspace() {
  const db = new Database(privateWorkspacePath);
  db.pragma("journal_mode = DELETE");
  createManifest(db, "private_client_workspace");
  const tables = [
    "tenants", "tenant_scopes", "users", "auth_sessions",
    "client_assets", "assets", "scans", "findings", "evidence", "integrations",
    "ai_providers", "ai_task_assignments", "ai_jobs", "tenant_osint_settings",
    "osint_reanalyze_jobs", "osint_findings", "hunt_queries", "threat_landscapes",
    "detection_rules", "rule_deployments", "reports", "investigations",
    "investigation_links", "investigation_notes", "exercises", "exercise_injects",
    "exercise_roles", "exercise_participants", "exercise_events",
    "threat_actor_tenants", "threat_actor_detection_rules",
  ];
  const manifest = db.prepare("INSERT INTO export_manifest (key, value) VALUES (?, ?)");
  let totalRows = 0;
  for (const table of tables) {
    const count = copyPrivateTable(db, table);
    totalRows += count;
    if (count > 0 || hasTable(source, table)) manifest.run(`${table}_count`, String(count));
  }
  manifest.run("total_private_rows", String(totalRows));
  db.close();
  return { totalRows };
}

const intel = exportThreatIntel();
const actors = exportThreatActors();
const privateWorkspace = exportPrivateWorkspace();
source.close();

console.log(`[export-public-dbs] source: ${sourcePath}`);
console.log(`[export-public-dbs] public threat intel: ${threatIntelPath} (${intel.sourceCount} sources, ${intel.findingCount} findings)`);
console.log(`[export-public-dbs] public threat actors: ${threatActorsPath} (${actors.actorCount} actors, ${actors.ttpCount || 0} TTPs, ${actors.iocCount || 0} IOCs)`);
console.log(`[export-public-dbs] private client workspace: ${privateWorkspacePath} (${privateWorkspace.totalRows} rows, git-ignored)`);
