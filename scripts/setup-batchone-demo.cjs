#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { randomBytes, randomUUID, scryptSync } = require("crypto");
const Database = require("better-sqlite3");

const ROOT = path.resolve(__dirname, "..");
const argv = process.argv.slice(2);
const force = argv.includes("--force");
const targetArg = argv.find((arg) => arg.startsWith("--target="));
const targetDb = path.resolve(ROOT, targetArg ? targetArg.slice("--target=".length) : "data.db");
const publicDir = path.join(ROOT, "data", "public");
const intelDbPath = path.join(publicDir, "optrasight-threat-intel-public.db");
const tapDbPath = path.join(publicDir, "optrasight-threat-actors-public.db");
const publicPortraitDir = path.join(publicDir, "portraits", "curated-source");
const publicRootPortraitDir = path.join(publicDir, "portraits", "root-style");
const runtimePortraitDir = path.join(ROOT, "data", "portraits", "curated-source");
const runtimeRootPortraitDir = path.join(ROOT, "data", "portraits");
const PORTRAIT_NAME_ALIASES = new Map([
  ["lazarus_group", "lazarus"],
  ["sandworm_team", "sandworm"],
]);

if (!fs.existsSync(intelDbPath) || !fs.existsSync(tapDbPath)) {
  console.error("[setup:batchone] Missing public DB exports under data/public/.");
  console.error("Run `npm run db:export-public` from a populated local workspace before packaging a release.");
  process.exit(2);
}

if (fs.existsSync(targetDb) && !force) {
  console.error(`[setup:batchone] Refusing to overwrite existing ${path.relative(ROOT, targetDb)}.`);
  console.error("Re-run with `npm run setup:batchone -- --force` to rebuild the local demo DB.");
  process.exit(2);
}

fs.mkdirSync(path.dirname(targetDb), { recursive: true });
if (force && fs.existsSync(targetDb)) fs.rmSync(targetDb);
for (const suffix of ["-wal", "-shm", "-journal"]) {
  const sidecar = `${targetDb}${suffix}`;
  if (force && fs.existsSync(sidecar)) fs.rmSync(sidecar);
}

const now = () => new Date().toISOString();
const j = (value) => JSON.stringify(value ?? null);
const id = () => randomUUID();

function hashPassword(password) {
  const salt = randomBytes(16).toString("base64url");
  const derived = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString("base64url");
  return `scrypt:v1:16384:8:1:${salt}:${derived}`;
}

function createRuntimeSchema(db) {
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, plan TEXT NOT NULL DEFAULT 'starter', created_at TEXT NOT NULL);
    CREATE TABLE tenant_scopes (
      tenant_id TEXT PRIMARY KEY,
      brand_keywords TEXT NOT NULL DEFAULT '[]',
      monitored_domains TEXT NOT NULL DEFAULT '[]',
      ip_ranges TEXT NOT NULL DEFAULT '[]',
      executive_emails TEXT NOT NULL DEFAULT '[]',
      client_types TEXT NOT NULL DEFAULT '[]',
      geos TEXT NOT NULL DEFAULT '[]',
      industries TEXT NOT NULL DEFAULT '[]',
      monitored_technologies TEXT NOT NULL DEFAULT '[]',
      notification_emails TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE users (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst',
      account_type TEXT NOT NULL DEFAULT 'platform', display_name TEXT,
      status TEXT NOT NULL DEFAULT 'active', password_must_change INTEGER NOT NULL DEFAULT 0,
      mfa_enabled INTEGER NOT NULL DEFAULT 0, mfa_secret_enc TEXT, mfa_verified_at TEXT,
      created_at TEXT, last_login_at TEXT, failed_login_count INTEGER NOT NULL DEFAULT 0,
      failed_mfa_count INTEGER NOT NULL DEFAULT 0, account_locked_until TEXT
    );
    CREATE TABLE auth_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, issued_at TEXT NOT NULL, last_used_at TEXT NOT NULL, revoked_at TEXT, access_mode TEXT NOT NULL DEFAULT 'credentialed');
    CREATE TABLE ai_providers (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, provider TEXT NOT NULL, label TEXT NOT NULL,
      model TEXT NOT NULL, base_url TEXT, api_key_enc TEXT, api_key_mask TEXT,
      enabled INTEGER NOT NULL DEFAULT 1, is_default INTEGER NOT NULL DEFAULT 0,
      last_tested_at TEXT, last_test_ok INTEGER, last_test_message TEXT,
      config TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE ai_task_assignments (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, task TEXT NOT NULL, provider_id TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(tenant_id, task));
    CREATE TABLE osint_sources (
      id TEXT PRIMARY KEY, category TEXT NOT NULL, name TEXT NOT NULL, url TEXT NOT NULL,
      language TEXT NOT NULL DEFAULT 'en', region TEXT, reliability TEXT NOT NULL DEFAULT 'B',
      enabled INTEGER NOT NULL DEFAULT 1, last_fetched_at TEXT
    );
    CREATE TABLE osint_findings (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL,
      title TEXT NOT NULL, url TEXT, published_at TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium', cve_ids TEXT NOT NULL DEFAULT '[]',
      affected_tech TEXT NOT NULL DEFAULT '[]', threat_actors TEXT NOT NULL DEFAULT '[]',
      summary TEXT, raw_snippet TEXT, ai_summary TEXT, ai_relevance_score INTEGER,
      ai_recommendation TEXT, ai_analyzed_at TEXT, ai_provider_label TEXT,
      draft_email TEXT, draft_email_at TEXT, status TEXT NOT NULL DEFAULT 'new',
      created_at TEXT NOT NULL, iocs TEXT NOT NULL DEFAULT '{}', content_hash TEXT,
      source_content TEXT, source_fetched_at TEXT, cirt_analysis TEXT, cirt_analyzed_at TEXT,
      cirt_provider_label TEXT, cirt_status TEXT NOT NULL DEFAULT 'pending',
      cirt_error TEXT, cirt_attempts INTEGER NOT NULL DEFAULT 0, cirt_next_attempt_at TEXT,
      analyst_tags TEXT NOT NULL DEFAULT '[]', analyst_edited_at TEXT, analyst_edited_by TEXT,
      intel_category TEXT, attack_techniques TEXT, sectors TEXT, regions TEXT, cluster_id TEXT
    );
    CREATE TABLE threat_actors (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, profile_id TEXT NOT NULL, primary_name TEXT NOT NULL,
      mitre_group_id TEXT, aliases TEXT NOT NULL DEFAULT '[]', vendor_names TEXT NOT NULL DEFAULT '{}',
      actor_type TEXT NOT NULL DEFAULT 'Unknown', sponsorship TEXT NOT NULL DEFAULT 'Unknown',
      assessed_origin TEXT, origin_confidence TEXT, sponsoring_entity TEXT, motivation TEXT NOT NULL DEFAULT '[]',
      active_since INTEGER, sophistication TEXT NOT NULL DEFAULT 'Intermediate', tlp TEXT NOT NULL DEFAULT 'AMBER',
      admiralty_source TEXT NOT NULL DEFAULT 'B', admiralty_info TEXT NOT NULL DEFAULT '2',
      wep_confidence TEXT NOT NULL DEFAULT 'Likely', target_sectors TEXT NOT NULL DEFAULT '[]',
      target_regions TEXT NOT NULL DEFAULT '[]', target_tech_stack TEXT NOT NULL DEFAULT '[]',
      org_size_preference TEXT, intent_proximity TEXT NOT NULL DEFAULT 'Opportunistic',
      relevance_rating TEXT, exec_what TEXT, exec_so_what TEXT, exec_what_now TEXT,
      threat_level TEXT NOT NULL DEFAULT 'MODERATE', threat_level_rationale TEXT,
      sector_actively_targeted INTEGER NOT NULL DEFAULT 0, diamond_adversary TEXT NOT NULL DEFAULT '{}',
      diamond_capability TEXT NOT NULL DEFAULT '{}', diamond_infrastructure TEXT NOT NULL DEFAULT '{}',
      diamond_victim TEXT NOT NULL DEFAULT '{}', diamond_meta TEXT NOT NULL DEFAULT '{}',
      business_impact TEXT NOT NULL DEFAULT '{}', capability_profile TEXT NOT NULL DEFAULT '{}',
      infrastructure_profile TEXT NOT NULL DEFAULT '{}', ir_actions TEXT NOT NULL DEFAULT '{}',
      countermeasures TEXT NOT NULL DEFAULT '{}', forecast TEXT, extortion_tactics TEXT NOT NULL DEFAULT '{}',
      body_md TEXT, status TEXT NOT NULL DEFAULT 'draft', version INTEGER NOT NULL DEFAULT 1,
      cutoff_date TEXT, prepared_by TEXT, ai_provider_label TEXT, portrait_url TEXT,
      portrait_generated_at TEXT, portrait_status TEXT NOT NULL DEFAULT 'idle',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by TEXT NOT NULL,
      UNIQUE(tenant_id, profile_id)
    );
    CREATE TABLE threat_actor_ttps (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL, tactic TEXT NOT NULL,
      technique_id TEXT NOT NULL, sub_technique_id TEXT, technique_name TEXT NOT NULL,
      evidence TEXT, status TEXT NOT NULL DEFAULT 'suspected', detection_priority TEXT NOT NULL DEFAULT 'P3',
      created_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_iocs (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL, ioc_type TEXT NOT NULL,
      value TEXT NOT NULL, first_seen TEXT, last_confirmed TEXT, confidence TEXT NOT NULL DEFAULT 'Likely',
      tlp TEXT NOT NULL DEFAULT 'AMBER', source TEXT, mitre_ttps TEXT NOT NULL DEFAULT '[]',
      recommended_action TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_campaigns (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL, name TEXT NOT NULL,
      period TEXT, target_sector TEXT, target_geography TEXT, initial_access TEXT, outcome TEXT,
      source_url TEXT, finding_ids TEXT NOT NULL DEFAULT '[]', rule_ids TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_references (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL, ref_num INTEGER NOT NULL,
      source_type TEXT, title TEXT NOT NULL, date TEXT, url TEXT, archive_url TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE threat_actor_tools (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL, name TEXT NOT NULL,
      category TEXT, purpose TEXT, variants TEXT NOT NULL DEFAULT '[]', hash_or_rule TEXT,
      confidence TEXT NOT NULL DEFAULT 'Likely', created_at TEXT NOT NULL
    );
    CREATE TABLE ai_jobs (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
      payload_json TEXT NOT NULL, result_json TEXT, error_json TEXT, provider_label TEXT,
      created_by TEXT, created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT,
      progress_pct INTEGER NOT NULL DEFAULT 0, target_label TEXT, target_url TEXT, heartbeat_at TEXT
    );
    CREATE TABLE audit_log (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
      target TEXT, detail TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
    );
    CREATE TABLE hunt_queries (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, title TEXT NOT NULL, description TEXT,
      source_finding_ids TEXT NOT NULL DEFAULT '[]', affected_tech TEXT NOT NULL DEFAULT '[]',
      queries TEXT NOT NULL DEFAULT '{}', ai_provider_label TEXT, created_at TEXT NOT NULL,
      created_by TEXT NOT NULL
    );
    CREATE INDEX idx_auth_sessions_user ON auth_sessions(user_id, revoked_at);
    CREATE INDEX idx_osint_sources_cat ON osint_sources(category);
    CREATE INDEX idx_osint_findings_tenant ON osint_findings(tenant_id);
    CREATE INDEX idx_osint_findings_intel_category ON osint_findings(tenant_id, intel_category);
    CREATE INDEX idx_threat_actors_tenant ON threat_actors(tenant_id, updated_at DESC);
    CREATE INDEX idx_threat_actor_ttps_actor ON threat_actor_ttps(actor_id);
    CREATE INDEX idx_threat_actor_iocs_actor ON threat_actor_iocs(actor_id);
    CREATE INDEX idx_ai_jobs_tenant_created ON ai_jobs(tenant_id, created_at DESC);
    CREATE INDEX idx_audit_tenant ON audit_log(tenant_id, created_at);
  `);
}

function seedWorkspace(db, tenantId, ts) {
  db.prepare("INSERT INTO tenants (id, name, slug, plan, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(tenantId, "BatchOne Demo Workspace", "batchone-demo", "batchone", ts);
  db.prepare(`
    INSERT INTO tenant_scopes (
      tenant_id, brand_keywords, monitored_domains, ip_ranges, executive_emails,
      client_types, geos, industries, monitored_technologies, notification_emails
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(tenantId, j(["optrasight", "batchone"]), j(["example.org"]), j([]), j([]), j(["Threat Intel"]), j(["Global"]), j(["security-operations"]), j(["osint", "threat-intelligence"]), j([]));

  const insertUser = db.prepare(`
    INSERT INTO users (
      id, tenant_id, email, password, role, account_type, display_name, status,
      password_must_change, mfa_enabled, mfa_secret_enc, mfa_verified_at,
      created_at, last_login_at, failed_login_count, failed_mfa_count, account_locked_until
    ) VALUES (?, ?, ?, ?, ?, 'platform', ?, 'active', 1, 0, NULL, NULL, ?, NULL, 0, 0, NULL)
  `);
  for (const user of [
    { email: "admin@cep.com", password: "ChangeMe!2026Admin", role: "admin", name: "Seed Platform Admin" },
    { email: "reviewer@cep.com", password: "ChangeMe!2026Review", role: "reviewer", name: "Seed Read-only Reviewer" },
  ]) {
    const uid = id();
    insertUser.run(uid, tenantId, user.email, hashPassword(user.password), user.role, user.name, ts);
  }

  const providers = [
    ["openai", "OpenAI", "gpt-4.1-mini"],
    ["anthropic", "Anthropic", "claude-sonnet-4-20250514"],
    ["gemini", "Google Gemini", "gemini-flash-latest"],
    ["perplexity", "Perplexity", "sonar-pro"],
    ["deepseek", "DeepSeek", "deepseek-chat"],
    ["kimi", "Kimi (Moonshot)", "moonshot-v1-128k"],
    ["ollama", "Ollama (local)", "llama3.1:8b"],
  ];
  const insertProvider = db.prepare(`
    INSERT INTO ai_providers (
      id, tenant_id, provider, label, model, base_url, api_key_enc, api_key_mask,
      enabled, is_default, last_tested_at, last_test_ok, last_test_message,
      config, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, '{}', ?, ?)
  `);
  for (const [provider, label, model] of providers) insertProvider.run(id(), tenantId, provider, label, model, ts, ts);
}

function importIntel(db, tenantId) {
  const sourceDb = new Database(intelDbPath, { readonly: true });
  const sources = sourceDb.prepare("SELECT * FROM osint_sources ORDER BY id").all();
  const findings = sourceDb.prepare("SELECT * FROM osint_findings_public ORDER BY published_at DESC, id").all();
  const insertSource = db.prepare("INSERT INTO osint_sources (id, category, name, url, language, region, reliability, enabled, last_fetched_at) VALUES (@id, @category, @name, @url, @language, @region, @reliability, @enabled, @last_fetched_at)");
  const insertFinding = db.prepare(`
    INSERT INTO osint_findings (
      id, tenant_id, source_id, title, url, published_at, severity, cve_ids,
      affected_tech, threat_actors, summary, raw_snippet, ai_summary,
      ai_relevance_score, ai_recommendation, ai_analyzed_at, ai_provider_label,
      draft_email, draft_email_at, status, created_at, iocs, content_hash,
      source_content, source_fetched_at, cirt_analysis, cirt_analyzed_at,
      cirt_provider_label, cirt_status, cirt_error, cirt_attempts,
      cirt_next_attempt_at, analyst_tags, analyst_edited_at, analyst_edited_by,
      intel_category, attack_techniques, sectors, regions, cluster_id
    ) VALUES (
      @id, @tenant_id, @source_id, @title, @url, @published_at, @severity, @cve_ids,
      @affected_tech, @threat_actors, @summary, @raw_snippet, @ai_summary,
      NULL, NULL, @ai_analyzed_at, @ai_provider_label,
      NULL, NULL, 'new', @created_at, @iocs, @content_hash,
      NULL, NULL, NULL, NULL,
      NULL, 'pending', NULL, 0,
      NULL, '[]', NULL, NULL,
      @intel_category, @attack_techniques, @sectors, @regions, @cluster_id
    )
  `);
  db.transaction(() => {
    for (const source of sources) insertSource.run(source);
    for (const finding of findings) insertFinding.run({ ...finding, tenant_id: tenantId });
  })();
  sourceDb.close();
  return { sources: sources.length, findings: findings.length };
}

function normalizeName(value) {
  return String(value || "").toLowerCase().replace(/&/g, "and").replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

function portraitUrlFor(name) {
  if (!fs.existsSync(publicPortraitDir)) return null;
  const files = fs.readdirSync(publicPortraitDir).filter((file) => file.toLowerCase().endsWith(".png"));
  const byNormalized = new Map(files.map((file) => [normalizeName(path.basename(file, ".png")), file]));
  const key = normalizeName(name);
  const file = byNormalized.get(key) || byNormalized.get(PORTRAIT_NAME_ALIASES.get(key));
  return file ? `/portraits/curated-source/${file}` : null;
}

function portraitUrlForProfile(profile) {
  const primaryUrl = portraitUrlFor(profile.primary_name);
  if (primaryUrl) return primaryUrl;
  for (const ext of ["webp", "png"]) {
    if (fs.existsSync(path.join(publicRootPortraitDir, `${profile.id}.${ext}`))) {
      return `/portraits/${profile.id}.${ext}`;
    }
  }
  return null;
}

function importTap(db, tenantId) {
  const sourceDb = new Database(tapDbPath, { readonly: true });
  const sourceProfiles = sourceDb.prepare("SELECT * FROM threat_actor_profiles ORDER BY profile_id, primary_name").all();
  const seenProfileIds = new Set();
  const profiles = [];
  const importedActorIds = new Set();
  for (const profile of sourceProfiles) {
    if (seenProfileIds.has(profile.profile_id)) continue;
    seenProfileIds.add(profile.profile_id);
    profiles.push(profile);
    importedActorIds.add(profile.id);
  }
  const ttps = sourceDb.prepare("SELECT * FROM threat_actor_ttps_public ORDER BY actor_id, technique_id").all();
  const iocs = sourceDb.prepare("SELECT * FROM threat_actor_iocs_public ORDER BY actor_id, ioc_type, value").all();
  const campaigns = sourceDb.prepare("SELECT * FROM threat_actor_campaigns_public ORDER BY actor_id, name").all();
  const refs = sourceDb.prepare("SELECT * FROM threat_actor_references_public ORDER BY actor_id, ref_num").all();
  const tools = sourceDb.prepare("SELECT * FROM threat_actor_tools_public ORDER BY actor_id, name").all();
  const insertProfile = db.prepare(`
    INSERT INTO threat_actors (
      id, tenant_id, profile_id, primary_name, mitre_group_id, aliases, vendor_names, actor_type,
      sponsorship, assessed_origin, origin_confidence, sponsoring_entity, motivation, active_since,
      sophistication, tlp, admiralty_source, admiralty_info, wep_confidence, target_sectors,
      target_regions, target_tech_stack, org_size_preference, intent_proximity, relevance_rating,
      exec_what, exec_so_what, exec_what_now, threat_level, threat_level_rationale,
      sector_actively_targeted, diamond_adversary, diamond_capability, diamond_infrastructure,
      diamond_victim, diamond_meta, business_impact, capability_profile, infrastructure_profile,
      ir_actions, countermeasures, forecast, extortion_tactics, body_md, status, version,
      cutoff_date, prepared_by, ai_provider_label, portrait_url, portrait_generated_at,
      portrait_status, created_at, updated_at, created_by
    ) VALUES (
      @id, @tenant_id, @profile_id, @primary_name, @mitre_group_id, @aliases, @vendor_names, @actor_type,
      @sponsorship, @assessed_origin, @origin_confidence, @sponsoring_entity, @motivation, @active_since,
      @sophistication, @tlp, @admiralty_source, @admiralty_info, @wep_confidence, @target_sectors,
      @target_regions, @target_tech_stack, @org_size_preference, @intent_proximity, NULL,
      @exec_what, @exec_so_what, @exec_what_now, @threat_level, @threat_level_rationale,
      0, @diamond_adversary, @diamond_capability, @diamond_infrastructure,
      @diamond_victim, @diamond_meta, @business_impact, @capability_profile, @infrastructure_profile,
      @ir_actions, @countermeasures, @forecast, @extortion_tactics, @body_md, @status, @version,
      @cutoff_date, 'OptraSight public seed', @ai_provider_label, @portrait_url, @portrait_generated_at,
      @portrait_status, @created_at, @updated_at, 'public-seed'
    )
  `);
  const insertTtp = db.prepare("INSERT INTO threat_actor_ttps (id, tenant_id, actor_id, tactic, technique_id, sub_technique_id, technique_name, evidence, status, detection_priority, created_at) VALUES (@id, @tenant_id, @actor_id, @tactic, @technique_id, @sub_technique_id, @technique_name, @evidence, @status, @detection_priority, @created_at)");
  const insertIoc = db.prepare("INSERT INTO threat_actor_iocs (id, tenant_id, actor_id, ioc_type, value, first_seen, last_confirmed, confidence, tlp, source, mitre_ttps, recommended_action, created_at) VALUES (@id, @tenant_id, @actor_id, @ioc_type, @value, @first_seen, @last_confirmed, @confidence, @tlp, @source, @mitre_ttps, @recommended_action, @created_at)");
  const insertCampaign = db.prepare("INSERT INTO threat_actor_campaigns (id, tenant_id, actor_id, name, period, target_sector, target_geography, initial_access, outcome, source_url, finding_ids, rule_ids, created_at) VALUES (@id, @tenant_id, @actor_id, @name, @period, @target_sector, @target_geography, @initial_access, @outcome, @source_url, '[]', '[]', @created_at)");
  const insertRef = db.prepare("INSERT INTO threat_actor_references (id, tenant_id, actor_id, ref_num, source_type, title, date, url, archive_url, created_at) VALUES (@id, @tenant_id, @actor_id, @ref_num, @source_type, @title, @date, @url, @archive_url, @created_at)");
  const insertTool = db.prepare("INSERT INTO threat_actor_tools (id, tenant_id, actor_id, name, category, purpose, variants, hash_or_rule, confidence, created_at) VALUES (@id, @tenant_id, @actor_id, @name, @category, @purpose, @variants, @hash_or_rule, @confidence, @created_at)");
  db.transaction(() => {
    for (const profile of profiles) {
      const portraitUrl = portraitUrlForProfile(profile);
      insertProfile.run({ ...profile, tenant_id: tenantId, portrait_url: portraitUrl, portrait_generated_at: portraitUrl ? profile.updated_at : null, portrait_status: portraitUrl ? "ready" : "idle" });
    }
    for (const row of ttps) if (importedActorIds.has(row.actor_id)) insertTtp.run({ ...row, tenant_id: tenantId });
    for (const row of iocs) if (importedActorIds.has(row.actor_id)) insertIoc.run({ ...row, tenant_id: tenantId });
    for (const row of campaigns) if (importedActorIds.has(row.actor_id)) insertCampaign.run({ ...row, tenant_id: tenantId });
    for (const row of refs) if (importedActorIds.has(row.actor_id)) insertRef.run({ ...row, tenant_id: tenantId });
    for (const row of tools) if (importedActorIds.has(row.actor_id)) insertTool.run({ ...row, tenant_id: tenantId });
  })();
  sourceDb.close();
  const portraitCount = db.prepare("SELECT COUNT(*) AS count FROM threat_actors WHERE portrait_url IS NOT NULL").get().count;
  return {
    profiles: profiles.length,
    duplicateProfilesSkipped: sourceProfiles.length - profiles.length,
    ttps: ttps.filter((row) => importedActorIds.has(row.actor_id)).length,
    iocs: iocs.filter((row) => importedActorIds.has(row.actor_id)).length,
    campaigns: campaigns.filter((row) => importedActorIds.has(row.actor_id)).length,
    refs: refs.filter((row) => importedActorIds.has(row.actor_id)).length,
    tools: tools.filter((row) => importedActorIds.has(row.actor_id)).length,
    portraits: portraitCount,
  };
}

function restorePortraitFiles() {
  let restored = 0;
  if (fs.existsSync(publicRootPortraitDir)) {
    fs.mkdirSync(runtimeRootPortraitDir, { recursive: true });
    const files = fs.readdirSync(publicRootPortraitDir).filter((file) => /\.(png|webp)$/i.test(file));
    for (const file of files) {
      fs.copyFileSync(path.join(publicRootPortraitDir, file), path.join(runtimeRootPortraitDir, file));
      restored++;
    }
  }
  if (fs.existsSync(publicPortraitDir)) {
    fs.mkdirSync(runtimePortraitDir, { recursive: true });
    const files = fs.readdirSync(publicPortraitDir).filter((file) => file.toLowerCase().endsWith(".png"));
    for (const file of files) {
      fs.copyFileSync(path.join(publicPortraitDir, file), path.join(runtimePortraitDir, file));
      restored++;
    }
  }
  return restored;
}

const db = new Database(targetDb);
const ts = now();
const tenantId = "tenant-batchone-demo";
createRuntimeSchema(db);
seedWorkspace(db, tenantId, ts);
const intel = importIntel(db, tenantId);
const tap = importTap(db, tenantId);
const portraits = restorePortraitFiles();
const missingPortraits = db.prepare(`
  SELECT profile_id, primary_name
    FROM threat_actors
   WHERE portrait_url IS NULL OR portrait_url = ''
   ORDER BY profile_id
`).all();
db.prepare("INSERT INTO audit_log (id, tenant_id, actor, action, target, detail, created_at) VALUES (?, ?, 'setup:batchone', 'public_demo_restore', 'data.db', ?, ?)")
  .run(id(), tenantId, j({ intel, tap, portraits, missingPortraits: missingPortraits.length }), ts);
db.pragma("wal_checkpoint(TRUNCATE)");
db.close();

console.log(`[setup:batchone] wrote ${path.relative(ROOT, targetDb)}`);
console.log(`[setup:batchone] sources=${intel.sources} findings=${intel.findings}`);
console.log(`[setup:batchone] tap_profiles=${tap.profiles} portraits_linked=${tap.portraits} portrait_files=${portraits}`);
if (missingPortraits.length) {
  console.log(`[setup:batchone] portraits_missing=${missingPortraits.length} (${missingPortraits.slice(0, 12).map((r) => `${r.profile_id}:${r.primary_name}`).join(", ")}${missingPortraits.length > 12 ? ", ..." : ""})`);
}
console.log("[setup:batchone] seed users: admin@cep.com / ChangeMe!2026Admin, reviewer@cep.com / ChangeMe!2026Review");
console.log("[setup:batchone] first login must rotate password and enroll MFA.");
