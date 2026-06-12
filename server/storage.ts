import {
  tenants, tenantScopes, users, aiProviders, aiTaskAssignments,
  osintSources as osintSourcesTbl,
  auditLog as auditLogTbl,
  type ThreatActorDTO, type ThreatActorFullDTO,
  type ThreatActorTtpDTO, type ThreatActorToolDTO,
  type ThreatActorCampaignDTO, type ThreatActorIocDTO,
  type ThreatActorReferenceDTO, type ThreatActorRuleLinkDTO,
  type ThreatActorTenantDTO, type TenantRelevance,
  type ActorType, type SponsorshipLevel, type TlpLevel, type ThreatLevel,
  type IntentProximity, type WepConfidence, type SophisticationLevel,
  type AdmiraltySource, type AdmiraltyInfo, type IocType, type TtpStatus,
  type DetectionPriority, type TapStatus,
  type Tenant, type User,
  type AiProvider,
  type AiProviderSummary,
  type AiTask, type AiProviderKind,
  type OsintSource,
  type AuditLogEntry,
  type OsintFindingDTO, type HuntQueryDTO, type ThreatLandscapeDTO,
  type DetectionRuleDTO, type RuleDeploymentDTO, type DeploymentMode, type DeploymentStatus,
  type RuleStatus, type RuleSeverity, type SiemTargetId, SIEM_TARGETS, SIEM_TARGET_IDS,
  type SearchResultDTO,
  MONITORED_TECHNOLOGIES,
  OSINT_CATEGORY_LABELS, OSINT_CATEGORY_ORDER, OSINT_OVERVIEW_PERSONAS, type OsintOverviewPersona,
  type OsintSourceRowDTO, type OsintOverviewResultDTO,
} from "@shared/schema";
import { drizzle } from "drizzle-orm/better-sqlite3";
import Database from "better-sqlite3";
import { createCipheriv, createDecipheriv, createHash, createHmac, scryptSync, timingSafeEqual } from "node:crypto";
import { and, desc, eq, like } from "drizzle-orm";
import { randomUUID, randomBytes } from "node:crypto";
import { isStrictProduction, MockFallbackBlockedError } from "./productionMode";
import { dispatchAi, testProvider as testAiProviderImpl } from "./aiClient";
import { isSecurityPublisherHost } from "./iocPublisherBlocklist";
import { fetchSourcesBatch } from "./sourceFetch";
import { OSINT_SOURCES, REMOVED_OSINT_SOURCE_IDS } from "./osintSeed";
import { ensureClusterIdPersisted, backfillClusters } from "./osintClustering";
import { secretStore } from "./secretStore";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const sqlite = new Database("data.db");
sqlite.pragma("journal_mode = WAL");
export const db = drizzle(sqlite);

const AI_PROVIDER_SECRET = "ai_provider";

// ---------- bootstrap ----------
function ensureSchema() {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
      plan TEXT NOT NULL DEFAULT 'starter', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tenant_scopes (
      tenant_id TEXT PRIMARY KEY,
      brand_keywords TEXT NOT NULL DEFAULT '[]',
      monitored_domains TEXT NOT NULL DEFAULT '[]',
      ip_ranges TEXT NOT NULL DEFAULT '[]',
      executive_emails TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'threat_intel_expert',
      account_type TEXT NOT NULL DEFAULT 'platform',
      display_name TEXT, status TEXT NOT NULL DEFAULT 'active',
      password_must_change INTEGER NOT NULL DEFAULT 0,
      mfa_enabled INTEGER NOT NULL DEFAULT 0,
      mfa_secret_enc TEXT,
      mfa_verified_at TEXT,
      failed_login_count INTEGER NOT NULL DEFAULT 0,
      failed_mfa_count INTEGER NOT NULL DEFAULT 0,
      account_locked_until TEXT,
      created_at TEXT, last_login_at TEXT
    );
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      access_mode TEXT NOT NULL DEFAULT 'credentialed',
      issued_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL,
      revoked_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id, revoked_at);
    CREATE TABLE IF NOT EXISTS ai_providers (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      label TEXT NOT NULL,
      model TEXT NOT NULL,
      base_url TEXT,
      api_key_enc TEXT,
      api_key_mask TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      is_default INTEGER NOT NULL DEFAULT 0,
      last_tested_at TEXT,
      last_test_ok INTEGER,
      last_test_message TEXT,
      config TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ai_task_assignments (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      task TEXT NOT NULL,
      provider_id TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(tenant_id, task)
    );
    CREATE TABLE IF NOT EXISTS osint_sources (
      id TEXT PRIMARY KEY, category TEXT NOT NULL, name TEXT NOT NULL,
      url TEXT NOT NULL, language TEXT NOT NULL DEFAULT 'en', region TEXT,
      reliability TEXT NOT NULL DEFAULT 'B', enabled INTEGER NOT NULL DEFAULT 1,
      last_fetched_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_osint_sources_cat ON osint_sources(category);
    CREATE TABLE IF NOT EXISTS osint_findings (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL,
      title TEXT NOT NULL, url TEXT, published_at TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium',
      cve_ids TEXT NOT NULL DEFAULT '[]',
      affected_tech TEXT NOT NULL DEFAULT '[]',
      threat_actors TEXT NOT NULL DEFAULT '[]',
      summary TEXT, raw_snippet TEXT,
      ai_summary TEXT, ai_relevance_score INTEGER,
      ai_recommendation TEXT, ai_analyzed_at TEXT, ai_provider_label TEXT,
      draft_email TEXT, draft_email_at TEXT,
      status TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_osint_findings_tenant ON osint_findings(tenant_id);
    CREATE TABLE IF NOT EXISTS hunt_queries (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      title TEXT NOT NULL, description TEXT,
      source_finding_ids TEXT NOT NULL DEFAULT '[]',
      affected_tech TEXT NOT NULL DEFAULT '[]',
      queries TEXT NOT NULL DEFAULT '{}',
      ai_provider_label TEXT,
      created_at TEXT NOT NULL, created_by TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS threat_landscapes (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'generating',
      body_md TEXT,
      stats TEXT NOT NULL DEFAULT '{}',
      ai_provider_label TEXT,
      created_at TEXT NOT NULL, created_by TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT,
      detail TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, created_at);
    -- v2.30.2 — Detection Rule Studio
    CREATE TABLE IF NOT EXISTS detection_rules (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      title TEXT NOT NULL, description TEXT,
      source_finding_ids TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'draft',
      severity TEXT NOT NULL DEFAULT 'medium',
      mitre_techniques TEXT NOT NULL DEFAULT '[]',
      affected_tech TEXT NOT NULL DEFAULT '[]',
      threat_actors TEXT NOT NULL DEFAULT '[]',
      sigma_yaml TEXT,
      queries TEXT NOT NULL DEFAULT '{}',
      notes TEXT,
      version INTEGER NOT NULL DEFAULT 1,
      ai_provider_label TEXT,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_detection_rules_tenant ON detection_rules(tenant_id, updated_at DESC);
    CREATE TABLE IF NOT EXISTS rule_deployments (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      rule_id TEXT NOT NULL, siem_id TEXT NOT NULL,
      mode TEXT NOT NULL DEFAULT 'manual',
      status TEXT NOT NULL DEFAULT 'pending',
      external_id TEXT, message TEXT,
      rule_version INTEGER NOT NULL DEFAULT 1,
      deployed_at TEXT, deployed_by TEXT,
      updated_at TEXT NOT NULL,
      UNIQUE(tenant_id, rule_id, siem_id)
    );
    CREATE INDEX IF NOT EXISTS idx_rule_deployments_rule ON rule_deployments(tenant_id, rule_id);
    -- v2.30.3 — Threat Actor Profiles (TAP). Header + body in threat_actors;
    -- sub-resources (TTPs, tools, campaigns, IoCs, references, rule links)
    -- in dedicated tables for structured querying.
    CREATE TABLE IF NOT EXISTS threat_actors (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      profile_id TEXT NOT NULL,
      primary_name TEXT NOT NULL,
      mitre_group_id TEXT,
      aliases TEXT NOT NULL DEFAULT '[]',
      vendor_names TEXT NOT NULL DEFAULT '{}',
      actor_type TEXT NOT NULL DEFAULT 'Unknown',
      sponsorship TEXT NOT NULL DEFAULT 'Unknown',
      assessed_origin TEXT, origin_confidence TEXT, sponsoring_entity TEXT,
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
      relevance_rating TEXT,
      exec_what TEXT, exec_so_what TEXT, exec_what_now TEXT,
      threat_level TEXT NOT NULL DEFAULT 'MODERATE',
      threat_level_rationale TEXT,
      sector_actively_targeted INTEGER NOT NULL DEFAULT 0,
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
      cutoff_date TEXT, prepared_by TEXT,
      ai_provider_label TEXT,
      portrait_url TEXT,
      portrait_generated_at TEXT,
      portrait_status TEXT NOT NULL DEFAULT 'idle',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by TEXT NOT NULL,
      UNIQUE(tenant_id, profile_id)
    );
    CREATE INDEX IF NOT EXISTS idx_threat_actors_tenant ON threat_actors(tenant_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_threat_actors_primary_name ON threat_actors(tenant_id, primary_name);
    CREATE TABLE IF NOT EXISTS threat_actor_ttps (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
      tactic TEXT NOT NULL, technique_id TEXT NOT NULL,
      sub_technique_id TEXT, technique_name TEXT NOT NULL,
      evidence TEXT,
      status TEXT NOT NULL DEFAULT 'suspected',
      detection_priority TEXT NOT NULL DEFAULT 'P3',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_threat_actor_ttps_actor ON threat_actor_ttps(actor_id);
    CREATE TABLE IF NOT EXISTS threat_actor_tools (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
      name TEXT NOT NULL, category TEXT, purpose TEXT,
      variants TEXT NOT NULL DEFAULT '[]',
      hash_or_rule TEXT,
      confidence TEXT NOT NULL DEFAULT 'Likely',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_threat_actor_tools_actor ON threat_actor_tools(actor_id);
    CREATE TABLE IF NOT EXISTS threat_actor_campaigns (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
      name TEXT NOT NULL, period TEXT,
      target_sector TEXT, target_geography TEXT, initial_access TEXT, outcome TEXT,
      source_url TEXT,
      finding_ids TEXT NOT NULL DEFAULT '[]',
      rule_ids TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_threat_actor_campaigns_actor ON threat_actor_campaigns(actor_id);
    CREATE TABLE IF NOT EXISTS threat_actor_iocs (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
      ioc_type TEXT NOT NULL, value TEXT NOT NULL,
      first_seen TEXT, last_confirmed TEXT,
      confidence TEXT NOT NULL DEFAULT 'Likely',
      tlp TEXT NOT NULL DEFAULT 'AMBER',
      source TEXT,
      mitre_ttps TEXT NOT NULL DEFAULT '[]',
      recommended_action TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_threat_actor_iocs_actor ON threat_actor_iocs(actor_id);
    CREATE INDEX IF NOT EXISTS idx_threat_actor_iocs_value ON threat_actor_iocs(tenant_id, ioc_type, value);
    CREATE TABLE IF NOT EXISTS threat_actor_references (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
      ref_num INTEGER NOT NULL,
      source_type TEXT, title TEXT NOT NULL,
      date TEXT, url TEXT, archive_url TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_threat_actor_refs_actor ON threat_actor_references(actor_id);
    CREATE TABLE IF NOT EXISTS threat_actor_detection_rules (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      priority TEXT NOT NULL DEFAULT 'P3',
      notes TEXT,
      created_at TEXT NOT NULL,
      UNIQUE(tenant_id, actor_id, rule_id)
    );
    CREATE INDEX IF NOT EXISTS idx_threat_actor_rule_links_actor ON threat_actor_detection_rules(actor_id);
    -- v2.30.5 — cross-tenant relevance tagging on a TAP.
    -- owner_tenant_id = tenant whose TAP this is (the actor's tenant);
    -- tenant_id       = the tagged client tenant.
    CREATE TABLE IF NOT EXISTS threat_actor_tenants (
      id TEXT PRIMARY KEY,
      owner_tenant_id TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      relevance TEXT NOT NULL DEFAULT 'watching',
      rationale TEXT,
      tagged_by TEXT,
      tagged_by_ai INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      UNIQUE(actor_id, tenant_id)
    );
    CREATE INDEX IF NOT EXISTS idx_threat_actor_tenants_actor ON threat_actor_tenants(actor_id);
    CREATE INDEX IF NOT EXISTS idx_threat_actor_tenants_tenant ON threat_actor_tenants(tenant_id);
  `);
  // ALTER tenant_scopes for v2.4 + osint_findings for v2.8 — wrapped per-column
  // so re-runs are idempotent.
  const alters: string[] = [
    `ALTER TABLE tenant_scopes ADD COLUMN client_types TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE tenant_scopes ADD COLUMN geos TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE tenant_scopes ADD COLUMN industries TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE tenant_scopes ADD COLUMN monitored_technologies TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE tenant_scopes ADD COLUMN notification_emails TEXT NOT NULL DEFAULT '[]'`,
    // Internal account lifecycle and MFA enforcement.
    `ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'platform'`,
    `ALTER TABLE users ADD COLUMN display_name TEXT`,
    `ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'`,
    `ALTER TABLE users ADD COLUMN password_must_change INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN mfa_secret_enc TEXT`,
    `ALTER TABLE users ADD COLUMN mfa_verified_at TEXT`,
    `ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN failed_mfa_count INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN account_locked_until TEXT`,
    `ALTER TABLE users ADD COLUMN created_at TEXT`,
    `ALTER TABLE users ADD COLUMN last_login_at TEXT`,
    `ALTER TABLE auth_sessions ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'credentialed'`,
    // v2.8 — IoC parsing + cross-source dedupe.
    `ALTER TABLE osint_findings ADD COLUMN iocs TEXT NOT NULL DEFAULT '{}'`,
    `ALTER TABLE osint_findings ADD COLUMN content_hash TEXT`,
    // v2.16 — per-finding source-content cache + CIRT deep-dive cache.
    // The background analyzer fills these so deep-dive can return instantly
    // for already-analyzed findings instead of running a 60-120s live AI call.
    `ALTER TABLE osint_findings ADD COLUMN source_content TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN source_fetched_at TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN cirt_analysis TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN cirt_analyzed_at TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN cirt_provider_label TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN cirt_status TEXT NOT NULL DEFAULT 'pending'`,
    `ALTER TABLE osint_findings ADD COLUMN cirt_error TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN cirt_attempts INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE osint_findings ADD COLUMN cirt_next_attempt_at TEXT`,
    // v2.17 — analyst overrides + free-form tags on each finding.
    `ALTER TABLE osint_findings ADD COLUMN analyst_tags TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE osint_findings ADD COLUMN analyst_edited_at TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN analyst_edited_by TEXT`,
    // v2.29 — AI categorisation of the intel item.
    //   threat_intel  — actionable threat advisory / incident report
    //   regular_report — quarterly landscape / vendor M-Trends-style review
    //   advertisement — product marketing / vendor promo / sponsored post
    // Nullable so unanalysed rows stay null.
    `ALTER TABLE osint_findings ADD COLUMN intel_category TEXT`,
    // v2.30 — deeper analytics signals. All nullable.
    //   attack_techniques  : JSON [{id, name?, tactic?}]
    //   sectors            : JSON [string]
    //   regions            : JSON [string]
    //   cluster_id         : TEXT — rule-based dedup cluster id
    `ALTER TABLE osint_findings ADD COLUMN attack_techniques TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN sectors TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN regions TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN cluster_id TEXT`,
    // v2.32 — AI-generated portrait per threat actor (lazy fire on first card view).
    //   portrait_url           : relative path under /portraits/… served as static
    //   portrait_generated_at  : ISO timestamp of successful generation
    //   portrait_status        : idle | generating | ready | failed
    `ALTER TABLE threat_actors ADD COLUMN portrait_url TEXT`,
    `ALTER TABLE threat_actors ADD COLUMN portrait_generated_at TEXT`,
    `ALTER TABLE threat_actors ADD COLUMN portrait_status TEXT NOT NULL DEFAULT 'idle'`,
  ];
  for (const stmt of alters) {
    try { sqlite.exec(stmt); } catch { /* column already exists */ }
  }
  sqlite.prepare(`
    UPDATE users
       SET account_type = 'platform'
     WHERE COALESCE(account_type, '') NOT IN ('client', 'platform')
  `).run();

  // v2.16 — tenant-level background-job settings + indexes for the analyzer
  // queue. Idempotent.
  // v2.30 — cluster index for dedup analytics.
  sqlite.exec(`
    CREATE INDEX IF NOT EXISTS idx_osint_findings_cluster_id
      ON osint_findings(tenant_id, cluster_id);
    CREATE INDEX IF NOT EXISTS idx_osint_findings_intel_category
      ON osint_findings(tenant_id, intel_category);
  `);

  // v2.30 — bulk re-analyse job table for admin-triggered backfill.
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS osint_reanalyze_jobs (
      id TEXT PRIMARY KEY,
      tenant_id TEXT,
      status TEXT NOT NULL DEFAULT 'queued',
      total_count INTEGER NOT NULL DEFAULT 0,
      done_count INTEGER NOT NULL DEFAULT 0,
      fail_count INTEGER NOT NULL DEFAULT 0,
      started_at TEXT NOT NULL,
      finished_at TEXT,
      error TEXT
    );
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS tenant_osint_settings (
      tenant_id TEXT PRIMARY KEY,
      auto_fetch_enabled INTEGER NOT NULL DEFAULT 0,
      fetch_interval_min INTEGER NOT NULL DEFAULT 60,
      auto_analyze_enabled INTEGER NOT NULL DEFAULT 0,
      analyze_concurrency INTEGER NOT NULL DEFAULT 2,
      analyze_max_per_tick INTEGER NOT NULL DEFAULT 8,
      last_fetch_at TEXT,
      last_fetch_count INTEGER,
      last_fetch_error TEXT,
      last_analyze_at TEXT,
      last_analyze_ok_count INTEGER NOT NULL DEFAULT 0,
      last_analyze_fail_count INTEGER NOT NULL DEFAULT 0,
      last_analyze_error TEXT,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_osint_findings_cirt_status
      ON osint_findings(tenant_id, cirt_status, cirt_next_attempt_at);
  `);

  // v2.27 — generic async-AI job queue. Long-running model calls (chat/triage,
  // chat/deep-dive) now run server-side and the UI polls this table by id,
  // which sidesteps the ~100s edge-proxy timeout that was killing browser
  // fetches and turning real DeepSeek responses into "Failed to fetch".
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS ai_jobs (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      result_json TEXT,
      error_json TEXT,
      provider_label TEXT,
      created_by TEXT,
      created_at TEXT NOT NULL,
      started_at TEXT,
      completed_at TEXT,
      progress_pct INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_ai_jobs_tenant_created
      ON ai_jobs(tenant_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_ai_jobs_status
      ON ai_jobs(status, created_at);
  `);

  // v2.30.5 — add target_label / target_url to ai_jobs so the global notification
  // tray can show a human-readable name and a deep-link for each running /
  // completed job (e.g. "TAP-005 Mustang Panda" → "/#/threat-actors?focus=<id>").
  // Wrapped per-column so re-runs on an existing DB are idempotent.
  const aiJobAlters: string[] = [
    `ALTER TABLE ai_jobs ADD COLUMN target_label TEXT`,
    `ALTER TABLE ai_jobs ADD COLUMN target_url TEXT`,
    `ALTER TABLE ai_jobs ADD COLUMN heartbeat_at TEXT`,
  ];
  for (const stmt of aiJobAlters) {
    try { sqlite.exec(stmt); } catch (e: any) {
      if (!/duplicate column/i.test(String(e?.message ?? ""))) throw e;
    }
  }
}

function migrateCredentialSecretsOutOfPublicDb(): void {
  const migratedAi = sqlite.transaction(() => {
    const rows = sqlite.prepare(`
      SELECT id, tenant_id AS tenantId, api_key_enc AS apiKeyEnc
      FROM ai_providers
      WHERE api_key_enc IS NOT NULL AND api_key_enc != ''
    `).all() as Array<{ id: string; tenantId: string; apiKeyEnc: string }>;
    const clear = sqlite.prepare("UPDATE ai_providers SET api_key_enc = NULL WHERE id = ?");
    for (const row of rows) {
      secretStore.setSecret(row.tenantId, AI_PROVIDER_SECRET, row.id, "api_key", row.apiKeyEnc);
      clear.run(row.id);
    }
    return rows.length;
  })();

  if (migratedAi) {
    console.log(`[secrets] migrated ${migratedAi} AI provider key(s) out of public DB`);
  }
}

const DATA_DIR = resolve(process.cwd(), "data");
try { mkdirSync(DATA_DIR, { recursive: true }); } catch { /* fs perms */ }

function loadKek(): Buffer {
  const env = process.env.OPTRASIGHT_KEY_ENCRYPTION_KEY || process.env.OPTRASIGHT_KEK;
  if (env) {
    const raw = /^[A-Za-z0-9+/=]{43,}$/.test(env) ? Buffer.from(env, "base64") : Buffer.from(env, "utf8");
    return createHash("sha256").update(raw).digest();
  }
  const keyPath = join(DATA_DIR, ".optrasight-kek");
  try {
    if (existsSync(keyPath)) {
      const v = readFileSync(keyPath, "utf8").trim();
      if (v) return Buffer.from(v, "base64");
    }
    const key = randomBytes(32);
    writeFileSync(keyPath, key.toString("base64"), { mode: 0o600 });
    try { chmodSync(keyPath, 0o600); } catch { /* best-effort */ }
    return key;
  } catch {
    return createHash("sha256").update(`optrasight-local-${process.cwd()}`).digest();
  }
}

const KEK = loadKek();
const enc = (s: string) => {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", KEK, iv);
  const ciphertext = Buffer.concat([cipher.update(s, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${ciphertext.toString("base64")}`;
};
const dec = (s: string | null | undefined) => {
  if (!s) return null;
  try {
    if (s.startsWith("v1:")) {
      const [, ivB64, tagB64, bodyB64] = s.split(":");
      const decipher = createDecipheriv("aes-256-gcm", KEK, Buffer.from(ivB64, "base64"));
      decipher.setAuthTag(Buffer.from(tagB64, "base64"));
      return Buffer.concat([decipher.update(Buffer.from(bodyB64, "base64")), decipher.final()]).toString("utf8");
    }
    return Buffer.from(s, "base64").toString("utf8");
  } catch { return null; }
};
const mask = (s: string) =>
  s.length <= 4 ? "•".repeat(s.length) : "•".repeat(Math.max(4, s.length - 4)) + s.slice(-4);

const PASSWORD_PREFIX = "scrypt:v1";
function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("base64url");
  const derived = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString("base64url");
  return `${PASSWORD_PREFIX}:16384:8:1:${salt}:${derived}`;
}

function verifyPassword(candidate: string, stored: string): { ok: boolean; needsRehash: boolean } {
  if (!stored.startsWith(`${PASSWORD_PREFIX}:`)) {
    return { ok: stored === candidate, needsRehash: stored === candidate };
  }
  const parts = stored.split(":");
  if (parts.length !== 7) return { ok: false, needsRehash: false };
  const [, , nRaw, rRaw, pRaw, salt, hash] = parts;
  const n = Number(nRaw);
  const r = Number(rRaw);
  const pValue = Number(pRaw);
  if (!Number.isFinite(n) || !Number.isFinite(r) || !Number.isFinite(pValue)) {
    return { ok: false, needsRehash: false };
  }
  try {
    const expected = Buffer.from(hash, "base64url");
    const actual = scryptSync(candidate, salt, expected.length, { N: n, r, p: pValue });
    return { ok: expected.length === actual.length && timingSafeEqual(expected, actual), needsRehash: false };
  } catch {
    return { ok: false, needsRehash: false };
  }
}

const DUMMY_PASSWORD_HASH = hashPassword("optrasight-absent-user-timing-equalizer");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buf: Buffer): string {
  let bits = "";
  let out = "";
  for (const byte of buf) bits += byte.toString(2).padStart(8, "0");
  for (let i = 0; i < bits.length; i += 5) {
    out += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  }
  return out;
}

function base32Decode(value: string): Buffer {
  const normalized = value.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const ch of normalized) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx >= 0) bits += idx.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totpCode(secretBase32: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32Decode(secretBase32)).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

function verifyTotp(secretBase32: string | null | undefined, code: string | null | undefined): boolean {
  if (!secretBase32 || !code || !/^\d{6}$/.test(code)) return false;
  const step = Math.floor(Date.now() / 30_000);
  return [-1, 0, 1].some((delta) => totpCode(secretBase32, step + delta) === code);
}

function newMfaSecret(): string {
  return base32Encode(randomBytes(20));
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function issueSession(userId: string, accessMode: "credentialed" | "guest" = "credentialed"): string {
  const token = randomBytes(32).toString("base64url");
  const ts = now();
  sqlite.prepare(`
    INSERT INTO auth_sessions (token_hash, user_id, access_mode, issued_at, last_used_at, revoked_at)
    VALUES (?, ?, ?, ?, ?, NULL)
  `).run(tokenHash(token), userId, accessMode, ts, ts);
  return token;
}

export const SESSION_ABSOLUTE_MS = Number(process.env.OPTRASIGHT_SESSION_ABSOLUTE_MS || 24 * 60 * 60 * 1000);
export const SESSION_IDLE_TIMEOUT_MS = Number(process.env.OPTRASIGHT_SESSION_IDLE_MS || 12 * 60 * 60 * 1000);
export const ADMIN_SESSION_ABSOLUTE_MS = Number(process.env.OPTRASIGHT_ADMIN_SESSION_ABSOLUTE_MS || 12 * 60 * 60 * 1000);
export const ADMIN_SESSION_IDLE_TIMEOUT_MS = Number(process.env.OPTRASIGHT_ADMIN_SESSION_IDLE_MS || 60 * 60 * 1000);
const SESSION_IDLE_TOUCH_MS = Number(process.env.OPTRASIGHT_SESSION_TOUCH_MS || 5 * 60 * 1000);
const AUTH_LOCK_THRESHOLD = Number(process.env.OPTRASIGHT_AUTH_LOCK_THRESHOLD || 5);
const AUTH_LOCK_MS = Number(process.env.OPTRASIGHT_AUTH_LOCK_MS || 15 * 60 * 1000);

function shouldTouchSession(lastUsedAt: string | null | undefined): boolean {
  if (!lastUsedAt) return true;
  const lastUsedMs = Date.parse(lastUsedAt);
  if (!Number.isFinite(lastUsedMs)) return true;
  return Date.now() - lastUsedMs >= SESSION_IDLE_TOUCH_MS;
}

export function sessionExpiryReason(
  session: { issuedAt?: string | null; lastUsedAt?: string | null; role?: string | null; accessMode?: string | null },
  nowMs = Date.now(),
): "absolute" | "idle" | null {
  const issuedMs = Date.parse(session.issuedAt || "");
  const lastUsedMs = Date.parse(session.lastUsedAt || "");
  const adminSession = session.role === "admin" && session.accessMode !== "guest";
  const absoluteMs = adminSession ? ADMIN_SESSION_ABSOLUTE_MS : SESSION_ABSOLUTE_MS;
  const idleMs = adminSession ? ADMIN_SESSION_IDLE_TIMEOUT_MS : SESSION_IDLE_TIMEOUT_MS;
  if (!Number.isFinite(issuedMs) || nowMs - issuedMs >= absoluteMs) return "absolute";
  if (!Number.isFinite(lastUsedMs) || nowMs - lastUsedMs >= idleMs) return "idle";
  return null;
}

function userLockedUntil(user: Pick<User, "accountLockedUntil">): string | null {
  const lockedUntil = (user as any).accountLockedUntil ?? null;
  if (!lockedUntil) return null;
  const lockedMs = Date.parse(lockedUntil);
  if (!Number.isFinite(lockedMs) || lockedMs <= Date.now()) return null;
  return lockedUntil;
}

function recordAuthFailure(uid: string, kind: "login" | "mfa"): void {
  const col = kind === "login" ? "failed_login_count" : "failed_mfa_count";
  const row = sqlite.prepare(`SELECT COALESCE(${col}, 0) AS n FROM users WHERE id = ?`).get(uid) as { n: number } | undefined;
  const next = Number(row?.n || 0) + 1;
  const lockedUntil = next >= AUTH_LOCK_THRESHOLD
    ? new Date(Date.now() + AUTH_LOCK_MS).toISOString()
    : null;
  sqlite.prepare(`
    UPDATE users
    SET ${col} = ?,
        account_locked_until = COALESCE(?, account_locked_until)
    WHERE id = ?
  `).run(next, lockedUntil, uid);
}

function clearAuthFailures(uid: string): void {
  sqlite.prepare(`
    UPDATE users
    SET failed_login_count = 0,
        failed_mfa_count = 0,
        account_locked_until = NULL
    WHERE id = ?
  `).run(uid);
}

function accessModeForRole(role: string): "credentialed" | "guest" {
  return role === "reviewer" ? "guest" : "credentialed";
}

function aiProviderSecret(
  row: Pick<AiProvider, "tenantId" | "id" | "apiKeyEnc"> | null | undefined,
): string | null {
  if (!row) return null;
  return secretStore.getSecret(row.tenantId, AI_PROVIDER_SECRET, row.id, "api_key") ?? row.apiKeyEnc ?? null;
}

function hydrateAiProviderSecret<T extends AiProvider | null | undefined>(row: T): T {
  if (!row) return row;
  return { ...row, apiKeyEnc: aiProviderSecret(row) } as T;
}

function aiProviderHasSecret(row: Pick<AiProvider, "tenantId" | "id" | "apiKeyEnc"> | null | undefined): boolean {
  return !!aiProviderSecret(row);
}

// ---------- helpers ----------
const j = (v: unknown) => JSON.stringify(v ?? []);
const p = <T = any>(v: string | null | undefined, d: T): T => {
  if (!v) return d;
  try { return JSON.parse(v) as T; } catch { return d; }
};
const now = () => new Date().toISOString();
const id = () => randomUUID();

const BATCH_ONE_WORKSPACE_PROFILE = {
  clientTypes: ["Threat Intelligence"],
  geos: ["Global"],
  industries: ["security-operations"],
  monitoredTechnologies: ["osint", "threat-intelligence", "detection-engineering"],
};
const BATCH_ONE_AI_CONTEXT = {
  industries: BATCH_ONE_WORKSPACE_PROFILE.industries,
  geos: BATCH_ONE_WORKSPACE_PROFILE.geos,
  monitoredTechnologies: BATCH_ONE_WORKSPACE_PROFILE.monitoredTechnologies,
};

/** v2.30 — safe JSON parse helpers for the new analytics columns. Defensive
 *  because the columns are nullable and may contain legacy nulls/empties from
 *  the v2.29 era. Never throws. */
function parseJsonArray<T = unknown>(raw: unknown): T[] | null {
  if (raw == null || raw === "") return null;
  try {
    const v = JSON.parse(String(raw));
    return Array.isArray(v) ? (v as T[]) : null;
  } catch { return null; }
}
function parseAttackTechniques(raw: unknown): Array<{ id: string; name?: string; tactic?: string }> | null {
  const arr = parseJsonArray<any>(raw);
  if (!arr) return null;
  return arr
    .map((x) => {
      if (typeof x === "string") return { id: x };
      if (x && typeof x === "object" && typeof x.id === "string") return x as any;
      return null;
    })
    .filter((x): x is { id: string; name?: string; tactic?: string } => !!x);
}

// ---------- seeding ----------
const SEED_TENANTS = [
  {
    name: "BatchOne Workspace", slug: "batchone-workspace",
    keywords: ["optrasight", "batchone", "threat-intel"],
    domains: ["example.org"],
    ipRanges: ["203.0.113.0/24"],
    profile: {
      clientTypes: ["Threat Intel"],
      geos: ["Global"],
      industries: ["security-operations"],
      monitoredTechnologies: ["osint", "threat-intelligence", "detection-engineering"],
    },
  },
];

const BLOCKED_INITIAL_PASSWORD_SHA256 = new Set([
  "ec62f5d9f10bb6ab56516e28978e1a5e1bfe2ffc40f3b0cc990efc49f9ce621b",
  "833126ae95cdb91fe9e83ec1944bdbc7a73bfb36c861f71e9464423f8062ac91",
]);

function isBlockedInitialPassword(value: string): boolean {
  const digest = createHash("sha256").update(value, "utf8").digest("hex");
  return BLOCKED_INITIAL_PASSWORD_SHA256.has(digest);
}

function seedAiProvidersIfEmpty(tenantId: string) {
  const existing = db.select().from(aiProviders).where(eq(aiProviders.tenantId, tenantId)).all();
  if (existing.length) return;
  const seedSpec = [
    { provider: "openai" as AiProviderKind,        label: "OpenAI",          model: "gpt-4.1-mini" },
    { provider: "anthropic" as AiProviderKind,     label: "Anthropic",       model: "claude-sonnet-4-20250514" },
    { provider: "gemini" as AiProviderKind,        label: "Google Gemini",   model: "gemini-flash-latest" },
    { provider: "perplexity" as AiProviderKind,    label: "Perplexity",      model: "sonar-pro" },
    { provider: "deepseek" as AiProviderKind,      label: "DeepSeek",        model: "deepseek-chat" },
    { provider: "kimi" as AiProviderKind,          label: "Kimi (Moonshot)", model: "moonshot-v1-128k" },
    { provider: "ollama" as AiProviderKind,        label: "Ollama (local)",  model: "llama3.1:8b" },
  ];
  for (const p of seedSpec) {
    const pid = id();
    db.insert(aiProviders).values({
      id: pid, tenantId, provider: p.provider, label: p.label, model: p.model,
      baseUrl: null,
      apiKeyEnc: null,
      apiKeyMask: null,
      enabled: 0, isDefault: 0,
      lastTestedAt: null, lastTestOk: null, lastTestMessage: null,
      config: "{}", createdAt: now(), updatedAt: now(),
    }).run();
  }
}

function seedOsintSourcesIfEmpty() {
  const upsert = sqlite.prepare(`
    INSERT INTO osint_sources (id, category, name, url, language, region, reliability, enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    ON CONFLICT(id) DO UPDATE SET
      category = excluded.category,
      name = excluded.name,
      url = excluded.url,
      language = excluded.language,
      region = excluded.region,
      reliability = excluded.reliability
  `);
  const tx = sqlite.transaction((rows: typeof OSINT_SOURCES) => {
    for (const s of rows) upsert.run(s.id, s.category, s.name, s.url, s.language ?? "en", s.region ?? null, s.reliability ?? "B");
    const keep = rows.map((s) => s.id);
    if (keep.length > 0) {
      const placeholders = keep.map(() => "?").join(",");
      sqlite.prepare(`
        DELETE FROM osint_sources
        WHERE id NOT IN (${placeholders})
          AND id NOT IN (SELECT DISTINCT source_id FROM osint_findings)
      `).run(...keep);
    }
    if (REMOVED_OSINT_SOURCE_IDS.length > 0) {
      const removedPlaceholders = REMOVED_OSINT_SOURCE_IDS.map(() => "?").join(",");
      sqlite.prepare(`DELETE FROM osint_sources WHERE id IN (${removedPlaceholders})`).run(...REMOVED_OSINT_SOURCE_IDS);
    }
  });
  tx(OSINT_SOURCES);
}

function seedIfEmpty() {
  const existing = db.select().from(tenants).all();
  if (existing.length) return;

  let firstTenantId: string | null = null;
  for (const s of SEED_TENANTS) {
    const tid = id();
    if (!firstTenantId) firstTenantId = tid;
    db.insert(tenants).values({
      id: tid, name: s.name, slug: s.slug, plan: "pro", createdAt: now(),
    }).run();
    db.insert(tenantScopes).values({
      tenantId: tid, brandKeywords: j(s.keywords),
      monitoredDomains: j(s.domains), ipRanges: j(s.ipRanges),
      executiveEmails: j([]),
    }).run();
    // seed AI providers per tenant (so the AI Setup page is pre-populated)
    seedAiProvidersIfEmpty(tid);

    // Seed minimal workspace context for legacy rows that still carry scope
    // columns. BatchOne does not expose client profile matching or switching.
    if (s.profile) {
      const profilePayload: Record<string, string> = {
        clientTypes: j(s.profile.clientTypes ?? []),
        geos: j(s.profile.geos ?? []),
        industries: j(s.profile.industries ?? []),
        monitoredTechnologies: j(s.profile.monitoredTechnologies ?? []),
      };
      const existingScope = db.select().from(tenantScopes).where(eq(tenantScopes.tenantId, tid)).get();
      if (existingScope) {
        db.update(tenantScopes).set(profilePayload as any).where(eq(tenantScopes.tenantId, tid)).run();
      } else {
        db.insert(tenantScopes).values({ tenantId: tid, ...(profilePayload as any) }).run();
      }
    }
  }

  // Platform admin seed account for local BatchOne administration.
  if (firstTenantId) {
    db.insert(users).values({
      id: id(), tenantId: firstTenantId,
      email: "admin@cep.com", password: hashPassword("ChangeMe!2026Admin"), role: "admin",
      accountType: "platform",
      displayName: "Seed Platform Admin",
      status: "active",
      passwordMustChange: false,
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaVerifiedAt: null,
      createdAt: now(),
      lastLoginAt: null,
    }).run();
  }
}

function platformUserForBatchOne<T extends Omit<User, "password"> & {
  tenantName?: string | null; tenantSlug?: string | null; tenantPlan?: string | null;
}>(row: T): T {
  return row;
}

function revokeUserSessions(uid: string): void {
  sqlite.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").run(now(), uid);
}

function ensurePlatformSeedUsers() {
  const firstTenant = db.select().from(tenants).all()[0];
  if (!firstTenant) return;
  const seeds = [
    { email: "admin@cep.com", password: "ChangeMe!2026Admin", role: "admin", displayName: "Seed Platform Admin" },
    { email: "reviewer@cep.com", password: "ChangeMe!2026Review", role: "reviewer", displayName: "Seed Read-only Reviewer" },
  ];
  for (const seed of seeds) {
    const existing = db.select().from(users).where(eq(users.email, seed.email)).get();
    if (existing) continue;
    const uid = id();
    db.insert(users).values({
      id: uid,
      tenantId: firstTenant.id,
      email: seed.email,
      password: hashPassword(seed.password),
      role: seed.role,
      accountType: "platform",
      displayName: seed.displayName,
      status: "active",
      passwordMustChange: false,
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaVerifiedAt: null,
      createdAt: now(),
      lastLoginAt: null,
    }).run();
  }
}

ensureSchema();
migrateCredentialSecretsOutOfPublicDb();
seedOsintSourcesIfEmpty();
seedIfEmpty();
ensurePlatformSeedUsers();

// v2.30 — Startup backfill of cluster_id for findings published within the
// last 30 days that don't yet have one. Bounded by limit (10000) and a
// hard time budget; runs asynchronously so server start is never blocked.
// Errors are swallowed — clustering is a best-effort signal.
setTimeout(() => {
  try {
    const sinceIso = new Date(Date.now() - 30 * 86400_000).toISOString();
    const { scanned, assigned } = backfillClusters(sqlite, { sinceIso, limit: 10000 });
    if (scanned > 0) {
      console.log(`[cluster] startup backfill: scanned=${scanned} assigned=${assigned}`);
    }
  } catch (e) {
    console.warn("[cluster] startup backfill failed", e);
  }
}, 5000);

// v2.30.3 — Startup backfill of Threat Actor Profiles (TAP). Walks every
// tenant once and inserts a shell TAP for any distinct threat-actor name
// referenced by an osint_finding or detection_rule that doesn't already have
// one. Idempotent — second boot is a no-op. Runs deferred so server start is
// never blocked, and errors are swallowed because TAP shells are best-effort.
setTimeout(() => {
  try {
    const tids = sqlite.prepare("SELECT id FROM tenants").all() as { id: string }[];
    let total = 0;
    for (const { id: tid } of tids) {
      try {
        total += storage.backfillThreatActorsFromExistingData(tid, { createdBy: "system" });
      } catch (e) { console.warn(`[tap] backfill failed for tenant ${tid}`, e); }
    }
    if (total > 0) console.log(`[tap] startup backfill: inserted ${total} shell threat-actor profiles`);
  } catch (e) {
    console.warn("[tap] startup backfill failed", e);
  }
}, 7500);

// v2.30.2.1 — One-shot migration: lift every legacy hunt_query into the new
// detection_rules table so the Detection Rules page reflects the analyst's
// actual history. Detection rules are the intel-driven evolution of hunt
// queries; the original hunt_queries rows are kept untouched (they still
// power the OSINT page button), but each one now has a peer detection_rule
// with a deterministic id derived from the hunt_query id (`migrated:<hqid>`)
// so re-runs are fully idempotent.
//
// Mapping:
//   hunt_queries.title             → detection_rules.title
//   hunt_queries.description       → detection_rules.description
//   hunt_queries.source_finding_ids→ detection_rules.source_finding_ids
//                                  + derive severity = max(linked findings)
//                                  + derive threat_actors / affected_tech
//   hunt_queries.affected_tech     → detection_rules.affected_tech (union)
//   hunt_queries.queries           → split into sigma_yaml + queries{}
//                                    (joining string[] values with \n\n)
//   hunt_queries.ai_provider_label → detection_rules.ai_provider_label
//   hunt_queries.created_at/by     → preserved verbatim
//   detection_rules.status         = 'draft' (analyst reviews before approval)
//   detection_rules.version        = 1
//   detection_rules.notes          = 'Migrated from legacy hunt query (v2.30.2.1)'
function migrateHuntQueriesToDetectionRules(): void {
  let hqRows: any[] = [];
  try {
    hqRows = sqlite.prepare(
      "SELECT * FROM hunt_queries ORDER BY created_at ASC"
    ).all() as any[];
  } catch {
    return; // table missing on first boot
  }
  if (hqRows.length === 0) return;

  const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const SEVERITY_FALLBACK = "medium";
  const ts = now();
  let migrated = 0;
  let skipped = 0;

  for (const hq of hqRows) {
    const ruleId = `migrated:${hq.id}`;
    // Idempotency: skip if a peer detection_rule already exists.
    const existing = sqlite.prepare(
      "SELECT id FROM detection_rules WHERE tenant_id = ? AND id = ?"
    ).get(hq.tenant_id, ruleId);
    if (existing) { skipped += 1; continue; }

    // Parse JSON columns defensively.
    let findingIds: string[] = [];
    try { findingIds = JSON.parse(hq.source_finding_ids || "[]"); } catch {}
    let affectedTech: string[] = [];
    try { affectedTech = JSON.parse(hq.affected_tech || "[]"); } catch {}
    let rawQueries: Record<string, unknown> = {};
    try { rawQueries = JSON.parse(hq.queries || "{}") || {}; } catch {}

    // Split sigma out, normalise everything else to a single string per SIEM.
    let sigmaYaml: string | null = null;
    const queries: Record<string, string> = {};
    for (const [k, v] of Object.entries(rawQueries)) {
      const flat = Array.isArray(v)
        ? v.filter((x) => typeof x === "string" && x.trim().length > 0).join("\n\n")
        : (typeof v === "string" ? v : "");
      if (!flat) continue;
      if (k === "sigma") sigmaYaml = flat;
      else queries[k] = flat;
    }

    // Derive severity, threat actors, and any extra tech from the linked
    // findings (best-effort — missing findings are silently skipped).
    let bestSev = -1;
    let severity = SEVERITY_FALLBACK;
    const techSet = new Set<string>(affectedTech);
    const actorSet = new Set<string>();
    for (const fid of findingIds) {
      const f = sqlite.prepare(
        "SELECT severity, affected_tech, threat_actors FROM osint_findings WHERE tenant_id = ? AND id = ?"
      ).get(hq.tenant_id, fid) as any | undefined;
      if (!f) continue;
      const r = sevRank[String(f.severity || "").toLowerCase()] ?? -1;
      if (r > bestSev) { bestSev = r; severity = String(f.severity).toLowerCase(); }
      try {
        const at = JSON.parse(f.affected_tech || "[]");
        if (Array.isArray(at)) at.forEach((x) => typeof x === "string" && techSet.add(x));
      } catch {}
      try {
        const ta = JSON.parse(f.threat_actors || "[]");
        if (Array.isArray(ta)) ta.forEach((x) => typeof x === "string" && actorSet.add(x));
      } catch {}
    }
    // Severity must be one of the RuleSeverity values; collapse 'info' → 'low'.
    if (severity === "info") severity = "low";
    if (!sevRank[severity] && severity !== "low") severity = SEVERITY_FALLBACK;

    try {
      sqlite.prepare(`INSERT INTO detection_rules (
        id, tenant_id, title, description, source_finding_ids, status, severity,
        mitre_techniques, affected_tech, threat_actors, sigma_yaml, queries, notes,
        version, ai_provider_label, created_at, updated_at, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        ruleId, hq.tenant_id, hq.title || "Migrated hunt query",
        hq.description ?? null,
        JSON.stringify(findingIds), "draft", severity,
        "[]", JSON.stringify(Array.from(techSet)), JSON.stringify(Array.from(actorSet)),
        sigmaYaml, JSON.stringify(queries),
        "Migrated from legacy hunt query (v2.30.2.1). Original hunt-query id: " + hq.id,
        1, hq.ai_provider_label ?? null,
        hq.created_at || ts, ts, hq.created_by || "system",
      );
      migrated += 1;
    } catch (e) {
      console.warn(`[migrate-hq->dr] failed to migrate hunt_query ${hq.id}:`, e);
    }
  }

  if (migrated > 0 || skipped > 0) {
    console.log(`[migrate-hq->dr] migrated=${migrated} skipped=${skipped} (legacy hunt_queries kept)`);
  }
}

try { migrateHuntQueriesToDetectionRules(); } catch (e) {
  console.warn("[migrate-hq->dr] migration failed", e);
}

// ---------- OSINT source enrichment helpers ----------

/**
 * Translation table for OSINT source names whose canonical title is not in
 * English. The seed catalog is overwhelmingly English already; this map only
 * holds the handful of CJK / Cyrillic regulator feeds that ship with a
 * native-language title. Falls through (returns input) when no mapping exists
 * so we never lose information.
 */
const SOURCE_NAME_TRANSLATIONS: Record<string, string> = {
  // Mainland China
  "CNVD — China National Vuln DB":                "CNVD — China National Vulnerability Database",
  "CNNVD — China National Information Security": "CNNVD — China National Information Security Vulnerability Database",
  // Russia
  "BDU FSTEC (Russia)":                            "BDU FSTEC — Russian Federal Vulnerability Database",
  // Japan
  "VulnDB — JVN iPedia":                          "JVN iPedia — Japan Vulnerability Notes",
  "JVN — JPCERT/JPCERT advisories":                "JVN — JPCERT/CC Advisories",
  // Taiwan
  "Taiwan NICST":                                  "Taiwan NICS — National Information & Communication Security Taskforce",
  "Taiwan iThome SecurityWeekly":                  "Taiwan iThome — Security Weekly",
  // Hong Kong
  "Hong Kong HKMA — Cybersecurity Fortification":  "HKMA — Cybersecurity Fortification Initiative (Hong Kong)",
  "Hong Kong OFCA Cyber":                          "OFCA — Office of the Communications Authority (Hong Kong)",
  // Malaysia / Singapore / India
  "Bank Negara Malaysia (RMiT)":                   "Bank Negara Malaysia — Risk Management in Technology (RMiT)",
  "Singapore CSA bulletins":                       "CSA Singapore — Cybersecurity Advisories",
  "MAS Notice — Cybersecurity (Singapore)":        "MAS Singapore — Cybersecurity Notices",
  "MAS — Notice 655 / TRM Guidelines":             "MAS Singapore — Notice 655 / Technology Risk Management Guidelines",
  "RBI Cybersecurity (India)":                     "RBI India — Cybersecurity Guidelines",
};

function translateSourceName(name: string, language: string): string {
  // Strip CJK / Cyrillic if present (defensive — the seed is Latin-only today
  // but synthetic sources from real feed scans may contain native characters).
  const nonLatin = /[\u3040-\u30ff\u4e00-\u9fff\uac00-\ud7af\u0400-\u04ff]/.test(name);
  const mapped = SOURCE_NAME_TRANSLATIONS[name];
  if (mapped) return mapped;
  if (nonLatin) {
    // Best-effort: drop non-Latin runs and append a language tag so the row stays readable.
    const stripped = name.replace(/[\u3040-\u30ff\u4e00-\u9fff\uac00-\ud7af\u0400-\u04ff]+/g, "").replace(/\s+/g, " ").trim();
    return stripped ? `${stripped} (${language})` : `${name} (${language})`;
  }
  return name;
}

function classifySourceKind(url: string | null | undefined): string {
  const u = (url || "").toLowerCase();
  if (!u) return "web";
  if (/\.json(\?|$)/.test(u) || u.includes("/api/") || u.includes("api.")) return "json";
  if (/\.(rss|xml|atom|rdf)(\?|$)/.test(u) || u.includes("/rss") || u.includes("/feed") || u.includes("/atom")) return "rss";
  return "web";
}

function sourceLastFetchedAt(source: any): string | null {
  return source?.lastFetchedAt ?? source?.last_fetched_at ?? null;
}

function markOsintSourcesFetched(sourceIds: Iterable<string>, fetchedAt = now()): void {
  const ids = Array.from(new Set(Array.from(sourceIds).filter(Boolean)));
  if (ids.length === 0) return;
  const placeholders = ids.map(() => "?").join(",");
  sqlite.prepare(`UPDATE osint_sources SET last_fetched_at = ? WHERE id IN (${placeholders})`).run(fetchedAt, ...ids);
}

// Re-export persona list so routes can hand it to taxonomies.
export { OSINT_OVERVIEW_PERSONAS as OSINT_OVERVIEW_PERSONA_LIST };

// ---------- public API ----------
export const storage = {
  // auth
  login(email: string, password: string, mfaCode?: string): (User & { accessToken: string; accessMode: "credentialed" | "guest" }) | { mfaRequired: true } | undefined {
    const u = db.select().from(users).where(eq(users.email, email)).get();
    if (!u) {
      verifyPassword(password, DUMMY_PASSWORD_HASH);
      return undefined;
    }
    if ((u.status ?? "active") !== "active") {
      verifyPassword(password, u.password);
      return undefined;
    }
    if (userLockedUntil(u)) return undefined;
    const verified = verifyPassword(password, u.password);
    if (!verified.ok) {
      recordAuthFailure(u.id, "login");
      return undefined;
    }
    if (u.mfaEnabled) {
      const secret = dec(u.mfaSecretEnc);
      if (!verifyTotp(secret, mfaCode)) {
        recordAuthFailure(u.id, "mfa");
        return { mfaRequired: true };
      }
    }
    if (verified.needsRehash) {
      db.update(users).set({ password: hashPassword(password) }).where(eq(users.id, u.id)).run();
    }
    clearAuthFailures(u.id);
    db.update(users).set({ lastLoginAt: now() } as any).where(eq(users.id, u.id)).run();
    const accessMode = accessModeForRole(u.role);
    return { ...u, accessToken: issueSession(u.id, accessMode), accessMode };
  },
  changeOwnPassword(uid: string, currentPassword: string, nextPassword: string): Omit<User, "password"> | undefined {
    const u = db.select().from(users).where(eq(users.id, uid)).get();
    if (!u) return undefined;
    if (!verifyPassword(currentPassword, u.password).ok) throw new Error("current password is incorrect");
    if (verifyPassword(nextPassword, u.password).ok) {
      throw new Error("new password cannot be the same as the current temporary password");
    }
    if (isBlockedInitialPassword(nextPassword)) {
      throw new Error("new password cannot reuse a seeded or temporary setup password");
    }
    db.update(users).set({
      password: hashPassword(nextPassword),
      passwordMustChange: false,
    } as any).where(eq(users.id, uid)).run();
    return storage.getUserPublic(uid);
  },
  getUserPublic(uid: string): Omit<User, "password"> | undefined {
    return sqlite.prepare(`
      SELECT id, tenant_id AS tenantId, email, role,
             display_name AS displayName,
             COALESCE(account_type, 'platform') AS accountType,
             COALESCE(status, 'active') AS status,
             COALESCE(password_must_change, 0) AS passwordMustChange,
             COALESCE(mfa_enabled, 0) AS mfaEnabled,
             mfa_verified_at AS mfaVerifiedAt,
             COALESCE(failed_login_count, 0) AS failedLoginCount,
             COALESCE(failed_mfa_count, 0) AS failedMfaCount,
             account_locked_until AS accountLockedUntil,
             created_at AS createdAt,
             last_login_at AS lastLoginAt
      FROM users
      WHERE id = ?
    `).get(uid) as Omit<User, "password"> | undefined;
  },
  getMfaSetup(uid: string): { enabled: boolean; verifiedAt: string | null; secret: string; otpauthUrl: string } | undefined {
    const u = db.select().from(users).where(eq(users.id, uid)).get();
    if (!u) return undefined;
    if (u.mfaEnabled) return undefined;
    let secret = dec(u.mfaSecretEnc);
    if (!secret) {
      secret = newMfaSecret();
      db.update(users).set({ mfaSecretEnc: enc(secret) } as any).where(eq(users.id, uid)).run();
    }
    const label = encodeURIComponent(`OptraSight:${u.email}`);
    const issuer = encodeURIComponent("OptraSight");
    return {
      enabled: !!u.mfaEnabled,
      verifiedAt: u.mfaVerifiedAt ?? null,
      secret,
      otpauthUrl: `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`,
    };
  },
  verifyMfaSetup(uid: string, code: string): Omit<User, "password"> | undefined {
    const u = db.select().from(users).where(eq(users.id, uid)).get();
    if (!u) return undefined;
    if (userLockedUntil(u)) throw new Error("account temporarily locked due to failed authentication attempts");
    const secret = dec(u.mfaSecretEnc);
    if (!verifyTotp(secret, code)) {
      recordAuthFailure(uid, "mfa");
      throw new Error("invalid MFA code");
    }
    db.update(users).set({
      mfaEnabled: true,
      mfaVerifiedAt: now(),
    } as any).where(eq(users.id, uid)).run();
    clearAuthFailures(uid);
    return storage.getUserPublic(uid);
  },
  getUser(token: string): User | undefined {
    const h = tokenHash(token);
    const session = sqlite.prepare(`
      SELECT s.user_id AS userId,
             COALESCE(s.access_mode, 'credentialed') AS accessMode,
             s.issued_at AS issuedAt,
             s.last_used_at AS lastUsedAt,
             u.role AS role
      FROM auth_sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.revoked_at IS NULL
    `).get(h) as { userId: string; accessMode: "credentialed" | "guest"; issuedAt: string | null; lastUsedAt: string | null; role: string | null } | undefined;
    if (session?.userId) {
      if (sessionExpiryReason(session)) {
        sqlite.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL").run(now(), h);
        return undefined;
      }
      // Keep a browser session stable during normal in-app refresh/polling.
      // We only touch the session activity marker periodically,
      // instead of rewriting it on every authenticated API call.
      if (shouldTouchSession(session.lastUsedAt)) {
        sqlite.prepare("UPDATE auth_sessions SET last_used_at = ? WHERE token_hash = ?").run(now(), h);
      }
      const u = db.select().from(users).where(eq(users.id, session.userId)).get();
      if (!u || (u.status ?? "active") !== "active") return undefined;
      return { ...u, accessMode: session.accessMode } as User;
    }
    return undefined;
  },
  logout(token: string): boolean {
    const r = sqlite.prepare(`
      UPDATE auth_sessions SET revoked_at = ?
      WHERE token_hash = ? AND revoked_at IS NULL
    `).run(now(), tokenHash(token));
    return r.changes > 0;
  },
  listPlatformUsers(): Array<Omit<User, "password"> & { tenantName: string | null; tenantSlug: string | null; tenantPlan: string | null }> {
    const rows = sqlite.prepare(`
      SELECT u.id, u.tenant_id AS tenantId, u.email, u.role,
             u.display_name AS displayName,
             COALESCE(u.account_type, 'platform') AS accountType,
             COALESCE(u.status, 'active') AS status,
             COALESCE(u.password_must_change, 0) AS passwordMustChange,
             COALESCE(u.mfa_enabled, 0) AS mfaEnabled,
             u.mfa_verified_at AS mfaVerifiedAt,
             COALESCE(u.failed_login_count, 0) AS failedLoginCount,
             COALESCE(u.failed_mfa_count, 0) AS failedMfaCount,
             u.account_locked_until AS accountLockedUntil,
             u.created_at AS createdAt,
             u.last_login_at AS lastLoginAt,
             t.name AS tenantName,
             t.slug AS tenantSlug,
             t.plan AS tenantPlan
      FROM users u
      LEFT JOIN tenants t ON t.id = u.tenant_id
      WHERE COALESCE(u.account_type, 'platform') = 'platform'
      ORDER BY
        CASE u.role WHEN 'admin' THEN 0 ELSE 1 END,
        CASE COALESCE(u.status, 'active') WHEN 'active' THEN 0 ELSE 1 END,
        u.email COLLATE NOCASE
    `).all() as Array<Omit<User, "password"> & { tenantName: string | null; tenantSlug: string | null; tenantPlan: string | null }>;
    return rows.map(platformUserForBatchOne);
  },
  createPlatformUser(opts: {
    tenantId: string; email: string; password: string; role: string; displayName?: string; status?: string;
  }): Omit<User, "password"> | undefined {
    if (isBlockedInitialPassword(opts.password)) {
      throw new Error("password cannot reuse a seeded or temporary setup password");
    }
    const tenant = db.select().from(tenants).where(eq(tenants.id, opts.tenantId)).get();
    if (!tenant) throw new Error("workspace not found");
    const uid = id();
    db.insert(users).values({
      id: uid,
      tenantId: opts.tenantId,
      email: opts.email.trim().toLowerCase(),
      password: hashPassword(opts.password),
      role: opts.role,
      accountType: "platform",
      displayName: opts.displayName?.trim() || null,
      status: opts.status ?? "active",
      passwordMustChange: true,
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaVerifiedAt: null,
      failedLoginCount: 0,
      failedMfaCount: 0,
      accountLockedUntil: null,
      createdAt: now(),
      lastLoginAt: null,
    } as any).run();
    return storage.getUserPublic(uid);
  },
  updatePlatformUser(uid: string, patch: {
    tenantId?: string; email?: string; password?: string; role?: string; displayName?: string | null; status?: string;
  }): Omit<User, "password"> | undefined {
    const existing = storage.getUserPublic(uid);
    if (!existing || (existing as any).accountType !== "platform") return undefined;
    const nextTenantId = patch.tenantId ?? existing.tenantId;
    const tenant = db.select().from(tenants).where(eq(tenants.id, nextTenantId)).get();
    if (!tenant) throw new Error("workspace not found");
    const payload: Record<string, any> = {};
    if (patch.tenantId !== undefined) payload.tenantId = patch.tenantId;
    if (patch.email !== undefined) payload.email = patch.email.trim().toLowerCase();
    if (patch.password !== undefined) {
      if (isBlockedInitialPassword(patch.password)) {
        throw new Error("password cannot reuse a seeded or temporary setup password");
      }
      payload.password = hashPassword(patch.password);
      payload.passwordMustChange = true;
      payload.mfaEnabled = false;
      payload.mfaSecretEnc = null;
      payload.mfaVerifiedAt = null;
      payload.failedLoginCount = 0;
      payload.failedMfaCount = 0;
      payload.accountLockedUntil = null;
      revokeUserSessions(uid);
    }
    if (patch.role !== undefined) payload.role = patch.role;
    if (patch.displayName !== undefined) payload.displayName = patch.displayName?.trim() || null;
    if (patch.status !== undefined) payload.status = patch.status;
    if (Object.keys(payload).length > 0) {
      db.update(users).set(payload as any).where(eq(users.id, uid)).run();
    }
    return storage.getUserPublic(uid);
  },
  disablePlatformUser(uid: string): Omit<User, "password"> | undefined {
    return storage.updatePlatformUser(uid, { status: "disabled" });
  },
  deletePlatformUser(uid: string): Omit<User, "password"> | undefined {
    const existing = storage.getUserPublic(uid);
    if (!existing || (existing as any).accountType !== "platform") return undefined;
    const tx = sqlite.transaction(() => {
      revokeUserSessions(uid);
      sqlite.prepare("DELETE FROM users WHERE id = ? AND COALESCE(account_type, 'platform') = 'platform'").run(uid);
    });
    tx();
    return existing;
  },
  resetPlatformUserMfa(uid: string): Omit<User, "password"> | undefined {
    const existing = storage.getUserPublic(uid);
    if (!existing || (existing as any).accountType !== "platform") return undefined;
    db.update(users).set({
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaVerifiedAt: null,
      failedMfaCount: 0,
      accountLockedUntil: null,
    } as any).where(eq(users.id, uid)).run();
    revokeUserSessions(uid);
    return storage.getUserPublic(uid);
  },

  // tenants
  listTenants(_role: string, tenantId: string, _userId?: string): Tenant[] {
    const t = db.select().from(tenants).where(eq(tenants.id, tenantId)).get();
    return t ? [t] : [];
  },
  getTenant(tid: string): Tenant | undefined {
    return db.select().from(tenants).where(eq(tenants.id, tid)).get();
  },

  // ---------- AI providers ----------
  listAiProviders(tid: string): AiProviderSummary[] {
    const rows = db.select().from(aiProviders)
      .where(eq(aiProviders.tenantId, tid))
      .orderBy(desc(aiProviders.isDefault), aiProviders.label).all();
    return rows.map(aiProviderToSummary);
  },
  hasUsableAiProvider(tid: string): boolean {
    const row = db.select().from(aiProviders)
      .where(and(eq(aiProviders.tenantId, tid), eq(aiProviders.enabled, 1)))
      .all()
      .find((p) => aiProviderHasSecret(p) && p.lastTestOk === 1);
    return !!row;
  },
  upsertAiProvider(tid: string, opts: {
    id?: string;
    provider: AiProviderKind; label: string; model: string;
    baseUrl?: string; apiKey?: string;
    enabled: boolean; isDefault: boolean;
    config?: Record<string, any>;
  }): AiProviderSummary {
    const t = now();
    const existing = opts.id
      ? db.select().from(aiProviders).where(and(eq(aiProviders.id, opts.id), eq(aiProviders.tenantId, tid))).get()
      : undefined;
    const row: any = existing ? { ...existing } : {
      id: id(), tenantId: tid, createdAt: t,
    };
    row.provider = opts.provider;
    row.label = opts.label;
    row.model = opts.model;
    row.baseUrl = opts.baseUrl && opts.baseUrl.length ? opts.baseUrl : null;
    if (opts.apiKey !== undefined) {
      if (opts.apiKey === "") {
        secretStore.deleteSecret(tid, AI_PROVIDER_SECRET, row.id, "api_key");
        row.apiKeyEnc = null; row.apiKeyMask = null;
      } else if (opts.apiKey.length > 0) {
        secretStore.setSecret(tid, AI_PROVIDER_SECRET, row.id, "api_key", enc(opts.apiKey));
        row.apiKeyEnc = null;
        row.apiKeyMask = mask(opts.apiKey);
      }
    }
    row.enabled = opts.enabled ? 1 : 0;
    row.isDefault = opts.isDefault ? 1 : 0;
    if (opts.config !== undefined) row.config = j(opts.config);
    if (!row.config) row.config = "{}";
    row.updatedAt = t;

    if (existing) {
      db.update(aiProviders).set(row).where(eq(aiProviders.id, existing.id)).run();
    } else {
      db.insert(aiProviders).values(row).run();
    }
    // ensure only one default per tenant
    if (opts.isDefault) {
      db.update(aiProviders)
        .set({ isDefault: 0, updatedAt: t })
        .where(and(eq(aiProviders.tenantId, tid)))
        .run();
      db.update(aiProviders)
        .set({ isDefault: 1, updatedAt: t })
        .where(eq(aiProviders.id, row.id))
        .run();
    }
    const fresh = db.select().from(aiProviders).where(eq(aiProviders.id, row.id)).get()!;
    return aiProviderToSummary(fresh);
  },
  deleteAiProvider(tid: string, pid: string): boolean {
    // unassign any tasks first
    db.delete(aiTaskAssignments)
      .where(and(eq(aiTaskAssignments.tenantId, tid), eq(aiTaskAssignments.providerId, pid)))
      .run();
    const r = db.delete(aiProviders)
      .where(and(eq(aiProviders.id, pid), eq(aiProviders.tenantId, tid))).run();
    if (r.changes > 0) secretStore.deleteOwnerSecrets(tid, AI_PROVIDER_SECRET, pid);
    return r.changes > 0;
  },
  testAiProvider(tid: string, pid: string): { ok: boolean; latencyMs: number; message: string; probedAt: string } {
    const row = db.select().from(aiProviders).where(and(eq(aiProviders.id, pid), eq(aiProviders.tenantId, tid))).get();
    if (!row) return { ok: false, latencyMs: 0, message: "unknown provider", probedAt: now() };
    const r = testAiProviderImpl(hydrateAiProviderSecret(row)!);
    const probedAt = now();
    db.update(aiProviders).set({
      lastTestedAt: probedAt,
      lastTestOk: r.ok ? 1 : 0,
      lastTestMessage: r.message,
      updatedAt: probedAt,
    }).where(eq(aiProviders.id, pid)).run();
    return { ...r, probedAt };
  },
  getAiAssignments(tid: string): Record<AiTask, string> {
    const rows = db.select().from(aiTaskAssignments)
      .where(eq(aiTaskAssignments.tenantId, tid)).all();
    const m: Record<string, string> = {};
    for (const r of rows) m[r.task] = r.providerId;
    if (!m.osint_chat && m.osint_overview) m.osint_chat = m.osint_overview;
    return m as Record<AiTask, string>;
  },
  setAiAssignments(tid: string, assignments: Record<string, string>) {
    const t = now();
    for (const [task, pid] of Object.entries(assignments)) {
      const exists = db.select().from(aiTaskAssignments)
        .where(and(eq(aiTaskAssignments.tenantId, tid), eq(aiTaskAssignments.task, task))).get();
      if (exists) {
        db.update(aiTaskAssignments).set({ providerId: pid, updatedAt: t })
          .where(eq(aiTaskAssignments.id, exists.id)).run();
      } else {
        db.insert(aiTaskAssignments).values({
          id: id(), tenantId: tid, task, providerId: pid, updatedAt: t,
        }).run();
      }
    }
  },
  /** Resolve the live-tested provider configured for a task. Only fall back
   *  when no explicit assignment exists, so selected providers are never
   *  silently replaced by a different vendor. */
  resolveAiProvider(tid: string, task: AiTask): AiProvider | undefined {
    const usable = (row: AiProvider | undefined | null) =>
      !!row && !!row.enabled && aiProviderHasSecret(row) && row.lastTestOk === 1;
    const assignments = storage.getAiAssignments(tid);
    const pid = assignments[task];
    if (pid) {
      const row = db.select().from(aiProviders).where(and(eq(aiProviders.id, pid), eq(aiProviders.tenantId, tid))).get();
      if (usable(row)) return hydrateAiProviderSecret(row)!;
      return undefined;
    }
    const def = db.select().from(aiProviders)
      .where(and(eq(aiProviders.tenantId, tid), eq(aiProviders.isDefault, 1)))
      .get();
    if (usable(def)) return hydrateAiProviderSecret(def)!;
    const fallback = db.select().from(aiProviders)
      .where(and(eq(aiProviders.tenantId, tid), eq(aiProviders.enabled, 1)))
      .all()
      .find((row) => usable(row));
    return hydrateAiProviderSecret(fallback);
  },
  /** Resolve a live-tested provider that can perform image generation for TAP
   *  portraits. Chat/text model names are allowed here because aiLive selects
   *  the current image-capable model for the same provider family at call time.
   */
  resolveAiPortraitProvider(tid: string): AiProvider | undefined {
    const usable = (row: AiProvider | undefined | null) =>
      !!row && !!row.enabled && aiProviderHasSecret(row) && row.lastTestOk === 1;
    const supportsPortrait = (row: AiProvider | undefined | null) =>
      !!row && ["openai", "azure-openai", "gemini"].includes(String(row.provider));
    const assignments = storage.getAiAssignments(tid);
    const pid = assignments.tap_portrait;
    if (pid) {
      const row = db.select().from(aiProviders).where(and(eq(aiProviders.id, pid), eq(aiProviders.tenantId, tid))).get();
      if (usable(row) && supportsPortrait(row)) return hydrateAiProviderSecret(row)!;
      return undefined;
    }
    const def = db.select().from(aiProviders)
      .where(and(eq(aiProviders.tenantId, tid), eq(aiProviders.isDefault, 1)))
      .get();
    if (usable(def) && supportsPortrait(def)) return hydrateAiProviderSecret(def)!;
    const fallback = db.select().from(aiProviders)
      .where(and(eq(aiProviders.tenantId, tid), eq(aiProviders.enabled, 1)))
      .all()
      .find((row) => usable(row) && supportsPortrait(row));
    return hydrateAiProviderSecret(fallback);
  },

  // ---------- OSINT monitoring ----------
  listOsintSources(opts?: { category?: string; q?: string }): OsintSource[] {
    const filters: any[] = [];
    if (opts?.category) filters.push(eq(osintSourcesTbl.category, opts.category));
    if (opts?.q) filters.push(like(osintSourcesTbl.name, `%${opts.q}%`));
    const q = filters.length
      ? db.select().from(osintSourcesTbl).where(and(...filters))
      : db.select().from(osintSourcesTbl);
    return q.orderBy(osintSourcesTbl.category, osintSourcesTbl.name).limit(1000).all();
  },

  /**
   * Enriched source list for the dashboard. Adds:
   *   - categoryLabel (human-readable English label from OSINT_CATEGORY_LABELS)
   *   - englishName   (translated when the upstream name is non-Latin script)
   *   - kind          (best-effort "json" | "rss" | "web" based on URL hints)
   *   - findingCount  (rows in osint_findings.source_id == s.id, all tenants)
   *
   * findingCount is computed in one GROUP BY pass to keep the response O(1) DB calls.
   */
  listOsintSourceRows(opts?: { category?: string; q?: string; tenantId?: string }): OsintSourceRowDTO[] {
    const sources = storage.listOsintSources({ category: opts?.category, q: opts?.q });
    // Aggregate finding counts in a single pass.
    let countSql = "SELECT source_id as sid, COUNT(*) as n FROM osint_findings";
    const params: any[] = [];
    if (opts?.tenantId) {
      countSql += " WHERE tenant_id = ?";
      params.push(opts.tenantId);
    }
    countSql += " GROUP BY source_id";
    const counts = sqlite.prepare(countSql).all(...params) as Array<{ sid: string; n: number }>;
    const countMap = new Map(counts.map((c) => [c.sid, c.n]));
    let fetchedSql = "SELECT source_id as sid, MAX(COALESCE(source_fetched_at, created_at)) as ts FROM osint_findings";
    const fetchedParams: any[] = [];
    if (opts?.tenantId) {
      fetchedSql += " WHERE tenant_id = ?";
      fetchedParams.push(opts.tenantId);
    }
    fetchedSql += " GROUP BY source_id";
    const fetchedRows = sqlite.prepare(fetchedSql).all(...fetchedParams) as Array<{ sid: string; ts: string | null }>;
    const fetchedMap = new Map(fetchedRows.map((r) => [r.sid, r.ts]));
    return sources.map((s) => ({
      id: s.id,
      category: s.category,
      categoryLabel: OSINT_CATEGORY_LABELS[s.category] ?? s.category,
      name: s.name,
      englishName: translateSourceName(s.name, s.language),
      url: s.url,
      language: s.language,
      region: s.region,
      reliability: s.reliability,
      kind: classifySourceKind(s.url),
      findingCount: countMap.get(s.id) ?? 0,
      lastFetchedAt: sourceLastFetchedAt(s) ?? fetchedMap.get(s.id) ?? null,
      enabled: !!s.enabled,
    }));
  },

  /**
   * v2.29 — Bulk enable / disable / delete on osint_sources.
   * Returns the number of rows affected.
   */
  bulkUpdateOsintSources(ids: string[], action: "enable" | "disable" | "delete"): number {
    if (!Array.isArray(ids) || ids.length === 0) return 0;
    const placeholders = ids.map(() => "?").join(",");
    if (action === "delete") {
      const res = sqlite.prepare(`DELETE FROM osint_sources WHERE id IN (${placeholders})`).run(...ids);
      return Number(res.changes ?? 0);
    }
    const flag = action === "enable" ? 1 : 0;
    const res = sqlite.prepare(`UPDATE osint_sources SET enabled = ? WHERE id IN (${placeholders})`).run(flag, ...ids);
    return Number(res.changes ?? 0);
  },

  /**
   * v2.29 — Aggregations powering the Sources Analytics dashboard.
   *   - trend           : daily count of findings over the last 30 days
   *   - topContribution : 10 sources with the most findings (last 30 days)
   *   - topThreatIntel  : 10 sources whose findings are tagged intel_category='threat_intel'
   *   - topClientEmail  : 10 sources whose findings have draft_email IS NOT NULL
   * tenantId is optional; when present every aggregation is scoped to that tenant.
   */
  getOsintSourcesAnalytics(opts?: { tenantId?: string }): {
    trend: Array<{ day: string; count: number }>;
    topByContribution: Array<{ sourceId: string; name: string; categoryLabel: string; count: number }>;
    topByThreatIntel: Array<{ sourceId: string; name: string; categoryLabel: string; count: number }>;
    topByClientEmail: Array<{ sourceId: string; name: string; categoryLabel: string; count: number }>;
  } {
    const tenantClause = opts?.tenantId ? " AND tenant_id = ?" : "";
    const tenantParam: any[] = opts?.tenantId ? [opts.tenantId] : [];
    const since30 = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    // ---- daily trend (last 30 days) ----
    // SQLite has no DATE_TRUNC; substr the ISO-8601 created_at down to yyyy-mm-dd.
    const trendRows = sqlite
      .prepare(`
        SELECT substr(COALESCE(published_at, created_at), 1, 10) as day, COUNT(*) as n
        FROM osint_findings
        WHERE COALESCE(published_at, created_at) >= ?${tenantClause}
        GROUP BY day
        ORDER BY day ASC
      `)
      .all(since30, ...tenantParam) as Array<{ day: string; n: number }>;
    // Fill missing days with 0 so the chart line stays continuous.
    const trend: Array<{ day: string; count: number }> = [];
    const have = new Map(trendRows.map((r) => [r.day, r.n]));
    for (let i = 29; i >= 0; i--) {
      const d = new Date(); d.setUTCDate(d.getUTCDate() - i); d.setUTCHours(0, 0, 0, 0);
      const key = d.toISOString().slice(0, 10);
      trend.push({ day: key, count: have.get(key) ?? 0 });
    }

    const sourceMeta = new Map(storage.listOsintSources().map((s) => [s.id, s]));
    const dressTopN = (rows: Array<{ sid: string; n: number }>) =>
      rows.map((r) => {
        const src = sourceMeta.get(r.sid);
        return {
          sourceId: r.sid,
          name: src ? translateSourceName(src.name, src.language) : r.sid,
          categoryLabel: src ? (OSINT_CATEGORY_LABELS[src.category] ?? src.category) : "unknown",
          count: r.n,
        };
      });

    const topContribRows = sqlite
      .prepare(`
        SELECT source_id as sid, COUNT(*) as n
        FROM osint_findings
        WHERE COALESCE(published_at, created_at) >= ?${tenantClause}
        GROUP BY source_id
        ORDER BY n DESC
        LIMIT 10
      `)
      .all(since30, ...tenantParam) as Array<{ sid: string; n: number }>;

    const topThreatRows = sqlite
      .prepare(`
        SELECT source_id as sid, COUNT(*) as n
        FROM osint_findings
        WHERE intel_category = 'threat_intel'${tenantClause}
        GROUP BY source_id
        ORDER BY n DESC
        LIMIT 10
      `)
      .all(...tenantParam) as Array<{ sid: string; n: number }>;

    const topEmailRows = sqlite
      .prepare(`
        SELECT source_id as sid, COUNT(*) as n
        FROM osint_findings
        WHERE draft_email IS NOT NULL${tenantClause}
        GROUP BY source_id
        ORDER BY n DESC
        LIMIT 10
      `)
      .all(...tenantParam) as Array<{ sid: string; n: number }>;

    return {
      trend,
      topByContribution: dressTopN(topContribRows),
      topByThreatIntel: dressTopN(topThreatRows),
      topByClientEmail: dressTopN(topEmailRows),
    };
  },

  // -------------------------------------------------------------------------
  // v2.30 — Deep Sources Analytics.
  // 4 new payloads on top of the v2.29 panels:
  //   1) Actionability scorecard — composite 0..100 per source.
  //   2) Noise-vs-signal quadrant — volume vs threat-intel ratio.
  //   3) Overlap — unique-rate + first-to-publish + co-occurrence matrix
  //      using v2.30 cluster_id.
  //   4) ATT&CK + sectors heatmaps — source × tactic / sector counts.
  // All 30-day windowed, tenant-scoped (or cross-tenant when admin asks).
  // -------------------------------------------------------------------------

  getOsintSourceScorecard(opts?: { tenantId?: string }): import("@shared/schema").OsintSourceScoreRow[] {
    const tenantClause = opts?.tenantId ? " AND tenant_id = ?" : "";
    const tenantParam: any[] = opts?.tenantId ? [opts.tenantId] : [];
    const since30 = new Date(Date.now() - 30 * 86400_000).toISOString();
    const sourceMeta = new Map(storage.listOsintSources().map((s) => [s.id, s]));

    // Pull aggregate counters per source in a single sweep.
    const rows = sqlite.prepare(`
      SELECT
        source_id as sid,
        COUNT(*) as total,
        SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) as sev_high,
        SUM(CASE WHEN intel_category IS NOT NULL THEN 1 ELSE 0 END) as cat_total,
        SUM(CASE WHEN intel_category = 'threat_intel' THEN 1 ELSE 0 END) as cat_intel,
        SUM(CASE WHEN draft_email IS NOT NULL THEN 1 ELSE 0 END) as analyst_conv,
        SUM(CASE WHEN iocs IS NOT NULL AND iocs != '' THEN length(iocs) ELSE 0 END) as iocs_len_sum,
        SUM(CASE WHEN iocs IS NOT NULL AND iocs != '{}' AND iocs != '' THEN 1 ELSE 0 END) as iocs_rows
      FROM osint_findings
      WHERE COALESCE(published_at, created_at) >= ?${tenantClause}
      GROUP BY source_id
    `).all(since30, ...tenantParam) as Array<{
      sid: string; total: number; sev_high: number; cat_total: number;
      cat_intel: number; analyst_conv: number; iocs_len_sum: number; iocs_rows: number;
    }>;

    // Median lag per source = median (created_at - published_at) in hours.
    // SQLite has no MEDIAN; compute in JS over a per-source row list.
    const lagRows = sqlite.prepare(`
      SELECT source_id as sid,
             (julianday(created_at) - julianday(published_at)) * 24.0 as lag_h
      FROM osint_findings
      WHERE COALESCE(published_at, created_at) >= ?${tenantClause}
        AND published_at IS NOT NULL AND created_at IS NOT NULL
    `).all(since30, ...tenantParam) as Array<{ sid: string; lag_h: number }>;
    const lagBySrc = new Map<string, number[]>();
    for (const r of lagRows) {
      if (typeof r.lag_h !== "number" || isNaN(r.lag_h) || r.lag_h < 0) continue;
      const a = lagBySrc.get(r.sid) ?? [];
      a.push(r.lag_h);
      lagBySrc.set(r.sid, a);
    }
    const median = (arr: number[]): number => {
      if (!arr.length) return 0;
      const s = arr.slice().sort((a, b) => a - b);
      const mid = Math.floor(s.length / 2);
      return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
    };

    // IoC density: precise mean IoC count per finding per source via a second
    // small pass (parsing JSON in SQL is messy). We grab id+iocs in batch and
    // count in JS.
    const iocRows = sqlite.prepare(`
      SELECT source_id as sid, iocs
      FROM osint_findings
      WHERE COALESCE(published_at, created_at) >= ?${tenantClause}
    `).all(since30, ...tenantParam) as Array<{ sid: string; iocs: string | null }>;
    const iocSums = new Map<string, { sum: number; n: number }>();
    for (const r of iocRows) {
      const slot = iocSums.get(r.sid) ?? { sum: 0, n: 0 };
      slot.n += 1;
      if (r.iocs) {
        try {
          const obj = JSON.parse(r.iocs);
          if (obj && typeof obj === "object") {
            for (const k of Object.keys(obj)) {
              const v = obj[k];
              if (Array.isArray(v)) slot.sum += v.length;
            }
          }
        } catch { /* ignore */ }
      }
      iocSums.set(r.sid, slot);
    }

    const clamp01 = (n: number) => Math.max(0, Math.min(1, n));
    const out: import("@shared/schema").OsintSourceScoreRow[] = rows.map((r) => {
      const total = r.total || 0;
      const sevSkew = total > 0 ? clamp01(r.sev_high / total) : 0;
      const intelRatio = r.cat_total > 0 ? clamp01(r.cat_intel / r.cat_total) : 0;
      const conv = total > 0 ? clamp01(r.analyst_conv / total) : 0;
      const iocSlot = iocSums.get(r.sid) ?? { sum: 0, n: 0 };
      const meanIoc = iocSlot.n > 0 ? iocSlot.sum / iocSlot.n : 0;
      const iocDensity = clamp01(Math.min(5, meanIoc) / 5);
      const lagArr = lagBySrc.get(r.sid) ?? [];
      const lagH = median(lagArr);
      const freshScore = clamp01(1 - Math.min(72, lagH) / 72);
      // Composite weights: conv 0.30, ioc 0.20, intel 0.20, sev 0.15, fresh 0.15.
      const score01 =
        0.30 * conv +
        0.20 * iocDensity +
        0.20 * intelRatio +
        0.15 * sevSkew +
        0.15 * freshScore;
      const src = sourceMeta.get(r.sid);
      return {
        sourceId: r.sid,
        name: src ? translateSourceName(src.name, src.language) : r.sid,
        categoryLabel: src ? (OSINT_CATEGORY_LABELS[src.category] ?? src.category) : "unknown",
        totalFindings: total,
        iocDensity: Math.round(iocDensity * 1000) / 1000,
        analystConversionRate: Math.round(conv * 1000) / 1000,
        severitySkew: Math.round(sevSkew * 1000) / 1000,
        threatIntelRatio: Math.round(intelRatio * 1000) / 1000,
        freshnessLagHours: Math.round(lagH * 10) / 10,
        freshnessScore: Math.round(freshScore * 1000) / 1000,
        actionabilityScore: Math.round(score01 * 100),
      };
    });
    // Sort by score desc, then total desc — high-value sources at the top.
    out.sort((a, b) => b.actionabilityScore - a.actionabilityScore || b.totalFindings - a.totalFindings);
    return out;
  },

  getOsintSourceQuadrant(opts?: { tenantId?: string }): import("@shared/schema").OsintSourceQuadrantPoint[] {
    const card = storage.getOsintSourceScorecard(opts);
    // 30-day window — volumePerDay = totalFindings / 30 (continuous, since we
    // don't require the source to have hit every day).
    return card.map((r) => ({
      sourceId: r.sourceId,
      name: r.name,
      categoryLabel: r.categoryLabel,
      volumePerDay: Math.round((r.totalFindings / 30) * 100) / 100,
      threatIntelRatio: r.threatIntelRatio,
      analystConversionRate: r.analystConversionRate,
      totalFindings: r.totalFindings,
    }));
  },

  getOsintSourceOverlap(opts?: { tenantId?: string }): import("@shared/schema").OsintSourceOverlapDTO {
    const tenantClause = opts?.tenantId ? " AND tenant_id = ?" : "";
    const tenantParam: any[] = opts?.tenantId ? [opts.tenantId] : [];
    const since30 = new Date(Date.now() - 30 * 86400_000).toISOString();
    const sourceMeta = new Map(storage.listOsintSources().map((s) => [s.id, s]));

    // Pull every clustered finding in the window so we can group by cluster.
    const rows = sqlite.prepare(`
      SELECT id, source_id as sid, cluster_id, published_at
      FROM osint_findings
      WHERE COALESCE(published_at, created_at) >= ?${tenantClause}
        AND cluster_id IS NOT NULL
    `).all(since30, ...tenantParam) as Array<{ id: string; sid: string; cluster_id: string; published_at: string }>;

    // Per-source counters.
    const totalBySrc = new Map<string, number>();
    const uniqueBySrc = new Map<string, number>();
    const firstBySrc = new Map<string, number>();
    const shareTotalBySrc = new Map<string, number>();

    // Group findings by cluster.
    const clusters = new Map<string, Array<{ id: string; sid: string; pub: string }>>();
    for (const r of rows) {
      totalBySrc.set(r.sid, (totalBySrc.get(r.sid) ?? 0) + 1);
      const arr = clusters.get(r.cluster_id) ?? [];
      arr.push({ id: r.id, sid: r.sid, pub: r.published_at });
      clusters.set(r.cluster_id, arr);
    }

    // Per-source x per-source co-occurrence (top-15 by total).
    const topSources = Array.from(totalBySrc.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([sid]) => sid);
    const sIdx = new Map(topSources.map((s, i) => [s, i]));
    const N = topSources.length;
    const matrix: number[][] = Array.from({ length: N }, () => Array(N).fill(0));

    for (const [, members] of clusters) {
      const uniqSrcs = Array.from(new Set(members.map((m) => m.sid)));
      // Unique-rate: cluster has exactly one distinct source.
      if (uniqSrcs.length === 1) {
        uniqueBySrc.set(uniqSrcs[0], (uniqueBySrc.get(uniqSrcs[0]) ?? 0) + members.length);
      } else {
        // First-to-publish: earliest published_at among members.
        let firstSrc = members[0].sid;
        let firstPub = members[0].pub;
        for (const m of members) {
          if (m.pub && (m.pub < firstPub || !firstPub)) { firstPub = m.pub; firstSrc = m.sid; }
        }
        firstBySrc.set(firstSrc, (firstBySrc.get(firstSrc) ?? 0) + 1);
        for (const s of uniqSrcs) shareTotalBySrc.set(s, (shareTotalBySrc.get(s) ?? 0) + 1);
        // Co-occurrence: every pair of distinct sources in the cluster gets +1.
        for (let i = 0; i < uniqSrcs.length; i++) {
          const a = sIdx.get(uniqSrcs[i]);
          if (a === undefined) continue;
          matrix[a][a] += 1; // own cluster count (multi-source clusters only)
          for (let j = i + 1; j < uniqSrcs.length; j++) {
            const b = sIdx.get(uniqSrcs[j]);
            if (b === undefined) continue;
            matrix[a][b] += 1;
            matrix[b][a] += 1;
          }
        }
      }
    }

    const nameOf = (sid: string) => {
      const src = sourceMeta.get(sid);
      return src ? translateSourceName(src.name, src.language) : sid;
    };

    const uniqueRate = Array.from(totalBySrc.entries()).map(([sid, total]) => {
      const uniqueCount = uniqueBySrc.get(sid) ?? 0;
      return {
        sourceId: sid,
        name: nameOf(sid),
        uniqueRate: total > 0 ? Math.round((uniqueCount / total) * 1000) / 1000 : 0,
        total,
        uniqueCount,
      };
    }).sort((a, b) => b.total - a.total).slice(0, 20);

    const firstToPublish = Array.from(firstBySrc.entries()).map(([sid, firstCount]) => ({
      sourceId: sid,
      name: nameOf(sid),
      firstCount,
      shareTotal: shareTotalBySrc.get(sid) ?? 0,
    })).sort((a, b) => b.firstCount - a.firstCount).slice(0, 15);

    return {
      uniqueRate,
      firstToPublish,
      coOccurrence: {
        sourceIds: topSources,
        sourceNames: topSources.map(nameOf),
        matrix,
      },
    };
  },

  getOsintSourceHeatmaps(opts?: { tenantId?: string }): import("@shared/schema").OsintSourceHeatmapsDTO {
    const tenantClause = opts?.tenantId ? " AND tenant_id = ?" : "";
    const tenantParam: any[] = opts?.tenantId ? [opts.tenantId] : [];
    const since30 = new Date(Date.now() - 30 * 86400_000).toISOString();
    const sourceMeta = new Map(storage.listOsintSources().map((s) => [s.id, s]));

    // Pull all relevant fields for the window once.
    const rows = sqlite.prepare(`
      SELECT source_id as sid, attack_techniques, sectors, regions
      FROM osint_findings
      WHERE COALESCE(published_at, created_at) >= ?${tenantClause}
    `).all(since30, ...tenantParam) as Array<{ sid: string; attack_techniques: string | null; sectors: string | null; regions: string | null }>;

    // ATT&CK tactic mapping. We bucket techniques into 14 canonical Enterprise
    // tactics for human readability; the source data is technique-level.
    // (Detail technique counts are still available via individual finding pages.)
    const TACTIC_MAP: Record<string, { id: string; label: string }> = {
      // Reconnaissance
      "T1595": { id: "TA0043", label: "Reconnaissance" }, "T1592": { id: "TA0043", label: "Reconnaissance" },
      "T1589": { id: "TA0043", label: "Reconnaissance" }, "T1590": { id: "TA0043", label: "Reconnaissance" },
      "T1591": { id: "TA0043", label: "Reconnaissance" }, "T1593": { id: "TA0043", label: "Reconnaissance" },
      "T1594": { id: "TA0043", label: "Reconnaissance" }, "T1596": { id: "TA0043", label: "Reconnaissance" }, "T1597": { id: "TA0043", label: "Reconnaissance" }, "T1598": { id: "TA0043", label: "Reconnaissance" },
      // Resource Development
      "T1583": { id: "TA0042", label: "Resource Development" }, "T1584": { id: "TA0042", label: "Resource Development" }, "T1585": { id: "TA0042", label: "Resource Development" }, "T1586": { id: "TA0042", label: "Resource Development" }, "T1587": { id: "TA0042", label: "Resource Development" }, "T1588": { id: "TA0042", label: "Resource Development" }, "T1608": { id: "TA0042", label: "Resource Development" },
      // Initial Access
      "T1078": { id: "TA0001", label: "Initial Access" }, "T1133": { id: "TA0001", label: "Initial Access" }, "T1190": { id: "TA0001", label: "Initial Access" }, "T1189": { id: "TA0001", label: "Initial Access" }, "T1199": { id: "TA0001", label: "Initial Access" }, "T1200": { id: "TA0001", label: "Initial Access" }, "T1566": { id: "TA0001", label: "Initial Access" }, "T1091": { id: "TA0001", label: "Initial Access" }, "T1195": { id: "TA0001", label: "Initial Access" },
      // Execution
      "T1059": { id: "TA0002", label: "Execution" }, "T1106": { id: "TA0002", label: "Execution" }, "T1129": { id: "TA0002", label: "Execution" }, "T1203": { id: "TA0002", label: "Execution" }, "T1204": { id: "TA0002", label: "Execution" }, "T1559": { id: "TA0002", label: "Execution" }, "T1569": { id: "TA0002", label: "Execution" }, "T1610": { id: "TA0002", label: "Execution" }, "T1053": { id: "TA0002", label: "Execution" },
      // Persistence
      "T1098": { id: "TA0003", label: "Persistence" }, "T1136": { id: "TA0003", label: "Persistence" }, "T1137": { id: "TA0003", label: "Persistence" }, "T1176": { id: "TA0003", label: "Persistence" }, "T1505": { id: "TA0003", label: "Persistence" }, "T1543": { id: "TA0003", label: "Persistence" }, "T1546": { id: "TA0003", label: "Persistence" }, "T1547": { id: "TA0003", label: "Persistence" }, "T1554": { id: "TA0003", label: "Persistence" }, "T1556": { id: "TA0003", label: "Persistence" }, "T1574": { id: "TA0003", label: "Persistence" }, "T1525": { id: "TA0003", label: "Persistence" },
      // Privilege Escalation
      "T1548": { id: "TA0004", label: "Privilege Escalation" }, "T1484": { id: "TA0004", label: "Privilege Escalation" }, "T1611": { id: "TA0004", label: "Privilege Escalation" }, "T1068": { id: "TA0004", label: "Privilege Escalation" }, "T1055": { id: "TA0004", label: "Privilege Escalation" }, "T1134": { id: "TA0004", label: "Privilege Escalation" },
      // Defense Evasion
      "T1027": { id: "TA0005", label: "Defense Evasion" }, "T1036": { id: "TA0005", label: "Defense Evasion" }, "T1070": { id: "TA0005", label: "Defense Evasion" }, "T1112": { id: "TA0005", label: "Defense Evasion" }, "T1140": { id: "TA0005", label: "Defense Evasion" }, "T1197": { id: "TA0005", label: "Defense Evasion" }, "T1202": { id: "TA0005", label: "Defense Evasion" }, "T1207": { id: "TA0005", label: "Defense Evasion" }, "T1211": { id: "TA0005", label: "Defense Evasion" }, "T1218": { id: "TA0005", label: "Defense Evasion" }, "T1222": { id: "TA0005", label: "Defense Evasion" }, "T1480": { id: "TA0005", label: "Defense Evasion" }, "T1497": { id: "TA0005", label: "Defense Evasion" }, "T1535": { id: "TA0005", label: "Defense Evasion" }, "T1542": { id: "TA0005", label: "Defense Evasion" }, "T1553": { id: "TA0005", label: "Defense Evasion" }, "T1562": { id: "TA0005", label: "Defense Evasion" }, "T1564": { id: "TA0005", label: "Defense Evasion" }, "T1578": { id: "TA0005", label: "Defense Evasion" }, "T1600": { id: "TA0005", label: "Defense Evasion" }, "T1620": { id: "TA0005", label: "Defense Evasion" },
      // Credential Access
      "T1110": { id: "TA0006", label: "Credential Access" }, "T1187": { id: "TA0006", label: "Credential Access" }, "T1212": { id: "TA0006", label: "Credential Access" }, "T1539": { id: "TA0006", label: "Credential Access" }, "T1552": { id: "TA0006", label: "Credential Access" }, "T1555": { id: "TA0006", label: "Credential Access" }, "T1557": { id: "TA0006", label: "Credential Access" }, "T1558": { id: "TA0006", label: "Credential Access" }, "T1606": { id: "TA0006", label: "Credential Access" }, "T1003": { id: "TA0006", label: "Credential Access" }, "T1040": { id: "TA0006", label: "Credential Access" }, "T1056": { id: "TA0006", label: "Credential Access" }, "T1111": { id: "TA0006", label: "Credential Access" },
      // Discovery
      "T1007": { id: "TA0007", label: "Discovery" }, "T1010": { id: "TA0007", label: "Discovery" }, "T1012": { id: "TA0007", label: "Discovery" }, "T1016": { id: "TA0007", label: "Discovery" }, "T1018": { id: "TA0007", label: "Discovery" }, "T1033": { id: "TA0007", label: "Discovery" }, "T1046": { id: "TA0007", label: "Discovery" }, "T1049": { id: "TA0007", label: "Discovery" }, "T1057": { id: "TA0007", label: "Discovery" }, "T1069": { id: "TA0007", label: "Discovery" }, "T1082": { id: "TA0007", label: "Discovery" }, "T1083": { id: "TA0007", label: "Discovery" }, "T1087": { id: "TA0007", label: "Discovery" }, "T1120": { id: "TA0007", label: "Discovery" }, "T1124": { id: "TA0007", label: "Discovery" }, "T1135": { id: "TA0007", label: "Discovery" }, "T1201": { id: "TA0007", label: "Discovery" }, "T1217": { id: "TA0007", label: "Discovery" }, "T1482": { id: "TA0007", label: "Discovery" }, "T1518": { id: "TA0007", label: "Discovery" }, "T1580": { id: "TA0007", label: "Discovery" }, "T1614": { id: "TA0007", label: "Discovery" }, "T1615": { id: "TA0007", label: "Discovery" }, "T1619": { id: "TA0007", label: "Discovery" },
      // Lateral Movement
      "T1021": { id: "TA0008", label: "Lateral Movement" }, "T1080": { id: "TA0008", label: "Lateral Movement" }, "T1210": { id: "TA0008", label: "Lateral Movement" }, "T1534": { id: "TA0008", label: "Lateral Movement" }, "T1550": { id: "TA0008", label: "Lateral Movement" }, "T1563": { id: "TA0008", label: "Lateral Movement" }, "T1570": { id: "TA0008", label: "Lateral Movement" }, "T1072": { id: "TA0008", label: "Lateral Movement" }, "T1601": { id: "TA0008", label: "Lateral Movement" },
      // Collection
      "T1005": { id: "TA0009", label: "Collection" }, "T1025": { id: "TA0009", label: "Collection" }, "T1039": { id: "TA0009", label: "Collection" }, "T1074": { id: "TA0009", label: "Collection" }, "T1113": { id: "TA0009", label: "Collection" }, "T1114": { id: "TA0009", label: "Collection" }, "T1115": { id: "TA0009", label: "Collection" }, "T1119": { id: "TA0009", label: "Collection" }, "T1123": { id: "TA0009", label: "Collection" }, "T1125": { id: "TA0009", label: "Collection" }, "T1185": { id: "TA0009", label: "Collection" }, "T1213": { id: "TA0009", label: "Collection" }, "T1530": { id: "TA0009", label: "Collection" }, "T1602": { id: "TA0009", label: "Collection" },
      // Command and Control
      "T1071": { id: "TA0011", label: "Command & Control" }, "T1090": { id: "TA0011", label: "Command & Control" }, "T1092": { id: "TA0011", label: "Command & Control" }, "T1095": { id: "TA0011", label: "Command & Control" }, "T1102": { id: "TA0011", label: "Command & Control" }, "T1104": { id: "TA0011", label: "Command & Control" }, "T1105": { id: "TA0011", label: "Command & Control" }, "T1132": { id: "TA0011", label: "Command & Control" }, "T1205": { id: "TA0011", label: "Command & Control" }, "T1219": { id: "TA0011", label: "Command & Control" }, "T1568": { id: "TA0011", label: "Command & Control" }, "T1571": { id: "TA0011", label: "Command & Control" }, "T1572": { id: "TA0011", label: "Command & Control" }, "T1573": { id: "TA0011", label: "Command & Control" }, "T1001": { id: "TA0011", label: "Command & Control" }, "T1008": { id: "TA0011", label: "Command & Control" }, "T1029": { id: "TA0011", label: "Command & Control" }, "T1030": { id: "TA0011", label: "Command & Control" },
      // Exfiltration
      "T1011": { id: "TA0010", label: "Exfiltration" }, "T1020": { id: "TA0010", label: "Exfiltration" }, "T1041": { id: "TA0010", label: "Exfiltration" }, "T1048": { id: "TA0010", label: "Exfiltration" }, "T1052": { id: "TA0010", label: "Exfiltration" }, "T1567": { id: "TA0010", label: "Exfiltration" },
      // Impact
      "T1485": { id: "TA0040", label: "Impact" }, "T1486": { id: "TA0040", label: "Impact" }, "T1489": { id: "TA0040", label: "Impact" }, "T1490": { id: "TA0040", label: "Impact" }, "T1491": { id: "TA0040", label: "Impact" }, "T1496": { id: "TA0040", label: "Impact" }, "T1498": { id: "TA0040", label: "Impact" }, "T1499": { id: "TA0040", label: "Impact" }, "T1529": { id: "TA0040", label: "Impact" }, "T1531": { id: "TA0040", label: "Impact" }, "T1561": { id: "TA0040", label: "Impact" }, "T1565": { id: "TA0040", label: "Impact" }, "T1657": { id: "TA0040", label: "Impact" },
    };

    // Aggregate counts per (source, tactic) and per (source, sector/region).
    const tacticBySrc = new Map<string, Map<string, number>>();
    const dimensionBySrc = new Map<string, Map<string, number>>();
    const tacticTotals = new Map<string, number>();
    const dimTotals = new Map<string, number>();
    const srcTotals = new Map<string, number>();

    const inc = (m: Map<string, Map<string, number>>, sid: string, key: string) => {
      const slot = m.get(sid) ?? new Map<string, number>();
      slot.set(key, (slot.get(key) ?? 0) + 1);
      m.set(sid, slot);
    };

    for (const r of rows) {
      srcTotals.set(r.sid, (srcTotals.get(r.sid) ?? 0) + 1);
      // ATT&CK techniques — each entry contributes to its parent tactic.
      try {
        const arr = r.attack_techniques ? JSON.parse(r.attack_techniques) : null;
        if (Array.isArray(arr)) {
          const seen = new Set<string>();
          for (const t of arr) {
            const techId = String((t && typeof t === "object" && t.id) ? t.id : t || "").toUpperCase().split(".")[0];
            if (!/^T[0-9]{4}$/.test(techId)) continue;
            const tac = TACTIC_MAP[techId];
            if (!tac) continue;
            if (seen.has(tac.id)) continue;
            seen.add(tac.id);
            inc(tacticBySrc, r.sid, tac.id);
            tacticTotals.set(tac.id, (tacticTotals.get(tac.id) ?? 0) + 1);
          }
        }
      } catch { /* ignore */ }
      // Sectors + regions — unified dimension list. Prefix with kind so they
      // don't collide when a region and sector share a short token.
      const pushDim = (val: unknown, prefix: string) => {
        try {
          const arr = typeof val === "string" ? JSON.parse(val) : null;
          if (!Array.isArray(arr)) return;
          const seen = new Set<string>();
          for (const x of arr) {
            const k = String(x || "").trim().toLowerCase();
            if (!k) continue;
            const dim = `${prefix}:${k}`;
            if (seen.has(dim)) continue;
            seen.add(dim);
            inc(dimensionBySrc, r.sid, dim);
            dimTotals.set(dim, (dimTotals.get(dim) ?? 0) + 1);
          }
        } catch { /* ignore */ }
      };
      pushDim(r.sectors, "sector");
      pushDim(r.regions, "region");
    }

    // Pick top-N sources (by total findings) and top-N dimensions / tactics.
    const TOP_SOURCES = 12;
    const TOP_DIMS = 12;
    const topSrcs = Array.from(srcTotals.entries())
      .sort((a, b) => b[1] - a[1]).slice(0, TOP_SOURCES).map(([s]) => s);
    const nameOf = (sid: string) => {
      const src = sourceMeta.get(sid);
      return src ? translateSourceName(src.name, src.language) : sid;
    };

    // ATT&CK matrix: 12 tactics, ordered TA0043, TA0042, TA0001..TA0040.
    const tacticOrder = [
      "TA0043","TA0042","TA0001","TA0002","TA0003","TA0004","TA0005",
      "TA0006","TA0007","TA0008","TA0009","TA0011","TA0010","TA0040",
    ];
    const tacticLabel: Record<string, string> = {
      TA0043: "Reconnaissance", TA0042: "Resource Dev", TA0001: "Initial Access",
      TA0002: "Execution", TA0003: "Persistence", TA0004: "Priv Escalation",
      TA0005: "Defense Evasion", TA0006: "Credential Access", TA0007: "Discovery",
      TA0008: "Lateral Movement", TA0009: "Collection", TA0011: "C2",
      TA0010: "Exfiltration", TA0040: "Impact",
    };
    // Only emit tactics that have at least one hit (otherwise the heatmap is mostly empty).
    const tacticsUsed = tacticOrder.filter((t) => (tacticTotals.get(t) ?? 0) > 0);
    const attackMatrix: number[][] = topSrcs.map((sid) =>
      tacticsUsed.map((t) => (tacticBySrc.get(sid)?.get(t) ?? 0)),
    );

    // Sectors+regions matrix: top dimensions by total.
    const topDims = Array.from(dimTotals.entries())
      .sort((a, b) => b[1] - a[1]).slice(0, TOP_DIMS).map(([d]) => d);
    const sectorsMatrix: number[][] = topSrcs.map((sid) =>
      topDims.map((d) => (dimensionBySrc.get(sid)?.get(d) ?? 0)),
    );

    return {
      attack: {
        sourceIds: topSrcs,
        sourceNames: topSrcs.map(nameOf),
        tactics: tacticsUsed,
        tacticLabels: tacticsUsed.map((t) => tacticLabel[t] ?? t),
        matrix: attackMatrix,
      },
      sectors: {
        sourceIds: topSrcs,
        sourceNames: topSrcs.map(nameOf),
        dimensions: topDims,
        matrix: sectorsMatrix,
      },
    };
  },

  // -------------------------------------------------------------------------
  // v2.30 — Admin "Re-analyse last 30 days" async job.
  // -------------------------------------------------------------------------

  createOsintReanalyzeJob(
    tid: string,
    opts: { sinceDays?: number; onlyUnanalyzed?: boolean; ids?: string[] },
  ): import("@shared/schema").OsintReanalyzeJobDTO {
    const jobId = randomUUID();
    const sinceDays = Math.max(1, Math.min(opts.sinceDays ?? 30, 365));
    const sinceIso = new Date(Date.now() - sinceDays * 86400_000).toISOString();
    const onlyUnanalyzed = !!opts.onlyUnanalyzed;
    const explicitIds = Array.isArray(opts.ids) && opts.ids.length > 0 ? opts.ids.slice() : null;
    // Compute total. Three scopes:
    //   1) explicit ids   → count of given ids that exist in this tenant
    //   2) onlyUnanalyzed → unanalyzed findings in window
    //   3) default       → all findings in window
    let total = 0;
    if (explicitIds) {
      const placeholders = explicitIds.map(() => "?").join(",");
      const row = sqlite.prepare(
        `SELECT COUNT(*) as n FROM osint_findings WHERE tenant_id = ? AND id IN (${placeholders})`,
      ).get(tid, ...explicitIds) as { n: number };
      total = row?.n ?? 0;
    } else if (onlyUnanalyzed) {
      const row = sqlite.prepare(`
        SELECT COUNT(*) as n FROM osint_findings
        WHERE tenant_id = ? AND COALESCE(published_at, created_at) >= ? AND ai_analyzed_at IS NULL
      `).get(tid, sinceIso) as { n: number };
      total = row?.n ?? 0;
    } else {
      const row = sqlite.prepare(`
        SELECT COUNT(*) as n FROM osint_findings
        WHERE tenant_id = ? AND COALESCE(published_at, created_at) >= ?
      `).get(tid, sinceIso) as { n: number };
      total = row?.n ?? 0;
    }
    const startedAt = now();
    sqlite.prepare(`
      INSERT INTO osint_reanalyze_jobs (id, tenant_id, status, total_count, done_count, fail_count, started_at)
      VALUES (?, ?, 'queued', ?, 0, 0, ?)
    `).run(jobId, tid, total, startedAt);
    // Kick off the worker (fire-and-forget). It updates row state as it goes.
    setTimeout(() => {
      storage._runReanalyzeJob(jobId, tid, sinceIso, { onlyUnanalyzed, ids: explicitIds })
        .catch((e) => console.warn("[reanalyze] job failed", e));
    }, 50);
    return { id: jobId, status: "queued", totalCount: total, doneCount: 0, failCount: 0, startedAt, finishedAt: null, error: null };
  },

  getOsintReanalyzeJob(tid: string, jobId: string): import("@shared/schema").OsintReanalyzeJobDTO | undefined {
    const row = sqlite.prepare(`
      SELECT * FROM osint_reanalyze_jobs WHERE id = ? AND tenant_id = ?
    `).get(jobId, tid) as any;
    if (!row) return undefined;
    return {
      id: row.id,
      status: row.status,
      totalCount: row.total_count,
      doneCount: row.done_count,
      failCount: row.fail_count,
      startedAt: row.started_at,
      finishedAt: row.finished_at,
      error: row.error,
    };
  },

  cancelOsintReanalyzeJob(tid: string, jobId: string, actor?: string | null): { ok: boolean; status: string; message?: string } {
    const row = sqlite.prepare(
      "SELECT id, status FROM osint_reanalyze_jobs WHERE id = ? AND tenant_id = ?",
    ).get(jobId, tid) as { id: string; status: string } | undefined;
    if (!row) return { ok: false, status: "not_found", message: "OSINT reanalysis job not found for this tenant." };
    if (row.status !== "queued" && row.status !== "running") {
      return { ok: false, status: row.status, message: `OSINT reanalysis job already ${row.status}.` };
    }
    sqlite.prepare(
      `UPDATE osint_reanalyze_jobs
         SET status = 'cancelled',
             finished_at = ?,
             error = ?
       WHERE id = ? AND tenant_id = ? AND status IN ('queued','running')`,
    ).run(now(), `Cancelled by ${actor || "operator"}.`, jobId, tid);
    return { ok: true, status: "cancelled" };
  },

  async _runReanalyzeJob(
    jobId: string,
    tid: string,
    sinceIso: string,
    extra?: { onlyUnanalyzed?: boolean; ids?: string[] | null },
  ): Promise<void> {
    // Mark running.
    sqlite.prepare(`UPDATE osint_reanalyze_jobs SET status = 'running' WHERE id = ? AND status = 'queued'`).run(jobId);
    const initial = sqlite.prepare("SELECT status FROM osint_reanalyze_jobs WHERE id = ? AND tenant_id = ?").get(jobId, tid) as { status: string } | undefined;
    if (initial?.status === "cancelled") return;
    const onlyUnanalyzed = !!extra?.onlyUnanalyzed;
    const explicitIds = extra?.ids && extra.ids.length > 0 ? extra.ids : null;
    let ids: string[];
    if (explicitIds) {
      const placeholders = explicitIds.map(() => "?").join(",");
      ids = (sqlite.prepare(
        `SELECT id FROM osint_findings WHERE tenant_id = ? AND id IN (${placeholders}) ORDER BY published_at ASC`,
      ).all(tid, ...explicitIds) as Array<{ id: string }>).map((r) => r.id);
    } else if (onlyUnanalyzed) {
      ids = (sqlite.prepare(`
        SELECT id FROM osint_findings
        WHERE tenant_id = ? AND COALESCE(published_at, created_at) >= ? AND ai_analyzed_at IS NULL
        ORDER BY published_at ASC
      `).all(tid, sinceIso) as Array<{ id: string }>).map((r) => r.id);
    } else {
      ids = (sqlite.prepare(`
        SELECT id FROM osint_findings
        WHERE tenant_id = ? AND COALESCE(published_at, created_at) >= ?
        ORDER BY published_at ASC
      `).all(tid, sinceIso) as Array<{ id: string }>).map((r) => r.id);
    }

    const BATCH = 5;
    let done = 0, fail = 0;
    for (let i = 0; i < ids.length; i += BATCH) {
      const current = sqlite.prepare("SELECT status FROM osint_reanalyze_jobs WHERE id = ? AND tenant_id = ?").get(jobId, tid) as { status: string } | undefined;
      if (current?.status === "cancelled") return;
      const slice = ids.slice(i, i + BATCH);
      try {
        const res = await storage.runOsintAnalysis(tid, { ids: slice });
        done += res.count;
        fail += slice.length - res.count;
      } catch {
        fail += slice.length;
      }
      sqlite.prepare(`UPDATE osint_reanalyze_jobs SET done_count = ?, fail_count = ? WHERE id = ? AND status != 'cancelled'`).run(done, fail, jobId);
    }
    // Also re-run cluster backfill for the tenant’s findings in the window.
    try {
      const cls = backfillClusters(sqlite, { sinceIso, limit: 50000 });
      console.log(`[reanalyze] cluster backfill scanned=${cls.scanned} assigned=${cls.assigned}`);
    } catch (e) { console.warn("[reanalyze] cluster backfill failed", e); }
    sqlite.prepare(`UPDATE osint_reanalyze_jobs SET status = 'done', finished_at = ? WHERE id = ? AND status != 'cancelled'`).run(now(), jobId);
  },

  countOsintSourcesByCategory(): Array<{ category: string; label: string; count: number }> {
    const rows = sqlite.prepare("SELECT category, COUNT(*) as count FROM osint_sources GROUP BY category").all() as any[];
    // v2.10: emit in OSINT_CATEGORY_ORDER so the Sources tab dropdown matches
    // the Findings-tab order (CVE_VULN → CERT_GOV → VENDOR_RESEARCH →
    // SECURITY_NEWS → RANSOMWARE_LEAK).
    const byCat = new Map<string, number>(rows.map((r) => [r.category as string, r.count as number]));
    return OSINT_CATEGORY_ORDER
      .filter((c) => byCat.has(c))
      .map((c) => ({
        category: c,
        label: OSINT_CATEGORY_LABELS[c] ?? c,
        count: byCat.get(c) ?? 0,
      }));
  },

  /**
   * Run an OSINT scan: derive findings deterministically from the tenant's
   * monitored technologies, the OSINT source catalog, and a few stock CVE templates.
   * The seed mixes tenant + tech to ensure same-tenant determinism but inter-tenant variance.
   */
  async runOsintScan(tid: string, opts: { technologies?: string[]; categories?: string[]; maxFindings?: number; mode?: "real" | "mock" | "auto" }): Promise<{ count: number; findings: OsintFindingDTO[]; mode: string; feedsTried?: number; feedsOk?: number; errors?: string[] }> {
    const techs = (opts.technologies && opts.technologies.length)
      ? opts.technologies
      : BATCH_ONE_WORKSPACE_PROFILE.monitoredTechnologies;
    if (techs.length === 0) {
      return { count: 0, findings: [], mode: "none" };
    }
    const max = opts.maxFindings ?? 60;
    const mode = opts.mode ?? "auto";

    // ---- Try real feeds first if mode is real or auto ----
    let realResult: { items: any[]; feedsTried: number; feedsOk: number; errors: string[] } | null = null;
    if (mode !== "mock") {
      try {
        const { fetchRealOsintItems } = await import("./osintFetcher");
        realResult = await fetchRealOsintItems({ techs, maxItems: max });
      } catch (e: any) {
        realResult = { items: [], feedsTried: 0, feedsOk: 0, errors: [String(e?.message || e)] };
      }
    }

    if (realResult && realResult.items.length > 0) {
      // Persist real items into the same osint_findings table.
      // Find or create a synthetic OsintSource per real source name so the
      // Sources tab and finding rows display the actual feed name.
      const items: OsintFindingDTO[] = [];
      const tx = sqlite.transaction(() => {
        const allSources = storage.listOsintSources();
        const byId = new Map(allSources.map((s) => [s.id, s]));
        const byName = new Map(allSources.map((s) => [s.name.toLowerCase(), s]));
        const fetchedSourceIds = new Set<string>();
        for (const it of realResult!.items) {
          // Prefer canonical sourceId from the catalog (v2.7 parsers attach this).
          let src = it.sourceId ? byId.get(it.sourceId) : undefined;
          if (!src) src = byName.get(it.sourceName.toLowerCase()) ?? allSources.find((s) => s.name === it.sourceName);
          if (!src) {
            // Insert a new synthetic source row keyed on the real feed name so
            // future findings (and the Sources tab) reuse it.
            const sid = id();
            sqlite.prepare(
              `INSERT INTO osint_sources (id, category, name, url, language, region, reliability, enabled)
               VALUES (?, ?, ?, ?, 'en', NULL, 'A', 1)`
            ).run(sid, it.sourceCategory, it.sourceName, it.sourceUrl);
            src = { id: sid, category: it.sourceCategory, name: it.sourceName, url: it.sourceUrl, reliability: "A", region: null, language: "en" } as any;
          }
          if (!src) continue;
          fetchedSourceIds.add(src.id);
          const fid = id();
          const cveIds = it.cveIds.slice(0, 8);
          sqlite.prepare(`INSERT INTO osint_findings (
            id, tenant_id, source_id, title, url, published_at, severity,
            cve_ids, affected_tech, threat_actors, summary, raw_snippet,
            ai_summary, ai_relevance_score, ai_recommendation, ai_analyzed_at, ai_provider_label,
            draft_email, draft_email_at, status, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'new', ?)`).run(
            fid, tid, src.id, it.title.slice(0, 280), it.url, it.publishedAt, it.severity,
            j(cveIds), j(it.affectedTech), j(it.threatActors), it.summary, it.rawSnippet, now()
          );
          items.push({
            id: fid, tenantId: tid, sourceId: src.id,
            sourceName: it.sourceName, sourceCategory: it.sourceCategory,
            title: it.title, url: it.url, publishedAt: it.publishedAt, severity: it.severity,
            cveIds, affectedTech: it.affectedTech, threatActors: it.threatActors,
            summary: it.summary, aiSummary: null, aiRelevanceScore: null, aiRecommendation: null,
            aiAnalyzedAt: null, aiProviderLabel: null,
            draftEmail: null, draftEmailAt: null, status: "new", createdAt: now(),
          });
        }
        markOsintSourcesFetched(fetchedSourceIds);
      });
      tx();
      storage.appendAudit(tid, "system", "osint.scan", null, {
        count: items.length, mode: "real", feedsTried: realResult.feedsTried, feedsOk: realResult.feedsOk, technologies: techs,
      });
      return {
        count: items.length, findings: items, mode: "real",
        feedsTried: realResult.feedsTried, feedsOk: realResult.feedsOk,
        errors: realResult.errors.slice(0, 5),
      };
    }

    // ---- Mock fallback (mode === 'mock' OR real feeds returned nothing) ----
    // Production-strict gate: when OPTRASIGHT_STRICT=1 (default in production),
    // refuse to silently synthesise findings. The caller gets a real-feed-only
    // empty result so the dashboard reflects ground truth.
    if (isStrictProduction() && mode !== "mock") {
      storage.appendAudit(tid, "system", "osint.scan", null, {
        count: 0, mode: "real", feedsTried: realResult?.feedsTried ?? 0, feedsOk: realResult?.feedsOk ?? 0, technologies: techs, strict: true,
      });
      return {
        count: 0, findings: [], mode: "real",
        feedsTried: realResult?.feedsTried ?? 0,
        feedsOk: realResult?.feedsOk ?? 0,
        errors: realResult?.errors.slice(0, 5) ?? [
          "No upstream feeds returned matching items (strict production mode — mock fallback disabled)",
        ],
      };
    }
    if (mode === "mock" && isStrictProduction()) {
      throw new MockFallbackBlockedError(
        "osint.scan",
        "Explicit mock mode requested while strict production is on.",
      );
    }
    if (mode === "real") {
      // User explicitly asked for real feeds; do not synthesise.
      storage.appendAudit(tid, "system", "osint.scan", null, {
        count: 0, mode: "real", feedsTried: realResult?.feedsTried ?? 0, feedsOk: realResult?.feedsOk ?? 0, technologies: techs,
      });
      return {
        count: 0, findings: [], mode: "real",
        feedsTried: realResult?.feedsTried ?? 0,
        feedsOk: realResult?.feedsOk ?? 0,
        errors: realResult?.errors.slice(0, 5) ?? ["No upstream feeds returned matching items"],
      };
    }
    const allSources = storage.listOsintSources(opts.categories?.length
      ? undefined : undefined);
    const sources = opts.categories?.length
      ? allSources.filter((s) => opts.categories!.includes(s.category))
      : allSources;
    if (sources.length === 0) return { count: 0, findings: [] };

    const techLabels = new Map<string, string>();
    for (const t of MONITORED_TECHNOLOGIES) techLabels.set(t.id, t.label);

    // Stock vulnerability templates per tech category
    const TEMPLATES: Array<{ tech: string; sev: string; titleFn: (label: string) => string; cve: string; actors: string[] }> = [
      { tech: "fortinet-fortios",     sev: "critical", titleFn: (l) => `${l} — pre-auth RCE in SSL-VPN (CVE-2024-21762)`, cve: "CVE-2024-21762", actors: ["UNC5221", "Volt Typhoon"] },
      { tech: "fortinet-fortimanager",sev: "critical", titleFn: (l) => `${l} — out-of-bound auth bypass`, cve: "CVE-2024-47575", actors: ["UNC5820"] },
      { tech: "citrix-netscaler",     sev: "critical", titleFn: (l) => `${l} — Citrix Bleed 2 session hijack`, cve: "CVE-2025-5777", actors: ["Lockbit", "AlphV"] },
      { tech: "ivanti-connectsecure", sev: "critical", titleFn: (l) => `${l} — chained auth bypass + RCE`, cve: "CVE-2025-22457", actors: ["UNC5221"] },
      { tech: "paloalto-globalprotect", sev: "high",    titleFn: (l) => `${l} — config disclosure`, cve: "CVE-2025-0108", actors: ["opportunistic"] },
      { tech: "sonicwall-sma",        sev: "high",     titleFn: (l) => `${l} — SQLi to admin takeover`, cve: "CVE-2024-53704", actors: ["FOG", "AKira"] },
      { tech: "checkpoint-quantum",   sev: "high",     titleFn: (l) => `${l} — info-disclosure on remote access blade`, cve: "CVE-2024-24919", actors: ["opportunistic"] },
      { tech: "cisco-asa",            sev: "high",     titleFn: (l) => `${l} — ArcaneDoor implant chain`, cve: "CVE-2024-20353", actors: ["UAT4356"] },
      { tech: "cisco-iosxe",          sev: "critical", titleFn: (l) => `${l} — webui priv-esc + persistence implant`, cve: "CVE-2023-20198", actors: ["opportunistic"] },
      { tech: "f5-bigip",             sev: "high",     titleFn: (l) => `${l} — TMUI auth bypass`, cve: "CVE-2023-46747", actors: ["opportunistic"] },
      { tech: "barracuda-esg",        sev: "critical", titleFn: (l) => `${l} — SeaSpy / Saltwater backdoor`, cve: "CVE-2023-2868", actors: ["UNC4841"] },
      { tech: "ms-exchange",          sev: "critical", titleFn: (l) => `${l} — pre-auth RCE chain (ProxyNotShell variant)`, cve: "CVE-2024-26198", actors: ["Storm-0558"] },
      { tech: "ms-sharepoint",        sev: "critical", titleFn: (l) => `${l} — ToolShell RCE`, cve: "CVE-2025-53770", actors: ["opportunistic"] },
      { tech: "zimbra",               sev: "high",     titleFn: (l) => `${l} — XSS to credential theft`, cve: "CVE-2024-45519", actors: ["Russian APT"] },
      { tech: "okta",                 sev: "high",     titleFn: (l) => `${l} — push fatigue + delegated admin abuse`, cve: "CVE-2024-XXXX", actors: ["Scattered Spider"] },
      { tech: "ms-entra",             sev: "high",     titleFn: (l) => `${l} — token replay via MFA bypass`, cve: "CVE-2025-XXXX", actors: ["Storm-0558"] },
      { tech: "adfs",                 sev: "high",     titleFn: (l) => `${l} — golden SAML", actor abuse`, cve: "", actors: ["APT29"] },
      { tech: "vmware-vcenter",       sev: "critical", titleFn: (l) => `${l} — DCERPC heap overflow`, cve: "CVE-2024-37079", actors: ["AKira", "BlackBasta"] },
      { tech: "vmware-esxi",          sev: "critical", titleFn: (l) => `${l} — ESXiArgs encryptor reuse`, cve: "CVE-2021-21974", actors: ["AKira", "Lockbit"] },
      { tech: "vmware-horizon",       sev: "high",     titleFn: (l) => `${l} — Log4Shell exposure persists`, cve: "CVE-2021-44228", actors: ["opportunistic"] },
      { tech: "atlassian-confluence", sev: "critical", titleFn: (l) => `${l} — improper authz (CVE-2023-22518)`, cve: "CVE-2023-22518", actors: ["C3RB3R"] },
      { tech: "atlassian-jira",       sev: "high",     titleFn: (l) => `${l} — Jira app auth bypass`, cve: "CVE-2024-1597", actors: ["opportunistic"] },
      { tech: "gitlab",               sev: "critical", titleFn: (l) => `${l} — account takeover via password reset`, cve: "CVE-2023-7028", actors: ["opportunistic"] },
      { tech: "github-enterprise",    sev: "high",     titleFn: (l) => `${l} — SAML auth bypass`, cve: "CVE-2024-4985", actors: ["opportunistic"] },
      { tech: "jenkins",              sev: "critical", titleFn: (l) => `${l} — arg injection RCE`, cve: "CVE-2024-23897", actors: ["opportunistic"] },
      { tech: "teamcity",             sev: "critical", titleFn: (l) => `${l} — auth bypass on web UI`, cve: "CVE-2024-27198", actors: ["BianLian", "AKira"] },
      { tech: "log4j",                sev: "critical", titleFn: (l) => `${l} — Log4Shell persists in legacy stacks`, cve: "CVE-2021-44228", actors: ["opportunistic"] },
      { tech: "spring-framework",     sev: "high",     titleFn: (l) => `${l} — Spring4Shell variants`, cve: "CVE-2022-22965", actors: ["opportunistic"] },
      { tech: "spring-cloud",         sev: "critical", titleFn: (l) => `${l} — Spring Cloud Gateway code injection`, cve: "CVE-2022-22947", actors: ["opportunistic"] },
      { tech: "struts2",              sev: "critical", titleFn: (l) => `${l} — file upload RCE", actor reuse`, cve: "CVE-2024-53677", actors: ["opportunistic"] },
      { tech: "apache-httpd",         sev: "high",     titleFn: (l) => `${l} — mod_rewrite SSRF`, cve: "CVE-2024-38475", actors: ["opportunistic"] },
      { tech: "tomcat",               sev: "high",     titleFn: (l) => `${l} — Tomcat RCE via partial PUT`, cve: "CVE-2025-24813", actors: ["opportunistic"] },
      { tech: "moveit",               sev: "critical", titleFn: (l) => `${l} — MOVEit SQLi RCE rerun`, cve: "CVE-2023-34362", actors: ["Cl0p"] },
      { tech: "goanywhere-mft",       sev: "critical", titleFn: (l) => `${l} — auth bypass (CVE-2024-0204)`, cve: "CVE-2024-0204", actors: ["Cl0p"] },
      { tech: "cleo-harmony",         sev: "critical", titleFn: (l) => `${l} — autorun directory RCE`, cve: "CVE-2024-50623", actors: ["Termite", "Cl0p"] },
      { tech: "veeam",                sev: "critical", titleFn: (l) => `${l} — backup auth bypass`, cve: "CVE-2024-40711", actors: ["Akira", "Lockbit"] },
      { tech: "connectwise-screenconnect", sev: "critical", titleFn: (l) => `${l} — auth bypass + path-traversal`, cve: "CVE-2024-1709", actors: ["opportunistic"] },
      { tech: "oracle-weblogic",      sev: "critical", titleFn: (l) => `${l} — IIOP/T3 deserialisation`, cve: "CVE-2024-21006", actors: ["opportunistic"] },
      { tech: "crowdstrike-falcon",   sev: "medium",   titleFn: (l) => `${l} — channel-file faulty content advisory`, cve: "", actors: ["n/a"] },
      { tech: "aws-iam",              sev: "high",     titleFn: (l) => `${l} — privilege escalation via misconfigured trust policy`, cve: "", actors: ["opportunistic"] },
    ];

    // Build candidate set, restricted to tenant's selected techs
    const eligible = TEMPLATES.filter((t) => techs.includes(t.tech));
    const baseSeed = (tid + techs.join("|")).split("").reduce((a, c) => (a * 33 + c.charCodeAt(0)) | 0, 7);
    const items: OsintFindingDTO[] = [];
    let inserted = 0;
    const tx = sqlite.transaction(() => {
      for (let i = 0; i < max && i < eligible.length * 4; i++) {
        const tmpl = eligible[i % Math.max(1, eligible.length)];
        if (!tmpl) break;
        const src = sources[((baseSeed + i * 17) >>> 0) % sources.length];
        const fid = id();
        const label = techLabels.get(tmpl.tech) ?? tmpl.tech;
        const publishedAt = new Date(Date.now() - ((i * 6) + (baseSeed % 24)) * 3600_000).toISOString();
        const url = src.url;
        const cveIds = tmpl.cve ? [tmpl.cve] : [];
        const summary = `Mock OSINT signal: ${tmpl.titleFn(label)}. Source: ${src.name} (${src.category}). Published: ${publishedAt.slice(0,10)}.`;
        const rawSnippet = `From ${src.name}\n\n${tmpl.titleFn(label)}\n\nThreat actors observed: ${tmpl.actors.join(", ")}.\n\nReferences: ${cveIds.join(", ") || "n/a"}`;
        sqlite.prepare(`INSERT INTO osint_findings (
          id, tenant_id, source_id, title, url, published_at, severity,
          cve_ids, affected_tech, threat_actors, summary, raw_snippet,
          ai_summary, ai_relevance_score, ai_recommendation, ai_analyzed_at, ai_provider_label,
          draft_email, draft_email_at, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'new', ?)`).run(
          fid, tid, src.id, tmpl.titleFn(label), url, publishedAt, tmpl.sev,
          j(cveIds), j([tmpl.tech]), j(tmpl.actors), summary, rawSnippet, now()
        );
        items.push({
          id: fid, tenantId: tid, sourceId: src.id,
          sourceName: src.name, sourceCategory: src.category,
          title: tmpl.titleFn(label), url, publishedAt, severity: tmpl.sev,
          cveIds, affectedTech: [tmpl.tech], threatActors: tmpl.actors,
          summary, aiSummary: null, aiRelevanceScore: null, aiRecommendation: null,
          aiAnalyzedAt: null, aiProviderLabel: null,
          draftEmail: null, draftEmailAt: null, status: "new", createdAt: now(),
        });
        inserted += 1;
      }
    });
    tx();
    storage.appendAudit(tid, "system", "osint.scan", null, { count: inserted, mode: "mock", technologies: techs });
    return {
      count: inserted, findings: items, mode: "mock",
      feedsTried: realResult?.feedsTried ?? 0,
      feedsOk: realResult?.feedsOk ?? 0,
      errors: realResult?.errors.slice(0, 5) ?? [],
    };
  },

  /**
   * v2.7 Broad OSINT ingest — fetches across the ENTIRE 514-source catalog
   * (deep custom parsers + generic adapter), persists every parsed item once
   * per active tenant, and skips the tenant-tech filter at ingest time.
   * BatchOne writes parsed source items into the single local workspace.
   */
  async runGlobalOsintIngest(opts?: {
    days?: number;             // backfill window in days; default 365
    maxPerSource?: number;     // hard cap per single source; default 60
    maxTotal?: number;         // hard cap on total parsed items; default 10000
    actor?: string;
    onProgress?: (progress: { attempted: number; total: number; parsed: number; feedsOk: number }) => void;
  }): Promise<{ count: number; workspaces: number; tenants: number; feedsTried: number; feedsOk: number; errors: string[]; durationMs: number }> {
    const t0 = Date.now();
    const days = opts?.days ?? 365;
    const maxPerSource = opts?.maxPerSource ?? 60;
    const maxTotal = opts?.maxTotal ?? 10000;
    const sinceIso = new Date(Date.now() - days * 86400_000).toISOString();

    const { runBroadIngest } = await import("./osintFetcher");
    const result = await runBroadIngest({ sinceIso, maxPerSource, maxTotal, onProgress: opts?.onProgress });

    const workspaceRows = sqlite.prepare("SELECT id FROM tenants LIMIT 1").all() as Array<{ id: string }>;
    const workspaceIds = workspaceRows.map((r) => r.id);
    if (workspaceIds.length === 0) {
      return { count: 0, workspaces: 0, tenants: 0, feedsTried: result.feedsTried, feedsOk: result.feedsOk, errors: result.errors, durationMs: Date.now() - t0 };
    }

    const allSources = storage.listOsintSources();
    const byId = new Map(allSources.map((s) => [s.id, s]));
    const byName = new Map(allSources.map((s) => [s.name.toLowerCase(), s]));
    // v2.9 — host-based lookup for defensive source re-resolution. If a parser
    // emits a sourceId whose feed host doesn't match the item URL's host, we
    // prefer the host match (e.g. DFIR Report mis-tagged as Hacker News).
    const byHost = new Map<string, typeof allSources[number]>();
    for (const s of allSources) {
      try {
        const h = new URL(s.url).hostname.toLowerCase().replace(/^www\./, "");
        if (h && !byHost.has(h)) byHost.set(h, s);
      } catch { /* skip non-URL */ }
    }
    const hostOf = (raw: string): string => {
      try { return new URL(raw).hostname.toLowerCase().replace(/^www\./, ""); } catch { return ""; }
    };

    // Dedupe within the local workspace by (scope, content_hash) and legacy
    // (scope, source, url). The content hash collapses cross-source reposts so
    // the analyst does not get duplicate advisories from RSS aggregators.
    // same advisory from different RSS aggregators.
    let inserted = 0;
    const insertStmt = sqlite.prepare(`INSERT OR IGNORE INTO osint_findings (
      id, tenant_id, source_id, title, url, published_at, severity,
      cve_ids, affected_tech, threat_actors, iocs, content_hash, summary, raw_snippet,
      ai_summary, ai_relevance_score, ai_recommendation, ai_analyzed_at, ai_provider_label,
      draft_email, draft_email_at, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'new', ?)`);

    // For each parsed item: resolve canonical source row, then insert one row per tenant.
    const existingKeySet = new Set<string>(
      (sqlite.prepare("SELECT tenant_id || '::' || source_id || '::' || substr(url, 1, 200) AS k FROM osint_findings").all() as Array<{ k: string }>).map((r) => r.k.toLowerCase())
    );
    // Per-workspace content-hash set for cross-source dedupe at write time.
    const existingHashSet = new Set<string>(
      (sqlite.prepare("SELECT tenant_id || '::' || COALESCE(content_hash, '') AS k FROM osint_findings WHERE content_hash IS NOT NULL AND content_hash != ''").all() as Array<{ k: string }>).map((r) => r.k.toLowerCase())
    );

    const tx = sqlite.transaction(() => {
      const fetchedSourceIds = new Set<string>();
      for (const it of result.items) {
        // Resolve canonical source.
        let src = it.sourceId ? byId.get(it.sourceId) : undefined;
        if (!src) src = byName.get(it.sourceName.toLowerCase());
        // v2.9 — defensive: if the resolved source's feed host doesn't match the
        // item URL's host, re-resolve by URL host. Prevents items from being
        // mis-attributed to a sibling source (e.g. thedfirreport.com items
        // mis-tagged with The Hacker News' source_id).
        if (src && it.url) {
          const itemHost = hostOf(it.url);
          const srcHost = hostOf(src.url);
          if (itemHost && srcHost && itemHost !== srcHost) {
            const byHostSrc = byHost.get(itemHost);
            if (byHostSrc) src = byHostSrc;
          }
        }
        if (!src) {
          const sid = id();
          sqlite.prepare(
            `INSERT INTO osint_sources (id, category, name, url, language, region, reliability, enabled)
             VALUES (?, ?, ?, ?, 'en', NULL, 'B', 1)`
          ).run(sid, it.sourceCategory, it.sourceName, it.sourceUrl);
          src = { id: sid, category: it.sourceCategory, name: it.sourceName, url: it.sourceUrl, reliability: "B", region: null, language: "en" } as any;
          byId.set(sid, src!);
          byName.set(it.sourceName.toLowerCase(), src!);
        }
        fetchedSourceIds.add(src.id);
        const cveIds = it.cveIds.slice(0, 8);
        const iocsJson = j((it as any).iocs || {});
        const contentHash = (it as any).contentHash || "";
        for (const tid of workspaceIds) {
          const urlKey = `${tid}::${src!.id}::${(it.url || it.title).slice(0, 200)}`.toLowerCase();
          if (existingKeySet.has(urlKey)) continue;
          const hashKey = contentHash ? `${tid}::${contentHash}`.toLowerCase() : "";
          if (hashKey && existingHashSet.has(hashKey)) continue;
          existingKeySet.add(urlKey);
          if (hashKey) existingHashSet.add(hashKey);
          const fid = id();
          insertStmt.run(
            fid, tid, src!.id, it.title.slice(0, 280), it.url, it.publishedAt, it.severity,
            j(cveIds), j(it.affectedTech), j(it.threatActors), iocsJson, contentHash || null,
            it.summary, it.rawSnippet, now(),
          );
          inserted += 1;
        }
      }
      markOsintSourcesFetched(fetchedSourceIds);
    });
    tx();

    storage.appendAudit(workspaceIds[0], opts?.actor ?? "system", "osint.global_ingest", null, {
      inserted, workspaces: workspaceIds.length, parsed: result.items.length,
      feedsTried: result.feedsTried, feedsOk: result.feedsOk, days,
    });

    return {
      count: inserted,
      workspaces: workspaceIds.length,
      tenants: workspaceIds.length,
      feedsTried: result.feedsTried,
      feedsOk: result.feedsOk,
      errors: result.errors,
      durationMs: Date.now() - t0,
    };
  },

  listOsintFindings(tid: string, opts?: { severity?: string; status?: string; tech?: string; sourceId?: string; category?: string }): OsintFindingDTO[] {
    const where: any[] = ["tenant_id = ?"];
    const params: any[] = [tid];
    if (opts?.severity) { where.push("severity = ?"); params.push(opts.severity); }
    if (opts?.status)   { where.push("status = ?"); params.push(opts.status); }
    if (opts?.sourceId) { where.push("source_id = ?"); params.push(opts.sourceId); }
    const sql = `SELECT * FROM osint_findings WHERE ${where.join(" AND ")} ORDER BY published_at DESC LIMIT 500`;
    const rows = sqlite.prepare(sql).all(...params) as any[];
    const sourceMap = new Map(storage.listOsintSources().map((s) => [s.id, s]));
    const out: OsintFindingDTO[] = [];
    const filterTech = opts?.tech?.trim().toUpperCase();
    for (const r of rows) {
      const techArr = JSON.parse(r.affected_tech || "[]") as string[];
      const attackTechniques = parseAttackTechniques(r.attack_techniques) || [];
      if (filterTech) {
        const affectedMatch = techArr.some((t) => String(t).trim().toUpperCase() === filterTech);
        const attackMatch = attackTechniques.some((t) => t.id.trim().toUpperCase() === filterTech);
        if (!affectedMatch && !attackMatch) continue;
      }
      const src = sourceMap.get(r.source_id);
      if (opts?.category && (src?.category ?? "") !== opts.category) continue;
      let iocs: any = {};
      try { iocs = JSON.parse(r.iocs || "{}"); } catch { iocs = {}; }
      out.push({
        id: r.id, tenantId: r.tenant_id, sourceId: r.source_id,
        sourceName: src?.name ?? "unknown", sourceCategory: src?.category ?? "unknown",
        title: r.title, url: r.url, publishedAt: r.published_at, severity: r.severity,
        cveIds: JSON.parse(r.cve_ids || "[]"),
        affectedTech: techArr,
        threatActors: JSON.parse(r.threat_actors || "[]"),
        iocs,
        summary: r.summary, aiSummary: r.ai_summary,
        aiRelevanceScore: r.ai_relevance_score, aiRecommendation: r.ai_recommendation,
        aiAnalyzedAt: r.ai_analyzed_at, aiProviderLabel: r.ai_provider_label,
        draftEmail: r.draft_email, draftEmailAt: r.draft_email_at,
        status: r.status, createdAt: r.created_at,
        analystTags: (() => { try { const v = JSON.parse(r.analyst_tags || "[]"); return Array.isArray(v) ? v : []; } catch { return []; } })(),
        analystEditedAt: r.analyst_edited_at,
        analystEditedBy: r.analyst_edited_by,
        intelCategory: (r.intel_category as any) ?? null,
        attackTechniques,
        sectors: parseJsonArray<string>(r.sectors),
        regions: parseJsonArray<string>(r.regions),
        clusterId: (r.cluster_id as any) ?? null,
      });
    }
    return out;
  },

  getOsintFinding(tid: string, fid: string): OsintFindingDTO | undefined {
    const r = sqlite.prepare("SELECT * FROM osint_findings WHERE id = ? AND tenant_id = ?").get(fid, tid) as any;
    if (!r) return undefined;
    const src = storage.listOsintSources().find((s) => s.id === r.source_id);
    let iocs: any = {};
    try { iocs = JSON.parse(r.iocs || "{}"); } catch { iocs = {}; }
    return {
      id: r.id, tenantId: r.tenant_id, sourceId: r.source_id,
      sourceName: src?.name ?? "unknown", sourceCategory: src?.category ?? "unknown",
      title: r.title, url: r.url, publishedAt: r.published_at, severity: r.severity,
      cveIds: JSON.parse(r.cve_ids || "[]"),
      affectedTech: JSON.parse(r.affected_tech || "[]"),
      threatActors: JSON.parse(r.threat_actors || "[]"),
      iocs,
      summary: r.summary, aiSummary: r.ai_summary,
      aiRelevanceScore: r.ai_relevance_score, aiRecommendation: r.ai_recommendation,
      aiAnalyzedAt: r.ai_analyzed_at, aiProviderLabel: r.ai_provider_label,
      draftEmail: r.draft_email, draftEmailAt: r.draft_email_at,
      status: r.status, createdAt: r.created_at,
      rawSnippet: r.raw_snippet,
      analystTags: (() => { try { const v = JSON.parse(r.analyst_tags || "[]"); return Array.isArray(v) ? v : []; } catch { return []; } })(),
      analystEditedAt: r.analyst_edited_at,
      analystEditedBy: r.analyst_edited_by,
      intelCategory: (r.intel_category as any) ?? null,
      attackTechniques: parseAttackTechniques(r.attack_techniques),
      sectors: parseJsonArray<string>(r.sectors),
      regions: parseJsonArray<string>(r.regions),
      clusterId: (r.cluster_id as any) ?? null,
    };
  },

  /** v2.18 — cross-tenant lookup. Used by Global-view CIRT triage + deep dive
   *  where the calling user is admin and the request body carries finding IDs
   *  that span multiple tenants. The tenant_id column is read straight out of
   *  the row, so the returned DTO is still attributed correctly. */
  getOsintFindingAnyTenant(fid: string): OsintFindingDTO | undefined {
    const r = sqlite.prepare("SELECT * FROM osint_findings WHERE id = ?").get(fid) as any;
    if (!r) return undefined;
    const src = storage.listOsintSources().find((s) => s.id === r.source_id);
    let iocs: any = {};
    try { iocs = JSON.parse(r.iocs || "{}"); } catch { iocs = {}; }
    return {
      id: r.id, tenantId: r.tenant_id, sourceId: r.source_id,
      sourceName: src?.name ?? "unknown", sourceCategory: src?.category ?? "unknown",
      title: r.title, url: r.url, publishedAt: r.published_at, severity: r.severity,
      cveIds: JSON.parse(r.cve_ids || "[]"),
      affectedTech: JSON.parse(r.affected_tech || "[]"),
      threatActors: JSON.parse(r.threat_actors || "[]"),
      iocs,
      summary: r.summary, aiSummary: r.ai_summary,
      aiRelevanceScore: r.ai_relevance_score, aiRecommendation: r.ai_recommendation,
      aiAnalyzedAt: r.ai_analyzed_at, aiProviderLabel: r.ai_provider_label,
      draftEmail: r.draft_email, draftEmailAt: r.draft_email_at,
      status: r.status, createdAt: r.created_at,
      rawSnippet: r.raw_snippet,
      analystTags: (() => { try { const v = JSON.parse(r.analyst_tags || "[]"); return Array.isArray(v) ? v : []; } catch { return []; } })(),
      analystEditedAt: r.analyst_edited_at,
      analystEditedBy: r.analyst_edited_by,
      intelCategory: (r.intel_category as any) ?? null,
      attackTechniques: parseAttackTechniques(r.attack_techniques),
      sectors: parseJsonArray<string>(r.sectors),
      regions: parseJsonArray<string>(r.regions),
      clusterId: (r.cluster_id as any) ?? null,
    };
  },

  /** v2.17 — analyst override mutator. Updates only provided fields. Persists
   *  audit columns. Returns the refreshed DTO or undefined if not found. */
  updateOsintFinding(
    tid: string,
    fid: string,
    patch: {
      status?: string;
      cveIds?: string[];
      iocs?: Record<string, string[]>;
      analystTags?: string[];
      affectedTech?: string[];
      threatActors?: string[];
    },
    editedBy: string,
  ): OsintFindingDTO | undefined {
    const existing = storage.getOsintFinding(tid, fid);
    if (!existing) return undefined;
    const allowedStatus = new Set(["new", "triaged", "assessed", "dismissed", "escalated"]);
    const sets: string[] = [];
    const params: any[] = [];
    if (typeof patch.status === "string" && allowedStatus.has(patch.status)) {
      sets.push("status = ?"); params.push(patch.status);
    }
    if (Array.isArray(patch.cveIds)) {
      const cleaned = Array.from(new Set(patch.cveIds.map((s) => String(s).trim().toUpperCase()).filter(Boolean)));
      sets.push("cve_ids = ?"); params.push(JSON.stringify(cleaned));
    }
    if (patch.iocs && typeof patch.iocs === "object") {
      const cleanIocs: Record<string, string[]> = {};
      for (const [k, v] of Object.entries(patch.iocs)) {
        if (!Array.isArray(v)) continue;
        const cleaned = Array.from(new Set(v.map((s) => String(s).trim()).filter(Boolean)));
        if (cleaned.length) cleanIocs[k] = cleaned;
      }
      sets.push("iocs = ?"); params.push(JSON.stringify(cleanIocs));
    }
    if (Array.isArray(patch.analystTags)) {
      const cleaned = Array.from(new Set(patch.analystTags.map((s) => String(s).trim()).filter(Boolean))).slice(0, 32);
      sets.push("analyst_tags = ?"); params.push(JSON.stringify(cleaned));
    }
    if (Array.isArray(patch.affectedTech)) {
      const cleaned = Array.from(new Set(patch.affectedTech.map((s) => String(s).trim()).filter(Boolean)));
      sets.push("affected_tech = ?"); params.push(JSON.stringify(cleaned));
    }
    if (Array.isArray(patch.threatActors)) {
      const cleaned = Array.from(new Set(patch.threatActors.map((s) => String(s).trim()).filter(Boolean)));
      sets.push("threat_actors = ?"); params.push(JSON.stringify(cleaned));
    }
    if (sets.length === 0) return existing;
    sets.push("analyst_edited_at = ?"); params.push(now());
    sets.push("analyst_edited_by = ?"); params.push(editedBy);
    params.push(fid, tid);
    sqlite.prepare(`UPDATE osint_findings SET ${sets.join(", ")} WHERE id = ? AND tenant_id = ?`).run(...params);
    // v2.30 — if IoCs / CVEs / sectors / tech changed, attempt cluster (re-)assignment.
    // Idempotent: no-op if cluster_id already set. Errors are swallowed so analyst
    // edits never fail on clustering bugs.
    if (patch.iocs || patch.cveIds || patch.affectedTech) {
      try { ensureClusterIdPersisted(sqlite, fid); } catch (e) { console.warn("[cluster] analyst-edit assign failed", e); }
    }
    storage.appendAudit(tid, editedBy, "osint.finding.update", fid, { fields: Object.keys(patch) });
    return storage.getOsintFinding(tid, fid);
  },

  async runOsintAnalysis(tid: string, opts: { ids?: string[]; onlyUnanalyzed?: boolean }): Promise<{ count: number; provider: string | null }> {
    const provider = storage.resolveAiProvider(tid, "osint_analysis");
    if (!provider) return { count: 0, provider: null };
    let target: OsintFindingDTO[];
    if (opts.ids && opts.ids.length) {
      target = opts.ids.map((id) => storage.getOsintFinding(tid, id)).filter(Boolean) as OsintFindingDTO[];
    } else {
      target = storage.listOsintFindings(tid);
      if (opts.onlyUnanalyzed) target = target.filter((f) => !f.aiAnalyzedAt);
    }
    // v2.13: pre-fetch the source articles in parallel so the AI can read the
    // full intel, not just the feed teaser. Failures degrade gracefully — the
    // analyser still gets the title/summary/CVEs even if the URL is unreachable.
    const fetched = await fetchSourcesBatch(target.map((f) => f.url), { includeReferences: true, maxReferenceLinks: 5 });
    const contentByIdx = new Map<number, string | null>();
    fetched.forEach((r, i) => contentByIdx.set(i, r.content));

    let updated = 0;
    let lastError: Error | null = null;
    target.forEach((f, idx) => {
      const sourceContent = contentByIdx.get(idx) ?? null;
      let r: ReturnType<typeof dispatchAi>;
      try {
        r = dispatchAi({
          task: "osint_analysis",
          input: {
            finding: {
              title: f.title,
              summary: f.summary,
              severity: f.severity,
              affectedTech: f.affectedTech,
              cveIds: f.cveIds,
              threatActors: f.threatActors,
              url: f.url,
              sourceContent,
            },
            clientProfile: BATCH_ONE_AI_CONTEXT,
          },
          provider,
        });
      } catch (e: any) {
        // v2.26 — record the error and continue with the rest of the batch.
        // The route handler reports lastError if updated==0.
        lastError = e instanceof Error ? e : new Error(String(e));
        console.warn(`[osint.analyze] finding ${f.id} failed: ${lastError.message}`);
        return;
      }
      if (r.task !== "osint_analysis") return;

      // v2.18 — MERGE AI-suggested IoCs with the regex-parsed IoCs already on
      // the finding (set-dedupe per type, case-insensitive). If an analyst has
      // touched this finding (analyst_edited_at NOT NULL) we preserve the
      // analyst override and skip the AI-IoC / analyst_tags merges.
      //
      // v2.28.1 — EVEN WHEN analyst override is active, ALWAYS re-apply the
      // publisher blocklist to the existing stored IoCs. Analyst additions
      // are preserved; only known publisher / vendor reference hosts
      // (rapid7, mitre, mandiant, microsoft learn, github, etc.) get stripped.
      // This fixes "AI re-analysis shows no change" on edited findings whose
      // IoCs were extracted by pre-v2.28 code paths that did not have the
      // global blocklist.
      const row = sqlite.prepare("SELECT iocs, analyst_tags, analyst_edited_at FROM osint_findings WHERE id = ? AND tenant_id = ?").get(f.id, tid) as any;
      const analystOverrideActive = !!(row && row.analyst_edited_at);
      let mergedIocsJson: string | null = null;
      let mergedTagsJson: string | null = null;

      // ---- IoCs ----
      // Always rebuild the IoC bag through the publisher-blocklist filter.
      // When analyst override is NOT active, also merge AI-suggested IoCs.
      // When override IS active, only run the cleanup pass over the existing
      // stored IoCs (no AI merge).
      let existingIocs: Record<string, string[]> = {};
      try { const v = JSON.parse(row?.iocs || "{}"); if (v && typeof v === "object") existingIocs = v; } catch { /* ignore */ }
      const aiIocs = analystOverrideActive
        ? ({} as Record<string, string[] | undefined>)
        : ((r.output.iocs || {}) as Record<string, string[] | undefined>);
      const allKeys = new Set<string>([...Object.keys(existingIocs), ...Object.keys(aiIocs)]);
      if (allKeys.size > 0) {
        const isPublisherUrl = (u: string): boolean => {
          try { return isSecurityPublisherHost(new URL(u).hostname.toLowerCase()); } catch { return false; }
        };
        const merged: Record<string, string[]> = {};
        let mutatedExisting = false;
        for (const k of allKeys) {
          const seen = new Set<string>();
          const out: string[] = [];
          const pushIfClean = (raw: string, fromExisting: boolean) => {
            const s = String(raw).trim();
            if (!s) return;
            const lk = s.toLowerCase();
            if (seen.has(lk)) { if (fromExisting) mutatedExisting = true; return; }
            // Strip publisher / vendor reference hosts from url + domain buckets.
            if (k === "url" && isPublisherUrl(s)) { if (fromExisting) mutatedExisting = true; return; }
            if (k === "domain" && isSecurityPublisherHost(lk)) { if (fromExisting) mutatedExisting = true; return; }
            seen.add(lk); out.push(s);
          };
          for (const v of (existingIocs[k] || [])) pushIfClean(v, true);
          for (const v of (aiIocs[k] || [])) pushIfClean(v, false);
          if (out.length) merged[k] = out;
          else if ((existingIocs[k] || []).length) mutatedExisting = true; // entire bucket stripped
        }
        // Only write when something actually changed (either an AI merge happened
        // or the publisher filter removed at least one entry).
        const aiContributed = !analystOverrideActive && Object.keys(aiIocs).some(k => (aiIocs[k] || []).length > 0);
        if (aiContributed || mutatedExisting) {
          mergedIocsJson = JSON.stringify(merged);
        }
      }

      // ---- Analyst tags ----
      // Only merged when analyst override is NOT active (preserves the
      // analyst's curated tag set the same way as before).
      if (!analystOverrideActive && Array.isArray(r.output.analystTags) && r.output.analystTags.length > 0) {
        let existingTags: string[] = [];
        try { const v = JSON.parse(row?.analyst_tags || "[]"); if (Array.isArray(v)) existingTags = v; } catch { /* ignore */ }
        const seen = new Set<string>();
        const merged: string[] = [];
        for (const v of existingTags) {
          const s = String(v).trim(); if (!s) continue;
          const lk = s.toLowerCase(); if (seen.has(lk)) continue;
          seen.add(lk); merged.push(s);
        }
        for (const v of r.output.analystTags) {
          const s = String(v).trim(); if (!s) continue;
          const lk = s.toLowerCase(); if (seen.has(lk)) continue;
          seen.add(lk); merged.push(s);
          if (merged.length >= 32) break;
        }
        mergedTagsJson = JSON.stringify(merged);
      }

      // v2.26 — dispatcher is now LIVE-ONLY. If the AI call had failed,
      // dispatchAi would have thrown LiveAiError before reaching this point
      // (the catch in the route layer surfaces 502 to the UI). So if we got
      // here, the response is genuinely from the configured provider.
      const labelToStore = provider.label;
      // Build dynamic UPDATE (only touch iocs/analyst_tags when we have a merged value).
      const sets = ["ai_summary = ?", "ai_relevance_score = ?", "ai_recommendation = ?", "ai_analyzed_at = ?", "ai_provider_label = ?"];
      const params: any[] = [r.output.summary, r.output.relevanceScore, r.output.recommendation, now(), labelToStore];
      if (mergedIocsJson !== null) { sets.push("iocs = ?"); params.push(mergedIocsJson); }
      if (mergedTagsJson !== null) { sets.push("analyst_tags = ?"); params.push(mergedTagsJson); }
      // v2.29 — persist AI categorisation. Always write (overwrites a stale label).
      {
        const cat = (r.output as any).intelCategory;
        const VALID = new Set(["threat_intel", "regular_report", "advertisement"]);
        if (typeof cat === "string" && VALID.has(cat)) {
          sets.push("intel_category = ?");
          params.push(cat);
        }
      }
      // v2.30 — persist AI-extracted ATT&CK techniques, sectors, regions.
      // Each defensive: only write if the AI returned a valid non-empty array.
      {
        const tech = (r.output as any).attackTechniques;
        if (Array.isArray(tech)) {
          const clean = tech
            .map((t: any) => {
              if (typeof t === "string") return { id: t };
              if (t && typeof t === "object" && typeof t.id === "string") {
                return { id: t.id, name: t.name, tactic: t.tactic };
              }
              return null;
            })
            .filter((x: any) => x && /^T[0-9]{4}(\.[0-9]{3})?$/i.test(String(x.id)));
          if (clean.length > 0) {
            sets.push("attack_techniques = ?");
            params.push(JSON.stringify(clean));
          }
        }
      }
      {
        const sec = (r.output as any).sectors;
        if (Array.isArray(sec)) {
          const clean = sec
            .map((s: any) => String(s || "").trim().toLowerCase().replace(/\s+/g, "_"))
            .filter((s: string) => /^[a-z][a-z0-9_]{1,30}$/.test(s));
          if (clean.length > 0) {
            sets.push("sectors = ?");
            params.push(JSON.stringify(Array.from(new Set(clean)).slice(0, 12)));
          }
        }
      }
      {
        const reg = (r.output as any).regions;
        if (Array.isArray(reg)) {
          const clean = reg
            .map((s: any) => String(s || "").trim().toLowerCase())
            .filter((s: string) => /^[a-z][a-z0-9_-]{1,20}$/.test(s));
          if (clean.length > 0) {
            sets.push("regions = ?");
            params.push(JSON.stringify(Array.from(new Set(clean)).slice(0, 8)));
          }
        }
      }
      params.push(f.id, tid);
      sqlite.prepare(`UPDATE osint_findings SET ${sets.join(", ")} WHERE id = ? AND tenant_id = ?`).run(...params);
      // v2.30 — assign cluster_id now that IoCs/sectors/tech are richest.
      // Safe + idempotent + swallow errors so AI batch never aborts on this.
      try { ensureClusterIdPersisted(sqlite, f.id); } catch (e) { console.warn(`[cluster] analyze assign failed for ${f.id}`, e); }
      updated += 1;
    });
    storage.appendAudit(tid, "system", "osint.analyze", null, { count: updated, provider: provider.label });
    // v2.26 — if every single finding in the batch failed live, surface the
    // last error to the caller so the UI shows what went wrong instead of a
    // silent "0 updated". A partial-batch success still returns 200 with
    // count<target.length.
    if (updated === 0 && target.length > 0 && lastError) {
      throw lastError;
    }
    return { count: updated, provider: provider.label };
  },

  // -------------------------------------------------------------------------
  // v2.16 — Tenant-level background-job settings + per-finding CIRT cache.
  // Used by server/backgroundJobs.ts to drive periodic fetch + per-intel AI
  // analysis. Deep-dive prefers the cache so it returns instantly when the
  // analysis has already been pre-computed in the background.
  // -------------------------------------------------------------------------

  getOsintAutomationSettings(tid: string): {
    tenantId: string;
    autoFetchEnabled: boolean;
    fetchIntervalMin: number;
    autoAnalyzeEnabled: boolean;
    analyzeConcurrency: number;
    analyzeMaxPerTick: number;
    lastFetchAt: string | null;
    lastFetchCount: number | null;
    lastFetchError: string | null;
    lastAnalyzeAt: string | null;
    lastAnalyzeOkCount: number;
    lastAnalyzeFailCount: number;
    lastAnalyzeError: string | null;
    updatedAt: string;
  } {
    const row = sqlite.prepare("SELECT * FROM tenant_osint_settings WHERE tenant_id = ?").get(tid) as any;
    if (!row) {
      // Lazily insert defaults so subsequent UPDATEs work.
      sqlite.prepare(`INSERT INTO tenant_osint_settings (tenant_id, updated_at) VALUES (?, ?)`).run(tid, now());
      return storage.getOsintAutomationSettings(tid);
    }
    return {
      tenantId: row.tenant_id,
      autoFetchEnabled: !!row.auto_fetch_enabled,
      fetchIntervalMin: Number(row.fetch_interval_min ?? 60),
      autoAnalyzeEnabled: !!row.auto_analyze_enabled,
      analyzeConcurrency: Number(row.analyze_concurrency ?? 2),
      analyzeMaxPerTick: Number(row.analyze_max_per_tick ?? 8),
      lastFetchAt: row.last_fetch_at ?? null,
      lastFetchCount: row.last_fetch_count ?? null,
      lastFetchError: row.last_fetch_error ?? null,
      lastAnalyzeAt: row.last_analyze_at ?? null,
      lastAnalyzeOkCount: Number(row.last_analyze_ok_count ?? 0),
      lastAnalyzeFailCount: Number(row.last_analyze_fail_count ?? 0),
      lastAnalyzeError: row.last_analyze_error ?? null,
      updatedAt: row.updated_at,
    };
  },

  updateOsintAutomationSettings(tid: string, patch: {
    autoFetchEnabled?: boolean;
    fetchIntervalMin?: number;
    autoAnalyzeEnabled?: boolean;
    analyzeConcurrency?: number;
    analyzeMaxPerTick?: number;
  }): ReturnType<typeof storage.getOsintAutomationSettings> {
    // Ensure row exists.
    storage.getOsintAutomationSettings(tid);
    const sets: string[] = [];
    const params: any[] = [];
    if (patch.autoFetchEnabled !== undefined) { sets.push("auto_fetch_enabled = ?"); params.push(patch.autoFetchEnabled ? 1 : 0); }
    if (patch.fetchIntervalMin !== undefined) { sets.push("fetch_interval_min = ?"); params.push(Math.max(15, Math.min(1440, Math.round(patch.fetchIntervalMin)))); }
    if (patch.autoAnalyzeEnabled !== undefined) { sets.push("auto_analyze_enabled = ?"); params.push(patch.autoAnalyzeEnabled ? 1 : 0); }
    if (patch.analyzeConcurrency !== undefined) { sets.push("analyze_concurrency = ?"); params.push(Math.max(1, Math.min(8, Math.round(patch.analyzeConcurrency)))); }
    if (patch.analyzeMaxPerTick !== undefined) { sets.push("analyze_max_per_tick = ?"); params.push(Math.max(1, Math.min(50, Math.round(patch.analyzeMaxPerTick)))); }
    sets.push("updated_at = ?"); params.push(now());
    params.push(tid);
    sqlite.prepare(`UPDATE tenant_osint_settings SET ${sets.join(", ")} WHERE tenant_id = ?`).run(...params);
    return storage.getOsintAutomationSettings(tid);
  },

  /** Returns every tenant id that currently has a settings row. Used by the
   *  global scheduler to know which tenants to walk each minute. */
  listOsintAutomationTenants(): string[] {
    return (sqlite.prepare("SELECT tenant_id FROM tenant_osint_settings").all() as Array<{ tenant_id: string }>).map((r) => r.tenant_id);
  },

  /** Per-finding deep-dive cache lookup — returns null when no analysis has
   *  been persisted yet. */
  getOsintFindingCache(tid: string, fid: string): {
    sourceContent: string | null;
    sourceFetchedAt: string | null;
    cirtAnalysis: any | null;
    cirtAnalyzedAt: string | null;
    cirtProviderLabel: string | null;
    cirtStatus: string;
    cirtError: string | null;
    cirtAttempts: number;
    cirtNextAttemptAt: string | null;
  } | null {
    const r = sqlite.prepare(`SELECT source_content, source_fetched_at, cirt_analysis,
      cirt_analyzed_at, cirt_provider_label, cirt_status, cirt_error, cirt_attempts, cirt_next_attempt_at
      FROM osint_findings WHERE id = ? AND tenant_id = ?`).get(fid, tid) as any;
    if (!r) return null;
    let parsed: any = null;
    if (r.cirt_analysis) { try { parsed = JSON.parse(r.cirt_analysis); } catch { parsed = null; } }
    return {
      sourceContent: r.source_content ?? null,
      sourceFetchedAt: r.source_fetched_at ?? null,
      cirtAnalysis: parsed,
      cirtAnalyzedAt: r.cirt_analyzed_at ?? null,
      cirtProviderLabel: r.cirt_provider_label ?? null,
      cirtStatus: r.cirt_status ?? "pending",
      cirtError: r.cirt_error ?? null,
      cirtAttempts: Number(r.cirt_attempts ?? 0),
      cirtNextAttemptAt: r.cirt_next_attempt_at ?? null,
    };
  },

  /** Persist a successful per-intel CIRT analysis (object matches
   *  ChatDeepDivePerFinding). Also persists the source body that fed it. */
  saveOsintFindingCirt(tid: string, fid: string, payload: {
    sourceContent: string | null;
    cirtAnalysis: any;
    providerLabel: string;
  }): void {
    sqlite.prepare(`UPDATE osint_findings SET
      source_content = COALESCE(?, source_content),
      source_fetched_at = CASE WHEN ? IS NOT NULL THEN ? ELSE source_fetched_at END,
      cirt_analysis = ?,
      cirt_analyzed_at = ?,
      cirt_provider_label = ?,
      cirt_status = 'done',
      cirt_error = NULL,
      cirt_next_attempt_at = NULL
      WHERE id = ? AND tenant_id = ?`).run(
        payload.sourceContent, payload.sourceContent, now(),
        JSON.stringify(payload.cirtAnalysis),
        now(), payload.providerLabel, fid, tid,
      );
  },

  /** Mark a finding as failed; schedules the next retry with exponential
   *  backoff (5min / 30min / 2h). After 3 attempts the row stays in 'failed'
   *  and the scheduler stops picking it up automatically. */
  markOsintFindingCirtFailed(tid: string, fid: string, reason: string): void {
    const row = sqlite.prepare("SELECT cirt_attempts FROM osint_findings WHERE id = ? AND tenant_id = ?").get(fid, tid) as any;
    const attempts = Number(row?.cirt_attempts ?? 0) + 1;
    const backoffMin = attempts === 1 ? 5 : attempts === 2 ? 30 : attempts === 3 ? 120 : 0;
    const nextAttempt = backoffMin > 0 ? new Date(Date.now() + backoffMin * 60_000).toISOString() : null;
    sqlite.prepare(`UPDATE osint_findings SET
      cirt_status = ?,
      cirt_error = ?,
      cirt_attempts = ?,
      cirt_next_attempt_at = ?
      WHERE id = ? AND tenant_id = ?`).run(
        attempts >= 4 ? "failed" : "pending",
        String(reason).slice(0, 500),
        attempts,
        nextAttempt,
        fid, tid,
      );
  },

  /** Pick the next batch of findings due for CIRT analysis. Skips rows whose
   *  retry timer hasn't elapsed. Newest published first (operators care more
   *  about fresh intel). */
  listOsintCirtQueue(tid: string, limit: number): OsintFindingDTO[] {
    const nowIso = now();
    const rows = sqlite.prepare(`SELECT * FROM osint_findings
      WHERE tenant_id = ?
        AND cirt_status IN ('pending', 'fetching', 'analyzing')
        AND cirt_attempts < 4
        AND (cirt_next_attempt_at IS NULL OR cirt_next_attempt_at <= ?)
      ORDER BY published_at DESC
      LIMIT ?`).all(tid, nowIso, Math.max(1, Math.min(50, limit))) as any[];
    const sourceMap = new Map(storage.listOsintSources().map((s) => [s.id, s]));
    return rows.map((r) => {
      const src = sourceMap.get(r.source_id);
      let iocs: any = {};
      try { iocs = JSON.parse(r.iocs || "{}"); } catch { iocs = {}; }
      return {
        id: r.id, tenantId: r.tenant_id, sourceId: r.source_id,
        sourceName: src?.name ?? "unknown", sourceCategory: src?.category ?? "unknown",
        title: r.title, url: r.url, publishedAt: r.published_at, severity: r.severity,
        cveIds: JSON.parse(r.cve_ids || "[]"),
        affectedTech: JSON.parse(r.affected_tech || "[]"),
        threatActors: JSON.parse(r.threat_actors || "[]"),
        iocs,
        summary: r.summary, aiSummary: r.ai_summary,
        aiRelevanceScore: r.ai_relevance_score, aiRecommendation: r.ai_recommendation,
        aiAnalyzedAt: r.ai_analyzed_at, aiProviderLabel: r.ai_provider_label,
        draftEmail: r.draft_email, draftEmailAt: r.draft_email_at,
        status: r.status, createdAt: r.created_at,
        rawSnippet: r.raw_snippet,
      } as OsintFindingDTO;
    });
  },

  /** Summary numbers for the Settings card — pending / done / failed counts. */
  getOsintCirtQueueStats(tid: string): { pending: number; done: number; failed: number; total: number } {
    const row = sqlite.prepare(`SELECT
      SUM(CASE WHEN cirt_status = 'pending' AND cirt_attempts < 4 THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN cirt_status = 'done' THEN 1 ELSE 0 END) AS done,
      SUM(CASE WHEN cirt_status = 'failed' OR cirt_attempts >= 4 THEN 1 ELSE 0 END) AS failed,
      COUNT(*) AS total
      FROM osint_findings WHERE tenant_id = ?`).get(tid) as any;
    return {
      pending: Number(row?.pending || 0),
      done: Number(row?.done || 0),
      failed: Number(row?.failed || 0),
      total: Number(row?.total || 0),
    };
  },

  /** Reset CIRT cache + retry counters for a tenant. Used by the "Re-run
   *  analysis for all" button in Settings. */
  resetOsintCirtCache(tid: string, opts?: { failedOnly?: boolean }): { reset: number } {
    const whereExtra = opts?.failedOnly ? "AND (cirt_status = 'failed' OR cirt_attempts >= 4)" : "";
    const r = sqlite.prepare(`UPDATE osint_findings SET
      cirt_analysis = NULL, cirt_analyzed_at = NULL, cirt_provider_label = NULL,
      cirt_status = 'pending', cirt_error = NULL, cirt_attempts = 0, cirt_next_attempt_at = NULL
      WHERE tenant_id = ? ${whereExtra}`).run(tid);
    return { reset: r.changes ?? 0 };
  },

  /** Update fetch-result book-keeping after the background fetcher runs. */
  recordOsintAutoFetch(tid: string, opts: { count: number; error: string | null }): void {
    storage.getOsintAutomationSettings(tid);
    sqlite.prepare(`UPDATE tenant_osint_settings SET
      last_fetch_at = ?, last_fetch_count = ?, last_fetch_error = ?, updated_at = ?
      WHERE tenant_id = ?`).run(now(), opts.count, opts.error?.slice(0, 500) ?? null, now(), tid);
  },

  /** Update analysis-result book-keeping after a background tick. */
  recordOsintAutoAnalyze(tid: string, opts: { okCount: number; failCount: number; error: string | null }): void {
    storage.getOsintAutomationSettings(tid);
    sqlite.prepare(`UPDATE tenant_osint_settings SET
      last_analyze_at = ?, last_analyze_ok_count = ?, last_analyze_fail_count = ?,
      last_analyze_error = ?, updated_at = ?
      WHERE tenant_id = ?`).run(now(), opts.okCount, opts.failCount, opts.error?.slice(0, 500) ?? null, now(), tid);
  },

  // ---------- Hunt query generator ----------
  async generateHuntQueries(tid: string, opts: { findingIds: string[]; languages: string[]; title?: string; createdBy: string }): Promise<HuntQueryDTO> {
    const provider = storage.resolveAiProvider(tid, "hunt_query");
    if (!provider) throw new Error("No AI provider is configured for hunt query generation.");
    const findings = opts.findingIds.map((id) => storage.getOsintFinding(tid, id)).filter(Boolean) as OsintFindingDTO[];
    const affectedTech = Array.from(new Set(findings.flatMap((f) => f.affectedTech)));

    // v2.13: pre-fetch each source URL so the AI reads the full article body
    // before drafting hunting queries. Failures degrade to summary-only input.
    const fetched = await fetchSourcesBatch(findings.map((f) => f.url), { includeReferences: true, maxReferenceLinks: 3 });
    const contentByIdx = new Map<number, string | null>();
    fetched.forEach((r, i) => contentByIdx.set(i, r.content));

    const aiResult = dispatchAi({
      task: "hunt_query",
      input: {
        titleInstruction: "Return a top-level English `title` for the hunt package. It must be identifiable, concise, and based on the strongest visible signal, such as the primary CVE, actor, malware/tool, affected product, or source campaign. Avoid generic labels like `OSINT findings`.",
        findings: findings.map((f, idx) => ({
          title: f.title,
          cveIds: f.cveIds,
          affectedTech: f.affectedTech,
          threatActors: f.threatActors,
          summary: f.summary,
          rawSnippet: (f as any).rawSnippet ?? null,
          severity: f.severity,
          url: f.url,
          sourceContent: contentByIdx.get(idx) ?? null,
        })),
        languages: opts.languages,
      },
      provider,
    });
    let queries: Record<string, string | string[]> = {};
    if (aiResult.task === "hunt_query") queries = aiResult.output as Record<string, string | string[]>;
    const aiTitle = typeof (queries as any).__title === "string" ? String((queries as any).__title).trim() : "";
    delete (queries as any).__title;
    delete (queries as any).title;
    const missingLanguages = opts.languages.filter((lang) => !queries[lang]);
    if (missingLanguages.length) {
      throw new Error(`AI provider did not return hunt queries for: ${missingLanguages.join(", ")}`);
    }
    const hid = id();
    const title = opts.title ?? (aiTitle || `Hunt — ${affectedTech.slice(0, 2).join(", ") || "OSINT findings"} (${findings.length} signal${findings.length === 1 ? "" : "s"})`);
    const description = findings.map((f) => `• ${f.title}`).join("\n");
    sqlite.prepare(`INSERT INTO hunt_queries (
      id, tenant_id, title, description, source_finding_ids, affected_tech, queries,
      ai_provider_label, created_at, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      hid, tid, title, description, j(opts.findingIds), j(affectedTech), JSON.stringify(queries),
      provider?.label ?? null, now(), opts.createdBy
    );
    storage.appendAudit(tid, opts.createdBy, "hunt.generate", hid, { languages: opts.languages, findings: opts.findingIds.length });
    return {
      id: hid, tenantId: tid, title, description,
      sourceFindingIds: opts.findingIds, affectedTech, queries,
      aiProviderLabel: provider?.label ?? null, createdAt: now(), createdBy: opts.createdBy,
    };
  },

  listHuntQueries(tid: string): HuntQueryDTO[] {
    const rows = sqlite.prepare("SELECT * FROM hunt_queries WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 200").all(tid) as any[];
    return rows.map((r) => ({
      id: r.id, tenantId: r.tenant_id, title: r.title, description: r.description,
      sourceFindingIds: JSON.parse(r.source_finding_ids || "[]"),
      affectedTech: JSON.parse(r.affected_tech || "[]"),
      queries: JSON.parse(r.queries || "{}"),
      aiProviderLabel: r.ai_provider_label, createdAt: r.created_at, createdBy: r.created_by,
    }));
  },

  // ---------- Detection Rule Studio (v2.30.2) ----------
  /** Hydrate a detection-rule row + its deployments into the wire DTO. */
  _ruleRowToDto(r: any): DetectionRuleDTO {
    const deps = sqlite.prepare(
      "SELECT * FROM rule_deployments WHERE tenant_id = ? AND rule_id = ? ORDER BY siem_id"
    ).all(r.tenant_id, r.id) as any[];
    const siemLabel = (sid: string) => SIEM_TARGETS.find((s) => s.id === sid)?.label ?? sid;
    return {
      id: r.id, tenantId: r.tenant_id, title: r.title,
      description: r.description ?? null,
      sourceFindingIds: JSON.parse(r.source_finding_ids || "[]"),
      status: (r.status || "draft") as RuleStatus,
      severity: (r.severity || "medium") as RuleSeverity,
      mitreTechniques: JSON.parse(r.mitre_techniques || "[]"),
      affectedTech: JSON.parse(r.affected_tech || "[]"),
      threatActors: JSON.parse(r.threat_actors || "[]"),
      sigmaYaml: r.sigma_yaml ?? null,
      queries: JSON.parse(r.queries || "{}"),
      notes: r.notes ?? null,
      version: r.version ?? 1,
      aiProviderLabel: r.ai_provider_label ?? null,
      createdAt: r.created_at, updatedAt: r.updated_at, createdBy: r.created_by,
      deployments: deps.map((d) => ({
        id: d.id, ruleId: d.rule_id, siemId: d.siem_id as SiemTargetId,
        siemLabel: siemLabel(d.siem_id),
        mode: d.mode as DeploymentMode, status: d.status as DeploymentStatus,
        externalId: d.external_id ?? null, message: d.message ?? null,
        ruleVersion: d.rule_version ?? 1,
        deployedAt: d.deployed_at ?? null, deployedBy: d.deployed_by ?? null,
        updatedAt: d.updated_at,
      })),
    };
  },

  listDetectionRules(tid: string, filter?: { status?: RuleStatus }): DetectionRuleDTO[] {
    const where: string[] = ["tenant_id = ?"];
    const args: any[] = [tid];
    if (filter?.status) { where.push("status = ?"); args.push(filter.status); }
    const rows = sqlite.prepare(
      `SELECT * FROM detection_rules WHERE ${where.join(" AND ")} ORDER BY updated_at DESC LIMIT 500`
    ).all(...args) as any[];
    return rows.map((r) => storage._ruleRowToDto(r));
  },

  getDetectionRule(tid: string, rid: string): DetectionRuleDTO | undefined {
    const r = sqlite.prepare("SELECT * FROM detection_rules WHERE tenant_id = ? AND id = ?").get(tid, rid) as any;
    if (!r) return undefined;
    return storage._ruleRowToDto(r);
  },

  /** Create a detection rule. When `generate` is true the AI is invoked to
   *  populate sigmaYaml + queries + MITRE mapping. When false (or no findings)
   *  the rule is created empty so the analyst can author manually. */
  async createDetectionRule(tid: string, opts: {
    title?: string;
    description?: string;
    findingIds?: string[];
    languages?: string[];
    severity?: RuleSeverity;
    affectedTech?: string[];
    threatActors?: string[];
    generate: boolean;
    createdBy: string;
  }): Promise<DetectionRuleDTO> {
    const findingIds = opts.findingIds ?? [];
    const findings = findingIds
      .map((fid) => storage.getOsintFinding(tid, fid))
      .filter(Boolean) as OsintFindingDTO[];
    const langs = (opts.languages && opts.languages.length > 0)
      ? opts.languages.filter((l) => SIEM_TARGET_IDS.includes(l as any))
      : (SIEM_TARGET_IDS as readonly string[]).slice();
    const affectedTech = Array.from(new Set([
      ...(opts.affectedTech ?? []),
      ...findings.flatMap((f) => f.affectedTech),
    ]));
    const threatActors = Array.from(new Set([
      ...(opts.threatActors ?? []),
      ...findings.flatMap((f) => f.threatActors),
    ]));

    let title = opts.title ?? "";
    let description = opts.description ?? "";
    let severity: RuleSeverity = opts.severity ?? "medium";
    let mitreTechniques: Array<{ id: string; name?: string; tactic?: string }> = [];
    let sigmaYaml: string | null = null;
    let queries: Record<string, string> = {};
    let notes: string | null = null;
    let providerLabel: string | null = null;

    const shouldGenerate = opts.generate && findings.length > 0;
    if (shouldGenerate) {
      const provider = storage.resolveAiProvider(tid, "detection_rule");
      if (!provider) {
        throw new Error("no AI provider is configured for detection_rule — connect one in AI Setup");
      }
      // Pre-fetch source URLs so the model reads the article body verbatim.
      const fetched = await fetchSourcesBatch(findings.map((f) => f.url), { includeReferences: true, maxReferenceLinks: 3 });
      const byIdx = new Map<number, string | null>();
      fetched.forEach((r, i) => byIdx.set(i, r.content));
      const result = dispatchAi({
        task: "detection_rule",
        input: {
          findings: findings.map((f, idx) => ({
            title: f.title,
            cveIds: f.cveIds,
            affectedTech: f.affectedTech,
            threatActors: f.threatActors,
            summary: f.summary,
            rawSnippet: (f as any).rawSnippet ?? null,
            severity: f.severity,
            url: f.url,
            sourceContent: byIdx.get(idx) ?? null,
            attackTechniques: f.attackTechniques ?? null,
          })),
          languages: langs,
        },
        provider,
      });
      if (result.task !== "detection_rule") throw new Error("unexpected AI result");
      const out = result.output;
      if (!title) title = out.title;
      if (!description) description = out.description;
      severity = out.severity;
      mitreTechniques = out.mitreTechniques;
      sigmaYaml = out.sigmaYaml || null;
      queries = out.queries || {};
      notes = out.notes || null;
      providerLabel = provider.label;
    }

    if (!title) {
      const topTech = affectedTech[0] || (findings[0]?.cveIds[0]) || "detection rule";
      title = `Draft — ${topTech}`;
    }
    const rid = id();
    const ts = now();
    sqlite.prepare(`INSERT INTO detection_rules (
      id, tenant_id, title, description, source_finding_ids, status, severity,
      mitre_techniques, affected_tech, threat_actors, sigma_yaml, queries, notes,
      version, ai_provider_label, created_at, updated_at, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      rid, tid, title, description || null,
      j(findingIds), "draft", severity,
      JSON.stringify(mitreTechniques), j(affectedTech), j(threatActors),
      sigmaYaml, JSON.stringify(queries), notes,
      1, providerLabel, ts, ts, opts.createdBy,
    );
    storage.appendAudit(tid, opts.createdBy, "detection_rule.create", rid, {
      findings: findingIds.length, generated: shouldGenerate,
      languages: langs.length,
    });
    return storage.getDetectionRule(tid, rid)!;
  },

  updateDetectionRule(tid: string, rid: string, patch: {
    title?: string;
    description?: string;
    status?: RuleStatus;
    severity?: RuleSeverity;
    sigmaYaml?: string | null;
    queries?: Record<string, string>;
    notes?: string | null;
    affectedTech?: string[];
    threatActors?: string[];
    mitreTechniques?: Array<{ id: string; name?: string; tactic?: string }>;
    actor: string;
  }): DetectionRuleDTO | undefined {
    const existing = sqlite.prepare("SELECT * FROM detection_rules WHERE tenant_id = ? AND id = ?").get(tid, rid) as any;
    if (!existing) return undefined;
    const updates: string[] = [];
    const args: any[] = [];
    const push = (col: string, val: any) => { updates.push(`${col} = ?`); args.push(val); };
    if (patch.title !== undefined) push("title", patch.title);
    if (patch.description !== undefined) push("description", patch.description ?? null);
    if (patch.status !== undefined) push("status", patch.status);
    if (patch.severity !== undefined) push("severity", patch.severity);
    if (patch.sigmaYaml !== undefined) push("sigma_yaml", patch.sigmaYaml);
    if (patch.queries !== undefined) push("queries", JSON.stringify(patch.queries));
    if (patch.notes !== undefined) push("notes", patch.notes);
    if (patch.affectedTech !== undefined) push("affected_tech", j(patch.affectedTech));
    if (patch.threatActors !== undefined) push("threat_actors", j(patch.threatActors));
    if (patch.mitreTechniques !== undefined) push("mitre_techniques", JSON.stringify(patch.mitreTechniques));
    if (updates.length === 0) return storage.getDetectionRule(tid, rid);
    push("version", (existing.version ?? 1) + 1);
    push("updated_at", now());
    args.push(tid, rid);
    sqlite.prepare(`UPDATE detection_rules SET ${updates.join(", ")} WHERE tenant_id = ? AND id = ?`).run(...args);
    storage.appendAudit(tid, patch.actor, "detection_rule.update", rid, { fields: Object.keys(patch).filter((k) => k !== "actor") });
    return storage.getDetectionRule(tid, rid);
  },

  deleteDetectionRule(tid: string, rid: string, actor: string): boolean {
    const r = sqlite.prepare("SELECT id FROM detection_rules WHERE tenant_id = ? AND id = ?").get(tid, rid);
    if (!r) return false;
    sqlite.prepare("DELETE FROM rule_deployments WHERE tenant_id = ? AND rule_id = ?").run(tid, rid);
    sqlite.prepare("DELETE FROM detection_rules WHERE tenant_id = ? AND id = ?").run(tid, rid);
    storage.appendAudit(tid, actor, "detection_rule.delete", rid, {});
    return true;
  },

  /** Upsert a (rule, siem) deployment row. In manual mode we just flip status.
   *  In push mode we call the SIEM integration and record the live result. */
  deployDetectionRule(tid: string, rid: string, opts: {
    siemId: SiemTargetId;
    mode: DeploymentMode;
    status?: DeploymentStatus;
    externalId?: string;
    message?: string;
    actor: string;
  }): { deployment: RuleDeploymentDTO; rule: DetectionRuleDTO } | { error: string } {
    const rule = storage.getDetectionRule(tid, rid);
    if (!rule) return { error: "rule not found" };
    const target = SIEM_TARGETS.find((s) => s.id === opts.siemId);
    if (!target) return { error: `unknown SIEM target: ${opts.siemId}` };
    const query = rule.queries[opts.siemId];
    if (opts.mode === "push" && !query && opts.siemId !== "sigma") {
      return { error: `no query compiled for ${target.label} — generate or author one before pushing` };
    }

    let finalStatus: DeploymentStatus;
    let finalMessage: string | null = opts.message ?? null;
    let finalExternalId: string | null = opts.externalId ?? null;

    if (opts.mode === "push") {
      finalStatus = "failed";
      finalExternalId = null;
      finalMessage = `${target.label} push deployment is outside the BatchOne release. Use manual deployment after deploying the query in your SIEM.`;
    } else {
      // Manual mode: trust whatever the analyst said. Default to deployed.
      finalStatus = opts.status ?? "deployed";
    }

    const existing = sqlite.prepare(
      "SELECT * FROM rule_deployments WHERE tenant_id = ? AND rule_id = ? AND siem_id = ?"
    ).get(tid, rid, opts.siemId) as any;
    const ts = now();
    if (existing) {
      sqlite.prepare(`UPDATE rule_deployments SET
        mode = ?, status = ?, external_id = ?, message = ?, rule_version = ?,
        deployed_at = ?, deployed_by = ?, updated_at = ?
        WHERE id = ?`).run(
        opts.mode, finalStatus, finalExternalId, finalMessage, rule.version,
        finalStatus === "deployed" ? ts : (existing.deployed_at ?? null),
        finalStatus === "deployed" ? opts.actor : (existing.deployed_by ?? null),
        ts, existing.id,
      );
    } else {
      sqlite.prepare(`INSERT INTO rule_deployments (
        id, tenant_id, rule_id, siem_id, mode, status, external_id, message,
        rule_version, deployed_at, deployed_by, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        id(), tid, rid, opts.siemId, opts.mode, finalStatus,
        finalExternalId, finalMessage, rule.version,
        finalStatus === "deployed" ? ts : null,
        finalStatus === "deployed" ? opts.actor : null,
        ts,
      );
    }
    storage.appendAudit(tid, opts.actor, "detection_rule.deploy", rid, {
      siemId: opts.siemId, mode: opts.mode, status: finalStatus,
    });
    const refreshed = storage.getDetectionRule(tid, rid)!;
    const dep = refreshed.deployments.find((d) => d.siemId === opts.siemId)!;
    return { deployment: dep, rule: refreshed };
  },

  // ==========================================================================
  // v2.30.3 — Threat Actor Profiles (TAP)
  // ==========================================================================

  /** Hydrate a threat_actors row into the DTO shape. */
  _taRowToDto(r: any): ThreatActorDTO {
    return {
      id: r.id, tenantId: r.tenant_id,
      profileId: r.profile_id,
      primaryName: r.primary_name,
      mitreGroupId: r.mitre_group_id ?? null,
      aliases: JSON.parse(r.aliases || "[]"),
      vendorNames: JSON.parse(r.vendor_names || "{}"),
      actorType: (r.actor_type || "Unknown") as ActorType,
      sponsorship: (r.sponsorship || "Unknown") as SponsorshipLevel,
      assessedOrigin: r.assessed_origin ?? null,
      originConfidence: (r.origin_confidence ?? null) as WepConfidence | null,
      sponsoringEntity: r.sponsoring_entity ?? null,
      motivation: JSON.parse(r.motivation || "[]"),
      activeSince: r.active_since ?? null,
      sophistication: (r.sophistication || "Intermediate") as SophisticationLevel,
      tlp: (r.tlp || "AMBER") as TlpLevel,
      admiraltySource: (r.admiralty_source || "B") as AdmiraltySource,
      admiraltyInfo: (r.admiralty_info || "2") as AdmiraltyInfo,
      wepConfidence: (r.wep_confidence || "Likely") as WepConfidence,
      targetSectors: JSON.parse(r.target_sectors || "[]"),
      targetRegions: JSON.parse(r.target_regions || "[]"),
      targetTechStack: JSON.parse(r.target_tech_stack || "[]"),
      orgSizePreference: r.org_size_preference ?? null,
      intentProximity: (r.intent_proximity || "Opportunistic") as IntentProximity,
      relevanceRating: r.relevance_rating ?? null,
      execWhat: r.exec_what ?? null,
      execSoWhat: r.exec_so_what ?? null,
      execWhatNow: r.exec_what_now ?? null,
      threatLevel: (r.threat_level || "MODERATE") as ThreatLevel,
      threatLevelRationale: r.threat_level_rationale ?? null,
      sectorActivelyTargeted: !!r.sector_actively_targeted,
      diamondAdversary: JSON.parse(r.diamond_adversary || "{}"),
      diamondCapability: JSON.parse(r.diamond_capability || "{}"),
      diamondInfrastructure: JSON.parse(r.diamond_infrastructure || "{}"),
      diamondVictim: JSON.parse(r.diamond_victim || "{}"),
      diamondMeta: JSON.parse(r.diamond_meta || "{}"),
      businessImpact: JSON.parse(r.business_impact || "{}"),
      capabilityProfile: JSON.parse(r.capability_profile || "{}"),
      infrastructureProfile: JSON.parse(r.infrastructure_profile || "{}"),
      irActions: JSON.parse(r.ir_actions || "{}"),
      countermeasures: JSON.parse(r.countermeasures || "{}"),
      forecast: r.forecast ?? null,
      extortionTactics: JSON.parse(r.extortion_tactics || "{}"),
      bodyMd: r.body_md ?? null,
      status: (r.status || "draft") as TapStatus,
      version: r.version ?? 1,
      cutoffDate: r.cutoff_date ?? null,
      preparedBy: r.prepared_by ?? null,
      aiProviderLabel: r.ai_provider_label ?? null,
      portraitUrl: r.portrait_url ?? null,
      portraitGeneratedAt: r.portrait_generated_at ?? null,
      portraitStatus: (r.portrait_status ?? "idle") as "idle" | "generating" | "ready" | "failed",
      createdAt: r.created_at, updatedAt: r.updated_at, createdBy: r.created_by,
    };
  },

  _taTtpRowToDto(r: any): ThreatActorTtpDTO {
    return {
      id: r.id, actorId: r.actor_id,
      tactic: r.tactic, techniqueId: r.technique_id,
      subTechniqueId: r.sub_technique_id ?? null,
      techniqueName: r.technique_name,
      evidence: r.evidence ?? null,
      status: r.status as TtpStatus,
      detectionPriority: r.detection_priority as DetectionPriority,
      createdAt: r.created_at,
    };
  },
  _taToolRowToDto(r: any): ThreatActorToolDTO {
    return {
      id: r.id, actorId: r.actor_id,
      name: r.name, category: r.category ?? null, purpose: r.purpose ?? null,
      variants: JSON.parse(r.variants || "[]"),
      hashOrRule: r.hash_or_rule ?? null,
      confidence: r.confidence as WepConfidence,
      createdAt: r.created_at,
    };
  },
  _taCampaignRowToDto(r: any): ThreatActorCampaignDTO {
    return {
      id: r.id, actorId: r.actor_id,
      name: r.name, period: r.period ?? null,
      targetSector: r.target_sector ?? null,
      targetGeography: r.target_geography ?? null,
      initialAccess: r.initial_access ?? null,
      outcome: r.outcome ?? null,
      sourceUrl: r.source_url ?? null,
      findingIds: JSON.parse(r.finding_ids || "[]"),
      ruleIds: JSON.parse(r.rule_ids || "[]"),
      createdAt: r.created_at,
    };
  },
  _taIocRowToDto(r: any): ThreatActorIocDTO {
    return {
      id: r.id, actorId: r.actor_id,
      iocType: r.ioc_type as IocType, value: r.value,
      firstSeen: r.first_seen ?? null,
      lastConfirmed: r.last_confirmed ?? null,
      confidence: r.confidence as WepConfidence,
      tlp: r.tlp as TlpLevel,
      source: r.source ?? null,
      mitreTtps: JSON.parse(r.mitre_ttps || "[]"),
      recommendedAction: r.recommended_action ?? null,
      createdAt: r.created_at,
    };
  },
  _taRefRowToDto(r: any): ThreatActorReferenceDTO {
    return {
      id: r.id, actorId: r.actor_id,
      refNum: r.ref_num,
      sourceType: r.source_type ?? null,
      title: r.title,
      date: r.date ?? null,
      url: r.url ?? null,
      archiveUrl: r.archive_url ?? null,
      createdAt: r.created_at,
    };
  },
  _taRuleLinkRowToDto(r: any): ThreatActorRuleLinkDTO {
    // r may join detection_rules row when called from listFullThreatActor.
    return {
      id: r.id, actorId: r.actor_id, ruleId: r.rule_id,
      priority: r.priority as DetectionPriority,
      notes: r.notes ?? null,
      ruleTitle: r.rule_title ?? undefined,
      ruleStatus: r.rule_status ?? undefined,
      ruleMitreTechniques: (() => {
        try {
          const parsed = JSON.parse(r.rule_mitre_techniques || "[]");
          return Array.isArray(parsed) ? parsed : [];
        } catch {
          return [];
        }
      })(),
      createdAt: r.created_at,
    };
  },
  _taTenantRowToDto(r: any): ThreatActorTenantDTO {
    // r may join `tenants` and `tenant_scopes` so the UI can show name + sector.
    return {
      id: r.id,
      actorId: r.actor_id,
      tenantId: r.tenant_id,
      tenantName: r.tenant_name ?? undefined,
      tenantSector: r.tenant_sector ?? null,
      tenantRegion: r.tenant_region ?? null,
      relevance: r.relevance as TenantRelevance,
      rationale: r.rationale ?? null,
      taggedBy: r.tagged_by ?? null,
      taggedByAi: !!r.tagged_by_ai,
      createdAt: r.created_at,
    };
  },

  /** Assign the next TAP-NNN profile id for a tenant. Atomic enough for our
   *  single-process server; if multiple actors are created concurrently the
   *  UNIQUE index on (tenant_id, profile_id) catches collisions. */
  _nextTapProfileId(tid: string): string {
    const rows = sqlite.prepare(
      "SELECT profile_id FROM threat_actors WHERE tenant_id = ? AND profile_id LIKE 'TAP-%'"
    ).all(tid) as any[];
    let maxN = 0;
    for (const r of rows) {
      const m = /^TAP-(\d+)$/.exec(r.profile_id);
      if (m) {
        const n = parseInt(m[1], 10);
        if (n > maxN) maxN = n;
      }
    }
    return `TAP-${String(maxN + 1).padStart(3, "0")}`;
  },

  listThreatActors(tid: string, filter?: { status?: TapStatus; q?: string }): ThreatActorDTO[] {
    const where: string[] = ["tenant_id = ?"];
    const args: any[] = [tid];
    if (filter?.status) { where.push("status = ?"); args.push(filter.status); }
    if (filter?.q && filter.q.trim()) {
      where.push("(LOWER(primary_name) LIKE ? OR LOWER(aliases) LIKE ? OR LOWER(mitre_group_id) LIKE ?)");
      const needle = `%${filter.q.trim().toLowerCase()}%`;
      args.push(needle, needle, needle);
    }
    const rows = sqlite.prepare(
      `SELECT * FROM threat_actors WHERE ${where.join(" AND ")} ORDER BY updated_at DESC LIMIT 500`
    ).all(...args) as any[];
    return rows.map((r) => storage._taRowToDto(r));
  },

  getThreatActor(tid: string, aid: string): ThreatActorDTO | undefined {
    const r = sqlite.prepare("SELECT * FROM threat_actors WHERE tenant_id = ? AND id = ?").get(tid, aid) as any;
    if (!r) return undefined;
    return storage._taRowToDto(r);
  },

  /** Look up by primary name OR alias (case-insensitive). Returns the first match. */
  findThreatActorByName(tid: string, name: string): ThreatActorDTO | undefined {
    const needle = name.trim().toLowerCase();
    if (!needle) return undefined;
    const rows = sqlite.prepare(
      "SELECT * FROM threat_actors WHERE tenant_id = ?"
    ).all(tid) as any[];
    for (const r of rows) {
      if (String(r.primary_name).toLowerCase() === needle) return storage._taRowToDto(r);
      try {
        const aliases: string[] = JSON.parse(r.aliases || "[]");
        if (aliases.some((a) => a.toLowerCase() === needle)) return storage._taRowToDto(r);
      } catch { /* ignore */ }
    }
    return undefined;
  },

  getFullThreatActor(tid: string, aid: string): ThreatActorFullDTO | undefined {
    const head = storage.getThreatActor(tid, aid);
    if (!head) return undefined;
    const ttps = (sqlite.prepare("SELECT * FROM threat_actor_ttps WHERE tenant_id = ? AND actor_id = ? ORDER BY tactic, technique_id").all(tid, aid) as any[]).map(storage._taTtpRowToDto);
    const tools = (sqlite.prepare("SELECT * FROM threat_actor_tools WHERE tenant_id = ? AND actor_id = ? ORDER BY name").all(tid, aid) as any[]).map(storage._taToolRowToDto);
    const campaigns = (sqlite.prepare("SELECT * FROM threat_actor_campaigns WHERE tenant_id = ? AND actor_id = ? ORDER BY period DESC, created_at DESC").all(tid, aid) as any[]).map(storage._taCampaignRowToDto);
    const iocs = (sqlite.prepare("SELECT * FROM threat_actor_iocs WHERE tenant_id = ? AND actor_id = ? ORDER BY ioc_type, value").all(tid, aid) as any[]).map(storage._taIocRowToDto);
    const references = (sqlite.prepare("SELECT * FROM threat_actor_references WHERE tenant_id = ? AND actor_id = ? ORDER BY ref_num").all(tid, aid) as any[]).map(storage._taRefRowToDto);
    const ruleLinks = (sqlite.prepare(
      `SELECT l.*, dr.title AS rule_title, dr.status AS rule_status, dr.mitre_techniques AS rule_mitre_techniques
         FROM threat_actor_detection_rules l
         LEFT JOIN detection_rules dr ON dr.id = l.rule_id AND dr.tenant_id = l.tenant_id
        WHERE l.tenant_id = ? AND l.actor_id = ?
        ORDER BY l.priority, l.created_at`
    ).all(tid, aid) as any[]).map(storage._taRuleLinkRowToDto);
    const relevantTenants = storage.listThreatActorTenants(tid, aid);
    return { ...head, ttps, tools, campaigns, iocs, references, ruleLinks, relevantTenants };
  },

  // ----- Tenant relevance tagging (v2.30.5) -----
  /** List tenant tags for an actor, joined with tenant name + scope. The
   *  caller must own the actor (tid). Returns rows for tenants other than
   *  the owner only — the owner tenant is implicit. */
  listThreatActorTenants(tid: string, aid: string): ThreatActorTenantDTO[] {
    const rows = sqlite.prepare(
      `SELECT t.*, te.name AS tenant_name,
              ts.industries AS tenant_industries,
              ts.geos AS tenant_geos
         FROM threat_actor_tenants t
         LEFT JOIN tenants te ON te.id = t.tenant_id
         LEFT JOIN tenant_scopes ts ON ts.tenant_id = t.tenant_id
        WHERE t.owner_tenant_id = ? AND t.actor_id = ?
        ORDER BY
          CASE t.relevance WHEN 'targeted' THEN 0 WHEN 'sector-match' THEN 1 ELSE 2 END,
          t.created_at DESC`
    ).all(tid, aid) as any[];
    return rows.map((r) => {
      // Pick first industry / geo as a short pill label.
      let sector: string | null = null;
      let region: string | null = null;
      try {
        const inds: string[] = JSON.parse(r.tenant_industries || "[]");
        if (Array.isArray(inds) && inds.length > 0) sector = inds[0];
      } catch { /* ignore */ }
      try {
        const geos: string[] = JSON.parse(r.tenant_geos || "[]");
        if (Array.isArray(geos) && geos.length > 0) region = geos[0];
      } catch { /* ignore */ }
      return storage._taTenantRowToDto({ ...r, tenant_sector: sector, tenant_region: region });
    });
  },

  /** Add (or upsert relevance/rationale on) a tenant tag for an actor.
   *  Idempotent: re-tagging the same (actor, tenant) pair updates the row. */
  addThreatActorTenant(
    tid: string, aid: string,
    input: { tenantId: string; relevance?: TenantRelevance; rationale?: string | null },
    by: { taggedBy: string | null; taggedByAi: boolean }
  ): ThreatActorTenantDTO {
    const now = new Date().toISOString();
    const existing = sqlite.prepare(
      "SELECT id FROM threat_actor_tenants WHERE owner_tenant_id = ? AND actor_id = ? AND tenant_id = ?"
    ).get(tid, aid, input.tenantId) as any;
    if (existing) {
      sqlite.prepare(
        `UPDATE threat_actor_tenants
            SET relevance = ?, rationale = ?, tagged_by = ?, tagged_by_ai = ?
          WHERE id = ?`
      ).run(
        input.relevance ?? "watching",
        input.rationale ?? null,
        by.taggedBy ?? null,
        by.taggedByAi ? 1 : 0,
        existing.id,
      );
      const list = storage.listThreatActorTenants(tid, aid);
      const hit = list.find((t) => t.id === existing.id);
      if (hit) return hit;
    }
    const id = randomUUID();
    sqlite.prepare(
      `INSERT INTO threat_actor_tenants
         (id, owner_tenant_id, actor_id, tenant_id, relevance, rationale, tagged_by, tagged_by_ai, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      id, tid, aid, input.tenantId,
      input.relevance ?? "watching",
      input.rationale ?? null,
      by.taggedBy ?? null,
      by.taggedByAi ? 1 : 0,
      now,
    );
    const list = storage.listThreatActorTenants(tid, aid);
    return list.find((t) => t.id === id)!;
  },

  patchThreatActorTenant(
    tid: string, aid: string, tagId: string,
    patch: { relevance?: TenantRelevance; rationale?: string | null },
  ): ThreatActorTenantDTO | undefined {
    const sets: string[] = [];
    const args: any[] = [];
    if (patch.relevance !== undefined) { sets.push("relevance = ?"); args.push(patch.relevance); }
    if (patch.rationale !== undefined) { sets.push("rationale = ?"); args.push(patch.rationale); }
    if (sets.length === 0) {
      return storage.listThreatActorTenants(tid, aid).find((t) => t.id === tagId);
    }
    args.push(tid, aid, tagId);
    const res = sqlite.prepare(
      `UPDATE threat_actor_tenants SET ${sets.join(", ")} WHERE owner_tenant_id = ? AND actor_id = ? AND id = ?`
    ).run(...args);
    if (res.changes === 0) return undefined;
    return storage.listThreatActorTenants(tid, aid).find((t) => t.id === tagId);
  },

  removeThreatActorTenant(tid: string, aid: string, tagId: string): boolean {
    const res = sqlite.prepare(
      "DELETE FROM threat_actor_tenants WHERE owner_tenant_id = ? AND actor_id = ? AND id = ?"
    ).run(tid, aid, tagId);
    return res.changes > 0;
  },

  /** Batch read — returns every tenant tag for every actor owned by `tid`,
   *  joined with tenant name. Used by the Threat Actors page to render
   *  tenant chips on cards and to group the kanban by client without making
   *  N+1 calls. */
  listAllThreatActorTenants(tid: string): ThreatActorTenantDTO[] {
    const rows = sqlite.prepare(
      `SELECT t.*, te.name AS tenant_name,
              ts.industries AS tenant_industries,
              ts.geos AS tenant_geos
         FROM threat_actor_tenants t
         LEFT JOIN tenants te ON te.id = t.tenant_id
         LEFT JOIN tenant_scopes ts ON ts.tenant_id = t.tenant_id
        WHERE t.owner_tenant_id = ?
        ORDER BY t.actor_id,
          CASE t.relevance WHEN 'targeted' THEN 0 WHEN 'sector-match' THEN 1 ELSE 2 END,
          t.created_at DESC`
    ).all(tid) as any[];
    return rows.map((r) => {
      let sector: string | null = null;
      let region: string | null = null;
      try {
        const inds: string[] = JSON.parse(r.tenant_industries || "[]");
        if (Array.isArray(inds) && inds.length > 0) sector = inds[0];
      } catch { /* ignore */ }
      try {
        const geos: string[] = JSON.parse(r.tenant_geos || "[]");
        if (Array.isArray(geos) && geos.length > 0) region = geos[0];
      } catch { /* ignore */ }
      return storage._taTenantRowToDto({ ...r, tenant_sector: sector, tenant_region: region });
    });
  },

  /** All tenants visible to the owner so the AI / UI can suggest candidates.
   *  In single-org deployments this returns just the owner tenant; in MSSP
   *  mode the admin can list more. */
  listAvailableTenantsForTagging(_tid: string): Array<{ id: string; name: string; sector: string | null; region: string | null; orgSize: string | null }> {
    const rows = sqlite.prepare(
      `SELECT te.id, te.name,
              ts.industries AS industries, ts.geos AS geos, ts.client_types AS client_types
         FROM tenants te
         LEFT JOIN tenant_scopes ts ON ts.tenant_id = te.id
        ORDER BY te.name`
    ).all() as any[];
    return rows.map((r) => {
      let sector: string | null = null;
      let region: string | null = null;
      let orgSize: string | null = null;
      try { const v: string[] = JSON.parse(r.industries || "[]"); if (v.length) sector = v.join(", "); } catch { /* ignore */ }
      try { const v: string[] = JSON.parse(r.geos || "[]"); if (v.length) region = v.join(", "); } catch { /* ignore */ }
      try { const v: string[] = JSON.parse(r.client_types || "[]"); if (v.length) orgSize = v.join(", "); } catch { /* ignore */ }
      return { id: r.id, name: r.name, sector, region, orgSize };
    });
  },

  /** Create a shell TAP from just a name (and optional aliases). Returns the
   *  freshly-inserted header DTO. When `enrich` is true the caller is expected
   *  to call enrichThreatActor() separately so the long DeepSeek call doesn't
   *  block the HTTP write. */
  createThreatActor(tid: string, opts: {
    primaryName: string;
    aliases?: string[];
    actorType?: ActorType;
    sponsorship?: SponsorshipLevel;
    mitreGroupId?: string | null;
    motivation?: string[];
    tlp?: TlpLevel;
    createdBy: string;
  }): ThreatActorDTO {
    // Reuse existing actor if same name already exists (idempotent backfill).
    const existing = storage.findThreatActorByName(tid, opts.primaryName);
    if (existing) return existing;
    const aid = id();
    const ts = now();
    const profileId = storage._nextTapProfileId(tid);
    sqlite.prepare(`INSERT INTO threat_actors (
      id, tenant_id, profile_id, primary_name, mitre_group_id,
      aliases, vendor_names, actor_type, sponsorship,
      motivation, tlp,
      status, version, created_at, updated_at, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      aid, tid, profileId, opts.primaryName.trim(),
      opts.mitreGroupId ?? null,
      j(opts.aliases ?? []), JSON.stringify({}),
      opts.actorType ?? "Unknown", opts.sponsorship ?? "Unknown",
      j(opts.motivation ?? []), opts.tlp ?? "AMBER",
      "draft", 1, ts, ts, opts.createdBy,
    );
    storage.appendAudit(tid, opts.createdBy, "threat_actor.create", aid, {
      profileId, primaryName: opts.primaryName,
    });
    return storage.getThreatActor(tid, aid)!;
  },

  updateThreatActor(tid: string, aid: string, patch: Record<string, any> & { actor?: string }): ThreatActorDTO | undefined {
    const actor = patch.actor ?? "system";
    const row = sqlite.prepare("SELECT * FROM threat_actors WHERE tenant_id = ? AND id = ?").get(tid, aid) as any;
    if (!row) return undefined;
    const map: Record<string, string> = {
      primaryName: "primary_name", mitreGroupId: "mitre_group_id",
      assessedOrigin: "assessed_origin", originConfidence: "origin_confidence",
      sponsoringEntity: "sponsoring_entity", activeSince: "active_since",
      sophistication: "sophistication", tlp: "tlp",
      admiraltySource: "admiralty_source", admiraltyInfo: "admiralty_info",
      wepConfidence: "wep_confidence",
      orgSizePreference: "org_size_preference", intentProximity: "intent_proximity",
      relevanceRating: "relevance_rating",
      execWhat: "exec_what", execSoWhat: "exec_so_what", execWhatNow: "exec_what_now",
      threatLevel: "threat_level", threatLevelRationale: "threat_level_rationale",
      forecast: "forecast", bodyMd: "body_md", status: "status",
      cutoffDate: "cutoff_date", preparedBy: "prepared_by",
      actorType: "actor_type", sponsorship: "sponsorship",
    };
    const jsonMap: Record<string, string> = {
      aliases: "aliases", vendorNames: "vendor_names", motivation: "motivation",
      targetSectors: "target_sectors", targetRegions: "target_regions",
      targetTechStack: "target_tech_stack",
      diamondAdversary: "diamond_adversary", diamondCapability: "diamond_capability",
      diamondInfrastructure: "diamond_infrastructure",
      diamondVictim: "diamond_victim", diamondMeta: "diamond_meta",
      businessImpact: "business_impact", capabilityProfile: "capability_profile",
      infrastructureProfile: "infrastructure_profile",
      irActions: "ir_actions", countermeasures: "countermeasures",
      extortionTactics: "extortion_tactics",
    };
    const sets: string[] = [];
    const args: any[] = [];
    for (const [k, col] of Object.entries(map)) {
      if (k in patch) {
        sets.push(`${col} = ?`);
        args.push(patch[k]);
      }
    }
    for (const [k, col] of Object.entries(jsonMap)) {
      if (k in patch) {
        sets.push(`${col} = ?`);
        args.push(JSON.stringify(patch[k] ?? (Array.isArray(patch[k]) ? [] : {})));
      }
    }
    if ("sectorActivelyTargeted" in patch) {
      sets.push("sector_actively_targeted = ?");
      args.push(patch.sectorActivelyTargeted ? 1 : 0);
    }
    if (sets.length === 0) return storage.getThreatActor(tid, aid);
    sets.push("version = version + 1");
    sets.push("updated_at = ?");
    args.push(now());
    args.push(tid, aid);
    sqlite.prepare(`UPDATE threat_actors SET ${sets.join(", ")} WHERE tenant_id = ? AND id = ?`).run(...args);
    storage.appendAudit(tid, actor, "threat_actor.update", aid, {
      fields: Object.keys(patch).filter((k) => k !== "actor"),
    });
    return storage.getThreatActor(tid, aid);
  },

  // v2.32 — portrait lifecycle helpers (bypass the regular updateThreatActor
  // because portrait fields are server-managed, not analyst-editable, and
  // shouldn't bump version or trigger an audit event).
  setThreatActorPortrait(tid: string, aid: string, url: string): void {
    sqlite.prepare(
      `UPDATE threat_actors
          SET portrait_url = ?, portrait_generated_at = ?, portrait_status = 'ready'
        WHERE tenant_id = ? AND id = ?`
    ).run(url, new Date().toISOString(), tid, aid);
  },
  setThreatActorPortraitStatus(tid: string, aid: string, status: "idle" | "generating" | "ready" | "failed"): void {
    sqlite.prepare(
      `UPDATE threat_actors SET portrait_status = ? WHERE tenant_id = ? AND id = ?`
    ).run(status, tid, aid);
  },
  /** Clear the portrait fields (analyst removed an uploaded or AI-generated image).
   *  Resets status to 'idle' so the lazy-fire IntersectionObserver may re-fire on the
   *  next viewport entry — uploads are explicit user actions and don't suppress that. */
  clearThreatActorPortrait(tid: string, aid: string): void {
    sqlite.prepare(
      `UPDATE threat_actors
          SET portrait_url = NULL, portrait_generated_at = NULL, portrait_status = 'idle'
        WHERE tenant_id = ? AND id = ?`
    ).run(tid, aid);
  },

  deleteThreatActor(tid: string, aid: string, actor: string): boolean {
    const row = sqlite.prepare("SELECT id FROM threat_actors WHERE tenant_id = ? AND id = ?").get(tid, aid) as any;
    if (!row) return false;
    sqlite.prepare("DELETE FROM threat_actor_ttps WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_tools WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_campaigns WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_iocs WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_references WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_detection_rules WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_tenants WHERE owner_tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actors WHERE tenant_id = ? AND id = ?").run(tid, aid);
    storage.appendAudit(tid, actor, "threat_actor.delete", aid, {});
    return true;
  },

  // ---- TTPs ----
  addThreatActorTtp(tid: string, aid: string, body: any, actor: string): ThreatActorTtpDTO {
    const tid_ = id();
    const ts = now();
    sqlite.prepare(`INSERT INTO threat_actor_ttps (
      id, tenant_id, actor_id, tactic, technique_id, sub_technique_id,
      technique_name, evidence, status, detection_priority, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      tid_, tid, aid, body.tactic, body.techniqueId, body.subTechniqueId ?? null,
      body.techniqueName, body.evidence ?? null,
      body.status ?? "suspected", body.detectionPriority ?? "P3", ts,
    );
    storage.appendAudit(tid, actor, "threat_actor.ttp.add", aid, { ttpId: tid_, techniqueId: body.techniqueId });
    return storage._taTtpRowToDto(sqlite.prepare("SELECT * FROM threat_actor_ttps WHERE id = ?").get(tid_));
  },
  deleteThreatActorTtp(tid: string, aid: string, ttpId: string, actor: string): boolean {
    const res = sqlite.prepare("DELETE FROM threat_actor_ttps WHERE tenant_id = ? AND actor_id = ? AND id = ?").run(tid, aid, ttpId);
    if (res.changes > 0) storage.appendAudit(tid, actor, "threat_actor.ttp.delete", aid, { ttpId });
    return res.changes > 0;
  },

  // ---- Tools ----
  addThreatActorTool(tid: string, aid: string, body: any, actor: string): ThreatActorToolDTO {
    const tid_ = id(); const ts = now();
    sqlite.prepare(`INSERT INTO threat_actor_tools (
      id, tenant_id, actor_id, name, category, purpose, variants, hash_or_rule, confidence, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      tid_, tid, aid, body.name, body.category ?? null, body.purpose ?? null,
      j(body.variants ?? []), body.hashOrRule ?? null, body.confidence ?? "Likely", ts,
    );
    storage.appendAudit(tid, actor, "threat_actor.tool.add", aid, { toolId: tid_, name: body.name });
    return storage._taToolRowToDto(sqlite.prepare("SELECT * FROM threat_actor_tools WHERE id = ?").get(tid_));
  },
  deleteThreatActorTool(tid: string, aid: string, toolId: string, actor: string): boolean {
    const res = sqlite.prepare("DELETE FROM threat_actor_tools WHERE tenant_id = ? AND actor_id = ? AND id = ?").run(tid, aid, toolId);
    if (res.changes > 0) storage.appendAudit(tid, actor, "threat_actor.tool.delete", aid, { toolId });
    return res.changes > 0;
  },

  // ---- Campaigns ----
  addThreatActorCampaign(tid: string, aid: string, body: any, actor: string): ThreatActorCampaignDTO {
    const cid = id(); const ts = now();
    sqlite.prepare(`INSERT INTO threat_actor_campaigns (
      id, tenant_id, actor_id, name, period, target_sector, target_geography,
      initial_access, outcome, source_url, finding_ids, rule_ids, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      cid, tid, aid, body.name, body.period ?? null,
      body.targetSector ?? null, body.targetGeography ?? null,
      body.initialAccess ?? null, body.outcome ?? null, body.sourceUrl ?? null,
      j(body.findingIds ?? []), j(body.ruleIds ?? []), ts,
    );
    storage.appendAudit(tid, actor, "threat_actor.campaign.add", aid, { campaignId: cid, name: body.name });
    return storage._taCampaignRowToDto(sqlite.prepare("SELECT * FROM threat_actor_campaigns WHERE id = ?").get(cid));
  },
  deleteThreatActorCampaign(tid: string, aid: string, cid: string, actor: string): boolean {
    const res = sqlite.prepare("DELETE FROM threat_actor_campaigns WHERE tenant_id = ? AND actor_id = ? AND id = ?").run(tid, aid, cid);
    if (res.changes > 0) storage.appendAudit(tid, actor, "threat_actor.campaign.delete", aid, { campaignId: cid });
    return res.changes > 0;
  },

  // ---- IoCs ----
  addThreatActorIoc(tid: string, aid: string, body: any, actor: string): ThreatActorIocDTO {
    const iid = id(); const ts = now();
    sqlite.prepare(`INSERT INTO threat_actor_iocs (
      id, tenant_id, actor_id, ioc_type, value, first_seen, last_confirmed,
      confidence, tlp, source, mitre_ttps, recommended_action, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      iid, tid, aid, body.iocType, body.value,
      body.firstSeen ?? null, body.lastConfirmed ?? null,
      body.confidence ?? "Likely", body.tlp ?? "AMBER",
      body.source ?? null, j(body.mitreTtps ?? []),
      body.recommendedAction ?? null, ts,
    );
    storage.appendAudit(tid, actor, "threat_actor.ioc.add", aid, { iocId: iid, iocType: body.iocType });
    return storage._taIocRowToDto(sqlite.prepare("SELECT * FROM threat_actor_iocs WHERE id = ?").get(iid));
  },
  deleteThreatActorIoc(tid: string, aid: string, iid: string, actor: string): boolean {
    const res = sqlite.prepare("DELETE FROM threat_actor_iocs WHERE tenant_id = ? AND actor_id = ? AND id = ?").run(tid, aid, iid);
    if (res.changes > 0) storage.appendAudit(tid, actor, "threat_actor.ioc.delete", aid, { iocId: iid });
    return res.changes > 0;
  },

  // ---- References ----
  addThreatActorReference(tid: string, aid: string, body: any, actor: string): ThreatActorReferenceDTO {
    const rid = id(); const ts = now();
    // Auto-number when caller doesn't pass refNum.
    let refNum = body.refNum;
    if (!refNum) {
      const cur = sqlite.prepare("SELECT COALESCE(MAX(ref_num), 0) AS m FROM threat_actor_references WHERE tenant_id = ? AND actor_id = ?").get(tid, aid) as any;
      refNum = (cur?.m ?? 0) + 1;
    }
    sqlite.prepare(`INSERT INTO threat_actor_references (
      id, tenant_id, actor_id, ref_num, source_type, title, date, url, archive_url, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      rid, tid, aid, refNum, body.sourceType ?? null, body.title,
      body.date ?? null, body.url ?? null, body.archiveUrl ?? null, ts,
    );
    storage.appendAudit(tid, actor, "threat_actor.reference.add", aid, { refId: rid, refNum });
    return storage._taRefRowToDto(sqlite.prepare("SELECT * FROM threat_actor_references WHERE id = ?").get(rid));
  },
  deleteThreatActorReference(tid: string, aid: string, rid: string, actor: string): boolean {
    const res = sqlite.prepare("DELETE FROM threat_actor_references WHERE tenant_id = ? AND actor_id = ? AND id = ?").run(tid, aid, rid);
    if (res.changes > 0) storage.appendAudit(tid, actor, "threat_actor.reference.delete", aid, { refId: rid });
    return res.changes > 0;
  },

  // ---- Rule links ----
  linkThreatActorDetectionRule(tid: string, aid: string, body: { ruleId: string; priority?: DetectionPriority; notes?: string | null }, actor: string): ThreatActorRuleLinkDTO {
    const lid = id(); const ts = now();
    sqlite.prepare(`INSERT OR IGNORE INTO threat_actor_detection_rules (
      id, tenant_id, actor_id, rule_id, priority, notes, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
      lid, tid, aid, body.ruleId, body.priority ?? "P3", body.notes ?? null, ts,
    );
    storage.appendAudit(tid, actor, "threat_actor.rule.link", aid, { ruleId: body.ruleId });
    const row = sqlite.prepare(
      `SELECT l.*, dr.title AS rule_title, dr.status AS rule_status, dr.mitre_techniques AS rule_mitre_techniques
         FROM threat_actor_detection_rules l
         LEFT JOIN detection_rules dr ON dr.id = l.rule_id AND dr.tenant_id = l.tenant_id
        WHERE l.tenant_id = ? AND l.actor_id = ? AND l.rule_id = ?`
    ).get(tid, aid, body.ruleId) as any;
    return storage._taRuleLinkRowToDto(row);
  },
  unlinkThreatActorDetectionRule(tid: string, aid: string, ruleId: string, actor: string): boolean {
    const res = sqlite.prepare("DELETE FROM threat_actor_detection_rules WHERE tenant_id = ? AND actor_id = ? AND rule_id = ?").run(tid, aid, ruleId);
    if (res.changes > 0) storage.appendAudit(tid, actor, "threat_actor.rule.unlink", aid, { ruleId });
    return res.changes > 0;
  },

  /** Run AI-backed enrichment and persist everything in one shot.
   *  Sub-resource tables are wiped + repopulated; the header row is updated
   *  in-place. Throws on AI failure so the route can surface real errors. */
  async enrichThreatActor(tid: string, aid: string, opts: { force?: boolean; actor: string; providerId?: string | null }): Promise<ThreatActorFullDTO> {
    const head = storage.getThreatActor(tid, aid);
    if (!head) throw new Error(`threat actor not found: ${aid}`);
    // v2.30.6 — one-off provider override (from the TAP detail sheet picker)
    // wins over the tenant default resolver.
    let provider: AiProvider | undefined;
    if (opts.providerId) {
      provider = db.select().from(aiProviders)
        .where(and(eq(aiProviders.id, opts.providerId), eq(aiProviders.tenantId, tid)))
        .get();
      if (provider && (!provider.enabled || !aiProviderHasSecret(provider) || provider.lastTestOk !== 1)) provider = undefined;
      provider = hydrateAiProviderSecret(provider);
    }
    if (!provider) provider = storage.resolveAiProvider(tid, "threat_actor_enrichment");
    if (!provider) {
      throw new Error("no AI provider is configured for threat_actor_enrichment — connect one in AI Setup");
    }
    // v2.30.5 — give the AI the list of tenants it may tag as relevant.
    const availableTenants = storage.listAvailableTenantsForTagging(tid);
    const result = dispatchAi({
      task: "threat_actor_enrichment",
      input: {
        primaryName: head.primaryName,
        aliases: head.aliases,
        actorType: head.actorType,
        knownContext: head.bodyMd ? `Existing draft notes:\n${head.bodyMd.slice(0, 2000)}` : undefined,
        availableTenants,
      },
      provider,
    });
    if (result.task !== "threat_actor_enrichment") throw new Error("unexpected AI result");
    const out = result.output;
    const ts = now();
    // Update header
    sqlite.prepare(`UPDATE threat_actors SET
      mitre_group_id = ?, aliases = ?, vendor_names = ?,
      actor_type = ?, sponsorship = ?,
      assessed_origin = ?, origin_confidence = ?, sponsoring_entity = ?,
      motivation = ?, active_since = ?, sophistication = ?,
      tlp = ?, admiralty_source = ?, admiralty_info = ?, wep_confidence = ?,
      target_sectors = ?, target_regions = ?, target_tech_stack = ?,
      org_size_preference = ?, intent_proximity = ?,
      exec_what = ?, exec_so_what = ?, exec_what_now = ?,
      threat_level = ?, threat_level_rationale = ?, sector_actively_targeted = ?,
      diamond_adversary = ?, diamond_capability = ?, diamond_infrastructure = ?,
      diamond_victim = ?, diamond_meta = ?,
      business_impact = ?, capability_profile = ?, infrastructure_profile = ?,
      ir_actions = ?, countermeasures = ?, forecast = ?, extortion_tactics = ?,
      body_md = ?, ai_provider_label = ?, version = version + 1, updated_at = ?
     WHERE tenant_id = ? AND id = ?`).run(
      out.mitreGroupId,
      JSON.stringify(out.aliases), JSON.stringify(out.vendorNames),
      out.actorType, out.sponsorship,
      out.assessedOrigin, out.originConfidence, out.sponsoringEntity,
      JSON.stringify(out.motivation), out.activeSince, out.sophistication,
      out.tlp, out.admiraltySource, out.admiraltyInfo, out.wepConfidence,
      JSON.stringify(out.targetSectors), JSON.stringify(out.targetRegions),
      JSON.stringify(out.targetTechStack),
      out.orgSizePreference, out.intentProximity,
      out.execWhat, out.execSoWhat, out.execWhatNow,
      out.threatLevel, out.threatLevelRationale, out.sectorActivelyTargeted ? 1 : 0,
      JSON.stringify(out.diamondAdversary), JSON.stringify(out.diamondCapability),
      JSON.stringify(out.diamondInfrastructure),
      JSON.stringify(out.diamondVictim), JSON.stringify(out.diamondMeta),
      JSON.stringify(out.businessImpact), JSON.stringify(out.capabilityProfile),
      JSON.stringify(out.infrastructureProfile),
      JSON.stringify(out.irActions), JSON.stringify(out.countermeasures),
      out.forecast, JSON.stringify(out.extortionTactics),
      out.bodyMd, provider.label, ts, tid, aid,
    );
    // Wipe + replace sub-resources
    sqlite.prepare("DELETE FROM threat_actor_ttps WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_tools WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_campaigns WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_iocs WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    sqlite.prepare("DELETE FROM threat_actor_references WHERE tenant_id = ? AND actor_id = ?").run(tid, aid);
    for (const t of out.ttps) {
      sqlite.prepare(`INSERT INTO threat_actor_ttps (
        id, tenant_id, actor_id, tactic, technique_id, sub_technique_id,
        technique_name, evidence, status, detection_priority, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        id(), tid, aid, t.tactic, t.techniqueId, t.subTechniqueId ?? null,
        t.techniqueName, t.evidence ?? null,
        t.status ?? "suspected", t.detectionPriority ?? "P3", ts,
      );
    }
    for (const t of out.tools) {
      sqlite.prepare(`INSERT INTO threat_actor_tools (
        id, tenant_id, actor_id, name, category, purpose, variants, hash_or_rule, confidence, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        id(), tid, aid, t.name, t.category ?? null, t.purpose ?? null,
        j(t.variants ?? []), t.hashOrRule ?? null, t.confidence ?? "Likely", ts,
      );
    }
    for (const c of out.campaigns) {
      sqlite.prepare(`INSERT INTO threat_actor_campaigns (
        id, tenant_id, actor_id, name, period, target_sector, target_geography,
        initial_access, outcome, source_url, finding_ids, rule_ids, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        id(), tid, aid, c.name, c.period ?? null,
        c.targetSector ?? null, c.targetGeography ?? null,
        c.initialAccess ?? null, c.outcome ?? null, c.sourceUrl ?? null,
        "[]", "[]", ts,
      );
    }
    for (const i of out.iocs) {
      sqlite.prepare(`INSERT INTO threat_actor_iocs (
        id, tenant_id, actor_id, ioc_type, value, first_seen, last_confirmed,
        confidence, tlp, source, mitre_ttps, recommended_action, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        id(), tid, aid, i.iocType, i.value,
        i.firstSeen ?? null, i.lastConfirmed ?? null,
        i.confidence ?? "Likely", i.tlp ?? "AMBER",
        i.source ?? null, j(i.mitreTtps ?? []),
        i.recommendedAction ?? null, ts,
      );
    }
    let refIdx = 1;
    for (const r of out.references) {
      sqlite.prepare(`INSERT INTO threat_actor_references (
        id, tenant_id, actor_id, ref_num, source_type, title, date, url, archive_url, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        id(), tid, aid, r.refNum ?? refIdx, r.sourceType ?? null, r.title,
        r.date ?? null, r.url ?? null, r.archiveUrl ?? null, ts,
      );
      refIdx += 1;
    }
    // v2.30.5 — persist AI-suggested tenant relevance tags. We only insert
    // taggedByAi=true rows; analyst-set rows are left alone. Any existing
    // AI-suggested row for a (actor, tenant) pair is replaced.
    const aiTags = Array.isArray((out as any).relevantTenants) ? (out as any).relevantTenants : [];
    if (aiTags.length > 0) {
      // Wipe previous AI-tagged rows for this actor so we don't accumulate
      // stale suggestions across re-runs.
      sqlite.prepare(
        "DELETE FROM threat_actor_tenants WHERE owner_tenant_id = ? AND actor_id = ? AND tagged_by_ai = 1"
      ).run(tid, aid);
      for (const t of aiTags) {
        try {
          storage.addThreatActorTenant(
            tid, aid,
            { tenantId: t.tenantId, relevance: t.relevance, rationale: t.rationale ?? null },
            { taggedBy: "ai", taggedByAi: true },
          );
        } catch { /* ignore individual tag errors */ }
      }
    }
    storage.appendAudit(tid, opts.actor, "threat_actor.enrich", aid, {
      provider: provider.label,
      ttps: out.ttps.length, tools: out.tools.length,
      campaigns: out.campaigns.length, iocs: out.iocs.length,
      references: out.references.length,
      tenantTags: aiTags.length,
    });
    return storage.getFullThreatActor(tid, aid)!;
  },

  /** Backfill: scan distinct threatActors values from findings + detection_rules
   *  and create one shell TAP per name that doesn't already exist. Returns the
   *  number of new actors inserted. Safe to call on every boot; idempotent. */
  backfillThreatActorsFromExistingData(tid: string, opts?: { createdBy?: string }): number {
    const createdBy = opts?.createdBy ?? "system";
    const currentCatalog = sqlite.prepare(
      "SELECT COUNT(DISTINCT primary_name) AS n FROM threat_actors WHERE tenant_id = ?"
    ).get(tid) as { n: number };
    if ((currentCatalog?.n ?? 0) >= 100) return 0;
    const curated = sqlite.prepare(
      "SELECT COUNT(*) AS n FROM threat_actors WHERE tenant_id = ? AND prepared_by = 'OptraSight research seed'"
    ).get(tid) as { n: number };
    if ((curated?.n ?? 0) >= 50) return 0;
    const names = new Set<string>();
    const fRows = sqlite.prepare("SELECT threat_actors FROM osint_findings WHERE tenant_id = ?").all(tid) as any[];
    for (const r of fRows) {
      try {
        const arr = JSON.parse(r.threat_actors || "[]");
        if (Array.isArray(arr)) for (const n of arr) if (typeof n === "string" && n.trim()) names.add(n.trim());
      } catch { /* ignore */ }
    }
    const dRows = sqlite.prepare("SELECT threat_actors FROM detection_rules WHERE tenant_id = ?").all(tid) as any[];
    for (const r of dRows) {
      try {
        const arr = JSON.parse(r.threat_actors || "[]");
        if (Array.isArray(arr)) for (const n of arr) if (typeof n === "string" && n.trim()) names.add(n.trim());
      } catch { /* ignore */ }
    }
    let created = 0;
    for (const name of names) {
      if (storage.findThreatActorByName(tid, name)) continue;
      storage.createThreatActor(tid, { primaryName: name, createdBy });
      created += 1;
    }
    return created;
  },

  // ---------- Threat landscape ----------
  generateThreatLandscape(tid: string, opts: { title?: string; createdBy: string }): ThreatLandscapeDTO {
    const tenant = storage.getTenant(tid);
    const provider = storage.resolveAiProvider(tid, "threat_landscape");
    const recent = storage.listOsintFindings(tid).slice(0, 30);
    const tlid = id();
    const prevVersions = sqlite.prepare("SELECT MAX(version) as v FROM threat_landscapes WHERE tenant_id = ?").get(tid) as any;
    const version = (prevVersions?.v ?? 0) + 1;
    const title = opts.title ?? `Threat landscape — ${tenant?.name ?? "client"} v${version}`;
    if (!provider) throw new Error("No AI provider is configured for threat landscape generation.");
    const r = dispatchAi({
      task: "threat_landscape",
      input: {
        clientName: tenant?.name ?? "Client",
        profile: {
          clientTypes: BATCH_ONE_WORKSPACE_PROFILE.clientTypes,
          industries: BATCH_ONE_WORKSPACE_PROFILE.industries,
          geos: BATCH_ONE_WORKSPACE_PROFILE.geos,
          monitoredTechnologies: BATCH_ONE_WORKSPACE_PROFILE.monitoredTechnologies,
        },
        recentSignals: recent.slice(0, 15).map((f) => ({
          title: f.title, severity: f.severity, affectedTech: f.affectedTech, threatActors: f.threatActors,
        })),
      },
      provider,
    });
    if (r.task !== "threat_landscape" || !r.output.bodyMd?.trim()) {
      throw new Error("AI provider did not return a threat landscape report.");
    }
    const bodyMd = r.output.bodyMd;
    const stats = r.output.stats && typeof r.output.stats === "object" ? r.output.stats : {};
    sqlite.prepare(`INSERT INTO threat_landscapes (
      id, tenant_id, version, title, status, body_md, stats, ai_provider_label, created_at, created_by
    ) VALUES (?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?)`).run(
      tlid, tid, version, title, bodyMd, JSON.stringify(stats), provider?.label ?? null, now(), opts.createdBy
    );
    storage.appendAudit(tid, opts.createdBy, "threat_landscape.generate", tlid, { version });
    return {
      id: tlid, tenantId: tid, version, title, status: "ready", bodyMd, stats,
      aiProviderLabel: provider?.label ?? null, createdAt: now(), createdBy: opts.createdBy,
    };
  },

  listThreatLandscapes(tid: string): ThreatLandscapeDTO[] {
    const rows = sqlite.prepare("SELECT * FROM threat_landscapes WHERE tenant_id = ? ORDER BY version DESC LIMIT 30").all(tid) as any[];
    return rows.map((r) => ({
      id: r.id, tenantId: r.tenant_id, version: r.version, title: r.title, status: r.status,
      bodyMd: r.body_md, stats: JSON.parse(r.stats || "{}"),
      aiProviderLabel: r.ai_provider_label, createdAt: r.created_at, createdBy: r.created_by,
    }));
  },

  getThreatLandscape(tid: string, lid: string): ThreatLandscapeDTO | undefined {
    const r = sqlite.prepare("SELECT * FROM threat_landscapes WHERE id = ? AND tenant_id = ?").get(lid, tid) as any;
    if (!r) return undefined;
    return {
      id: r.id, tenantId: r.tenant_id, version: r.version, title: r.title, status: r.status,
      bodyMd: r.body_md, stats: JSON.parse(r.stats || "{}"),
      aiProviderLabel: r.ai_provider_label, createdAt: r.created_at, createdBy: r.created_by,
    };
  },

  searchPlatform(tid: string, q: string, opts?: { global?: boolean; role?: string }): { results: SearchResultDTO[] } {
    const needle = q.trim();
    if (needle.length < 2) return { results: [] };
    const likeQ = `%${needle}%`;
    const global = !!opts?.global && opts.role === "admin";
    const tenantClause = global ? "1=1" : "tenant_id = ?";
    const baseParams = global ? [] : [tid];
    const tenantsById = new Map((sqlite.prepare("SELECT id, name FROM tenants").all() as any[]).map((t) => [t.id, t.name]));
    const out: SearchResultDTO[] = [];
    const push = (r: SearchResultDTO) => { if (out.length < 40) out.push(r); };
    for (const r of sqlite.prepare(`SELECT id, tenant_id, title, severity, status, source_id, cve_ids, threat_actors FROM osint_findings WHERE ${tenantClause} AND (title LIKE ? OR COALESCE(summary,'') LIKE ? OR cve_ids LIKE ? OR threat_actors LIKE ?) ORDER BY published_at DESC LIMIT 10`).all(...baseParams, likeQ, likeQ, likeQ, likeQ) as any[]) {
      push({ id: r.id, type: "Intel finding", title: r.title, subtitle: `${p<string[]>(r.cve_ids, []).slice(0, 2).join(", ") || r.source_id}`, href: `#/osint?finding=${r.id}`, severity: r.severity, status: r.status, tenantName: tenantsById.get(r.tenant_id) ?? null, action: "generate_detection" });
    }
    for (const r of sqlite.prepare(`SELECT id, tenant_id, profile_id, primary_name, threat_level, status FROM threat_actors WHERE ${tenantClause} AND (primary_name LIKE ? OR aliases LIKE ? OR COALESCE(mitre_group_id,'') LIKE ?) ORDER BY updated_at DESC LIMIT 8`).all(...baseParams, likeQ, likeQ, likeQ) as any[]) {
      push({ id: r.id, type: "Threat actor", title: r.primary_name, subtitle: `${r.profile_id} · ${r.threat_level}`, href: `#/threat-actors?actor=${r.id}`, severity: r.threat_level, status: r.status, tenantName: tenantsById.get(r.tenant_id) ?? null, action: "open" });
    }
    return { results: out };
  },

  // ---------- Audit log ----------
  appendAudit(tid: string, actor: string, action: string, target: string | null, detail: Record<string, any>): void {
    sqlite.prepare("INSERT INTO audit_log (id, tenant_id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id(), tid, actor, action, target, JSON.stringify(detail || {}), now());
  },
  listAudit(tid: string, opts?: { limit?: number } | number): AuditLogEntry[] {
    const limit = typeof opts === "number" ? opts : (opts?.limit ?? 200);
    return db.select().from(auditLogTbl).where(eq(auditLogTbl.tenantId, tid))
      .orderBy(desc(auditLogTbl.createdAt)).limit(limit).all();
  },

  listOperationsJobs(tid: string, opts?: { max?: number }): any[] {
    const max = Math.max(20, Math.min(300, opts?.max ?? 120));
    const activeStatuses = new Set(["queued", "running"]);
    const terminalSuccessStatuses = new Set(["completed", "done", "succeeded"]);
    const normalizeProgress = (status: string, pct?: number | null): number => {
      if (terminalSuccessStatuses.has(status)) return 100;
      return Math.max(0, Math.min(100, Math.round(Number(pct ?? 0))));
    };
    const aiRows = sqlite.prepare(
      `SELECT id, tenant_id, kind, status, progress_pct, provider_label, created_by, created_at,
              started_at, completed_at, target_label, target_url, heartbeat_at, error_json, result_json
         FROM ai_jobs
        WHERE tenant_id = ?
        ORDER BY CASE WHEN status IN ('queued','running') THEN 0 ELSE 1 END, COALESCE(started_at, created_at) DESC
        LIMIT ?`,
    ).all(tid, max) as any[];
    const reRows = sqlite.prepare(
      `SELECT id, tenant_id, status, total_count, done_count, fail_count, started_at, finished_at, error
         FROM osint_reanalyze_jobs
        WHERE tenant_id = ?
        ORDER BY CASE WHEN status IN ('queued','running') THEN 0 ELSE 1 END, started_at DESC
        LIMIT ?`,
    ).all(tid, max) as any[];

    const jobs = [
      ...aiRows.map((r) => {
        const error = p<any>(r.error_json, null);
        return {
          source: "ai_job",
          id: r.id,
          tenantId: r.tenant_id,
          kind: r.kind,
          label: r.target_label || r.kind,
          status: r.status,
          progressPct: normalizeProgress(r.status, r.progress_pct),
          providerLabel: r.provider_label || null,
          actor: r.created_by || null,
          createdAt: r.created_at,
          startedAt: r.started_at || null,
          finishedAt: r.completed_at || null,
          heartbeatAt: r.heartbeat_at || null,
          target: r.target_label || null,
          targetUrl: r.target_url || null,
          errorMessage: error?.message ?? null,
          resultBytes: r.result_json ? Buffer.byteLength(r.result_json, "utf8") : 0,
          cancellable: activeStatuses.has(r.status),
        };
      }),
      ...reRows.map((r) => {
        const total = Number(r.total_count || 0);
        const done = Number(r.done_count || 0);
        const fail = Number(r.fail_count || 0);
        return {
          source: "osint_reanalyze",
          id: r.id,
          tenantId: r.tenant_id,
          kind: "osint_reanalyze",
          label: "OSINT bulk reanalysis",
          status: r.status,
          progressPct: total > 0 ? Math.min(100, Math.round(((done + fail) / total) * 100)) : 0,
          providerLabel: null,
          actor: null,
          createdAt: r.started_at,
          startedAt: r.started_at,
          finishedAt: r.finished_at || null,
          heartbeatAt: null,
          target: `${done}/${total} analyzed`,
          targetUrl: "#/operations-audit",
          totalCount: total,
          doneCount: done,
          failCount: fail,
          errorMessage: r.error || null,
          cancellable: activeStatuses.has(r.status),
        };
      }),
    ];

    return jobs
      .sort((a, b) => {
        const aw = activeStatuses.has(a.status) ? 0 : 1;
        const bw = activeStatuses.has(b.status) ? 0 : 1;
        if (aw !== bw) return aw - bw;
        return new Date(b.startedAt || b.createdAt || 0).getTime() - new Date(a.startedAt || a.createdAt || 0).getTime();
      })
      .slice(0, max);
  },

  cancelOperationsJob(tid: string, source: string, jobId: string, actor?: string | null): { ok: boolean; status: string; message?: string } {
    if (source === "ai_job") return storage.cancelAiJob(tid, jobId, actor);
    if (source === "osint_reanalyze") return storage.cancelOsintReanalyzeJob(tid, jobId, actor);
    return { ok: false, status: "not_supported", message: `Cannot cancel ${source}.` };
  },

  cancelAllOperationsJobs(tid: string, actor?: string | null): any[] {
    return storage.listOperationsJobs(tid, { max: 300 })
      .filter((job: any) => job.cancellable)
      .map((job: any) => ({
        source: job.source,
        id: job.id,
        ...storage.cancelOperationsJob(tid, job.source, job.id, actor),
      }));
  },

  // ---------- OSINT overview ----------
  generateOsintOverview(opts: {
    tid?: string;
    persona: OsintOverviewPersona;
    category?: string;
    severity?: string;
    scope: "client" | "global" | "industry" | "geo";
    scopeIds?: string[];
  }): OsintOverviewResultDTO {
    if (opts.scope !== "client") {
      throw new Error("BatchOne overview is tenant-scoped; global overview is not exposed in this release.");
    }
    if (!opts.tid) throw new Error("tid required for BatchOne overview");

    const tenant = storage.getTenant(opts.tid);
    const scopeLabel = tenant?.name ?? "BatchOne workspace";
    const rows = storage.listOsintFindings(opts.tid, { category: opts.category, severity: opts.severity });
    const findingsForAi = rows.slice(0, 60).map((f) => ({
      title: f.title, severity: f.severity, sourceCategory: f.sourceCategory,
      affectedTech: f.affectedTech, cveIds: f.cveIds, threatActors: f.threatActors,
      summary: f.summary, rawSnippet: (f as any).rawSnippet ?? null,
      publishedAt: f.publishedAt, tenantName: tenant?.name,
    }));

    const provider = storage.resolveAiProvider(opts.tid, "osint_overview");
    const personaMeta = OSINT_OVERVIEW_PERSONAS.find((p) => p.id === opts.persona) || OSINT_OVERVIEW_PERSONAS[0];
    if (!provider) {
      throw new Error("No AI provider is configured for OSINT overview.");
    }

    const aiResult = dispatchAi({
      task: "osint_overview",
      input: {
        persona: opts.persona,
        scopeLabel,
        category: opts.category ?? null,
        severityFilter: opts.severity ?? null,
        findings: findingsForAi,
      },
      provider,
    });
    const output = aiResult.task === "osint_overview" ? aiResult.output : { summary: "", keyTakeaways: [], recommendations: [] };

    storage.appendAudit(opts.tid, "system", "osint.overview", null, { persona: opts.persona, scope: "client", count: findingsForAi.length });

    return {
      persona: opts.persona,
      personaLabel: personaMeta.label,
      scopeLabel,
      category: opts.category ?? null,
      severityFilter: opts.severity ?? null,
      findingCount: findingsForAi.length,
      summary: output.summary,
      keyTakeaways: output.keyTakeaways,
      recommendations: output.recommendations,
      generatedAt: now(),
      providerLabel: provider.label,
    };
  },

  // ---------- v2.27 async AI jobs ----------
  /**
   * Create a queued AI job and return its id. The caller is expected to spawn
   * the actual work (e.g. via setImmediate) and use the update methods below
   * to mark it running / completed / failed. The UI polls GET
   * /api/v1/osint/ai-jobs/:id every few seconds until status is terminal.
   */
  createAiJob(opts: {
    tenantId: string; kind: string; payload: any; createdBy?: string | null;
    // v2.30.5 — optional human-readable label + deep-link for the notification tray.
    targetLabel?: string | null;
    targetUrl?: string | null;
  }): string {
    const id = (globalThis as any).crypto?.randomUUID?.() ?? `ajb-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    sqlite.prepare(
      "INSERT INTO ai_jobs (id, tenant_id, kind, status, payload_json, created_by, created_at, progress_pct, target_label, target_url, heartbeat_at) VALUES (?, ?, ?, 'queued', ?, ?, ?, 0, ?, ?, ?)",
    ).run(
      id, opts.tenantId, opts.kind,
      JSON.stringify(opts.payload ?? {}),
      opts.createdBy ?? null,
      new Date().toISOString(),
      opts.targetLabel ?? null,
      opts.targetUrl ?? null,
      new Date().toISOString(),
    );
    return id;
  },
  /** Touch the heartbeat so the reaper doesn't kill long-running jobs that
   *  are making progress. Call from inside the worker periodically. */
  setAiJobHeartbeat(id: string): void {
    sqlite.prepare("UPDATE ai_jobs SET heartbeat_at = ? WHERE id = ?")
      .run(new Date().toISOString(), id);
  },
  updateAiJobTarget(id: string, target: { targetLabel?: string | null; targetUrl?: string | null }): void {
    sqlite.prepare("UPDATE ai_jobs SET target_label = COALESCE(?, target_label), target_url = COALESCE(?, target_url) WHERE id = ?")
      .run(target.targetLabel ?? null, target.targetUrl ?? null, id);
  },
  markAiJobRunning(id: string): void {
    sqlite.prepare("UPDATE ai_jobs SET status = 'running', started_at = ? WHERE id = ? AND status IN ('queued','running')")
      .run(new Date().toISOString(), id);
  },
  setAiJobProgress(id: string, pct: number): void {
    sqlite.prepare("UPDATE ai_jobs SET progress_pct = ? WHERE id = ? AND status != 'cancelled'").run(Math.max(0, Math.min(100, Math.round(pct))), id);
  },
  completeAiJob(id: string, result: any, providerLabel?: string | null): void {
    sqlite.prepare(
      "UPDATE ai_jobs SET status = 'completed', result_json = ?, provider_label = ?, completed_at = ?, progress_pct = 100 WHERE id = ? AND status != 'cancelled'",
    ).run(JSON.stringify(result ?? null), providerLabel ?? null, new Date().toISOString(), id);
  },
  failAiJob(id: string, err: any): void {
    const payload = (err && typeof err === "object")
      ? { name: err.name || "Error", message: String(err.message ?? err), aiDiagnostic: (err as any).diagnostic ?? null, providerLabel: (err as any).providerLabel ?? null }
      : { name: "Error", message: String(err) };
    const providerLabel = (payload as any).providerLabel ?? null;
    sqlite.prepare(
      "UPDATE ai_jobs SET status = 'failed', error_json = ?, provider_label = COALESCE(?, provider_label), completed_at = ? WHERE id = ? AND status != 'cancelled'",
    ).run(JSON.stringify(payload), providerLabel, new Date().toISOString(), id);
  },
  cancelAiJob(tenantId: string, id: string, actor?: string | null): { ok: boolean; status: string; message?: string } {
    const row = sqlite.prepare("SELECT id, status FROM ai_jobs WHERE id = ? AND tenant_id = ?")
      .get(id, tenantId) as { id: string; status: string } | undefined;
    if (!row) return { ok: false, status: "not_found", message: "AI job not found for this tenant." };
    if (row.status !== "queued" && row.status !== "running") {
      return { ok: false, status: row.status, message: `AI job already ${row.status}.` };
    }
    sqlite.prepare(
      `UPDATE ai_jobs
         SET status = 'cancelled',
             error_json = ?,
             completed_at = ?,
             progress_pct = CASE WHEN progress_pct > 0 THEN progress_pct ELSE 0 END
       WHERE id = ? AND tenant_id = ? AND status IN ('queued','running')`,
    ).run(
      JSON.stringify({ name: "AiJobCancelled", message: `Cancelled by ${actor || "operator"}.` }),
      new Date().toISOString(),
      id,
      tenantId,
    );
    return { ok: true, status: "cancelled" };
  },
  /** Read a single job. Returns undefined when the id is unknown or scoped to another tenant.
   *  v2.30.5 — also returns targetLabel + targetUrl for the notification tray.
   *  When `includeResult` is false the (potentially massive) `result` field is
   *  omitted so the polling endpoint can stay cheap. The dedicated /full route
   *  in routes.ts uses includeResult=true to stream the entire payload. */
  getAiJob(tenantId: string, id: string, opts?: { includeResult?: boolean }): any | undefined {
    const r = sqlite.prepare("SELECT * FROM ai_jobs WHERE id = ? AND tenant_id = ?").get(id, tenantId) as any;
    if (!r) return undefined;
    const includeResult = opts?.includeResult !== false;
    let result: any = null;
    let resultBytes = 0;
    if (r.result_json) {
      resultBytes = Buffer.byteLength(r.result_json, "utf8");
      if (includeResult) {
        try { result = JSON.parse(r.result_json); } catch { result = null; }
      }
    }
    return {
      id: r.id,
      tenantId: r.tenant_id,
      kind: r.kind,
      status: r.status as "queued" | "running" | "completed" | "failed" | "cancelled",
      progressPct: r.progress_pct || 0,
      result,
      resultBytes,
      error: r.error_json ? JSON.parse(r.error_json) : null,
      providerLabel: r.provider_label || null,
      createdBy: r.created_by || null,
      createdAt: r.created_at,
      startedAt: r.started_at || null,
      completedAt: r.completed_at || null,
      targetLabel: r.target_label || null,
      targetUrl: r.target_url || null,
      heartbeatAt: r.heartbeat_at || null,
    };
  },
  /** v2.30.5 — list AI jobs for the notification tray. Returns all currently
   *  running/queued jobs plus the last N completed/failed jobs in the lookback
   *  window so the user can be notified about recently-finished work without
   *  loading every historical job. */
  listActiveAiJobs(tenantId: string, opts?: { lookbackMinutes?: number; max?: number }): any[] {
    const lookback = opts?.lookbackMinutes ?? 30;
    const max = Math.min(50, opts?.max ?? 20);
    const cutoff = new Date(Date.now() - lookback * 60 * 1000).toISOString();
    const rows = sqlite.prepare(
      `SELECT * FROM ai_jobs
        WHERE tenant_id = ?
          AND (status IN ('queued','running') OR completed_at >= ? OR created_at >= ?)
        ORDER BY CASE WHEN status IN ('queued','running') THEN 0 ELSE 1 END,
                 COALESCE(started_at, created_at) DESC
        LIMIT ?`,
    ).all(tenantId, cutoff, cutoff, max) as any[];
    return rows.map((r) => ({
      id: r.id,
      kind: r.kind,
      status: r.status as "queued" | "running" | "completed" | "failed" | "cancelled",
      progressPct: r.progress_pct || 0,
      providerLabel: r.provider_label || null,
      createdBy: r.created_by || null,
      createdAt: r.created_at,
      startedAt: r.started_at || null,
      completedAt: r.completed_at || null,
      targetLabel: r.target_label || null,
      targetUrl: r.target_url || null,
      heartbeatAt: r.heartbeat_at || null,
      errorMessage: r.error_json ? (() => { try { return JSON.parse(r.error_json).message ?? null; } catch { return null; } })() : null,
      // size-only — the tray never needs the whole payload
      resultBytes: r.result_json ? Buffer.byteLength(r.result_json, "utf8") : 0,
    }));
  },
  /** Historical CIRT result list for the OSINT panel. Summaries only; callers
   *  fetch /api/v1/ai-jobs/:id/full when the analyst opens a preview. */
  listCirtAiJobs(tenantId: string, opts?: { max?: number }): any[] {
    const max = Math.max(1, Math.min(100, opts?.max ?? 20));
    const rows = sqlite.prepare(
      `SELECT * FROM ai_jobs
        WHERE tenant_id = ?
          AND kind IN ('chat_triage', 'chat_deep_dive')
          AND status IN ('completed', 'failed')
        ORDER BY COALESCE(completed_at, created_at) DESC
        LIMIT ?`,
    ).all(tenantId, max) as any[];
    return rows.map((r) => {
      let payload: any = {};
      let errorMessage: string | null = null;
      try { payload = r.payload_json ? JSON.parse(r.payload_json) : {}; } catch { payload = {}; }
      try { errorMessage = r.error_json ? JSON.parse(r.error_json).message ?? null : null; } catch { errorMessage = null; }
      return {
        id: r.id,
        kind: r.kind,
        status: r.status as "completed" | "failed",
        payload,
        providerLabel: r.provider_label || null,
        createdBy: r.created_by || null,
        createdAt: r.created_at,
        startedAt: r.started_at || null,
        completedAt: r.completed_at || null,
        targetLabel: r.target_label || null,
        targetUrl: r.target_url || null,
        errorMessage,
        resultBytes: r.result_json ? Buffer.byteLength(r.result_json, "utf8") : 0,
      };
    });
  },
  /**
   * Mark any 'running' jobs older than `maxRuntimeMs` as failed. Called once
   * on boot to clean up jobs orphaned by a server restart, and periodically
   * by the scheduler.
   */
  reaperAiJobs(maxRuntimeMs = 15 * 60 * 1000): number {
    const cutoff = new Date(Date.now() - maxRuntimeMs).toISOString();
    // v2.30.5 — only reap jobs that have NOT sent a heartbeat in the cutoff
    // window. Long-running enrichments now ping the heartbeat periodically so
    // legitimate work isn't killed prematurely.
    const r = sqlite.prepare(
      `UPDATE ai_jobs SET status = 'failed', error_json = ?, completed_at = ?
        WHERE status IN ('queued','running')
          AND (started_at IS NULL OR started_at < ?)
          AND created_at < ?
          AND (heartbeat_at IS NULL OR heartbeat_at < ?)`,
    ).run(
      JSON.stringify({ name: "AiJobAborted", message: "Job exceeded the server-side runtime budget. Re-run to try again." }),
      new Date().toISOString(),
      cutoff,
      cutoff,
      cutoff,
    );
    return r.changes || 0;
  },

};

function aiProviderToSummary(p: AiProvider): AiProviderSummary {
  return {
    id: p.id,
    provider: p.provider as AiProviderKind,
    label: p.label, model: p.model,
    baseUrl: p.baseUrl ?? null,
    enabled: !!p.enabled,
    isDefault: !!p.isDefault,
    hasKey: aiProviderHasSecret(p),
    apiKeyMask: p.apiKeyMask ?? null,
    lastTestedAt: p.lastTestedAt ?? null,
    lastTestOk: p.lastTestOk == null ? null : !!p.lastTestOk,
    lastTestMessage: p.lastTestMessage ?? null,
    updatedAt: p.updatedAt,
  };
}
