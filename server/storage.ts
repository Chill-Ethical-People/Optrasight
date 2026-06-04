import {
  tenants, tenantScopes, users, assets, scans, findings, evidence,
  integrations as integrationsTbl, reports as reportsTbl,
  clientAssets, aiProviders, aiTaskAssignments,
  clientContacts as clientContactsTbl, osintSources as osintSourcesTbl,
  osintFindings as osintFindingsTbl, huntQueries as huntQueriesTbl,
  threatLandscapes as threatLandscapesTbl, auditLog as auditLogTbl,
  detectionRules as detectionRulesTbl, ruleDeployments as ruleDeploymentsTbl,
  threatActors as threatActorsTbl,
  threatActorTtps as threatActorTtpsTbl,
  threatActorTools as threatActorToolsTbl,
  threatActorCampaigns as threatActorCampaignsTbl,
  threatActorIocs as threatActorIocsTbl,
  threatActorReferences as threatActorReferencesTbl,
  threatActorDetectionRules as threatActorDetectionRulesTbl,
  threatActorTenants as threatActorTenantsTbl,
  type ThreatActorDTO, type ThreatActorFullDTO,
  type ThreatActorTtpDTO, type ThreatActorToolDTO,
  type ThreatActorCampaignDTO, type ThreatActorIocDTO,
  type ThreatActorReferenceDTO, type ThreatActorRuleLinkDTO,
  type ThreatActorTenantDTO, type TenantRelevance,
  type ActorType, type SponsorshipLevel, type TlpLevel, type ThreatLevel,
  type IntentProximity, type WepConfidence, type SophisticationLevel,
  type AdmiraltySource, type AdmiraltyInfo, type IocType, type TtpStatus,
  type DetectionPriority, type TapStatus,
  type Tenant, type User, type Asset, type Scan, type Finding, type Evidence,
  type AssetDTO, type FindingDTO, type EvidenceDTO, type TenantScopeDTO,
  type Integration, type Report, type ClientAsset, type AiProvider,
  type IntegrationSummary, type ReportKind,
  type ClientAssetDTO, type AiProviderSummary,
  type YoungDomainCandidateDTO, type AiTask, type AiProviderKind,
  type ClientContact, type OsintSource, type OsintFinding, type HuntQuery,
  type FindingIoCs,
  type ThreatLandscape, type AuditLogEntry,
  type ClientProfileDTO, type OsintFindingDTO, type HuntQueryDTO, type ThreatLandscapeDTO,
  type DetectionRuleDTO, type RuleDeploymentDTO, type DeploymentMode, type DeploymentStatus,
  type RuleStatus, type RuleSeverity, type SiemTargetId, SIEM_TARGETS, SIEM_TARGET_IDS,
  type InvestigationDTO, type InvestigationFullDTO, type InvestigationLinkDTO,
  type InvestigationNoteDTO, type InvestigationEntityType,
  type SearchResultDTO, type AttackCoverageDTO, type AttackCoverageTechniqueDTO, type CoverageState,
  YOUNG_DOMAIN_PRESETS, AI_TASKS, MONITORED_TECHNOLOGIES, HUNT_LANGUAGES,
  OSINT_CATEGORY_LABELS, OSINT_CATEGORY_ORDER, OSINT_OVERVIEW_PERSONAS, type OsintOverviewPersona,
  type OsintSourceRowDTO, type OsintOverviewResultDTO,
  SCAN_KIND_TO_TOOLS, type ScanKind,
  // v2.31.0 TTX
  type ExerciseDTO, type ExerciseInjectDTO, type ExerciseRoleDTO,
  type ExerciseParticipantDTO, type ExerciseEventDTO, type ExerciseFullDTO,
  type ExerciseStatus, type ExerciseFramework, type ExerciseScenarioType,
  type ExerciseSeverity, type ExerciseRoleKey, type ExerciseEventType,
  type InjectChannel,
} from "@shared/schema";
import { drizzle } from "drizzle-orm/better-sqlite3";
import Database from "better-sqlite3";
import { createCipheriv, createDecipheriv, createHash, scryptSync, timingSafeEqual } from "node:crypto";
import { and, desc, eq, like } from "drizzle-orm";
import { randomUUID, randomBytes } from "node:crypto";
import { runMockTool } from "./mockAdapters";
import { isStrictProduction, MockFallbackBlockedError } from "./productionMode";
import integrationsCatalog from "../spec/integrations.json";
import { dispatchAi, testProvider as testAiProviderImpl } from "./aiClient";
import { isSecurityPublisherHost } from "./iocPublisherBlocklist";
import { fetchSourcesBatch } from "./sourceFetch";
import { expandKeywords, type ExpandOptions } from "./keywordExpansion";
import { OSINT_SOURCES } from "./osintSeed";
import { ensureClusterIdPersisted, backfillClusters } from "./osintClustering";
// Phase 1 — real external scanners for Young-Domain Monitoring.
import { runDnstwist, type DnstwistRow } from "./tools/dnstwist";
import { runOpenSquat, type OpenSquatRow } from "./tools/opensquat";
import { runCrtSh, extractDomainsFromCtRows, type CtLogRow } from "./tools/ctlogs";
import { runDomScan, type DomScanRow } from "./tools/domscan";
import { runWhois, type WhoisRecord } from "./tools/whois";
import { ToolExecutionError, ToolUnavailableError } from "./tools/errors";
import { compareFingerprints, fingerprintImage, templateMatchImage, type ImageFingerprint, type ImageSimilarityResult } from "./brandImageSimilarity";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { promises as dnsPromises } from "node:dns";
import { spawnSync } from "node:child_process";

// In-memory cancellation registry for malicious-site / young-domain scans.
// Process-local: a server restart loses the abort handle but also kills the
// detached executor, so the consequence is the scan row stays 'running' in
// the DB. A future boot-time sweep should mark such rows 'failed' on restart.
const SCAN_ABORT_CONTROLLERS = new Map<string, AbortController>();

// DNSTwist landing-page screenshots live next to the SQLite DB so a single
// volume mount captures both. Served as static under `/dnstwist-screenshots/*`
// by the express routes.
export const DNSTWIST_SCREENSHOTS_DIR = resolve(process.cwd(), "data", "dnstwist_screenshots");
try { mkdirSync(DNSTWIST_SCREENSHOTS_DIR, { recursive: true }); } catch { /* fs perms */ }

interface BrandAbuseMatch {
  assetId: string;
  assetKind: "logo" | "trademark" | "app_icon";
  assetName: string;
  source: "dnstwist_screenshot" | "urlscan_screenshot";
  score: number;
  similarity: ImageSimilarityResult;
  template?: { score: number; box: { x: number; y: number; width: number; height: number; scale: number } | null };
  assetFingerprint: Omit<ImageFingerprint, "histogram"> & { histogramBins: number };
  candidateFingerprint: Omit<ImageFingerprint, "histogram"> & { histogramBins: number };
}

interface CatalogEntry {
  id: string;
  name: string;
  layer: string;
  purpose?: string;
  license?: string;
  invocation?: { kind?: string; image?: string };
  env?: Array<{ name: string; required?: boolean; description?: string }>;
  schedule_default?: string;
  platform_endpoint?: string;
  repo?: string;
}
const EXCHANGE_CATALOG: CatalogEntry[] = [
  {
    id: "stix_export",
    name: "STIX 2.1 Export",
    layer: "threat_intel",
    purpose: "Export selected investigations, actors, findings, and indicators as a STIX 2.1 bundle.",
    license: "Built-in",
    invocation: { kind: "library" },
    env: [],
    platform_endpoint: "GET /api/v1/exchange/stix/export",
  },
  {
    id: "misp",
    name: "MISP",
    layer: "threat_intel",
    purpose: "Future live push/pull of indicators and events. Truthfully gated until implemented.",
    license: "AGPL-3.0",
    invocation: { kind: "http_api" },
    env: [{ name: "MISP_URL", required: true }, { name: "MISP_API_KEY", required: true }],
    platform_endpoint: "planned",
  },
  {
    id: "opencti",
    name: "OpenCTI",
    layer: "threat_intel",
    purpose: "Future live graph synchronisation for CTI objects. Truthfully gated until implemented.",
    license: "Apache-2.0",
    invocation: { kind: "http_api" },
    env: [{ name: "OPENCTI_URL", required: true }, { name: "OPENCTI_TOKEN", required: true }],
    platform_endpoint: "planned",
  },
  {
    id: "taxii",
    name: "TAXII 2.1",
    layer: "threat_intel",
    purpose: "Future TAXII collection publishing/subscription. Truthfully gated until implemented.",
    license: "OASIS standard",
    invocation: { kind: "http_api" },
    env: [{ name: "TAXII_ROOT_URL", required: true }, { name: "TAXII_TOKEN", required: true }],
    platform_endpoint: "planned",
  },
];
const CATALOG: CatalogEntry[] = [
  ...((integrationsCatalog as any).integrations as CatalogEntry[]),
  ...EXCHANGE_CATALOG,
];
const CATALOG_BY_ID = new Map(CATALOG.map((c) => [c.id, c]));

const sqlite = new Database("data.db");
sqlite.pragma("journal_mode = WAL");
export const db = drizzle(sqlite);

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
      password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst'
    );
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      issued_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL,
      revoked_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id, revoked_at);
    CREATE TABLE IF NOT EXISTS assets (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
      value TEXT NOT NULL, source_tool TEXT, technologies TEXT NOT NULL DEFAULT '[]',
      risk_score INTEGER NOT NULL DEFAULT 0, discovered_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
      tool TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', target TEXT,
      config TEXT NOT NULL DEFAULT '{}', finding_count INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, log TEXT
    );
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, scan_id TEXT,
      type TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium',
      title TEXT NOT NULL, description TEXT, target TEXT, source_tool TEXT,
      status TEXT NOT NULL DEFAULT 'open', extra TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS evidence (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, finding_id TEXT,
      kind TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
      url TEXT, artifact_url TEXT, extra TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS integrations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      tool_id TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      api_key_enc TEXT,
      api_secret_enc TEXT,
      api_key_mask TEXT,
      api_secret_mask TEXT,
      config TEXT NOT NULL DEFAULT '{}',
      last_tested_at TEXT,
      last_test_ok INTEGER,
      last_test_message TEXT,
      updated_at TEXT NOT NULL,
      UNIQUE(tenant_id, tool_id)
    );
    CREATE TABLE IF NOT EXISTS client_assets (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      name TEXT NOT NULL,
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      sha256 TEXT NOT NULL,
      data TEXT NOT NULL,
      jurisdiction TEXT,
      registered_mark TEXT,
      notes TEXT,
      created_at TEXT NOT NULL
    );
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
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      author_tenant_id TEXT NOT NULL,
      author_email TEXT NOT NULL,
      title TEXT NOT NULL,
      kind TEXT NOT NULL,
      tenant_ids TEXT NOT NULL DEFAULT '[]',
      tenant_names TEXT NOT NULL DEFAULT '[]',
      scan_count INTEGER NOT NULL DEFAULT 0,
      finding_count INTEGER NOT NULL DEFAULT 0,
      critical_count INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'generating',
      body_md TEXT, body_html TEXT,
      stats TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS investigations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      severity TEXT NOT NULL DEFAULT 'medium',
      summary TEXT,
      assignee TEXT,
      source_type TEXT,
      source_id TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      created_by TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_investigations_tenant ON investigations(tenant_id, updated_at DESC);
    CREATE TABLE IF NOT EXISTS investigation_links (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      investigation_id TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      label TEXT,
      created_at TEXT NOT NULL,
      created_by TEXT NOT NULL,
      UNIQUE(tenant_id, investigation_id, entity_type, entity_id)
    );
    CREATE INDEX IF NOT EXISTS idx_investigation_links_case ON investigation_links(tenant_id, investigation_id);
    CREATE TABLE IF NOT EXISTS investigation_notes (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      investigation_id TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'analyst',
      body TEXT NOT NULL,
      created_at TEXT NOT NULL,
      created_by TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_investigation_notes_case ON investigation_notes(tenant_id, investigation_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS client_contacts (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      name TEXT NOT NULL, role TEXT, email TEXT NOT NULL, phone TEXT,
      is_primary INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
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

    -- v2.31.0 — Tabletop Exercise (TTX) Generator. 5 tables: exercises + injects
    --              + roles + participants + events.
    CREATE TABLE IF NOT EXISTS exercises (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      code TEXT NOT NULL,                   -- TTX-NNN
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft',
      framework TEXT NOT NULL DEFAULT 'hkma',
      scenario_type TEXT NOT NULL DEFAULT 'ransomware-affiliate',
      severity TEXT NOT NULL DEFAULT 'HIGH',
      scheduled_at TEXT,
      duration_min INTEGER NOT NULL DEFAULT 120,
      facilitator_id TEXT,
      narrative_md TEXT,
      objectives TEXT NOT NULL DEFAULT '[]',
      evaluation_rubric TEXT NOT NULL DEFAULT '{}',
      source_tap_ids TEXT NOT NULL DEFAULT '[]',
      source_finding_ids TEXT NOT NULL DEFAULT '[]',
      source_references TEXT NOT NULL DEFAULT '[]',
      uploaded_pptx_path TEXT,
      uploaded_pptx_name TEXT,
      ai_provider_label TEXT,
      version INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by TEXT NOT NULL,
      UNIQUE(tenant_id, code)
    );
    CREATE INDEX IF NOT EXISTS idx_exercises_tenant ON exercises(tenant_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_exercises_status ON exercises(tenant_id, status);

    CREATE TABLE IF NOT EXISTS exercise_injects (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, exercise_id TEXT NOT NULL,
      sequence INTEGER NOT NULL DEFAULT 0,
      at_minute INTEGER NOT NULL DEFAULT 0,
      channel TEXT NOT NULL DEFAULT 'email',
      audience_roles TEXT NOT NULL DEFAULT '[]',
      title TEXT NOT NULL,
      body_md TEXT NOT NULL DEFAULT '',
      expected_actions TEXT NOT NULL DEFAULT '[]',
      iocs TEXT NOT NULL DEFAULT '[]',
      attachments TEXT NOT NULL DEFAULT '[]',
      sent_at TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_injects_exercise ON exercise_injects(tenant_id, exercise_id, sequence);

    CREATE TABLE IF NOT EXISTS exercise_roles (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, exercise_id TEXT NOT NULL,
      role_key TEXT NOT NULL,
      label TEXT NOT NULL,
      brief_md TEXT NOT NULL DEFAULT '',
      color TEXT NOT NULL DEFAULT '#64748b',
      created_at TEXT NOT NULL,
      UNIQUE(exercise_id, role_key)
    );
    CREATE INDEX IF NOT EXISTS idx_exercise_roles ON exercise_roles(tenant_id, exercise_id);

    CREATE TABLE IF NOT EXISTS exercise_participants (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, exercise_id TEXT NOT NULL,
      role_id TEXT NOT NULL,
      display_name TEXT NOT NULL,
      email TEXT,
      token TEXT NOT NULL UNIQUE,
      joined_at TEXT, last_seen_at TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_participants_exercise ON exercise_participants(tenant_id, exercise_id);
    CREATE INDEX IF NOT EXISTS idx_participants_token ON exercise_participants(token);

    CREATE TABLE IF NOT EXISTS exercise_events (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, exercise_id TEXT NOT NULL,
      ts TEXT NOT NULL,
      type TEXT NOT NULL,
      actor_id TEXT,
      actor_role TEXT,
      payload TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_events_exercise ON exercise_events(tenant_id, exercise_id, ts);
  `);
  // ALTER tenant_scopes for v2.4 + osint_findings for v2.8 — wrapped per-column
  // so re-runs are idempotent.
  const alters: string[] = [
    `ALTER TABLE tenant_scopes ADD COLUMN client_types TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE tenant_scopes ADD COLUMN geos TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE tenant_scopes ADD COLUMN industries TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE tenant_scopes ADD COLUMN monitored_technologies TEXT NOT NULL DEFAULT '[]'`,
    `ALTER TABLE tenant_scopes ADD COLUMN notification_emails TEXT NOT NULL DEFAULT '[]'`,
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
    // Phase 0 — evidence_source flags how a finding row was produced:
    //   live         — real scanner / API call against real targets
    //   demo         — curated pitch / demo seeding (the bundled data.db rows)
    //   ai_inferred  — derived purely from AI inference, no scanner data
    // Defaults to 'demo' so existing bundled rows are correctly classified
    // until a real scanner regenerates them.
    `ALTER TABLE findings ADD COLUMN evidence_source TEXT NOT NULL DEFAULT 'demo'`,
  ];
  for (const stmt of alters) {
    try { sqlite.exec(stmt); } catch { /* column already exists */ }
  }

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

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function issueSession(userId: string): string {
  const token = randomBytes(32).toString("base64url");
  const ts = now();
  sqlite.prepare(`
    INSERT INTO auth_sessions (token_hash, user_id, issued_at, last_used_at, revoked_at)
    VALUES (?, ?, ?, ?, NULL)
  `).run(tokenHash(token), userId, ts, ts);
  return token;
}

function connectorSupport(cat: CatalogEntry): { implemented: boolean; reason?: string } {
  if (cat.id === "stix_export") return { implemented: true };
  if (cat.id === "urlscan") return { implemented: true };
  if (["dnstwist", "opensquat", "crtsh", "domscan", "whois", "keyword_expansion"].includes(cat.id)) {
    return { implemented: true };
  }
  if (cat.layer === "siem") {
    return { implemented: false, reason: "Detection-rule push connectors are not implemented yet. Use manual deployment." };
  }
  return { implemented: false, reason: "Connector is catalogued but not wired to a live OptraSight action yet." };
}

function commandAvailable(binary: string): boolean {
  const first = binary.trim().split(/\s+/)[0];
  if (!first) return false;
  const r = spawnSync(first, ["--version"], { encoding: "utf8", timeout: 2500 });
  if (!r.error && (r.status === 0 || r.stdout || r.stderr)) return true;
  const help = spawnSync(first, ["--help"], { encoding: "utf8", timeout: 2500 });
  return !help.error && (help.status === 0 || !!help.stdout || !!help.stderr);
}

function curlJson(
  method: "GET" | "POST",
  url: string,
  headers: Record<string, string>,
  body?: Record<string, any>,
  timeoutSeconds = 15,
): { ok: boolean; status: number; body: any; raw: string; error?: string; latencyMs: number } {
  const started = Date.now();
  const args = [
    "-sS",
    "-X", method,
    "--max-time", String(timeoutSeconds),
    "-w", "\n__OPTRASIGHT_HTTP_STATUS__:%{http_code}",
    "-H", "Accept: application/json",
  ];
  for (const [k, v] of Object.entries(headers)) args.push("-H", `${k}: ${v}`);
  if (body) {
    args.push("-H", "Content-Type: application/json", "--data-binary", JSON.stringify(body));
  }
  args.push(url);
  const r = spawnSync("curl", args, { encoding: "utf8", timeout: (timeoutSeconds + 2) * 1000 });
  const rawOut = r.stdout || "";
  const marker = rawOut.lastIndexOf("\n__OPTRASIGHT_HTTP_STATUS__:");
  const raw = marker >= 0 ? rawOut.slice(0, marker) : rawOut;
  const status = marker >= 0 ? parseInt(rawOut.slice(marker + "\n__OPTRASIGHT_HTTP_STATUS__:".length), 10) || 0 : 0;
  let parsed: any = null;
  try { parsed = raw ? JSON.parse(raw) : null; } catch { parsed = raw; }
  const ok = status >= 200 && status < 300;
  return {
    ok,
    status,
    body: parsed,
    raw,
    error: ok ? undefined : (r.stderr || `HTTP ${status}`),
    latencyMs: Date.now() - started,
  };
}

function urlScanReady(tid: string): { ready: boolean; apiKey?: string; reason?: string } {
  const row = db.select().from(integrationsTbl)
    .where(and(eq(integrationsTbl.tenantId, tid), eq(integrationsTbl.toolId, "urlscan")))
    .get();
  const apiKey = dec(row?.apiKeyEnc);
  if (!row || !row.enabled) return { ready: false, reason: "URLScan.io integration disabled or missing" };
  if (!apiKey) return { ready: false, reason: "URLScan.io API key not configured" };
  if (row.lastTestOk !== 1) return { ready: false, reason: "URLScan.io integration has not passed live test" };
  return { ready: true, apiKey };
}

function urlScanSearchAndSubmit(tid: string, url: string): Record<string, any> {
  const ready = urlScanReady(tid);
  const base = {
    source: "urlscan.io",
    url,
    enabled: ready.ready,
    searchedAt: now(),
  };
  if (!ready.ready || !ready.apiKey) return { ...base, skipped: true, reason: ready.reason };
  const headers = { "API-Key": ready.apiKey };
  const query = encodeURIComponent(`task.url:"${url}" OR page.url:"${url}"`);
  const search = curlJson("GET", `https://urlscan.io/api/v1/search/?q=${query}&size=3`, headers, undefined, 15);
  const results = Array.isArray(search.body?.results) ? search.body.results : [];
  const existing = results[0] || null;
  const out: Record<string, any> = {
    ...base,
    skipped: false,
    search: {
      ok: search.ok,
      status: search.status,
      total: search.body?.total ?? results.length,
      resultCount: results.length,
      first: existing ? {
        uuid: existing._id || existing.uuid || null,
        taskUrl: existing.task?.url ?? null,
        pageUrl: existing.page?.url ?? null,
        result: existing.result ?? null,
        screenshot: existing.screenshot ?? null,
        verdicts: existing.verdicts ?? null,
        sort: existing.sort ?? null,
      } : null,
      error: search.ok ? null : (search.body?.message || search.body?.description || search.error),
    },
  };
  const submit = curlJson("POST", "https://urlscan.io/api/v1/scan/", headers, {
    url,
    visibility: "unlisted",
    tags: ["optrasight", "brand-abuse"],
  }, 20);
  out.submission = {
    ok: submit.ok,
    status: submit.status,
    uuid: submit.body?.uuid ?? null,
    api: submit.body?.api ?? null,
    result: submit.body?.result ?? null,
    visibility: submit.body?.visibility ?? "unlisted",
    message: submit.body?.message ?? null,
    error: submit.ok ? null : (submit.body?.message || submit.body?.description || submit.error),
  };
  return out;
}

function integration2summary(
  cat: CatalogEntry,
  row?: Integration,
): IntegrationSummary {
  const requiredEnv = (cat.env || []).filter((e) => e.required).map((e) => e.name);
  const support = connectorSupport(cat);
  const config = row ? p<Record<string, any>>(row.config, {}) : {};
  const details = p<Record<string, any>>(row?.lastTestMessage?.startsWith("{") ? row.lastTestMessage : "", {});
  const lastTestMessage = details.message ?? row?.lastTestMessage ?? null;
  return {
    id: cat.id,
    name: cat.name,
    layer: cat.layer,
    purpose: cat.purpose,
    license: cat.license,
    invocationKind: cat.invocation?.kind,
    requiredEnv,
    enabled: row ? !!row.enabled : true,
    hasCredentials: !!(row?.apiKeyEnc || row?.apiSecretEnc) || requiredEnv.length === 0,
    implemented: support.implemented,
    configured: !!(row?.apiKeyEnc || row?.apiSecretEnc) || requiredEnv.length === 0,
    liveTested: !!details.liveTested,
    statusLabel: support.implemented ? (details.statusLabel ?? undefined) : "Not implemented",
    apiKeyMask: row?.apiKeyMask ?? null,
    apiSecretMask: row?.apiSecretMask ?? null,
    lastTestedAt: row?.lastTestedAt ?? null,
    lastTestOk: row?.lastTestOk == null ? null : !!row.lastTestOk,
    lastTestMessage,
    config,
    scheduleDefault: cat.schedule_default,
    endpoint: cat.platform_endpoint,
  };
}

// ---------- helpers ----------
const j = (v: unknown) => JSON.stringify(v ?? []);
const p = <T = any>(v: string | null | undefined, d: T): T => {
  if (!v) return d;
  try { return JSON.parse(v) as T; } catch { return d; }
};
const now = () => new Date().toISOString();
const id = () => randomUUID();

function asset2dto(a: Asset): AssetDTO {
  return { ...a, technologies: p<string[]>(a.technologies, []) };
}
function finding2dto(f: Finding): FindingDTO {
  return { ...f, extra: p<Record<string, any>>(f.extra, {}) };
}
function evidence2dto(e: Evidence): EvidenceDTO {
  return { ...e, extra: p<Record<string, any>>(e.extra, {}) };
}
function scope2dto(row: any): TenantScopeDTO {
  return {
    brandKeywords: p<string[]>(row.brandKeywords, []),
    monitoredDomains: p<string[]>(row.monitoredDomains, []),
    ipRanges: p<string[]>(row.ipRanges, []),
    executiveEmails: p<string[]>(row.executiveEmails, []),
  };
}
function scope2profile(row: any, contacts: ClientContact[]): ClientProfileDTO {
  return {
    ...scope2dto(row),
    clientTypes: p<string[]>(row.clientTypes, []),
    geos: p<string[]>(row.geos, []),
    industries: p<string[]>(row.industries, []),
    monitoredTechnologies: p<string[]>(row.monitoredTechnologies, []),
    notificationEmails: p<string[]>(row.notificationEmails, []),
    contacts,
  };
}

// ---------- report rendering ----------
function sevWeight(s: string): number {
  return ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 } as Record<string, number>)[s] ?? 0;
}

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

interface PerTenantBlock {
  tenant: Tenant;
  findings: FindingDTO[];
  scans: Scan[];
  assets: AssetDTO[];
  evidence: EvidenceDTO[];
}

function renderReportMarkdown(opts: {
  title: string;
  kind: ReportKind;
  authorEmail: string;
  perTenant: PerTenantBlock[];
  includeEvidence: boolean;
}): string {
  const { title, kind, authorEmail, perTenant, includeEvidence } = opts;
  const lines: string[] = [];
  const generatedAt = new Date().toISOString();

  lines.push(`# ${title}`);
  lines.push("");
  lines.push(`**Report kind:** \`${kind}\`  `);
  lines.push(`**Generated at:** ${generatedAt}  `);
  lines.push(`**Generated by:** ${authorEmail}  `);
  lines.push(`**Tenants covered:** ${perTenant.map((p) => p.tenant.name).join(", ") || "—"}  `);
  lines.push("");

  // executive summary
  const totalFind = perTenant.reduce((n, p) => n + p.findings.length, 0);
  const totalCrit = perTenant.reduce((n, p) => n + p.findings.filter((f) => f.severity === "critical").length, 0);
  const totalHigh = perTenant.reduce((n, p) => n + p.findings.filter((f) => f.severity === "high").length, 0);
  const totalAssets = perTenant.reduce((n, p) => n + p.assets.length, 0);
  const totalScans = perTenant.reduce((n, p) => n + p.scans.length, 0);

  lines.push("## Executive summary");
  lines.push("");
  lines.push(`- **Findings:** ${totalFind} total — ${totalCrit} critical, ${totalHigh} high`);
  lines.push(`- **Assets discovered:** ${totalAssets}`);
  lines.push(`- **Scans included:** ${totalScans}`);
  lines.push(`- **Tenants:** ${perTenant.length}`);
  lines.push("");

  for (const block of perTenant) {
    const { tenant, findings, scans, assets, evidence } = block;
    lines.push(`---`);
    lines.push("");
    lines.push(`## ${tenant.name}`);
    lines.push(`*Tenant slug: \`${tenant.slug}\` · Plan: ${tenant.plan}*`);
    lines.push("");

    // Severity breakdown
    const sevCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });
    lines.push("### Severity breakdown");
    lines.push("");
    lines.push("| Severity | Count |");
    lines.push("| --- | --- |");
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
      lines.push(`| ${sev} | ${sevCounts[sev] || 0} |`);
    }
    lines.push("");

    // Findings table — top 25 by severity
    if (kind !== "executive") {
      const sorted = [...findings].sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity));
      const top = sorted.slice(0, 25);
      lines.push(`### Findings (${findings.length} total, showing top ${top.length})`);
      lines.push("");
      if (top.length === 0) {
        lines.push("_No findings._");
      } else {
        lines.push("| Severity | Type | Title | Target | Tool | Status |");
        lines.push("| --- | --- | --- | --- | --- | --- |");
        for (const f of top) {
          const cell = (s: string | null | undefined) =>
            (s ?? "—").replace(/\|/g, "\\|").replace(/\n/g, " ").slice(0, 80);
          lines.push(`| ${f.severity} | ${f.type} | ${cell(f.title)} | ${cell(f.target)} | ${cell(f.sourceTool)} | ${f.status} |`);
        }
      }
      lines.push("");
    }

    // Top assets (attack_surface or full)
    if (kind === "attack_surface" || kind === "full") {
      const topAssets = [...assets].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0)).slice(0, 15);
      lines.push("### Top assets at risk");
      lines.push("");
      if (topAssets.length === 0) {
        lines.push("_No assets._");
      } else {
        lines.push("| Risk | Kind | Value | Source | Discovered |");
        lines.push("| --- | --- | --- | --- | --- |");
        for (const a of topAssets) {
          lines.push(`| ${a.riskScore} | ${a.kind} | \`${a.value}\` | ${a.sourceTool ?? "—"} | ${a.discoveredAt} |`);
        }
      }
      lines.push("");
    }

    // Scans summary
    if (kind !== "executive" && scans.length) {
      lines.push("### Scans included");
      lines.push("");
      lines.push("| Kind | Tools | Status | Findings | Created |");
      lines.push("| --- | --- | --- | --- | --- |");
      for (const s of scans.slice(0, 20)) {
        lines.push(`| ${s.kind} | \`${s.tool}\` | ${s.status} | ${s.findingCount} | ${s.createdAt} |`);
      }
      lines.push("");
    }

    // Evidence section
    if (includeEvidence && evidence.length) {
      lines.push("### Evidence captures");
      lines.push("");
      for (const e of evidence.slice(0, 10)) {
        lines.push(`- **${e.kind}** — ${e.status}${e.url ? ` · \`${e.url}\`` : ""}${e.artifactUrl ? ` · [artifact](${e.artifactUrl})` : ""}`);
      }
      lines.push("");
    }
  }

  lines.push("---");
  lines.push("");
  lines.push("_Generated by OptraSight v2. This report aggregates findings across the selected tenants and is intended for the recipient organization's security team._");
  lines.push("");
  return lines.join("\n");
}

function escHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" } as Record<string, string>)[c]);
}

function mdToHtml(md: string, title: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let inTable = false;
  let inCode = false;

  function closeTable() {
    if (inTable) { out.push("</tbody></table>"); inTable = false; }
  }

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw;

    // skip pipe-table separator rows
    if (/^\s*\|?\s*[-: ]+\|[-: |]+\|?\s*$/.test(line)) continue;

    // table rows
    if (/^\s*\|.*\|\s*$/.test(line)) {
      const cells = line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
      if (!inTable) {
        out.push('<table><thead><tr>');
        cells.forEach((c) => out.push(`<th>${inlineMd(c)}</th>`));
        out.push("</tr></thead><tbody>");
        inTable = true;
      } else {
        out.push("<tr>");
        cells.forEach((c) => out.push(`<td>${inlineMd(c)}</td>`));
        out.push("</tr>");
      }
      continue;
    } else {
      closeTable();
    }

    if (line.startsWith("### ")) { out.push(`<h3>${inlineMd(line.slice(4))}</h3>`); continue; }
    if (line.startsWith("## ")) { out.push(`<h2>${inlineMd(line.slice(3))}</h2>`); continue; }
    if (line.startsWith("# ")) { out.push(`<h1>${inlineMd(line.slice(2))}</h1>`); continue; }
    if (line.startsWith("---")) { out.push("<hr/>"); continue; }
    if (line.startsWith("- ")) {
      // collect contiguous list items
      const items: string[] = [line.slice(2)];
      while (i + 1 < lines.length && lines[i + 1].startsWith("- ")) {
        items.push(lines[++i].slice(2));
      }
      out.push("<ul>" + items.map((x) => `<li>${inlineMd(x)}</li>`).join("") + "</ul>");
      continue;
    }
    if (line.trim() === "") { out.push(""); continue; }
    out.push(`<p>${inlineMd(line)}</p>`);
  }
  closeTable();

  function inlineMd(s: string): string {
    let h = escHtml(s);
    h = h.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    h = h.replace(/\*([^*]+)\*/g, "<em>$1</em>");
    h = h.replace(/`([^`]+)`/g, "<code>$1</code>");
    h = h.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
    return h;
  }

  // unused inCode flag silenced
  void inCode;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<title>${escHtml(title)}</title>
<style>
body { font-family: ui-sans-serif, -apple-system, "Segoe UI", Roboto, system-ui, sans-serif; max-width: 880px; margin: 32px auto; padding: 0 24px; color: #0f172a; line-height: 1.55; }
h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -.01em; }
h2 { font-size: 17px; margin: 28px 0 10px; padding-bottom: 6px; border-bottom: 1px solid #e2e8f0; }
h3 { font-size: 13px; margin: 20px 0 8px; text-transform: uppercase; letter-spacing: .04em; color: #475569; }
p  { margin: 6px 0; }
ul { margin: 6px 0 12px 18px; padding: 0; }
li { margin: 2px 0; }
code { background: #f1f5f9; padding: 1px 5px; border-radius: 3px; font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; font-size: 12px; }
th { background: #f8fafc; text-align: left; padding: 6px 8px; border-bottom: 1px solid #e2e8f0; font-weight: 600; }
td { padding: 6px 8px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
hr { border: none; border-top: 1px solid #e2e8f0; margin: 24px 0; }
em { color: #64748b; font-style: normal; }
@media print { body { margin: 0; max-width: none; } h2 { page-break-after: avoid; } table { page-break-inside: auto; } tr { page-break-inside: avoid; } }
</style></head><body>
${out.join("\n")}
</body></html>`;
}

// ---------- seeding ----------
const SEED_TENANTS = [
  {
    name: "Acme Bank", slug: "acme-bank",
    keywords: ["acme", "acmebank", "acme-pay"],
    domains: ["acmebank.com"],
    ipRanges: ["203.0.113.0/24"],
    user: { email: "analyst@acmebank.com", password: "demo1234", role: "analyst" },
    profile: {
      clientTypes: ["MSS", "MDR", "CIR"],
      geos: ["HK", "SG", "TW"],
      industries: ["banking", "financial-services"],
      monitoredTechnologies: ["chrome", "firefox", "oracle-weblogic", "ms-exchange", "fortigate"],
    },
  },
  {
    name: "Globex Retail", slug: "globex",
    keywords: ["globex", "globex-shop"],
    domains: ["globex.example"],
    ipRanges: [],
    user: { email: "ciso@globex.example", password: "demo1234", role: "analyst" },
    profile: {
      clientTypes: ["MSS", "Threat Intel"],
      geos: ["MY", "SG", "ID"],
      industries: ["retail", "ecommerce", "logistics"],
      monitoredTechnologies: ["chrome", "firefox", "veeam", "vmware-vcenter", "citrix-netscaler"],
    },
  },
  {
    name: "Initech Health", slug: "initech-health",
    keywords: ["initech", "initech-care"],
    domains: ["initech-health.example"],
    ipRanges: [],
    user: { email: "soc@initech-health.example", password: "demo1234", role: "analyst" },
    profile: {
      clientTypes: ["MDR", "CIR", "Threat Intel"],
      geos: ["TW", "CN", "JP"],
      industries: ["healthcare", "pharmaceuticals"],
      monitoredTechnologies: ["chrome", "ms-exchange", "ivanti-connect-secure", "oracle-weblogic"],
    },
  },
];

function seedAiProvidersIfEmpty(tenantId: string) {
  const existing = db.select().from(aiProviders).where(eq(aiProviders.tenantId, tenantId)).all();
  if (existing.length) return;
  const seedSpec = [
    { provider: "openai" as AiProviderKind,        label: "OpenAI",          model: "gpt-4o-mini",      isDefault: true,  hasKey: true  },
    { provider: "anthropic" as AiProviderKind,     label: "Anthropic",       model: "claude-3-5-sonnet", isDefault: false, hasKey: false },
    { provider: "gemini" as AiProviderKind,        label: "Google Gemini",   model: "gemini-2.5-flash", isDefault: false, hasKey: false },
    { provider: "perplexity" as AiProviderKind,    label: "Perplexity",      model: "sonar-large",      isDefault: false, hasKey: false },
    { provider: "deepseek" as AiProviderKind,      label: "DeepSeek",        model: "deepseek-chat",    isDefault: false, hasKey: false },
    { provider: "kimi" as AiProviderKind,          label: "Kimi (Moonshot)", model: "kimi-latest",      isDefault: false, hasKey: false },
    { provider: "ollama" as AiProviderKind,        label: "Ollama (local)",  model: "llama3.1:8b",      isDefault: false, hasKey: false },
  ];
  let defaultId: string | null = null;
  for (const p of seedSpec) {
    const pid = id();
    if (p.isDefault) defaultId = pid;
    const apiKey = p.hasKey ? `sk-demo-${p.provider}-key-${tenantId.slice(0, 8)}` : null;
    db.insert(aiProviders).values({
      id: pid, tenantId, provider: p.provider, label: p.label, model: p.model,
      baseUrl: null,
      apiKeyEnc: apiKey ? enc(apiKey) : null,
      apiKeyMask: apiKey ? mask(apiKey) : null,
      enabled: 1, isDefault: p.isDefault ? 1 : 0,
      lastTestedAt: null, lastTestOk: null, lastTestMessage: null,
      config: "{}", createdAt: now(), updatedAt: now(),
    }).run();
  }
  // assign all 5 AI tasks to the default provider
  if (defaultId) {
    for (const t of AI_TASKS) {
      db.insert(aiTaskAssignments).values({
        id: id(), tenantId, task: t, providerId: defaultId, updatedAt: now(),
      }).run();
    }
  }
}

function seedOsintSourcesIfEmpty() {
  const existing = db.select().from(osintSourcesTbl).all();
  if (existing.length >= 500) return;
  // wipe and reseed if catalog grew
  if (existing.length > 0) sqlite.exec("DELETE FROM osint_sources");
  const ins = sqlite.prepare(
    "INSERT INTO osint_sources (id, category, name, url, language, region, reliability, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, 1)"
  );
  const tx = sqlite.transaction((rows: typeof OSINT_SOURCES) => {
    for (const s of rows) ins.run(s.id, s.category, s.name, s.url, s.language ?? "en", s.region ?? null, s.reliability ?? "B");
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
    db.insert(users).values({
      id: id(), tenantId: tid, email: s.user.email,
      password: s.user.password, role: s.user.role,
    }).run();

    // pre-populate one scan per kind so the dashboard isn't empty
    const primary = s.domains[0];
    const kindsToSeed: ScanKind[] = ["lookalikes", "discovery", "vulnerabilities", "passive-intel", "osint"];
    for (const kind of kindsToSeed) {
      const sid = id();
      const tools = SCAN_KIND_TO_TOOLS[kind];
      db.insert(scans).values({
        id: sid, tenantId: tid, kind, tool: tools.join(","),
        status: "succeeded", target: primary, config: j({}),
        findingCount: 0, createdAt: now(), startedAt: now(), finishedAt: now(),
        log: tools.map((t) => `[${t}] ok`).join("\n"),
      }).run();
      let total = 0;
      for (const t of tools) {
        const res = runMockTool(t, {
          target: primary, targets: [primary], keywords: s.keywords,
        });
        for (const a of res.assets) {
          db.insert(assets).values({
            id: id(), tenantId: tid, kind: a.kind, value: a.value,
            sourceTool: a.sourceTool ?? null,
            technologies: j(a.technologies ?? []),
            riskScore: a.riskScore ?? 0, discoveredAt: a.discoveredAt ?? now(),
          }).run();
        }
        for (const f of res.findings) {
          total += 1;
          db.insert(findings).values({
            id: id(), tenantId: tid, scanId: sid, type: f.type,
            severity: f.severity, title: f.title, description: f.description ?? null,
            target: f.target ?? null, sourceTool: f.sourceTool ?? null,
            status: "open", extra: j(f.extra ?? {}), createdAt: now(),
          }).run();
        }
        for (const e of res.evidence) {
          db.insert(evidence).values({
            id: id(), tenantId: tid, findingId: null, kind: e.kind,
            status: e.status, url: e.url ?? null, artifactUrl: e.artifactUrl ?? null,
            extra: j(e.extra ?? {}), createdAt: now(),
          }).run();
        }
      }
      db.update(scans).set({ findingCount: total }).where(eq(scans.id, sid)).run();
    }

    // sample evidence URLScan capture
    const ev = runMockTool("urlscan", { target: `https://login-${s.slug}.com` }).evidence[0];
    db.insert(evidence).values({
      id: id(), tenantId: tid, findingId: null, kind: ev.kind,
      status: ev.status, url: ev.url ?? null, artifactUrl: ev.artifactUrl ?? null,
      extra: j(ev.extra ?? {}), createdAt: now(),
    }).run();

    // seed AI providers per tenant (so the AI Setup page is pre-populated)
    seedAiProvidersIfEmpty(tid);

    // seed client profile with industries / geos / techs so global pivots work out of the box.
    // Inlined (not via storage.setClientProfile) because seedIfEmpty() runs at module-init,
    // before the `storage` const at the bottom of this file has been constructed.
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

  // MSSP admin — cross-tenant role. Anchored to the first tenant by default but
  // can pivot to any tenant via the AppShell tenant switcher (X-Tenant-Id header).
  if (firstTenantId) {
    db.insert(users).values({
      id: id(), tenantId: firstTenantId,
      email: "admin@brandguard.local", password: "admin1234", role: "admin",
    }).run();
  }
}

ensureSchema();
seedOsintSourcesIfEmpty();
seedIfEmpty();

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

// Re-export persona list so routes can hand it to taxonomies.
export { OSINT_OVERVIEW_PERSONAS as OSINT_OVERVIEW_PERSONA_LIST };

// ---------- public API ----------
export const storage = {
  // auth
  login(email: string, password: string): (User & { accessToken: string }) | undefined {
    const u = db.select().from(users).where(eq(users.email, email)).get();
    if (!u) return undefined;
    const verified = verifyPassword(password, u.password);
    if (!verified.ok) return undefined;
    if (verified.needsRehash) {
      db.update(users).set({ password: hashPassword(password) }).where(eq(users.id, u.id)).run();
    }
    return { ...u, accessToken: issueSession(u.id) };
  },
  getUser(token: string): User | undefined {
    const h = tokenHash(token);
    const session = sqlite.prepare(`
      SELECT user_id AS userId FROM auth_sessions
      WHERE token_hash = ? AND revoked_at IS NULL
    `).get(h) as { userId: string } | undefined;
    if (session?.userId) {
      sqlite.prepare("UPDATE auth_sessions SET last_used_at = ? WHERE token_hash = ?").run(now(), h);
      return db.select().from(users).where(eq(users.id, session.userId)).get();
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

  // tenants
  listTenants(role: string, tenantId: string): Tenant[] {
    if (role === "admin") return db.select().from(tenants).all();
    const t = db.select().from(tenants).where(eq(tenants.id, tenantId)).get();
    return t ? [t] : [];
  },
  getTenant(tid: string): Tenant | undefined {
    return db.select().from(tenants).where(eq(tenants.id, tid)).get();
  },
  getScope(tid: string): TenantScopeDTO {
    const row = db.select().from(tenantScopes).where(eq(tenantScopes.tenantId, tid)).get();
    return row ? scope2dto(row) :
      { brandKeywords: [], monitoredDomains: [], ipRanges: [], executiveEmails: [] };
  },
  setScope(tid: string, scope: TenantScopeDTO) {
    const exists = db.select().from(tenantScopes).where(eq(tenantScopes.tenantId, tid)).get();
    const payload = {
      brandKeywords: j(scope.brandKeywords),
      monitoredDomains: j(scope.monitoredDomains),
      ipRanges: j(scope.ipRanges),
      executiveEmails: j(scope.executiveEmails),
    };
    if (exists) {
      db.update(tenantScopes).set(payload).where(eq(tenantScopes.tenantId, tid)).run();
    } else {
      db.insert(tenantScopes).values({ tenantId: tid, ...payload }).run();
    }
  },

  // ---------- client profile (extended scope + contacts) ----------
  getClientProfile(tid: string): ClientProfileDTO {
    const row = db.select().from(tenantScopes).where(eq(tenantScopes.tenantId, tid)).get();
    const contacts = db.select().from(clientContactsTbl)
      .where(eq(clientContactsTbl.tenantId, tid))
      .orderBy(desc(clientContactsTbl.isPrimary), clientContactsTbl.name)
      .all();
    if (!row) {
      return {
        brandKeywords: [], monitoredDomains: [], ipRanges: [], executiveEmails: [],
        clientTypes: [], geos: [], industries: [],
        monitoredTechnologies: [], notificationEmails: [],
        contacts,
      };
    }
    return scope2profile(row, contacts);
  },
  setClientProfile(tid: string, patch: Partial<{
    brandKeywords: string[]; monitoredDomains: string[]; ipRanges: string[]; executiveEmails: string[];
    clientTypes: string[]; geos: string[]; industries: string[];
    monitoredTechnologies: string[]; notificationEmails: string[];
  }>): ClientProfileDTO {
    const exists = db.select().from(tenantScopes).where(eq(tenantScopes.tenantId, tid)).get();
    const payload: Record<string, string> = {};
    if (patch.brandKeywords !== undefined) payload.brandKeywords = j(patch.brandKeywords);
    if (patch.monitoredDomains !== undefined) payload.monitoredDomains = j(patch.monitoredDomains);
    if (patch.ipRanges !== undefined) payload.ipRanges = j(patch.ipRanges);
    if (patch.executiveEmails !== undefined) payload.executiveEmails = j(patch.executiveEmails);
    if (patch.clientTypes !== undefined) payload.clientTypes = j(patch.clientTypes);
    if (patch.geos !== undefined) payload.geos = j(patch.geos);
    if (patch.industries !== undefined) payload.industries = j(patch.industries);
    if (patch.monitoredTechnologies !== undefined) payload.monitoredTechnologies = j(patch.monitoredTechnologies);
    if (patch.notificationEmails !== undefined) payload.notificationEmails = j(patch.notificationEmails);
    if (Object.keys(payload).length > 0) {
      if (exists) {
        db.update(tenantScopes).set(payload as any).where(eq(tenantScopes.tenantId, tid)).run();
      } else {
        db.insert(tenantScopes).values({ tenantId: tid, ...(payload as any) }).run();
      }
    }
    return storage.getClientProfile(tid);
  },
  listContacts(tid: string): ClientContact[] {
    return db.select().from(clientContactsTbl)
      .where(eq(clientContactsTbl.tenantId, tid))
      .orderBy(desc(clientContactsTbl.isPrimary), clientContactsTbl.name).all();
  },
  upsertContact(tid: string, opts: {
    id?: string; name: string; role?: string; email: string; phone?: string; isPrimary?: boolean;
  }): ClientContact {
    const t = now();
    if (opts.isPrimary) {
      // demote any other primaries
      sqlite.prepare("UPDATE client_contacts SET is_primary=0 WHERE tenant_id=?").run(tid);
    }
    if (opts.id) {
      const existing = db.select().from(clientContactsTbl)
        .where(and(eq(clientContactsTbl.id, opts.id), eq(clientContactsTbl.tenantId, tid))).get();
      if (existing) {
        db.update(clientContactsTbl).set({
          name: opts.name, role: opts.role ?? null, email: opts.email,
          phone: opts.phone ?? null, isPrimary: opts.isPrimary ? 1 : 0,
        }).where(eq(clientContactsTbl.id, opts.id)).run();
        return db.select().from(clientContactsTbl).where(eq(clientContactsTbl.id, opts.id)).get()!;
      }
    }
    const cid = id();
    db.insert(clientContactsTbl).values({
      id: cid, tenantId: tid, name: opts.name, role: opts.role ?? null,
      email: opts.email, phone: opts.phone ?? null,
      isPrimary: opts.isPrimary ? 1 : 0, createdAt: t,
    }).run();
    return db.select().from(clientContactsTbl).where(eq(clientContactsTbl.id, cid)).get()!;
  },
  deleteContact(tid: string, cid: string): boolean {
    const r = db.delete(clientContactsTbl)
      .where(and(eq(clientContactsTbl.id, cid), eq(clientContactsTbl.tenantId, tid))).run();
    return r.changes > 0;
  },

  // assets
  listAssets(tid: string, kind?: string, q?: string): AssetDTO[] {
    const filters = [eq(assets.tenantId, tid)];
    if (kind) filters.push(eq(assets.kind, kind));
    if (q) filters.push(like(assets.value, `%${q}%`));
    const rows = db.select().from(assets)
      .where(and(...filters))
      .orderBy(desc(assets.discoveredAt))
      .limit(500).all();
    return rows.map(asset2dto);
  },

  // scans
  listScans(tid: string): Scan[] {
    return db.select().from(scans)
      .where(eq(scans.tenantId, tid))
      .orderBy(desc(scans.createdAt))
      .limit(100).all();
  },
  getScan(tid: string, sid: string): Scan | undefined {
    const s = db.select().from(scans).where(eq(scans.id, sid)).get();
    return s && s.tenantId === tid ? s : undefined;
  },
  createScan(tid: string, kind: ScanKind, target: string | undefined,
             targets: string[] | undefined, config: Record<string, any>): Scan {
    const tools = SCAN_KIND_TO_TOOLS[kind] ?? [];
    const sid = id();
    db.insert(scans).values({
      id: sid, tenantId: tid, kind, tool: tools.join(","), status: "queued",
      target: target ?? null, config: j({ ...config, ...(targets ? { targets } : {}) }),
      findingCount: 0, createdAt: now(),
    }).run();

    // dispatch synchronously in the demo; the FastAPI build dispatches via Celery
    setImmediate(() => storage.runScan(sid));
    return db.select().from(scans).where(eq(scans.id, sid)).get()!;
  },
  runScan(sid: string) {
    const s = db.select().from(scans).where(eq(scans.id, sid)).get();
    if (!s) return;
    db.update(scans).set({ status: "running", startedAt: now() }).where(eq(scans.id, sid)).run();

    const cfg = p<Record<string, any>>(s.config, {});
    const scope = storage.getScope(s.tenantId);
    const allTools = (s.tool || "").split(",").filter(Boolean);
    const enabled = storage.enabledTools(s.tenantId);
    const tools = allTools.filter((t) => enabled.has(t));
    const skipped = allTools.filter((t) => !enabled.has(t));
    const log: string[] = [];
    let total = 0;

    for (const t of skipped) log.push(`[${t}] skipped — integration disabled`);

    for (const t of tools) {
      const res = runMockTool(t, {
        target: s.target ?? undefined,
        targets: cfg.targets,
        keywords: scope.brandKeywords,
      });
      for (const a of res.assets) {
        db.insert(assets).values({
          id: id(), tenantId: s.tenantId, kind: a.kind, value: a.value,
          sourceTool: a.sourceTool ?? null,
          technologies: j(a.technologies ?? []),
          riskScore: a.riskScore ?? 0, discoveredAt: a.discoveredAt ?? now(),
        }).run();
      }
      for (const f of res.findings) {
        total += 1;
        db.insert(findings).values({
          id: id(), tenantId: s.tenantId, scanId: sid, type: f.type,
          severity: f.severity, title: f.title, description: f.description ?? null,
          target: f.target ?? null, sourceTool: f.sourceTool ?? null,
          status: "open", extra: j(f.extra ?? {}), createdAt: now(),
        }).run();
      }
      for (const e of res.evidence) {
        db.insert(evidence).values({
          id: id(), tenantId: s.tenantId, findingId: null, kind: e.kind,
          status: e.status, url: e.url ?? null, artifactUrl: e.artifactUrl ?? null,
          extra: j(e.extra ?? {}), createdAt: now(),
        }).run();
      }
      log.push(`[${t}] ok findings=${res.findings.length} assets=${res.assets.length}`);
    }
    db.update(scans).set({
      status: "succeeded", finishedAt: now(),
      findingCount: total, log: log.join("\n"),
    }).where(eq(scans.id, sid)).run();
  },

  // findings
  listFindings(tid: string, type?: string, severity?: string, status?: string): FindingDTO[] {
    const filters = [eq(findings.tenantId, tid)];
    if (type) filters.push(eq(findings.type, type));
    if (severity) filters.push(eq(findings.severity, severity));
    if (status) filters.push(eq(findings.status, status));
    const rows = db.select().from(findings)
      .where(and(...filters))
      .orderBy(desc(findings.createdAt))
      .limit(500).all();
    return rows.map(finding2dto);
  },
  triageFinding(tid: string, fid: string, status: string, note?: string) {
    const f = db.select().from(findings).where(eq(findings.id, fid)).get();
    if (!f || f.tenantId !== tid) return false;
    const extra = p<Record<string, any>>(f.extra, {});
    if (note) {
      const notes = (extra.notes as any[]) || [];
      notes.push({ at: now(), note });
      extra.notes = notes;
    }
    db.update(findings).set({ status, extra: j(extra) }).where(eq(findings.id, fid)).run();
    return true;
  },

  // evidence
  listEvidence(tid: string): EvidenceDTO[] {
    const rows = db.select().from(evidence)
      .where(eq(evidence.tenantId, tid))
      .orderBy(desc(evidence.createdAt))
      .limit(200).all();
    return rows.map(evidence2dto);
  },
  async submitUrlScan(tid: string, url: string, findingId?: string): Promise<EvidenceDTO> {
    const ready = urlScanReady(tid);
    if (!ready.ready || !ready.apiKey) {
      throw new ToolUnavailableError({
        tool: "urlscan",
        kind: "credential",
        configHint: "Open Integrations, enable URLScan.io, and save URLSCAN_API_KEY.",
        message: ready.reason || "URLScan.io evidence capture requires a configured and live-tested API key.",
      });
    }
    const submittedAt = now();
    let status = "queued";
    let artifactUrl: string | null = null;
    let extra: Record<string, any> = {
      source: "urlscan.io",
      submittedAt,
      visibility: "unlisted",
      live: true,
    };
    try {
      const result = urlScanSearchAndSubmit(tid, url);
      const submission = result.submission || {};
      extra = { ...extra, ...result };
      if (!submission.ok) {
        status = "failed";
        extra = {
          ...extra,
          httpStatus: submission.status,
          error: submission.error || `URLScan.io returned HTTP ${submission.status}`,
        };
      } else {
        artifactUrl = submission.result ?? (submission.uuid ? `https://urlscan.io/result/${submission.uuid}/` : null);
        extra = {
          ...extra,
          uuid: submission.uuid ?? null,
          api: submission.api ?? null,
          result: submission.result ?? null,
          message: submission.message ?? "URLScan submission accepted.",
        };
      }
    } catch (err: any) {
      throw new ToolExecutionError("urlscan", null, err?.message || "URLScan.io request failed");
    }
    const eid = id();
    db.insert(evidence).values({
      id: eid, tenantId: tid, findingId: findingId ?? null,
      kind: "urlscan", status, url,
      artifactUrl, extra: j(extra),
      createdAt: submittedAt,
    }).run();
    return evidence2dto(db.select().from(evidence).where(eq(evidence.id, eid)).get()!);
  },

  // ---------- integrations ----------
  /**
   * `true` when the tool is allowed to run for this tenant. The default is
   * permissive — a tool with no integrations row is treated as enabled.
   * The user can explicitly disable a tool in /#/integrations, which creates
   * a row with enabled=false and causes this helper to return false. Used
   * by the Malicious Site Scanner to skip dnstwist / opensquat / crt.sh /
   * domscan / whois / keyword_expansion when the tenant has turned them off.
   */
  isToolEnabled(tid: string, toolId: string): boolean {
    const row = db.select().from(integrationsTbl)
      .where(and(eq(integrationsTbl.tenantId, tid), eq(integrationsTbl.toolId, toolId)))
      .get();
    if (!row) return true;
    return !!row.enabled;
  },
  listIntegrations(tid: string): IntegrationSummary[] {
    const rows = db.select().from(integrationsTbl).where(eq(integrationsTbl.tenantId, tid)).all();
    const byTool = new Map(rows.map((r) => [r.toolId, r]));
    return CATALOG.map((cat) => integration2summary(cat, byTool.get(cat.id)));
  },
  getIntegration(tid: string, toolId: string): IntegrationSummary | undefined {
    const cat = CATALOG_BY_ID.get(toolId);
    if (!cat) return undefined;
    const row = db.select().from(integrationsTbl)
      .where(and(eq(integrationsTbl.tenantId, tid), eq(integrationsTbl.toolId, toolId)))
      .get();
    return integration2summary(cat, row);
  },
  saveIntegration(tid: string, toolId: string, patch: {
    enabled?: boolean; apiKey?: string; apiSecret?: string; config?: Record<string, any>;
  }): IntegrationSummary | undefined {
    const cat = CATALOG_BY_ID.get(toolId);
    if (!cat) return undefined;
    const existing = db.select().from(integrationsTbl)
      .where(and(eq(integrationsTbl.tenantId, tid), eq(integrationsTbl.toolId, toolId)))
      .get();
    const row: any = existing ? { ...existing } : {
      id: id(), tenantId: tid, toolId, enabled: 1,
      config: "{}", updatedAt: now(),
    };
    if (patch.enabled !== undefined) row.enabled = patch.enabled ? 1 : 0;
    if (patch.apiKey !== undefined) {
      if (patch.apiKey === "") {
        row.apiKeyEnc = null; row.apiKeyMask = null;
      } else {
        row.apiKeyEnc = enc(patch.apiKey);
        row.apiKeyMask = mask(patch.apiKey);
      }
    }
    if (patch.apiSecret !== undefined) {
      if (patch.apiSecret === "") {
        row.apiSecretEnc = null; row.apiSecretMask = null;
      } else {
        row.apiSecretEnc = enc(patch.apiSecret);
        row.apiSecretMask = mask(patch.apiSecret);
      }
    }
    if (patch.config !== undefined) row.config = j(patch.config);
    row.updatedAt = now();

    if (existing) {
      db.update(integrationsTbl).set(row).where(eq(integrationsTbl.id, existing.id)).run();
    } else {
      db.insert(integrationsTbl).values(row).run();
    }
    return storage.getIntegration(tid, toolId);
  },
  testIntegration(tid: string, toolId: string): { ok: boolean; message: string; latencyMs: number; probedAt: string; details: Record<string, any> } {
    const cat = CATALOG_BY_ID.get(toolId);
    if (!cat) return { ok: false, message: "unknown tool", latencyMs: 0, probedAt: now(), details: {} };
    const t0 = Date.now();
    const row = db.select().from(integrationsTbl)
      .where(and(eq(integrationsTbl.tenantId, tid), eq(integrationsTbl.toolId, toolId))).get();
    const requiredEnv = (cat.env || []).filter((e) => e.required).map((e) => e.name);
    const hasCreds = !!(row?.apiKeyEnc || row?.apiSecretEnc);
    const configured = hasCreds || requiredEnv.length === 0;
    const support = connectorSupport(cat);
    let ok = false;
    let liveTested = false;
    let message = "";
    let statusLabel = "Not configured";
    const binary = (cat.invocation as any)?.binary || cat.id;
    if (!support.implemented) {
      message = support.reason || `${cat.name} connector is not implemented yet.`;
      statusLabel = "Not implemented";
    } else if (!configured) {
      message = `${cat.name} requires ${requiredEnv.join(", ") || "credentials"}.`;
      statusLabel = "Not configured";
    } else if (cat.invocation?.kind === "cli") {
      ok = commandAvailable(binary);
      liveTested = true;
      message = ok
        ? `${cat.name} binary is available on this host.`
        : `${cat.name} binary is not available on PATH.`;
      statusLabel = ok ? "Live and configured" : "Unavailable tool";
    } else if (cat.invocation?.kind === "http_api") {
      if (cat.id === "urlscan") {
        const apiKey = dec(row?.apiKeyEnc);
        if (!apiKey) {
          ok = false;
          liveTested = false;
          message = "URLScan.io API key is not configured.";
        } else {
          const probe = curlJson(
            "GET",
            "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1",
            { "API-Key": apiKey },
            undefined,
            15,
          );
          ok = probe.ok;
          liveTested = true;
          message = probe.ok
            ? "URLScan.io search API responded successfully."
            : `URLScan.io live test failed: ${probe.body?.message || probe.body?.description || probe.error || `HTTP ${probe.status}`}`;
        }
      } else {
        ok = requiredEnv.length === 0 ? true : configured;
        liveTested = requiredEnv.length === 0;
        message = `${cat.name} is available through the built-in scanner path.`;
      }
      statusLabel = liveTested ? "Live and configured" : "Configured";
    } else {
      ok = true;
      liveTested = true;
      message = `${cat.name} is available locally.`;
      statusLabel = "Live and configured";
    }
    const probedAt = now();
    const details = {
      layer: cat.layer,
      kind: cat.invocation?.kind,
      implemented: support.implemented,
      configured,
      liveTested,
      statusLabel,
      requiredEnv,
    };
    const storedMessage = JSON.stringify({ message, ...details });
    const baseRow = {
      lastTestedAt: probedAt,
      lastTestOk: ok ? 1 : 0,
      lastTestMessage: storedMessage,
      updatedAt: probedAt,
    };
    db.update(integrationsTbl).set({
      ...baseRow,
    }).where(and(eq(integrationsTbl.tenantId, tid), eq(integrationsTbl.toolId, toolId))).run();
    if (!row) {
      db.insert(integrationsTbl).values({
        id: id(), tenantId: tid, toolId, enabled: 1, config: "{}",
        ...baseRow,
        updatedAt: probedAt,
      } as any).run();
    }
    return { ok, message, latencyMs: Date.now() - t0, probedAt, details };
  },
  // returns the set of *enabled* tool ids for a tenant (used to filter scan dispatch)
  enabledTools(tid: string): Set<string> {
    const rows = db.select().from(integrationsTbl).where(eq(integrationsTbl.tenantId, tid)).all();
    const enabled = new Set<string>();
    // default-on: any tool with no row is treated as enabled
    const explicit = new Map(rows.map((r) => [r.toolId, !!r.enabled]));
    for (const cat of CATALOG) {
      if (explicit.has(cat.id)) {
        if (explicit.get(cat.id)) enabled.add(cat.id);
      } else {
        enabled.add(cat.id);
      }
    }
    return enabled;
  },

  // ---------- reports ----------
  listReports(tid: string, role: string): Report[] {
    if (role === "admin") {
      return db.select().from(reportsTbl).orderBy(desc(reportsTbl.createdAt)).limit(100).all();
    }
    // analysts see reports they authored OR reports that include their tenant
    const rows = db.select().from(reportsTbl).orderBy(desc(reportsTbl.createdAt)).limit(200).all();
    return rows.filter((r) => {
      if (r.authorTenantId === tid) return true;
      const tids = p<string[]>(r.tenantIds, []);
      return tids.includes(tid);
    });
  },
  getReport(rid: string): Report | undefined {
    return db.select().from(reportsTbl).where(eq(reportsTbl.id, rid)).get();
  },
  createReport(opts: {
    authorTenantId: string; authorEmail: string;
    tenantIds: string[]; kind: ReportKind; title?: string;
    scanIds?: string[]; includeEvidence: boolean;
  }): Report {
    const rid = id();
    const tenantRows = opts.tenantIds.map((t) => storage.getTenant(t)).filter(Boolean) as Tenant[];
    const tenantNames = tenantRows.map((t) => t.name);
    const title = opts.title || `${opts.kind.replace(/_/g, " ")} report — ${tenantNames.join(", ")}`;

    // gather data per tenant
    let totalScans = 0, totalFindings = 0, criticalCount = 0;
    const perTenant: Array<{ tenant: Tenant; findings: FindingDTO[]; scans: Scan[]; assets: AssetDTO[]; evidence: EvidenceDTO[] }> = [];
    for (const t of tenantRows) {
      const tFindings = storage.listFindings(t.id);
      const tScans = storage.listScans(t.id);
      const tAssets = storage.listAssets(t.id);
      const tEv = storage.listEvidence(t.id);
      const filteredScans = opts.scanIds && opts.scanIds.length
        ? tScans.filter((s) => opts.scanIds!.includes(s.id))
        : tScans;
      totalScans += filteredScans.length;
      totalFindings += tFindings.length;
      criticalCount += tFindings.filter((f) => f.severity === "critical").length;
      perTenant.push({ tenant: t, findings: tFindings, scans: filteredScans, assets: tAssets, evidence: tEv });
    }

    const md = renderReportMarkdown({
      title, kind: opts.kind, authorEmail: opts.authorEmail,
      perTenant, includeEvidence: opts.includeEvidence,
    });
    const html = mdToHtml(md, title);

    db.insert(reportsTbl).values({
      id: rid,
      authorTenantId: opts.authorTenantId,
      authorEmail: opts.authorEmail,
      title,
      kind: opts.kind,
      tenantIds: j(opts.tenantIds),
      tenantNames: j(tenantNames),
      scanCount: totalScans,
      findingCount: totalFindings,
      criticalCount,
      status: "ready",
      bodyMd: md,
      bodyHtml: html,
      stats: j({
        bySeverity: perTenant.flatMap((b) => b.findings).reduce((acc: Record<string, number>, f) => {
          acc[f.severity] = (acc[f.severity] || 0) + 1; return acc;
        }, {}),
      }),
      createdAt: now(),
    } as any).run();
    return db.select().from(reportsTbl).where(eq(reportsTbl.id, rid)).get()!;
  },

  // ---------- tenant onboarding ----------
  createTenant(opts: {
    name: string; slug: string; plan: string;
    brandKeywords: string[]; monitoredDomains: string[]; ipRanges: string[];
    executiveEmails: string[];
    primaryContactName?: string; primaryContactEmail?: string;
    industry?: string; geographies?: string[];
  }): Tenant {
    // ensure slug is unique
    const existing = db.select().from(tenants).where(eq(tenants.slug, opts.slug)).get();
    if (existing) {
      throw new Error(`Slug already exists: ${opts.slug}`);
    }
    const tid = id();
    db.insert(tenants).values({
      id: tid, name: opts.name, slug: opts.slug, plan: opts.plan, createdAt: now(),
    }).run();
    db.insert(tenantScopes).values({
      tenantId: tid,
      brandKeywords: j(opts.brandKeywords),
      monitoredDomains: j(opts.monitoredDomains),
      ipRanges: j(opts.ipRanges),
      executiveEmails: j(opts.executiveEmails),
    }).run();
    // seed AI providers for the new tenant so the AI Setup page is usable
    seedAiProvidersIfEmpty(tid);
    return db.select().from(tenants).where(eq(tenants.id, tid)).get()!;
  },

  // ---------- client assets (logos / trademarks) ----------
  listClientAssets(tid: string, kind?: string): ClientAssetDTO[] {
    const filters = [eq(clientAssets.tenantId, tid)];
    if (kind) filters.push(eq(clientAssets.kind, kind));
    const rows = db.select().from(clientAssets)
      .where(and(...filters))
      .orderBy(desc(clientAssets.createdAt))
      .limit(200).all();
    return rows.map((a) => assetToDto(a));
  },
  addClientAsset(tid: string, opts: {
    kind: "logo" | "trademark" | "app_icon";
    name: string; mime: string; data: string;
    jurisdiction?: string; registeredMark?: string; notes?: string;
  }): ClientAssetDTO {
    // accept either raw base64 or a data URL
    const m = /^data:[^;]+;base64,(.*)$/.exec(opts.data);
    const raw = m ? m[1] : opts.data;
    const buf = Buffer.from(raw, "base64");

    // ----- security hardening -----
    const ALLOWED = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"];
    const MAX_BYTES = 2 * 1024 * 1024; // 2 MB
    const mime = (opts.mime || "").toLowerCase().trim();
    if (!ALLOWED.includes(mime)) {
      throw new Error(`unsupported MIME type: ${opts.mime}. Allowed: ${ALLOWED.join(", ")}`);
    }
    if (buf.length === 0) throw new Error("empty file");
    if (buf.length > MAX_BYTES) throw new Error(`file too large (${buf.length} bytes; max ${MAX_BYTES})`);

    // Magic-byte sniff vs declared MIME (defence in depth)
    let sniffOk = false;
    let cleanedData = raw;
    if (mime === "image/png") {
      sniffOk = buf.length >= 4 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
    } else if (mime === "image/jpeg") {
      sniffOk = buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
    } else if (mime === "image/gif") {
      sniffOk = buf.length >= 4 && buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38;
    } else if (mime === "image/webp") {
      sniffOk = buf.length >= 12 &&
        buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 && // RIFF
        buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50;   // WEBP
    } else if (mime === "image/svg+xml") {
      // SVG: text-based; accept if it begins with <?xml or <svg (with optional whitespace/BOM).
      const head = buf.slice(0, 200).toString("utf8").replace(/^\ufeff/, "").trim();
      sniffOk = /^(<\?xml|<svg\b)/i.test(head);
      if (sniffOk) {
        // Strip <script>, on*= handlers, and javascript: URLs
        let text = buf.toString("utf8");
        text = text
          .replace(/<script[\s\S]*?<\/script>/gi, "")
          .replace(/\s+on[a-z]+\s*=\s*"[^"]*"/gi, "")
          .replace(/\s+on[a-z]+\s*=\s*'[^']*'/gi, "")
          .replace(/\s+on[a-z]+\s*=\s*[^\s>]+/gi, "")
          .replace(/javascript:[^"'\s>]+/gi, "about:blank")
          .replace(/<foreignObject[\s\S]*?<\/foreignObject>/gi, "");
        cleanedData = Buffer.from(text, "utf8").toString("base64");
      }
    }
    if (!sniffOk) throw new Error(`file content does not match declared MIME ${mime} (magic-byte mismatch)`);

    const cleanedBuf = Buffer.from(cleanedData, "base64");
    const sha256 = createHash("sha256").update(cleanedBuf).digest("hex");
    const aid = id();
    db.insert(clientAssets).values({
      id: aid, tenantId: tid, kind: opts.kind, name: opts.name,
      mime: mime, size: cleanedBuf.length, sha256, data: cleanedData,
      jurisdiction: opts.jurisdiction ?? null,
      registeredMark: opts.registeredMark ?? null,
      notes: opts.notes ?? null,
      createdAt: now(),
    }).run();
    storage.appendAudit(tid, "system", "asset.upload", aid, { kind: opts.kind, mime, size: cleanedBuf.length, sha256 });
    const row = db.select().from(clientAssets).where(eq(clientAssets.id, aid)).get()!;
    return assetToDto(row);
  },
  deleteClientAsset(tid: string, aid: string): boolean {
    const r = db.delete(clientAssets)
      .where(and(eq(clientAssets.id, aid), eq(clientAssets.tenantId, tid))).run();
    return r.changes > 0;
  },

  // ---------- keyword expansion ----------
  expandKeywordsForTenant(tid: string, opts: ExpandOptions) {
    return expandKeywords(opts);
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
      .find((p) => !!p.apiKeyEnc && p.lastTestOk === 1);
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
        row.apiKeyEnc = null; row.apiKeyMask = null;
      } else if (opts.apiKey.length > 0) {
        row.apiKeyEnc = enc(opts.apiKey);
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
    return r.changes > 0;
  },
  testAiProvider(tid: string, pid: string): { ok: boolean; latencyMs: number; message: string; probedAt: string } {
    const row = db.select().from(aiProviders).where(and(eq(aiProviders.id, pid), eq(aiProviders.tenantId, tid))).get();
    if (!row) return { ok: false, latencyMs: 0, message: "unknown provider", probedAt: now() };
    const r = testAiProviderImpl(row);
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
      !!row && !!row.enabled && !!row.apiKeyEnc && row.lastTestOk === 1;
    const assignments = storage.getAiAssignments(tid);
    const pid = assignments[task];
    if (pid) {
      const row = db.select().from(aiProviders).where(and(eq(aiProviders.id, pid), eq(aiProviders.tenantId, tid))).get();
      if (usable(row)) return row;
      return undefined;
    }
    const def = db.select().from(aiProviders)
      .where(and(eq(aiProviders.tenantId, tid), eq(aiProviders.isDefault, 1)))
      .get();
    if (usable(def)) return def;
    return db.select().from(aiProviders)
      .where(and(eq(aiProviders.tenantId, tid), eq(aiProviders.enabled, 1)))
      .all()
      .find((row) => usable(row));
  },

  // ---------- AI dispatch helpers ----------
  aiTriageFinding(tid: string, fid: string) {
    const f = db.select().from(findings).where(eq(findings.id, fid)).get();
    if (!f || f.tenantId !== tid) return undefined;
    const provider = storage.resolveAiProvider(tid, "triage");
    if (!provider) return undefined;
    const dto = finding2dto(f);
    const r = dispatchAi({ task: "triage", input: dto, provider });
    if (r.task !== "triage") return undefined;
    // store the AI verdict on the finding's extra payload
    const extra = p<Record<string, any>>(f.extra, {});
    extra.ai = {
      provider: provider.label,
      model: provider.model,
      at: now(),
      ...r.output,
    };
    db.update(findings).set({ extra: j(extra) }).where(eq(findings.id, fid)).run();
    return { provider: { id: provider.id, label: provider.label, model: provider.model }, ...r.output };
  },
  aiSummarizeReport(rid: string) {
    const r = db.select().from(reportsTbl).where(eq(reportsTbl.id, rid)).get();
    if (!r) return undefined;
    const provider = storage.resolveAiProvider(r.authorTenantId, "report_summary");
    if (!provider) return undefined;
    const tenantNames = p<string[]>(r.tenantNames, []);
    const stats = p<Record<string, any>>(r.stats, {});
    const bySev = stats.bySeverity || {};
    // gather a top-finding sample across the report's tenants
    const tenantIds = p<string[]>(r.tenantIds, []);
    const topFindings = tenantIds.flatMap((tid) =>
      storage.listFindings(tid).slice(0, 5).map((f) => ({
        severity: f.severity, type: f.type, title: f.title, target: f.target,
      }))
    ).slice(0, 15);
    const out = dispatchAi({
      task: "report_summary",
      input: {
        title: r.title,
        tenants: tenantNames,
        totals: {
          findings: r.findingCount,
          critical: r.criticalCount,
          high: bySev.high || 0,
          assets: 0,
          scans: r.scanCount,
        },
        topFindings,
      },
      provider,
    });
    if (out.task !== "report_summary") return undefined;
    const next = stats;
    next.aiSummary = {
      provider: provider.label, model: provider.model, at: now(),
      ...out.output,
    };
    db.update(reportsTbl).set({ stats: j(next) }).where(eq(reportsTbl.id, rid)).run();
    return next.aiSummary;
  },

  // ---------- young-domain monitoring ----------
  // Phase 1 (productionalised + async-job pattern):
  //
  //   startYoungDomainScan() inserts a scans row with status='running' and
  //   returns its id SYNCHRONOUSLY. The real work — DNSTwist + openSquat +
  //   crt.sh + WHOIS — runs detached and updates scans.status when done.
  //
  // Per-seed parallelism is capped at 4 (saturating the resolver, not the
  // process). openSquat is invoked ONCE for the union of brand keywords
  // because each invocation re-downloads the Whoisds 100k-row feed.
  //
  // The client polls GET /api/v1/scans/:sid every few seconds to surface
  // progress and fetches the candidates when status flips off 'running'.
  //
  // AI verdicts remain decoupled — analysts trigger them via
  // runYoungDomainAnalysis / runYoungDomainAnalysisOne after the scan persists.
  startYoungDomainScan(
    tid: string,
    opts: { mode: "tenant" | "global" | "both"; presetIds?: string[]; domains?: string[]; maxPerSeed?: number },
  ): { id: string } {
    const sid = id();
    const ts = now();
    const max = opts.maxPerSeed ?? 10;

    // Tenant seeds only matter when the scan mode actually scans tenant
    // domains. `mode='global'` reads exclusively from YOUNG_DOMAIN_PRESETS
    // and must never bring tenant_scope.monitoredDomains into play (would be
    // misleading in the scans.target field and could leak the wrong seed
    // into the scan log).
    const tenantSeeds: string[] = (() => {
      if (opts.mode === "global") return [];
      if (opts.domains && opts.domains.length) return opts.domains;
      const scope = storage.getScope(tid);
      return scope.monitoredDomains;
    })();

    // Resolve the global presets up front so scans.target reflects the
    // actual seeds queued (e.g. "sharepoint.com,sharepointonline.com")
    // rather than the tenant scope.
    const globalSeeds: string[] = (() => {
      if (opts.mode === "tenant") return [];
      const presets = (opts.presetIds && opts.presetIds.length
        ? YOUNG_DOMAIN_PRESETS.filter((p) => opts.presetIds!.includes(p.id))
        : YOUNG_DOMAIN_PRESETS);
      return presets.flatMap((p) => [...p.seeds]);
    })();

    const allSeedsForDisplay = [...tenantSeeds, ...globalSeeds];

    // Insert scan row immediately so the client can start polling.
    db.insert(scans).values({
      id: sid, tenantId: tid, kind: "young-domain",
      tool: "dnstwist,opensquat,crtsh,domscan,keyword_expansion", status: "running",
      target: allSeedsForDisplay.length ? allSeedsForDisplay.slice(0, 20).join(",") : null,
      config: j({ mode: opts.mode, presetIds: opts.presetIds || [], maxPerSeed: max }),
      findingCount: 0,
      createdAt: ts, startedAt: ts, finishedAt: null,
      log: `[scan ${sid}] queued at ${ts} · mode=${opts.mode} · ${allSeedsForDisplay.length} seed(s)`,
    }).run();

    // Register a cancellation controller before kicking off the work so
    // cancelScan() has somewhere to call abort() on.
    const abortCtrl = new AbortController();
    SCAN_ABORT_CONTROLLERS.set(sid, abortCtrl);

    // Kick off background work. Detached — never awaited by the caller.
    // Errors are written to scans.log so the client poller surfaces them.
    setImmediate(() => {
      storage._executeYoungDomainScan(tid, sid, opts, tenantSeeds, max, abortCtrl.signal).catch((err: any) => {
        // eslint-disable-next-line no-console
        console.error(`[young-domain] background scan ${sid} crashed:`, err);
        try {
          db.update(scans).set({
            status: "failed",
            finishedAt: now(),
            log: `[scan ${sid}] crashed: ${err?.message ?? err}\n${err?.stack ?? ""}`,
          }).where(eq(scans.id, sid)).run();
        } catch { /* DB write failed — last-ditch logged above */ }
      }).finally(() => {
        SCAN_ABORT_CONTROLLERS.delete(sid);
      });
    });

    return { id: sid };
  },

  /**
   * Cancel an in-flight malicious-site / young-domain scan.
   *
   * Returns:
   *   - { ok: true,  status: "cancelled" }  — abort fired, executor will
   *     finalise the scan row to status='cancelled' as it unwinds
   *   - { ok: false, status: "<terminal>" } — scan already finished
   *   - { ok: false, status: "not_found" }  — wrong tenant or missing id
   *
   * Tenant-scoped: a scan can only be cancelled by the tenant that owns it
   * (or an MSSP admin pivoting via X-Tenant-Id).
   */
  cancelScan(tid: string, sid: string): { ok: boolean; status: string; message?: string } {
    const row = sqlite.prepare(
      "SELECT id, tenant_id, status FROM scans WHERE id = ? AND tenant_id = ?",
    ).get(sid, tid) as { id: string; tenant_id: string; status: string } | undefined;
    if (!row) return { ok: false, status: "not_found", message: "Scan not found for this tenant." };

    if (row.status !== "running" && row.status !== "queued") {
      return { ok: false, status: row.status, message: `Scan already ${row.status}.` };
    }

    // Flip the DB status immediately so the client's poll sees the cancel
    // even if the abort takes a few seconds to propagate through child kills.
    // The executor's own finalisation will overwrite log + finishedAt as it
    // unwinds; we only set status here for instant UI feedback.
    db.update(scans).set({
      status: "cancelled",
    }).where(eq(scans.id, sid)).run();

    const controller = SCAN_ABORT_CONTROLLERS.get(sid);
    if (controller) {
      try { controller.abort(); } catch { /* already aborted */ }
    }
    return { ok: true, status: "cancelled" };
  },

  /**
   * Background body of a young-domain scan. Never called directly by routes —
   * invoked by startYoungDomainScan() via setImmediate(). All updates land on
   * the scans row that startYoungDomainScan() pre-inserted; the client polls
   * GET /api/v1/scans/:sid to observe progress.
   */
  async _executeYoungDomainScan(
    tid: string,
    sid: string,
    opts: { mode: "tenant" | "global" | "both"; presetIds?: string[]; domains?: string[]; maxPerSeed?: number },
    tenantSeeds: string[],
    max: number,
    signal?: AbortSignal,
  ): Promise<void> {
    const globalPresets = (opts.presetIds && opts.presetIds.length
      ? YOUNG_DOMAIN_PRESETS.filter((p) => opts.presetIds!.includes(p.id))
      : YOUNG_DOMAIN_PRESETS);

    type DiscoveredBy = "dnstwist" | "opensquat" | "crtsh" | "domscan" | "keyword_expansion";
    interface Pending {
      domain: string;
      seed: string;
      source: "tenant" | "global";
      presetId?: string;
      presetName?: string;
      discoveredBy: Set<DiscoveredBy>;
      technique: string;
      similarity: number;
      hasA: boolean;
      hasMx: boolean;
      dnsA: string[];
      dnsMx: string[];
      crtshNotBefore?: string;
      sourceEvidence: Record<string, any>;
    }

    // Build the (seed, source, presetId?, presetName?) list we need to scan.
    const seedJobs: Array<{ seed: string; source: "tenant" | "global"; presetId?: string; presetName?: string }> = [];
    if (opts.mode === "tenant" || opts.mode === "both") {
      for (const seed of tenantSeeds) seedJobs.push({ seed, source: "tenant" });
    }
    if (opts.mode === "global" || opts.mode === "both") {
      for (const preset of globalPresets) {
        for (const seed of preset.seeds) seedJobs.push({ seed, source: "global", presetId: preset.id, presetName: preset.name });
      }
    }

    const pending = new Map<string, Pending>();
    const warnings: Array<{ tool: string; seed?: string; reason: string; installHint?: string }> = [];
    const logLines: string[] = [];
    const t0 = Date.now();

    const brandKeyword = (seed: string): string => (seed.split(".")[0] || seed).toLowerCase();

    // Persist progress to scans.log so the UI's polling sees updates without
    // us re-querying every tick. Best-effort — never throws.
    const persistProgress = (line: string): void => {
      logLines.push(`[+${Math.round((Date.now() - t0) / 1000)}s] ${line}`);
      try {
        db.update(scans).set({ log: logLines.join("\n") }).where(eq(scans.id, sid)).run();
      } catch { /* swallow */ }
    };

    persistProgress(`starting scan: ${seedJobs.length} seed(s), maxPerSeed=${max}`);

    // ---- Step 1: openSquat — single invocation across all keywords. ----
    // openSquat downloads a daily 100k-row Whoisds feed on every run, so
    // calling it once with the union of brand keywords is dramatically faster
    // than per-seed (and produces the same matches: we attribute each match
    // back to a seed via substring overlap below).
    const scopeForKeywords = storage.getScope(tid);
    const uniqueKeywords = Array.from(new Set([
      ...seedJobs.map((j) => brandKeyword(j.seed)),
      ...(opts.mode !== "global" ? (scopeForKeywords.brandKeywords || []) : []),
      ...(opts.mode !== "tenant" ? globalPresets.flatMap((p) => [p.name, ...p.seeds.map(brandKeyword)]) : []),
    ].map((k) => String(k || "").toLowerCase().trim()).filter(Boolean)));
    if (uniqueKeywords.length) {
      // Per-tool enable gates. A tenant that turned a tool off in
      // /#/integrations should never see it run — we log [tool] skipped
      // instead so the scans.log makes the choice visible.
      const opensquatEnabled = storage.isToolEnabled(tid, "opensquat");
      const domscanEnabled = storage.isToolEnabled(tid, "domscan");
      const keywordExpansionEnabled = storage.isToolEnabled(tid, "keyword_expansion");
      if (!opensquatEnabled) persistProgress(`opensquat: skipped (disabled in Integrations)`);
      if (!domscanEnabled) persistProgress(`domscan: skipped (disabled in Integrations)`);
      if (!keywordExpansionEnabled) persistProgress(`keyword expansion: skipped (disabled in Integrations)`);

      const [openSquatRes, domScanRes] = await Promise.allSettled([
        (async () => {
          if (!opensquatEnabled) return [] as OpenSquatRow[];
          persistProgress(`opensquat: scanning ${uniqueKeywords.length} unique brand keyword(s)…`);
          return runOpenSquat(uniqueKeywords, { timeoutMs: 180_000, signal });
        })(),
        (async () => {
          if (!domscanEnabled) return [] as DomScanRow[];
          persistProgress(`domscan: scanning ${uniqueKeywords.length} unique brand keyword(s)…`);
          const row = db.select().from(integrationsTbl)
            .where(and(eq(integrationsTbl.tenantId, tid), eq(integrationsTbl.toolId, "domscan")))
            .get();
          const apiKey = row?.enabled === 0 ? null : dec(row?.apiKeyEnc);
          if (!apiKey) throw new Error("DomScan API key not configured in Integrations");
          return runDomScan(uniqueKeywords, { apiKey, timeoutMs: 25_000, signal });
        })(),
      ]);

      if (openSquatRes.status === "fulfilled") {
        if (opensquatEnabled) persistProgress(`opensquat: ${openSquatRes.value.length} match(es)`);
        for (const row of openSquatRes.value) {
          const job = seedJobs.find((j) => row.domain.includes(brandKeyword(j.seed))) ?? seedJobs[0];
          if (job) upsertFromOpenSquat(pending, job, row);
        }
      } else {
        warnings.push(makeWarning("opensquat", "(all keywords)", openSquatRes.reason));
        persistProgress(`opensquat: FAILED — ${openSquatRes.reason?.message ?? openSquatRes.reason}`);
      }

      if (domScanRes.status === "fulfilled") {
        if (domscanEnabled) persistProgress(`domscan: ${domScanRes.value.length} registered match(es)`);
        for (const row of domScanRes.value) {
          const job = seedJobs.find((j) => row.domain.includes(brandKeyword(j.seed))) ?? seedJobs[0];
          if (job) upsertFromDomScan(pending, job, row);
        }
      } else {
        warnings.push(makeWarning("domscan", "(all keywords)", domScanRes.reason));
        persistProgress(`domscan: FAILED — ${domScanRes.reason?.message ?? domScanRes.reason}`);
      }

      if (keywordExpansionEnabled) try {
        // Generate variants then DNS-verify before pushing to `pending`.
        // The expansion engine is pure math — it will happily emit thousands
        // of strings that don't correspond to registered domains. Without
        // the DNS gate every variant would then receive a 15s whois call
        // and a 10s HTTP probe — minutes-per-candidate of wasted work and
        // the cause of the 30+ minute "stuck" scans.
        const expansion = expandKeywords({ base: uniqueKeywords, domains: seedJobs.map((j) => j.seed), maxPerTechnique: 15 });
        // Cap raw variants at top 50 by riskScore so we don't DNS-flood.
        // The 14 expansion techniques each emit dozens; only the highest-
        // similarity ones are worth verifying.
        const topVariants = expansion.variants
          .filter((v) => v.variant.includes("."))
          .slice(0, 50);
        persistProgress(`keyword expansion: ${expansion.uniqueCount} variant(s), DNS-verifying top ${topVariants.length}…`);
        const verifiedDomains = await dnsVerifyDomains(topVariants.map((v) => v.variant), signal);
        let kept = 0;
        for (const variant of topVariants) {
          if (!verifiedDomains.has(variant.variant)) continue;
          const job = seedJobs.find((j) => variant.variant.includes(brandKeyword(j.seed))) ?? seedJobs[0];
          if (job) {
            upsertFromKeywordExpansion(pending, job, variant);
            kept++;
          }
        }
        persistProgress(`keyword expansion: ${kept}/${topVariants.length} variants resolve (registered) · ${pending.size} candidates after merge`);
      } catch (err: any) {
        warnings.push(makeWarning("keyword_expansion", "(all keywords)", err));
        persistProgress(`keyword expansion: FAILED — ${err?.message ?? err}`);
      }
    }

    // ---- Step 2: DNSTwist + crt.sh per seed (concurrency 4). ----
    // dnstwist's --screenshots flag drives Playwright/Chromium to render each
    // resolved permutation and save <domain>.png into the supplied dir. We
    // bump the per-process timeout (300s) because Chromium launches are slow.
    // If Chromium / dnstwist[full] is missing, dnstwist simply emits no PNGs
    // and the candidate's screenshotUrl stays null — no hard failure.
    const seedConcurrency = 4;
    let seedsDone = 0;
    const seedsInFlight = new Set<string>();
    // Heartbeat every 30s so the UI knows DNSTwist is still working on long
    // seeds (Playwright screenshot + phash can take 3-5 min per seed).
    const heartbeat = setInterval(() => {
      if (seedsInFlight.size === 0) return;
      const live = Array.from(seedsInFlight).slice(0, 4).join(", ")
        + (seedsInFlight.size > 4 ? ` +${seedsInFlight.size - 4} more` : "");
      persistProgress(`dnstwist+crtsh: ${seedsDone}/${seedJobs.length} done · still running: ${live}`);
    }, 30_000);
    // Per-seed tool gates — checked once outside the worker loop because
    // every seed shares the same enable bit.
    const dnstwistEnabled = storage.isToolEnabled(tid, "dnstwist");
    const crtshEnabled = storage.isToolEnabled(tid, "crtsh");
    if (!dnstwistEnabled) persistProgress(`dnstwist: skipped (disabled in Integrations)`);
    if (!crtshEnabled) persistProgress(`crtsh: skipped (disabled in Integrations)`);
    try {
      await runWithConcurrency(seedJobs, seedConcurrency, async (job) => {
        if (!dnstwistEnabled && !crtshEnabled) return;  // both off → nothing to do
        const { seed } = job;
        const kw = brandKeyword(seed);
        const since = new Date(Date.now() - 90 * 86400_000).toISOString();
        seedsInFlight.add(seed);
        persistProgress(`dnstwist+crtsh: ${seed} started (${seedsDone}/${seedJobs.length} done)`);
        const [dtRes, ctRes] = await Promise.allSettled([
          dnstwistEnabled
            ? runDnstwist(seed, {
                registeredOnly: true,
                threads: 8,
                timeoutMs: 540_000,
                screenshotsDir: DNSTWIST_SCREENSHOTS_DIR,
                signal,
              })
            : Promise.resolve([] as DnstwistRow[]),
          crtshEnabled
            ? runCrtSh(kw, { sinceIso: since, limit: 100, timeoutMs: 25_000, signal })
            : Promise.resolve([] as CtLogRow[]),
        ]);
        let dtCount = 0;
        if (dtRes.status === "fulfilled") {
          for (const row of dtRes.value as DnstwistRow[]) upsertFromDnstwist(pending, job, row);
          dtCount = (dtRes.value as DnstwistRow[]).length;
        } else if (dnstwistEnabled && !warnings.some((w) => w.tool === "dnstwist")) {
          warnings.push(makeWarning("dnstwist", seed, dtRes.reason));
        }
        let ctCount = 0;
        if (ctRes.status === "fulfilled") {
          const domains = extractDomainsFromCtRows(ctRes.value as CtLogRow[]);
          for (const d of domains) {
            if (d === seed) continue;
            if (!d.includes(kw)) continue;
            upsertFromCrtSh(pending, job, d, (ctRes.value as CtLogRow[])[0]?.notBefore);
            ctCount++;
          }
        } else if (crtshEnabled && !warnings.some((w) => w.tool === "crtsh")) {
          warnings.push(makeWarning("crtsh", seed, ctRes.reason));
        }
        seedsInFlight.delete(seed);
        seedsDone++;
        persistProgress(
          `dnstwist+crtsh: ${seed} done · dnstwist=${dnstwistEnabled ? (dtRes.status === "fulfilled" ? dtCount : "FAIL") : "off"} · crtsh=${crtshEnabled ? (ctRes.status === "fulfilled" ? ctCount : "FAIL") : "off"} · ${seedsDone}/${seedJobs.length} seeds done · ${pending.size} unique candidates`,
        );
      });
    } finally {
      clearInterval(heartbeat);
    }

    persistProgress(`discovery phase complete · ${pending.size} unique candidates`);

    // ---- Step 3: per-seed cap. ----
    const grouped = new Map<string, Pending[]>();
    for (const p of Array.from(pending.values())) {
      const key = p.seed;
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key)!.push(p);
    }
    const ranked: Pending[] = [];
    for (const arr of Array.from(grouped.values())) {
      arr.sort((a: Pending, b: Pending) => {
        if (a.discoveredBy.size !== b.discoveredBy.size) return b.discoveredBy.size - a.discoveredBy.size;
        if (a.similarity !== b.similarity) return b.similarity - a.similarity;
        return a.domain.localeCompare(b.domain);
      });
      ranked.push(...arr.slice(0, max));
    }
    persistProgress(`ranked + capped to ${ranked.length} candidates`);

    // ---- Step 4: WHOIS enrichment (concurrency 5). ----
    const whoisEnabled = storage.isToolEnabled(tid, "whois");
    const whoisByDomain = new Map<string, WhoisRecord>();
    if (!whoisEnabled) {
      persistProgress(`whois: skipped (disabled in Integrations)`);
    } else {
      let whoisMissingWarned = false;
      await runWithConcurrency(ranked, 5, async (p) => {
        try {
          const rec = await runWhois(p.domain, { timeoutMs: 15_000, signal });
          whoisByDomain.set(p.domain, rec);
        } catch (err: any) {
          if (err?.name === "ToolUnavailableError" && !whoisMissingWarned) {
            warnings.push({
              tool: "whois",
              reason: err.message,
              installHint: err.installHint,
            });
            whoisMissingWarned = true;
          }
        }
      });
      persistProgress(`whois: enriched ${whoisByDomain.size}/${ranked.length} candidates`);
    }

    // ---- Step 4b: lightweight HTTP/site evidence (concurrency 5). ----
    const siteEvidenceByDomain = new Map<string, any>();
    await runWithConcurrency(ranked, 5, async (p) => {
      siteEvidenceByDomain.set(p.domain, await probeSiteEvidence(p.domain, signal));
    });
    persistProgress(`http: probed ${siteEvidenceByDomain.size}/${ranked.length} candidates`);

    // ---- Step 5: persist findings. ----
    const ts = now();
    let persisted = 0;
    for (const p of ranked) {
      const wh = whoisByDomain.get(p.domain) ?? null;
      const ageDays = wh?.ageDays ?? 0;
      const recencyBoost = ageDays > 0 && ageDays <= 14 ? 0.2 : ageDays <= 60 ? 0.1 : 0;
      const sourcesBoost = (p.discoveredBy.size - 1) * 0.1;
      const riskScore = Math.round(((p.similarity * 0.4)
        + (p.hasMx ? 0.15 : 0)
        + (p.hasA ? 0.1 : 0)
        + recencyBoost
        + sourcesBoost
      ) * 100);
      // Phase 1 — real DNSTwist landing-page screenshot from Playwright. The
      // PNG only exists when (a) the domain resolved AND (b) Chromium rendered
      // it successfully. When absent we set null and the card shows a
      // "no screenshot" placeholder. ?v= cache-busts on re-scan.
      const screenshotFile = findDnstwistScreenshotFile(p.domain);
      const screenshotUrl: string | null = screenshotFile
        ? `/dnstwist-screenshots/${encodeURIComponent(screenshotFile)}?v=${Date.now()}`
        : null;
      const brandAbuse = await computeBrandAbuseMatches(
        tid,
        screenshotFile ? join(DNSTWIST_SCREENSHOTS_DIR, screenshotFile) : null,
      );
      const siteEvidence = siteEvidenceByDomain.get(p.domain) ?? { status: "unknown" };
      const cid = id();
      const primaryTool: "dnstwist" | "opensquat" | "crtsh" =
        p.discoveredBy.has("dnstwist") ? "dnstwist"
        : p.discoveredBy.has("opensquat") ? "opensquat"
        : "crtsh";

      db.insert(findings).values({
        id: cid, tenantId: tid, scanId: sid, type: "young-domain",
        severity: riskScore >= 75 ? "high" : riskScore >= 50 ? "medium" : "low",
        title: `Young-domain candidate: ${p.domain}`,
        description: `Discovered via ${Array.from(p.discoveredBy).join(" + ")}. Permutation of ${p.seed} (${p.technique}). Similarity ${Math.round(p.similarity * 100)}%. ${wh?.registrar ? `Registrar: ${wh.registrar}. ` : ""}${ageDays ? `Age: ${ageDays}d.` : ""}`,
        target: p.domain,
        sourceTool: primaryTool,
        status: "open",
        evidenceSource: "live",
        extra: j({
          source: p.source, seed: p.seed, presetId: p.presetId, presetName: p.presetName,
          technique: p.technique, ageDays, hasMx: p.hasMx, hasA: p.hasA,
          similarity: Math.round(p.similarity * 1000) / 1000,
          riskScore, screenshotUrl,
          brandAbuse,
          discoveredBy: Array.from(p.discoveredBy),
          dnsA: p.dnsA, dnsMx: p.dnsMx,
          siteEvidence,
          sourceEvidence: p.sourceEvidence,
          whois: wh ? {
            createdAt: wh.createdAt, updatedAt: wh.updatedAt, expiresAt: wh.expiresAt,
            registrar: wh.registrar, country: wh.registrantCountry,
            nameServers: wh.nameServers,
          } : null,
          warnings,
          ai: null, analyst: null,
        }),
        createdAt: ts,
      }).run();
      persisted++;
    }

    // ---- Step 6: finalise scan row. ----
    // If the user clicked Cancel mid-scan we honour that even if some
    // candidates were persisted before the abort propagated.
    const cancelled = signal?.aborted === true;
    const toolsUsed = ["dnstwist", "opensquat", "crtsh", "domscan", "keyword_expansion"];
    const usedOk = toolsUsed.filter((t) => !warnings.some((w) => w.tool === t));
    const finalStatus = cancelled ? "cancelled"
      : persisted === 0 && warnings.length > 0 ? "failed"
      : warnings.length > 0 ? "partial"
      : "succeeded";
    for (const t of toolsUsed) {
      const w = warnings.find((x) => x.tool === t);
      // When the scan was cancelled, tool-level "FAILED — aborted" entries
      // are a side-effect of the cancel and not a real fault. Recolour them
      // so the log reads honestly.
      if (cancelled && w && /aborted by caller/i.test(w.reason)) {
        logLines.push(`[${t}] cancelled`);
      } else if (w) {
        logLines.push(`[${t}] FAILED — ${w.reason}${w.installHint ? ` (install: ${w.installHint})` : ""}`);
      } else {
        logLines.push(`[${t}] ok`);
      }
    }
    if (cancelled) {
      logLines.push(`[summary] CANCELLED at ${Math.round((Date.now() - t0) / 1000)}s · ${persisted} candidate(s) persisted before abort`);
    } else {
      logLines.push(`[summary] candidates=${persisted} sources_used=${usedOk.length}/${toolsUsed.length} duration=${Math.round((Date.now() - t0) / 1000)}s`);
    }
    db.update(scans).set({
      status: finalStatus,
      findingCount: persisted,
      finishedAt: now(),
      log: logLines.join("\n"),
    }).where(eq(scans.id, sid)).run();

    // ---- helpers (local closures over `pending`) ----
    function upsertFromDnstwist(map: Map<string, Pending>, job: { seed: string; source: "tenant" | "global"; presetId?: string; presetName?: string }, row: DnstwistRow): void {
      const key = row.domain.toLowerCase();
      const existing = map.get(key);
      const dnsA = validDnsValues(row.dns_a);
      const dnsMx = validDnsValues(row.dns_mx);
      const hasA = dnsA.length > 0;
      const hasMx = dnsMx.length > 0;
      const sim = typeof row.ssdeep_score === "number" ? row.ssdeep_score / 100
        : typeof row.phash_score === "number" ? row.phash_score / 100
        : 0;
      if (existing) {
        existing.discoveredBy.add("dnstwist");
        existing.sourceEvidence.dnstwist = row;
        if (sim > existing.similarity) existing.similarity = sim;
        existing.hasA = existing.hasA || hasA;
        existing.hasMx = existing.hasMx || hasMx;
        existing.dnsA = mergeUnique(existing.dnsA, dnsA);
        existing.dnsMx = mergeUnique(existing.dnsMx, dnsMx);
        if (!existing.technique) existing.technique = row.fuzzer;
      } else {
        map.set(key, {
          domain: key,
          seed: job.seed, source: job.source,
          presetId: job.presetId, presetName: job.presetName,
          discoveredBy: new Set<DiscoveredBy>(["dnstwist"]),
          technique: row.fuzzer || "permutation",
          similarity: sim, hasA, hasMx,
          dnsA,
          dnsMx,
          sourceEvidence: { dnstwist: row },
        });
      }
    }
    function upsertFromOpenSquat(map: Map<string, Pending>, job: { seed: string; source: "tenant" | "global"; presetId?: string; presetName?: string }, row: OpenSquatRow): void {
      const key = row.domain.toLowerCase();
      const existing = map.get(key);
      const sim = typeof row.confidence === "number" ? Math.min(1, 0.2 + row.confidence * 0.2) : 0.4;
      if (existing) {
        existing.discoveredBy.add("opensquat");
        existing.sourceEvidence.opensquat = row;
        if (sim > existing.similarity) existing.similarity = sim;
        if (!existing.technique) existing.technique = "squat";
      } else {
        map.set(key, {
          domain: key,
          seed: job.seed, source: job.source,
          presetId: job.presetId, presetName: job.presetName,
          discoveredBy: new Set<DiscoveredBy>(["opensquat"]),
          technique: "squat",
          similarity: sim,
          hasA: false, hasMx: false,
          dnsA: [], dnsMx: [],
          sourceEvidence: { opensquat: row },
        });
      }
    }
    function upsertFromDomScan(map: Map<string, Pending>, job: { seed: string; source: "tenant" | "global"; presetId?: string; presetName?: string }, row: DomScanRow): void {
      const key = row.domain.toLowerCase();
      const existing = map.get(key);
      const sim = typeof row.score === "number" ? Math.min(1, row.score > 1 ? row.score / 100 : row.score) : 0.45;
      if (existing) {
        existing.discoveredBy.add("domscan");
        existing.sourceEvidence.domscan = row;
        if (sim > existing.similarity) existing.similarity = sim;
      } else {
        map.set(key, {
          domain: key,
          seed: job.seed, source: job.source,
          presetId: job.presetId, presetName: job.presetName,
          discoveredBy: new Set<DiscoveredBy>(["domscan"]),
          technique: "domain-intel",
          similarity: sim,
          hasA: false, hasMx: false,
          dnsA: [], dnsMx: [],
          sourceEvidence: { domscan: row },
        });
      }
    }
    function upsertFromKeywordExpansion(map: Map<string, Pending>, job: { seed: string; source: "tenant" | "global"; presetId?: string; presetName?: string }, row: any): void {
      const key = String(row.variant).toLowerCase();
      const existing = map.get(key);
      const sim = typeof row.similarity === "number" ? row.similarity : 0.4;
      if (existing) {
        existing.discoveredBy.add("keyword_expansion");
        existing.sourceEvidence.keyword_expansion = row;
        if (sim > existing.similarity) existing.similarity = sim;
        if (!existing.technique) existing.technique = row.techniqueLabel || row.technique || "keyword-expansion";
      } else {
        map.set(key, {
          domain: key,
          seed: job.seed, source: job.source,
          presetId: job.presetId, presetName: job.presetName,
          discoveredBy: new Set<DiscoveredBy>(["keyword_expansion"]),
          technique: row.techniqueLabel || row.technique || "keyword-expansion",
          similarity: sim,
          hasA: false, hasMx: false,
          dnsA: [], dnsMx: [],
          sourceEvidence: { keyword_expansion: row },
        });
      }
    }
    function upsertFromCrtSh(map: Map<string, Pending>, job: { seed: string; source: "tenant" | "global"; presetId?: string; presetName?: string }, domain: string, notBefore?: string): void {
      const key = domain.toLowerCase();
      const existing = map.get(key);
      const sim = 0.35;
      if (existing) {
        existing.discoveredBy.add("crtsh");
        existing.sourceEvidence.crtsh = { domain, notBefore };
        if (!existing.crtshNotBefore && notBefore) existing.crtshNotBefore = notBefore;
      } else {
        map.set(key, {
          domain: key,
          seed: job.seed, source: job.source,
          presetId: job.presetId, presetName: job.presetName,
          discoveredBy: new Set<DiscoveredBy>(["crtsh"]),
          technique: "ct-log",
          similarity: sim,
          hasA: false, hasMx: false,
          dnsA: [], dnsMx: [],
          crtshNotBefore: notBefore,
          sourceEvidence: { crtsh: { domain, notBefore } },
        });
      }
    }
    function mergeUnique<T>(a: T[], b: T[]): T[] {
      const out = [...a];
      for (const x of b) if (!out.includes(x)) out.push(x);
      return out;
    }
    function validDnsValues(values: string[] | undefined): string[] {
      return (values ?? [])
        .map((v) => String(v).trim())
        .filter((v) => v.length > 0 && !v.startsWith("!") && v !== "~" && v.toLowerCase() !== "localhost");
    }
    function findDnstwistScreenshotFile(domain: string): string | null {
      const legacy = `${domain}.png`;
      if (existsSync(join(DNSTWIST_SCREENSHOTS_DIR, legacy))) return legacy;
      try {
        const matches = readdirSync(DNSTWIST_SCREENSHOTS_DIR)
          .filter((name) => name.endsWith(`_${domain}.png`))
          .sort();
        return matches.length ? matches[matches.length - 1] : null;
      } catch {
        return null;
      }
    }
    /**
     * Resolve A-records for a batch of domains and return the set that
     * actually resolve. Used to filter keyword-expansion variants down to
     * registered domains before we spend WHOIS + HTTP probe budget on them.
     * Concurrency-limited (20) so we don't hammer the local resolver.
     * Each lookup is wrapped in a 3s timeout. Honors the scan-level abort
     * signal so cancel short-circuits the batch.
     */
    async function dnsVerifyDomains(domains: string[], extSignal?: AbortSignal): Promise<Set<string>> {
      const resolved = new Set<string>();
      if (!domains.length) return resolved;
      const queue = domains.slice();
      const concurrency = 20;
      const timeoutMs = 3000;
      const workers: Promise<void>[] = [];
      for (let i = 0; i < Math.min(concurrency, queue.length); i++) {
        workers.push((async () => {
          while (queue.length) {
            if (extSignal?.aborted) return;
            const d = queue.shift();
            if (!d) return;
            try {
              const ips = await Promise.race([
                dnsPromises.resolve4(d),
                new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs)),
              ]);
              if (Array.isArray(ips) && ips.length > 0) resolved.add(d);
            } catch {
              /* ENOTFOUND / ESERVFAIL / timeout — drop silently */
            }
          }
        })());
      }
      await Promise.all(workers);
      return resolved;
    }

    async function probeSiteEvidence(domain: string, externalSignal?: AbortSignal): Promise<Record<string, any>> {
      const started = Date.now();
      if (externalSignal?.aborted) return { status: "unknown", aborted: true, elapsedMs: 0 };
      const urls = [`https://${domain}`, `http://${domain}`];
      for (const url of urls) {
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), 10_000);
        const onExt = () => ac.abort();
        if (externalSignal) externalSignal.addEventListener("abort", onExt, { once: true });
        try {
          const res = await fetch(url, {
            redirect: "follow",
            signal: ac.signal,
            headers: { "User-Agent": "Mozilla/5.0 OptraSight Malicious Site Scanner" },
          });
          const finalUrl = res.url;
          const text = await res.text().catch(() => "");
          const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(text)?.[1]?.replace(/\s+/g, " ").trim() ?? null;
          const lower = text.slice(0, 200_000).toLowerCase();
          const loginFormDetected = /<input[^>]+type=["']?(password|email)["']?/i.test(text)
            || /\b(sign in|log in|login|password|verify account|one-time password|otp)\b/i.test(text);
          const cloudflareBlocked = res.status === 403 && /cloudflare|attention required|cf-ray|checking your browser/i.test(text);
          const parked = /\b(domain is for sale|buy this domain|parking|sedo|afternic|hugedomains|namecheap parking)\b/i.test(text);
          const status = cloudflareBlocked ? "cloudflare_blocked"
            : parked ? "parked"
            : loginFormDetected ? "login_page"
            : finalUrl !== url ? "redirect"
            : res.status >= 200 && res.status < 300 ? "http_200"
            : "unknown";
          clearTimeout(timer);
          if (externalSignal) externalSignal.removeEventListener("abort", onExt);
          return {
            status, statusCode: res.status, finalUrl, title,
            loginFormDetected, cloudflareBlocked, parked,
            elapsedMs: Date.now() - started,
            textSignals: lower.includes("password") ? ["password"] : [],
          };
        } catch (err: any) {
          clearTimeout(timer);
          if (externalSignal) externalSignal.removeEventListener("abort", onExt);
          if (url.startsWith("http://")) {
            return { status: "inaccessible", error: String(err?.message ?? err), elapsedMs: Date.now() - started };
          }
        }
      }
      return { status: "unknown", elapsedMs: Date.now() - started };
    }
    function makeWarning(tool: string, seed: string, reason: any): { tool: string; seed: string; reason: string; installHint?: string } {
      if (reason instanceof ToolUnavailableError) {
        return { tool, seed, reason: reason.message, installHint: reason.installHint };
      }
      return { tool, seed, reason: String(reason?.message ?? reason) };
    }
    async function runWithConcurrency<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
      const queue = items.slice();
      const workers: Promise<void>[] = [];
      for (let i = 0; i < Math.min(limit, queue.length); i++) {
        workers.push((async () => {
          while (queue.length) {
            const item = queue.shift();
            if (!item) break;
            try { await fn(item); } catch { /* per-item errors land in warnings already */ }
          }
        })());
      }
      await Promise.all(workers);
    }
  },

  // Run AI analysis on a single candidate. Updates its finding's extra.ai,
  // severity, status, and screenshot URL (verdict tint).
  runYoungDomainAnalysisOne(tid: string, fid: string): YoungDomainCandidateDTO | null {
    const row = db.select().from(findings)
      .where(and(eq(findings.tenantId, tid), eq(findings.id, fid), eq(findings.type, "young-domain")))
      .get();
    if (!row) return null;
    const provider = storage.resolveAiProvider(tid, "young_domain");
    if (!provider) return null;
    const ex = p<Record<string, any>>(row.extra, {});
    const brandAssets = db.select().from(clientAssets)
      .where(eq(clientAssets.tenantId, tid))
      .all()
      .filter((a) => a.kind === "logo" || a.kind === "trademark" || a.kind === "app_icon")
      .slice(0, 9)
      .map((a) => ({
        kind: a.kind as "logo" | "trademark" | "app_icon",
        name: a.name,
        mime: a.mime,
        sha256: a.sha256,
        dataBase64: a.data,
      }));
    const screenshot = loadScreenshotPayload(ex.screenshotUrl ?? null);
    const candidateUrl = `https://${row.target || ""}`;
    const urlscan = urlScanSearchAndSubmit(tid, candidateUrl);
    const siteEvidence = { ...(ex.siteEvidence || {}), urlscan };
    const r2 = dispatchAi({
      task: "young_domain",
      input: {
        domain: row.target || "", candidateUrl, seed: ex.seed || "", presetName: ex.presetName,
        technique: ex.technique || "", similarity: ex.similarity || 0,
        hasMx: !!ex.hasMx, hasA: !!ex.hasA, ageDays: ex.ageDays || 0,
        discoveredBy: ex.discoveredBy || [],
        whois: ex.whois ?? null,
        dnsA: ex.dnsA || [],
        dnsMx: ex.dnsMx || [],
        siteEvidence,
        screenshot,
        brandAbuse: ex.brandAbuse || null,
        brandAssets,
        providerVisionSupported: providerSupportsVision(provider),
      },
      provider,
    });
    const out = r2.task === "young_domain" ? (r2.output as any) : null;
    if (!out) return null;
    const ai = {
      verdict: out.verdict as string,
      confidence: out.confidence as number,
      reasoning: out.reasoning as string,
      targetBrand: out.targetBrand as string | null,
      visionSupported: !!out.visionSupported,
      brandAssetDetected: !!out.brandAssetDetected,
      matchedAssetKinds: Array.isArray(out.matchedAssetKinds) ? out.matchedAssetKinds : [],
      visualSimilarity: typeof out.visualSimilarity === "number" ? out.visualSimilarity : null,
      loginFormDetected: !!out.loginFormDetected,
      cloudflareBlocked: !!out.cloudflareBlocked,
      keyEvidence: Array.isArray(out.keyEvidence) ? out.keyEvidence : [],
      recommendedActions: Array.isArray(out.recommendedActions) ? out.recommendedActions : [],
      provider: provider.label,
      at: now(),
    };
    // Screenshot URL — preserve what the scanner persisted (real PNG from
    // dnstwist's Playwright render, or null when unavailable). The legacy
    // SVG verdict-tint behaviour is gone; verdict is conveyed by the
    // VerdictBadge overlay on the card instead.
    const screenshotUrl: string | null = ex.screenshotUrl ?? null;
    // Combined risk score: technical + AI verdict
    const sim = ex.similarity || 0;
    const verdictWeight = ai.verdict === "phishing" || ai.verdict === "forged_login" ? 0.5
      : ai.verdict === "brand_impersonation" ? 0.4
      : ai.verdict === "spoofing" ? 0.3
      : ai.verdict === "parked_benign" ? 0.1
      : 0.15;
    const visualBoost = ai.brandAssetDetected ? 0.15 : 0;
    const riskScore = Math.round(Math.min(1, (sim * 0.35) + verdictWeight + visualBoost + (ex.hasMx ? 0.05 : 0) + (ex.hasA ? 0.05 : 0)) * 100);
    const severity = ai.verdict === "phishing" || ai.verdict === "forged_login" ? "critical"
      : ai.verdict === "brand_impersonation" ? "high"
      : ai.verdict === "spoofing" ? "medium"
      : ai.verdict === "parked_benign" ? "low"
      : "info";
    const status = ai.verdict === "phishing" || ai.verdict === "forged_login" || ai.verdict === "brand_impersonation" ? "investigating" : "open";
    db.update(findings).set({
      severity, status,
      title: `${ai.verdict} candidate: ${row.target}`,
      description: ai.reasoning,
      sourceTool: "dnstwist+ai",
      extra: j({ ...ex, screenshotUrl, riskScore, siteEvidence, ai, analyst: ex.analyst ?? null }),
    }).where(eq(findings.id, fid)).run();
    return storage.getYoungDomainCandidate(tid, fid);
  },

  // Run AI analysis across many candidates. Returns count analyzed.
  runYoungDomainAnalysis(tid: string, opts: { source: "tenant" | "global" | "both"; onlyUnanalyzed: boolean; ids?: string[] }): { analyzed: number; total: number; provider: string | null } {
    const provider = storage.resolveAiProvider(tid, "young_domain");
    if (!provider) return { analyzed: 0, total: 0, provider: null };
    const rows = db.select().from(findings)
      .where(and(eq(findings.tenantId, tid), eq(findings.type, "young-domain")))
      .all();
    const explicit = opts.ids && opts.ids.length ? new Set(opts.ids) : null;
    let analyzed = 0;
    let total = 0;
    for (const row of rows) {
      const ex = p<Record<string, any>>(row.extra, {});
      if (explicit && !explicit.has(row.id)) continue;
      if (opts.source !== "both" && ex.source !== opts.source) continue;
      total++;
      if (opts.onlyUnanalyzed && ex.ai) continue;
      storage.runYoungDomainAnalysisOne(tid, row.id);
      analyzed++;
    }
    return { analyzed, total, provider: provider.label };
  },

  // Single candidate fetcher for the details dialog.
  getYoungDomainCandidate(tid: string, fid: string): YoungDomainCandidateDTO | null {
    const row = db.select().from(findings)
      .where(and(eq(findings.tenantId, tid), eq(findings.id, fid), eq(findings.type, "young-domain")))
      .get();
    if (!row) return null;
    return mapYoungDomainRow(row);
  },

  // Analyst marks the assessment.
  setYoungDomainAssessment(tid: string, fid: string, opts: { analystVerdict: string | null; analystNotes?: string | null; analystBy: string }): YoungDomainCandidateDTO | null {
    const row = db.select().from(findings)
      .where(and(eq(findings.tenantId, tid), eq(findings.id, fid), eq(findings.type, "young-domain")))
      .get();
    if (!row) return null;
    const ex = p<Record<string, any>>(row.extra, {});
    const analyst = opts.analystVerdict
      ? {
          verdict: opts.analystVerdict,
          notes: opts.analystNotes ?? null,
          at: now(),
          by: opts.analystBy,
        }
      : null;
    db.update(findings).set({
      // When analyst sets phishing/impersonation, escalate finding status.
      status: analyst?.verdict === "phishing" || analyst?.verdict === "impersonation"
        ? "investigating"
        : analyst?.verdict === "benign" || analyst?.verdict === "parked"
          ? "resolved"
          : row.status,
      extra: j({ ...ex, analyst }),
    }).where(eq(findings.id, fid)).run();
    return storage.getYoungDomainCandidate(tid, fid);
  },
  listYoungDomainCandidates(tid: string, source?: "tenant" | "global"): YoungDomainCandidateDTO[] {
    const rows = db.select().from(findings)
      .where(and(eq(findings.tenantId, tid), eq(findings.type, "young-domain")))
      .orderBy(desc(findings.createdAt))
      .limit(500).all();
    const list: YoungDomainCandidateDTO[] = [];
    for (const f of rows) {
      const ex = p<Record<string, any>>(f.extra, {});
      if (source && ex.source !== source) continue;
      list.push(mapYoungDomainRow(f));
    }
    return list;
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
      lastFetchedAt: s.lastFetchedAt,
      enabled: !!s.enabled,
    }));
  },

  /**
   * v2.29 — KPI strip data for the Sources tab.
   *   - totalSources: every row in osint_sources
   *   - sourcesReturningIntel: distinct source_id with at least one finding in last 30 days
   *   - intelParsedToday: rows whose published_at OR created_at falls inside today (UTC)
   *   - enabledCount / disabledCount: split by osint_sources.enabled
   */
  getOsintSourcesKpis(opts?: { tenantId?: string }): {
    totalSources: number;
    sourcesReturningIntel: number;
    intelParsedToday: number;
    enabledCount: number;
    disabledCount: number;
  } {
    const tenantClause = opts?.tenantId ? " AND tenant_id = ?" : "";
    const tenantParam: any[] = opts?.tenantId ? [opts.tenantId] : [];
    const now30 = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const today = new Date(); today.setUTCHours(0, 0, 0, 0);
    const todayIso = today.toISOString();

    const total = (sqlite.prepare("SELECT COUNT(*) as n FROM osint_sources").get() as any).n as number;
    const enabled = (sqlite.prepare("SELECT COUNT(*) as n FROM osint_sources WHERE enabled = 1").get() as any).n as number;
    const disabled = total - enabled;

    const returning = (sqlite
      .prepare(`SELECT COUNT(DISTINCT source_id) as n FROM osint_findings WHERE (published_at >= ? OR created_at >= ?)${tenantClause}`)
      .get(now30, now30, ...tenantParam) as any).n as number;

    const parsedToday = (sqlite
      .prepare(`SELECT COUNT(*) as n FROM osint_findings WHERE (published_at >= ? OR created_at >= ?)${tenantClause}`)
      .get(todayIso, todayIso, ...tenantParam) as any).n as number;

    return {
      totalSources: total,
      sourcesReturningIntel: returning,
      intelParsedToday: parsedToday,
      enabledCount: enabled,
      disabledCount: disabled,
    };
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
    const sIdx = new Map(topSrcs.map((s, i) => [s, i]));
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
      } catch (e) {
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
    const profile = storage.getClientProfile(tid);
    const techs = (opts.technologies && opts.technologies.length)
      ? opts.technologies
      : profile.monitoredTechnologies;
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
   * Tenants only see what matches their monitored technologies at view time.
   */
  async runGlobalOsintIngest(opts?: {
    days?: number;             // backfill window in days; default 365
    maxPerSource?: number;     // hard cap per single source; default 60
    maxTotal?: number;         // hard cap on total parsed items; default 10000
    actor?: string;
  }): Promise<{ count: number; tenants: number; feedsTried: number; feedsOk: number; errors: string[]; durationMs: number }> {
    const t0 = Date.now();
    const days = opts?.days ?? 365;
    const maxPerSource = opts?.maxPerSource ?? 60;
    const maxTotal = opts?.maxTotal ?? 10000;
    const sinceIso = new Date(Date.now() - days * 86400_000).toISOString();

    const { runBroadIngest } = await import("./osintFetcher");
    const result = await runBroadIngest({ sinceIso, maxPerSource, maxTotal });

    // List all tenants once.
    const tenantRows = sqlite.prepare("SELECT id FROM tenants").all() as Array<{ id: string }>;
    const tenantIds = tenantRows.map((r) => r.id);
    if (tenantIds.length === 0) {
      return { count: 0, tenants: 0, feedsTried: result.feedsTried, feedsOk: result.feedsOk, errors: result.errors, durationMs: Date.now() - t0 };
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

    // v2.8 — dedupe within a tenant by (tenant, content_hash) AND legacy (tenant, source, url).
    // content_hash collapses cross-source reposts so a tenant doesn't get N copies of the
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
    // v2.8 — per-tenant content-hash set for cross-source dedupe at write time.
    const existingHashSet = new Set<string>(
      (sqlite.prepare("SELECT tenant_id || '::' || COALESCE(content_hash, '') AS k FROM osint_findings WHERE content_hash IS NOT NULL AND content_hash != ''").all() as Array<{ k: string }>).map((r) => r.k.toLowerCase())
    );

    const tx = sqlite.transaction(() => {
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
        const cveIds = it.cveIds.slice(0, 8);
        const iocsJson = j((it as any).iocs || {});
        const contentHash = (it as any).contentHash || "";
        for (const tid of tenantIds) {
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
    });
    tx();

    storage.appendAudit(tenantIds[0], opts?.actor ?? "system", "osint.global_ingest", null, {
      inserted, tenants: tenantIds.length, parsed: result.items.length,
      feedsTried: result.feedsTried, feedsOk: result.feedsOk, days,
    });

    return {
      count: inserted,
      tenants: tenantIds.length,
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
    const profile = storage.getClientProfile(tid);

    // v2.13: pre-fetch the source articles in parallel so the AI can read the
    // full intel, not just the feed teaser. Failures degrade gracefully — the
    // analyser still gets the title/summary/CVEs even if the URL is unreachable.
    const fetched = await fetchSourcesBatch(target.map((f) => f.url));
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
            clientProfile: { industries: profile.industries, geos: profile.geos, monitoredTechnologies: profile.monitoredTechnologies },
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

  generateOsintEmail(tid: string, ids: string[]): { drafts: Array<{ id: string; subject: string; body: string }>; provider: string | null } {
    const provider = storage.resolveAiProvider(tid, "email_draft");
    if (!provider) return { drafts: [], provider: null };
    const profile = storage.getClientProfile(tid);
    const tenant = storage.getTenant(tid);
    const drafts: Array<{ id: string; subject: string; body: string }> = [];
    for (const fid of ids) {
      const f = storage.getOsintFinding(tid, fid);
      if (!f) continue;
      const r = dispatchAi({
        task: "email_draft",
        input: {
          finding: f,
          clientName: tenant?.name ?? "Client",
          industries: profile.industries,
          geos: profile.geos,
          recipientEmails: profile.notificationEmails,
        },
        provider,
      });
      if (r.task !== "email_draft") continue;
      sqlite.prepare(`UPDATE osint_findings SET draft_email = ?, draft_email_at = ? WHERE id = ? AND tenant_id = ?`).run(
        JSON.stringify({ subject: r.output.subject, body: r.output.body }), now(), fid, tid
      );
      drafts.push({ id: fid, subject: r.output.subject, body: r.output.body });
    }
    storage.appendAudit(tid, "system", "osint.email_draft", null, { count: drafts.length, provider: provider.label });
    return { drafts, provider: provider.label };
  },

  // ---------- Hunt query generator ----------
  async generateHuntQueries(tid: string, opts: { findingIds: string[]; languages: string[]; title?: string; createdBy: string }): Promise<HuntQueryDTO> {
    const provider = storage.resolveAiProvider(tid, "hunt_query");
    const findings = opts.findingIds.map((id) => storage.getOsintFinding(tid, id)).filter(Boolean) as OsintFindingDTO[];
    const affectedTech = Array.from(new Set(findings.flatMap((f) => f.affectedTech)));
    const cveIds = Array.from(new Set(findings.flatMap((f) => f.cveIds)));

    // v2.13: pre-fetch each source URL so the AI reads the full article body
    // before drafting hunting queries. Failures degrade to summary-only input.
    const fetched = await fetchSourcesBatch(findings.map((f) => f.url));
    const contentByIdx = new Map<number, string | null>();
    fetched.forEach((r, i) => contentByIdx.set(i, r.content));

    // Use the AI dispatcher whenever a provider is configured; otherwise fall back to a
    // synthetic provider so we still exercise the rich context-aware generator.
    // The new huntQueryMock weaves real signals (titles, summaries, raw snippets, IoCs,
    // behavioural patterns, threat actors) into language-specific templates.
    const huntProvider = provider ?? ({
      id: "local-fallback", label: "OptraSight local generator",
      provider: "ollama" as AiProviderKind, model: "local", apiKeyEnc: null,
    } as unknown as AiProvider);
    const aiResult = dispatchAi({
      task: "hunt_query",
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
          sourceContent: contentByIdx.get(idx) ?? null,
        })),
        languages: opts.languages,
      },
      provider: huntProvider,
    });
    let queries: Record<string, string | string[]> = {};
    if (aiResult.task === "hunt_query") queries = aiResult.output as Record<string, string | string[]>;
    // Backfill any requested language not produced by AI (defensive — the new generator covers all 9 langs)
    for (const lang of opts.languages) {
      if (!queries[lang]) queries[lang] = mockHuntQueryFor(lang, affectedTech, cveIds);
    }
    const hid = id();
    const title = opts.title ?? `Hunt — ${affectedTech.slice(0, 2).join(", ") || "OSINT findings"} (${findings.length} signal${findings.length === 1 ? "" : "s"})`;
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
      const fetched = await fetchSourcesBatch(findings.map((f) => f.url));
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
      const integrationId = target.integrationId;
      const intg = integrationId ? storage.getIntegration(tid, integrationId) : undefined;
      if (!intg) {
        finalStatus = "failed";
        finalMessage = `${target.label} integration not connected — enable & test it in Integrations first`;
      } else if (!intg.enabled) {
        finalStatus = "failed";
        finalMessage = `${target.label} integration is disabled`;
      } else if (intg.lastTestOk === false) {
        finalStatus = "failed";
        finalMessage = `${target.label} last connectivity test failed — fix credentials and retry`;
      } else {
        finalStatus = "failed";
        finalExternalId = null;
        finalMessage = `${target.label} push connector is not implemented yet. Use manual deployment after deploying the query in your SIEM.`;
      }
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
  listAvailableTenantsForTagging(tid: string): Array<{ id: string; name: string; sector: string | null; region: string | null; orgSize: string | null }> {
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
      if (provider && (!provider.enabled || !provider.apiKeyEnc || provider.lastTestOk !== 1)) provider = undefined;
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
    const profile = storage.getClientProfile(tid);
    const tenant = storage.getTenant(tid);
    const provider = storage.resolveAiProvider(tid, "threat_landscape");
    const recent = storage.listOsintFindings(tid).slice(0, 30);
    const tlid = id();
    const prevVersions = sqlite.prepare("SELECT MAX(version) as v FROM threat_landscapes WHERE tenant_id = ?").get(tid) as any;
    const version = (prevVersions?.v ?? 0) + 1;
    const title = opts.title ?? `Threat landscape — ${tenant?.name ?? "client"} v${version}`;
    let bodyMd: string;
    let stats: Record<string, any>;
    if (provider) {
      const r = dispatchAi({
        task: "threat_landscape",
        input: {
          clientName: tenant?.name ?? "Client",
          profile: {
            clientTypes: profile.clientTypes, industries: profile.industries,
            geos: profile.geos, monitoredTechnologies: profile.monitoredTechnologies,
          },
          recentSignals: recent.slice(0, 15).map((f) => ({
            title: f.title, severity: f.severity, affectedTech: f.affectedTech, threatActors: f.threatActors,
          })),
        },
        provider,
      });
      if (r.task === "threat_landscape") {
        bodyMd = r.output.bodyMd && r.output.bodyMd.length > 0
          ? r.output.bodyMd
          : mockThreatLandscape(tenant?.name ?? "Client", profile, recent);
        stats = r.output.stats;
      } else {
        bodyMd = mockThreatLandscape(tenant?.name ?? "Client", profile, recent);
        stats = { topActors: [], topSectors: profile.industries, geosCovered: profile.geos };
      }
    } else {
      bodyMd = mockThreatLandscape(tenant?.name ?? "Client", profile, recent);
      stats = { topActors: [], topSectors: profile.industries, geosCovered: profile.geos };
    }
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

  // ---------- Investigation Workspace ----------
  listInvestigations(tid: string, opts?: { status?: string; q?: string }): InvestigationDTO[] {
    const params: any[] = [tid];
    let where = "i.tenant_id = ?";
    if (opts?.status && opts.status !== "all") {
      where += " AND i.status = ?";
      params.push(opts.status);
    }
    if (opts?.q?.trim()) {
      where += " AND (i.title LIKE ? OR COALESCE(i.summary, '') LIKE ? OR COALESCE(i.assignee, '') LIKE ?)";
      const likeQ = `%${opts.q.trim()}%`;
      params.push(likeQ, likeQ, likeQ);
    }
    const rows = sqlite.prepare(`
      SELECT i.*,
             (SELECT COUNT(*) FROM investigation_links l WHERE l.tenant_id = i.tenant_id AND l.investigation_id = i.id) AS link_count,
             (SELECT COUNT(*) FROM investigation_notes n WHERE n.tenant_id = i.tenant_id AND n.investigation_id = i.id) AS note_count
        FROM investigations i
       WHERE ${where}
       ORDER BY i.updated_at DESC
       LIMIT 300
    `).all(...params) as any[];
    return rows.map((r) => ({
      id: r.id, tenantId: r.tenant_id, title: r.title, status: r.status,
      severity: r.severity, summary: r.summary ?? null, assignee: r.assignee ?? null,
      sourceType: r.source_type ?? null, sourceId: r.source_id ?? null,
      createdAt: r.created_at, updatedAt: r.updated_at, createdBy: r.created_by,
      linkCount: Number(r.link_count ?? 0), noteCount: Number(r.note_count ?? 0),
    }));
  },

  createInvestigation(tid: string, input: {
    title: string; severity?: string; summary?: string | null; assignee?: string | null;
    sourceType?: InvestigationEntityType | null; sourceId?: string | null; createdBy: string;
  }): InvestigationDTO {
    const iid = id();
    const ts = now();
    sqlite.prepare(`
      INSERT INTO investigations (
        id, tenant_id, title, status, severity, summary, assignee,
        source_type, source_id, created_at, updated_at, created_by
      ) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      iid, tid, input.title, input.severity ?? "medium", input.summary ?? null,
      input.assignee ?? null, input.sourceType ?? null, input.sourceId ?? null,
      ts, ts, input.createdBy,
    );
    if (input.sourceType && input.sourceId) {
      storage.addInvestigationLink(tid, iid, {
        entityType: input.sourceType,
        entityId: input.sourceId,
        label: input.title,
        createdBy: input.createdBy,
      });
    }
    storage.appendAudit(tid, input.createdBy, "investigation.create", iid, {
      severity: input.severity ?? "medium",
      sourceType: input.sourceType ?? null,
      sourceId: input.sourceId ?? null,
    });
    return storage.getInvestigationFull(tid, iid)!;
  },

  patchInvestigation(tid: string, iid: string, patch: {
    title?: string; status?: string; severity?: string; summary?: string | null; assignee?: string | null; actor: string;
  }): InvestigationDTO | null {
    const current = sqlite.prepare("SELECT id FROM investigations WHERE tenant_id = ? AND id = ?").get(tid, iid) as any;
    if (!current) return null;
    const sets: string[] = [];
    const params: any[] = [];
    for (const [key, col] of Object.entries({
      title: "title", status: "status", severity: "severity", summary: "summary", assignee: "assignee",
    })) {
      if ((patch as any)[key] !== undefined) {
        sets.push(`${col} = ?`);
        params.push((patch as any)[key]);
      }
    }
    if (sets.length) {
      sets.push("updated_at = ?");
      params.push(now(), tid, iid);
      sqlite.prepare(`UPDATE investigations SET ${sets.join(", ")} WHERE tenant_id = ? AND id = ?`).run(...params);
      storage.appendAudit(tid, patch.actor, "investigation.update", iid, { fields: Object.keys(patch).filter((k) => k !== "actor") });
    }
    return storage.getInvestigationFull(tid, iid);
  },

  getInvestigationFull(tid: string, iid: string): InvestigationFullDTO | null {
    const r = sqlite.prepare(`
      SELECT i.*,
             (SELECT COUNT(*) FROM investigation_links l WHERE l.tenant_id = i.tenant_id AND l.investigation_id = i.id) AS link_count,
             (SELECT COUNT(*) FROM investigation_notes n WHERE n.tenant_id = i.tenant_id AND n.investigation_id = i.id) AS note_count
        FROM investigations i
       WHERE i.tenant_id = ? AND i.id = ?
    `).get(tid, iid) as any;
    if (!r) return null;
    const links = sqlite.prepare("SELECT * FROM investigation_links WHERE tenant_id = ? AND investigation_id = ? ORDER BY created_at DESC")
      .all(tid, iid).map((l: any) => ({
        id: l.id, tenantId: l.tenant_id, investigationId: l.investigation_id,
        entityType: l.entity_type, entityId: l.entity_id, label: l.label ?? null,
        createdAt: l.created_at, createdBy: l.created_by,
      })) as InvestigationLinkDTO[];
    const notes = sqlite.prepare("SELECT * FROM investigation_notes WHERE tenant_id = ? AND investigation_id = ? ORDER BY created_at DESC")
      .all(tid, iid).map((n: any) => ({
        id: n.id, tenantId: n.tenant_id, investigationId: n.investigation_id,
        kind: n.kind, body: n.body, createdAt: n.created_at, createdBy: n.created_by,
      })) as InvestigationNoteDTO[];

    const iocs: FindingIoCs = {};
    const relatedActors = new Map<string, { id: string; name: string; profileId?: string }>();
    const recommendedDetections = new Map<string, { id: string; title: string; status: string; severity: string }>();
    const techniqueIds = new Set<string>();
    const timeline: Array<{ id: string; type: string; title: string; at: string; detail?: string | null }> = [
      { id: r.id, type: "investigation", title: `Opened: ${r.title}`, at: r.created_at, detail: r.summary ?? null },
      ...notes.map((n) => ({ id: n.id, type: `note.${n.kind}`, title: n.body.slice(0, 90), at: n.createdAt, detail: n.createdBy })),
    ];
    const mergeIocs = (raw: any) => {
      const obj = typeof raw === "string" ? p<FindingIoCs>(raw, {}) : (raw || {});
      for (const [k, vals] of Object.entries(obj)) {
        if (!Array.isArray(vals)) continue;
        const cur = new Set((iocs as any)[k] || []);
        vals.forEach((v) => { if (typeof v === "string" && v.trim()) cur.add(v.trim()); });
        if (cur.size) (iocs as any)[k] = Array.from(cur).slice(0, 50);
      }
    };
    for (const l of links) {
      if (l.entityType === "osint_finding") {
        const f = sqlite.prepare("SELECT * FROM osint_findings WHERE tenant_id = ? AND id = ?").get(tid, l.entityId) as any;
        if (f) {
          mergeIocs(f.iocs);
          timeline.push({ id: f.id, type: "osint_finding", title: f.title, at: f.published_at, detail: f.summary });
          for (const t of parseAttackTechniques(f.attack_techniques) || []) {
            if (t.id) techniqueIds.add(t.id.toUpperCase());
          }
          for (const a of p<string[]>(f.threat_actors, [])) {
            const actor = sqlite.prepare("SELECT id, profile_id, primary_name FROM threat_actors WHERE tenant_id = ? AND lower(primary_name) = lower(?) LIMIT 1").get(tid, a) as any;
            if (actor) relatedActors.set(actor.id, { id: actor.id, name: actor.primary_name, profileId: actor.profile_id });
          }
          for (const rule of sqlite.prepare("SELECT id, title, status, severity FROM detection_rules WHERE tenant_id = ? AND source_finding_ids LIKE ? LIMIT 20")
            .all(tid, `%${f.id}%`) as any[]) {
            recommendedDetections.set(rule.id, { id: rule.id, title: rule.title, status: rule.status, severity: rule.severity });
          }
        }
      } else if (l.entityType === "finding" || l.entityType === "domain_candidate") {
        const f = sqlite.prepare("SELECT * FROM findings WHERE tenant_id = ? AND id = ?").get(tid, l.entityId) as any;
        if (f) timeline.push({ id: f.id, type: l.entityType, title: f.title, at: f.created_at, detail: f.description });
      } else if (l.entityType === "threat_actor") {
        const a = sqlite.prepare("SELECT id, profile_id, primary_name FROM threat_actors WHERE tenant_id = ? AND id = ?").get(tid, l.entityId) as any;
        if (a) {
          relatedActors.set(a.id, { id: a.id, name: a.primary_name, profileId: a.profile_id });
          const ttps = sqlite.prepare("SELECT technique_id, sub_technique_id FROM threat_actor_ttps WHERE tenant_id = ? AND actor_id = ?").all(tid, a.id) as any[];
          for (const t of ttps) {
            if (t.sub_technique_id) techniqueIds.add(String(t.sub_technique_id).toUpperCase());
            if (t.technique_id) techniqueIds.add(String(t.technique_id).toUpperCase());
          }
        }
      } else if (l.entityType === "detection_rule") {
        const rule = sqlite.prepare("SELECT id, title, status, severity FROM detection_rules WHERE tenant_id = ? AND id = ?").get(tid, l.entityId) as any;
        if (rule) recommendedDetections.set(rule.id, { id: rule.id, title: rule.title, status: rule.status, severity: rule.severity });
      }
    }
    for (const tidTech of techniqueIds) {
      for (const rule of sqlite.prepare("SELECT id, title, status, severity FROM detection_rules WHERE tenant_id = ? AND upper(mitre_techniques) LIKE ? LIMIT 20")
        .all(tid, `%${tidTech}%`) as any[]) {
        recommendedDetections.set(rule.id, { id: rule.id, title: rule.title, status: rule.status, severity: rule.severity });
      }
    }
    timeline.sort((a, b) => b.at.localeCompare(a.at));
    return {
      id: r.id, tenantId: r.tenant_id, title: r.title, status: r.status,
      severity: r.severity, summary: r.summary ?? null, assignee: r.assignee ?? null,
      sourceType: r.source_type ?? null, sourceId: r.source_id ?? null,
      createdAt: r.created_at, updatedAt: r.updated_at, createdBy: r.created_by,
      linkCount: Number(r.link_count ?? links.length), noteCount: Number(r.note_count ?? notes.length),
      links, notes, timeline, iocs,
      relatedActors: Array.from(relatedActors.values()),
      recommendedDetections: Array.from(recommendedDetections.values()),
    };
  },

  addInvestigationLink(tid: string, iid: string, input: {
    entityType: InvestigationEntityType; entityId: string; label?: string | null; createdBy: string;
  }): InvestigationLinkDTO | null {
    const inv = sqlite.prepare("SELECT id FROM investigations WHERE tenant_id = ? AND id = ?").get(tid, iid) as any;
    if (!inv) return null;
    const lid = id();
    const ts = now();
    sqlite.prepare(`
      INSERT OR IGNORE INTO investigation_links
        (id, tenant_id, investigation_id, entity_type, entity_id, label, created_at, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(lid, tid, iid, input.entityType, input.entityId, input.label ?? null, ts, input.createdBy);
    sqlite.prepare("UPDATE investigations SET updated_at = ? WHERE tenant_id = ? AND id = ?").run(ts, tid, iid);
    storage.appendAudit(tid, input.createdBy, "investigation.link.add", iid, { entityType: input.entityType, entityId: input.entityId });
    const row = sqlite.prepare("SELECT * FROM investigation_links WHERE tenant_id = ? AND investigation_id = ? AND entity_type = ? AND entity_id = ?")
      .get(tid, iid, input.entityType, input.entityId) as any;
    return row ? {
      id: row.id, tenantId: row.tenant_id, investigationId: row.investigation_id,
      entityType: row.entity_type, entityId: row.entity_id, label: row.label ?? null,
      createdAt: row.created_at, createdBy: row.created_by,
    } : null;
  },

  deleteInvestigationLink(tid: string, iid: string, linkId: string, actor: string): boolean {
    const res = sqlite.prepare("DELETE FROM investigation_links WHERE tenant_id = ? AND investigation_id = ? AND id = ?").run(tid, iid, linkId);
    if (res.changes > 0) {
      sqlite.prepare("UPDATE investigations SET updated_at = ? WHERE tenant_id = ? AND id = ?").run(now(), tid, iid);
      storage.appendAudit(tid, actor, "investigation.link.delete", iid, { linkId });
    }
    return res.changes > 0;
  },

  addInvestigationNote(tid: string, iid: string, input: { kind?: "analyst" | "ai" | "system"; body: string; createdBy: string }): InvestigationNoteDTO | null {
    const inv = sqlite.prepare("SELECT id FROM investigations WHERE tenant_id = ? AND id = ?").get(tid, iid) as any;
    if (!inv) return null;
    const nid = id();
    const ts = now();
    sqlite.prepare(`
      INSERT INTO investigation_notes (id, tenant_id, investigation_id, kind, body, created_at, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(nid, tid, iid, input.kind ?? "analyst", input.body, ts, input.createdBy);
    sqlite.prepare("UPDATE investigations SET updated_at = ? WHERE tenant_id = ? AND id = ?").run(ts, tid, iid);
    storage.appendAudit(tid, input.createdBy, "investigation.note.add", iid, { kind: input.kind ?? "analyst" });
    return {
      id: nid, tenantId: tid, investigationId: iid, kind: input.kind ?? "analyst",
      body: input.body, createdAt: ts, createdBy: input.createdBy,
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
    for (const r of sqlite.prepare(`SELECT id, tenant_id, title, severity, status, target, source_tool FROM findings WHERE ${tenantClause} AND (title LIKE ? OR COALESCE(target,'') LIKE ?) ORDER BY created_at DESC LIMIT 8`).all(...baseParams, likeQ, likeQ) as any[]) {
      push({ id: r.id, type: "Exposure finding", title: r.title, subtitle: `${r.source_tool || "signal"}${r.target ? ` · ${r.target}` : ""}`, href: `#/findings?finding=${r.id}`, severity: r.severity, status: r.status, tenantName: tenantsById.get(r.tenant_id) ?? null, action: "investigate" });
    }
    for (const r of sqlite.prepare(`SELECT id, tenant_id, title, severity, status, source_id, cve_ids, threat_actors FROM osint_findings WHERE ${tenantClause} AND (title LIKE ? OR COALESCE(summary,'') LIKE ? OR cve_ids LIKE ? OR threat_actors LIKE ?) ORDER BY published_at DESC LIMIT 10`).all(...baseParams, likeQ, likeQ, likeQ, likeQ) as any[]) {
      push({ id: r.id, type: "Intel finding", title: r.title, subtitle: `${p<string[]>(r.cve_ids, []).slice(0, 2).join(", ") || r.source_id}`, href: `#/osint?finding=${r.id}`, severity: r.severity, status: r.status, tenantName: tenantsById.get(r.tenant_id) ?? null, action: "generate_detection" });
    }
    for (const r of sqlite.prepare(`SELECT id, tenant_id, profile_id, primary_name, threat_level, status FROM threat_actors WHERE ${tenantClause} AND (primary_name LIKE ? OR aliases LIKE ? OR COALESCE(mitre_group_id,'') LIKE ?) ORDER BY updated_at DESC LIMIT 8`).all(...baseParams, likeQ, likeQ, likeQ) as any[]) {
      push({ id: r.id, type: "Threat actor", title: r.primary_name, subtitle: `${r.profile_id} · ${r.threat_level}`, href: `#/threat-actors?actor=${r.id}`, severity: r.threat_level, status: r.status, tenantName: tenantsById.get(r.tenant_id) ?? null, action: "open" });
    }
    for (const r of sqlite.prepare(`SELECT id, tenant_id, title, target, severity, status FROM findings WHERE ${tenantClause} AND type = 'young-domain' AND (title LIKE ? OR COALESCE(target,'') LIKE ?) ORDER BY created_at DESC LIMIT 8`).all(...baseParams, likeQ, likeQ) as any[]) {
      push({ id: r.id, type: "Domain candidate", title: r.target || r.title, subtitle: r.title, href: `#/malicious-site-scanner?candidate=${r.id}`, severity: r.severity, status: r.status, tenantName: tenantsById.get(r.tenant_id) ?? null, action: "copy", copyValue: r.target });
    }
    for (const r of sqlite.prepare(`SELECT id, tenant_id, title, severity, status FROM detection_rules WHERE ${tenantClause} AND (title LIKE ? OR COALESCE(description,'') LIKE ? OR mitre_techniques LIKE ?) ORDER BY updated_at DESC LIMIT 8`).all(...baseParams, likeQ, likeQ, likeQ) as any[]) {
      push({ id: r.id, type: "Detection rule", title: r.title, subtitle: r.status, href: `#/detection-rules?rule=${r.id}`, severity: r.severity, status: r.status, tenantName: tenantsById.get(r.tenant_id) ?? null, action: "open" });
    }
    for (const r of sqlite.prepare(`SELECT id, tenant_id, code, title, severity, status FROM exercises WHERE ${tenantClause} AND (title LIKE ? OR code LIKE ?) ORDER BY updated_at DESC LIMIT 6`).all(...baseParams, likeQ, likeQ) as any[]) {
      push({ id: r.id, type: "Tabletop exercise", title: r.title, subtitle: r.code, href: `#/exercises?exercise=${r.id}`, severity: r.severity, status: r.status, tenantName: tenantsById.get(r.tenant_id) ?? null, action: "open" });
    }
    for (const r of sqlite.prepare(`SELECT id, author_tenant_id, title, kind, status FROM reports WHERE ${global ? "1=1" : "author_tenant_id = ?"} AND title LIKE ? ORDER BY created_at DESC LIMIT 5`).all(...baseParams, likeQ) as any[]) {
      push({ id: r.id, type: "Report", title: r.title, subtitle: r.kind, href: `#/reports?report=${r.id}`, status: r.status, tenantName: tenantsById.get(r.author_tenant_id) ?? null, action: "open" });
    }
    return { results: out };
  },

  getAttackCoverage(tid: string, opts?: { global?: boolean; role?: string }): AttackCoverageDTO {
    const global = !!opts?.global && opts.role === "admin";
    const tenantClause = global ? "1=1" : "tenant_id = ?";
    const baseParams = global ? [] : [tid];
    const tenantsById = new Map((sqlite.prepare("SELECT id, name FROM tenants").all() as any[]).map((t) => [t.id, t.name]));
    const map = new Map<string, AttackCoverageTechniqueDTO>();
    const ensure = (tech: { id: string; name?: string; tactic?: string }): AttackCoverageTechniqueDTO => {
      const key = tech.id.toUpperCase();
      const cur = map.get(key);
      if (cur) return cur;
      const item: AttackCoverageTechniqueDTO = {
        id: key, name: tech.name || key, tactic: tech.tactic || "Unmapped",
        state: "observed_no_rule", observedCount: 0, actorCount: 0, ruleCount: 0, deployedCount: 0,
        tenants: [], links: [],
      };
      map.set(key, item);
      return item;
    };
    const addTenant = (item: AttackCoverageTechniqueDTO, tenantId: string) => {
      const name = tenantsById.get(tenantId);
      if (name && !item.tenants.includes(name)) item.tenants.push(name);
    };
    for (const f of sqlite.prepare(`SELECT id, tenant_id, title, attack_techniques FROM osint_findings WHERE ${tenantClause} AND attack_techniques IS NOT NULL`).all(...baseParams) as any[]) {
      for (const t of parseAttackTechniques(f.attack_techniques) || []) {
        const item = ensure(t);
        item.observedCount += 1;
        addTenant(item, f.tenant_id);
        item.links.push({ type: "osint_finding", id: f.id, label: f.title, href: `#/osint?finding=${f.id}`, tenantName: tenantsById.get(f.tenant_id) ?? null });
      }
    }
    for (const a of sqlite.prepare(`SELECT ta.id, ta.tenant_id, ta.primary_name, tt.technique_id, tt.technique_name, tt.tactic FROM threat_actor_ttps tt JOIN threat_actors ta ON ta.id = tt.actor_id WHERE tt.${global ? "tenant_id IS NOT NULL" : "tenant_id = ?"}`).all(...baseParams) as any[]) {
      const item = ensure({ id: a.technique_id, name: a.technique_name, tactic: a.tactic });
      item.actorCount += 1;
      addTenant(item, a.tenant_id);
      item.links.push({ type: "threat_actor", id: a.id, label: a.primary_name, href: `#/threat-actors?actor=${a.id}`, tenantName: tenantsById.get(a.tenant_id) ?? null });
    }
    for (const r of sqlite.prepare(`SELECT id, tenant_id, title, status, mitre_techniques FROM detection_rules WHERE ${tenantClause} AND mitre_techniques != '[]'`).all(...baseParams) as any[]) {
      for (const t of parseAttackTechniques(r.mitre_techniques) || []) {
        const item = ensure(t);
        item.ruleCount += 1;
        addTenant(item, r.tenant_id);
        item.links.push({ type: "detection_rule", id: r.id, label: r.title, href: `#/detection-rules?rule=${r.id}`, tenantName: tenantsById.get(r.tenant_id) ?? null });
      }
    }
    for (const d of sqlite.prepare(`SELECT rd.rule_id, rd.tenant_id, rd.status, dr.title, dr.mitre_techniques FROM rule_deployments rd JOIN detection_rules dr ON dr.id = rd.rule_id WHERE rd.${global ? "tenant_id IS NOT NULL" : "tenant_id = ?"} AND rd.status = 'deployed'`).all(...baseParams) as any[]) {
      for (const t of parseAttackTechniques(d.mitre_techniques) || []) {
        const item = ensure(t);
        item.deployedCount += 1;
        addTenant(item, d.tenant_id);
      }
    }
    for (const item of map.values()) {
      item.state = item.deployedCount > 0
        ? "deployed"
        : item.ruleCount > 0
          ? (item.links.some((l) => l.type === "detection_rule" && /reviewed|approved/i.test(l.label)) ? "rule_reviewed" : "rule_draft")
          : "observed_no_rule";
    }
    const techniques = Array.from(map.values()).sort((a, b) =>
      b.deployedCount - a.deployedCount || b.ruleCount - a.ruleCount || b.observedCount - a.observedCount || a.id.localeCompare(b.id),
    );
    return { generatedAt: now(), scope: global ? "global" : "tenant", techniques };
  },

  exportStixBundle(tid: string, opts: { investigationId?: string; actorId?: string; findingIds?: string[]; since?: string; role?: string; actorEmail?: string }): any {
    const objects: any[] = [];
    const nowIso = now();
    const bundleId = `bundle--${id()}`;
    const indicatorIds = new Map<string, string>();
    const addIndicator = (type: string, value: string, name?: string) => {
      const key = `${type}:${value}`;
      if (indicatorIds.has(key)) return indicatorIds.get(key)!;
      const sid = `indicator--${id()}`;
      indicatorIds.set(key, sid);
      const patternType = type === "domain" ? "domain-name:value" :
        type === "url" ? "url:value" :
        type === "ipv4" ? "ipv4-addr:value" :
        type === "ipv6" ? "ipv6-addr:value" :
        type === "sha256" ? "file:hashes.'SHA-256'" :
        type === "sha1" ? "file:hashes.'SHA-1'" :
        type === "md5" ? "file:hashes.MD5" :
        type === "email" ? "email-addr:value" : "x-observable:value";
      objects.push({
        type: "indicator",
        spec_version: "2.1",
        id: sid,
        created: nowIso,
        modified: nowIso,
        name: name || `${type}: ${value}`,
        pattern_type: "stix",
        pattern: `[${patternType} = '${String(value).replace(/'/g, "\\'")}']`,
        valid_from: nowIso,
      });
      return sid;
    };
    const findingIds = new Set(opts.findingIds || []);
    if (opts.investigationId) {
      const inv = storage.getInvestigationFull(tid, opts.investigationId);
      if (inv) {
        objects.push({
          type: "report", spec_version: "2.1", id: `report--${id()}`,
          created: inv.createdAt, modified: inv.updatedAt, name: inv.title,
          description: inv.summary || "OptraSight investigation export.",
          published: inv.updatedAt, report_types: ["threat-report"],
          object_refs: [],
        });
        inv.links.filter((l) => l.entityType === "osint_finding").forEach((l) => findingIds.add(l.entityId));
      }
    }
    if (opts.actorId) {
      const actor = sqlite.prepare("SELECT * FROM threat_actors WHERE tenant_id = ? AND id = ?").get(tid, opts.actorId) as any;
      if (actor) {
        const actorStixId = `threat-actor--${id()}`;
        objects.push({
          type: "threat-actor", spec_version: "2.1", id: actorStixId,
          created: actor.created_at, modified: actor.updated_at,
          name: actor.primary_name, aliases: p<string[]>(actor.aliases, []),
          description: actor.exec_what || actor.body_md || undefined,
          threat_actor_types: [String(actor.actor_type || "unknown").toLowerCase().replace(/\s+/g, "-")],
        });
        const iocRows = sqlite.prepare("SELECT ioc_type, value, created_at, source FROM threat_actor_iocs WHERE tenant_id = ? AND actor_id = ? LIMIT 200").all(tid, opts.actorId) as any[];
        for (const io of iocRows) addIndicator(io.ioc_type, io.value, `${actor.primary_name} ${io.ioc_type}`);
      }
    }
    let osintRows: any[] = [];
    if (findingIds.size > 0) {
      const ids = Array.from(findingIds);
      const marks = ids.map(() => "?").join(",");
      osintRows = sqlite.prepare(`SELECT * FROM osint_findings WHERE tenant_id = ? AND id IN (${marks})`).all(tid, ...ids) as any[];
    } else {
      const since = opts.since || new Date(Date.now() - 30 * 86400_000).toISOString();
      osintRows = sqlite.prepare("SELECT * FROM osint_findings WHERE tenant_id = ? AND published_at >= ? ORDER BY published_at DESC LIMIT 100").all(tid, since) as any[];
    }
    for (const f of osintRows) {
      const refs: string[] = [];
      const io = p<FindingIoCs>(f.iocs, {});
      for (const [type, values] of Object.entries(io)) {
        if (Array.isArray(values)) for (const v of values.slice(0, 30)) refs.push(addIndicator(type, String(v), f.title));
      }
      for (const t of parseAttackTechniques(f.attack_techniques) || []) {
        const attackId = `attack-pattern--${id()}`;
        refs.push(attackId);
        objects.push({
          type: "attack-pattern", spec_version: "2.1", id: attackId,
          created: nowIso, modified: nowIso, name: t.name || t.id,
          external_references: [{ source_name: "mitre-attack", external_id: t.id }],
        });
      }
      objects.push({
        type: "report", spec_version: "2.1", id: `report--${id()}`,
        created: f.created_at, modified: f.ai_analyzed_at || f.created_at,
        name: f.title, description: f.ai_summary || f.summary || f.raw_snippet || undefined,
        published: f.published_at, report_types: ["threat-report"],
        external_references: f.url ? [{ source_name: f.source_id, url: f.url }] : [],
        object_refs: refs.filter(Boolean),
      });
    }
    return { type: "bundle", id: bundleId, objects };
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
    const aiRows = sqlite.prepare(
      `SELECT id, tenant_id, kind, status, progress_pct, provider_label, created_by, created_at,
              started_at, completed_at, target_label, target_url, heartbeat_at, error_json, result_json
         FROM ai_jobs
        WHERE tenant_id = ?
        ORDER BY CASE WHEN status IN ('queued','running') THEN 0 ELSE 1 END, COALESCE(started_at, created_at) DESC
        LIMIT ?`,
    ).all(tid, max) as any[];
    const scanRows = sqlite.prepare(
      `SELECT id, tenant_id, kind, tool, status, target, finding_count, created_at, started_at, finished_at, log
         FROM scans
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
          progressPct: r.progress_pct || 0,
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
      ...scanRows.map((r) => {
        const log = String(r.log || "");
        const failedLine = log.split(/\n/).reverse().find((line) => /fail|error|crash|abort/i.test(line));
        return {
          source: "scan",
          id: r.id,
          tenantId: r.tenant_id,
          kind: r.kind,
          label: r.target || r.kind,
          status: r.status,
          progressPct: r.status === "succeeded" ? 100 : activeStatuses.has(r.status) ? 50 : 0,
          providerLabel: r.tool,
          actor: null,
          createdAt: r.created_at,
          startedAt: r.started_at || null,
          finishedAt: r.finished_at || null,
          heartbeatAt: null,
          target: r.target || null,
          targetUrl: "#/malicious-site-scanner",
          findingCount: r.finding_count || 0,
          errorMessage: r.status === "failed" ? (failedLine || "Scan failed.") : null,
          logTail: log.split(/\n/).slice(-8).join("\n"),
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
          targetUrl: "#/sources-analytics",
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
    if (source === "scan") return storage.cancelScan(tid, jobId);
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

  // metrics for dashboard
  metrics(tid: string) {
    const allFindings = storage.listFindings(tid);
    const allAssets = storage.listAssets(tid);
    const allScans = storage.listScans(tid);
    const bySeverity = (sev: string) => allFindings.filter((f) => f.severity === sev).length;
    const byType = (t: string) => allFindings.filter((f) => f.type === t).length;
    const open = allFindings.filter((f) => f.status === "open").length;
    return {
      counts: {
        assets: allAssets.length,
        scans: allScans.length,
        findingsTotal: allFindings.length,
        findingsOpen: open,
        critical: bySeverity("critical"),
        high: bySeverity("high"),
        medium: bySeverity("medium"),
        low: bySeverity("low"),
        info: bySeverity("info"),
        lookalikes: byType("lookalike"),
        vulnerabilities: byType("vulnerability"),
        exposures: byType("exposure"),
        osint: byType("osint"),
      },
      recentFindings: allFindings.slice(0, 8),
      recentScans: allScans.slice(0, 5),
      young: {
        total: allFindings.filter((f) => f.type === "young-domain").length,
        phishing: allFindings.filter((f) => f.type === "young-domain" && (f.extra?.ai as any)?.verdict === "phishing").length,
        impersonation: allFindings.filter((f) => f.type === "young-domain" && (f.extra?.ai as any)?.verdict === "impersonation").length,
      },
    };
  },

  // ---------- global (cross-tenant) views ----------
  /**
   * Build the "global groups" matrix: per dimension, what distinct values exist
   * across all tenants, and which tenant ids fall into each. Used by the
   * ScopeBar dropdown and as the source of truth for global generators.
   */
  listGlobalGroups(): {
    client: Array<{ id: string; label: string; tenantIds: string[] }>;
    industry: Array<{ id: string; label: string; tenantIds: string[] }>;
    geo:      Array<{ id: string; label: string; tenantIds: string[] }>;
  } {
    const allTenants = db.select().from(tenants).all();
    const profiles = new Map<string, ClientProfileDTO>();
    for (const t of allTenants) profiles.set(t.id, storage.getClientProfile(t.id));

    const client = allTenants.map((t) => ({ id: t.id, label: t.name, tenantIds: [t.id] }));

    const indMap = new Map<string, string[]>();
    const geoMap = new Map<string, string[]>();
    for (const t of allTenants) {
      const p = profiles.get(t.id)!;
      for (const ind of p.industries) {
        if (!indMap.has(ind)) indMap.set(ind, []);
        indMap.get(ind)!.push(t.id);
      }
      for (const g of p.geos) {
        if (!geoMap.has(g)) geoMap.set(g, []);
        geoMap.get(g)!.push(t.id);
      }
    }
    const industry = Array.from(indMap.entries()).map(([k, v]) => ({ id: k, label: k, tenantIds: v })).sort((a, b) => a.label.localeCompare(b.label));
    const geo      = Array.from(geoMap.entries()).map(([k, v]) => ({ id: k, label: k, tenantIds: v })).sort((a, b) => a.label.localeCompare(b.label));
    return { client, industry, geo };
  },

  /**
   * Resolve a (dimension, ids) filter to the concrete set of tenant ids it
   * spans. Empty ids = all tenants in that dimension.
   */
  resolveGlobalScope(dimension: "client" | "industry" | "geo", ids: string[]): { tenantIds: string[]; groups: Array<{ id: string; label: string; tenantIds: string[] }> } {
    const groups = storage.listGlobalGroups();
    const pool = groups[dimension];
    const selected = ids.length === 0 ? pool : pool.filter((g) => ids.includes(g.id));
    const tenantSet = new Set<string>();
    for (const g of selected) for (const tid of g.tenantIds) tenantSet.add(tid);
    return { tenantIds: Array.from(tenantSet), groups: selected };
  },

  /**
   * Cross-tenant OSINT findings. Same filter API as listOsintFindings plus the
   * dimension/ids scope. Each row is enriched with tenant info for the UI.
   *
   * When `dedup` is true (v2.12+), intel items that exist on multiple tenants are
   * COLLAPSED to a single row whose `tenantTags` array carries every tenant the
   * item is associated with. The grouping key is preferentially `contentHash`
   * (SHA-1 of title+host); falling back to lowercased URL when hash is absent.
   * Per-row AI fields and analyst-set status are merged: the most recently
   * analyzed AI verdict wins; status falls back to the worst-case state.
   */
  listGlobalOsintFindings(opts: {
    dimension: "client" | "industry" | "geo";
    ids: string[];
    severity?: string;
    status?: string;
    tech?: string;
    sourceId?: string;
    category?: string;
    limit?: number;
    dedup?: boolean;
  }): Array<OsintFindingDTO & {
    tenantName: string;
    tenantSlug: string;
    tenantTags?: Array<{ id: string; name: string; slug: string }>;
    duplicateCount?: number;
  }> {
    const scope = storage.resolveGlobalScope(opts.dimension, opts.ids);
    if (scope.tenantIds.length === 0) return [];
    const tenantInfo = new Map(db.select().from(tenants).all().map((t) => [t.id, t]));
    const out: Array<OsintFindingDTO & { tenantName: string; tenantSlug: string }> = [];
    for (const tid of scope.tenantIds) {
      const rows = storage.listOsintFindings(tid, {
        severity: opts.severity,
        status: opts.status,
        tech: opts.tech,
        sourceId: opts.sourceId,
        category: opts.category,
      });
      const t = tenantInfo.get(tid)!;
      for (const r of rows) {
        out.push({ ...r, tenantName: t.name, tenantSlug: t.slug });
      }
    }
    out.sort((a, b) => (b.publishedAt || "").localeCompare(a.publishedAt || ""));

    if (!opts.dedup) {
      return opts.limit ? out.slice(0, opts.limit) : out;
    }

    // v2.12 dedup pass — collapse same intel across tenants into one tagged row.
    const groups = new Map<string, Array<OsintFindingDTO & { tenantName: string; tenantSlug: string }>>();
    for (const r of out) {
      // Use contentHash first; fall back to normalised url; final fallback to title-host pair.
      const hk = (r as any).contentHash || "";
      const uk = (r.url || "").toLowerCase().split("#")[0].split("?")[0];
      const tk = (r.title || "").toLowerCase().replace(/\s+/g, " ").trim();
      const key = hk || uk || tk;
      const bucket = groups.get(key);
      if (bucket) bucket.push(r);
      else groups.set(key, [r]);
    }

    const STATUS_WORST: Record<string, number> = { dismissed: 0, new: 1, triaged: 2, escalated: 3 };
    const merged: Array<OsintFindingDTO & {
      tenantName: string;
      tenantSlug: string;
      tenantTags?: Array<{ id: string; name: string; slug: string }>;
      duplicateCount?: number;
    }> = [];
    for (const bucket of groups.values()) {
      bucket.sort((a, b) => (b.publishedAt || "").localeCompare(a.publishedAt || ""));
      const head = bucket[0];
      // Pick the row with the most recent AI verdict so the merged record reflects the latest enrichment.
      const withAi = bucket.filter((b) => !!(b as any).aiAnalyzedAt);
      withAi.sort((a, b) => String((b as any).aiAnalyzedAt || "").localeCompare(String((a as any).aiAnalyzedAt || "")));
      const aiSource = withAi[0] || head;
      // Pick worst-case status across tenants.
      let worstStatus = head.status;
      let worstScore = STATUS_WORST[String(head.status)] ?? 0;
      for (const b of bucket) {
        const s = STATUS_WORST[String(b.status)] ?? 0;
        if (s > worstScore) { worstScore = s; worstStatus = b.status; }
      }
      // Union the per-row tag arrays so we don't lose tenant-specific tech / CVE / actor signals.
      const cveSet = new Set<string>();
      const techSet = new Set<string>();
      const actorSet = new Set<string>();
      for (const b of bucket) {
        for (const v of (b.cveIds || [])) cveSet.add(v);
        for (const v of (b.affectedTech || [])) techSet.add(v);
        for (const v of (b.threatActors || [])) actorSet.add(v);
      }
      const tagSet = new Map<string, { id: string; name: string; slug: string }>();
      for (const b of bucket) {
        if (!tagSet.has(b.tenantSlug)) {
          tagSet.set(b.tenantSlug, { id: (b as any).tenantId, name: b.tenantName, slug: b.tenantSlug });
        }
      }
      merged.push({
        ...head,
        status: worstStatus,
        cveIds: Array.from(cveSet),
        affectedTech: Array.from(techSet),
        threatActors: Array.from(actorSet),
        aiSummary: (aiSource as any).aiSummary,
        aiRelevanceScore: (aiSource as any).aiRelevanceScore,
        aiRecommendation: (aiSource as any).aiRecommendation,
        aiAnalyzedAt: (aiSource as any).aiAnalyzedAt,
        aiProviderLabel: (aiSource as any).aiProviderLabel,
        tenantTags: Array.from(tagSet.values()),
        duplicateCount: bucket.length,
      });
    }
    merged.sort((a, b) => (b.publishedAt || "").localeCompare(a.publishedAt || ""));
    return opts.limit ? merged.slice(0, opts.limit) : merged;
  },

  /**
   * Global aggregation of OSINT source rows — same DTO shape as listOsintSourceRows
   * but findingCount tallies rows from every tenant in the resolved scope.
   * Used by the Global view's Sources tab.
   */
  listGlobalOsintSourceRows(opts: {
    dimension: "client" | "industry" | "geo";
    ids: string[];
    category?: string;
    q?: string;
  }): OsintSourceRowDTO[] {
    const scope = storage.resolveGlobalScope(opts.dimension, opts.ids);
    if (scope.tenantIds.length === 0) return storage.listOsintSourceRows({ category: opts.category, q: opts.q }).map((r) => ({ ...r, findingCount: 0 }));
    const sources = storage.listOsintSources({ category: opts.category, q: opts.q });
    const placeholders = scope.tenantIds.map(() => "?").join(",");
    const countRows = sqlite.prepare(`SELECT source_id as sid, COUNT(*) as n FROM osint_findings WHERE tenant_id IN (${placeholders}) GROUP BY source_id`).all(...scope.tenantIds) as Array<{ sid: string; n: number }>;
    const countMap = new Map(countRows.map((c) => [c.sid, c.n]));
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
      lastFetchedAt: s.lastFetchedAt,
    }));
  },

  /**
   * Cross-tenant aggregation of email drafts and hunt-query history for the
   * Global view's Drafts & Queries tab. Each item is tagged with its tenant.
   */
  listGlobalDrafts(opts: {
    dimension: "client" | "industry" | "geo";
    ids: string[];
  }): {
    drafts: Array<OsintFindingDTO & { tenantName: string; tenantSlug: string }>;
    huntQueries: Array<HuntQueryDTO & { tenantName: string; tenantSlug: string }>;
  } {
    const scope = storage.resolveGlobalScope(opts.dimension, opts.ids);
    const drafts: Array<OsintFindingDTO & { tenantName: string; tenantSlug: string }> = [];
    const queries: Array<HuntQueryDTO & { tenantName: string; tenantSlug: string }> = [];
    if (scope.tenantIds.length === 0) return { drafts, huntQueries: queries };
    const tenantInfo = new Map(db.select().from(tenants).all().map((t) => [t.id, t]));
    for (const tid of scope.tenantIds) {
      const t = tenantInfo.get(tid)!;
      for (const f of storage.listOsintFindings(tid)) {
        if (f.draftEmail) drafts.push({ ...f, tenantName: t.name, tenantSlug: t.slug });
      }
      for (const q of storage.listHuntQueries(tid)) {
        queries.push({ ...q, tenantName: t.name, tenantSlug: t.slug });
      }
    }
    drafts.sort((a, b) => (b.draftEmailAt || "").localeCompare(a.draftEmailAt || ""));
    queries.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
    return { drafts, huntQueries: queries };
  },

  /**
   * AI overview — generates a persona-tuned summary, takeaways and recommendations
   * for the currently scoped OSINT findings. Mirrors the dispatchAi pattern of
   * threat_landscape: AI provider when available, deterministic fallback otherwise.
   *
   * Scope resolution:
   *   scope="client"   → single tenant (tid required)
   *   scope="global"   → all tenants (admin call)
   *   scope="industry" → resolveGlobalScope("industry", scopeIds)
   *   scope="geo"      → resolveGlobalScope("geo", scopeIds)
   */
  generateOsintOverview(opts: {
    tid?: string;
    persona: OsintOverviewPersona;
    category?: string;
    severity?: string;
    scope: "client" | "global" | "industry" | "geo";
    scopeIds?: string[];
  }): OsintOverviewResultDTO {
    // Gather the findings + a scope label.
    let scopeLabel: string;
    let findingsForAi: Array<{
      title: string; severity: string; sourceCategory: string;
      affectedTech: string[]; cveIds: string[]; threatActors: string[];
      summary?: string | null; rawSnippet?: string | null;
      publishedAt?: string; tenantName?: string;
    }> = [];
    let providerLabel: string | null = null;
    if (opts.scope === "client") {
      if (!opts.tid) throw new Error("tid required for scope=client");
      const tenant = storage.getTenant(opts.tid);
      scopeLabel = tenant?.name ?? "Client";
      const rows = storage.listOsintFindings(opts.tid, { category: opts.category, severity: opts.severity });
      findingsForAi = rows.slice(0, 60).map((f) => ({
        title: f.title, severity: f.severity, sourceCategory: f.sourceCategory,
        affectedTech: f.affectedTech, cveIds: f.cveIds, threatActors: f.threatActors,
        summary: f.summary, rawSnippet: (f as any).rawSnippet ?? null,
        publishedAt: f.publishedAt, tenantName: tenant?.name,
      }));
    } else {
      const dimension = opts.scope === "global" ? "client" : opts.scope as "industry" | "geo";
      const groups = storage.listGlobalGroups()[dimension] || [];
      const ids = (opts.scopeIds && opts.scopeIds.length) ? opts.scopeIds : groups.map((g) => g.id);
      const scope = storage.resolveGlobalScope(dimension, ids);
      const tenantInfo = new Map(db.select().from(tenants).all().map((t) => [t.id, t]));
      const groupLabels = groups.filter((g) => ids.includes(g.id)).map((g) => g.label);
      scopeLabel = opts.scope === "global"
        ? `Global (${scope.tenantIds.length} client${scope.tenantIds.length === 1 ? "" : "s"})`
        : `${opts.scope === "industry" ? "Industry" : "Geography"}: ${groupLabels.slice(0, 3).join(", ") || "(none)"}`;
      for (const tid of scope.tenantIds) {
        const t = tenantInfo.get(tid);
        const rows = storage.listOsintFindings(tid, { category: opts.category, severity: opts.severity });
        for (const r of rows.slice(0, 30)) {
          findingsForAi.push({
            title: r.title, severity: r.severity, sourceCategory: r.sourceCategory,
            affectedTech: r.affectedTech, cveIds: r.cveIds, threatActors: r.threatActors,
            summary: r.summary, rawSnippet: (r as any).rawSnippet ?? null,
            publishedAt: r.publishedAt, tenantName: t?.name,
          });
        }
      }
    }

    // Determine which tenant to use for AI provider resolution. For client scope it's tid;
    // for global / industry / geo we resolve against the first resolvable tenant.
    let providerTid = opts.tid;
    if (!providerTid) {
      const firstTenant = db.select().from(tenants).all()[0];
      providerTid = firstTenant?.id;
    }
    const provider = providerTid ? storage.resolveAiProvider(providerTid, "osint_overview") : null;
    const personaMeta = OSINT_OVERVIEW_PERSONAS.find((p) => p.id === opts.persona) || OSINT_OVERVIEW_PERSONAS[0];

    const overviewProvider = provider ?? ({
      id: "local-fallback", label: "OptraSight local generator",
      provider: "ollama" as AiProviderKind, model: "local", apiKeyEnc: null,
    } as unknown as AiProvider);
    if (provider) providerLabel = provider.label;
    else providerLabel = "OptraSight local generator";

    const aiResult = dispatchAi({
      task: "osint_overview",
      input: {
        persona: opts.persona,
        scopeLabel,
        category: opts.category ?? null,
        severityFilter: opts.severity ?? null,
        findings: findingsForAi,
      },
      provider: overviewProvider,
    });
    const output = aiResult.task === "osint_overview" ? aiResult.output : { summary: "", keyTakeaways: [], recommendations: [] };

    if (opts.tid) {
      storage.appendAudit(opts.tid, "system", "osint.overview", null, { persona: opts.persona, scope: opts.scope, count: findingsForAi.length });
    }

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
      providerLabel,
    };
  },

  /**
   * Generate one threat-landscape report per selected group. Reports are
   * persisted under each group's primary tenant (first tenant in the group),
   * but tagged in `stats.globalScope` so the UI can list them as global.
   */
  generateGlobalThreatLandscape(opts: {
    dimension: "client" | "industry" | "geo";
    ids: string[];
    title?: string;
    createdBy: string;
  }): ThreatLandscapeDTO[] {
    const scope = storage.resolveGlobalScope(opts.dimension, opts.ids);
    const out: ThreatLandscapeDTO[] = [];
    for (const grp of scope.groups) {
      const groupTids = grp.tenantIds;
      if (groupTids.length === 0) continue;
      // Aggregate signals across all tenants in the group.
      const recent: OsintFindingDTO[] = [];
      for (const tid of groupTids) recent.push(...storage.listOsintFindings(tid).slice(0, 30));
      recent.sort((a, b) => (b.publishedAt || "").localeCompare(a.publishedAt || ""));
      // Aggregate profile fields.
      const industries = new Set<string>();
      const geos = new Set<string>();
      const techs = new Set<string>();
      const clientTypes = new Set<string>();
      for (const tid of groupTids) {
        const p = storage.getClientProfile(tid);
        p.industries.forEach((x) => industries.add(x));
        p.geos.forEach((x) => geos.add(x));
        p.monitoredTechnologies.forEach((x) => techs.add(x));
        p.clientTypes.forEach((x) => clientTypes.add(x));
      }
      const aggregateProfile = {
        clientTypes: Array.from(clientTypes),
        industries: Array.from(industries),
        geos: Array.from(geos),
        monitoredTechnologies: Array.from(techs),
      } as any;
      // Pick an anchor tenant — use the first tenant in the group for persistence
      // and AI provider routing. AI summary references the group label, not the tenant.
      const anchorTid = groupTids[0];
      const anchor = storage.getTenant(anchorTid)!;
      const provider = storage.resolveAiProvider(anchorTid, "threat_landscape");
      const prevV = sqlite.prepare("SELECT MAX(version) as v FROM threat_landscapes WHERE tenant_id = ?").get(anchorTid) as any;
      const version = (prevV?.v ?? 0) + 1;
      const dimensionLabel = opts.dimension === "client" ? "Client" : opts.dimension === "industry" ? "Industry" : "Geography";
      const title = opts.title ?? `Threat landscape — ${dimensionLabel}: ${grp.label} v${version}`;
      let bodyMd: string;
      let stats: Record<string, any>;
      if (provider) {
        const r = dispatchAi({
          task: "threat_landscape",
          input: {
            clientName: `${dimensionLabel}: ${grp.label} (${groupTids.length} tenant${groupTids.length === 1 ? "" : "s"})`,
            profile: aggregateProfile,
            recentSignals: recent.slice(0, 15).map((f) => ({
              title: f.title, severity: f.severity, affectedTech: f.affectedTech, threatActors: f.threatActors,
            })),
          },
          provider,
        });
        if (r.task === "threat_landscape") {
          bodyMd = r.output.bodyMd && r.output.bodyMd.length > 0
            ? r.output.bodyMd
            : mockThreatLandscape(`${dimensionLabel}: ${grp.label}`, aggregateProfile, recent);
          stats = r.output.stats;
        } else {
          bodyMd = mockThreatLandscape(`${dimensionLabel}: ${grp.label}`, aggregateProfile, recent);
          stats = { topActors: [], topSectors: aggregateProfile.industries, geosCovered: aggregateProfile.geos };
        }
      } else {
        bodyMd = mockThreatLandscape(`${dimensionLabel}: ${grp.label}`, aggregateProfile, recent);
        stats = { topActors: [], topSectors: aggregateProfile.industries, geosCovered: aggregateProfile.geos };
      }
      stats.globalScope = {
        dimension: opts.dimension,
        groupId: grp.id,
        groupLabel: grp.label,
        tenantIds: groupTids,
        tenantNames: groupTids.map((t) => storage.getTenant(t)?.name ?? t),
      };
      const tlid = id();
      sqlite.prepare(`INSERT INTO threat_landscapes (
        id, tenant_id, version, title, status, body_md, stats, ai_provider_label, created_at, created_by
      ) VALUES (?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?)`).run(
        tlid, anchorTid, version, title, bodyMd, JSON.stringify(stats), provider?.label ?? null, now(), opts.createdBy
      );
      storage.appendAudit(anchorTid, opts.createdBy, "threat_landscape.generate.global", tlid, { version, dimension: opts.dimension, groupId: grp.id, tenantIds: groupTids });
      out.push({
        id: tlid, tenantId: anchorTid, version, title, status: "ready", bodyMd, stats,
        aiProviderLabel: provider?.label ?? null, createdAt: now(), createdBy: opts.createdBy,
      });
    }
    return out;
  },

  /**
   * List all global threat landscapes ever generated. Just scans every tenant's
   * threat_landscapes table and returns rows whose stats.globalScope is set.
   */
  listGlobalThreatLandscapes(opts?: { dimension?: string }): ThreatLandscapeDTO[] {
    const allTenants = db.select().from(tenants).all();
    const out: ThreatLandscapeDTO[] = [];
    for (const t of allTenants) {
      const rows = sqlite.prepare("SELECT * FROM threat_landscapes WHERE tenant_id = ? ORDER BY version DESC LIMIT 30").all(t.id) as any[];
      for (const r of rows) {
        const stats = JSON.parse(r.stats || "{}");
        if (!stats.globalScope) continue;
        if (opts?.dimension && stats.globalScope.dimension !== opts.dimension) continue;
        out.push({
          id: r.id, tenantId: r.tenant_id, version: r.version, title: r.title, status: r.status,
          bodyMd: r.body_md, stats, aiProviderLabel: r.ai_provider_label, createdAt: r.created_at, createdBy: r.created_by,
        });
      }
    }
    out.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
    return out;
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
        ORDER BY created_at DESC
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

  // ============================================================
  // v2.31.0 — Tabletop Exercise (TTX) Generator
  // ============================================================
  _exerciseRowToDto(row: any): ExerciseDTO {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      code: row.code,
      title: row.title,
      status: row.status as ExerciseStatus,
      framework: row.framework as ExerciseFramework,
      scenarioType: row.scenario_type as ExerciseScenarioType,
      severity: row.severity as ExerciseSeverity,
      scheduledAt: row.scheduled_at || null,
      durationMin: Number(row.duration_min ?? 120),
      facilitatorId: row.facilitator_id || null,
      narrativeMd: row.narrative_md || null,
      objectives: p<string[]>(row.objectives, []),
      evaluationRubric: p<Record<string, unknown>>(row.evaluation_rubric, {}),
      sourceTapIds: p<string[]>(row.source_tap_ids, []),
      sourceFindingIds: p<string[]>(row.source_finding_ids, []),
      sourceReferences: p<Array<{ title: string; url?: string }>>(row.source_references, []),
      uploadedPptxName: row.uploaded_pptx_name || null,
      aiProviderLabel: row.ai_provider_label || null,
      version: Number(row.version ?? 1),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      createdBy: row.created_by,
    };
  },
  _injectRowToDto(row: any): ExerciseInjectDTO {
    return {
      id: row.id,
      exerciseId: row.exercise_id,
      sequence: Number(row.sequence ?? 0),
      atMinute: Number(row.at_minute ?? 0),
      channel: row.channel as InjectChannel,
      audienceRoles: p<ExerciseRoleKey[]>(row.audience_roles, []),
      title: row.title,
      bodyMd: row.body_md || "",
      expectedActions: p<string[]>(row.expected_actions, []),
      iocs: p<Array<{ type: string; value: string }>>(row.iocs, []),
      attachments: p<Array<{ name: string; url?: string }>>(row.attachments, []),
      sentAt: row.sent_at || null,
      createdAt: row.created_at,
    };
  },
  _roleRowToDto(row: any): ExerciseRoleDTO {
    return {
      id: row.id,
      exerciseId: row.exercise_id,
      roleKey: row.role_key as ExerciseRoleKey,
      label: row.label,
      briefMd: row.brief_md || "",
      color: row.color || "#64748b",
      createdAt: row.created_at,
    };
  },
  _participantRowToDto(row: any): ExerciseParticipantDTO {
    return {
      id: row.id,
      exerciseId: row.exercise_id,
      roleId: row.role_id,
      roleKey: row.role_key as ExerciseRoleKey | undefined,
      roleLabel: row.role_label as string | undefined,
      displayName: row.display_name,
      email: row.email || null,
      token: row.token,
      joinedAt: row.joined_at || null,
      lastSeenAt: row.last_seen_at || null,
      createdAt: row.created_at,
    };
  },
  _eventRowToDto(row: any): ExerciseEventDTO {
    return {
      id: row.id,
      exerciseId: row.exercise_id,
      ts: row.ts,
      type: row.type as ExerciseEventType,
      actorId: row.actor_id || null,
      actorRole: (row.actor_role || null) as ExerciseRoleKey | null,
      payload: p<Record<string, unknown>>(row.payload, {}),
    };
  },

  // ---- exercise codes ----
  nextExerciseCode(tid: string): string {
    const rows = sqlite.prepare(
      "SELECT code FROM exercises WHERE tenant_id = ?",
    ).all(tid) as Array<{ code: string }>;
    let maxN = 0;
    for (const r of rows) {
      const m = /^TTX-(\d+)$/.exec(String(r.code || ""));
      if (m) maxN = Math.max(maxN, parseInt(m[1], 10));
    }
    const n = maxN + 1;
    return `TTX-${String(n).padStart(3, "0")}`;
  },

  // ---- exercise CRUD ----
  listExercises(tid: string, filter?: { status?: ExerciseStatus; q?: string }): ExerciseDTO[] {
    const where: string[] = ["e.tenant_id = ?"];
    const args: any[] = [tid];
    if (filter?.status) { where.push("e.status = ?"); args.push(filter.status); }
    if (filter?.q) { where.push("(LOWER(e.title) LIKE ? OR LOWER(e.code) LIKE ?)"); const q = `%${filter.q.toLowerCase()}%`; args.push(q, q); }
    const rows = sqlite.prepare(`
      SELECT e.*,
        (SELECT COUNT(*) FROM exercise_injects i WHERE i.exercise_id = e.id) AS inject_count,
        (SELECT COUNT(*) FROM exercise_roles r WHERE r.exercise_id = e.id) AS role_count,
        (SELECT COUNT(*) FROM exercise_participants p WHERE p.exercise_id = e.id) AS participant_count
      FROM exercises e
      WHERE ${where.join(" AND ")}
      ORDER BY e.updated_at DESC
    `).all(...args) as any[];
    return rows.map((r) => ({
      ...storage._exerciseRowToDto(r),
      injectCount: Number(r.inject_count ?? 0),
      roleCount: Number(r.role_count ?? 0),
      participantCount: Number(r.participant_count ?? 0),
    }));
  },
  getExercise(tid: string, eid: string): ExerciseDTO | undefined {
    const row = sqlite.prepare("SELECT * FROM exercises WHERE tenant_id = ? AND id = ?").get(tid, eid) as any;
    if (!row) return undefined;
    return storage._exerciseRowToDto(row);
  },
  getExerciseFull(tid: string, eid: string): ExerciseFullDTO | undefined {
    const base = storage.getExercise(tid, eid);
    if (!base) return undefined;
    return {
      ...base,
      injects: storage.listInjects(tid, eid),
      roles: storage.listRoles(tid, eid),
      participants: storage.listParticipants(tid, eid),
      events: storage.listEvents(tid, eid),
    };
  },
  createExercise(tid: string, createdBy: string, input: {
    title: string;
    framework?: ExerciseFramework;
    scenarioType?: ExerciseScenarioType;
    severity?: ExerciseSeverity;
    durationMin?: number;
    scheduledAt?: string | null;
    sourceTapIds?: string[];
    sourceFindingIds?: string[];
  }): ExerciseDTO {
    const eid = id();
    const ts = now();
    const code = storage.nextExerciseCode(tid);
    sqlite.prepare(`INSERT INTO exercises (
      id, tenant_id, code, title, status, framework, scenario_type, severity,
      scheduled_at, duration_min, facilitator_id, narrative_md,
      objectives, evaluation_rubric,
      source_tap_ids, source_finding_ids, source_references,
      uploaded_pptx_path, uploaded_pptx_name, ai_provider_label,
      version, created_at, updated_at, created_by
    ) VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, NULL, NULL, '[]', '{}', ?, ?, '[]', NULL, NULL, NULL, 1, ?, ?, ?)`).run(
      eid, tid, code, input.title.trim(),
      input.framework ?? "hkma",
      input.scenarioType ?? "ransomware-affiliate",
      input.severity ?? "HIGH",
      input.scheduledAt ?? null,
      input.durationMin ?? 120,
      j(input.sourceTapIds ?? []),
      j(input.sourceFindingIds ?? []),
      ts, ts, createdBy,
    );
    storage.appendAudit(tid, createdBy, "exercise.create", eid, { code, title: input.title });
    return storage.getExercise(tid, eid)!;
  },
  patchExercise(tid: string, eid: string, patch: Record<string, any> & { actor?: string }): ExerciseDTO | undefined {
    const actor = patch.actor ?? "system";
    const row = sqlite.prepare("SELECT * FROM exercises WHERE tenant_id = ? AND id = ?").get(tid, eid) as any;
    if (!row) return undefined;
    const scalarMap: Record<string, string> = {
      title: "title", status: "status", framework: "framework",
      scenarioType: "scenario_type", severity: "severity",
      durationMin: "duration_min", scheduledAt: "scheduled_at",
      facilitatorId: "facilitator_id", narrativeMd: "narrative_md",
      uploadedPptxPath: "uploaded_pptx_path", uploadedPptxName: "uploaded_pptx_name",
      aiProviderLabel: "ai_provider_label",
    };
    const jsonMap: Record<string, string> = {
      objectives: "objectives",
      evaluationRubric: "evaluation_rubric",
      sourceTapIds: "source_tap_ids",
      sourceFindingIds: "source_finding_ids",
      sourceReferences: "source_references",
    };
    const sets: string[] = [];
    const args: any[] = [];
    for (const [k, col] of Object.entries(scalarMap)) {
      if (k in patch) { sets.push(`${col} = ?`); args.push(patch[k]); }
    }
    for (const [k, col] of Object.entries(jsonMap)) {
      if (k in patch) { sets.push(`${col} = ?`); args.push(JSON.stringify(patch[k] ?? (Array.isArray(patch[k]) ? [] : {}))); }
    }
    if (sets.length === 0) return storage.getExercise(tid, eid);
    sets.push("version = version + 1");
    sets.push("updated_at = ?");
    args.push(now());
    args.push(tid, eid);
    sqlite.prepare(`UPDATE exercises SET ${sets.join(", ")} WHERE tenant_id = ? AND id = ?`).run(...args);
    storage.appendAudit(tid, actor, "exercise.update", eid, {
      fields: Object.keys(patch).filter((k) => k !== "actor"),
    });
    return storage.getExercise(tid, eid);
  },
  deleteExercise(tid: string, eid: string, actor: string): boolean {
    const row = sqlite.prepare("SELECT id FROM exercises WHERE tenant_id = ? AND id = ?").get(tid, eid) as any;
    if (!row) return false;
    sqlite.prepare("DELETE FROM exercise_events WHERE tenant_id = ? AND exercise_id = ?").run(tid, eid);
    sqlite.prepare("DELETE FROM exercise_participants WHERE tenant_id = ? AND exercise_id = ?").run(tid, eid);
    sqlite.prepare("DELETE FROM exercise_roles WHERE tenant_id = ? AND exercise_id = ?").run(tid, eid);
    sqlite.prepare("DELETE FROM exercise_injects WHERE tenant_id = ? AND exercise_id = ?").run(tid, eid);
    sqlite.prepare("DELETE FROM exercises WHERE tenant_id = ? AND id = ?").run(tid, eid);
    storage.appendAudit(tid, actor, "exercise.delete", eid, {});
    return true;
  },

  // ---- injects ----
  listInjects(tid: string, eid: string): ExerciseInjectDTO[] {
    const rows = sqlite.prepare(
      "SELECT * FROM exercise_injects WHERE tenant_id = ? AND exercise_id = ? ORDER BY sequence ASC, at_minute ASC, created_at ASC",
    ).all(tid, eid) as any[];
    return rows.map(storage._injectRowToDto);
  },
  addInject(tid: string, eid: string, input: {
    sequence?: number; atMinute?: number; channel?: InjectChannel;
    audienceRoles?: ExerciseRoleKey[]; title: string; bodyMd?: string;
    expectedActions?: string[];
    iocs?: Array<{ type: string; value: string }>;
    attachments?: Array<{ name: string; url?: string }>;
  }, actor: string): ExerciseInjectDTO {
    const iid = id();
    const ts = now();
    // Auto-assign next sequence if not given
    let seq = input.sequence;
    if (seq == null) {
      const max = sqlite.prepare(
        "SELECT COALESCE(MAX(sequence), -1) AS m FROM exercise_injects WHERE exercise_id = ?",
      ).get(eid) as { m: number };
      seq = (max?.m ?? -1) + 1;
    }
    sqlite.prepare(`INSERT INTO exercise_injects (
      id, tenant_id, exercise_id, sequence, at_minute, channel,
      audience_roles, title, body_md, expected_actions,
      iocs, attachments, sent_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`).run(
      iid, tid, eid, seq, input.atMinute ?? 0,
      input.channel ?? "email",
      j(input.audienceRoles ?? []), input.title.trim(),
      input.bodyMd ?? "",
      j(input.expectedActions ?? []),
      j(input.iocs ?? []),
      j(input.attachments ?? []),
      ts,
    );
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(ts, eid);
    storage.appendAudit(tid, actor, "exercise.inject.add", eid, { injectId: iid, title: input.title });
    return storage._injectRowToDto(sqlite.prepare("SELECT * FROM exercise_injects WHERE id = ?").get(iid));
  },
  patchInject(tid: string, iid: string, patch: Record<string, any> & { actor?: string }): ExerciseInjectDTO | undefined {
    const actor = patch.actor ?? "system";
    const row = sqlite.prepare("SELECT * FROM exercise_injects WHERE tenant_id = ? AND id = ?").get(tid, iid) as any;
    if (!row) return undefined;
    const scalarMap: Record<string, string> = {
      sequence: "sequence", atMinute: "at_minute", channel: "channel",
      title: "title", bodyMd: "body_md",
    };
    const jsonMap: Record<string, string> = {
      audienceRoles: "audience_roles", expectedActions: "expected_actions",
      iocs: "iocs", attachments: "attachments",
    };
    const sets: string[] = [];
    const args: any[] = [];
    for (const [k, col] of Object.entries(scalarMap)) {
      if (k in patch) { sets.push(`${col} = ?`); args.push(patch[k]); }
    }
    for (const [k, col] of Object.entries(jsonMap)) {
      if (k in patch) { sets.push(`${col} = ?`); args.push(JSON.stringify(patch[k] ?? [])); }
    }
    if (sets.length === 0) return storage._injectRowToDto(row);
    args.push(tid, iid);
    sqlite.prepare(`UPDATE exercise_injects SET ${sets.join(", ")} WHERE tenant_id = ? AND id = ?`).run(...args);
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(now(), row.exercise_id);
    storage.appendAudit(tid, actor, "exercise.inject.update", row.exercise_id, {
      injectId: iid, fields: Object.keys(patch).filter((k) => k !== "actor"),
    });
    return storage._injectRowToDto(sqlite.prepare("SELECT * FROM exercise_injects WHERE id = ?").get(iid));
  },
  deleteInject(tid: string, iid: string, actor: string): boolean {
    const row = sqlite.prepare("SELECT exercise_id FROM exercise_injects WHERE tenant_id = ? AND id = ?").get(tid, iid) as any;
    if (!row) return false;
    sqlite.prepare("DELETE FROM exercise_injects WHERE tenant_id = ? AND id = ?").run(tid, iid);
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(now(), row.exercise_id);
    storage.appendAudit(tid, actor, "exercise.inject.delete", row.exercise_id, { injectId: iid });
    return true;
  },
  markInjectSent(tid: string, iid: string, actor: string): ExerciseInjectDTO | undefined {
    const row = sqlite.prepare("SELECT * FROM exercise_injects WHERE tenant_id = ? AND id = ?").get(tid, iid) as any;
    if (!row) return undefined;
    const ts = now();
    sqlite.prepare("UPDATE exercise_injects SET sent_at = ? WHERE id = ?").run(ts, iid);
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(ts, row.exercise_id);
    storage.addEvent(tid, row.exercise_id, {
      type: "inject-sent",
      actorId: actor, actorRole: null,
      payload: { injectId: iid, title: row.title, atMinute: row.at_minute, channel: row.channel },
    });
    storage.appendAudit(tid, actor, "exercise.inject.send", row.exercise_id, { injectId: iid });
    return storage._injectRowToDto(sqlite.prepare("SELECT * FROM exercise_injects WHERE id = ?").get(iid));
  },

  // ---- roles ----
  listRoles(tid: string, eid: string): ExerciseRoleDTO[] {
    const rows = sqlite.prepare(
      "SELECT * FROM exercise_roles WHERE tenant_id = ? AND exercise_id = ? ORDER BY created_at ASC",
    ).all(tid, eid) as any[];
    return rows.map(storage._roleRowToDto);
  },
  upsertRole(tid: string, eid: string, input: {
    roleKey: ExerciseRoleKey; label: string; briefMd?: string; color?: string;
  }, actor: string): ExerciseRoleDTO {
    const existing = sqlite.prepare(
      "SELECT * FROM exercise_roles WHERE tenant_id = ? AND exercise_id = ? AND role_key = ?",
    ).get(tid, eid, input.roleKey) as any;
    if (existing) {
      sqlite.prepare(
        "UPDATE exercise_roles SET label = ?, brief_md = ?, color = ? WHERE id = ?",
      ).run(input.label, input.briefMd ?? existing.brief_md ?? "", input.color ?? existing.color ?? "#64748b", existing.id);
      sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(now(), eid);
      storage.appendAudit(tid, actor, "exercise.role.update", eid, { roleId: existing.id, roleKey: input.roleKey });
      return storage._roleRowToDto(sqlite.prepare("SELECT * FROM exercise_roles WHERE id = ?").get(existing.id));
    }
    const rid = id();
    const ts = now();
    sqlite.prepare(`INSERT INTO exercise_roles (
      id, tenant_id, exercise_id, role_key, label, brief_md, color, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      rid, tid, eid, input.roleKey, input.label.trim(),
      input.briefMd ?? "", input.color ?? "#64748b", ts,
    );
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(ts, eid);
    storage.appendAudit(tid, actor, "exercise.role.create", eid, { roleId: rid, roleKey: input.roleKey });
    return storage._roleRowToDto(sqlite.prepare("SELECT * FROM exercise_roles WHERE id = ?").get(rid));
  },
  patchRole(tid: string, rid: string, patch: { label?: string; briefMd?: string; color?: string; actor?: string }): ExerciseRoleDTO | undefined {
    const actor = patch.actor ?? "system";
    const row = sqlite.prepare("SELECT * FROM exercise_roles WHERE tenant_id = ? AND id = ?").get(tid, rid) as any;
    if (!row) return undefined;
    const sets: string[] = [];
    const args: any[] = [];
    if (patch.label !== undefined) { sets.push("label = ?"); args.push(patch.label); }
    if (patch.briefMd !== undefined) { sets.push("brief_md = ?"); args.push(patch.briefMd); }
    if (patch.color !== undefined) { sets.push("color = ?"); args.push(patch.color); }
    if (sets.length === 0) return storage._roleRowToDto(row);
    args.push(tid, rid);
    sqlite.prepare(`UPDATE exercise_roles SET ${sets.join(", ")} WHERE tenant_id = ? AND id = ?`).run(...args);
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(now(), row.exercise_id);
    storage.appendAudit(tid, actor, "exercise.role.update", row.exercise_id, { roleId: rid });
    return storage._roleRowToDto(sqlite.prepare("SELECT * FROM exercise_roles WHERE id = ?").get(rid));
  },
  deleteRole(tid: string, rid: string, actor: string): boolean {
    const row = sqlite.prepare("SELECT exercise_id FROM exercise_roles WHERE tenant_id = ? AND id = ?").get(tid, rid) as any;
    if (!row) return false;
    // Cascade: delete participants attached to this role
    sqlite.prepare("DELETE FROM exercise_participants WHERE tenant_id = ? AND role_id = ?").run(tid, rid);
    sqlite.prepare("DELETE FROM exercise_roles WHERE tenant_id = ? AND id = ?").run(tid, rid);
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(now(), row.exercise_id);
    storage.appendAudit(tid, actor, "exercise.role.delete", row.exercise_id, { roleId: rid });
    return true;
  },

  // ---- participants ----
  listParticipants(tid: string, eid: string): ExerciseParticipantDTO[] {
    const rows = sqlite.prepare(`
      SELECT p.*, r.role_key, r.label AS role_label
      FROM exercise_participants p
      LEFT JOIN exercise_roles r ON r.id = p.role_id
      WHERE p.tenant_id = ? AND p.exercise_id = ?
      ORDER BY p.created_at ASC
    `).all(tid, eid) as any[];
    return rows.map(storage._participantRowToDto);
  },
  addParticipant(tid: string, eid: string, input: {
    roleId: string; displayName: string; email?: string | null;
  }, actor: string): ExerciseParticipantDTO {
    // Verify role belongs to this exercise + tenant.
    const role = sqlite.prepare(
      "SELECT id FROM exercise_roles WHERE tenant_id = ? AND exercise_id = ? AND id = ?",
    ).get(tid, eid, input.roleId) as any;
    if (!role) throw new Error("Role not found for this exercise");
    const pid = id();
    const ts = now();
    const token = randomBytes(16).toString("hex"); // 32-char hex
    sqlite.prepare(`INSERT INTO exercise_participants (
      id, tenant_id, exercise_id, role_id, display_name, email, token,
      joined_at, last_seen_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)`).run(
      pid, tid, eid, input.roleId, input.displayName.trim(),
      input.email ?? null, token, ts,
    );
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(ts, eid);
    storage.appendAudit(tid, actor, "exercise.participant.add", eid, {
      participantId: pid, roleId: input.roleId, displayName: input.displayName,
    });
    return storage._participantRowToDto(sqlite.prepare(`
      SELECT p.*, r.role_key, r.label AS role_label
      FROM exercise_participants p LEFT JOIN exercise_roles r ON r.id = p.role_id
      WHERE p.id = ?
    `).get(pid));
  },
  participantByToken(token: string): (ExerciseParticipantDTO & { tenantId: string }) | undefined {
    const row = sqlite.prepare(`
      SELECT p.*, r.role_key, r.label AS role_label
      FROM exercise_participants p LEFT JOIN exercise_roles r ON r.id = p.role_id
      WHERE p.token = ?
    `).get(token) as any;
    if (!row) return undefined;
    return { ...storage._participantRowToDto(row), tenantId: row.tenant_id };
  },
  touchParticipant(pid: string): void {
    const ts = now();
    sqlite.prepare(
      "UPDATE exercise_participants SET last_seen_at = ?, joined_at = COALESCE(joined_at, ?) WHERE id = ?",
    ).run(ts, ts, pid);
  },
  deleteParticipant(tid: string, pid: string, actor: string): boolean {
    const row = sqlite.prepare("SELECT exercise_id FROM exercise_participants WHERE tenant_id = ? AND id = ?").get(tid, pid) as any;
    if (!row) return false;
    sqlite.prepare("DELETE FROM exercise_participants WHERE tenant_id = ? AND id = ?").run(tid, pid);
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(now(), row.exercise_id);
    storage.appendAudit(tid, actor, "exercise.participant.delete", row.exercise_id, { participantId: pid });
    return true;
  },

  // ---- events ----
  listEvents(tid: string, eid: string, opts?: { sinceTs?: string; limit?: number }): ExerciseEventDTO[] {
    const where: string[] = ["tenant_id = ?", "exercise_id = ?"];
    const args: any[] = [tid, eid];
    if (opts?.sinceTs) { where.push("ts > ?"); args.push(opts.sinceTs); }
    const lim = Math.max(1, Math.min(opts?.limit ?? 500, 1000));
    const rows = sqlite.prepare(
      `SELECT * FROM exercise_events WHERE ${where.join(" AND ")} ORDER BY ts ASC LIMIT ${lim}`,
    ).all(...args) as any[];
    return rows.map(storage._eventRowToDto);
  },
  addEvent(tid: string, eid: string, input: {
    type: ExerciseEventType;
    actorId?: string | null;
    actorRole?: ExerciseRoleKey | null;
    payload?: Record<string, unknown>;
  }): ExerciseEventDTO {
    const evid = id();
    const ts = now();
    sqlite.prepare(`INSERT INTO exercise_events (
      id, tenant_id, exercise_id, ts, type, actor_id, actor_role, payload
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      evid, tid, eid, ts, input.type,
      input.actorId ?? null, input.actorRole ?? null,
      JSON.stringify(input.payload ?? {}),
    );
    sqlite.prepare("UPDATE exercises SET updated_at = ? WHERE id = ?").run(ts, eid);
    return storage._eventRowToDto(sqlite.prepare("SELECT * FROM exercise_events WHERE id = ?").get(evid));
  },
};

// ---------- helpers (DTO mappers) ----------
// Translate legacy verdict strings from pre-wave-1 demo rows (impersonation,
// parked, benign, unreachable) into the current enum. Without this we hand
// out wire shapes the client cannot render — VerdictBadge crashes on a
// missing VERDICT_META key and the whole page blanks.
function normaliseLegacyVerdict(v: unknown): YoungDomainCandidateDTO["verdict"] {
  switch (v) {
    case "phishing": case "spoofing": case "brand_impersonation":
    case "forged_login": case "parked_benign": case "inconclusive":
      return v as YoungDomainCandidateDTO["verdict"];
    case "impersonation": return "brand_impersonation";
    case "parked":        return "parked_benign";
    case "benign":        return "parked_benign";
    case "unreachable":   return "inconclusive";
    default:              return "inconclusive";
  }
}

function mapYoungDomainRow(row: any): YoungDomainCandidateDTO {
  const ex = p<Record<string, any>>(row.extra, {});
  const ai = ex.ai || null;
  const an = ex.analyst || null;
  const discoveredBy: Array<"dnstwist" | "opensquat" | "crtsh" | "domscan" | "keyword_expansion"> | undefined =
    Array.isArray(ex.discoveredBy) && ex.discoveredBy.length
      ? ex.discoveredBy.filter((d: any) => d === "dnstwist" || d === "opensquat" || d === "crtsh" || d === "domscan" || d === "keyword_expansion")
      : undefined;
  const evidenceSource = (row.evidenceSource ?? row.evidence_source) as
    | "live" | "demo" | "ai_inferred" | undefined;
  return {
    id: row.id,
    domain: row.target || "",
    seed: ex.seed || "",
    source: (ex.source === "global" ? "global" : "tenant"),
    presetId: ex.presetId,
    presetName: ex.presetName,
    technique: ex.technique || "",
    registeredAt: ex.whois?.createdAt ?? row.createdAt,
    ageDays: ex.ageDays || 0,
    hasMx: !!ex.hasMx,
    hasA: !!ex.hasA,
    similarity: ex.similarity || 0,
    riskScore: ex.riskScore || 0,
    screenshotUrl: ex.screenshotUrl ?? null,
    discoveredBy,
    evidenceSource: evidenceSource ?? "demo",
    verdict: ai ? normaliseLegacyVerdict(ai.verdict) : "inconclusive",
    confidence: ai?.confidence ?? 0,
    reasoning: ai?.reasoning || "",
    targetBrand: ai?.targetBrand ?? null,
    aiProviderLabel: ai?.provider ?? null,
    aiAnalyzed: !!ai,
    aiAnalyzedAt: ai?.at ?? null,
    analystVerdict: an?.verdict ? normaliseLegacyVerdict(an.verdict) : null,
    analystNotes: an?.notes ?? null,
    analystAt: an?.at ?? null,
    analystBy: an?.by ?? null,
    siteStatus: ex.siteEvidence?.status ?? "unknown",
    brandAbuse: ex.brandAbuse ?? null,
    brandAssetDetected: !!ai?.brandAssetDetected,
    matchedAssetKinds: Array.isArray(ai?.matchedAssetKinds) ? ai.matchedAssetKinds : [],
    visualSimilarity: typeof ai?.visualSimilarity === "number" ? ai.visualSimilarity : null,
    loginFormDetected: !!(ai?.loginFormDetected ?? ex.siteEvidence?.loginFormDetected),
    cloudflareBlocked: !!(ai?.cloudflareBlocked ?? ex.siteEvidence?.cloudflareBlocked),
    keyEvidence: Array.isArray(ai?.keyEvidence) ? ai.keyEvidence : [],
    recommendedActions: Array.isArray(ai?.recommendedActions) ? ai.recommendedActions : [],
    visionSupported: !!ai?.visionSupported,
  };
}

function providerSupportsVision(provider: AiProvider): boolean {
  const kind = provider.provider;
  const model = (provider.model || "").toLowerCase();
  if (kind === "openai" || kind === "azure-openai") return /gpt-4o|gpt-5|vision/.test(model);
  if (kind === "anthropic") return /claude/.test(model);
  if (kind === "gemini") return /gemini/.test(model);
  if (kind === "kimi") return /vision|k1|kimi/.test(model);
  return false;
}

function loadScreenshotPayload(url: string | null): { available: boolean; mime?: string; dataBase64?: string | null; url?: string | null } {
  if (!url) return { available: false, url: null };
  try {
    const clean = decodeURIComponent(url.split("?")[0].split("/").pop() || "");
    if (!clean || clean.includes("/") || clean.includes("..")) return { available: false, url };
    const path = join(DNSTWIST_SCREENSHOTS_DIR, clean);
    if (!existsSync(path)) return { available: false, url };
    return {
      available: true,
      mime: "image/png",
      dataBase64: readFileSync(path).toString("base64"),
      url,
    };
  } catch {
    return { available: false, url };
  }
}

function publicScreenshotUrlToPath(url: string | null): string | null {
  if (!url) return null;
  try {
    const clean = decodeURIComponent(url.split("?")[0].split("/").pop() || "");
    if (!clean || clean.includes("/") || clean.includes("..")) return null;
    const path = join(DNSTWIST_SCREENSHOTS_DIR, clean);
    return existsSync(path) ? path : null;
  } catch {
    return null;
  }
}

function compactFingerprint(fp: ImageFingerprint): Omit<ImageFingerprint, "histogram"> & { histogramBins: number } {
  const { histogram, ...rest } = fp;
  return { ...rest, histogramBins: histogram.length };
}

async function computeBrandAbuseMatches(tid: string, screenshotPath: string | null): Promise<{
  source: "local_image_similarity";
  generatedAt: string;
  candidateAvailable: boolean;
  matchCount: number;
  topScore: number;
  matches: BrandAbuseMatch[];
  error?: string;
}> {
  if (!screenshotPath) {
    return { source: "local_image_similarity", generatedAt: now(), candidateAvailable: false, matchCount: 0, topScore: 0, matches: [] };
  }
  try {
    const candidateBuffer = readFileSync(screenshotPath);
    const candidateFingerprint = await fingerprintImage(candidateBuffer);
    const rows = db.select().from(clientAssets)
      .where(eq(clientAssets.tenantId, tid))
      .all()
      .filter((a) => (a.kind === "logo" || a.kind === "trademark" || a.kind === "app_icon") && a.mime !== "image/svg+xml")
      .slice(0, 20);
    const matches: BrandAbuseMatch[] = [];
    for (const a of rows) {
      try {
        const assetBuffer = Buffer.from(a.data, "base64");
        const assetFingerprint = await fingerprintImage(assetBuffer);
        const sim = compareFingerprints(candidateFingerprint, assetFingerprint);
        const template = await templateMatchImage(candidateBuffer, assetBuffer);
        const score = Math.max(sim.score, template.score);
        matches.push({
          assetId: a.id,
          assetKind: a.kind as "logo" | "trademark" | "app_icon",
          assetName: a.name,
          source: "dnstwist_screenshot",
          score,
          similarity: { ...sim, templateSimilarity: template.score, templateBox: template.box || undefined },
          template,
          assetFingerprint: compactFingerprint(assetFingerprint),
          candidateFingerprint: compactFingerprint(candidateFingerprint),
        });
      } catch {
        // One corrupt or unsupported asset should not break the whole scan.
      }
    }
    matches.sort((a, b) => b.score - a.score);
    return {
      source: "local_image_similarity",
      generatedAt: now(),
      candidateAvailable: true,
      matchCount: matches.length,
      topScore: matches[0]?.score ?? 0,
      matches: matches.slice(0, 5),
    };
  } catch (err: any) {
    return {
      source: "local_image_similarity",
      generatedAt: now(),
      candidateAvailable: false,
      matchCount: 0,
      topScore: 0,
      matches: [],
      error: err?.message || "image similarity failed",
    };
  }
}

function assetToDto(a: ClientAsset): ClientAssetDTO {
  return {
    id: a.id, tenantId: a.tenantId,
    kind: a.kind as ClientAssetDTO["kind"], name: a.name,
    mime: a.mime, size: a.size, sha256: a.sha256,
    jurisdiction: a.jurisdiction ?? null,
    registeredMark: a.registeredMark ?? null,
    notes: a.notes ?? null,
    dataUrl: `data:${a.mime};base64,${a.data}`,
    createdAt: a.createdAt,
  };
}

function aiProviderToSummary(p: AiProvider): AiProviderSummary {
  return {
    id: p.id,
    provider: p.provider as AiProviderKind,
    label: p.label, model: p.model,
    baseUrl: p.baseUrl ?? null,
    enabled: !!p.enabled,
    isDefault: !!p.isDefault,
    hasKey: !!p.apiKeyEnc,
    apiKeyMask: p.apiKeyMask ?? null,
    lastTestedAt: p.lastTestedAt ?? null,
    lastTestOk: p.lastTestOk == null ? null : !!p.lastTestOk,
    lastTestMessage: p.lastTestMessage ?? null,
    updatedAt: p.updatedAt,
  };
}

// ---------- mock generators (for hunt queries + threat landscape) ----------
function mockHuntQueryFor(lang: string, affectedTech: string[], cveIds: string[]): string {
  const techList = (affectedTech || []).slice(0, 6);
  const cveList = (cveIds || []).slice(0, 6);
  const techRegex = techList.length ? techList.map((t) => t.replace(/[^a-z0-9-]/gi, ".")).join("|") : "vendor|product";
  const cveRegex = cveList.length ? cveList.join("|") : "CVE-2024-XXXXX";
  const techCsv = techList.length ? techList.map((t) => `"${t}"`).join(",") : '"product"';
  const cveCsv = cveList.length ? cveList.map((c) => `"${c}"`).join(",") : '"CVE-2024-XXXXX"';

  switch (lang) {
    case "splunk":
      return [
        `index=* sourcetype IN ("vendor:firewall","vendor:proxy","WinEventLog:*","linux_secure")`,
        `  earliest=-30d`,
        `  (${techList.map((t) => `product="${t}"`).join(" OR ") || 'product="*"'})`,
        `  OR (cve IN (${cveCsv}))`,
        `  OR (process_command_line="*PowerShell -enc*" OR uri_path="*..%2f*" OR http_user_agent="*sqlmap*")`,
        `| stats count, values(src_ip) AS src, values(dest_ip) AS dst, values(user) AS users by host, product, signature`,
        `| where count > 1`,
        `| sort - count`,
      ].join("\n");
    case "kql_elk":
      return [
        `event.module : (${techList.map((t) => `"${t}"`).join(" or ") || '"*"'})`,
        `and (vulnerability.id : (${cveList.map((c) => `"${c}"`).join(" or ") || '"CVE-*"'})`,
        `     or process.command_line : ("*-EncodedCommand*" or "*Invoke-Mimikatz*")`,
        `     or url.original : ("*../../*" or "*%2e%2e%2f*"))`,
        `and @timestamp >= now-30d`,
      ].join("\n");
    case "chronicle":
      return [
        `rule optrasight_${(techList[0] || "vendor").replace(/[^a-z0-9]/gi, "_").toLowerCase()}_exploitation {`,
        `  meta:`,
        `    author = "OptraSight OSINT"`,
        `    severity = "High"`,
        `    description = "Exploitation activity for ${techList.join(", ") || "monitored tech"} (${cveList.join(", ") || "recent CVE"})"`,
        `  events:`,
        `    $e.metadata.event_type = "NETWORK_HTTP"`,
        `    $e.principal.hostname != ""`,
        `    re.regex($e.target.url, \`(?i)(${techRegex})\`)`,
        `    re.regex($e.security_result.description, \`(?i)(${cveRegex})\`)`,
        `  condition: $e`,
        `}`,
      ].join("\n");
    case "defender":
      return [
        `// Microsoft Defender / Sentinel KQL`,
        `union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents`,
        `| where Timestamp > ago(30d)`,
        `| where ProcessCommandLine has_any ("powershell -enc", "certutil -urlcache", "mshta http")`,
        `   or RemoteUrl has_any (${techCsv})`,
        `   or AdditionalFields has_any (${cveCsv})`,
        `| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, RemoteUrl, RemoteIP`,
        `| sort by Timestamp desc`,
      ].join("\n");
    case "crowdstrike":
      return [
        `// CrowdStrike Falcon LogScale (CQL)`,
        `#event_simpleName=/ProcessRollup2|NetworkConnect|DnsRequest/`,
        `| in(field=ImageFileName, values=[${techCsv}], ignoreCase=true)`,
        `   OR in(field=CommandLine, values=[${cveCsv}])`,
        `   OR regex(field=CommandLine, regex="(?i)(powershell\\\\s+-enc|certutil\\\\s+-urlcache|rundll32\\\\s+javascript:)")`,
        `| groupby([ComputerName, UserName, ImageFileName])`,
        `| sort(field=_count, order=desc)`,
      ].join("\n");
    case "cortex_xdr":
      return [
        `// Cortex XDR XQL`,
        `dataset = xdr_data`,
        `| filter event_type in (PROCESS, NETWORK, FILE)`,
        `| filter (action_process_image_name in (${techCsv})`,
        `       or action_remote_ip != null and action_remote_url contains_any (${techCsv})`,
        `       or actor_process_command_line ~= "(?i)(${cveRegex}|powershell.*-enc|certutil.*urlcache)")`,
        `| fields _time, agent_hostname, actor_process_image_name, action_process_image_command_line, action_remote_url`,
        `| sort desc _time`,
      ].join("\n");
    case "sentinelone":
      return [
        `// SentinelOne PowerQuery`,
        `event.type in ("Process Creation", "DNS Resolved", "IP Connect")`,
        `and (tgt.process.image.path contains:anycase (${techCsv})`,
        `     or url.address contains:anycase (${techCsv})`,
        `     or src.process.cmdline matches "(?i)(${cveRegex}|powershell.*-enc)")`,
        `| group count() by endpoint.name, src.process.image.path, tgt.process.cmdline`,
        `| sort -count`,
      ].join("\n");
    case "yara":
      return [
        `rule OptraSight_${(techList[0] || "vendor").replace(/[^a-z0-9]/gi, "_")}_${(cveList[0] || "recent").replace(/-/g, "_")}`,
        `{`,
        `  meta:`,
        `    author      = "OptraSight OSINT"`,
        `    description = "Exploitation tooling for ${techList.join(", ") || "monitored tech"}"`,
        `    cve         = "${cveList.join(", ") || "CVE-2024-XXXXX"}"`,
        `    severity    = "high"`,
        `  strings:`,
        `    $tech1 = "${techList[0] || "product"}" ascii nocase wide`,
        `    $cve1  = "${cveList[0] || "CVE-2024-XXXXX"}" ascii nocase wide`,
        `    $tool1 = /Invoke-(Mimikatz|WebRequest|Expression)/ ascii nocase wide`,
        `    $tool2 = { 4D 5A 90 00 03 00 00 00 } /* MZ header */`,
        `  condition:`,
        `    uint16(0) == 0x5a4d and 2 of ($tech*, $cve*) and any of ($tool*)`,
        `}`,
      ].join("\n");
    case "sigma":
      return [
        `title: OptraSight - Suspicious Activity Targeting ${techList.join(", ") || "Monitored Tech"}`,
        `id: ${(cveList[0] || "optrasight").toLowerCase().replace(/[^a-z0-9]/g, "-")}-${Date.now().toString(36)}`,
        `status: experimental`,
        `description: Detect potential exploitation aligned with ${cveList.join(", ") || "recent CVEs"}`,
        `author: OptraSight OSINT`,
        `tags:`,
        `    - attack.initial_access`,
        `    - attack.t1190`,
        `logsource:`,
        `    category: process_creation`,
        `    product: windows`,
        `detection:`,
        `    selection_tech:`,
        `        Image|contains:`,
        techList.map((t) => `            - '${t}'`).join("\n") || `            - 'product'`,
        `    selection_cve:`,
        `        CommandLine|contains:`,
        cveList.map((c) => `            - '${c}'`).join("\n") || `            - 'CVE-2024-XXXXX'`,
        `    suspicious_tools:`,
        `        CommandLine|contains:`,
        `            - '-EncodedCommand'`,
        `            - 'Invoke-Mimikatz'`,
        `            - 'certutil -urlcache'`,
        `    condition: (selection_tech or selection_cve) and suspicious_tools`,
        `falsepositives:`,
        `    - Vendor patching scripts`,
        `    - Authorised red-team activity`,
        `level: high`,
      ].join("\n");
    default:
      return `// Unsupported language: ${lang}\n// Generated for ${techList.join(", ")} / ${cveList.join(", ")}`;
  }
}

function mockThreatLandscape(
  clientName: string,
  profile: ClientProfileDTO,
  recent: OsintFindingDTO[],
): string {
  const today = new Date().toISOString().slice(0, 10);
  const sevCounts = recent.reduce<Record<string, number>>((m, f) => {
    m[f.severity] = (m[f.severity] || 0) + 1;
    return m;
  }, {});
  const topTech = (() => {
    const tally: Record<string, number> = {};
    recent.forEach((f) => (f.affectedTech || []).forEach((t) => (tally[t] = (tally[t] || 0) + 1)));
    return Object.entries(tally).sort((a, b) => b[1] - a[1]).slice(0, 6);
  })();
  const topCves = (() => {
    const tally: Record<string, number> = {};
    recent.forEach((f) => (f.cveIds || []).forEach((c) => (tally[c] = (tally[c] || 0) + 1)));
    return Object.entries(tally).sort((a, b) => b[1] - a[1]).slice(0, 8);
  })();
  const topActors = (() => {
    const tally: Record<string, number> = {};
    recent.forEach((f) => (f.threatActors || []).forEach((a) => (tally[a] = (tally[a] || 0) + 1)));
    return Object.entries(tally).sort((a, b) => b[1] - a[1]).slice(0, 6);
  })();
  const industries = (profile.industries || []).join(", ") || "(unspecified)";
  const geos = (profile.geos || []).join(", ") || "(unspecified)";
  const services = (profile.clientTypes || []).join(", ") || "(unspecified)";
  const techWatch = (profile.monitoredTechnologies || []).slice(0, 12).join(", ") || "(no watchlist configured)";

  return [
    `# Threat Landscape — ${clientName}`,
    ``,
    `**Date:** ${today}`,
    `**Industries:** ${industries}`,
    `**Geographies:** ${geos}`,
    `**Subscribed services:** ${services}`,
    ``,
    `## Executive Summary`,
    ``,
    `Across the last reporting window, OptraSight ingested **${recent.length}** correlated OSINT items relevant to ${clientName}'s monitored technology stack and operating regions. Severity distribution: ${Object.entries(sevCounts).map(([k, v]) => `**${v}** ${k}`).join(", ") || "no findings"}. The dominant exposure vectors are concentrated around ${topTech.slice(0, 3).map(([t]) => `\`${t}\``).join(", ") || "perimeter and identity infrastructure"}, consistent with the broader threat trend of opportunistic edge-device exploitation followed by credential pivoting.`,
    ``,
    `## Threat Actor Activity`,
    ``,
    topActors.length
      ? topActors.map(([a, c]) => `- **${a}** — ${c} corroborating reports across the period.`).join("\n")
      : `No named-actor activity correlated to the client profile in this window. Continue monitoring commodity-criminal and ransomware-affiliate channels.`,
    ``,
    `## Most-Mentioned CVEs`,
    ``,
    topCves.length
      ? topCves.map(([c, n]) => `- \`${c}\` — referenced in ${n} item(s)`).join("\n")
      : `- No high-volume CVE mentions intersecting the watchlist this period.`,
    ``,
    `## Affected Technology (intersection with watchlist)`,
    ``,
    topTech.length
      ? topTech.map(([t, n]) => `- **${t}** — ${n} report(s)`).join("\n")
      : `- No matches against the watchlist (${techWatch}). Re-evaluate whether the watchlist reflects current architecture.`,
    ``,
    `## Sector & Regional Context`,
    ``,
    `Operations covering **${industries}** in **${geos}** are most frequently targeted via:`,
    `1. **Edge / VPN exploitation** — ungated administrative interfaces remain the single largest initial-access driver.`,
    `2. **Identity-provider compromise** — phishing, MFA-fatigue, and OAuth consent abuse against ${profile.executiveEmails?.length ? "named executive accounts" : "executive identities"}.`,
    `3. **Supply-chain & MSP abuse** — particularly relevant for clients consuming ${services}.`,
    ``,
    `## Recommendations (next 30 days)`,
    ``,
    `1. Patch verification across the watchlist (${techWatch}) — confirm coverage on the top-mentioned CVEs above.`,
    `2. Hunt: deploy the OptraSight-generated hunt queries (Splunk / KQL / Chronicle / MDE / CrowdStrike / Cortex XDR / SentinelOne / YARA / Sigma) for the top 3 affected technologies.`,
    `3. Validate detective controls for **${topActors[0]?.[0] || "the leading commodity ransomware affiliates"}** TTPs — ingress, lateral movement, and exfiltration paths.`,
    `4. Brief executive contacts (${(profile.contacts || []).map((c) => c.name).slice(0, 3).join(", ") || "primary contacts"}) on regional ransomware activity intersecting the industry.`,
    `5. Re-baseline the OSINT watchlist quarterly to reflect technology drift.`,
    ``,
    `## Methodology`,
    ``,
    `This report is automatically generated by OptraSight's threat-landscape engine using the configured AI provider, OSINT findings collected from 500+ sources, and the client profile (industries / geographies / monitored technologies / subscribed services). Each finding is correlated against the watchlist before inclusion. Numerical statistics in this report reflect raw counts of correlated items and are not weighted for source reliability.`,
    ``,
    `*Report version stored — see Version History to compare against prior periods.*`,
  ].join("\n");
}
