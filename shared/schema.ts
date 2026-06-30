import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// ----- Tenants -----
export const tenants = sqliteTable("tenants", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  plan: text("plan").notNull().default("starter"),
  createdAt: text("created_at").notNull(),
});

// brand_keywords/monitored_domains/etc stored as JSON-encoded text columns.
// v2.4 adds client-profile fields: type, geos, industries, monitoredTechnologies,
// notification routing.
export const tenantScopes = sqliteTable("tenant_scopes", {
  tenantId: text("tenant_id").primaryKey(),
  brandKeywords: text("brand_keywords").notNull().default("[]"),
  monitoredDomains: text("monitored_domains").notNull().default("[]"),
  ipRanges: text("ip_ranges").notNull().default("[]"),
  executiveEmails: text("executive_emails").notNull().default("[]"),
  // Multi-select client classification
  clientTypes: text("client_types").notNull().default("[]"),       // MSS|MDR|CIR|TI|RT|VCISO
  geos: text("geos").notNull().default("[]"),                       // ISO codes + regional aggregates
  industries: text("industries").notNull().default("[]"),           // BANKING|HEALTHCARE|...
  monitoredTechnologies: text("monitored_technologies").notNull().default("[]"), // tech ids for OSINT
  notificationEmails: text("notification_emails").notNull().default("[]"),
});

// ----- OSINT sources catalog (500+ feeds) -----
export const osintSources = sqliteTable("osint_sources", {
  id: text("id").primaryKey(),
  category: text("category").notNull(), // CVE|VENDOR|CERT|RANSOMWARE|RSS|SOCIAL|PASTE|TELEGRAM|DARKWEB|GHSA|GOV
  name: text("name").notNull(),
  url: text("url").notNull(),
  language: text("language").notNull().default("en"),
  region: text("region"),
  reliability: text("reliability").notNull().default("B"), // NATO admiralty A-F
  enabled: integer("enabled").notNull().default(1),
  lastFetchedAt: text("last_fetched_at"),
});

// ----- OSINT findings (intel items) -----
export const osintFindings = sqliteTable("osint_findings", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  sourceId: text("source_id").notNull(),
  title: text("title").notNull(),
  url: text("url"),
  publishedAt: text("published_at").notNull(),
  severity: text("severity").notNull().default("medium"),
  cveIds: text("cve_ids").notNull().default("[]"),
  affectedTech: text("affected_tech").notNull().default("[]"),
  threatActors: text("threat_actors").notNull().default("[]"),
  /** v2.29 — AI classification of the intel item. One of
   *  'threat_intel' | 'regular_report' | 'advertisement' | null (unanalysed). */
  intelCategory: text("intel_category"),
  /** v2.30 — AI-extracted MITRE ATT&CK techniques, JSON array of
   *  { id: string; name?: string; tactic?: string }. Nullable for unanalysed. */
  attackTechniques: text("attack_techniques"),
  /** v2.30 — AI-extracted sector tags, JSON array of strings
   *  (e.g. ['finance','healthcare']). Nullable for unanalysed. */
  sectors: text("sectors"),
  /** v2.30 — AI-extracted geographic regions, JSON array of strings
   *  (e.g. ['apac','emea','global']). Nullable for unanalysed. */
  regions: text("regions"),
  /** v2.30 — Similarity-cluster id used to dedup near-duplicate findings
   *  across sources (rule-based on ingest). Nullable for unclustered. */
  clusterId: text("cluster_id"),
  // v2.8 — extracted Indicators of Compromise, JSON of
  // { ipv4: string[]; ipv6: string[]; domain: string[]; url: string[];
  //   md5: string[]; sha1: string[]; sha256: string[]; email: string[]; btc: string[] }
  iocs: text("iocs").notNull().default("{}"),
  // v2.8 — SHA-1 over normalised (title + host) used for cross-source dedupe.
  contentHash: text("content_hash"),
  summary: text("summary"),
  rawSnippet: text("raw_snippet"),
  // AI enrichment (null until analyzed)
  aiSummary: text("ai_summary"),
  aiRelevanceScore: integer("ai_relevance_score"), // 0-100
  aiRecommendation: text("ai_recommendation"),
  aiAnalyzedAt: text("ai_analyzed_at"),
  aiProviderLabel: text("ai_provider_label"),
  // Email draft (null until generated)
  draftEmail: text("draft_email"),
  draftEmailAt: text("draft_email_at"),
  // Analyst triage
  status: text("status").notNull().default("new"), // new|triaged|dismissed|escalated
  createdAt: text("created_at").notNull(),
});

// ----- Threat hunting queries (AI-generated, multi-language) -----
export const huntQueries = sqliteTable("hunt_queries", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  sourceFindingIds: text("source_finding_ids").notNull().default("[]"),
  affectedTech: text("affected_tech").notNull().default("[]"),
  // languages stored as JSON: { splunk: "...", kql_elk: "...", ... }
  queries: text("queries").notNull().default("{}"),
  aiProviderLabel: text("ai_provider_label"),
  createdAt: text("created_at").notNull(),
  createdBy: text("created_by").notNull(),
});

// ----- Threat landscape reports (AI-generated, versioned) -----
export const threatLandscapes = sqliteTable("threat_landscapes", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  version: integer("version").notNull().default(1),
  title: text("title").notNull(),
  status: text("status").notNull().default("generating"),
  bodyMd: text("body_md"),
  stats: text("stats").notNull().default("{}"), // top actors, top sectors, geos covered
  aiProviderLabel: text("ai_provider_label"),
  createdAt: text("created_at").notNull(),
  createdBy: text("created_by").notNull(),
});

// ----- Detection rules (v2.30.2 — Detection Rule Studio) -----
// A detection rule is a versioned, deployable asset derived from one or more
// OSINT findings (or authored manually). It carries the Sigma YAML, the
// per-SIEM compiled queries, MITRE mapping, severity, and a draft/approved/
// archived lifecycle. Each rule has zero or more `rule_deployments` rows
// (one per SIEM platform) that track push status.
export const detectionRules = sqliteTable("detection_rules", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  // Source intel that justifies this rule. JSON array of OSINT finding ids.
  sourceFindingIds: text("source_finding_ids").notNull().default("[]"),
  // Lifecycle: draft | reviewed | approved | archived
  status: text("status").notNull().default("draft"),
  severity: text("severity").notNull().default("medium"), // low|medium|high|critical
  // MITRE ATT&CK mapping: JSON array of { id, name?, tactic? }
  mitreTechniques: text("mitre_techniques").notNull().default("[]"),
  // Technologies the rule covers; JSON string array.
  affectedTech: text("affected_tech").notNull().default("[]"),
  // Threat actors referenced; JSON string array.
  threatActors: text("threat_actors").notNull().default("[]"),
  // Sigma YAML — canonical cross-platform rule source.
  sigmaYaml: text("sigma_yaml"),
  // Per-SIEM compiled queries: JSON { splunk: "...", kql_elk: "...", ... }
  queries: text("queries").notNull().default("{}"),
  // Author's notes / tuning guidance.
  notes: text("notes"),
  // Monotonic version counter; bumped on each save.
  version: integer("version").notNull().default(1),
  aiProviderLabel: text("ai_provider_label"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
  createdBy: text("created_by").notNull(),
});

// One row per (rule, SIEM platform) tracking the deployment lifecycle. A rule
// may be deployed to multiple SIEMs; status is independent per platform.
export const ruleDeployments = sqliteTable("rule_deployments", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  ruleId: text("rule_id").notNull(),
  // Target SIEM/EDR id — matches a HuntLangId (splunk, kql_elk, defender, ...)
  siemId: text("siem_id").notNull(),
  // "push" = platform attempted a real API call; "manual" = analyst flipped
  // the switch themselves (no API call made).
  mode: text("mode").notNull().default("manual"),
  // pending | deployed | failed | rolled_back
  status: text("status").notNull().default("pending"),
  // ID returned by the SIEM (saved search id, rule id, etc.) when push mode
  // succeeds. Free-form for manual deployments.
  externalId: text("external_id"),
  // Last attempt outcome (error message / success summary).
  message: text("message"),
  // Snapshot of rule.version at the time of deployment.
  ruleVersion: integer("rule_version").notNull().default(1),
  deployedAt: text("deployed_at"),
  deployedBy: text("deployed_by"),
  updatedAt: text("updated_at").notNull(),
});

// ----- Audit log (security events) -----
export const auditLog = sqliteTable("audit_log", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  actor: text("actor").notNull(),  // user email
  action: text("action").notNull(), // asset.upload|asset.delete|provider.create|...
  target: text("target"),
  detail: text("detail").notNull().default("{}"),
  createdAt: text("created_at").notNull(),
});

// ----- Users -----
export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  accountType: text("account_type").notNull().default("platform"),
  role: text("role").notNull().default("threat_intel_expert"),
  displayName: text("display_name"),
  status: text("status").notNull().default("active"),
  passwordMustChange: integer("password_must_change", { mode: "boolean" }).notNull().default(false),
  mfaEnabled: integer("mfa_enabled", { mode: "boolean" }).notNull().default(false),
  mfaSecretEnc: text("mfa_secret_enc"),
  mfaVerifiedAt: text("mfa_verified_at"),
  failedLoginCount: integer("failed_login_count").notNull().default(0),
  failedMfaCount: integer("failed_mfa_count").notNull().default(0),
  accountLockedUntil: text("account_locked_until"),
  createdAt: text("created_at"),
  lastLoginAt: text("last_login_at"),
});

// ----- Assets -----
export const assets = sqliteTable("assets", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  kind: text("kind").notNull(), // domain|subdomain|ip|url
  value: text("value").notNull(),
  sourceTool: text("source_tool"),
  technologies: text("technologies").notNull().default("[]"),
  riskScore: integer("risk_score").notNull().default(0),
  discoveredAt: text("discovered_at").notNull(),
});

// ----- Scans -----
export const scans = sqliteTable("scans", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  kind: text("kind").notNull(),
  tool: text("tool").notNull(),
  status: text("status").notNull().default("queued"),
  target: text("target"),
  config: text("config").notNull().default("{}"),
  findingCount: integer("finding_count").notNull().default(0),
  createdAt: text("created_at").notNull(),
  startedAt: text("started_at"),
  finishedAt: text("finished_at"),
  log: text("log"),
});

// ----- Findings -----
// `evidence_source` distinguishes data produced by a real scanner / API call
// (`live`) from curated pitch/demo seeding (`demo`) and from AI-inferred
// derivations (`ai_inferred`). Defaults to `demo` so the existing bundled
// data/data.db rows are correctly classified until real scanners regenerate
// them. The UI hides `demo` rows by default in strict production mode.
export const findings = sqliteTable("findings", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  scanId: text("scan_id"),
  type: text("type").notNull(), // lookalike|vulnerability|exposure|osint
  severity: text("severity").notNull().default("medium"),
  title: text("title").notNull(),
  description: text("description"),
  target: text("target"),
  sourceTool: text("source_tool"),
  status: text("status").notNull().default("open"),
  extra: text("extra").notNull().default("{}"),
  evidenceSource: text("evidence_source").notNull().default("demo"),
  createdAt: text("created_at").notNull(),
});

export const EVIDENCE_SOURCES = ["live", "demo", "ai_inferred"] as const;
export type EvidenceSource = typeof EVIDENCE_SOURCES[number];

// ----- Evidence -----
export const evidence = sqliteTable("evidence", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  findingId: text("finding_id"),
  kind: text("kind").notNull(),
  status: text("status").notNull().default("queued"),
  url: text("url"),
  artifactUrl: text("artifact_url"),
  extra: text("extra").notNull().default("{}"),
  createdAt: text("created_at").notNull(),
});

// ----- Per-tenant integration config (key/enabled state) -----
export const integrations = sqliteTable("integrations", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  toolId: text("tool_id").notNull(),
  enabled: integer("enabled").notNull().default(1), // 0/1 boolean
  apiKeyEnc: text("api_key_enc"),     // AES-GCM ciphertext base64 (demo: base64-only)
  apiSecretEnc: text("api_secret_enc"),
  apiKeyMask: text("api_key_mask"),   // last 4 chars for display
  apiSecretMask: text("api_secret_mask"),
  config: text("config").notNull().default("{}"),
  lastTestedAt: text("last_tested_at"),
  lastTestOk: integer("last_test_ok"), // 0/1/null
  lastTestMessage: text("last_test_message"),
  updatedAt: text("updated_at").notNull(),
});

// ----- Client brand assets (logos, trademarks, app icons) -----
export const clientAssets = sqliteTable("client_assets", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  kind: text("kind").notNull(), // logo | trademark | app_icon
  name: text("name").notNull(),
  mime: text("mime").notNull(),
  size: integer("size").notNull(),
  sha256: text("sha256").notNull(),
  data: text("data").notNull(), // base64 payload — demo storage; production should use S3
  jurisdiction: text("jurisdiction"), // for trademarks: HK, SG, CN, MY, US, etc.
  registeredMark: text("registered_mark"), // trademark registration #
  notes: text("notes"),
  createdAt: text("created_at").notNull(),
});

// ----- AI providers (per-tenant) -----
// v2.4 adds DeepSeek to the provider list.
export const aiProviders = sqliteTable("ai_providers", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  provider: text("provider").notNull(), // openai | anthropic | gemini | azure-openai | ollama | perplexity | deepseek | kimi
  label: text("label").notNull(),
  model: text("model").notNull(),
  baseUrl: text("base_url"),
  apiKeyEnc: text("api_key_enc"),
  apiKeyMask: text("api_key_mask"),
  enabled: integer("enabled").notNull().default(1),
  isDefault: integer("is_default").notNull().default(0),
  lastTestedAt: text("last_tested_at"),
  lastTestOk: integer("last_test_ok"),
  lastTestMessage: text("last_test_message"),
  config: text("config").notNull().default("{}"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// ----- AI task assignments — which provider handles which capability -----
export const aiTaskAssignments = sqliteTable("ai_task_assignments", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  task: text("task").notNull(), // triage | analysis | young_domain | report_summary | logo_abuse
  providerId: text("provider_id").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// ----- Generated reports -----
export const reports = sqliteTable("reports", {
  id: text("id").primaryKey(),
  authorTenantId: text("author_tenant_id").notNull(), // who created it
  authorEmail: text("author_email").notNull(),
  title: text("title").notNull(),
  kind: text("kind").notNull(), // executive|brand_abuse|attack_surface|full
  tenantIds: text("tenant_ids").notNull().default("[]"), // JSON array
  tenantNames: text("tenant_names").notNull().default("[]"),
  scanCount: integer("scan_count").notNull().default(0),
  findingCount: integer("finding_count").notNull().default(0),
  criticalCount: integer("critical_count").notNull().default(0),
  status: text("status").notNull().default("generating"), // generating|ready|failed
  bodyMd: text("body_md"),  // rendered markdown
  bodyHtml: text("body_html"),
  stats: text("stats").notNull().default("{}"),
  createdAt: text("created_at").notNull(),
});

// ----- Investigations: analyst case workspace ------------------------------
export const investigations = sqliteTable("investigations", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  title: text("title").notNull(),
  status: text("status").notNull().default("open"),
  severity: text("severity").notNull().default("medium"),
  summary: text("summary"),
  assignee: text("assignee"),
  sourceType: text("source_type"),
  sourceId: text("source_id"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
  createdBy: text("created_by").notNull(),
});

export const investigationLinks = sqliteTable("investigation_links", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  investigationId: text("investigation_id").notNull(),
  entityType: text("entity_type").notNull(),
  entityId: text("entity_id").notNull(),
  label: text("label"),
  createdAt: text("created_at").notNull(),
  createdBy: text("created_by").notNull(),
});

export const investigationNotes = sqliteTable("investigation_notes", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  investigationId: text("investigation_id").notNull(),
  kind: text("kind").notNull().default("analyst"),
  body: text("body").notNull(),
  createdAt: text("created_at").notNull(),
  createdBy: text("created_by").notNull(),
});

export const INVESTIGATION_STATUSES = ["open", "investigating", "contained", "monitoring", "closed"] as const;
export type InvestigationStatus = typeof INVESTIGATION_STATUSES[number];
export const INVESTIGATION_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type InvestigationSeverity = typeof INVESTIGATION_SEVERITIES[number];
const investigationSeveritySchema = z.preprocess((value) => {
  if (typeof value !== "string") return value;
  const normalized = value.trim().toLowerCase();
  if (normalized === "moderate") return "medium";
  if (normalized === "informational") return "info";
  return normalized;
}, z.enum(INVESTIGATION_SEVERITIES));
export const INVESTIGATION_ENTITY_TYPES = [
  "finding", "osint_finding", "threat_actor", "domain_candidate",
  "detection_rule", "exercise", "evidence",
] as const;
export type InvestigationEntityType = typeof INVESTIGATION_ENTITY_TYPES[number];

export interface InvestigationDTO {
  id: string;
  tenantId: string;
  title: string;
  status: InvestigationStatus;
  severity: InvestigationSeverity;
  summary: string | null;
  assignee: string | null;
  sourceType: InvestigationEntityType | null;
  sourceId: string | null;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  linkCount?: number;
  noteCount?: number;
}

export interface InvestigationLinkDTO {
  id: string;
  tenantId: string;
  investigationId: string;
  entityType: InvestigationEntityType;
  entityId: string;
  label: string | null;
  createdAt: string;
  createdBy: string;
}

export interface InvestigationNoteDTO {
  id: string;
  tenantId: string;
  investigationId: string;
  kind: "analyst" | "ai" | "system";
  body: string;
  createdAt: string;
  createdBy: string;
}

export interface InvestigationFullDTO extends InvestigationDTO {
  links: InvestigationLinkDTO[];
  notes: InvestigationNoteDTO[];
  timeline: Array<{ id: string; type: string; title: string; at: string; detail?: string | null }>;
  iocs: FindingIoCs;
  relatedActors: Array<{ id: string; name: string; profileId?: string }>;
  recommendedDetections: Array<{ id: string; title: string; status: string; severity: string }>;
}

export interface StixPreviewDTO {
  valid: boolean;
  objectCount: number;
  objectCounts: Record<string, number>;
  indicatorCount: number;
  reportCount: number;
  attackPatternCount: number;
  relationshipCount: number;
  findingCount: number;
  warnings: string[];
  errors: string[];
}

export const investigationCreateSchema = z.object({
  title: z.string().min(2).max(180),
  severity: investigationSeveritySchema.optional().default("medium"),
  summary: z.string().max(4000).optional().nullable(),
  assignee: z.string().max(160).optional().nullable(),
  sourceType: z.enum(INVESTIGATION_ENTITY_TYPES).optional().nullable(),
  sourceId: z.string().optional().nullable(),
});

export const investigationPatchSchema = z.object({
  title: z.string().min(2).max(180).optional(),
  status: z.enum(INVESTIGATION_STATUSES).optional(),
  severity: investigationSeveritySchema.optional(),
  summary: z.string().max(4000).optional().nullable(),
  assignee: z.string().max(160).optional().nullable(),
});

export const investigationLinkSchema = z.object({
  entityType: z.enum(INVESTIGATION_ENTITY_TYPES),
  entityId: z.string().min(1),
  label: z.string().max(260).optional().nullable(),
});

export const investigationNoteSchema = z.object({
  kind: z.enum(["analyst", "ai", "system"]).optional().default("analyst"),
  body: z.string().min(1).max(12000),
});

export interface SearchResultDTO {
  id: string;
  type: string;
  title: string;
  subtitle: string;
  href: string;
  severity?: string | null;
  status?: string | null;
  tenantName?: string | null;
  action?: "open" | "investigate" | "triage" | "generate_detection" | "copy";
  copyValue?: string | null;
}

export type CoverageState = "observed_no_rule" | "rule_draft" | "rule_reviewed" | "deployed" | "validated";
export interface AttackCoverageTechniqueDTO {
  id: string;
  name: string;
  tactic: string;
  state: CoverageState;
  observedCount: number;
  actorCount: number;
  ruleCount: number;
  deployedCount: number;
  tenants: string[];
  links: Array<{ type: string; id: string; label: string; href: string; tenantName?: string | null }>;
}
export interface AttackCoverageDTO {
  generatedAt: string;
  scope: "tenant" | "global";
  techniques: AttackCoverageTechniqueDTO[];
}

// ----- Insert schemas -----
export const insertTenantSchema = createInsertSchema(tenants).omit({ id: true, createdAt: true });
export const insertScanSchema = createInsertSchema(scans).omit({
  id: true, createdAt: true, startedAt: true, finishedAt: true,
  status: true, findingCount: true, log: true,
});
export const insertScopeSchema = z.object({
  brandKeywords: z.array(z.string()),
  monitoredDomains: z.array(z.string()),
  ipRanges: z.array(z.string()),
  executiveEmails: z.array(z.string()),
});
export const triageSchema = z.object({
  status: z.enum(["open", "investigating", "takedown", "false_positive", "resolved"]),
  note: z.string().optional(),
});
export const PLATFORM_USER_ROLES = ["admin", "threat_intel_expert", "detection_engineer", "reviewer"] as const;
export const complexPasswordSchema = z.string()
  .min(12, "password must be at least 12 characters")
  .regex(/[a-z]/, "password must include a lowercase letter")
  .regex(/[A-Z]/, "password must include an uppercase letter")
  .regex(/[0-9]/, "password must include a number")
  .regex(/[^A-Za-z0-9]/, "password must include a symbol");
export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
  mfaCode: z.string().trim().regex(/^\d{6}$/, "MFA code must be 6 digits").optional(),
});
export const passwordChangeSchema = z.object({
  currentPassword: z.string(),
  newPassword: complexPasswordSchema,
});
export const mfaVerifySchema = z.object({
  code: z.string().trim().regex(/^\d{6}$/, "MFA code must be 6 digits"),
});
export const platformUserCreateSchema = z.object({
  email: z.string().email(),
  password: complexPasswordSchema,
  tenantId: z.string().min(1),
  displayName: z.string().trim().min(1).optional(),
  role: z.enum(PLATFORM_USER_ROLES).default("threat_intel_expert"),
  status: z.enum(["active", "disabled"]).default("active"),
});
export const platformUserUpdateSchema = z.object({
  email: z.string().email().optional(),
  password: complexPasswordSchema.optional(),
  tenantId: z.string().min(1).optional(),
  displayName: z.string().trim().min(1).nullable().optional(),
  role: z.enum(PLATFORM_USER_ROLES).optional(),
  status: z.enum(["active", "disabled"]).optional(),
});
export const platformUserBulkActionSchema = z.object({
  userIds: z.array(z.string().min(1)).min(1),
  action: z.enum(["disable", "delete"]),
});
export const scanRequestSchema = z.object({
  target: z.string().optional(),
  targets: z.array(z.string()).optional(),
  config: z.record(z.any()).optional(),
});
export const evidenceUrlScanSchema = z.object({
  url: z.string().url(),
  findingId: z.string().optional(),
});

export type Tenant = typeof tenants.$inferSelect;
export type TenantScope = typeof tenantScopes.$inferSelect;
export type User = typeof users.$inferSelect;
export type Asset = typeof assets.$inferSelect;
export type Scan = typeof scans.$inferSelect;
export type Finding = typeof findings.$inferSelect;
export type Evidence = typeof evidence.$inferSelect;

// ---- DTOs returned to client (parsed JSON columns) ----
export interface AssetDTO extends Omit<Asset, "technologies"> {
  technologies: string[];
}
export interface FindingDTO extends Omit<Finding, "extra"> {
  extra: Record<string, any>;
}
export interface EvidenceDTO extends Omit<Evidence, "extra"> {
  extra: Record<string, any>;
}

export const SCAN_KINDS = [
  "discovery", "lookalikes", "newly-registered", "vulnerabilities",
  "ports", "fingerprint", "osint", "passive-intel",
  "dorking", "logo-abuse", "cyberspace-search", "threat-intel",
  "passive-dns", "reputation", "ip-reputation",
  "malicious-site-scanner",
] as const;
export type ScanKind = typeof SCAN_KINDS[number];

// Multi-kind batch scan request
export const multiScanRequestSchema = z.object({
  kinds: z.array(z.enum(SCAN_KINDS)).min(1, "select at least one scan kind"),
  target: z.string().optional(),
  targets: z.array(z.string()).optional(),
  config: z.record(z.any()).optional(),
});

export const SCAN_KIND_TO_TOOLS: Record<ScanKind, string[]> = {
  discovery: ["amass", "subfinder", "wappalyzer"],
  lookalikes: ["dnstwist"],
  "newly-registered": ["opensquat"],
  vulnerabilities: ["nuclei"],
  ports: ["nmap"],
  fingerprint: ["wappalyzer"],
  osint: ["theharvester", "spiderfoot"],
  "passive-intel": ["shodan", "censys"],
  dorking: ["dorkscan"],
  "logo-abuse": ["tineye"],
  "cyberspace-search": ["fofa"],
  "threat-intel": ["kela"],
  "passive-dns": ["securitytrails"],
  reputation: ["virustotal"],
  "ip-reputation": ["abuseipdb"],
  "malicious-site-scanner": ["dnstwist", "opensquat", "crtsh", "domscan", "keyword_expansion"],
};

// ----- AI task taxonomy -----
export const AI_TASKS = [
  "triage", "analysis", "young_domain", "report_summary", "logo_abuse",
  "osint_analysis", "hunt_query", "threat_landscape",
  "osint_overview", "osint_chat", "detection_rule",
  // v2.30.3 — Threat Actor Profile enrichment (DeepSeek populates all 13
  // sections + appendices from primaryName + aliases).
  "threat_actor_enrichment",
  // Provider-backed image generation for TAP portraits. This lets BatchOne use
  // encrypted AI Setup credentials instead of requiring a local image CLI.
  "tap_portrait",
] as const;
export type AiTask = typeof AI_TASKS[number];

export const BATCH_ONE_AI_TASKS = [
  "osint_analysis",
  "osint_overview",
  "osint_chat",
  "hunt_query",
  "threat_actor_enrichment",
  "tap_portrait",
] as const satisfies readonly AiTask[];

export const AI_PROVIDERS = [
  "openai", "anthropic", "gemini", "azure-openai", "ollama", "perplexity", "deepseek", "kimi",
] as const;
export type AiProviderKind = typeof AI_PROVIDERS[number];

// ----- Client classification taxonomies -----
export const CLIENT_TYPES = [
  { id: "MSS",         label: "MSS — Managed Security Service" },
  { id: "MDR",         label: "MDR — Managed Detection & Response" },
  { id: "CIR",         label: "CIR — Cyber Incident Response" },
  { id: "TI",          label: "Threat Intelligence" },
  { id: "RED_TEAM",    label: "Red Team / Offensive" },
  { id: "VCISO",       label: "vCISO / Advisory" },
] as const;
export type ClientTypeId = typeof CLIENT_TYPES[number]["id"];

// Geographies — APAC sub-regions, EMEA, AMER + regional aggregates
export const GEOS = [
  { id: "APAC",  label: "APAC (region)",        kind: "region" },
  { id: "HK",    label: "Hong Kong SAR",        kind: "country" },
  { id: "TW",    label: "Taiwan",               kind: "country" },
  { id: "CN",    label: "Mainland China",       kind: "country" },
  { id: "MY",    label: "Malaysia",             kind: "country" },
  { id: "SG",    label: "Singapore",            kind: "country" },
  { id: "JP",    label: "Japan",                kind: "country" },
  { id: "KR",    label: "South Korea",          kind: "country" },
  { id: "AU",    label: "Australia",            kind: "country" },
  { id: "NZ",    label: "New Zealand",          kind: "country" },
  { id: "IN",    label: "India",                kind: "country" },
  { id: "PH",    label: "Philippines",          kind: "country" },
  { id: "TH",    label: "Thailand",             kind: "country" },
  { id: "VN",    label: "Vietnam",              kind: "country" },
  { id: "ID",    label: "Indonesia",            kind: "country" },
  { id: "EMEA",  label: "EMEA (region)",        kind: "region" },
  { id: "UK",    label: "United Kingdom",       kind: "country" },
  { id: "DE",    label: "Germany",              kind: "country" },
  { id: "FR",    label: "France",               kind: "country" },
  { id: "IT",    label: "Italy",                kind: "country" },
  { id: "NL",    label: "Netherlands",          kind: "country" },
  { id: "ES",    label: "Spain",                kind: "country" },
  { id: "AE",    label: "United Arab Emirates", kind: "country" },
  { id: "SA",    label: "Saudi Arabia",         kind: "country" },
  { id: "ZA",    label: "South Africa",         kind: "country" },
  { id: "AMER",  label: "Americas (region)",    kind: "region" },
  { id: "US",    label: "United States",        kind: "country" },
  { id: "CA",    label: "Canada",               kind: "country" },
  { id: "BR",    label: "Brazil",               kind: "country" },
  { id: "MX",    label: "Mexico",               kind: "country" },
] as const;
export type GeoId = typeof GEOS[number]["id"];

export const INDUSTRIES = [
  { id: "BANKING",        label: "Banking" },
  { id: "INSURANCE",      label: "Insurance" },
  { id: "CAPITAL_MARKETS",label: "Capital Markets / Securities" },
  { id: "FINTECH",        label: "FinTech" },
  { id: "CRYPTO",         label: "Crypto / Web3" },
  { id: "HEALTHCARE",     label: "Healthcare Providers" },
  { id: "PHARMA",         label: "Pharmaceuticals" },
  { id: "BIOTECH",        label: "BioTech" },
  { id: "GOVERNMENT",     label: "Government / Public Sector" },
  { id: "DEFENSE",        label: "Defense / Aerospace" },
  { id: "ENERGY",         label: "Energy / Oil & Gas" },
  { id: "UTILITIES",      label: "Utilities (Power / Water)" },
  { id: "MANUFACTURING",  label: "Manufacturing" },
  { id: "AUTOMOTIVE",     label: "Automotive" },
  { id: "RETAIL",         label: "Retail / E-commerce" },
  { id: "TELECOM",        label: "Telecommunications" },
  { id: "TECH",           label: "Technology / SaaS" },
  { id: "EDUCATION",      label: "Education / Research" },
  { id: "LOGISTICS",      label: "Transportation / Logistics" },
  { id: "HOSPITALITY",    label: "Hospitality / Travel" },
  { id: "MEDIA",          label: "Media / Entertainment" },
  { id: "LEGAL",          label: "Legal / Professional Services" },
  { id: "REAL_ESTATE",    label: "Real Estate" },
  { id: "NGO",            label: "NGO / Non-profit" },
  { id: "CRITICAL_INFRA", label: "Critical Infrastructure (general)" },
] as const;
export type IndustryId = typeof INDUSTRIES[number]["id"];

// ----- Commonly exploited technologies (OSINT watchlist) -----
export const MONITORED_TECHNOLOGIES = [
  // Edge / VPN — perennially exploited
  { id: "fortinet-fortios",    label: "Fortinet FortiOS / FortiGate",      category: "Edge / VPN" },
  { id: "fortinet-fortimail",  label: "Fortinet FortiMail",                category: "Edge / VPN" },
  { id: "fortinet-fortimanager", label: "Fortinet FortiManager",           category: "Edge / VPN" },
  { id: "citrix-netscaler",    label: "Citrix NetScaler / ADC / Gateway",  category: "Edge / VPN" },
  { id: "ivanti-connectsecure",label: "Ivanti Connect Secure / Pulse",     category: "Edge / VPN" },
  { id: "ivanti-epm",          label: "Ivanti Endpoint Manager",           category: "Edge / VPN" },
  { id: "paloalto-globalprotect", label: "Palo Alto GlobalProtect / PAN-OS", category: "Edge / VPN" },
  { id: "sonicwall-sma",       label: "SonicWall SMA / SSL-VPN",           category: "Edge / VPN" },
  { id: "checkpoint-quantum",  label: "Check Point Quantum Gateway",        category: "Edge / VPN" },
  { id: "cisco-asa",           label: "Cisco ASA / Firepower / FTD",       category: "Edge / VPN" },
  { id: "cisco-iosxe",         label: "Cisco IOS XE",                      category: "Network" },
  { id: "f5-bigip",            label: "F5 BIG-IP",                         category: "Edge / VPN" },
  { id: "barracuda-esg",       label: "Barracuda Email Security Gateway",  category: "Email" },
  // Mail / collaboration
  { id: "ms-exchange",         label: "Microsoft Exchange Server",         category: "Email / Collab" },
  { id: "ms-sharepoint",       label: "Microsoft SharePoint Server",       category: "Email / Collab" },
  { id: "zimbra",              label: "Zimbra Collaboration",              category: "Email / Collab" },
  // Identity / SSO
  { id: "okta",                label: "Okta",                              category: "Identity" },
  { id: "ms-entra",            label: "Microsoft Entra ID / Azure AD",     category: "Identity" },
  { id: "adfs",                label: "AD FS",                             category: "Identity" },
  // Hypervisor / virt
  { id: "vmware-vcenter",      label: "VMware vCenter",                    category: "Virtualisation" },
  { id: "vmware-esxi",         label: "VMware ESXi",                       category: "Virtualisation" },
  { id: "vmware-horizon",      label: "VMware Horizon",                    category: "Virtualisation" },
  { id: "citrix-xen",          label: "Citrix Hypervisor / XenServer",     category: "Virtualisation" },
  // Web / app
  { id: "atlassian-confluence",label: "Atlassian Confluence",              category: "Web / Collab" },
  { id: "atlassian-jira",      label: "Atlassian Jira",                    category: "Web / Collab" },
  { id: "atlassian-bitbucket", label: "Atlassian Bitbucket",               category: "Source" },
  { id: "gitlab",              label: "GitLab",                            category: "Source" },
  { id: "github-enterprise",   label: "GitHub Enterprise Server",          category: "Source" },
  { id: "jenkins",             label: "Jenkins",                           category: "CI/CD" },
  { id: "teamcity",            label: "JetBrains TeamCity",                category: "CI/CD" },
  // App frameworks
  { id: "log4j",               label: "Apache Log4j",                      category: "Library" },
  { id: "spring-framework",    label: "Spring Framework",                  category: "Framework" },
  { id: "spring-cloud",        label: "Spring Cloud Gateway / Function",   category: "Framework" },
  { id: "struts2",             label: "Apache Struts 2",                   category: "Framework" },
  { id: "apache-httpd",        label: "Apache HTTP Server",                category: "Web" },
  { id: "nginx",               label: "NGINX / NGINX Plus",                category: "Web" },
  { id: "tomcat",              label: "Apache Tomcat",                     category: "Web" },
  // File transfer
  { id: "moveit",              label: "Progress MOVEit Transfer",          category: "File Transfer" },
  { id: "goanywhere-mft",      label: "Fortra GoAnywhere MFT",             category: "File Transfer" },
  { id: "cleo-harmony",        label: "Cleo Harmony / VLTrader / LexiCom", category: "File Transfer" },
  // Backup / DR
  { id: "veeam",               label: "Veeam Backup & Replication",        category: "Backup" },
  { id: "commvault",           label: "Commvault",                         category: "Backup" },
  // RMM / remote access
  { id: "connectwise-screenconnect", label: "ConnectWise ScreenConnect",   category: "RMM" },
  { id: "kaseya-vsa",          label: "Kaseya VSA",                        category: "RMM" },
  { id: "teamviewer",          label: "TeamViewer",                        category: "RMM" },
  { id: "anydesk",             label: "AnyDesk",                           category: "RMM" },
  // Database
  { id: "oracle-weblogic",     label: "Oracle WebLogic",                   category: "App Server" },
  { id: "mssql-server",        label: "Microsoft SQL Server",              category: "Database" },
  { id: "postgresql",          label: "PostgreSQL",                        category: "Database" },
  { id: "mongodb",             label: "MongoDB",                           category: "Database" },
  { id: "elasticsearch",       label: "Elasticsearch / OpenSearch",        category: "Database" },
  // OT / ICS
  { id: "siemens-s7",          label: "Siemens SIMATIC S7",                category: "OT / ICS" },
  { id: "rockwell-controllogix", label: "Rockwell ControlLogix",          category: "OT / ICS" },
  { id: "schneider-modicon",   label: "Schneider Electric Modicon",        category: "OT / ICS" },
  // SaaS / cloud
  { id: "salesforce",          label: "Salesforce",                        category: "SaaS" },
  { id: "servicenow",          label: "ServiceNow",                        category: "SaaS" },
  { id: "snowflake",           label: "Snowflake",                         category: "SaaS / Data" },
  { id: "aws-iam",             label: "AWS IAM / S3 / Console",            category: "Cloud" },
  { id: "azure",               label: "Microsoft Azure",                   category: "Cloud" },
  { id: "gcp",                 label: "Google Cloud Platform",             category: "Cloud" },
  // Endpoint / EDR
  { id: "crowdstrike-falcon",  label: "CrowdStrike Falcon",                category: "Endpoint" },
  { id: "sentinelone",         label: "SentinelOne Singularity",           category: "Endpoint" },
  { id: "cortex-xdr",          label: "Palo Alto Cortex XDR",              category: "Endpoint" },
  { id: "defender-endpoint",   label: "Microsoft Defender for Endpoint",   category: "Endpoint" },
  // Browser / runtime
  { id: "chrome",              label: "Google Chrome / Chromium",          category: "Browser" },
  { id: "firefox",             label: "Mozilla Firefox",                   category: "Browser" },
  { id: "node-runtime",        label: "Node.js Runtime",                   category: "Runtime" },
] as const;
export type MonitoredTechId = typeof MONITORED_TECHNOLOGIES[number]["id"];

// ----- Hunt query languages -----
export const HUNT_LANGUAGES = [
  { id: "splunk",        label: "Splunk SPL" },
  { id: "kql_elk",       label: "ELK KQL (Kibana / Elastic)" },
  { id: "chronicle",     label: "Google Chronicle YARA-L 2.0" },
  { id: "defender",      label: "Microsoft Defender / Sentinel KQL" },
  { id: "crowdstrike",   label: "CrowdStrike Falcon LogScale (CQL)" },
  { id: "cortex_xdr",    label: "Palo Alto Cortex XDR (XQL)" },
  { id: "sentinelone",   label: "SentinelOne PowerQuery" },
  { id: "yara",          label: "YARA" },
  { id: "sigma",         label: "Sigma (YAML)" },
] as const;
export type HuntLangId = typeof HUNT_LANGUAGES[number]["id"];

// ----- Young domain monitoring presets -----
export const YOUNG_DOMAIN_PRESETS = [
  { id: "microsoft-365",  name: "Microsoft 365 / Office 365",      seeds: ["login.microsoftonline.com", "office.com", "outlook.com", "microsoft.com"] },
  { id: "sharepoint",     name: "SharePoint Online",                seeds: ["sharepoint.com", "onedrive.live.com"] },
  { id: "google-workspace", name: "Google Workspace",                seeds: ["accounts.google.com", "workspace.google.com", "docs.google.com"] },
  { id: "docusign",       name: "DocuSign",                         seeds: ["docusign.com", "docusign.net"] },
  { id: "adobe-cloud",    name: "Adobe Creative / Sign",            seeds: ["adobe.com", "adobesign.com"] },
  { id: "dropbox",        name: "Dropbox",                          seeds: ["dropbox.com"] },
  { id: "zoom",           name: "Zoom",                             seeds: ["zoom.us"] },
  { id: "slack",          name: "Slack",                            seeds: ["slack.com"] },
  { id: "atlassian",      name: "Atlassian / Jira / Confluence",    seeds: ["atlassian.com", "atlassian.net"] },
  { id: "salesforce",     name: "Salesforce",                       seeds: ["salesforce.com", "force.com"] },
  { id: "okta",           name: "Okta",                             seeds: ["okta.com", "oktapreview.com"] },
  { id: "github",         name: "GitHub",                           seeds: ["github.com"] },
  { id: "paypal",         name: "PayPal",                           seeds: ["paypal.com"] },
] as const;
export type YoungDomainPresetId = typeof YOUNG_DOMAIN_PRESETS[number]["id"];

export const REPORT_KINDS = ["executive", "brand_abuse", "attack_surface", "full"] as const;
export type ReportKind = typeof REPORT_KINDS[number];

export const integrationUpdateSchema = z.object({
  enabled: z.boolean().optional(),
  apiKey: z.string().optional(),
  apiSecret: z.string().optional(),
  config: z.record(z.any()).optional(),
});
export const reportRequestSchema = z.object({
  tenantIds: z.array(z.string()).min(1),
  kind: z.enum(REPORT_KINDS).default("full"),
  scanIds: z.array(z.string()).optional(),
  title: z.string().optional(),
  includeEvidence: z.boolean().default(true),
});

export type Integration = typeof integrations.$inferSelect;
export type Report = typeof reports.$inferSelect;
export type ClientAsset = typeof clientAssets.$inferSelect;
export type AiProvider = typeof aiProviders.$inferSelect;
export type AiTaskAssignment = typeof aiTaskAssignments.$inferSelect;
export type OsintSource = typeof osintSources.$inferSelect;
export type OsintFinding = typeof osintFindings.$inferSelect;
export type HuntQuery = typeof huntQueries.$inferSelect;
export type ThreatLandscape = typeof threatLandscapes.$inferSelect;
export type AuditLogEntry = typeof auditLog.$inferSelect;
export type DetectionRule = typeof detectionRules.$inferSelect;
export type RuleDeployment = typeof ruleDeployments.$inferSelect;

// ---- OSINT schemas ----
export const osintScanSchema = z.object({
  technologies: z.array(z.string()).optional(),  // override tenant watchlist
  categories: z.array(z.string()).optional(),    // filter by source category
  maxFindings: z.number().int().min(1).max(200).default(60),
  mode: z.enum(["real", "mock", "auto"]).default("auto"),  // auto = try real, fall back to mock
});

/**
 * Human-readable English labels for OSINT source categories.
 * The DB stores compact codes (CVE, GHSA, GOV, …); the API surfaces these
 * labels so the dashboard always renders an English description, regardless
 * of the analyst's locale.
 */
export const OSINT_CATEGORY_LABELS: Record<string, string> = {
  // v2.11 6-bucket taxonomy
  CVE_VULN:         "CVE & Vulnerability DBs",
  CERT_GOV:         "CERT / Government Advisories",
  VENDOR_RESEARCH:  "Vendor Threat Research",
  THREAT_INTEL:     "Threat Intelligence Feeds",
  SECURITY_NEWS:    "Security News & Press",
  RANSOMWARE_LEAK:  "Ransomware & Data-Leak Feeds",
  // legacy codes (kept so any pre-v2.10 row that survives is still labelled)
  CVE:         "CVE & Vulnerability DBs",
  GHSA:        "CVE & Vulnerability DBs",
  VENDOR:      "Vendor Threat Research",
  CERT:        "CERT / Government Advisories",
  GOV:         "CERT / Government Advisories",
  RANSOMWARE:  "Ransomware & Data-Leak Feeds",
  RSS:         "Security News & Press",
};

export const OSINT_CATEGORY_ORDER: readonly string[] = [
  "CVE_VULN",
  "CERT_GOV",
  "VENDOR_RESEARCH",
  "THREAT_INTEL",
  "SECURITY_NEWS",
  "RANSOMWARE_LEAK",
] as const;

/**
 * AI overview persona — controls the lens through which findings are
 * summarised on the Findings tab.
 */
export const OSINT_OVERVIEW_PERSONAS = [
  { id: "ir",     label: "Incident Response",      blurb: "Detect-respond-recover lens; what to contain, what to escalate, what playbook applies." },
  { id: "ti",     label: "Threat Intelligence",    blurb: "Actor-centric lens; campaigns, TTPs, infrastructure pivots, attribution confidence." },
  { id: "secops", label: "Security Operations",   blurb: "Detection-engineering lens; coverage gaps, hunting candidates, SIEM/EDR rule deltas." },
] as const;
export type OsintOverviewPersona = typeof OSINT_OVERVIEW_PERSONAS[number]["id"];

export const osintOverviewSchema = z.object({
  persona: z.enum(["ir", "ti", "secops"]).default("ir"),
  category: z.string().optional(),          // limit to a single source category (e.g. CVE, RANSOMWARE)
  severity: z.string().optional(),
  scope: z.enum(["client", "global", "industry", "geo"]).default("client"),
  scopeIds: z.array(z.string()).optional(), // only for scope != client
});
export const osintAnalyzeSchema = z.object({
  ids: z.array(z.string()).optional(),
  onlyUnanalyzed: z.boolean().default(true),
});
/**
 * Source row enriched for the dashboard — adds an English display name
 * (translated when the upstream name is non-Latin) and a parsed-finding
 * counter so analysts know which feeds are actually producing intel.
 */
/**
 * AI overview generated for the Findings tab. Persona-tuned summary, key
 * takeaways and recommendations across a scope (tenant / global / category).
 */
export interface OsintOverviewResultDTO {
  persona: OsintOverviewPersona;
  personaLabel: string;
  scopeLabel: string;          // e.g. "BatchOne Workspace"
  category: string | null;     // null = all categories
  severityFilter: string | null;
  findingCount: number;
  summary: string;             // 2-4 sentence overview
  keyTakeaways: string[];      // bullet list — 3-6 items
  recommendations: string[];   // bullet list — 3-6 items, persona-shaped
  generatedAt: string;
  providerLabel: string | null;
}

export interface OsintSourceRowDTO {
  id: string;
  category: string;
  categoryLabel: string;
  name: string;
  englishName: string;       // identical to name when already English; translated otherwise
  url: string;
  language: string;
  region: string | null;
  reliability: string;
  kind: string;              // computed: 'json' | 'rss' | 'web' (best-effort from URL)
  findingCount: number;      // total osint_findings rows pointing at this source across all tenants
  lastFetchedAt: string | null;
  /** v2.29 — source enabled flag (1 = on, 0 = paused, no fetches scheduled). */
  enabled: boolean;
}

/** v2.29 — KPI strip above the Sources tab. */
export interface OsintSourcesKpisDTO {
  totalSources: number;
  sourcesReturningIntel: number;     // distinct source_id with at least 1 finding in the last 30 days
  intelParsedToday: number;          // osint_findings rows whose published_at OR created_at falls in today
  enabledCount: number;
  disabledCount: number;
}

/** v2.29 — payload for the Sources usability dashboard. */
export interface OsintSourcesAnalyticsDTO {
  /** Last 30 days, ordered most-recent last. */
  trend: Array<{ day: string; count: number }>;
  topByContribution: Array<{ sourceId: string; name: string; categoryLabel: string; count: number }>;
  topByThreatIntel: Array<{ sourceId: string; name: string; categoryLabel: string; count: number }>;
  topByClientEmail: Array<{ sourceId: string; name: string; categoryLabel: string; count: number }>;
}

/**
 * v2.30 — Composite "actionability" scorecard per source. Sub-metrics each in
 * 0..1; score is a weighted average rendered 0..100. All last-30-day window.
 */
export interface OsintSourceScoreRow {
  sourceId: string;
  name: string;
  categoryLabel: string;
  totalFindings: number;
  // Sub-metrics, each normalised 0..1.
  iocDensity: number;          // mean IoC count per finding, capped at 5 → /5
  analystConversionRate: number; // draft_email IS NOT NULL / total
  severitySkew: number;        // (critical+high) / total
  threatIntelRatio: number;    // threat_intel / (categorised total)
  freshnessLagHours: number;   // raw median lag in hours — NOT normalised
  freshnessScore: number;      // 1 - clamp(lag_hours / 72, 0, 1)
  // Composite 0..100. Weights documented in storage.ts.
  actionabilityScore: number;
}

/** v2.30 — Noise-vs-signal quadrant point per source. */
export interface OsintSourceQuadrantPoint {
  sourceId: string;
  name: string;
  categoryLabel: string;
  volumePerDay: number;     // findings per day (30d avg)
  threatIntelRatio: number; // 0..1
  analystConversionRate: number; // 0..1, used for bubble size
  totalFindings: number;
}

/** v2.30 — Dedup / overlap analytics. */
export interface OsintSourceOverlapDTO {
  // For each source: unique-finding rate (findings not duplicated by any other
  // source within the cluster window).
  uniqueRate: Array<{ sourceId: string; name: string; uniqueRate: number; total: number; uniqueCount: number }>;
  // "First to publish" — how many times this source published the earliest
  // finding in a cluster shared with at least one other source.
  firstToPublish: Array<{ sourceId: string; name: string; firstCount: number; shareTotal: number }>;
  // Top-15 source x source co-occurrence matrix (count of shared clusters).
  coOccurrence: {
    sourceIds: string[];
    sourceNames: string[];
    matrix: number[][]; // square N x N, diagonal = own cluster count
  };
}

/** v2.30 — ATT&CK and sector heatmaps (sources × dimension). */
export interface OsintSourceHeatmapsDTO {
  attack: {
    sourceIds: string[];
    sourceNames: string[];
    tactics: string[];                // tactic ids ordered TA0001..TA0011 etc.
    tacticLabels: string[];
    matrix: number[][];               // [source][tactic] = count
  };
  sectors: {
    sourceIds: string[];
    sourceNames: string[];
    dimensions: string[];             // mix of sectors + regions, top-N
    matrix: number[][];               // [source][dimension] = count
  };
}

/** v2.30 — Status of an admin-triggered bulk re-analyse job. */
export interface OsintReanalyzeJobDTO {
  id: string;
  status: "queued" | "running" | "done" | "failed" | "cancelled";
  totalCount: number;
  doneCount: number;
  failCount: number;
  startedAt: string;
  finishedAt: string | null;
  error: string | null;
}

/** v2.29 — bulk enable/disable/delete on osint_sources. */
export interface OsintSourcesBulkPatch {
  ids: string[];
  action: "enable" | "disable" | "delete";
}

// v2.8 — grouped IoCs extracted from each finding.
export interface FindingIoCs {
  ipv4?: string[];
  ipv6?: string[];
  domain?: string[];
  url?: string[];
  md5?: string[];
  sha1?: string[];
  sha256?: string[];
  email?: string[];
  btc?: string[];
}

export interface OsintFindingDTO {
  id: string;
  tenantId: string;
  sourceId: string;
  sourceName: string;
  sourceCategory: string;
  sourceFetchedAt?: string | null;
  title: string;
  url: string | null;
  publishedAt: string;
  severity: string;
  cveIds: string[];
  affectedTech: string[];
  threatActors: string[];
  /** v2.8 — IoCs parsed from the title + summary + raw snippet. */
  iocs: FindingIoCs;
  summary: string | null;
  aiSummary: string | null;
  aiRelevanceScore: number | null;
  aiRecommendation: string | null;
  aiAnalyzedAt: string | null;
  aiProviderLabel: string | null;
  draftEmail: string | null;
  draftEmailAt: string | null;
  status: string;
  createdAt: string;
  rawSnippet?: string | null;
  // v2.17 — analyst-curated free-form tags + audit fields.
  analystTags?: string[];
  analystEditedAt?: string | null;
  analystEditedBy?: string | null;
  // v2.29 — AI categorisation of the intel item.
  intelCategory?: "threat_intel" | "regular_report" | "advertisement" | null;
  // v2.30 — AI-extracted enrichment for analytics + detection-rule generation.
  attackTechniques?: Array<{ id: string; name?: string; tactic?: string }> | null;
  sectors?: string[] | null;
  regions?: string[] | null;
  clusterId?: string | null;
}

/** v2.17 — PATCH body for /api/v1/osint/findings/:fid. All fields optional;
 *  only provided fields are updated. status takes the extended finding-status
 *  enum (new|triaged|assessed|dismissed|escalated). */
export interface OsintFindingPatch {
  status?: "new" | "triaged" | "assessed" | "dismissed" | "escalated";
  cveIds?: string[];
  iocs?: FindingIoCs;
  analystTags?: string[];
  affectedTech?: string[];
  threatActors?: string[];
}

// ---- Hunt query schemas ----
export const huntQueryCreateSchema = z.object({
  findingIds: z.array(z.string()).min(1, "select at least one OSINT finding"),
  languages: z.array(z.string()).min(1, "select at least one query language"),
  title: z.string().optional(),
});
export interface HuntQueryDTO {
  id: string;
  tenantId: string;
  title: string;
  description: string | null;
  sourceFindingIds: string[];
  affectedTech: string[];
  queries: Record<string, string | string[]>; // langId -> single query or multiple queries
  aiProviderLabel: string | null;
  createdAt: string;
  createdBy: string;
}

// ---- Detection rule schemas (v2.30.2) ----
// SIEM/EDR platforms supported by Detection Rule Studio. Each id maps 1:1 to
// a HUNT_LANGUAGES id and to a SIEM connector id in the integrations catalog.
export const SIEM_TARGETS = [
  { id: "splunk",       label: "Splunk SPL",                          integrationId: "siem_splunk"      },
  { id: "kql_elk",      label: "Elastic / ELK (KQL)",                 integrationId: "siem_elastic"     },
  { id: "defender",     label: "Microsoft Sentinel / Defender (KQL)", integrationId: "siem_sentinel"    },
  { id: "crowdstrike",  label: "CrowdStrike Falcon (CQL)",            integrationId: "siem_crowdstrike" },
  { id: "cortex_xdr",   label: "Palo Alto Cortex XDR (XQL)",          integrationId: "siem_cortex_xdr"  },
  { id: "sentinelone",  label: "SentinelOne (PowerQuery)",            integrationId: "siem_sentinelone" },
  { id: "chronicle",    label: "Google Chronicle (YARA-L)",           integrationId: "siem_chronicle"   },
  { id: "sigma",        label: "Sigma (YAML)",                        integrationId: null               },
] as const;
export type SiemTargetId = typeof SIEM_TARGETS[number]["id"];
export const SIEM_TARGET_IDS = SIEM_TARGETS.map((s) => s.id) as readonly SiemTargetId[];

// v2.30.2.3 — added 'reviewed' between draft and approved so the kanban
// board can split out analyst peer-review from final approval. Old rules
// with status='approved' continue to work unchanged.
export const RULE_STATUSES = ["draft", "reviewed", "approved", "archived"] as const;
export type RuleStatus = typeof RULE_STATUSES[number];
export const DEPLOYMENT_STATUSES = ["pending", "deployed", "failed", "rolled_back"] as const;
export type DeploymentStatus = typeof DEPLOYMENT_STATUSES[number];
export const DEPLOYMENT_MODES = ["push", "manual"] as const;
export type DeploymentMode = typeof DEPLOYMENT_MODES[number];

export const RULE_SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type RuleSeverity = typeof RULE_SEVERITIES[number];

/** POST /api/v1/detection-rules — generate-from-intel mode if findingIds present. */
export const detectionRuleCreateSchema = z.object({
  title: z.string().optional(),
  description: z.string().optional(),
  findingIds: z.array(z.string()).optional(),
  // Languages to emit; defaults to all SIEM targets if omitted.
  languages: z.array(z.string()).optional(),
  severity: z.enum(RULE_SEVERITIES).optional(),
  affectedTech: z.array(z.string()).optional(),
  threatActors: z.array(z.string()).optional(),
  // When true the server runs the AI to populate sigmaYaml + queries.
  // When false the rule is saved as an empty draft for manual authoring.
  generate: z.boolean().optional().default(true),
});

export const detectionRulePatchSchema = z.object({
  title: z.string().optional(),
  description: z.string().optional(),
  status: z.enum(RULE_STATUSES).optional(),
  severity: z.enum(RULE_SEVERITIES).optional(),
  sigmaYaml: z.string().nullable().optional(),
  queries: z.record(z.string()).optional(),
  notes: z.string().nullable().optional(),
  affectedTech: z.array(z.string()).optional(),
  threatActors: z.array(z.string()).optional(),
  mitreTechniques: z.array(z.object({ id: z.string(), name: z.string().optional(), tactic: z.string().optional() })).optional(),
});

export const detectionRuleDeploySchema = z.object({
  siemId: z.enum(SIEM_TARGETS.map((s) => s.id) as [SiemTargetId, ...SiemTargetId[]]),
  // "push" attempts the live integration call; "manual" just flips status.
  mode: z.enum(DEPLOYMENT_MODES).default("manual"),
  // When mode=manual the analyst can override the resulting status and add a
  // free-form externalId reference (e.g. ticket number).
  status: z.enum(DEPLOYMENT_STATUSES).optional(),
  externalId: z.string().optional(),
  message: z.string().optional(),
});

export interface RuleDeploymentDTO {
  id: string;
  ruleId: string;
  siemId: SiemTargetId;
  siemLabel: string;
  mode: DeploymentMode;
  status: DeploymentStatus;
  externalId: string | null;
  message: string | null;
  ruleVersion: number;
  deployedAt: string | null;
  deployedBy: string | null;
  updatedAt: string;
}

export interface DetectionRuleDTO {
  id: string;
  tenantId: string;
  title: string;
  description: string | null;
  sourceFindingIds: string[];
  status: RuleStatus;
  severity: RuleSeverity;
  mitreTechniques: Array<{ id: string; name?: string; tactic?: string }>;
  affectedTech: string[];
  threatActors: string[];
  sigmaYaml: string | null;
  queries: Record<string, string>;
  notes: string | null;
  version: number;
  aiProviderLabel: string | null;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  deployments: RuleDeploymentDTO[];
}

// ---- Threat landscape schemas ----
export const threatLandscapeGenerateSchema = z.object({
  title: z.string().optional(),
});
export interface ThreatLandscapeDTO {
  id: string;
  tenantId: string;
  version: number;
  title: string;
  status: string;
  bodyMd: string | null;
  stats: Record<string, any>;
  aiProviderLabel: string | null;
  createdAt: string;
  createdBy: string;
}

// ---- Tenant onboarding ----
export const tenantCreateSchema = z.object({
  name: z.string().min(2),
  slug: z.string().min(2).regex(/^[a-z0-9-]+$/, "lowercase letters, numbers, hyphens only"),
  plan: z.enum(["starter", "pro", "enterprise"]).default("pro"),
  brandKeywords: z.array(z.string()).default([]),
  monitoredDomains: z.array(z.string()).default([]),
  ipRanges: z.array(z.string()).default([]),
  executiveEmails: z.array(z.string()).default([]),
  primaryContactName: z.string().optional(),
  primaryContactEmail: z.string().email().optional(),
  industry: z.string().optional(),
  geographies: z.array(z.string()).default([]),
});

// ---- Asset upload ----
export const clientAssetUploadSchema = z.object({
  kind: z.enum(["logo", "trademark", "app_icon"]),
  name: z.string().min(1),
  mime: z.string().regex(/^image\//, "must be an image MIME type"),
  data: z.string().min(20), // base64 data URL or raw base64
  jurisdiction: z.string().optional(),
  registeredMark: z.string().optional(),
  notes: z.string().optional(),
});
export interface ClientAssetDTO {
  id: string;
  tenantId: string;
  kind: "logo" | "trademark" | "app_icon";
  name: string;
  mime: string;
  size: number;
  sha256: string;
  jurisdiction: string | null;
  registeredMark: string | null;
  notes: string | null;
  dataUrl: string; // data:image/...;base64,...
  createdAt: string;
}

// ---- Keyword expansion ----
export const keywordExpandSchema = z.object({
  base: z.array(z.string()).min(1, "at least one base keyword required"),
  domains: z.array(z.string()).default([]),
  techniques: z.array(z.string()).optional(), // 1..14 ids; if omitted all run
  tldList: z.array(z.string()).optional(),
  combosquatList: z.array(z.string()).optional(),
  sectorModifiers: z.array(z.string()).optional(),
  maxPerTechnique: z.number().int().min(1).max(500).default(50),
});
export interface KeywordVariant {
  variant: string;
  base: string;
  technique: string;        // id from the 14-technique list
  techniqueLabel: string;
  similarity: number;       // 0..1 (Levenshtein-derived)
  riskScore: number;        // 0..100
  notes?: string;
}
export interface KeywordExpansionDTO {
  inputs: string[];
  totalGenerated: number;
  uniqueCount: number;
  variants: KeywordVariant[];
  techniques: { id: string; label: string; count: number }[];
}

// ---- AI provider ----
export const aiProviderUpsertSchema = z.object({
  id: z.string().optional(),
  provider: z.enum(AI_PROVIDERS),
  label: z.string().min(1),
  model: z.string().min(1),
  baseUrl: z.string().url().optional().or(z.literal("")),
  apiKey: z.string().optional(),
  enabled: z.boolean().default(true),
  isDefault: z.boolean().default(false),
  config: z.record(z.any()).optional(),
});
export const aiAssignmentUpdateSchema = z.object({
  assignments: z.record(z.enum(AI_TASKS), z.string().min(1)),
});
export interface AiProviderSummary {
  id: string;
  provider: AiProviderKind;
  label: string;
  model: string;
  baseUrl: string | null;
  enabled: boolean;
  isDefault: boolean;
  hasKey: boolean;
  apiKeyMask: string | null;
  lastTestedAt: string | null;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
  updatedAt: string;
}

// ---- Malicious Site Scanner ----
export const youngDomainScanSchema = z.object({
  mode: z.enum(["tenant", "global", "both"]).default("both"),
  presetIds: z.array(z.string()).optional(),    // empty = all presets
  domains: z.array(z.string()).optional(),       // overrides tenant scope domains
  maxPerSeed: z.number().int().min(1).max(40).default(10),
});
export const YOUNG_DOMAIN_VERDICTS = [
  "phishing", "spoofing", "brand_impersonation", "forged_login", "parked_benign", "inconclusive",
] as const;
export type YoungDomainVerdict = typeof YOUNG_DOMAIN_VERDICTS[number];
export const MALICIOUS_SITE_STATUSES = [
  "cloudflare_blocked", "inaccessible", "http_200", "redirect", "parked", "login_page", "unknown",
] as const;
export type MaliciousSiteStatus = typeof MALICIOUS_SITE_STATUSES[number];

export interface YoungDomainCandidateDTO {
  id: string;
  domain: string;
  seed: string;
  source: "tenant" | "global";
  presetId?: string;
  presetName?: string;
  technique: string;
  registeredAt: string;
  ageDays: number;
  hasMx: boolean;
  hasA: boolean;
  similarity: number;
  riskScore: number;
  screenshotUrl: string | null;
  // Phase 1 — which discovery sources surfaced this domain.
  // Present on rows produced by the real-adapter pipeline; absent (or empty)
  // on legacy mock-seeded rows.
  discoveredBy?: Array<"dnstwist" | "opensquat" | "crtsh" | "domscan" | "keyword_expansion">;
  siteStatus?: MaliciousSiteStatus;
  brandAssetDetected?: boolean;
  matchedAssetKinds?: Array<"logo" | "trademark" | "app_icon">;
  visualSimilarity?: number | null;
  brandAbuse?: {
    source: string;
    generatedAt?: string;
    candidateAvailable?: boolean;
    matchCount?: number;
    topScore?: number;
    matches?: Array<{
      assetId: string;
      assetKind: "logo" | "trademark" | "app_icon";
      assetName: string;
      source: string;
      score: number;
      similarity?: Record<string, number>;
      template?: { score: number; box: { x: number; y: number; width: number; height: number; scale: number } | null };
    }>;
    error?: string;
  } | null;
  loginFormDetected?: boolean;
  cloudflareBlocked?: boolean;
  keyEvidence?: string[];
  recommendedActions?: string[];
  visionSupported?: boolean;
  // Phase 0 — `live` for real-adapter rows, `demo` for bundled / curated seed,
  // `ai_inferred` for AI-only derivations.
  evidenceSource?: EvidenceSource;
  // AI verdict (null until analyzed)
  verdict: YoungDomainVerdict;
  confidence: number;
  reasoning: string;
  targetBrand: string | null;
  aiProviderLabel: string | null;
  aiAnalyzed: boolean;
  aiAnalyzedAt: string | null;
  // Analyst assessment (null until reviewed by a human)
  analystVerdict: YoungDomainVerdict | null;
  analystNotes: string | null;
  analystAt: string | null;
  analystBy: string | null;
}

// Bulk AI analysis request
export const youngDomainAnalyzeSchema = z.object({
  source: z.enum(["tenant", "global", "both"]).default("both"),
  onlyUnanalyzed: z.boolean().default(true),
  ids: z.array(z.string()).optional(), // optional explicit subset
});
// Analyst assessment patch
export const youngDomainAssessmentSchema = z.object({
  analystVerdict: z.enum(YOUNG_DOMAIN_VERDICTS).nullable(),
  analystNotes: z.string().max(2000).nullable().optional(),
});

export interface IntegrationSummary {
  id: string;            // tool id
  name: string;
  layer: string;
  purpose?: string;
  license?: string;
  invocationKind?: string;
  requiredEnv: string[];
  enabled: boolean;
  hasCredentials: boolean;
  implemented?: boolean;
  configured?: boolean;
  liveTested?: boolean;
  statusLabel?: string;
  apiKeyMask?: string | null;
  apiSecretMask?: string | null;
  lastTestedAt?: string | null;
  lastTestOk?: boolean | null;
  lastTestMessage?: string | null;
  config?: Record<string, any>;
  scheduleDefault?: string;
  endpoint?: string;
}

// =============================================================================
// v2.30.3 — Threat Actor Profiles (TAP)
// =============================================================================
// A TAP is a versioned, structured threat-actor dossier modelled on the user's
// 13-section + 4-appendix template. The header + bodyMd give a human-readable
// document; sub-resource tables (ttps, tools, campaigns, iocs, references,
// detection rule links) give structured queryable data for the UI.

export const ACTOR_TYPES = [
  "Nation-State",
  "Ransomware-as-a-Service",
  "Ransomware Affiliate",
  "Organized Cybercrime",
  "Hacktivist",
  "Insider",
  "Mercenary",
  "Lone Actor",
  "Unknown",
] as const;
export type ActorType = typeof ACTOR_TYPES[number];

export const SPONSORSHIP_LEVELS = [
  "State-Sponsored",
  "State-Aligned",
  "State-Tolerated",
  "Independent",
  "Unknown",
] as const;
export type SponsorshipLevel = typeof SPONSORSHIP_LEVELS[number];

export const TLP_LEVELS = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] as const;
export type TlpLevel = typeof TLP_LEVELS[number];

export const THREAT_LEVELS = ["CRITICAL", "HIGH", "MODERATE", "LOW"] as const;
export type ThreatLevel = typeof THREAT_LEVELS[number];

export const INTENT_PROXIMITY = ["Direct", "Adjacent", "Opportunistic", "Indirect"] as const;
export type IntentProximity = typeof INTENT_PROXIMITY[number];

// Words-of-estimative-probability scale (Kent / NIC)
export const WEP_CONFIDENCE = [
  "Almost No Chance",
  "Very Unlikely",
  "Unlikely",
  "Roughly Even Chance",
  "Likely",
  "Very Likely",
  "Almost Certain",
] as const;
export type WepConfidence = typeof WEP_CONFIDENCE[number];

export const SOPHISTICATION_LEVELS = ["Strategic", "Advanced", "Intermediate", "Basic"] as const;
export type SophisticationLevel = typeof SOPHISTICATION_LEVELS[number];

// Admiralty grading — A..F for source reliability, 1..6 for information credibility.
export const ADMIRALTY_SOURCE = ["A", "B", "C", "D", "E", "F"] as const;
export type AdmiraltySource = typeof ADMIRALTY_SOURCE[number];
export const ADMIRALTY_INFO = ["1", "2", "3", "4", "5", "6"] as const;
export type AdmiraltyInfo = typeof ADMIRALTY_INFO[number];

export const IOC_TYPES = [
  "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email",
  "asn", "mutex", "regkey", "filename", "filepath", "cert_sha1", "btc_address",
] as const;
export type IocType = typeof IOC_TYPES[number];

export const TTP_STATUSES = ["confirmed", "suspected", "not-observed"] as const;
export type TtpStatus = typeof TTP_STATUSES[number];

export const DETECTION_PRIORITIES = ["P1", "P2", "P3", "P4"] as const;
export type DetectionPriority = typeof DETECTION_PRIORITIES[number];

export const TAP_STATUSES = ["draft", "reviewed", "approved", "archived"] as const;
export type TapStatus = typeof TAP_STATUSES[number];

// ----- threat_actors (header + body) -----
export const threatActors = sqliteTable("threat_actors", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  // TAP-NNN public identifier (auto-assigned, unique per tenant)
  profileId: text("profile_id").notNull(),
  // Canonical name analysts will use everywhere in the platform
  primaryName: text("primary_name").notNull(),
  mitreGroupId: text("mitre_group_id"),
  // JSON arrays of aliases — flat (free) and vendor-keyed (microsoft/crowdstrike/...)
  aliases: text("aliases").notNull().default("[]"),
  vendorNames: text("vendor_names").notNull().default("{}"),
  actorType: text("actor_type").notNull().default("Unknown"),
  sponsorship: text("sponsorship").notNull().default("Unknown"),
  assessedOrigin: text("assessed_origin"),
  originConfidence: text("origin_confidence"), // WEP scale
  sponsoringEntity: text("sponsoring_entity"),
  motivation: text("motivation").notNull().default("[]"), // JSON array
  activeSince: integer("active_since"),
  sophistication: text("sophistication").notNull().default("Intermediate"),
  tlp: text("tlp").notNull().default("AMBER"),
  admiraltySource: text("admiralty_source").notNull().default("B"),
  admiraltyInfo: text("admiralty_info").notNull().default("2"),
  wepConfidence: text("wep_confidence").notNull().default("Likely"),
  // Targeting profile (JSON arrays)
  targetSectors: text("target_sectors").notNull().default("[]"),
  targetRegions: text("target_regions").notNull().default("[]"),
  targetTechStack: text("target_tech_stack").notNull().default("[]"),
  orgSizePreference: text("org_size_preference"),
  intentProximity: text("intent_proximity").notNull().default("Opportunistic"),
  relevanceRating: text("relevance_rating"), // analyst-assigned rating vs tenant
  // Executive summary (§1)
  execWhat: text("exec_what"),
  execSoWhat: text("exec_so_what"),
  execWhatNow: text("exec_what_now"),
  threatLevel: text("threat_level").notNull().default("MODERATE"),
  threatLevelRationale: text("threat_level_rationale"),
  sectorActivelyTargeted: integer("sector_actively_targeted").notNull().default(0), // 0/1 boolean
  // Diamond Model (§6) — 4 quadrants + meta, stored as JSON blobs
  diamondAdversary: text("diamond_adversary").notNull().default("{}"),
  diamondCapability: text("diamond_capability").notNull().default("{}"),
  diamondInfrastructure: text("diamond_infrastructure").notNull().default("{}"),
  diamondVictim: text("diamond_victim").notNull().default("{}"),
  diamondMeta: text("diamond_meta").notNull().default("{}"),
  // Business impact matrix (§3) — keyed by Financial/Operational/Reputational/Regulatory/Data/Strategic
  businessImpact: text("business_impact").notNull().default("{}"),
  // Capability & resources (§4) — tier + evidence + funding/people/training/coordination
  capabilityProfile: text("capability_profile").notNull().default("{}"),
  // Infrastructure (§8) — hosting patterns blob
  infrastructureProfile: text("infrastructure_profile").notNull().default("{}"),
  // IR actions (§10) — { immediate: [], shortTerm: [], mediumTerm: [], strategic: [] }
  irActions: text("ir_actions").notNull().default("{}"),
  // Countermeasures (§11) — { d3fend: [], cisV8: [], iso27001: [] }
  countermeasures: text("countermeasures").notNull().default("{}"),
  // Forecast (§12)
  forecast: text("forecast"),
  // Extortion tactics (§7 — ransomware only)
  extortionTactics: text("extortion_tactics").notNull().default("{}"),
  // Full long-form markdown body (canonical narrative)
  bodyMd: text("body_md"),
  status: text("status").notNull().default("draft"), // reuses RULE_STATUSES set
  version: integer("version").notNull().default(1),
  cutoffDate: text("cutoff_date"),
  preparedBy: text("prepared_by"),
  aiProviderLabel: text("ai_provider_label"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
  createdBy: text("created_by").notNull(),
});

// ----- threat_actor_ttps (§5 MITRE ATT&CK matrix) -----
export const threatActorTtps = sqliteTable("threat_actor_ttps", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  actorId: text("actor_id").notNull(),
  tactic: text("tactic").notNull(), // e.g. "TA0001 Initial Access"
  techniqueId: text("technique_id").notNull(), // e.g. "T1566"
  subTechniqueId: text("sub_technique_id"), // e.g. "T1566.001"
  techniqueName: text("technique_name").notNull(),
  evidence: text("evidence"),
  status: text("status").notNull().default("suspected"),
  detectionPriority: text("detection_priority").notNull().default("P3"),
  createdAt: text("created_at").notNull(),
});

// ----- threat_actor_tools (§5 tooling/malware) -----
export const threatActorTools = sqliteTable("threat_actor_tools", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  actorId: text("actor_id").notNull(),
  name: text("name").notNull(),
  category: text("category"), // RAT, dropper, ransomware, recon, loader, post-ex
  purpose: text("purpose"),
  variants: text("variants").notNull().default("[]"), // JSON array
  hashOrRule: text("hash_or_rule"), // hash, YARA rule name, or Sigma reference
  confidence: text("confidence").notNull().default("Likely"),
  createdAt: text("created_at").notNull(),
});

// ----- threat_actor_campaigns (§7 timeline) -----
export const threatActorCampaigns = sqliteTable("threat_actor_campaigns", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  actorId: text("actor_id").notNull(),
  name: text("name").notNull(),
  period: text("period"), // "2023-06 → 2024-01"
  targetSector: text("target_sector"),
  targetGeography: text("target_geography"),
  initialAccess: text("initial_access"),
  outcome: text("outcome"),
  sourceUrl: text("source_url"),
  findingIds: text("finding_ids").notNull().default("[]"),
  ruleIds: text("rule_ids").notNull().default("[]"),
  createdAt: text("created_at").notNull(),
});

// ----- threat_actor_iocs (Appendix A) -----
export const threatActorIocs = sqliteTable("threat_actor_iocs", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  actorId: text("actor_id").notNull(),
  iocType: text("ioc_type").notNull(),
  value: text("value").notNull(),
  firstSeen: text("first_seen"),
  lastConfirmed: text("last_confirmed"),
  confidence: text("confidence").notNull().default("Likely"),
  tlp: text("tlp").notNull().default("AMBER"),
  source: text("source"),
  mitreTtps: text("mitre_ttps").notNull().default("[]"),
  recommendedAction: text("recommended_action"),
  createdAt: text("created_at").notNull(),
});

// ----- threat_actor_references (Appendix C) -----
export const threatActorReferences = sqliteTable("threat_actor_references", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  actorId: text("actor_id").notNull(),
  refNum: integer("ref_num").notNull(),
  sourceType: text("source_type"), // Vendor Report | Government | Academic | News | Blog | Other
  title: text("title").notNull(),
  date: text("date"),
  url: text("url"),
  archiveUrl: text("archive_url"),
  createdAt: text("created_at").notNull(),
});

// ----- threat_actor_detection_rules (Bridge to detection_rules; §9) -----
export const threatActorDetectionRules = sqliteTable("threat_actor_detection_rules", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  actorId: text("actor_id").notNull(),
  ruleId: text("rule_id").notNull(),
  priority: text("priority").notNull().default("P3"),
  notes: text("notes"),
  createdAt: text("created_at").notNull(),
});

// ----- threat_actor_tenants (Cross-tenant relevance tagging; v2.30.5) -----
// One row per (actor, tenant) pairing. Lets analysts and the AI mark which
// tenants are targeted/relevant for a given threat actor. The owning tenant
// is `ownerTenantId` (the tenant whose TAP this is); `tenantId` is the tagged
// client tenant. Both must be valid tenant ids.
export const threatActorTenants = sqliteTable("threat_actor_tenants", {
  id: text("id").primaryKey(),
  ownerTenantId: text("owner_tenant_id").notNull(),
  actorId: text("actor_id").notNull(),
  tenantId: text("tenant_id").notNull(),
  // 'targeted' = direct evidence the actor has attacked this tenant
  // 'sector-match' = actor targets the tenant's sector / region / size profile
  // 'watching' = analyst is monitoring as a possible future threat
  relevance: text("relevance").notNull().default("watching"),
  rationale: text("rationale"),
  taggedBy: text("tagged_by"), // user id, or 'ai' when taggedByAi=true
  taggedByAi: integer("tagged_by_ai", { mode: "boolean" }).notNull().default(false),
  createdAt: text("created_at").notNull(),
});

// ----- DTOs -----
export interface ThreatActorTtpDTO {
  id: string;
  actorId: string;
  tactic: string;
  techniqueId: string;
  subTechniqueId: string | null;
  techniqueName: string;
  evidence: string | null;
  status: TtpStatus;
  detectionPriority: DetectionPriority;
  createdAt: string;
}

export interface ThreatActorToolDTO {
  id: string;
  actorId: string;
  name: string;
  category: string | null;
  purpose: string | null;
  variants: string[];
  hashOrRule: string | null;
  confidence: WepConfidence;
  createdAt: string;
}

export interface ThreatActorCampaignDTO {
  id: string;
  actorId: string;
  name: string;
  period: string | null;
  targetSector: string | null;
  targetGeography: string | null;
  initialAccess: string | null;
  outcome: string | null;
  sourceUrl: string | null;
  findingIds: string[];
  ruleIds: string[];
  createdAt: string;
}

export interface ThreatActorIocDTO {
  id: string;
  actorId: string;
  iocType: IocType;
  value: string;
  firstSeen: string | null;
  lastConfirmed: string | null;
  confidence: WepConfidence;
  tlp: TlpLevel;
  source: string | null;
  mitreTtps: string[];
  recommendedAction: string | null;
  createdAt: string;
}

export interface ThreatActorReferenceDTO {
  id: string;
  actorId: string;
  refNum: number;
  sourceType: string | null;
  title: string;
  date: string | null;
  url: string | null;
  archiveUrl: string | null;
  createdAt: string;
}

export interface ThreatActorRuleLinkDTO {
  id: string;
  actorId: string;
  ruleId: string;
  priority: DetectionPriority;
  notes: string | null;
  ruleTitle?: string;
  ruleStatus?: string;
  ruleMitreTechniques?: Array<{ id: string; name?: string; tactic?: string }>;
  createdAt: string;
}

export interface ThreatActorDTO {
  id: string;
  tenantId: string;
  profileId: string;
  primaryName: string;
  mitreGroupId: string | null;
  aliases: string[];
  vendorNames: Record<string, string[]>;
  actorType: ActorType;
  sponsorship: SponsorshipLevel;
  assessedOrigin: string | null;
  originConfidence: WepConfidence | null;
  sponsoringEntity: string | null;
  motivation: string[];
  activeSince: number | null;
  sophistication: SophisticationLevel;
  tlp: TlpLevel;
  admiraltySource: AdmiraltySource;
  admiraltyInfo: AdmiraltyInfo;
  wepConfidence: WepConfidence;
  targetSectors: string[];
  targetRegions: string[];
  targetTechStack: string[];
  orgSizePreference: string | null;
  intentProximity: IntentProximity;
  relevanceRating: string | null;
  execWhat: string | null;
  execSoWhat: string | null;
  execWhatNow: string | null;
  threatLevel: ThreatLevel;
  threatLevelRationale: string | null;
  sectorActivelyTargeted: boolean;
  diamondAdversary: Record<string, any>;
  diamondCapability: Record<string, any>;
  diamondInfrastructure: Record<string, any>;
  diamondVictim: Record<string, any>;
  diamondMeta: Record<string, any>;
  businessImpact: Record<string, any>;
  capabilityProfile: Record<string, any>;
  infrastructureProfile: Record<string, any>;
  irActions: Record<string, any>;
  countermeasures: Record<string, any>;
  forecast: string | null;
  extortionTactics: Record<string, any>;
  bodyMd: string | null;
  status: TapStatus;
  version: number;
  cutoffDate: string | null;
  preparedBy: string | null;
  aiProviderLabel: string | null;
  // v2.32 — AI-generated portrait. portraitUrl is a relative path (e.g. /portraits/<id>.png)
  // served as a static file by the Express server. portraitStatus tracks the lifecycle so the
  // frontend can render a spinner / fallback while generation is in flight.
  portraitUrl: string | null;
  portraitGeneratedAt: string | null;
  portraitStatus: "idle" | "generating" | "ready" | "failed";
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export type TenantRelevance = "targeted" | "sector-match" | "watching";
export const TENANT_RELEVANCES: TenantRelevance[] = ["targeted", "sector-match", "watching"];

export interface ThreatActorTenantDTO {
  id: string;
  actorId: string;
  tenantId: string;
  tenantName?: string;
  tenantSector?: string | null;
  tenantRegion?: string | null;
  relevance: TenantRelevance;
  rationale: string | null;
  taggedBy: string | null;
  taggedByAi: boolean;
  createdAt: string;
}

export interface ThreatActorFullDTO extends ThreatActorDTO {
  ttps: ThreatActorTtpDTO[];
  tools: ThreatActorToolDTO[];
  campaigns: ThreatActorCampaignDTO[];
  iocs: ThreatActorIocDTO[];
  references: ThreatActorReferenceDTO[];
  ruleLinks: ThreatActorRuleLinkDTO[];
  relevantTenants: ThreatActorTenantDTO[];
}

// ----- Zod schemas -----
export const threatActorCreateSchema = z.object({
  primaryName: z.string().min(2),
  aliases: z.array(z.string()).optional().default([]),
  actorType: z.enum(ACTOR_TYPES).optional().default("Unknown"),
  sponsorship: z.enum(SPONSORSHIP_LEVELS).optional().default("Unknown"),
  mitreGroupId: z.string().optional().nullable(),
  motivation: z.array(z.string()).optional().default([]),
  tlp: z.enum(TLP_LEVELS).optional().default("AMBER"),
  // When true, server immediately calls DeepSeek to populate all 13 sections.
  // When false the actor is saved as an empty shell for manual authoring.
  enrich: z.boolean().optional().default(false),
});

export const threatActorPatchSchema = z.object({
  primaryName: z.string().min(2).optional(),
  mitreGroupId: z.string().nullable().optional(),
  aliases: z.array(z.string()).optional(),
  vendorNames: z.record(z.array(z.string())).optional(),
  actorType: z.enum(ACTOR_TYPES).optional(),
  sponsorship: z.enum(SPONSORSHIP_LEVELS).optional(),
  assessedOrigin: z.string().nullable().optional(),
  originConfidence: z.enum(WEP_CONFIDENCE).nullable().optional(),
  sponsoringEntity: z.string().nullable().optional(),
  motivation: z.array(z.string()).optional(),
  activeSince: z.number().int().nullable().optional(),
  sophistication: z.enum(SOPHISTICATION_LEVELS).optional(),
  tlp: z.enum(TLP_LEVELS).optional(),
  admiraltySource: z.enum(ADMIRALTY_SOURCE).optional(),
  admiraltyInfo: z.enum(ADMIRALTY_INFO).optional(),
  wepConfidence: z.enum(WEP_CONFIDENCE).optional(),
  targetSectors: z.array(z.string()).optional(),
  targetRegions: z.array(z.string()).optional(),
  targetTechStack: z.array(z.string()).optional(),
  orgSizePreference: z.string().nullable().optional(),
  intentProximity: z.enum(INTENT_PROXIMITY).optional(),
  relevanceRating: z.string().nullable().optional(),
  execWhat: z.string().nullable().optional(),
  execSoWhat: z.string().nullable().optional(),
  execWhatNow: z.string().nullable().optional(),
  threatLevel: z.enum(THREAT_LEVELS).optional(),
  threatLevelRationale: z.string().nullable().optional(),
  sectorActivelyTargeted: z.boolean().optional(),
  diamondAdversary: z.record(z.any()).optional(),
  diamondCapability: z.record(z.any()).optional(),
  diamondInfrastructure: z.record(z.any()).optional(),
  diamondVictim: z.record(z.any()).optional(),
  diamondMeta: z.record(z.any()).optional(),
  businessImpact: z.record(z.any()).optional(),
  capabilityProfile: z.record(z.any()).optional(),
  infrastructureProfile: z.record(z.any()).optional(),
  irActions: z.record(z.any()).optional(),
  countermeasures: z.record(z.any()).optional(),
  forecast: z.string().nullable().optional(),
  extortionTactics: z.record(z.any()).optional(),
  bodyMd: z.string().nullable().optional(),
  status: z.enum(TAP_STATUSES).optional(),
  cutoffDate: z.string().nullable().optional(),
  preparedBy: z.string().nullable().optional(),
});

export const threatActorEnrichSchema = z.object({
  // Replace existing content even if non-empty.
  force: z.boolean().optional().default(false),
  // Optional one-off provider override. When omitted, the resolver picks the
  // tenant default per the AI Setup assignments. Used by the TAP detail
  // sheet's "Re-enrich with…" picker (v2.30.6).
  providerId: z.string().uuid().nullable().optional(),
});

export const threatActorTtpSchema = z.object({
  tactic: z.string().min(1),
  techniqueId: z.string().min(1),
  subTechniqueId: z.string().nullable().optional(),
  techniqueName: z.string().min(1),
  evidence: z.string().nullable().optional(),
  status: z.enum(TTP_STATUSES).optional().default("suspected"),
  detectionPriority: z.enum(DETECTION_PRIORITIES).optional().default("P3"),
});

export const threatActorToolSchema = z.object({
  name: z.string().min(1),
  category: z.string().nullable().optional(),
  purpose: z.string().nullable().optional(),
  variants: z.array(z.string()).optional().default([]),
  hashOrRule: z.string().nullable().optional(),
  confidence: z.enum(WEP_CONFIDENCE).optional().default("Likely"),
});

export const threatActorCampaignSchema = z.object({
  name: z.string().min(1),
  period: z.string().nullable().optional(),
  targetSector: z.string().nullable().optional(),
  targetGeography: z.string().nullable().optional(),
  initialAccess: z.string().nullable().optional(),
  outcome: z.string().nullable().optional(),
  sourceUrl: z.string().nullable().optional(),
  findingIds: z.array(z.string()).optional().default([]),
  ruleIds: z.array(z.string()).optional().default([]),
});

export const threatActorIocSchema = z.object({
  iocType: z.enum(IOC_TYPES),
  value: z.string().min(1),
  firstSeen: z.string().nullable().optional(),
  lastConfirmed: z.string().nullable().optional(),
  confidence: z.enum(WEP_CONFIDENCE).optional().default("Likely"),
  tlp: z.enum(TLP_LEVELS).optional().default("AMBER"),
  source: z.string().nullable().optional(),
  mitreTtps: z.array(z.string()).optional().default([]),
  recommendedAction: z.string().nullable().optional(),
});

export const threatActorReferenceSchema = z.object({
  refNum: z.number().int().optional(),
  sourceType: z.string().nullable().optional(),
  title: z.string().min(1),
  date: z.string().nullable().optional(),
  url: z.string().nullable().optional(),
  archiveUrl: z.string().nullable().optional(),
});

export const threatActorRuleLinkSchema = z.object({
  ruleId: z.string().min(1),
  priority: z.enum(DETECTION_PRIORITIES).optional().default("P3"),
  notes: z.string().nullable().optional(),
});

export const threatActorTenantSchema = z.object({
  tenantId: z.string().min(1),
  relevance: z.enum(["targeted", "sector-match", "watching"] as const).optional().default("watching"),
  rationale: z.string().nullable().optional(),
});

export const threatActorTenantPatchSchema = z.object({
  relevance: z.enum(["targeted", "sector-match", "watching"] as const).optional(),
  rationale: z.string().nullable().optional(),
});

// ============================================================================
// Legacy full-platform exercise tables retained for DB compatibility.
// ============================================================================
//
// 5 tables:
//   exercises               — header, narrative, framework, status, source links
//   exercise_injects        — timeline of injects (email/chat/news/sensor/phone)
//   exercise_roles          — CISO/SOC/Legal/Comms/Exec/IT/etc. with role-brief
//   exercise_participants   — magic-link tokens per (exercise, role) participant
//   exercise_events         — facilitator timeline + responses + scores
//
// All TLD-style profile ids are `TTX-NNN` (auto-assigned, unique per tenant).

export const EXERCISE_STATUSES = ["draft", "scheduled", "running", "completed", "archived"] as const;
export type ExerciseStatus = typeof EXERCISE_STATUSES[number];

export const EXERCISE_FRAMEWORKS = ["hkma", "nist", "iso-sans"] as const;
export type ExerciseFramework = typeof EXERCISE_FRAMEWORKS[number];
export const EXERCISE_FRAMEWORK_LABEL: Record<ExerciseFramework, string> = {
  "hkma": "HKMA TM-G-2 / C-RAF + SFC",
  "nist": "NIST CSF 2.0 + SP 800-84",
  "iso-sans": "ISO 27035 + SANS PICERL",
};

export const EXERCISE_SEVERITIES = ["LOW", "MODERATE", "HIGH", "CRITICAL"] as const;
export type ExerciseSeverity = typeof EXERCISE_SEVERITIES[number];

export const EXERCISE_SCENARIO_TYPES = [
  "ransomware-affiliate",
  "supply-chain-vendor",
  "cloud-token-replay",
  "business-email-compromise",
  "ot-disruption",
  "data-exfiltration",
  "custom",
] as const;
export type ExerciseScenarioType = typeof EXERCISE_SCENARIO_TYPES[number];

export const INJECT_CHANNELS = [
  "email", "chat", "phone", "news", "sensor", "sms", "facilitator",
  "siem", "edr", "war-room",
] as const;
export type InjectChannel = typeof INJECT_CHANNELS[number];

export const ROLE_KEYS = [
  "FACILITATOR",
  "CIRT_LEAD",
  "SOC_ANALYST",
  "IT_OPS",
  "LEGAL",
  "COMMS",
  "EXEC",
  "HR",
  "THIRD_PARTY",
  "OBSERVER",
] as const;
export type ExerciseRoleKey = typeof ROLE_KEYS[number];
export const ROLE_LABEL: Record<ExerciseRoleKey, string> = {
  FACILITATOR: "Facilitator",
  CIRT_LEAD: "CIRT Lead / Incident Commander",
  SOC_ANALYST: "SOC Analyst / Detection",
  IT_OPS: "IT Ops / Engineering",
  LEGAL: "Legal & Privacy",
  COMMS: "Communications / PR",
  EXEC: "Executive Sponsor",
  HR: "Human Resources",
  THIRD_PARTY: "Third Party (Vendor / Provider)",
  OBSERVER: "Observer",
};

export const EVENT_TYPES = [
  "inject-sent", "inject-released", "response", "participant-response",
  "note", "decision", "escalation", "score", "phase-change",
] as const;
export type ExerciseEventType = typeof EVENT_TYPES[number];

// ----- exercises ------------------------------------------------------------
export const exercises = sqliteTable("exercises", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  code: text("code").notNull(), // TTX-NNN
  title: text("title").notNull(),
  status: text("status").notNull().default("draft"),
  framework: text("framework").notNull().default("hkma"),
  scenarioType: text("scenario_type").notNull().default("ransomware-affiliate"),
  severity: text("severity").notNull().default("HIGH"),
  // Schedule (ISO strings; null = unscheduled)
  scheduledAt: text("scheduled_at"),
  durationMin: integer("duration_min").notNull().default(120),
  // Facilitator user id
  facilitatorId: text("facilitator_id"),
  // Markdown narrative (the scenario backstory shown to the facilitator)
  narrativeMd: text("narrative_md"),
  // Objectives, success criteria, rubric — JSON
  objectives: text("objectives").notNull().default("[]"),
  evaluationRubric: text("evaluation_rubric").notNull().default("{}"),
  // Source linkage (JSON arrays of TAP ids + OSINT finding ids + reference urls)
  sourceTapIds: text("source_tap_ids").notNull().default("[]"),
  sourceFindingIds: text("source_finding_ids").notNull().default("[]"),
  sourceReferences: text("source_references").notNull().default("[]"),
  // Manual PPTX upload metadata (path/key on disk; null if generated only)
  uploadedPptxPath: text("uploaded_pptx_path"),
  uploadedPptxName: text("uploaded_pptx_name"),
  // AI provider used to generate (null if pure-template or manual)
  aiProviderLabel: text("ai_provider_label"),
  version: integer("version").notNull().default(1),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
  createdBy: text("created_by").notNull(),
});

// ----- exercise_injects -----------------------------------------------------
export const exerciseInjects = sqliteTable("exercise_injects", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  exerciseId: text("exercise_id").notNull(),
  sequence: integer("sequence").notNull().default(0), // order within timeline
  atMinute: integer("at_minute").notNull().default(0), // minutes from T+0
  channel: text("channel").notNull().default("email"),
  audienceRoles: text("audience_roles").notNull().default("[]"), // JSON array of ROLE_KEYS
  title: text("title").notNull(),
  bodyMd: text("body_md").notNull().default(""),
  // Expected actions (used for facilitator answer key + scoring)
  expectedActions: text("expected_actions").notNull().default("[]"),
  // Optional IOCs / attachments — JSON
  iocs: text("iocs").notNull().default("[]"),
  attachments: text("attachments").notNull().default("[]"),
  // Delivery state — set when facilitator clicks Send during a run
  sentAt: text("sent_at"),
  createdAt: text("created_at").notNull(),
});

// ----- exercise_roles -------------------------------------------------------
export const exerciseRoles = sqliteTable("exercise_roles", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  exerciseId: text("exercise_id").notNull(),
  roleKey: text("role_key").notNull(), // ROLE_KEYS
  label: text("label").notNull(),
  briefMd: text("brief_md").notNull().default(""),
  color: text("color").notNull().default("#64748b"),
  createdAt: text("created_at").notNull(),
});

// ----- exercise_participants ------------------------------------------------
export const exerciseParticipants = sqliteTable("exercise_participants", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  exerciseId: text("exercise_id").notNull(),
  roleId: text("role_id").notNull(), // FK -> exercise_roles.id
  displayName: text("display_name").notNull(),
  email: text("email"),
  token: text("token").notNull(), // 32-char magic-link token, unique
  joinedAt: text("joined_at"),
  lastSeenAt: text("last_seen_at"),
  createdAt: text("created_at").notNull(),
});

// ----- exercise_events ------------------------------------------------------
export const exerciseEvents = sqliteTable("exercise_events", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  exerciseId: text("exercise_id").notNull(),
  ts: text("ts").notNull(), // ISO timestamp
  type: text("type").notNull(), // EVENT_TYPES
  actorId: text("actor_id"), // user id OR participant id (free string)
  actorRole: text("actor_role"), // ROLE_KEY (for display)
  payload: text("payload").notNull().default("{}"),
});

// ----- DTOs (camelCase) -----------------------------------------------------
export interface ExerciseDTO {
  id: string;
  tenantId: string;
  code: string;
  title: string;
  status: ExerciseStatus;
  framework: ExerciseFramework;
  scenarioType: ExerciseScenarioType;
  severity: ExerciseSeverity;
  scheduledAt: string | null;
  durationMin: number;
  facilitatorId: string | null;
  narrativeMd: string | null;
  objectives: string[];
  evaluationRubric: Record<string, unknown>;
  sourceTapIds: string[];
  sourceFindingIds: string[];
  sourceReferences: Array<{ title: string; url?: string }>;
  uploadedPptxName: string | null;
  aiProviderLabel: string | null;
  version: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  // counts (joined)
  injectCount?: number;
  roleCount?: number;
  participantCount?: number;
}

export interface ExerciseInjectDTO {
  id: string;
  exerciseId: string;
  sequence: number;
  atMinute: number;
  channel: InjectChannel;
  audienceRoles: ExerciseRoleKey[];
  title: string;
  bodyMd: string;
  expectedActions: string[];
  iocs: Array<{ type: string; value: string }>;
  attachments: Array<{ name: string; url?: string }>;
  sentAt: string | null;
  createdAt: string;
}

export interface ExerciseRoleDTO {
  id: string;
  exerciseId: string;
  roleKey: ExerciseRoleKey;
  label: string;
  briefMd: string;
  color: string;
  createdAt: string;
}

export interface ExerciseParticipantDTO {
  id: string;
  exerciseId: string;
  roleId: string;
  roleKey?: ExerciseRoleKey;
  roleLabel?: string;
  displayName: string;
  email: string | null;
  token: string;
  joinedAt: string | null;
  lastSeenAt: string | null;
  createdAt: string;
}

export interface ExerciseEventDTO {
  id: string;
  exerciseId: string;
  ts: string;
  type: ExerciseEventType;
  actorId: string | null;
  actorRole: ExerciseRoleKey | null;
  payload: Record<string, unknown>;
}

export interface ExerciseFullDTO extends ExerciseDTO {
  injects: ExerciseInjectDTO[];
  roles: ExerciseRoleDTO[];
  participants: ExerciseParticipantDTO[];
  events: ExerciseEventDTO[];
}

// ----- Insert / Patch Zod schemas -------------------------------------------
export const exerciseCreateSchema = z.object({
  title: z.string().min(1),
  framework: z.enum(EXERCISE_FRAMEWORKS).optional().default("hkma"),
  scenarioType: z.enum(EXERCISE_SCENARIO_TYPES).optional().default("ransomware-affiliate"),
  severity: z.enum(EXERCISE_SEVERITIES).optional().default("HIGH"),
  durationMin: z.number().int().min(15).max(720).optional().default(120),
  scheduledAt: z.string().nullable().optional(),
  sourceTapIds: z.array(z.string()).optional().default([]),
  sourceFindingIds: z.array(z.string()).optional().default([]),
});

export const exercisePatchSchema = z.object({
  title: z.string().min(1).optional(),
  status: z.enum(EXERCISE_STATUSES).optional(),
  framework: z.enum(EXERCISE_FRAMEWORKS).optional(),
  scenarioType: z.enum(EXERCISE_SCENARIO_TYPES).optional(),
  severity: z.enum(EXERCISE_SEVERITIES).optional(),
  durationMin: z.number().int().min(15).max(720).optional(),
  scheduledAt: z.string().nullable().optional(),
  facilitatorId: z.string().nullable().optional(),
  narrativeMd: z.string().nullable().optional(),
  objectives: z.array(z.string()).optional(),
  evaluationRubric: z.record(z.any()).optional(),
  sourceTapIds: z.array(z.string()).optional(),
  sourceFindingIds: z.array(z.string()).optional(),
  sourceReferences: z.array(z.object({ title: z.string(), url: z.string().optional() })).optional(),
});

export const exerciseInjectSchema = z.object({
  sequence: z.number().int().optional(),
  atMinute: z.number().int().min(0).optional().default(0),
  channel: z.enum(INJECT_CHANNELS).optional().default("email"),
  audienceRoles: z.array(z.enum(ROLE_KEYS)).optional().default([]),
  title: z.string().min(1),
  bodyMd: z.string().optional().default(""),
  expectedActions: z.array(z.string()).optional().default([]),
  iocs: z.array(z.object({ type: z.string(), value: z.string() })).optional().default([]),
  attachments: z.array(z.object({ name: z.string(), url: z.string().optional() })).optional().default([]),
});

export const exerciseInjectPatchSchema = z.object({
  sequence: z.number().int().optional(),
  atMinute: z.number().int().min(0).optional(),
  channel: z.enum(INJECT_CHANNELS).optional(),
  audienceRoles: z.array(z.enum(ROLE_KEYS)).optional(),
  title: z.string().min(1).optional(),
  bodyMd: z.string().optional(),
  expectedActions: z.array(z.string()).optional(),
  iocs: z.array(z.object({ type: z.string(), value: z.string() })).optional(),
  attachments: z.array(z.object({ name: z.string(), url: z.string().optional() })).optional(),
});

export const exerciseRoleSchema = z.object({
  roleKey: z.enum(ROLE_KEYS),
  label: z.string().min(1),
  briefMd: z.string().optional().default(""),
  color: z.string().optional().default("#64748b"),
});

export const exerciseRolePatchSchema = z.object({
  label: z.string().min(1).optional(),
  briefMd: z.string().optional(),
  color: z.string().optional(),
});

export const exerciseParticipantSchema = z.object({
  roleId: z.string().min(1),
  displayName: z.string().min(1),
  email: z.string().email().nullable().optional(),
});

export const exerciseEventCreateSchema = z.object({
  type: z.enum(EVENT_TYPES),
  actorId: z.string().nullable().optional(),
  actorRole: z.enum(ROLE_KEYS).nullable().optional(),
  payload: z.record(z.any()).optional().default({}),
});
