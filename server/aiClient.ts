/**
 * AI client — live-provider dispatcher for BatchOne analysis tasks.
 *
 * BatchOne strict mode requires real provider output for AI workflows. Missing
 * keys, provider failures, malformed JSON, and schema mismatches surface as
 * explicit errors so the UI can show the real provider state.
 */
import type { AiTask, AiProvider, FindingDTO, YoungDomainCandidateDTO } from "@shared/schema";
import { liveChatJson, liveChatJsonDiagnostic, livePing, providerHasUsableKey, type LiveChatDiagnostic } from "./aiLive";
import { isSecurityPublisherHost } from "./iocPublisherBlocklist";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

// ---------- query-grammar reference (v2.12) ----------
// Loaded from server/queryGrammars/*.md at process start and injected into the
// hunt-query system prompt so the model has authoritative grammar for each SIEM.
function resolveGrammarDir(): string | null {
  const candidates: string[] = [];
  // __dirname is defined when bundled as CJS (esbuild target). Probe via
  // globalThis to avoid TS "only in CJS modules" errors when this file is
  // also typed as ESM.
  try {
    const dn = (globalThis as any).__dirname;
    if (typeof dn === "string" && dn.length > 0) candidates.push(join(dn, "queryGrammars"));
  } catch {}
  // Fallbacks relative to cwd — supports `node dist/index.cjs` run from
  // the dashboard project root.
  candidates.push(join(process.cwd(), "dist", "queryGrammars"));
  candidates.push(join(process.cwd(), "server", "queryGrammars"));
  candidates.push(join(process.cwd(), "queryGrammars"));
  for (const c of candidates) {
    if (c && existsSync(c)) return c;
  }
  return null;
}

// Map hunt-query language identifier → grammar MD file basename (without extension)
const LANG_TO_GRAMMAR: Record<string, string> = {
  splunk: "splunk",
  kql_elk: "elastic",
  elastic: "elastic",
  chronicle: "chronicle-yaral",
  defender: "sentinel-kql",
  sentinel: "sentinel-kql",
  crowdstrike: "crowdstrike-cql",
  cortex_xdr: "cortex-xql",
  sentinelone: "elastic",   // S1 Deep Visibility ≈ KQL-flavoured
  qradar: "qradar-aql",
  sumo: "sumologic",
  sumologic: "sumologic",
  sigma: "sigma",
  yara: "sigma",
};

let GRAMMAR_CACHE: Record<string, string> | null = null;
function loadGrammarCache(): Record<string, string> {
  if (GRAMMAR_CACHE) return GRAMMAR_CACHE;
  const dir = resolveGrammarDir();
  const out: Record<string, string> = {};
  if (!dir) {
    GRAMMAR_CACHE = out;
    return out;
  }
  try {
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".md")) continue;
      const key = f.replace(/\.md$/, "");
      try { out[key] = readFileSync(join(dir, f), "utf8"); } catch {}
    }
  } catch {}
  GRAMMAR_CACHE = out;
  return out;
}

function grammarReferenceFor(languages: string[]): string {
  const cache = loadGrammarCache();
  if (!cache || Object.keys(cache).length === 0) return "";
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const lang of languages) {
    const slug = LANG_TO_GRAMMAR[lang];
    if (!slug || seen.has(slug)) continue;
    const md = cache[slug];
    if (!md) continue;
    seen.add(slug);
    parts.push(`### Grammar: ${lang} (${slug}.md)\n\n${md.trim()}`);
  }
  if (parts.length === 0) return "";
  return [
    "## Platform query-grammar reference (authoritative)",
    "Use the following SIEM-specific grammar references as ground truth. Produce queries that are valid in the target platform's native syntax — do not invent operators or fields.",
    "",
    parts.join("\n\n---\n\n"),
  ].join("\n");
}


// v2.26 — live calls are now mandatory whenever a provider is configured.
// The kill-switch is retained for emergency offline development only.
function liveCallsEnabled(): boolean {
  return process.env.OPTRASIGHT_AI_LIVE !== "0";
}

/** v2.26 — thrown when a live AI call cannot produce a usable result. The
 *  dispatcher no longer silently falls back to mock; routes catch this and
 *  surface a 502 with the underlying reason so the UI shows a real error. */
export class LiveAiError extends Error {
  task: string;
  provider: string;
  providerLabel: string;
  reason: string;
  httpStatus: number;
  latencyMs: number;
  rawBodyPreview: string;
  constructor(task: string, provider: AiProvider, diag: { reason: string; httpStatus: number; latencyMs: number; rawBodyPreview: string }) {
    super(`AI provider "${provider.label || provider.provider}" failed on task ${task}: ${diag.reason} (HTTP ${diag.httpStatus}, ${diag.latencyMs}ms)`);
    this.name = "LiveAiError";
    this.task = task;
    this.provider = provider.provider;
    this.providerLabel = provider.label || provider.provider;
    this.reason = diag.reason;
    this.httpStatus = diag.httpStatus;
    this.latencyMs = diag.latencyMs;
    this.rawBodyPreview = diag.rawBodyPreview;
  }
}

// v2.26 — Wrapper around liveChatJsonDiagnostic that THROWS on failure (was
// previously falling back to mock). The per-task functions stay as-is; if any
// of them want to short-circuit (e.g. validation of structured output), they
// can still return null and the dispatcher will throw on their behalf.
export function liveChatJsonLogged(
  task: string,
  provider: AiProvider,
  opts: {
    system: string;
    user: string;
    temperature?: number;
    maxTokens?: number;
    timeoutSeconds?: number;
    /** Vision content blocks — forwarded to the provider when supported. */
    images?: import("./aiLive").LiveChatImage[];
  },
): Record<string, any> {
  const diag = liveChatJsonDiagnostic(provider, opts);
  if (diag.result) {
    if (diag.latencyMs > 20000 || diag.httpStatus !== 200) {
      console.log(`[ai:${task}] live ok provider=${provider.provider} model=${provider.model} ${diag.latencyMs}ms http=${diag.httpStatus}`);
    }
    return diag.result;
  }
  console.warn(
    `[ai:${task}] LIVE FAILED — surfacing error. provider=${provider.provider} model=${provider.model} ` +
      `reason="${diag.reason}" http=${diag.httpStatus} latency=${diag.latencyMs}ms preview=${JSON.stringify(diag.rawBodyPreview).slice(0, 300)}`,
  );
  throw new LiveAiError(task, provider, diag);
}

// ---------- deterministic helpers ----------
function djb2(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}
function pick<T>(arr: T[], seed: number): T {
  return arr[seed % arr.length];
}

// ---------- task: triage ----------
export interface TriageInput {
  finding: FindingDTO;
}
export interface TriageOutput {
  recommendedStatus: "investigating" | "takedown" | "false_positive" | "open";
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  reasoning: string;
  suggestedActions: string[];
  iocs: string[];
}

function _triageMock(finding: FindingDTO, provider: AiProvider): TriageOutput {
  const seed = djb2(`${provider.id}:${finding.id}:${finding.title}`);
  const sevMatrix: Record<string, TriageOutput["severity"]> = {
    critical: "critical", high: "high", medium: "high",
    low: "medium", info: "low",
  };
  const recommended: TriageOutput["recommendedStatus"][] =
    finding.type === "lookalike"
      ? ["takedown", "investigating"]
      : finding.type === "vulnerability"
      ? ["investigating", "investigating", "takedown"]
      : ["investigating", "false_positive", "investigating"];
  const recommendedStatus = pick(recommended, seed);
  const severity = sevMatrix[finding.severity] ?? finding.severity as TriageOutput["severity"];
  const confidence = 0.62 + ((seed % 35) / 100); // 0.62 — 0.97

  const reasoningTemplates = [
    `${finding.type} indicator on ${finding.target ?? "the asset"} matches known ${finding.severity}-severity TTPs. The signal pattern is consistent with active brand impersonation.`,
    `Correlated host fingerprint suggests an opportunistic phishing kit deployment. ${finding.target ?? "Target"} has been observed in adjacent campaigns.`,
    `WHOIS pivot reveals registrant overlap with prior takedown candidates. Recommend rapid response per HKMA SA-2 escalation policy.`,
    `Detection telemetry contains low-noise indicators with high precision. Confidence is bolstered by passive DNS confirmation.`,
  ];
  const reasoning = pick(reasoningTemplates, seed);

  const actionLib = [
    "Issue takedown notice to registrar abuse contact",
    "Submit screenshot evidence to Anti-Phishing Working Group",
    "Block at corporate egress proxy",
    "Notify SOC tier-2 for threat hunting pivot",
    "Open case in incident response platform",
    "Escalate to legal for brand abuse cease-and-desist",
    "Add domain to blocklist and SIEM detection list",
    "Capture passive DNS history for attribution",
  ];
  const suggestedActions = [
    pick(actionLib, seed),
    pick(actionLib, seed + 17),
    pick(actionLib, seed + 31),
  ].filter((v, i, a) => a.indexOf(v) === i);

  const iocs = [
    finding.target,
    finding.extra?.ip as string | undefined,
    finding.extra?.url as string | undefined,
  ].filter((x): x is string => !!x);

  return {
    recommendedStatus,
    severity,
    confidence: Math.round(confidence * 100) / 100,
    reasoning,
    suggestedActions,
    iocs,
  };
}

// ---------- task: young_domain ----------
export interface YoungDomainAiInput {
  domain: string;
  candidateUrl?: string;
  seed: string;
  presetName?: string;
  technique: string;
  similarity: number;
  hasMx: boolean;
  hasA: boolean;
  ageDays: number;
  discoveredBy?: string[];
  whois?: Record<string, any> | null;
  dnsA?: string[];
  dnsMx?: string[];
  siteEvidence?: Record<string, any>;
  screenshot?: { available: boolean; mime?: string; dataBase64?: string | null; url?: string | null };
  brandAbuse?: Record<string, any>;
  brandAssets?: Array<{ kind: "logo" | "trademark" | "app_icon"; name: string; mime: string; sha256: string; dataBase64?: string }>;
  providerVisionSupported?: boolean;
}
export interface YoungDomainAiOutput {
  verdict: YoungDomainCandidateDTO["verdict"];
  confidence: number;
  reasoning: string;
  targetBrand: string | null;
  visionSupported: boolean;
  brandAssetDetected: boolean;
  matchedAssetKinds: Array<"logo" | "trademark" | "app_icon">;
  visualSimilarity: number | null;
  loginFormDetected: boolean;
  cloudflareBlocked: boolean;
  keyEvidence: string[];
  recommendedActions: string[];
}

function _youngDomainMock(input: YoungDomainAiInput, provider: AiProvider): YoungDomainAiOutput {
  const seed = djb2(`${provider.id}:${input.domain}`);
  // Heuristic: high similarity + MX + young age → phishing
  let verdict: YoungDomainAiOutput["verdict"] = "inconclusive";
  const status = input.siteEvidence?.status;
  const login = !!input.siteEvidence?.loginFormDetected;
  const cf = !!input.siteEvidence?.cloudflareBlocked;
  if (input.similarity > 0.78 && (input.hasMx || login) && input.ageDays < 60) verdict = login ? "forged_login" : "phishing";
  else if (input.similarity > 0.7 && input.ageDays < 90) verdict = "brand_impersonation";
  else if (input.similarity > 0.55) verdict = "spoofing";
  else if (status === "parked") verdict = "parked_benign";
  else verdict = pick(["parked_benign", "spoofing", "inconclusive"] as const, seed);

  const baseConf = verdict === "phishing" || verdict === "forged_login" ? 0.84 : verdict === "brand_impersonation" ? 0.74 : verdict === "spoofing" ? 0.68 : 0.55;
  const confidence = Math.min(0.97, baseConf + ((seed % 12) / 100));

  const reasoning =
    verdict === "phishing"
      ? `Domain ${input.domain} is a ${(input.similarity * 100).toFixed(0)}% lexical match to ${input.seed} via ${input.technique}. MX records present and ${input.ageDays}-day registration window indicate active phishing infrastructure. Screenshot shows a credential capture page mimicking ${input.presetName ?? "the brand"}.`
      : verdict === "brand_impersonation"
      ? `Brand impersonation likely: ${input.domain} replicates visual identity of ${input.presetName ?? "the brand"}. No active mail flow detected yet, but landing page contains brand assets without authorisation.`
      : verdict === "parked_benign"
      ? `${input.domain} resolves to a parking page registrar. No mail server, generic hosting fingerprint. Low immediate risk; monitor for content changes.`
      : `${input.domain} appears benign — content unrelated to ${input.presetName ?? input.seed}, no impersonation indicators.`;

  return {
    verdict,
    confidence: Math.round(confidence * 100) / 100,
    reasoning,
    targetBrand: verdict === "phishing" || verdict === "brand_impersonation" || verdict === "forged_login" || verdict === "spoofing" ? (input.presetName ?? input.seed) : null,
    visionSupported: !!input.providerVisionSupported,
    brandAssetDetected: false,
    matchedAssetKinds: [],
    visualSimilarity: null,
    loginFormDetected: login,
    cloudflareBlocked: cf,
    keyEvidence: [
      `${Math.round(input.similarity * 100)}% lexical similarity via ${input.technique}`,
      input.hasMx ? "MX records present" : "No MX records observed",
      status ? `HTTP status: ${status}` : "HTTP status unavailable",
    ],
    recommendedActions: verdict === "phishing" || verdict === "forged_login"
      ? ["Preserve screenshot and headers", "Submit takedown request", "Block domain in secure web gateway"]
      : ["Monitor for content changes", "Recheck WHOIS and DNS in 24 hours"],
  };
}

// ---------- task: report_summary ----------
export interface ReportSummaryInput {
  title: string;
  tenants: string[];
  totals: { findings: number; critical: number; high: number; assets: number; scans: number };
  topFindings: Array<{ severity: string; type: string; title: string; target?: string | null }>;
}
export interface ReportSummaryOutput {
  executiveSummary: string;
  keyFindings: string[];
  recommendations: string[];
}

function _reportSummaryMock(input: ReportSummaryInput, _provider: AiProvider): ReportSummaryOutput {
  const tenantList = input.tenants.length > 1 ? `${input.tenants.length} tenants` : input.tenants[0];
  const exec = `Across ${tenantList}, OptraSight surfaced ${input.totals.findings} findings (${input.totals.critical} critical, ${input.totals.high} high) over ${input.totals.scans} scans. The dominant risk theme is brand impersonation and credential phishing infrastructure adjacent to the protected domains. Immediate priority items center on takedown coordination for the highest-similarity lookalike domains and remediation of the externally exposed services that materially raise the attack surface.`;

  const keyFindings = [
    `${input.totals.critical} critical-severity findings require executive escalation, primarily concentrated in lookalike-domain and exposed-service categories.`,
    `${input.totals.assets} unique assets enumerated — the discovery layer continues to outpace ad-hoc inventories maintained by infrastructure teams.`,
    `Top finding types correlate with phishing-kit telemetry observed in the broader APAC banking sector during the reporting window.`,
  ];
  const recommendations = [
    "Authorise rapid takedown for all critical lookalike domains within 24 hours.",
    "Patch or compensate the high-severity vulnerabilities with available exploits within the next sprint.",
    "Expand keyword coverage by enabling combosquat and homoglyph techniques in the next scheduled scan.",
    "Brief the executive committee on the brand-abuse posture during the next risk review.",
  ];
  return { executiveSummary: exec, keyFindings, recommendations };
}

// ---------- task: analysis (generic) ----------
export interface AnalysisInput {
  prompt: string;
  context?: Record<string, any>;
}
export interface AnalysisOutput {
  text: string;
  structured?: Record<string, any>;
}

function _analysisMock(input: AnalysisInput, provider: AiProvider): AnalysisOutput {
  const seed = djb2(`${provider.id}:${input.prompt}`);
  const tones = [
    "Analysis complete. The provided indicators correlate with a known phishing pattern.",
    "Reviewed context: pivoting on registrant artefacts yields three candidate clusters worth deeper investigation.",
    "Pattern summary: consistent with opportunistic credential harvesting against APAC financial services.",
  ];
  return { text: pick(tones, seed) + "\n\n" + input.prompt.slice(0, 200) };
}

// ---------- task: logo_abuse ----------
export interface LogoAbuseInput {
  baseAssetSha256: string;
  candidateUrl: string;
}
export interface LogoAbuseOutput {
  match: boolean;
  similarity: number;
  reasoning: string;
}

function _logoAbuseMock(input: LogoAbuseInput, provider: AiProvider): LogoAbuseOutput {
  const seed = djb2(`${provider.id}:${input.baseAssetSha256}:${input.candidateUrl}`);
  const sim = 0.5 + ((seed % 50) / 100);
  return {
    match: sim > 0.78,
    similarity: Math.round(sim * 100) / 100,
    reasoning: sim > 0.78
      ? `Candidate logo at ${input.candidateUrl} matches the registered mark with ${(sim * 100).toFixed(0)}% perceptual similarity. Recommend takedown.`
      : `Visual similarity ${(sim * 100).toFixed(0)}% — below the 78% threshold; classify as non-infringing for now.`,
  };
}

// ---------- task: osint_analysis ----------
export interface OsintAnalysisInput {
  finding: {
    title: string;
    summary: string | null;
    severity: string;
    affectedTech: string[];
    cveIds: string[];
    threatActors: string[];
    // v2.13 — source link + (optional) pre-fetched article text so the AI
    // can read the original report end-to-end before scoring relevance.
    url?: string | null;
    sourceContent?: string | null;
  };
  clientProfile: { industries: string[]; geos: string[]; monitoredTechnologies: string[] };
}
export interface OsintAnalysisOutput {
  summary: string;
  relevanceScore: number;
  recommendation: string;
  /**
   * v2.18 — IoCs extracted VERBATIM from sourceContent by the AI. Each group
   * is optional and may be empty. The storage layer MERGES these with any
   * regex-parsed IoCs already on the finding (set-dedupe per type) so analyst
   * overrides via PATCH /api/v1/osint/findings/:fid always win.
   */
  iocs?: {
    ipv4?: string[];
    ipv6?: string[];
    domain?: string[];
    url?: string[];
    md5?: string[];
    sha1?: string[];
    sha256?: string[];
    email?: string[];
    btc?: string[];
  };
  /**
   * v2.18 — Tags suggested by the AI by matching the article against
   * clientProfile.industries ∪ geos ∪ monitoredTechnologies. Strictly a
   * verbatim (case-insensitive substring / synonym) hit — never invented.
   */
  analystTags?: string[];
  /**
   * v2.29 — categorisation of the intel item.
   *   threat_intel    — actionable threat advisory / incident / IoC report
   *   regular_report  — periodic landscape / vendor M-Trends-style review
   *   advertisement   — product marketing / vendor promo / sponsored post
   */
  intelCategory?: "threat_intel" | "regular_report" | "advertisement";
  /**
   * v2.30 — MITRE ATT&CK techniques mentioned in the article. Strict format:
   * id matches /^T[0-9]{4}(\.[0-9]{3})?$/ (Tnnnn or Tnnnn.nnn for sub-tech).
   * The persistence layer drops malformed entries silently.
   */
  attackTechniques?: Array<{ id: string; name?: string; tactic?: string }>;
  /**
   * v2.30 — industry sectors named or strongly implied as victims/targets.
   * Lowercase snake_case, e.g. ['finance','healthcare','technology'].
   */
  sectors?: string[];
  /**
   * v2.30 — geographic regions affected. Use coarse buckets:
   * ['global','apac','emea','americas','na','sa','africa'] or country codes.
   */
  regions?: string[];
}

function _osintAnalysisMock(input: OsintAnalysisInput, provider: AiProvider): OsintAnalysisOutput {
  const seed = djb2(`${provider.id}:${input.finding.title}`);
  const watchHits = (input.finding.affectedTech || []).filter((t) => (input.clientProfile.monitoredTechnologies || []).includes(t));
  const sevWeight: Record<string, number> = { critical: 0.95, high: 0.78, medium: 0.55, low: 0.32, info: 0.18 };
  const base = sevWeight[input.finding.severity] ?? 0.4;
  const watchBoost = Math.min(0.15, watchHits.length * 0.05);
  const relevanceScore = Math.min(1, Math.round((base + watchBoost + (seed % 10) / 100) * 100) / 100);
  const techMention = (input.finding.affectedTech || []).slice(0, 3).join(", ") || "the referenced technology";
  const cveMention = (input.finding.cveIds || []).slice(0, 2).join(", ");
  const summary = [
    `${input.finding.title.slice(0, 110)}${input.finding.title.length > 110 ? "…" : ""}`,
    `Affected: ${techMention}${cveMention ? ` (${cveMention})` : ""}.`,
    watchHits.length
      ? `Direct intersection with the client's watchlist (${watchHits.join(", ")}) — prioritise.`
      : `No direct watchlist intersection; tracked for situational awareness.`,
  ].join(" ");
  const recommendation = relevanceScore > 0.7
    ? `Patch verification across ${techMention}; deploy hunt queries for ${cveMention || "the referenced TTPs"}; brief affected business owners within 24h.`
    : relevanceScore > 0.45
    ? `Track for trending; validate detection coverage; revisit if additional corroborating reports emerge.`
    : `Low immediate impact — archive after one further review cycle unless the situation evolves.`;
  return {
    summary, relevanceScore, recommendation,
    intelCategory: "threat_intel",
    // v2.30 — mock returns empty arrays so the persist layer no-ops.
    attackTechniques: [],
    sectors: [],
    regions: [],
  };
}

// ---------- task: hunt_query ----------
export interface HuntQueryInput {
  findings: Array<{
    title: string;
    cveIds: string[];
    affectedTech: string[];
    threatActors: string[];
    summary?: string | null;
    rawSnippet?: string | null;
    severity?: string;
    // v2.13 — attach the source URL and (optional) pre-fetched article text
    // so the AI reads the underlying intel rather than relying on the short
    // ingested summary alone.
    url?: string | null;
    sourceContent?: string | null;
  }>;
  languages: string[];
  titleInstruction?: string;
}
// v2.13: each language may now carry multiple queries. Older clients that
// expect a single string still work because the dispatcher returns the first
// query alongside the array (see HuntQueryOutputItem below).
export type HuntQueryOutput = Record<string, string | string[]>;

// ---------- task: osint_overview ----------
export interface OsintOverviewInput {
  persona: "ir" | "ti" | "secops";
  scopeLabel: string;
  category: string | null;
  severityFilter: string | null;
  findings: Array<{
    title: string;
    severity: string;
    sourceCategory: string;
    affectedTech: string[];
    cveIds: string[];
    threatActors: string[];
    summary?: string | null;
    rawSnippet?: string | null;
    publishedAt?: string;
    tenantName?: string;
  }>;
}
export interface OsintOverviewOutput {
  summary: string;
  keyTakeaways: string[];
  recommendations: string[];
}

function _osintOverviewMock(input: OsintOverviewInput, provider: AiProvider): OsintOverviewOutput {
  void provider;
  const sevTally: Record<string, number> = {};
  const techTally: Record<string, number> = {};
  const actorTally: Record<string, number> = {};
  const cveTally: Record<string, number> = {};
  const tenantTally: Record<string, number> = {};
  for (const f of input.findings) {
    sevTally[f.severity] = (sevTally[f.severity] || 0) + 1;
    (f.affectedTech || []).forEach((t) => (techTally[t] = (techTally[t] || 0) + 1));
    (f.threatActors || []).forEach((a) => (actorTally[a] = (actorTally[a] || 0) + 1));
    (f.cveIds || []).forEach((c) => (cveTally[c] = (cveTally[c] || 0) + 1));
    if (f.tenantName) tenantTally[f.tenantName] = (tenantTally[f.tenantName] || 0) + 1;
  }
  const top = (m: Record<string, number>, n = 4) =>
    Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, n);
  const topTech = top(techTally);
  const topActors = top(actorTally);
  const topCves = top(cveTally, 6);
  const topTenants = top(tenantTally, 4);

  const persona = input.persona;
  const total = input.findings.length;
  const critHigh = (sevTally.critical || 0) + (sevTally.high || 0);
  const categoryNote = input.category ? ` filtered to **${input.category}** sources` : "";
  const severityNote = input.severityFilter ? ` with severity ≥ ${input.severityFilter}` : "";

  // Persona-tuned summary opening
  const summaryHead = persona === "ir"
    ? `From an **incident-response** perspective, ${input.scopeLabel} has **${total}** recent OSINT items${categoryNote}${severityNote} — ${critHigh} of which are critical/high and warrant active containment review.`
    : persona === "ti"
    ? `From a **threat-intelligence** perspective, ${input.scopeLabel} surfaced **${total}** correlated items${categoryNote}${severityNote}. ${topActors.length ? `Named-actor activity is dominated by ${topActors.slice(0, 2).map(([a]) => a).join(" and ")}.` : "No named-actor attribution dominates this window."}`
    : `From a **security-operations** perspective, ${input.scopeLabel} surfaced **${total}** items${categoryNote}${severityNote} that intersect monitored telemetry. ${topTech.length ? `Detection coverage gaps cluster around ${topTech.slice(0, 2).map(([t]) => `\`${t}\``).join(" and ")}.` : "No dominant technology cluster this window."}`;

  const summaryBody = [
    topCves.length ? `Top CVEs: ${topCves.map(([c, n]) => `\`${c}\` (×${n})`).join(", ")}.` : null,
    topTenants.length > 1 ? `Cross-client distribution: ${topTenants.map(([t, n]) => `${t} (${n})`).join(", ")}.` : null,
  ].filter(Boolean).join(" ");

  const summary = [summaryHead, summaryBody].filter(Boolean).join(" ");

  // Persona-tuned takeaways
  let keyTakeaways: string[] = [];
  if (persona === "ir") {
    keyTakeaways = [
      critHigh > 0 ? `**${critHigh} critical/high** findings flagged — trigger triage on these before lower-severity items.` : `No critical/high findings in this window — maintain steady-state monitoring.`,
      topTech.length ? `Initial-access surface concentration: ${topTech.slice(0, 3).map(([t, n]) => `${t} (${n} reports)`).join(", ")}.` : `No dominant attack surface this window.`,
      topActors.length ? `Named-actor signal: ${topActors.slice(0, 3).map(([a, n]) => `${a} (${n})`).join(", ")} — align containment to known playbooks.` : `No named-actor attribution — treat as commodity-criminal activity.`,
      `Establish go/no-go on emergency change-control for the top CVE-affected products in the next 24h.`,
      input.scopeLabel.toLowerCase().includes("global") ? `Multiple tenants impacted — escalate to MSSP-wide incident bridge if any tenant confirms exploitation.` : `Confirm asset inventory accuracy against the affected-tech list before stand-down.`,
    ];
  } else if (persona === "ti") {
    keyTakeaways = [
      topActors.length ? `Active threat actors: ${topActors.map(([a, n]) => `**${a}** (${n})`).join(", ")} — review their last-known TTPs and infrastructure overlap.` : `No named-actor activity — likely commodity / opportunistic exploitation.`,
      topCves.length ? `CVE cluster: ${topCves.slice(0, 4).map(([c, n]) => `${c} (×${n})`).join(", ")} — candidate pivots for passive DNS and certificate transparency hunts.` : `No high-volume CVE cluster — monitor for emerging vulnerabilities.`,
      topTech.length ? `Technology vector concentration: ${topTech.slice(0, 3).map(([t, n]) => `${t} (${n})`).join(", ")} — consider tagging campaign reports accordingly.` : `Technology vector diffuse — weak attribution potential.`,
      `Cross-reference findings with internal IoC repository for prior-period overlap — attribution confidence rises with corroboration.`,
      `Schedule next intel cycle: deepen on highest-volume actor over the coming sprint.`,
    ];
  } else {
    keyTakeaways = [
      topTech.length ? `Detection-coverage priority: ${topTech.slice(0, 3).map(([t, n]) => `${t} (${n})`).join(", ")} — ensure parsing rules and field extractions are current.` : `No dominant detection target.`,
      topCves.length ? `Hunting candidates: ${topCves.slice(0, 4).map(([c]) => c).join(", ")} — generate SIEM/EDR queries via the Hunt-query button.` : `No CVE-driven hunting candidates this window.`,
      `Rule-engineering deltas — verify Sigma / KQL / Splunk coverage for the affected technology stack.`,
      critHigh > 0 ? `**${critHigh} critical/high** — raise their severity weighting in SOAR enrichment for the next 30 days.` : `Severity distribution skews low — maintain baseline detection.`,
      `Schedule a weekly hunt review on the top-3 technologies above.`,
    ];
  }

  // Persona-tuned recommendations
  let recommendations: string[] = [];
  if (persona === "ir") {
    recommendations = [
      `Patch verification across ${topTech.slice(0, 3).map(([t]) => t).join(", ") || "the watchlist"} — confirm coverage within 7 days.`,
      `Update the IR playbook with the top actor TTPs (${topActors.slice(0, 2).map(([a]) => a).join(", ") || "commodity affiliates"}) and rehearse the corresponding incident drill.`,
      `Engage the on-call SOC tier to deploy hunt queries for the listed CVEs and stage containment artefacts (block-lists, EDR custom IoCs).`,
      `Brief executive sponsors using OptraSight's Draft-email feature — escalate within 24h for any tenant with critical/high exposure.`,
      `Document a post-incident review checkpoint in 14 days.`,
    ];
  } else if (persona === "ti") {
    recommendations = [
      `Open a tracking case per dominant actor (${topActors.slice(0, 3).map(([a]) => a).join(", ") || "top campaign"}) and pivot to passive DNS / WHOIS overlap.`,
      `Run YARA across recent EDR collection using the OptraSight-generated rules for ${topTech.slice(0, 2).map(([t]) => t).join(", ") || "the affected technology"}.`,
      `Issue a tactical-intel note covering the top ${Math.min(topCves.length, 4) || 3} CVEs and their observed exploitation patterns.`,
      `Update the watchlist with newly observed IoCs (IPs / domains / hashes) extracted from raw snippets.`,
      `Schedule a deep-dive on the highest-volume actor for the next intel cycle.`,
    ];
  } else {
    recommendations = [
      `Deploy the OptraSight-generated hunt queries (Splunk / KQL / Chronicle / MDE / CrowdStrike / Cortex XDR / SentinelOne / YARA / Sigma) for the top technologies.`,
      `Validate parsing & extraction for ${topTech.slice(0, 3).map(([t]) => t).join(", ") || "monitored products"} — missing fields blind your detection.`,
      `Add Sigma rules for the top CVEs (${topCves.slice(0, 3).map(([c]) => c).join(", ") || "recent vulnerabilities"}) and tune false-positive thresholds within the next sprint.`,
      `Run a coverage audit against MITRE ATT&CK for the suspected initial-access techniques (T1190, T1133) — plug any gaps.`,
      `Reconcile detection logic across SIEM and EDR — unify field names so cross-platform hunts work.`,
    ];
  }

  return {
    summary,
    keyTakeaways: keyTakeaways.filter(Boolean),
    recommendations: recommendations.filter(Boolean),
  };
}

// ---------- task: threat_landscape ----------
export interface ThreatLandscapeInput {
  clientName: string;
  profile: { clientTypes: string[]; industries: string[]; geos: string[]; monitoredTechnologies: string[] };
  recentSignals: Array<{ title: string; severity: string; affectedTech: string[]; threatActors: string[] }>;
}
export interface ThreatLandscapeOutput {
  bodyMd: string;
  stats: Record<string, any>;
}

// ---------- public dispatcher ----------
export interface DispatchOptions<I> {
  task: AiTask;
  input: I;
  provider: AiProvider;
}
// `isMock` is retained in the result contract for legacy callers, but BatchOne
// dispatch paths throw before returning synthetic output.
export type DispatchResult =
  | { task: "triage";           output: TriageOutput; isMock: boolean }
  | { task: "young_domain";     output: YoungDomainAiOutput; isMock: boolean }
  | { task: "report_summary";   output: ReportSummaryOutput; isMock: boolean }
  | { task: "analysis";         output: AnalysisOutput; isMock: boolean }
  | { task: "logo_abuse";       output: LogoAbuseOutput; isMock: boolean }
  | { task: "osint_analysis";   output: OsintAnalysisOutput; isMock: boolean }
  | { task: "hunt_query";       output: HuntQueryOutput; isMock: boolean }
  | { task: "threat_landscape"; output: ThreatLandscapeOutput; isMock: boolean }
  | { task: "osint_overview";   output: OsintOverviewOutput; isMock: boolean }
  | { task: "detection_rule";   output: DetectionRuleOutput; isMock: boolean }
  | { task: "threat_actor_enrichment"; output: ThreatActorEnrichmentOutput; isMock: boolean };

// =============================================================================
//                           LIVE-CALL WRAPPERS
// =============================================================================
//
// Each helper below builds a small system+user prompt tuned for the task,
// calls the live provider via liveChatJson(), validates the returned JSON
// shape, and either returns the typed output or null. dispatchAi() converts a
// missing or invalid live result into a LiveAiError.
//
// The system prompts always say "Respond with a strict JSON object matching
// this TypeScript shape" and then describe the keys. The user message carries
// the structured input as JSON so the model has the raw data verbatim.
// =============================================================================

// Helper: coerce arbitrary value to a string array.
function asStringArray(v: any, max = 12): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => (typeof x === "string" ? x : x == null ? "" : String(x))).filter(Boolean).slice(0, max);
}
function asNumber(v: any, fallback: number): number {
  const n = typeof v === "number" ? v : parseFloat(v);
  return Number.isFinite(n) ? n : fallback;
}
function asString(v: any, fallback = ""): string {
  return typeof v === "string" && v.length > 0 ? v : fallback;
}
function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

// v2.28 — Detect and strip IoC-enumeration tails from a free-text summary.
// The AI is told not to enumerate IoCs in prose, but DeepSeek occasionally
// still appends a 'Notable IoCs include ...' tail. We:
//   1. extract any IPv4 / SHA-256 / SHA-1 / MD5 / domains / URLs from that tail,
//   2. merge them into the cleanedIocs bag,
//   3. drop the matching sentence(s) so the summary stays clean prose.
function scrubIocSentencesFromSummary(
  summary: string,
  cleanedIocs: NonNullable<OsintAnalysisOutput["iocs"]>,
): { summary: string; iocs: NonNullable<OsintAnalysisOutput["iocs"]> } {
  if (!summary) return { summary: "", iocs: cleanedIocs };
  const TRIGGER_RE = /\b(notable\s+io[cC]s?|indicators? of compromise|the (?:known )?ioCs?|associated io[cC]s?|associated indicators|key indicators|ioc(?:s)?(?:\s+include|s?:))/i;
  // Split on sentence-ish boundaries but keep punctuation. We approximate
  // with '. ' and '; ' — the IoC tails we've seen consistently use one of
  // those.
  const parts = summary.split(/(?<=[.;!?])\s+/);
  const kept: string[] = [];
  let extractedText = "";
  for (const part of parts) {
    if (TRIGGER_RE.test(part)) {
      extractedText += " " + part;
      continue;
    }
    kept.push(part);
  }
  if (!extractedText.trim()) return { summary, iocs: cleanedIocs };

  // ---- Extract values from the dropped text ----
  const out: NonNullable<OsintAnalysisOutput["iocs"]> = { ...cleanedIocs };
  const stripDefangs = (s: string): string => String(s)
    .replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\{\.\}/g, ".")
    .replace(/\[dot\]/gi, ".").replace(/\bhxxp(s?):\/\//gi, "http$1://")
    .replace(/\[:\]/g, ":").replace(/\[@\]/g, "@").replace(/\[at\]/gi, "@").trim();

  // Helper that merges values into a bucket with case-insensitive dedupe.
  const mergeBucket = (key: keyof NonNullable<OsintAnalysisOutput["iocs"]>, values: string[]) => {
    if (!values.length) return;
    const seen = new Set<string>(((out[key] || []) as string[]).map((v: string) => v.toLowerCase()));
    const merged: string[] = [...((out[key] || []) as string[])];
    for (const v of values) {
      const s = stripDefangs(v);
      if (!s) continue;
      const lk = s.toLowerCase();
      if (seen.has(lk)) continue;
      seen.add(lk);
      merged.push(s);
    }
    if (merged.length) out[key] = merged;
  };

  const text = stripDefangs(extractedText);
  // SHA-256
  const sha256 = Array.from(text.matchAll(/\b[a-fA-F0-9]{64}\b/g)).map((m) => m[0].toLowerCase());
  mergeBucket("sha256", sha256);
  const sha256Set = new Set(sha256);
  // SHA-1 (40 hex, not part of any sha256 already matched)
  const sha1 = Array.from(text.matchAll(/\b[a-fA-F0-9]{40}\b/g))
    .map((m) => m[0].toLowerCase())
    .filter((v) => ![...sha256Set].some((h) => h.includes(v)));
  mergeBucket("sha1", sha1);
  // MD5 (32 hex, not part of sha1/sha256)
  const sha1Set = new Set(sha1);
  const md5 = Array.from(text.matchAll(/\b[a-fA-F0-9]{32}\b/g))
    .map((m) => m[0].toLowerCase())
    .filter((v) => !sha256Set.has(v) && !sha1Set.has(v)
      && ![...sha256Set, ...sha1Set].some((h) => h.includes(v)));
  mergeBucket("md5", md5);
  // IPv4 (filter version-numbers — reuse the same heuristic as elsewhere)
  const ipv4 = Array.from(text.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g))
    .map((m) => m[0])
    .filter((ip) => {
      // Drop private + version-y
      if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.)/.test(ip)) return false;
      const parts = ip.split(".").map(Number);
      const allLow = parts.every((p) => p <= 32);
      const tinyCount = parts.filter((p) => p <= 9).length;
      if (allLow && tinyCount >= 2) return false;
      return true;
    });
  mergeBucket("ipv4", ipv4);
  // Domains (filter security-publisher hosts)
  const domains = Array.from(text.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|info|biz|onion|ru|cn|jp|hk|sg|tw|kr|in|de|fr|uk|tk|ml|ga|cf|xyz|top|club|site|live|app|dev|me|cc|microsoftonline\.com|onmicrosoft\.com)\b/gi))
    .map((m) => m[0].toLowerCase())
    .filter((d) => !isSecurityPublisherHost(d));
  mergeBucket("domain", domains);
  // URLs — strip publisher refs
  const urls = Array.from(text.matchAll(/https?:\/\/[^\s,"<>)]+/g))
    .map((m) => stripDefangs(m[0]))
    .filter((u) => {
      try {
        const h = new URL(u).hostname.toLowerCase();
        return !isSecurityPublisherHost(h);
      } catch { return true; }
    });
  mergeBucket("url", urls);
  // BTC
  const btc = Array.from(text.matchAll(/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{25,90}\b/g)).map((m) => m[0]);
  mergeBucket("btc", btc);
  // Emails
  const emails = Array.from(text.matchAll(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g)).map((m) => m[0].toLowerCase());
  mergeBucket("email", emails);

  // Re-join the kept sentences. If we dropped the IoC tail mid-thought, the
  // remaining prose may end without a period — don't worry about it; the
  // analyst-facing summary stays readable.
  let cleanSummary = kept.join(" ").trim();
  // Tidy up trailing semicolons / hanging conjunctions left after stripping.
  cleanSummary = cleanSummary
    .replace(/[;,]\s*$/g, ".")
    .replace(/\s+;/g, ";")
    .replace(/\s{2,}/g, " ")
    .replace(/\s+\./g, ".")
    .trim();
  return { summary: cleanSummary, iocs: out };
}

// ---------- triage ----------
function triageLive(finding: FindingDTO, provider: AiProvider): TriageOutput | null {
  const system = [
    "You are a top-tier CIRT (Cyber Incident Response Team) and SOC expert triaging a brand-protection / OSINT finding.",
    "Apply the standard CIRT priority ladder when setting severity and recommendedStatus:",
    "  • CRITICAL — unpatched zero-day or in-the-wild exploited CVE, active ransomware / data-extortion campaign, targeted APT operation, authentication bypass / RCE / privilege escalation in a widely-deployed product, banking / critical-infrastructure impact.",
    "  • HIGH — confirmed brand impersonation with weaponised infrastructure, credible phishing kit, malware family with active distribution.",
    "  • MEDIUM — suspicious look-alike domain with weak signals, generic spam, dormant infrastructure.",
    "  • LOW / INFO — benign mention, parked, or duplicate of an existing case.",
    "Always respond in ENGLISH. Translate any non-English titles, quotes, or technical terms inline.",
    "Be decisive. Name the exact CVE IDs, product versions, threat-actor groups, and IOCs that appear in the source material — verbatim, not paraphrased.",
    "Respond with a STRICT JSON object — no prose, no markdown fences — matching:",
    `{`,
    `  "recommendedStatus": "investigating" | "takedown" | "false_positive" | "open",`,
    `  "severity": "critical" | "high" | "medium" | "low" | "info",`,
    `  "confidence": number,  // 0..1`,
    `  "reasoning": string,   // 2-4 sentences citing the specific signals (CVEs, actor, infra, exploitation status) that drove the verdict`,
    `  "suggestedActions": string[],  // 2-5 direct, ordered next steps for the analyst — patch / block / hunt / takedown — each tied to a concrete asset or control`,
    `  "iocs": string[]               // verbatim domains, IPs, URLs, hashes, file paths, mutex names — DO NOT paraphrase`,
    `}`,
  ].join("\n");
  const user = JSON.stringify({ finding });
  const raw = liveChatJsonLogged("triage", provider, { system, user, timeoutSeconds: 180 });
  if (!raw) return null;
  const recommendedStatus = asString(raw.recommendedStatus, "investigating");
  const allowedStatus = ["investigating", "takedown", "false_positive", "open"];
  const recStatus = (allowedStatus.includes(recommendedStatus) ? recommendedStatus : "investigating") as TriageOutput["recommendedStatus"];
  const sev = asString(raw.severity, finding.severity || "medium");
  const allowedSev = ["critical", "high", "medium", "low", "info"];
  const severity = (allowedSev.includes(sev) ? sev : "medium") as TriageOutput["severity"];
  return {
    recommendedStatus: recStatus,
    severity,
    confidence: clamp01(asNumber(raw.confidence, 0.7)),
    reasoning: asString(raw.reasoning, "AI analysis complete."),
    suggestedActions: asStringArray(raw.suggestedActions, 6),
    iocs: asStringArray(raw.iocs, 12),
  };
}

// ---------- young_domain ----------
function youngDomainLive(input: YoungDomainAiInput, provider: AiProvider): YoungDomainAiOutput | null {
  const system = [
    "You are a senior brand-protection and phishing investigation analyst for an MSSP.",
    "You will receive candidate domain intelligence, WHOIS/DNS/MX/HTTP evidence, screenshot evidence, and official client brand assets including logos, trademarks, and app icons.",
    "When present, brandAbuse contains deterministic local image-similarity scores generated from uploaded brand assets and captured screenshots; treat those scores as evidence, not as a final verdict.",
    "When present, siteEvidence.urlscan contains URLScan.io search/submission metadata. Use existing URLScan results and submitted scan links as corroborating evidence, but do not require URLScan to be available.",
    "Classify the candidate into exactly one verdict: phishing, spoofing, brand_impersonation, forged_login, parked_benign, inconclusive.",
    "Use the explicit candidateUrl/finalUrl as source context. Do not assume a Cloudflare, CAPTCHA, security-check, parked, or inaccessible screenshot reveals the true site content.",
    "Use visual evidence only if image inputs are actually available to you. If you cannot inspect images, set visionSupported=false and do not claim that a logo, trademark, or app icon was visually detected.",
    "Image attachment convention: the first image (when present) is the candidate site's rendered landing-page screenshot. Any additional images are the tenant's official brand assets, ordered by `brandAssets` in the JSON below. Compare the screenshot against each brand asset and report visualSimilarity in [0,1].",
    "Consider lexical similarity, typosquatting technique, registration age, registrar anomalies, MX records, HTTP behavior, redirects, Cloudflare/block pages, login forms, page title/text, visual similarity to official assets, favicon/app-icon similarity, and overlap across DNSTwist, openSquat, crt.sh, DomScan, and keyword expansion.",
    "Respond with a STRICT JSON object matching:",
    `{ "verdict": "phishing" | "spoofing" | "brand_impersonation" | "forged_login" | "parked_benign" | "inconclusive",`,
    `  "confidence": number,  // 0..1`,
    `  "visionSupported": boolean,`,
    `  "brandAssetDetected": boolean,`,
    `  "matchedAssetKinds": ("logo" | "trademark" | "app_icon")[],`,
    `  "visualSimilarity": number | null,`,
    `  "loginFormDetected": boolean,`,
    `  "cloudflareBlocked": boolean,`,
    `  "keyEvidence": string[],`,
    `  "reasoning": string,`,
    `  "recommendedActions": string[],`,
    `  "targetBrand": string | null }`,
  ].join("\n");

  // Build the image-content array when the provider supports vision. The
  // raw base64 bytes never go in the user-text payload — they'd burn input
  // tokens for nothing. We replace them with descriptive metadata so the
  // model knows what each attached image represents.
  const visionOn = !!input.providerVisionSupported;
  const images: import("./aiLive").LiveChatImage[] = [];
  if (visionOn && input.screenshot?.available && input.screenshot.dataBase64 && input.screenshot.mime) {
    images.push({
      kind: "screenshot",
      mime: input.screenshot.mime,
      dataBase64: input.screenshot.dataBase64,
      label: `Candidate landing page screenshot for ${input.domain}`,
    });
  }
  if (visionOn) {
    for (const ba of input.brandAssets ?? []) {
      if (!ba.dataBase64 || !ba.mime) continue;
      images.push({
        kind: ba.kind,
        mime: ba.mime,
        dataBase64: ba.dataBase64,
        label: `Official ${ba.kind}: ${ba.name}`,
      });
    }
  }

  // Strip base64 bodies from the JSON-text payload regardless of whether
  // vision is on — when off, the model is told the screenshot exists but
  // cannot be inspected; when on, the actual bytes ride alongside as image
  // content-blocks. Either way the text user message stays compact.
  const sanitized = {
    ...input,
    screenshot: input.screenshot ? {
      available: !!input.screenshot.available,
      mime: input.screenshot.mime,
      url: input.screenshot.url,
    } : undefined,
    brandAssets: (input.brandAssets ?? []).map((ba) => ({
      kind: ba.kind, name: ba.name, mime: ba.mime, sha256: ba.sha256,
    })),
    _imageAttachments: images.length > 0
      ? images.map((img, idx) => ({ index: idx, kind: img.kind, mime: img.mime, label: img.label }))
      : [],
  };
  const user = JSON.stringify(sanitized);

  const raw = liveChatJsonLogged("young_domain", provider, {
    system,
    user,
    timeoutSeconds: 180,
    images: images.length ? images : undefined,
  });
  if (!raw) return null;
  const verdictRaw = asString(raw.verdict, "benign");
  const allowed = ["phishing", "spoofing", "brand_impersonation", "forged_login", "parked_benign", "inconclusive"];
  const verdict = (allowed.includes(verdictRaw) ? verdictRaw : "inconclusive") as YoungDomainAiOutput["verdict"];
  const kinds = Array.isArray(raw.matchedAssetKinds)
    ? raw.matchedAssetKinds.filter((k: any) => k === "logo" || k === "trademark" || k === "app_icon")
    : [];
  return {
    verdict,
    confidence: clamp01(asNumber(raw.confidence, 0.6)),
    reasoning: asString(raw.reasoning, "AI classification."),
    targetBrand: raw.targetBrand == null ? null : asString(raw.targetBrand, null as any) || null,
    visionSupported: !!raw.visionSupported,
    brandAssetDetected: !!raw.brandAssetDetected,
    matchedAssetKinds: kinds,
    visualSimilarity: raw.visualSimilarity == null ? null : clamp01(asNumber(raw.visualSimilarity, 0)),
    loginFormDetected: !!raw.loginFormDetected,
    cloudflareBlocked: !!raw.cloudflareBlocked,
    keyEvidence: asStringArray(raw.keyEvidence, 8),
    recommendedActions: asStringArray(raw.recommendedActions, 8),
  };
}

// ---------- report_summary ----------
function reportSummaryLive(input: ReportSummaryInput, provider: AiProvider): ReportSummaryOutput | null {
  const system = [
    "You are an executive-level cybersecurity report writer for an MSSP.",
    "Summarise the supplied report data. Respond with STRICT JSON:",
    `{ "executiveSummary": string,        // 3-5 sentences`,
    `  "keyFindings": string[],            // 3-6 bullets`,
    `  "recommendations": string[] }       // 3-6 bullets`,
  ].join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJsonLogged("report_summary", provider, { system, user, timeoutSeconds: 240 });
  if (!raw) return null;
  return {
    executiveSummary: asString(raw.executiveSummary, ""),
    keyFindings: asStringArray(raw.keyFindings, 10),
    recommendations: asStringArray(raw.recommendations, 10),
  };
}

// ---------- analysis ----------
function analysisLive(input: AnalysisInput, provider: AiProvider): AnalysisOutput | null {
  const system = [
    "You are a cybersecurity threat-analysis assistant.",
    "Read the user's prompt and any supplied context, then respond with STRICT JSON:",
    `{ "text": string,            // your analysis as a single Markdown string`,
    `  "structured": object|null  // optional supporting structure }`,
  ].join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJsonLogged("analysis", provider, { system, user, timeoutSeconds: 180 });
  if (!raw) return null;
  return {
    text: asString(raw.text, ""),
    structured: raw.structured && typeof raw.structured === "object" ? raw.structured : undefined,
  };
}

// ---------- logo_abuse ----------
function logoAbuseLive(input: LogoAbuseInput, provider: AiProvider): LogoAbuseOutput | null {
  const system = [
    "You are a trademark / logo-abuse analyst. The user supplies a base asset SHA-256 and a candidate URL.",
    "You cannot view images directly; use the URL pattern + filename + asset hash as signal.",
    "Respond with STRICT JSON:",
    `{ "match": boolean, "similarity": number (0..1), "reasoning": string }`,
  ].join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJsonLogged("logo_abuse", provider, { system, user, timeoutSeconds: 180 });
  if (!raw) return null;
  return {
    match: !!raw.match,
    similarity: clamp01(asNumber(raw.similarity, 0.5)),
    reasoning: asString(raw.reasoning, "AI logo-abuse assessment."),
  };
}

// ---------- osint_analysis ----------
// v2.18 — Variant C (user-refined) two-pass prompt. Pass 1 enumerates every
// CVE/MITRE/product/version/actor/malware/hash/IP/domain/URL/email/btc in a
// 'scratch' field with surrounding sentence-level evidence; Pass 2 promotes
// only sourceContent-grounded IoCs into the typed groups, applies the CIRT
// relevance ladder, and emits analystTags ⊆ (industries ∪ geos ∪
// monitoredTechnologies) via verbatim case-insensitive substring + obvious
// synonym matching. Scratch is discarded server-side.
function osintAnalysisLive(input: OsintAnalysisInput, provider: AiProvider): OsintAnalysisOutput | null {
  const hasFetched = !!(input.finding.sourceContent && input.finding.sourceContent.length > 40);
  const system = [
    "You are a senior CTI/CIRT analyst. The 'sourceContent' (when present) is the authoritative article body; the feed 'summary' is only a teaser.",
    hasFetched
      ? "The 'sourceContent' field holds the cleaned text of the original article and may include 'Referenced source (...)' sections fetched from links inside that article. Treat the Primary source as authoritative for the finding. Use Referenced source sections as supplemental evidence to enrich CVE details, vendor context, IoC confirmation, MITRE mapping, and recommended actions. If a referenced source conflicts with the Primary source, say so and prefer the Primary source for the finding's core claim."
      : "Only the feed teaser is available — sourceContent is empty. Say so in the summary and leave IoC groups empty rather than regex-fishing from the teaser.",
    "ALWAYS respond in ENGLISH. Translate non-English inline.",
    "",
    "Work in TWO passes before emitting JSON. Both passes happen inside the JSON object — the 'scratch' field captures pass 1; the remaining fields are pass 2. Do not skip pass 1.",
    "",
    "PASS 1 — EXTRACTION (scratch, internal reasoning):",
    "  • Read the article end-to-end and understand the context of the reported intel.",
    "  • If 'Referenced source (...)' sections are present, read those too and capture what they add beyond the primary article. Do not ignore referenced CVE/vendor/MITRE/IoC evidence.",
    "  • Extract every available CVE, MITRE TID, product name, version string, threat-actor alias, malware family, file hash, IP, domain, URL, email, and bitcoin address you see — VERBATIM, with the surrounding sentence as evidence.",
    "  • Mark each IoC as \"from primary source\", \"from referenced source\", or \"from feed summary\".",
    "",
    "PASS 2 — STRUCTURED OUTPUT:",
    "  • summary — 4-7 sentences covering: (a) actor + event, (b) affected products + verbatim CVEs, (c) mechanism + MITRE TXXXX + Cyber Kill Chain phase(s), (d) exploitation status (PoC / in-the-wild / mass-scanning / vendor-only disclosure). The summary is PROSE for analyst reading — DO NOT enumerate hashes, IP addresses, domains, URLs, or other raw IoCs inside the summary. Those go in the 'iocs' object only. You may say 'three C2 IPs and two backdoor SHA-256 hashes were observed' as a count/description, but never paste the actual values.",
    "  • relevanceScore — BatchOne CIRT actionability ladder:",
    "      0.85-1.00 — active exploitation, zero-day, severe supply-chain risk, confirmed IoCs, or urgent defensive action.",
    "      0.60-0.84 — actionable advisory with named CVEs, actors, malware, tools, or detection opportunities.",
    "      0.30-0.59 — useful context or trend signal, but limited direct actionability.",
    "      0.00-0.29 — generic news, marketing, event, opinion, or low-evidence content.",
    "  • recommendation — 2-4 ordered actions tied to analyst controls (patch validation, configuration review, detection rule, proactive hunt, or suppression/filtering).",
    "  • iocs — promote ONLY items marked \"from primary source\" or \"from referenced source\" in pass 1. Strip common defangs: '1.2.3[.]4' → '1.2.3.4', 'hxxps://' → 'https://', '(.)' → '.'. Empty arrays when none.",
    "  • CRITICAL IoC EXCLUSIONS — these are NEVER IoCs even if they appear in the text:",
    "    - The article's OWN URL (finding.url) or its publisher host. The publisher host is the domain that PUBLISHED the article. These are publication addresses, NOT threat indicators. Strip them from 'domain' and 'url' buckets.\n    - Reference URLs from well-known security publishers and vendor research blogs — even when they appear inside the article body. Examples: www.rapid7.com, www.mandiant.com, cloud.google.com/blog, www.crowdstrike.com, www.microsoft.com/security, learn.microsoft.com, blog.talosintelligence.com, unit42.paloaltonetworks.com, www.kaspersky.com, securelist.com, www.welivesecurity.com, www.welivesecurity.com, blogs.cisco.com, www.fortinet.com, www.sentinelone.com, www.sophos.com, www.symantec.com, www.trendmicro.com, www.checkpoint.com, research.checkpoint.com, www.recordedfuture.com, www.proofpoint.com, www.bleepingcomputer.com, thehackernews.com, www.infosecurity-magazine.com, www.securityweek.com, www.cisa.gov, www.cert.gov, attack.mitre.org, nvd.nist.gov, github.com, www.zdnet.com, krebsonsecurity.com, www.darkreading.com, www.theregister.com, blog.virustotal.com, www.virustotal.com. These are reference / citation links — never threat indicators.",
    "    - Software version numbers misclassified as IPv4. Strings like '3.2.1.1', '3.2.0.0', '10.0.19042', '6.5.4.2', '1.0.0.0', '7.0.3.5' are software/build version numbers — NOT IPv4 addresses. Real IPv4 IoCs typically (a) appear defanged ('1[.]2[.]3[.]4'), or (b) appear in an explicit Indicators/IoC table, or (c) have at least one octet > 32 AND are clearly described as network addresses. If the surrounding text says 'version', 'build', 'release', 'patch', 'Windows', 'firmware', 'driver', etc., it is NOT an IPv4.",
    "    - Vendor advisory URLs that merely link to a patch (e.g. https://www.microsoft.com/security/advisory/...) belong in 'recommendation' as references, NOT in the IoC 'url' bucket. The 'url' bucket is reserved for malicious / C2 / phishing URLs only.",
    "  • analystTags — for each item in clientProfile.industries ∪ clientProfile.geos ∪ clientProfile.monitoredTechnologies, check pass-1 evidence for a verbatim case-insensitive substring hit or an obvious synonym (e.g. 'Fortinet' → 'FortiGate VPN' is a hit). Emit only items from the three profile lists — NEVER invented strings. Order by strength of evidence. Max 8.",
    "  • intelCategory — classify the article into EXACTLY ONE of:",
    "      'threat_intel'   — actionable advisory: vulnerability + exploitation, incident report, IoC dump, malware analysis, threat-actor disclosure, ransomware victim post.",
    "      'regular_report' — periodic landscape / industry overview: quarterly threat report, annual security trend report, vendor M-Trends-style summary, regulatory bulletin without immediate IoCs.",
    "      'advertisement'  — product marketing / vendor promo / webinar / 'why our XDR is the best' content / sponsored partner post / sales-led case study. ALSO: posts that exist primarily to drive a CTA (free trial, demo, contact sales) rather than convey threat intelligence.",
    "      When in doubt between threat_intel and regular_report, pick threat_intel if the article includes a CVE, an IoC, or a named active campaign; otherwise regular_report. When in doubt between threat_intel and advertisement, pick threat_intel unless the article is dominated by branding/CTA language with thin or generic threat detail.",
    "  • attackTechniques — list MITRE ATT&CK techniques EXPLICITLY mentioned (verbatim) OR strongly implied by described behaviour. Use canonical ids: Tnnnn or Tnnnn.nnn for sub-techniques (e.g. T1566.001). Each item: { id, name?, tactic? } where tactic is the TA-id when known (e.g. 'TA0001' Initial Access). Max 12. Empty array when none.",
    "  • sectors — industry sectors named or strongly implied as victims/targets. Lowercase snake_case from this canonical list: finance, banking, healthcare, technology, government, defense, energy, manufacturing, retail, telecom, education, transportation, media, legal, insurance, hospitality, agriculture, critical_infrastructure. Max 8. Empty array when none.",
    "  • regions — geographic regions affected. Coarse buckets: 'global', 'apac', 'emea', 'americas', 'na', 'sa', 'africa'. Country codes (lowercase ISO 3166-1 alpha-2 like 'us', 'cn', 'hk', 'sg', 'jp', 'kr', 'gb', 'de', 'fr', 'ru', 'ua', 'il', 'in', 'au') are also accepted. Max 6. Empty array when none.",
    "",
    "Be specific. Do NOT paraphrase IoCs or CVE IDs. Do NOT pad. Omit information that isn't in the article rather than inventing it.",
    "",
    "Respond with STRICT JSON, no markdown fences:",
    `{`,
    `  "scratch":         string,        // pass-1 working notes, discarded server-side`,
    `  "summary":         string,        // 4-7 sentences, structure as above`,
    `  "relevanceScore":  number,        // 0..1, CIRT ladder`,
    `  "recommendation":  string,        // 2-4 ordered actions`,
    `  "iocs": {`,
    `    "ipv4":   string[],`,
    `    "ipv6":   string[],`,
    `    "domain": string[],`,
    `    "url":    string[],`,
    `    "md5":    string[],`,
    `    "sha1":   string[],`,
    `    "sha256": string[],`,
    `    "email":  string[],`,
    `    "btc":    string[]`,
    `  },`,
    `  "analystTags":     string[],     // ⊆ profile lists, verbatim, max 8`,
    `  "intelCategory":   string,        // 'threat_intel' | 'regular_report' | 'advertisement'`,
    `  "attackTechniques": Array<{ id: string; name?: string; tactic?: string }>,  // Tnnnn(.nnn), max 12`,
    `  "sectors":         string[],     // canonical sector list, max 8`,
    `  "regions":         string[]      // coarse bucket or ISO country code, max 6`,
    `}`,
  ].join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJsonLogged("osint_analysis", provider, { system, user, timeoutSeconds: 300 });
  if (!raw) return null;

  // ---- Normalise IoC groups (defang strip + dedupe) ----
  const IOC_KEYS = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "btc"] as const;
  const stripDefangs = (s: string): string => String(s)
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\{\.\}/g, ".")
    .replace(/\[dot\]/gi, ".")
    .replace(/\bhxxp(s?):\/\//gi, "http$1://")
    .replace(/\bfxp:\/\//gi, "ftp://")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]/g, "@")
    .replace(/\[at\]/gi, "@")
    .trim();
  const cleanedIocs: NonNullable<OsintAnalysisOutput["iocs"]> = {};
  if (raw.iocs && typeof raw.iocs === "object") {
    for (const k of IOC_KEYS) {
      const arr = (raw.iocs as any)[k];
      if (!Array.isArray(arr)) continue;
      const out: string[] = [];
      const seen = new Set<string>();
      for (const v of arr) {
        const s = stripDefangs(String(v || ""));
        if (!s) continue;
        const key = s.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(s);
      }
      if (out.length) (cleanedIocs as any)[k] = out;
    }
  }

  // ---- v2.23 — Belt-and-suspenders: even if the AI ignores the prompt's
  // "never include publisher host" rule, strip the article's own host from
  // the AI-returned domain and url buckets. Also strip software-version
  // false-positives from the ipv4 bucket. ----
  const publisherHosts = new Set<string>();
  if (input.finding.url) {
    try {
      const h = new URL(input.finding.url).hostname.toLowerCase();
      publisherHosts.add(h);
      publisherHosts.add(h.replace(/^www\./, ""));
    } catch { /* malformed finding URL — skip */ }
  }
  if (cleanedIocs.domain) {
    cleanedIocs.domain = cleanedIocs.domain.filter((d) => {
      const dl = String(d).toLowerCase();
      return !publisherHosts.has(dl) && !publisherHosts.has(dl.replace(/^www\./, ""));
    });
    if (!cleanedIocs.domain.length) delete cleanedIocs.domain;
  }
  if (cleanedIocs.url) {
    cleanedIocs.url = cleanedIocs.url.filter((u) => {
      try {
        const h = new URL(String(u)).hostname.toLowerCase();
        if (publisherHosts.has(h) || publisherHosts.has(h.replace(/^www\./, ""))) return false;
        // v2.28 — strip well-known security publisher / vendor research domains.
        // Reference links to these never become threat indicators.
        if (isSecurityPublisherHost(h)) return false;
        return true;
      } catch { return true; }
    });
    if (!cleanedIocs.url.length) delete cleanedIocs.url;
  }
  if (cleanedIocs.domain) {
    cleanedIocs.domain = cleanedIocs.domain.filter((d) => {
      // v2.28 — same publisher list, also applied to bare domain bucket.
      return !isSecurityPublisherHost(String(d).toLowerCase());
    });
    if (!cleanedIocs.domain.length) delete cleanedIocs.domain;
  }
  if (cleanedIocs.ipv4) {
    cleanedIocs.ipv4 = cleanedIocs.ipv4.filter((ip) => {
      const parts = String(ip).split(".").map(Number);
      if (parts.length !== 4 || parts.some((p) => !Number.isFinite(p))) return false;
      // Same heuristic as osintFetcher.looksLikeVersionNumber's octet rule:
      // all octets <= 32 AND at least two <= 9 → almost certainly a version.
      const allLow = parts.every((p) => p <= 32);
      const tinyCount = parts.filter((p) => p <= 9).length;
      if (allLow && tinyCount >= 2) return false;
      return true;
    });
    if (!cleanedIocs.ipv4.length) delete cleanedIocs.ipv4;
  }

  // ---- Normalise analyst tags: keep only verbatim case-insensitive members
  // of the three profile lists. Defends against hallucinated tags even if the
  // model ignores the prompt's "never invented" rule. ----
  const profileSet = new Map<string, string>(); // lower -> original casing
  for (const v of input.clientProfile.industries || []) profileSet.set(String(v).toLowerCase(), String(v));
  for (const v of input.clientProfile.geos || []) profileSet.set(String(v).toLowerCase(), String(v));
  for (const v of input.clientProfile.monitoredTechnologies || []) profileSet.set(String(v).toLowerCase(), String(v));
  const tagsOut: string[] = [];
  const tagSeen = new Set<string>();
  if (Array.isArray(raw.analystTags)) {
    for (const t of raw.analystTags) {
      const k = String(t || "").trim().toLowerCase();
      if (!k) continue;
      const original = profileSet.get(k);
      if (!original) continue; // drop hallucinated tags
      if (tagSeen.has(k)) continue;
      tagSeen.add(k);
      tagsOut.push(original);
      if (tagsOut.length >= 8) break;
    }
  }

  // v2.28 — belt-and-suspenders: even when the AI complies with the prompt's
  // "no IoCs in summary" rule most of the time, DeepSeek occasionally still
  // appends a 'Notable IoCs include ...' tail. Detect those sentences, extract
  // any IoCs they contain, merge them into the bag, and strip the sentences
  // from the prose. This keeps the analyst-facing summary clean prose while
  // ensuring no IoCs are lost.
  const rawSummary = asString(raw.summary, input.finding.title);
  const { summary: scrubbedSummary, iocs: finalIocs } = scrubIocSentencesFromSummary(rawSummary, cleanedIocs);

  // v2.29 — intel categorisation. Default to threat_intel when the AI omits
  // it; tolerate slight variations in casing or spelling. Anything outside
  // the three buckets is normalised to threat_intel to avoid blank rows.
  let intelCategory: OsintAnalysisOutput["intelCategory"] = "threat_intel";
  {
    const raw_cat = String((raw as any).intelCategory ?? "").trim().toLowerCase().replace(/\s+/g, "_");
    if (raw_cat === "regular_report" || raw_cat === "report" || raw_cat === "landscape") intelCategory = "regular_report";
    else if (raw_cat === "advertisement" || raw_cat === "ad" || raw_cat === "marketing" || raw_cat === "promo") intelCategory = "advertisement";
    else if (raw_cat === "threat_intel" || raw_cat === "threat" || raw_cat === "intel") intelCategory = "threat_intel";
  }

  // v2.30 — normalise attackTechniques / sectors / regions.
  const TECH_RE = /^T[0-9]{4}(\.[0-9]{3})?$/i;
  const techOut: Array<{ id: string; name?: string; tactic?: string }> = [];
  if (Array.isArray((raw as any).attackTechniques)) {
    const seen = new Set<string>();
    for (const t of (raw as any).attackTechniques) {
      let id = "", name: string | undefined, tactic: string | undefined;
      if (typeof t === "string") id = t;
      else if (t && typeof t === "object") {
        id = String(t.id ?? "");
        if (typeof t.name === "string") name = t.name;
        if (typeof t.tactic === "string") tactic = t.tactic;
      }
      id = id.trim().toUpperCase();
      if (!TECH_RE.test(id)) continue;
      if (seen.has(id)) continue;
      seen.add(id);
      techOut.push({ id, name, tactic });
      if (techOut.length >= 12) break;
    }
  }

  const SECTOR_CANON = new Set([
    "finance","banking","healthcare","technology","government","defense",
    "energy","manufacturing","retail","telecom","education","transportation",
    "media","legal","insurance","hospitality","agriculture","critical_infrastructure",
  ]);
  const SECTOR_ALIAS: Record<string,string> = {
    "financial":"finance","fintech":"finance","bank":"banking","banks":"banking",
    "health":"healthcare","medical":"healthcare","hospital":"healthcare",
    "tech":"technology","it":"technology","saas":"technology","cloud":"technology",
    "gov":"government","public_sector":"government","military":"defense",
    "oil":"energy","gas":"energy","power":"energy","utilities":"energy",
    "mfg":"manufacturing","industrial":"manufacturing","ot":"manufacturing",
    "ecommerce":"retail","e-commerce":"retail","telecommunications":"telecom",
    "telco":"telecom","isp":"telecom","edu":"education","university":"education",
    "logistics":"transportation","shipping":"transportation","aviation":"transportation",
    "news":"media","journalism":"media","law":"legal","insurer":"insurance",
    "hotel":"hospitality","tourism":"hospitality","farm":"agriculture",
    "cni":"critical_infrastructure","infrastructure":"critical_infrastructure",
  };
  const sectorsOut: string[] = [];
  if (Array.isArray((raw as any).sectors)) {
    const seen = new Set<string>();
    for (const v of (raw as any).sectors) {
      const k0 = String(v || "").trim().toLowerCase().replace(/\s+/g, "_");
      if (!k0) continue;
      const k = SECTOR_CANON.has(k0) ? k0 : (SECTOR_ALIAS[k0] || "");
      if (!k || !SECTOR_CANON.has(k)) continue;
      if (seen.has(k)) continue;
      seen.add(k);
      sectorsOut.push(k);
      if (sectorsOut.length >= 8) break;
    }
  }

  const REGION_BUCKET = new Set(["global","apac","emea","americas","na","sa","africa"]);
  const COUNTRY_RE = /^[a-z]{2}$/;
  const regionsOut: string[] = [];
  if (Array.isArray((raw as any).regions)) {
    const seen = new Set<string>();
    for (const v of (raw as any).regions) {
      const k = String(v || "").trim().toLowerCase();
      if (!k) continue;
      if (!REGION_BUCKET.has(k) && !COUNTRY_RE.test(k)) continue;
      if (seen.has(k)) continue;
      seen.add(k);
      regionsOut.push(k);
      if (regionsOut.length >= 6) break;
    }
  }

  return {
    summary: scrubbedSummary,
    relevanceScore: clamp01(asNumber(raw.relevanceScore, 0.5)),
    recommendation: asString(raw.recommendation, "Monitor for trending; revisit if corroborating reports emerge."),
    iocs: Object.keys(finalIocs).length ? finalIocs : undefined,
    analystTags: tagsOut.length ? tagsOut : undefined,
    intelCategory,
    attackTechniques: techOut.length ? techOut : undefined,
    sectors: sectorsOut.length ? sectorsOut : undefined,
    regions: regionsOut.length ? regionsOut : undefined,
  };
}

// ---------- hunt_query ----------
function huntQueryLive(input: HuntQueryInput, provider: AiProvider): HuntQueryOutput | null {
  const langs = input.languages || [];
  if (langs.length === 0) return {};
  const grammarRef = grammarReferenceFor(langs);
  const anyFetched = (input.findings || []).some((f) => !!(f.sourceContent && f.sourceContent.length > 40));
  const system = [
    "You are a Lead Detection Engineer and Threat Hunter. From the supplied OSINT findings, write hunting queries for EACH requested language.",
    anyFetched
      ? "Each finding includes its source URL plus the FULL article text fetched from that URL (in the 'sourceContent' field). Read the article end-to-end before drafting queries — do NOT rely on the title or summary alone. Extract IoCs (CVEs, file paths, registry keys, command lines, domains, hashes, behavioural patterns, mutex names, scheduled-task names) directly from the article body, VERBATIM."
      : "Only short summaries are available; extract every IoC, CVE, technology, and threat actor you can.",
    "For EACH requested language, produce 1 to 5 DISTINCT queries — exactly as many as the intel justifies. Each query MUST cover a different detection ANGLE drawn from this taxonomy:",
    "  (a) NETWORK — DNS queries, HTTP/TLS connections, JA3/JA4, C2 beacon patterns, domain / IP / URL indicators.",
    "  (b) ENDPOINT — process tree, parent-child anomalies, command-line / argument patterns, LOLBin abuse, suspicious API calls.",
    "  (c) FILE / REGISTRY / PERSISTENCE — file hashes, written paths, scheduled tasks, Run keys, services, WMI subscriptions, startup folders.",
    "  (d) AUTHENTICATION / IDENTITY / LATERAL MOVEMENT — anomalous logons, Kerberos abuse (AS-REP / Golden / Silver), token theft, SMB / WinRM / RDP pivoting.",
    "  (e) DATA STAGING / EXFILTRATION — archiving tools, cloud-storage uploads, DNS-tunnelling, large outbound transfers.",
    "Hard rules: do NOT pad with weak queries — one well-grounded query beats five guesses. Skip angles the intel does not support. Anchor every TTP-driven query to a MITRE ATT&CK technique ID (TXXXX[.XXX]) in the description.",
    "Every query MUST be valid in its target platform's native syntax (Splunk SPL, Elastic KQL/EQL, Chronicle UDM, Defender KQL, CrowdStrike CQL / Falcon LogScale, Cortex XQL, SentinelOne Deep Visibility / PowerQuery, YARA, Sigma).",
    "Always respond in ENGLISH. Translate any non-English quoted strings inline. Query keywords / operators stay in the platform's native syntax, but field names, comments, and any prose MUST be English.",
    "Respond with STRICT JSON. Include a top-level `title` string for the overall hunt package, then one key per requested language identifier. The title must be identifiable and based on the strongest visible signal, such as the primary CVE, actor, malware/tool, affected product, or source campaign. Avoid generic labels like `OSINT findings`.",
    "Each language value is an OBJECT shaped like:",
    `{ "title": "Identifiable hunt title", "<language>": { "queries": [ { "name": "short English label", "description": "one-sentence English explanation including the MITRE TXXXX where applicable", "query": "...native syntax, no markdown fences..." }, ... ] } }`,
    "Backward-compat: if you can only produce one query, you may instead return the language value as a single string — but prefer the structured 'queries' array.",
    "Do NOT wrap query content in markdown fences. The 'query' field must be ready to paste into the target SIEM unchanged.",
    "Supported language identifiers include: splunk, kql_elk, chronicle, defender, crowdstrike, cortex_xdr, sentinelone, yara, sigma.",
    grammarRef ? "\n" + grammarRef : "",
  ].filter(Boolean).join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJsonLogged("hunt_query", provider, { system, user, timeoutSeconds: 300 });
  if (!raw) return null;
  const out: HuntQueryOutput = {};
  if (typeof raw.title === "string" && raw.title.trim().length > 0) {
    (out as any).__title = raw.title.trim().slice(0, 160);
  }
  for (const lang of langs) {
    const v = raw[lang];
    if (typeof v === "string" && v.trim().length > 0) {
      out[lang] = v.trim();
    } else if (v && typeof v === "object" && Array.isArray(v.queries)) {
      const items: string[] = [];
      for (const item of v.queries) {
        if (!item) continue;
        if (typeof item === "string" && item.trim().length > 0) {
          items.push(item.trim());
          continue;
        }
        const qstr = typeof item.query === "string" ? item.query.trim() : "";
        if (!qstr) continue;
        const name = typeof item.name === "string" && item.name.trim() ? item.name.trim() : null;
        const desc = typeof item.description === "string" && item.description.trim() ? item.description.trim() : null;
        const header = [name, desc].filter(Boolean).join(" — ");
        items.push(header ? `// ${header}\n${qstr}` : qstr);
      }
      if (items.length === 1) out[lang] = items[0];
      else if (items.length > 1) out[lang] = items;
    } else if (Array.isArray(v)) {
      const items = v.filter((s: any) => typeof s === "string" && s.trim().length > 0).map((s: string) => s.trim());
      if (items.length === 1) out[lang] = items[0];
      else if (items.length > 1) out[lang] = items;
    }
  }
  return Object.keys(out).length > 0 ? out : null;
}

// ---------- detection_rule (v2.30.2 — Detection Rule Studio) ----------
export interface DetectionRuleInput {
  findings: Array<{
    title: string;
    cveIds: string[];
    affectedTech: string[];
    threatActors: string[];
    summary?: string | null;
    rawSnippet?: string | null;
    severity?: string;
    url?: string | null;
    sourceContent?: string | null;
    attackTechniques?: Array<{ id: string; name?: string; tactic?: string }> | null;
  }>;
  languages: string[];  // SIEM target ids the user asked us to emit
  // Free-form analyst hint that biases the rule (e.g. "focus on detection from
  // proxy logs" or "exclude staging environments").
  hint?: string;
}
export interface DetectionRuleOutput {
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  mitreTechniques: Array<{ id: string; name?: string; tactic?: string }>;
  sigmaYaml: string;
  queries: Record<string, string>; // siemId -> compiled query
  notes: string;
}
function detectionRuleLive(input: DetectionRuleInput, provider: AiProvider): DetectionRuleOutput | null {
  const langs = (input.languages || []).filter(Boolean);
  if (langs.length === 0) return null;
  const system = [
    "You are a Lead Detection Engineer building a single, deployable detection rule from one or more pieces of OSINT threat intel.",
    "You will return ONE rule — not one rule per finding. Synthesize the supplied intel into ONE high-fidelity behaviour that warrants alerting.",
    "The rule must be specific enough to deploy without immediate FP storms: anchor on at least one strong primary indicator (process+commandline anomaly, signed-binary abuse with a specific child, registry write under a specific key, unusual logon pattern, exact C2 indicator, etc.) plus 1-2 corroborating conditions.",
    "You MUST produce:",
    "  • sigmaYaml — a valid Sigma YAML document (https://github.com/SigmaHQ/sigma). Include: title, id (uuid), status: experimental, description, references (the supplied source URLs), author: 'OptraSight Detection Studio', date (today YYYY/MM/DD), tags (attack.* lower-case names like attack.execution / attack.t1059.001), logsource, detection (selection/condition), falsepositives, level (severity). Do NOT wrap in markdown fences.",
    "  • queries — the SAME detection compiled to EACH requested SIEM/EDR target. Keys MUST be the exact requested language identifiers. Each value is a SINGLE query string (no fences), valid in its target's native syntax:",
    "      splunk      → Splunk SPL (use index= and source/sourcetype when knowable; bound time with earliest=-7d unless otherwise stated)",
    "      kql_elk     → Elastic KQL (NOT EQL); plain `field:value AND …` form",
    "      defender    → Microsoft Sentinel / Defender KQL: starts with a table name (DeviceProcessEvents, SecurityEvent, etc.) followed by `| where …`",
    "      crowdstrike → CrowdStrike Falcon LogScale CQL: `#repo=base_sensor | <conditions>`",
    "      cortex_xdr  → Palo Alto XQL: `dataset=xdr_data | filter …`",
    "      sentinelone → SentinelOne PowerQuery: `<conditions> | <pipes>`",
    "      chronicle   → Google Chronicle YARA-L 2.0 (rule { meta events condition })",
    "  • mitreTechniques — every MITRE ATT&CK technique the rule covers, with id (TXXXX[.XXX]), name, and tactic. Do NOT invent IDs.",
    "  • severity — one of low|medium|high|critical, calibrated to potential impact AND signal strength.",
    "  • title — short, English, action-focused (e.g. 'CVE-2024-XYZ — ScreenConnect post-exploitation child-process chain').",
    "  • description — 2-4 sentences in plain English: what behaviour, why it matters, anchor to the supplied intel.",
    "  • notes — tuning + deployment guidance: known FP sources, recommended index/datasource, thresholds, and how to validate.",
    "Hard rules:",
    "  • Always respond in ENGLISH — keywords/operators stay native, but field names, comments and prose are English. Translate any non-English strings inline.",
    "  • Do NOT pad queries with weak OR-chains; one well-grounded detection beats five guesses.",
    "  • If the intel does not support a specific platform's data sources, still emit a syntactically valid query for that platform anchored on the strongest cross-platform indicators — do NOT skip languages.",
    "  • Do NOT wrap any query/yaml content in markdown fences. Every value must paste verbatim into the target tool.",
    "Respond with STRICT JSON matching exactly:",
    `{ "title": string, "description": string, "severity": "low|medium|high|critical", "mitreTechniques": [{"id":"T1059.001","name":"PowerShell","tactic":"execution"}], "sigmaYaml": string, "queries": { "<lang>": string, ... }, "notes": string }`,
  ].join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJsonLogged("detection_rule", provider, { system, user, timeoutSeconds: 360 });
  if (!raw) return null;
  const rawTitle = typeof raw.title === "string" ? raw.title.trim() : "";
  const rawDesc = typeof raw.description === "string" ? raw.description.trim() : "";
  const rawSeverity = typeof raw.severity === "string" ? raw.severity.toLowerCase().trim() : "medium";
  const severity: DetectionRuleOutput["severity"] = (["low", "medium", "high", "critical"] as const).includes(rawSeverity as any) ? (rawSeverity as any) : "medium";
  const rawSigma = typeof raw.sigmaYaml === "string" ? raw.sigmaYaml.trim() : "";
  const rawNotes = typeof raw.notes === "string" ? raw.notes.trim() : "";
  const rawQueries = raw.queries && typeof raw.queries === "object" ? raw.queries : {};
  const queries: Record<string, string> = {};
  for (const lang of langs) {
    const v = rawQueries[lang];
    if (typeof v === "string" && v.trim().length > 0) queries[lang] = v.trim();
  }
  const techniques: Array<{ id: string; name?: string; tactic?: string }> = [];
  if (Array.isArray(raw.mitreTechniques)) {
    for (const t of raw.mitreTechniques) {
      if (!t) continue;
      const tid = typeof t.id === "string" ? t.id.trim() : "";
      if (!tid) continue;
      techniques.push({
        id: tid,
        name: typeof t.name === "string" ? t.name.trim() : undefined,
        tactic: typeof t.tactic === "string" ? t.tactic.trim() : undefined,
      });
    }
  }
  // Bare minimum to call the live call a success: title + (sigma or at least one query).
  if (!rawTitle || (!rawSigma && Object.keys(queries).length === 0)) return null;
  return {
    title: rawTitle,
    description: rawDesc,
    severity,
    mitreTechniques: techniques,
    sigmaYaml: rawSigma,
    queries,
    notes: rawNotes,
  };
}

// ---------- threat_actor_enrichment (v2.30.3) ----------
// Populates an entire Threat Actor Profile from a primary name + optional
// aliases. The output shape mirrors the 13-section + 4-appendix template the
// user supplied so the storage layer can write it straight into the TAP tables
// without any extra parsing.
export interface ThreatActorEnrichmentInput {
  primaryName: string;
  aliases?: string[];
  actorType?: string;
  knownContext?: string; // free-form analyst hint
  // v2.30.5 — list of tenants the AI may tag as relevant. Each entry is
  // { id, name, sector, region, orgSize }. When provided, the model emits
  // `relevantTenants: [{ tenantId, relevance, rationale }]` in its response
  // so the server can persist them as auto-suggested tenant relevance tags.
  availableTenants?: Array<{
    id: string;
    name: string;
    sector: string | null;
    region: string | null;
    orgSize: string | null;
  }>;
}
export interface ThreatActorEnrichmentOutput {
  // header / identity
  primaryName: string;
  mitreGroupId: string | null;
  aliases: string[];
  vendorNames: Record<string, string[]>;
  actorType: string;
  sponsorship: string;
  assessedOrigin: string | null;
  originConfidence: string | null;
  sponsoringEntity: string | null;
  motivation: string[];
  activeSince: number | null;
  sophistication: string;
  tlp: string;
  admiraltySource: string;
  admiraltyInfo: string;
  wepConfidence: string;
  // §3 targeting
  targetSectors: string[];
  targetRegions: string[];
  targetTechStack: string[];
  orgSizePreference: string | null;
  intentProximity: string;
  // §1 exec summary
  execWhat: string;
  execSoWhat: string;
  execWhatNow: string;
  threatLevel: string;
  threatLevelRationale: string;
  sectorActivelyTargeted: boolean;
  // §6 Diamond Model
  diamondAdversary: Record<string, any>;
  diamondCapability: Record<string, any>;
  diamondInfrastructure: Record<string, any>;
  diamondVictim: Record<string, any>;
  diamondMeta: Record<string, any>;
  // §3 business impact
  businessImpact: Record<string, any>;
  // §4 capability
  capabilityProfile: Record<string, any>;
  // §5 MITRE ATT&CK matrix
  ttps: Array<{
    tactic: string;
    techniqueId: string;
    subTechniqueId?: string | null;
    techniqueName: string;
    evidence?: string | null;
    status?: string;
    detectionPriority?: string;
  }>;
  // §5 tooling/malware
  tools: Array<{
    name: string;
    category?: string | null;
    purpose?: string | null;
    variants?: string[];
    hashOrRule?: string | null;
    confidence?: string;
  }>;
  // §7 campaign timeline
  campaigns: Array<{
    name: string;
    period?: string | null;
    targetSector?: string | null;
    targetGeography?: string | null;
    initialAccess?: string | null;
    outcome?: string | null;
    sourceUrl?: string | null;
  }>;
  // §7 extortion (ransomware-only; empty object otherwise)
  extortionTactics: Record<string, any>;
  // §8 infrastructure profile
  infrastructureProfile: Record<string, any>;
  // §10 IR actions
  irActions: Record<string, any>;
  // §11 countermeasures (D3FEND / CIS v8 / ISO 27001:2022)
  countermeasures: Record<string, any>;
  // §12 forecast
  forecast: string;
  // Appendix A — IOCs
  iocs: Array<{
    iocType: string;
    value: string;
    firstSeen?: string | null;
    lastConfirmed?: string | null;
    confidence?: string;
    tlp?: string;
    source?: string | null;
    mitreTtps?: string[];
    recommendedAction?: string | null;
  }>;
  // Appendix C — References
  references: Array<{
    refNum?: number;
    sourceType?: string | null;
    title: string;
    date?: string | null;
    url?: string | null;
    archiveUrl?: string | null;
  }>;
  // v2.30.5 — tenant relevance tags suggested by the AI. Only populated when
  // `availableTenants` was provided in the input. Each entry references one of
  // the supplied tenants by id.
  relevantTenants: Array<{
    tenantId: string;
    relevance: "targeted" | "sector-match" | "watching";
    rationale: string | null;
  }>;
  // Full narrative markdown body (canonical long-form)
  bodyMd: string;
}
function threatActorEnrichmentLive(
  input: ThreatActorEnrichmentInput,
  provider: AiProvider,
): ThreatActorEnrichmentOutput | null {
  const aliases = (input.aliases ?? []).filter(Boolean);
  const system = [
    "You are a Senior Threat-Intelligence Analyst producing a structured Threat Actor Profile (TAP) suitable for delivery to a banking-sector SOC/CIRT.",
    "Always respond in ENGLISH. Translate any non-English actor names, group aliases, motto, or quoted strings inline.",
    "Produce a complete, evidence-anchored dossier covering: identity & attribution, vendor naming cross-ref (microsoft, crowdstrike, mandiant, recordedFuture, mitre, other), victimology & targeting, capability & resources, MITRE ATT&CK TTP matrix (with TXXXX[.XXX] IDs and tactic names), Diamond Model (adversary, capability, infrastructure, victim, meta-features), campaign timeline, infrastructure patterns, IOCs, IR actions (by phase 0-4h / 4-72h / 72h-1wk / 1-4wk), defensive countermeasures (D3FEND, CIS v8, ISO 27001:2022), forecast, and references with archive.org URLs where available.",
    "Use the words-of-estimative-probability (WEP) linguistic scale verbatim: 'Almost No Chance' | 'Very Unlikely' | 'Unlikely' | 'Roughly Even Chance' | 'Likely' | 'Very Likely' | 'Almost Certain'.",
    "Use Admiralty source letters A..F and info digits 1..6. Use TLP labels CLEAR|GREEN|AMBER|AMBER+STRICT|RED. Use threatLevel CRITICAL|HIGH|MODERATE|LOW.",
    "Use sophistication Strategic|Advanced|Intermediate|Basic. Use intentProximity Direct|Adjacent|Opportunistic|Indirect.",
    "TTP status values: confirmed | suspected | not-observed. detectionPriority: P1|P2|P3|P4.",
    "IOC iocType values: ipv4|ipv6|domain|url|md5|sha1|sha256|email|asn|mutex|regkey|filename|filepath|cert_sha1|btc_address.",
    "bodyMd MUST be a full Markdown report using these exact section headings in order:",
    "  # <Primary Name> \u2014 Threat Actor Profile",
    "  ## 1. Executive Summary",
    "  ## 2. Identity & Attribution",
    "  ## 3. Victimology & Targeting",
    "  ## 4. Capability & Resources",
    "  ## 5. Modus Operandi & TTP Matrix",
    "  ## 6. Diamond Model",
    "  ## 7. Campaign & Activity Timeline",
    "  ## 8. Infrastructure Profile",
    "  ## 9. Detection & Threat Hunting",
    "  ## 10. Incident Response Actions",
    "  ## 11. Defensive Countermeasures",
    "  ## 12. Forecast, Implications & Recommendations",
    "  ## 13. Intelligence Confidence Assessment",
    "  ## Appendix A \u2014 IOC Register",
    "  ## Appendix B \u2014 STIX 2.1 Export",
    "  ## Appendix C \u2014 References",
    "Do not invent CVEs, ATT&CK IDs, IOCs or report titles. If a fact is unknown, omit it or set the value to null; do not pad with vague text.",
    // --- v2.30.5: tenant-relevance suggestion ---
    // If `availableTenants` is supplied in the user payload, you MUST also output
    // a `relevantTenants` array suggesting which of those tenants this actor is
    // most relevant to. Use one of three relevance levels:
    //   'targeted'     — direct public evidence the actor has attacked this tenant
    //                    (name match in a campaign report, leaked victim list, etc.)
    //   'sector-match' — the actor's known target sector / region / org-size profile
    //                    overlaps with the tenant's profile.
    //   'watching'     — plausible future relevance based on TTPs or geopolitical alignment,
    //                    but no direct evidence yet.
    // Only tag tenants where there is a real reason — do NOT tag every tenant by default.
    // Provide a one-sentence `rationale` for each tag. If `availableTenants` is empty
    // or missing, return `relevantTenants: []`.
    "If the user payload includes `availableTenants`, also emit `relevantTenants`: a list of {tenantId, relevance, rationale} entries. relevance MUST be one of 'targeted' | 'sector-match' | 'watching'. Reference tenants ONLY by their supplied id. Do not invent tenants. Keep rationales to one sentence each.",
    "Respond with STRICT JSON matching this TypeScript shape exactly (snake_case keys are NOT allowed \u2014 use camelCase):",
    `{
  "primaryName": string, "mitreGroupId": string | null,
  "aliases": string[], "vendorNames": { "microsoft": string[], "crowdstrike": string[], "mandiant": string[], "recordedFuture": string[], "mitre": string[], "other": string[] },
  "actorType": string, "sponsorship": string,
  "assessedOrigin": string | null, "originConfidence": string | null, "sponsoringEntity": string | null,
  "motivation": string[], "activeSince": number | null, "sophistication": string,
  "tlp": string, "admiraltySource": string, "admiraltyInfo": string, "wepConfidence": string,
  "targetSectors": string[], "targetRegions": string[], "targetTechStack": string[],
  "orgSizePreference": string | null, "intentProximity": string,
  "execWhat": string, "execSoWhat": string, "execWhatNow": string,
  "threatLevel": string, "threatLevelRationale": string, "sectorActivelyTargeted": boolean,
  "diamondAdversary": object, "diamondCapability": object, "diamondInfrastructure": object, "diamondVictim": object, "diamondMeta": object,
  "businessImpact": { "financial": string, "operational": string, "reputational": string, "regulatory": string, "data": string, "strategic": string },
  "capabilityProfile": { "tier": string, "evidence": string, "funding": string, "people": string, "training": string, "coordination": string },
  "ttps": [{ "tactic": "TA0001 Initial Access", "techniqueId": "T1566", "subTechniqueId": "T1566.001" | null, "techniqueName": string, "evidence": string, "status": "confirmed"|"suspected"|"not-observed", "detectionPriority": "P1"|"P2"|"P3"|"P4" }],
  "tools": [{ "name": string, "category": string, "purpose": string, "variants": string[], "hashOrRule": string | null, "confidence": string }],
  "campaigns": [{ "name": string, "period": string, "targetSector": string, "targetGeography": string, "initialAccess": string, "outcome": string, "sourceUrl": string | null }],
  "extortionTactics": object,
  "infrastructureProfile": { "hostingPatterns": object, "c2": string[], "redirectors": string[], "signedCerts": string[], "vps": string[] },
  "irActions": { "immediate": string[], "shortTerm": string[], "mediumTerm": string[], "strategic": string[] },
  "countermeasures": { "d3fend": string[], "cisV8": string[], "iso27001": string[] },
  "forecast": string,
  "iocs": [{ "iocType": string, "value": string, "firstSeen": string | null, "lastConfirmed": string | null, "confidence": string, "tlp": string, "source": string | null, "mitreTtps": string[], "recommendedAction": string | null }],
  "references": [{ "refNum": number, "sourceType": string, "title": string, "date": string | null, "url": string | null, "archiveUrl": string | null }],
  "relevantTenants": [{ "tenantId": string, "relevance": "targeted"|"sector-match"|"watching", "rationale": string }],
  "bodyMd": string
}`,
  ].join("\n");
  const user = JSON.stringify({
    primaryName: input.primaryName,
    aliases,
    actorType: input.actorType ?? null,
    knownContext: input.knownContext ?? null,
    availableTenants: input.availableTenants ?? [],
    requestedAt: new Date().toISOString(),
  });
  const raw = liveChatJsonLogged("threat_actor_enrichment", provider, {
    system, user,
    timeoutSeconds: 540,
    maxTokens: 32000,
  });
  if (!raw || typeof raw !== "object") return null;
  const str = (v: any, d = ""): string => (typeof v === "string" ? v.trim() : d);
  const strOrNull = (v: any): string | null => {
    if (v === null || v === undefined) return null;
    const s = String(v).trim();
    return s.length === 0 ? null : s;
  };
  const arrStr = (v: any): string[] => Array.isArray(v) ? v.filter((x) => typeof x === "string" && x.trim().length > 0).map((x) => x.trim()) : [];
  const obj = (v: any): Record<string, any> => (v && typeof v === "object" && !Array.isArray(v)) ? v : {};
  const primaryName = str(raw.primaryName, input.primaryName);
  const bodyMd = str(raw.bodyMd, "");
  if (!primaryName || !bodyMd) return null;
  const vendorRaw = obj(raw.vendorNames);
  const vendorNames: Record<string, string[]> = {};
  for (const k of ["microsoft", "crowdstrike", "mandiant", "recordedFuture", "mitre", "other"]) {
    vendorNames[k] = arrStr(vendorRaw[k]);
  }
  const out: ThreatActorEnrichmentOutput = {
    primaryName,
    mitreGroupId: strOrNull(raw.mitreGroupId),
    aliases: arrStr(raw.aliases),
    vendorNames,
    actorType: str(raw.actorType, "Unknown"),
    sponsorship: str(raw.sponsorship, "Unknown"),
    assessedOrigin: strOrNull(raw.assessedOrigin),
    originConfidence: strOrNull(raw.originConfidence),
    sponsoringEntity: strOrNull(raw.sponsoringEntity),
    motivation: arrStr(raw.motivation),
    activeSince: typeof raw.activeSince === "number" ? Math.floor(raw.activeSince) : (raw.activeSince ? parseInt(String(raw.activeSince), 10) || null : null),
    sophistication: str(raw.sophistication, "Intermediate"),
    tlp: str(raw.tlp, "AMBER"),
    admiraltySource: str(raw.admiraltySource, "B"),
    admiraltyInfo: str(raw.admiraltyInfo, "2"),
    wepConfidence: str(raw.wepConfidence, "Likely"),
    targetSectors: arrStr(raw.targetSectors),
    targetRegions: arrStr(raw.targetRegions),
    targetTechStack: arrStr(raw.targetTechStack),
    orgSizePreference: strOrNull(raw.orgSizePreference),
    intentProximity: str(raw.intentProximity, "Opportunistic"),
    execWhat: str(raw.execWhat),
    execSoWhat: str(raw.execSoWhat),
    execWhatNow: str(raw.execWhatNow),
    threatLevel: str(raw.threatLevel, "MODERATE"),
    threatLevelRationale: str(raw.threatLevelRationale),
    sectorActivelyTargeted: !!raw.sectorActivelyTargeted,
    diamondAdversary: obj(raw.diamondAdversary),
    diamondCapability: obj(raw.diamondCapability),
    diamondInfrastructure: obj(raw.diamondInfrastructure),
    diamondVictim: obj(raw.diamondVictim),
    diamondMeta: obj(raw.diamondMeta),
    businessImpact: obj(raw.businessImpact),
    capabilityProfile: obj(raw.capabilityProfile),
    ttps: Array.isArray(raw.ttps) ? raw.ttps.filter((t: any) => t && typeof t.techniqueId === "string" && typeof t.techniqueName === "string").map((t: any) => ({
      tactic: str(t.tactic),
      techniqueId: str(t.techniqueId),
      subTechniqueId: strOrNull(t.subTechniqueId),
      techniqueName: str(t.techniqueName),
      evidence: strOrNull(t.evidence),
      status: str(t.status, "suspected"),
      detectionPriority: str(t.detectionPriority, "P3"),
    })) : [],
    tools: Array.isArray(raw.tools) ? raw.tools.filter((t: any) => t && typeof t.name === "string").map((t: any) => ({
      name: str(t.name),
      category: strOrNull(t.category),
      purpose: strOrNull(t.purpose),
      variants: arrStr(t.variants),
      hashOrRule: strOrNull(t.hashOrRule),
      confidence: str(t.confidence, "Likely"),
    })) : [],
    campaigns: Array.isArray(raw.campaigns) ? raw.campaigns.filter((c: any) => c && typeof c.name === "string").map((c: any) => ({
      name: str(c.name),
      period: strOrNull(c.period),
      targetSector: strOrNull(c.targetSector),
      targetGeography: strOrNull(c.targetGeography),
      initialAccess: strOrNull(c.initialAccess),
      outcome: strOrNull(c.outcome),
      sourceUrl: strOrNull(c.sourceUrl),
    })) : [],
    extortionTactics: obj(raw.extortionTactics),
    infrastructureProfile: obj(raw.infrastructureProfile),
    irActions: obj(raw.irActions),
    countermeasures: obj(raw.countermeasures),
    forecast: str(raw.forecast),
    iocs: Array.isArray(raw.iocs) ? raw.iocs.filter((i: any) => i && typeof i.value === "string" && typeof i.iocType === "string").map((i: any) => ({
      iocType: str(i.iocType),
      value: str(i.value),
      firstSeen: strOrNull(i.firstSeen),
      lastConfirmed: strOrNull(i.lastConfirmed),
      confidence: str(i.confidence, "Likely"),
      tlp: str(i.tlp, "AMBER"),
      source: strOrNull(i.source),
      mitreTtps: arrStr(i.mitreTtps),
      recommendedAction: strOrNull(i.recommendedAction),
    })) : [],
    references: Array.isArray(raw.references) ? raw.references.filter((r: any) => r && typeof r.title === "string").map((r: any, i: number) => ({
      refNum: typeof r.refNum === "number" ? r.refNum : i + 1,
      sourceType: strOrNull(r.sourceType),
      title: str(r.title),
      date: strOrNull(r.date),
      url: strOrNull(r.url),
      archiveUrl: strOrNull(r.archiveUrl),
    })) : [],
    relevantTenants: (() => {
      const allowedIds = new Set((input.availableTenants ?? []).map((t) => t.id));
      const allowedRel = new Set(["targeted", "sector-match", "watching"]);
      if (!Array.isArray(raw.relevantTenants)) return [];
      return raw.relevantTenants
        .filter((t: any) => t && typeof t.tenantId === "string" && allowedIds.has(t.tenantId))
        .map((t: any) => ({
          tenantId: t.tenantId,
          relevance: (allowedRel.has(t.relevance) ? t.relevance : "watching") as "targeted" | "sector-match" | "watching",
          rationale: strOrNull(t.rationale),
        }));
    })(),
    bodyMd,
  };
  return out;
}

// ---------- threat_landscape ----------
function threatLandscapeLive(input: ThreatLandscapeInput, provider: AiProvider): ThreatLandscapeOutput | null {
  const system = [
    "You are a Lead Threat-Intelligence Analyst writing a client-specific threat-landscape brief in CIRT report style.",
    "Always respond in ENGLISH. Translate any non-English actor names, group aliases, or quoted strings inline.",
    "bodyMd MUST use this exact Markdown skeleton (sections in this order, headings verbatim):",
    "  # 🌐 Client Threat Landscape Brief",
    "  ## 📋 Executive Summary",
    "  ## 🎭 Threat Actor Activity",
    "    — name groups, aliases, MITRE G-IDs (GXXXX), recent campaigns affecting the client's sector / geography.",
    "  ## 🧨 Vulnerability Landscape",
    "    — verbatim CVE IDs, affected products / versions, exploitation status (PoC / ITW / mass-scanning).",
    "  ## ⚙️ Detection & Mitigation Recommendations",
    "    — direct, ordered actions tied to a concrete asset or control; reference MITRE TXXXX where relevant.",
    "  ## 🔗 Source References",
    "    — bullet list of `[source] — [url]` for every intel item cited above.",
    "Be specific. Do NOT paraphrase CVE IDs, actor names, or IOCs. Do NOT pad. Omit sections that have no supporting data rather than inventing content.",
    "Respond with STRICT JSON:",
    `{ "bodyMd": string,           // FULL markdown report following the skeleton above`,
    `  "stats": object }           // free-form stats; include severityTally, topActors, topSectors, geosCovered, signalCount where reasonable`,
  ].join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJsonLogged("threat_landscape", provider, { system, user, timeoutSeconds: 300 });
  if (!raw) return null;
  const bodyMd = asString(raw.bodyMd, "");
  const stats = raw.stats && typeof raw.stats === "object" ? raw.stats : {};
  return { bodyMd, stats };
}

// ---------- osint_overview ----------
function osintOverviewLive(input: OsintOverviewInput, provider: AiProvider): OsintOverviewOutput | null {
  const personaGuidance = {
    ir: "IR persona — prioritise containment, eradication, evidence preservation, and forensic timeline. Lead with what to do in the next hour.",
    ti: "TI persona — prioritise actor attribution, campaign linkage, infrastructure pivots, and strategic forecasting. Cite MITRE GXXXX / TXXXX IDs.",
    secops: "SecOps persona — prioritise detection coverage, alert tuning, hunt leads, and operational hardening. Reference concrete SIEM/EDR platforms.",
  } as const;
  const guide = (personaGuidance as Record<string, string>)[input.persona] || "";
  const system = [
    `You are a senior cyber analyst writing a persona-tuned OSINT overview. The active persona is "${input.persona}" (ir=incident response, ti=threat intelligence, secops=security operations).`,
    guide,
    "Always respond in ENGLISH. Translate any non-English quoted strings or actor aliases inline.",
    "Be specific: name verbatim CVE IDs, threat-actor groups (with MITRE GXXXX where known), products / versions, and IOCs. Do NOT paraphrase. Do NOT pad. If a bullet has no supporting data, omit it.",
    "Each keyTakeaway and recommendation should be a single sentence, lead with the most important word, and — where applicable — anchor to a MITRE ATT&CK technique ID (TXXXX[.XXX]).",
    "Respond with STRICT JSON:",
    `{ "summary": string,           // 3-5 sentence narrative tuned to the persona above`,
    `  "keyTakeaways": string[],     // 4-6 single-sentence bullets, MITRE-anchored where applicable`,
    `  "recommendations": string[] } // 4-6 single-sentence, ordered, directly actionable bullets`,
  ].join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJsonLogged("osint_overview", provider, { system, user, timeoutSeconds: 300 });
  if (!raw) return null;
  return {
    summary: asString(raw.summary, ""),
    keyTakeaways: asStringArray(raw.keyTakeaways, 10),
    recommendations: asStringArray(raw.recommendations, 10),
  };
}

// =============================================================================
//                          CHATBOT TASKS (v2.15)
// =============================================================================
//
// Two analyst-facing endpoints powering the OSINT page floating chatbot:
//   * chatTriage      — CIRT tier report (Tier 1 Critical → Tier 4 Info) + an
//                       Analyst Action Plan Summary, rendered as Markdown.
//   * chatDeepDive    — per-finding deep analysis for a hand-picked subset,
//                       returns full HTML report with emoji + pretty styling.
//
// Both helpers expect the caller (storage) to have already pre-fetched
// sourceContent via sourceFetch.ts.
// =============================================================================

export interface ChatTriageInputFinding {
  id: string;
  source: string;
  category: string;
  title: string;
  url: string | null;
  publishedAt: string;
  severity?: string;
  cveIds?: string[];
  affectedTech?: string[];
  threatActors?: string[];
  summary?: string | null;
  sourceContent?: string | null; // pre-fetched article body, capped at ~3K chars for triage
}
export interface ChatTriageInput {
  rangeLabel: string; // e.g. "last 24 hours", "last 7 days"
  clientProfile?: {
    industries?: string[];
    geos?: string[];
    technologies?: string[];
  };
  findings: ChatTriageInputFinding[];
}
export interface ChatTriageOutput {
  reportMd: string; // full Markdown report with tier sections
}

/** v2.15 — diagnostic wrapper around chatTriageLive so callers can surface
 *  failure reasons (timeouts, bad keys, JSON parse) to the UI instead of
 *  silently mock-falling-back. */
export function chatTriageLiveDiagnostic(
  input: ChatTriageInput,
  provider: AiProvider,
): { result: ChatTriageOutput | null; diag: LiveChatDiagnostic | null } {
  if (!shouldGoLive(provider)) {
    return { result: null, diag: { ok: false, result: null, reason: "live AI disabled or provider has no usable key", httpStatus: 0, latencyMs: 0, rawBodyPreview: "" } };
  }
  const system = buildTriageSystemPrompt();
  const user = JSON.stringify(input);
  // v2.27 — 9-minute upstream cap. The browser doesn't hold this connection
  // (chat/triage is now an async job), so the wall-clock here only needs to
  // exceed how long DeepSeek v4-pro actually spends reasoning over a 24-hour
  // feed. Observed: 4-6 min for ~30 findings.
  // v2.27.1 — explicitly request 32K output tokens. DeepSeek's API default
  // when max_tokens is omitted is only 4096, which truncates long CIRT
  // triage reports mid-sentence (observed in v2.27 first run: report cut
  // off at ~3700 chars). DeepSeek v4-pro supports up to 32K output tokens.
  const diag = liveChatJsonDiagnostic(provider, { system, user, timeoutSeconds: 540, maxTokens: 32000 });
  if (!diag.ok || !diag.result) return { result: null, diag };
  const reportMd = asString(diag.result.reportMd, "");
  if (reportMd.length < 50) {
    return { result: null, diag: { ...diag, ok: false, reason: "model returned reportMd shorter than 50 chars (likely truncated)" } };
  }
  return { result: { reportMd }, diag };
}

function buildTriageSystemPrompt(): string {
  return _CHAT_TRIAGE_SYSTEM_PROMPT;
}

export function chatTriageLive(input: ChatTriageInput, provider: AiProvider): ChatTriageOutput | null {
  return chatTriageLiveDiagnostic(input, provider).result;
}

// Note: the system prompt was previously inlined here; lifted to a module
// constant so chatTriageLiveDiagnostic can share it.
const _CHAT_TRIAGE_SYSTEM_PROMPT_BUILDER = () => null; // legacy guard — see body below
function _unused_chatTriageLive_legacy(input: ChatTriageInput, provider: AiProvider): ChatTriageOutput | null {
  if (!shouldGoLive(provider)) return null;
  const system = [
    "You are a top-tier CIRT (Cyber Incident Response Team) and SOC expert performing an initial Threat Intelligence Triage.",
    "Review every supplied threat-intel item. For each item you have the title, source, category, publish time, CVE IDs, affected technology, threat actors, the feed summary, AND (when reachable) the truncated body fetched from the source URL. Treat the fetched body as authoritative when present.",
    "Apply this CIRT tier ladder — use it VERBATIM for the section headings:",
    "  • TIER 1: CRITICAL RISK (Immediate Triage & Action Required) — active exploitation, zero-day, severe supply-chain compromise, authentication bypass / RCE / privilege escalation in widely deployed products, banking / critical-infrastructure impact.",
    "  • TIER 2: HIGH RISK (Prioritize for Patching & Threat Hunting) — high-impact CVEs with PoCs, notable extortion / ransomware campaigns, weaponised brand impersonation.",
    "  • TIER 3: MEDIUM RISK (Awareness & Detection Engineering) — emerging tactics, new malware families, phishing automation — update SOC detection rules.",
    "  • TIER 4: LOW RISK / INFORMATIONAL (Filter Out) — vendor marketing, webinars, regulatory news, product announcements, retrospectives.",
    "Group items by tier. Within each tier, cluster related items into sub-topics (e.g. 'Active Exploitation of Edge Infrastructure', 'Supply Chain Compromise', 'Enterprise App Vulnerabilities & Patch Tuesday'). Each sub-topic must include:",
    "  • Intel: one bullet per related title, in italics. Cite verbatim CVE IDs, product versions, threat-actor groups.",
    "  • Why it's <Tier>: one sentence on rationale (active exploitation? targeted? supply-chain blast radius?).",
    "  • Action: one direct, ordered next step tied to a concrete asset or control.",
    "End with an 'Analyst Action Plan Summary:' — a numbered list of 3-6 immediate orders covering: 'Drop everything and check for', 'Engage DevOps / AppSec', 'Deploy Threat Hunts', and 'Standard Op' as applicable.",
    "Open the report with a 2-3 sentence executive lead-in (e.g. 'As a top-tier CIRT and SOC expert, I have reviewed the provided threat intelligence feed. The current landscape is dominated by N major themes: ...').",
    "Always respond in ENGLISH. Translate any non-English titles, quotes, or technical terms inline.",
    "Output MUST use this exact Markdown skeleton (headings VERBATIM, including the leading emoji):",
    "",
    "  <2-3 sentence executive lead-in paragraph>",
    "",
    "  ## 🚨 TIER 1: CRITICAL RISK (Immediate Triage & Action Required)",
    "  *<one-italic-line scope description>*",
    "  ### 1. <Sub-topic name>",
    "  - **Intel:** *<title 1>*",
    "  - **Intel:** *<title 2>*",
    "  - **Why it's Critical:** <rationale>",
    "  - **Action:** <ordered action>",
    "  ### 2. <Sub-topic name>",
    "  ...",
    "",
    "  ## 🔴 TIER 2: HIGH RISK (Prioritize for Patching & Threat Hunting)",
    "  ...",
    "",
    "  ## 🟠 TIER 3: MEDIUM RISK (Awareness & Detection Engineering)",
    "  ...",
    "",
    "  ## ⚪ TIER 4: LOW RISK / INFORMATIONAL (Filter Out)",
    "  *<one-italic-line scope description>*",
    "  - **Ignore/Filter out for triage:**",
    "    - <bullet of vendor marketing / webinars / regulatory items>",
    "",
    "  ## 📋 Analyst Action Plan Summary:",
    "  1. **Drop everything and check for:** <items>",
    "  2. **Engage DevOps:** <items>",
    "  3. **Deploy Threat Hunts:** <items>",
    "  4. **Standard Op:** <items>",
    "",
    "Omit a TIER section entirely if no intel belongs in it. Do NOT pad. Do NOT invent CVE IDs or actors not in the source material.",
    "Respond with STRICT JSON: { \"reportMd\": \"...full markdown report...\" } — no prose outside the JSON, no markdown fences around the JSON.",
  ].join("\n");
  const user = JSON.stringify(input);
  const raw = liveChatJson(provider, { system, user });
  if (!raw) return null;
  const reportMd = asString(raw.reportMd, "");
  if (reportMd.length < 50) return null;
  return { reportMd };
}

// v2.15 — module-level system prompt so chatTriageLiveDiagnostic can reuse it.
const _CHAT_TRIAGE_SYSTEM_PROMPT: string = [
  "You are a top-tier CIRT (Cyber Incident Response Team) and SOC expert performing an initial Threat Intelligence Triage.",
  "Review every supplied threat-intel item. For each item you have the title, source, category, publish time, CVE IDs, affected technology, threat actors, the feed summary, AND (when reachable) the truncated body fetched from the source URL. Treat the fetched body as authoritative when present.",
  "Apply this CIRT tier ladder — use it VERBATIM for the section headings:",
  "  • TIER 1: CRITICAL RISK (Immediate Triage & Action Required) — active exploitation, zero-day, severe supply-chain compromise, authentication bypass / RCE / privilege escalation in widely deployed products, banking / critical-infrastructure impact.",
  "  • TIER 2: HIGH RISK (Prioritize for Patching & Threat Hunting) — high-impact CVEs with PoCs, notable extortion / ransomware campaigns, weaponised brand impersonation.",
  "  • TIER 3: MEDIUM RISK (Awareness & Detection Engineering) — emerging tactics, new malware families, phishing automation — update SOC detection rules.",
  "  • TIER 4: LOW RISK / INFORMATIONAL (Filter Out) — vendor marketing, webinars, regulatory news, product announcements, retrospectives.",
  "Group items by tier. Within each tier, cluster related items into sub-topics (e.g. 'Active Exploitation of Edge Infrastructure', 'Supply Chain Compromise', 'Enterprise App Vulnerabilities & Patch Tuesday'). Each sub-topic must include:",
  "  • Intel: one bullet per related title, in italics. Cite verbatim CVE IDs, product versions, threat-actor groups.",
  "  • Why it's <Tier>: one sentence on rationale (active exploitation? targeted? supply-chain blast radius?).",
  "  • Action: one direct, ordered next step tied to a concrete asset or control.",
  "After the tier sections, include a 'Source Aggregation:' section. Group the supplied findings by source name/domain and summarize count, date span, dominant intel category, notable CVEs/actors, and 1-3 representative source URLs. This section must help analysts see which publishers contributed the strongest signal.",
  "End with an 'Analyst Action Plan Summary:' — a numbered list of 3-6 immediate orders covering: 'Drop everything and check for', 'Engage DevOps / AppSec', 'Deploy Threat Hunts', and 'Standard Op' as applicable.",
  "Open the report with a 2-3 sentence executive lead-in (e.g. 'As a top-tier CIRT and SOC expert, I have reviewed the provided threat intelligence feed. The current landscape is dominated by N major themes: ...').",
  "Always respond in ENGLISH only. Translate any non-English titles, quotes, or technical terms inline. Do not emit Chinese, Japanese, Korean, or other non-English prose in headings, bullets, or summaries.",
  "Output MUST use this exact Markdown skeleton (headings VERBATIM, including the leading emoji):",
  "",
  "  <2-3 sentence executive lead-in paragraph>",
  "",
  "  ## \uD83D\uDEA8 TIER 1: CRITICAL RISK (Immediate Triage & Action Required)",
  "  *<one-italic-line scope description>*",
  "  ### 1. <Sub-topic name>",
  "  - **Intel:** *<title 1>*",
  "  - **Intel:** *<title 2>*",
  "  - **Why it's Critical:** <rationale>",
  "  - **Action:** <ordered action>",
  "  ### 2. <Sub-topic name>",
  "  ...",
  "",
  "  ## \uD83D\uDD34 TIER 2: HIGH RISK (Prioritize for Patching & Threat Hunting)",
  "  ...",
  "",
  "  ## \uD83D\uDFE0 TIER 3: MEDIUM RISK (Awareness & Detection Engineering)",
  "  ...",
  "",
  "  ## \u26AA TIER 4: LOW RISK / INFORMATIONAL (Filter Out)",
  "  *<one-italic-line scope description>*",
  "  - **Ignore/Filter out for triage:**",
  "    - <bullet of vendor marketing / webinars / regulatory items>",
  "",
  "  ## Source Aggregation:",
  "  - **<source/domain>:** <count> item(s); date span <oldest> to <newest>; dominant category <category>; notable CVEs/actors <list or none>; representative sources <URL list>",
  "",
  "  ## \uD83D\uDCCB Analyst Action Plan Summary:",
  "  1. **Drop everything and check for:** <items>",
  "  2. **Engage DevOps:** <items>",
  "  3. **Deploy Threat Hunts:** <items>",
  "  4. **Standard Op:** <items>",
  "",
  "Omit a TIER section entirely if no intel belongs in it. Do NOT pad. Do NOT invent CVE IDs or actors not in the source material.",
  "Respond with STRICT JSON: { \"reportMd\": \"...full markdown report...\" } — no prose outside the JSON, no markdown fences around the JSON.",
].join("\n");

export interface ChatDeepDiveInputFinding {
  id: string;
  source: string;
  title: string;
  url: string | null;
  publishedAt: string;
  severity?: string;
  cveIds?: string[];
  affectedTech?: string[];
  threatActors?: string[];
  summary?: string | null;
  sourceContent?: string | null; // full article body (up to 18K chars)
}
export interface ChatDeepDiveInput {
  clientProfile?: {
    industries?: string[];
    geos?: string[];
    technologies?: string[];
  };
  findings: ChatDeepDiveInputFinding[];
}
export interface ChatDeepDivePerFinding {
  findingId: string;
  title: string;
  url: string | null;
  source: string;
  severityLabel: string; // CRITICAL | HIGH | MEDIUM | LOW | INFO
  relevanceScore: number; // 0..1
  executiveSummary: string; // 2-3 sentence headline
  detailedAnalysis: string; // 4-7 sentence CIRT structured analysis
  mitreTtps: string[]; // ["T1566.001 — Phishing", ...]
  iocs: string[]; // verbatim domains/IPs/hashes
  detectionActions: string[]; // 2-5 ordered actions
  cveIds: string[];
}
export interface ChatDeepDiveOutput {
  perFinding: ChatDeepDivePerFinding[];
  overallAssessment: string; // 2-4 sentence cross-finding synthesis
}

/** v2.15 — diagnostic wrapper around chatDeepDiveLive. Same idea as the triage
 *  variant: lets the caller (osintChat.runChatDeepDive) raise a useful error
 *  back to the UI when the live provider doesn't respond. */
export function chatDeepDiveLiveDiagnostic(
  input: ChatDeepDiveInput,
  provider: AiProvider,
): { result: ChatDeepDiveOutput | null; diag: LiveChatDiagnostic | null } {
  if (!shouldGoLive(provider)) {
    return { result: null, diag: { ok: false, result: null, reason: "live AI disabled or provider has no usable key", httpStatus: 0, latencyMs: 0, rawBodyPreview: "" } };
  }
  const system = _CHAT_DEEPDIVE_SYSTEM_PROMPT;
  const user = JSON.stringify(input);
  // Deep-dive has up to 20 findings with full article bodies in user content,
  // and a per-finding structured output — budget generously.
  // v2.27 — raised to 9 min for the same reason as chat-triage: DeepSeek
  // v4-pro can spend 4-6 min on reasoning before emitting the final JSON.
  // v2.27.1 — explicitly request 32K output tokens (same reasoning as
  // chat-triage: DeepSeek's default 4096 truncates long structured output).
  const diag = liveChatJsonDiagnostic(provider, { system, user, timeoutSeconds: 540, maxTokens: 32000 });
  if (!diag.ok || !diag.result) return { result: null, diag };
  const raw = diag.result;
  const perFindingRaw = Array.isArray(raw.perFinding) ? raw.perFinding : [];
  const perFinding: ChatDeepDivePerFinding[] = perFindingRaw.map((p: any) => ({
    findingId: asString(p?.findingId, ""),
    title: asString(p?.title, ""),
    url: typeof p?.url === "string" ? p.url : null,
    source: asString(p?.source, ""),
    severityLabel: asString(p?.severityLabel, "INFO").toUpperCase(),
    relevanceScore: clamp01(asNumber(p?.relevanceScore, 0)),
    executiveSummary: asString(p?.executiveSummary, ""),
    detailedAnalysis: asString(p?.detailedAnalysis, ""),
    mitreTtps: asStringArray(p?.mitreTtps, 20),
    iocs: asStringArray(p?.iocs, 50),
    detectionActions: asStringArray(p?.detectionActions, 10),
    cveIds: asStringArray(p?.cveIds, 30),
  })).filter((p: ChatDeepDivePerFinding) => p.findingId && p.detailedAnalysis.length > 20);
  if (perFinding.length === 0) {
    return { result: null, diag: { ...diag, ok: false, reason: "model returned no valid per-finding analyses (likely truncated — try fewer findings)" } };
  }
  return {
    result: { perFinding, overallAssessment: asString(raw.overallAssessment, "") },
    diag,
  };
}

export function chatDeepDiveLive(input: ChatDeepDiveInput, provider: AiProvider): ChatDeepDiveOutput | null {
  return chatDeepDiveLiveDiagnostic(input, provider).result;
}

// v2.15 — module-level deep-dive system prompt so chatDeepDiveLiveDiagnostic
// (and legacy variants) share the same wording.
const _CHAT_DEEPDIVE_SYSTEM_PROMPT: string = [
  "You are a top-tier CIRT analyst performing DEEP DIVE analysis on a hand-picked set of threat-intel findings.",
  "Each finding includes its title, source, publish time, feed summary, and (when reachable) the FULL article body fetched from the source URL in the 'sourceContent' field. Read the article body end-to-end — it is the AUTHORITATIVE source. The feed summary is a fallback when the body is unavailable.",
  "For EACH finding, produce a structured CIRT analysis:",
  "  • severityLabel — CRITICAL / HIGH / MEDIUM / LOW / INFO using the same ladder as the triage report.",
  "  • relevanceScore — 0.85-1.00 direct hit + active exploitation, 0.60-0.84 hits monitored tech/geo/sector but informational, 0.30-0.59 adjacent, 0.00-0.29 generic noise.",
  "  • executiveSummary — 2-3 sentences: what happened, who's affected, exploitation status. Plain English.",
  "  • detailedAnalysis — 4-7 sentences in this order: (1) what happened / actor, (2) affected products & versions with verbatim CVE IDs, (3) attack mechanism + MITRE TXXXX[.XXX] IDs, (4) exploitation status (PoC / ITW / mass-scanning), (5) verbatim IOCs from the article.",
  "  • mitreTtps — array of strings like 'T1566.001 — Spearphishing Attachment'. Anchor every TTP claim to a real ATT&CK technique.",
  "  • iocs — verbatim domains, IPs, URLs, hashes, file paths, mutex names — NO paraphrasing. Empty array is fine.",
  "  • detectionActions — 2-5 ordered, direct actions tied to concrete assets/controls.",
  "  • cveIds — verbatim CVE IDs that appear in the article. Empty array is fine.",
  "Finish with overallAssessment — 2-4 sentences synthesising patterns across the selected findings (shared actor? shared CVE family? same supply-chain compromise?).",
  "Always respond in ENGLISH. Translate non-English quotes inline. Anti-hallucination: if a piece of information is not in the source material, omit it — do NOT invent.",
  "Respond with STRICT JSON — no prose, no markdown fences:",
  `{ "perFinding": [ { "findingId": string, "title": string, "url": string|null, "source": string, "severityLabel": string, "relevanceScore": number, "executiveSummary": string, "detailedAnalysis": string, "mitreTtps": string[], "iocs": string[], "detectionActions": string[], "cveIds": string[] }, ... ],`,
  `  "overallAssessment": string }`,
].join("\n");

// Legacy single-shot deep-dive — kept for reference. Live path is chatDeepDiveLiveDiagnostic above.
function _unused_chatDeepDiveLive_legacy(input: ChatDeepDiveInput, provider: AiProvider): ChatDeepDiveOutput | null {
  if (!shouldGoLive(provider)) return null;
  const system = [
    "You are a top-tier CIRT analyst performing DEEP DIVE analysis on a hand-picked set of threat-intel findings.",
    "Each finding includes its title, source, publish time, feed summary, and (when reachable) the FULL article body fetched from the source URL in the 'sourceContent' field. Read the article body end-to-end — it is the AUTHORITATIVE source. The feed summary is a fallback when the body is unavailable.",
    "For EACH finding, produce a structured CIRT analysis:",
    "  • severityLabel — CRITICAL / HIGH / MEDIUM / LOW / INFO using the same ladder as the triage report.",
    "  • relevanceScore — 0.85-1.00 direct hit + active exploitation, 0.60-0.84 hits monitored tech/geo/sector but informational, 0.30-0.59 adjacent, 0.00-0.29 generic noise.",
    "  • executiveSummary — 2-3 sentences: what happened, who's affected, exploitation status. Plain English.",
    "  • detailedAnalysis — 4-7 sentences in this order: (1) what happened / actor, (2) affected products & versions with verbatim CVE IDs, (3) attack mechanism + MITRE TXXXX[.XXX] IDs, (4) exploitation status (PoC / ITW / mass-scanning), (5) verbatim IOCs from the article.",
    "  • mitreTtps — array of strings like 'T1566.001 — Spearphishing Attachment'. Anchor every TTP claim to a real ATT&CK technique.",
    "  • iocs — verbatim domains, IPs, URLs, hashes, file paths, mutex names — NO paraphrasing. Empty array is fine.",
    "  • detectionActions — 2-5 ordered, direct actions tied to concrete assets/controls.",
    "  • cveIds — verbatim CVE IDs that appear in the article. Empty array is fine.",
    "Finish with overallAssessment — 2-4 sentences synthesising patterns across the selected findings (shared actor? shared CVE family? same supply-chain compromise?).",
    "Always respond in ENGLISH. Translate non-English quotes inline. Anti-hallucination: if a piece of information is not in the source material, omit it — do NOT invent.",
    "Respond with STRICT JSON — no prose, no markdown fences:",
    `{ "perFinding": [ { "findingId": string, "title": string, "url": string|null, "source": string, "severityLabel": string, "relevanceScore": number, "executiveSummary": string, "detailedAnalysis": string, "mitreTtps": string[], "iocs": string[], "detectionActions": string[], "cveIds": string[] }, ... ],`,
    `  "overallAssessment": string }`,
  ].join("\n");
  void system; // legacy body retained for reference; live path uses _CHAT_DEEPDIVE_SYSTEM_PROMPT
  const user = JSON.stringify(input);
  const raw = liveChatJson(provider, { system, user });
  if (!raw) return null;
  const perFindingRaw = Array.isArray(raw.perFinding) ? raw.perFinding : [];
  const perFinding: ChatDeepDivePerFinding[] = perFindingRaw.map((p: any) => ({
    findingId: asString(p?.findingId, ""),
    title: asString(p?.title, ""),
    url: typeof p?.url === "string" ? p.url : null,
    source: asString(p?.source, ""),
    severityLabel: asString(p?.severityLabel, "INFO").toUpperCase(),
    relevanceScore: clamp01(asNumber(p?.relevanceScore, 0)),
    executiveSummary: asString(p?.executiveSummary, ""),
    detailedAnalysis: asString(p?.detailedAnalysis, ""),
    mitreTtps: asStringArray(p?.mitreTtps, 20),
    iocs: asStringArray(p?.iocs, 50),
    detectionActions: asStringArray(p?.detectionActions, 10),
    cveIds: asStringArray(p?.cveIds, 30),
  })).filter((p: ChatDeepDivePerFinding) => p.findingId && p.detailedAnalysis.length > 20);
  if (perFinding.length === 0) return null;
  return {
    perFinding,
    overallAssessment: asString(raw.overallAssessment, ""),
  };
}

// =============================================================================
//                              DISPATCHER
// =============================================================================

function shouldGoLive(provider: AiProvider): boolean {
  return liveCallsEnabled() && providerHasUsableKey(provider);
}

// v2.26 — helper that turns a downstream null (live call succeeded HTTP-wise
// but the per-task parser rejected the model's output) into a LiveAiError so
// the dispatcher never silently returns a mock.
function throwLiveSchemaError(task: string, provider: AiProvider): never {
  throw new LiveAiError(task, provider, {
    reason: "model returned a response that did not match the expected schema for this task",
    httpStatus: 200,
    latencyMs: 0,
    rawBodyPreview: "",
  });
}

/** v2.26 — dispatchAi NEVER returns a mock when a provider is configured. If
 *  the live call fails (network, timeout, malformed JSON, schema mismatch) it
 *  throws LiveAiError so the calling route returns 502 with a real reason.
 *  The mock paths still exist but only execute when there is no usable
 *  provider at all (live AI globally disabled OR provider has no key) — a
 *  state the route layer also guards against by returning 409 "no provider". */
export function dispatchAi(opts: DispatchOptions<any>): DispatchResult {
  const live = shouldGoLive(opts.provider);
  if (!live) {
    throw new LiveAiError(opts.task, opts.provider, {
      reason: "live AI is disabled or the configured provider has no usable API key",
      httpStatus: 0,
      latencyMs: 0,
      rawBodyPreview: "",
    });
  }
  switch (opts.task) {
    case "triage": {
      const out = triageLive(opts.input as FindingDTO, opts.provider);
      if (!out) throwLiveSchemaError("triage", opts.provider);
      return { task: "triage", output: out, isMock: false };
    }
    case "young_domain": {
      const out = youngDomainLive(opts.input as YoungDomainAiInput, opts.provider);
      if (!out) throwLiveSchemaError("young_domain", opts.provider);
      return { task: "young_domain", output: out, isMock: false };
    }
    case "report_summary": {
      const out = reportSummaryLive(opts.input as ReportSummaryInput, opts.provider);
      if (!out) throwLiveSchemaError("report_summary", opts.provider);
      return { task: "report_summary", output: out, isMock: false };
    }
    case "analysis": {
      const out = analysisLive(opts.input as AnalysisInput, opts.provider);
      if (!out) throwLiveSchemaError("analysis", opts.provider);
      return { task: "analysis", output: out, isMock: false };
    }
    case "logo_abuse": {
      const out = logoAbuseLive(opts.input as LogoAbuseInput, opts.provider);
      if (!out) throwLiveSchemaError("logo_abuse", opts.provider);
      return { task: "logo_abuse", output: out, isMock: false };
    }
    case "osint_analysis": {
      const out = osintAnalysisLive(opts.input as OsintAnalysisInput, opts.provider);
      if (!out) throwLiveSchemaError("osint_analysis", opts.provider);
      return { task: "osint_analysis", output: out, isMock: false };
    }
    case "hunt_query": {
      // v2.26 — hunt_query is fully live. The legacy "merge with mock template"
      // behaviour is gone; if the live provider does not return queries for a
      // requested language, that language is simply absent from the output.
      const out = huntQueryLive(opts.input as HuntQueryInput, opts.provider);
      if (!out) throwLiveSchemaError("hunt_query", opts.provider);
      return { task: "hunt_query", output: out, isMock: false };
    }
    case "threat_landscape": {
      const out = threatLandscapeLive(opts.input as ThreatLandscapeInput, opts.provider);
      if (!out) throwLiveSchemaError("threat_landscape", opts.provider);
      return { task: "threat_landscape", output: out, isMock: false };
    }
    case "osint_overview": {
      const out = osintOverviewLive(opts.input as OsintOverviewInput, opts.provider);
      if (!out) throwLiveSchemaError("osint_overview", opts.provider);
      return { task: "osint_overview", output: out, isMock: false };
    }
    case "osint_chat": {
      throw new LiveAiError("osint_chat", opts.provider, {
        reason: "osint_chat is handled by the synchronous chatroom path, not dispatchAi",
        httpStatus: 0,
        latencyMs: 0,
        rawBodyPreview: "",
      });
    }
    case "detection_rule": {
      const out = detectionRuleLive(opts.input as DetectionRuleInput, opts.provider);
      if (!out) throwLiveSchemaError("detection_rule", opts.provider);
      return { task: "detection_rule", output: out, isMock: false };
    }
    case "threat_actor_enrichment": {
      const out = threatActorEnrichmentLive(opts.input as ThreatActorEnrichmentInput, opts.provider);
      if (!out) throwLiveSchemaError("threat_actor_enrichment", opts.provider);
      return { task: "threat_actor_enrichment", output: out, isMock: false };
    }
    default: {
      throw new LiveAiError("unknown", opts.provider, {
        reason: `unsupported AI task: ${(opts as any).task}`,
        httpStatus: 0,
        latencyMs: 0,
        rawBodyPreview: "",
      });
    }
  }
}

// =============================================================================
//                          PROVIDER CONNECTIVITY TEST
// =============================================================================

// Test connectivity — issues a real lightweight ping against the configured
// endpoint. Falls back to a heuristic message when no key is set so the UI
// can still display a sensible status.
export function testProvider(provider: AiProvider): { ok: boolean; latencyMs: number; message: string } {
  return livePing(provider);
}
