/**
 * OSINT AI Chatbot — server-side glue for the floating chatbot on the OSINT
 * Monitoring page. Two endpoints:
 *
 *   runChatTriage()   — bucketed CIRT tier triage report (Tier 1 -> Tier 4 +
 *                       Analyst Action Plan Summary) rendered as Markdown.
 *   runChatDeepDive() — per-finding deep CIRT analysis for a hand-picked
 *                       subset of findings; the route layer wraps the
 *                       structured result into a downloadable HTML report.
 *
 * Both functions pre-fetch the article body for each finding via sourceFetch
 * BEFORE dispatching to the AI provider so the model reads the actual
 * intel, not just the feed teaser.
 */

import type { OsintFindingDTO } from "@shared/schema";

import { fetchSourcesBatch } from "./sourceFetch";
import {
  chatTriageLiveDiagnostic, chatTriageMock,
  chatDeepDiveLiveDiagnostic,
  type ChatTriageInput, type ChatTriageInputFinding,
  type ChatDeepDiveInputFinding, type ChatDeepDiveOutput,
  type ChatDeepDivePerFinding,
} from "./aiClient";
import type { LiveChatDiagnostic } from "./aiLive";

// v2.15 — surfaced to callers/UI so a failed live-AI call can show the actual
// reason (HTTP code, timeout, parse error) instead of silently falling back to
// a deterministic mock.
export interface AiDiagnosticInfo {
  ok: boolean;
  reason: string;
  httpStatus: number;
  latencyMs: number;
  rawBodyPreview: string;
}
function diagToInfo(d: LiveChatDiagnostic | null | undefined): AiDiagnosticInfo | null {
  if (!d) return null;
  return {
    ok: d.ok,
    reason: d.reason,
    httpStatus: d.httpStatus,
    latencyMs: d.latencyMs,
    rawBodyPreview: d.rawBodyPreview,
  };
}

// Error thrown when a tenant has a live AI provider configured but the live
// call failed for any reason (HTTP error, timeout, parse failure, truncation).
// The route layer catches this and returns 502 with the diagnostic so the UI
// can show a precise error toast.
export class ChatLiveAiError extends Error {
  diagnostic: AiDiagnosticInfo;
  providerLabel: string;
  constructor(providerLabel: string, diag: LiveChatDiagnostic) {
    super(`AI provider "${providerLabel}" failed: ${diag.reason} (HTTP ${diag.httpStatus}, ${diag.latencyMs}ms)`);
    this.name = "ChatLiveAiError";
    this.providerLabel = providerLabel;
    this.diagnostic = diagToInfo(diag)!;
  }
}

// ---------------------------------------------------------------------------
// Date-range filter
// ---------------------------------------------------------------------------

export type ChatRangeKey = "1d" | "7d" | "1m" | "1q" | "1y" | "all";

const RANGE_HOURS: Record<ChatRangeKey, number | null> = {
  "1d": 24,
  "7d": 24 * 7,
  "1m": 24 * 30,
  "1q": 24 * 90,
  "1y": 24 * 365,
  "all": null,
};
const RANGE_LABEL: Record<ChatRangeKey, string> = {
  "1d": "last 24 hours",
  "7d": "last 7 days",
  "1m": "last 30 days",
  "1q": "last quarter",
  "1y": "last year",
  "all": "full history",
};

function filterByRange(items: OsintFindingDTO[], range: ChatRangeKey): OsintFindingDTO[] {
  const hours = RANGE_HOURS[range];
  if (hours == null) return items;
  const cutoff = Date.now() - hours * 3600_000;
  return items.filter((f) => {
    const t = Date.parse(f.publishedAt || f.createdAt || "");
    return Number.isFinite(t) && t >= cutoff;
  });
}

// ---------------------------------------------------------------------------
// Chat triage
// ---------------------------------------------------------------------------

export interface RunChatTriageOpts {
  tenantId: string;
  range: ChatRangeKey;
  maxItems?: number;
  // v2.18 — Global view support. When `findingIds` is non-empty the triage
  // routine runs cross-tenant: each ID is looked up via
  // storage.getOsintFindingAnyTenant() and the client profile is unioned
  // across every distinct tenant the IDs touch. `tenantId` is used only as
  // the AI-provider resolution anchor (falls back to whichever tenant has
  // a configured provider). When `findingIds` is empty/undefined the path
  // is unchanged: tenant-scoped triage over `range`.
  findingIds?: string[];
  crossTenant?: boolean;
}
export interface RunChatTriageResult {
  reportMd: string;
  rangeLabel: string;
  itemsAnalysed: number;
  providerLabel: string | null;
  aiDiagnostic: AiDiagnosticInfo | null;
  generatedAt: string;
}

// v2.18 — union the client-profile signals (industries / geos / monitored
// technologies) across every tenant involved in a Global-view triage or
// deep-dive request. Returns the canonical { industries, geos, technologies }
// shape used by both osint_overview and osint_analysis prompts.
function unionClientProfiles(storage: any, tenantIds: string[]): {
  industries: string[]; geos: string[]; technologies: string[];
} {
  const indSet = new Set<string>();
  const geoSet = new Set<string>();
  const techSet = new Set<string>();
  for (const tid of tenantIds) {
    if (!tid) continue;
    const p = storage.getClientProfile ? storage.getClientProfile(tid) : null;
    if (!p) continue;
    for (const x of (p.industries || [])) indSet.add(String(x));
    for (const x of (p.geos || [])) geoSet.add(String(x));
    for (const x of (p.monitoredTechnologies || p.technologies || [])) techSet.add(String(x));
  }
  return {
    industries: Array.from(indSet),
    geos: Array.from(geoSet),
    technologies: Array.from(techSet),
  };
}

// v2.18 — walk the candidate tenants in order and return the first one that
// has a resolved AI provider for the requested capability. Used so Global-view
// triage/deep-dive can find a working provider even when the admin's own
// tenant has none configured.
function resolveProviderAcrossTenants(storage: any, candidates: string[], capability: string): any {
  const seen = new Set<string>();
  for (const tid of candidates) {
    if (!tid || seen.has(tid)) continue;
    seen.add(tid);
    if (!storage.resolveAiProvider) return null;
    const p = storage.resolveAiProvider(tid, capability);
    if (p) return p;
  }
  return null;
}

export async function runChatTriage(storage: any, opts: RunChatTriageOpts): Promise<RunChatTriageResult> {
  const max = opts.maxItems ?? 60;

  // v2.18 — Global path: caller passed explicit findingIds spanning N tenants.
  let inRange: OsintFindingDTO[];
  const involvedTenantIds = new Set<string>();
  if (opts.crossTenant && opts.findingIds && opts.findingIds.length > 0) {
    const collected: OsintFindingDTO[] = [];
    for (const fid of opts.findingIds) {
      const f = storage.getOsintFindingAnyTenant
        ? storage.getOsintFindingAnyTenant(fid)
        : storage.getOsintFinding(opts.tenantId, fid);
      if (f) {
        collected.push(f);
        if (f.tenantId) involvedTenantIds.add(f.tenantId);
      }
    }
    inRange = filterByRange(collected, opts.range)
      .sort((a, b) => (Date.parse(b.publishedAt || b.createdAt || "") - Date.parse(a.publishedAt || a.createdAt || "")))
      .slice(0, max);
  } else {
    const all = storage.listOsintFindings(opts.tenantId);
    inRange = filterByRange(all, opts.range)
      .sort((a, b) => (Date.parse(b.publishedAt || b.createdAt || "") - Date.parse(a.publishedAt || a.createdAt || "")))
      .slice(0, max);
    involvedTenantIds.add(opts.tenantId);
  }

  // Pre-fetch with a small per-item budget so triage prompt stays compact.
  const fetched = await fetchSourcesBatch(inRange.map((f) => f.url));
  const contentByUrl = new Map<string, string | null>();
  for (const r of fetched) contentByUrl.set(r.url || "", r.content);

  const triageItems: ChatTriageInputFinding[] = inRange.map((f) => {
    const body = (f.url && contentByUrl.get(f.url)) || null;
    return {
      id: f.id,
      source: f.sourceName,
      category: f.sourceCategory,
      title: f.title,
      url: f.url,
      publishedAt: f.publishedAt,
      severity: f.severity,
      cveIds: f.cveIds || [],
      affectedTech: f.affectedTech || [],
      threatActors: f.threatActors || [],
      summary: f.summary,
      // Tight abstract for triage to keep token cost low.
      sourceContent: body ? body.slice(0, 1200) : null,
    };
  });

  // v2.18 — union client profile across every tenant involved (global mode).
  const clientProfile = unionClientProfiles(storage, Array.from(involvedTenantIds));
  // Prefer a resolved provider on opts.tenantId; if global view doesn't have
  // one on the admin's own tenant, try the first involved tenant that does.
  const tenantProvider = resolveProviderAcrossTenants(
    storage,
    [opts.tenantId, ...Array.from(involvedTenantIds)],
    "osint_overview",
  );

  const input: ChatTriageInput = {
    rangeLabel: RANGE_LABEL[opts.range],
    clientProfile,
    findings: triageItems,
  };

  let reportMd = "";
  let providerLabel: string | null = null;
  let aiDiagnostic: AiDiagnosticInfo | null = null;
  if (tenantProvider) {
    const { result: live, diag } = chatTriageLiveDiagnostic(input, tenantProvider);
    aiDiagnostic = diagToInfo(diag);
    if (live) {
      reportMd = live.reportMd;
      providerLabel = tenantProvider.label || tenantProvider.provider;
    } else if (diag && !diag.ok) {
      // Provider was configured but the live call failed — surface the
      // actual reason instead of silently returning a deterministic mock.
      throw new ChatLiveAiError(tenantProvider.label || tenantProvider.provider, diag);
    }
  }
  if (!reportMd) {
    // No provider configured — deterministic mock so the UI still works.
    const mock = chatTriageMock(input);
    reportMd = mock.reportMd;
    providerLabel = null;
  }

  return {
    reportMd,
    rangeLabel: RANGE_LABEL[opts.range],
    itemsAnalysed: triageItems.length,
    providerLabel,
    aiDiagnostic,
    generatedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Chat deep dive
// ---------------------------------------------------------------------------

export interface RunChatDeepDiveOpts {
  tenantId: string;
  findingIds: string[];
  // v2.18 — when true, look findings up cross-tenant and union client profiles
  // across every involved tenant. Used by Global-view deep dive.
  crossTenant?: boolean;
}
export interface RunChatDeepDiveResult {
  perFinding: ChatDeepDivePerFinding[];
  overallAssessment: string;
  htmlReport: string;       // downloadable, styled HTML
  htmlFileName: string;
  providerLabel: string | null;
  aiDiagnostic: AiDiagnosticInfo | null;
  cacheHits: number;        // v2.16 — how many came from the per-intel cache
  liveCalls: number;        // v2.16 — how many required a live AI call
  generatedAt: string;
}

export async function runChatDeepDive(storage: any, opts: RunChatDeepDiveOpts): Promise<RunChatDeepDiveResult> {
  if (!opts.findingIds.length) throw new Error("findingIds required");

  // v2.18 — cross-tenant lookup when Global view is the caller.
  const findings = opts.findingIds
    .map((id) => opts.crossTenant && storage.getOsintFindingAnyTenant
      ? storage.getOsintFindingAnyTenant(id)
      : storage.getOsintFinding(opts.tenantId, id))
    .filter((f: any): f is OsintFindingDTO => !!f);

  if (findings.length === 0) throw new Error("no matching findings");

  // Tenants touched by this batch — used for profile union + provider fallback.
  const involvedTenantIds = Array.from(new Set(findings.map((f) => f.tenantId).filter(Boolean)));
  const clientProfile = unionClientProfiles(
    storage,
    opts.crossTenant ? involvedTenantIds : [opts.tenantId],
  );
  const tenantProvider = resolveProviderAcrossTenants(
    storage,
    [opts.tenantId, ...involvedTenantIds],
    "osint_analysis",
  );

  // v2.16 — prefer the per-finding CIRT cache populated by the background
  // analyzer. We split the requested findings into:
  //   - cached: already have a fresh CIRT analysis → return instantly
  //   - missing: no cache yet → run a live call ONE AT A TIME (single-finding
  //              payloads almost never exceed the 90s/6000-token budget,
  //              unlike the old batched 20-finding call which routinely timed
  //              out at 120s)
  // v2.18 — cache lookups must use each finding's own tenantId in Global mode
  // so we don't miss the cache for findings outside opts.tenantId.
  const tidFor = (f: OsintFindingDTO) => (opts.crossTenant && f.tenantId) ? f.tenantId : opts.tenantId;
  const perFinding: ChatDeepDivePerFinding[] = [];
  const missing: OsintFindingDTO[] = [];
  let cacheHits = 0;
  for (const f of findings) {
    const cached = (storage as any).getOsintFindingCache
      ? (storage as any).getOsintFindingCache(tidFor(f), f.id)
      : null;
    if (cached && cached.cirtStatus === "done" && cached.cirtAnalysis) {
      perFinding.push(cached.cirtAnalysis as ChatDeepDivePerFinding);
      cacheHits += 1;
    } else {
      missing.push(f);
    }
  }

  let providerLabel: string | null = null;
  let aiDiagnostic: AiDiagnosticInfo | null = null;

  // Resolve a single providerLabel — prefer the cache's record, then live.
  if (cacheHits > 0) {
    const first = findings.find((f) => {
      const c = (storage as any).getOsintFindingCache?.(tidFor(f), f.id);
      return c?.cirtStatus === "done";
    });
    if (first) {
      const c = (storage as any).getOsintFindingCache(tidFor(first), first.id);
      providerLabel = c?.cirtProviderLabel ?? null;
    }
  }

  if (missing.length > 0 && tenantProvider) {
    // Pre-fetch source bodies for the missing batch.
    const fetched = await fetchSourcesBatch(missing.map((f) => f.url));
    const sourceByIdx = new Map<number, string | null>();
    fetched.forEach((r, i) => sourceByIdx.set(i, r.content));

    // Run each missing finding as its OWN single-element live call. This is
    // the same path the background analyzer takes and is the reason deep
    // dive is now reliable on slow providers (DeepSeek 30-60s per item).
    let lastDiag: AiDiagnosticInfo | null = null;
    for (let i = 0; i < missing.length; i++) {
      const f = missing[i];
      const sourceContent = sourceByIdx.get(i) ?? null;
      const deepInput: ChatDeepDiveInputFinding = {
        id: f.id,
        source: f.sourceName,
        title: f.title,
        url: f.url,
        publishedAt: f.publishedAt,
        severity: f.severity,
        cveIds: f.cveIds || [],
        affectedTech: f.affectedTech || [],
        threatActors: f.threatActors || [],
        summary: f.summary,
        sourceContent,
      };
      const { result: live, diag } = chatDeepDiveLiveDiagnostic(
        { clientProfile, findings: [deepInput] },
        tenantProvider,
      );
      lastDiag = diagToInfo(diag);
      if (live && live.perFinding.length > 0) {
        const match = live.perFinding.find((p) => p.findingId === f.id) || live.perFinding[0];
        perFinding.push(match);
        providerLabel = providerLabel ?? (tenantProvider.label || tenantProvider.provider);
        // Persist into the cache so the next call is instant. In Global mode
        // write back to the finding's owning tenant.
        if ((storage as any).saveOsintFindingCirt) {
          (storage as any).saveOsintFindingCirt(tidFor(f), f.id, {
            sourceContent,
            cirtAnalysis: match,
            providerLabel: tenantProvider.label || tenantProvider.provider,
          });
        }
      } else if (diag && !diag.ok) {
        // Bail out on the first hard failure with full diagnostic context.
        throw new ChatLiveAiError(tenantProvider.label || tenantProvider.provider, diag);
      }
    }
    aiDiagnostic = lastDiag;
  }

  let result: ChatDeepDiveOutput | null = perFinding.length > 0
    ? { perFinding, overallAssessment: buildOverallAssessment(perFinding) }
    : null;
  // Mock fallback — only reached when NO AI provider is configured AND no cache.
  if (!result) {
    result = {
      perFinding: findings.map((f) => ({
        findingId: f.id,
        title: f.title,
        url: f.url,
        source: f.sourceName,
        severityLabel: (f.severity || "INFO").toUpperCase(),
        relevanceScore: typeof f.aiRelevanceScore === "number" ? f.aiRelevanceScore : 0.5,
        executiveSummary: f.aiSummary || f.summary || "(no AI provider configured — deterministic mock)",
        detailedAnalysis: f.aiSummary || f.summary || "Configure DeepSeek / OpenAI / Anthropic / Gemini under AI Setup for full CIRT-grade deep dive analysis.",
        mitreTtps: [],
        iocs: [],
        detectionActions: [
          "Review the source advisory and validate exposure against monitored assets.",
          "Generate hunt queries via the OSINT hunt-query workflow if exposure is confirmed.",
        ],
        cveIds: f.cveIds || [],
      })),
      overallAssessment: "Deterministic mock — configure a live AI provider for cross-finding pattern synthesis.",
    };
  }

  const htmlReport = buildDeepDiveHtml(result, {
    providerLabel,
    rangeLabel: "selected findings",
    clientProfile,
    generatedAt: new Date().toISOString(),
  });

  return {
    perFinding: result.perFinding,
    overallAssessment: result.overallAssessment,
    htmlReport,
    htmlFileName: `optrasight-deep-dive-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.html`,
    providerLabel,
    aiDiagnostic,
    cacheHits,
    liveCalls: result.perFinding.length - cacheHits,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Build a short cross-finding synthesis when we've assembled the perFinding
 * array from the cache (the live AI normally emits this in batch mode, but
 * cache-only deep-dives don't have it). Picks up the top severities and any
 * shared CVEs/actors so the report still reads like a CIRT brief.
 */
function buildOverallAssessment(perFinding: ChatDeepDivePerFinding[]): string {
  if (perFinding.length === 0) return "";
  const sevCounts = new Map<string, number>();
  const cves = new Set<string>();
  for (const p of perFinding) {
    sevCounts.set(p.severityLabel, (sevCounts.get(p.severityLabel) || 0) + 1);
    (p.cveIds || []).forEach((c) => cves.add(c));
  }
  const sevLine = Array.from(sevCounts.entries())
    .sort(([a], [b]) => severityRank(b) - severityRank(a))
    .map(([s, n]) => `${n}×${s}`)
    .join(", ");
  const cveLine = cves.size > 0
    ? ` Notable CVEs across the set: ${Array.from(cves).slice(0, 6).join(", ")}.`
    : "";
  return `Synthesised from the per-intel CIRT cache (background analyzer). Severity distribution: ${sevLine}.${cveLine} Each finding's detailed breakdown above remains the authoritative source — cross-reference monitored assets against the listed IoCs and detection actions before standing down.`;
}

function severityRank(label: string): number {
  switch ((label || "").toUpperCase()) {
    case "CRITICAL": return 5;
    case "HIGH": return 4;
    case "MEDIUM": return 3;
    case "LOW": return 2;
    case "INFO": return 1;
    default: return 0;
  }
}

// ---------------------------------------------------------------------------
// HTML report builder — pretty, emoji-rich, self-contained
// ---------------------------------------------------------------------------

function esc(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function severityBadge(label: string): { color: string; bg: string; emoji: string } {
  const u = label.toUpperCase();
  if (u === "CRITICAL") return { color: "#fff", bg: "#b91c1c", emoji: "🚨" };
  if (u === "HIGH")     return { color: "#fff", bg: "#dc2626", emoji: "🔴" };
  if (u === "MEDIUM")   return { color: "#1f2937", bg: "#fbbf24", emoji: "🟠" };
  if (u === "LOW")      return { color: "#fff", bg: "#6b7280", emoji: "⚪" };
  return { color: "#fff", bg: "#374151", emoji: "ℹ️" };
}

function buildDeepDiveHtml(
  result: ChatDeepDiveOutput,
  meta: { providerLabel: string | null; rangeLabel: string; clientProfile: any; generatedAt: string },
): string {
  const cards = result.perFinding.map((p, idx) => {
    const sev = severityBadge(p.severityLabel);
    const rel = Math.round(p.relevanceScore * 100);
    const ttps = p.mitreTtps.length
      ? `<div class="block"><div class="block-label">🧬 MITRE ATT&CK</div><div class="chips">${p.mitreTtps.map((t) => `<span class="chip chip-mitre">${esc(t)}</span>`).join("")}</div></div>`
      : "";
    const cves = p.cveIds.length
      ? `<div class="block"><div class="block-label">🛡️ CVEs</div><div class="chips">${p.cveIds.map((c) => `<span class="chip chip-cve">${esc(c)}</span>`).join("")}</div></div>`
      : "";
    const iocs = p.iocs.length
      ? `<div class="block"><div class="block-label">🎯 Indicators of Compromise</div><pre class="iocs">${p.iocs.map(esc).join("\n")}</pre></div>`
      : "";
    const actions = p.detectionActions.length
      ? `<div class="block"><div class="block-label">⚙️ Detection &amp; Mitigation Actions</div><ol class="actions">${p.detectionActions.map((a) => `<li>${esc(a)}</li>`).join("")}</ol></div>`
      : "";
    const link = p.url ? `<a class="src-link" href="${esc(p.url)}" target="_blank" rel="noopener">🔗 Source</a>` : "";

    return `
      <article class="card" id="finding-${idx + 1}">
        <header class="card-head" style="background: ${sev.bg}; color: ${sev.color};">
          <div class="sev-pill">${sev.emoji} ${esc(p.severityLabel)}</div>
          <div class="rel">Relevance ${rel}%</div>
        </header>
        <div class="card-body">
          <h2 class="card-title">${esc(p.title)}</h2>
          <div class="meta"><strong>${esc(p.source)}</strong> ${link}</div>
          <p class="exec">${esc(p.executiveSummary)}</p>
          <div class="block">
            <div class="block-label">📋 Detailed Analysis</div>
            <p class="analysis">${esc(p.detailedAnalysis)}</p>
          </div>
          ${cves}
          ${ttps}
          ${iocs}
          ${actions}
        </div>
      </article>
    `;
  }).join("\n");

  const profile = meta.clientProfile && (meta.clientProfile.industries?.length || meta.clientProfile.geos?.length || meta.clientProfile.technologies?.length)
    ? `<div class="profile">
        ${meta.clientProfile.industries?.length ? `<div><strong>Industries:</strong> ${meta.clientProfile.industries.map(esc).join(", ")}</div>` : ""}
        ${meta.clientProfile.geos?.length ? `<div><strong>Geographies:</strong> ${meta.clientProfile.geos.map(esc).join(", ")}</div>` : ""}
        ${meta.clientProfile.technologies?.length ? `<div><strong>Monitored Tech:</strong> ${meta.clientProfile.technologies.map(esc).join(", ")}</div>` : ""}
      </div>`
    : "";

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OptraSight CIRT Deep Dive Report</title>
<style>
  *,*::before,*::after { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #0f172a; background: #f8fafc; line-height: 1.55; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 48px 32px 80px; }
  .hero { padding: 32px; border-radius: 18px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #312e81 100%); color: #f8fafc; box-shadow: 0 20px 60px -20px rgba(15,23,42,.45); }
  .hero h1 { margin: 0 0 8px; font-size: 32px; font-weight: 700; letter-spacing: -0.01em; }
  .hero .sub { color: #cbd5e1; font-size: 14px; }
  .hero .badges { margin-top: 18px; display: flex; gap: 8px; flex-wrap: wrap; }
  .badge { padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; background: rgba(255,255,255,.12); color: #e2e8f0; }
  .profile { margin-top: 14px; padding: 14px 18px; border-radius: 12px; background: rgba(255,255,255,.07); color: #e2e8f0; font-size: 13px; display: grid; gap: 4px; }

  .overview { margin: 28px 0; padding: 24px 28px; border-radius: 14px; background: #eef2ff; border: 1px solid #c7d2fe; }
  .overview h2 { margin: 0 0 8px; font-size: 18px; color: #312e81; }
  .overview p { margin: 0; color: #1e293b; }

  .cards { display: grid; gap: 18px; margin-top: 8px; }
  .card { border-radius: 14px; background: #ffffff; box-shadow: 0 4px 20px -8px rgba(15,23,42,.12); overflow: hidden; border: 1px solid #e2e8f0; }
  .card-head { display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; font-size: 13px; font-weight: 600; }
  .sev-pill { font-size: 14px; letter-spacing: 0.04em; }
  .rel { opacity: 0.92; }
  .card-body { padding: 22px 26px 26px; }
  .card-title { margin: 0 0 6px; font-size: 19px; color: #0f172a; line-height: 1.35; }
  .meta { font-size: 12px; color: #475569; margin-bottom: 14px; }
  .src-link { color: #2563eb; text-decoration: none; margin-left: 10px; }
  .src-link:hover { text-decoration: underline; }
  .exec { font-size: 15px; color: #1f2937; margin: 0 0 18px; padding: 12px 16px; border-left: 4px solid #6366f1; background: #f5f3ff; border-radius: 0 8px 8px 0; }
  .block { margin-top: 14px; }
  .block-label { font-size: 12px; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; }
  .analysis { margin: 0; font-size: 14px; color: #1f2937; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 500; }
  .chip-cve { background: #fee2e2; color: #991b1b; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .chip-mitre { background: #ede9fe; color: #5b21b6; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .iocs { background: #0f172a; color: #f8fafc; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; padding: 12px 14px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .actions { margin: 0; padding-left: 22px; font-size: 14px; color: #1f2937; }
  .actions li { margin: 4px 0; }
  footer { margin-top: 30px; text-align: center; color: #64748b; font-size: 12px; }
</style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>🛡️ OptraSight CIRT Deep Dive Report</h1>
      <div class="sub">Generated ${esc(new Date(meta.generatedAt).toUTCString())} · ${result.perFinding.length} finding${result.perFinding.length === 1 ? "" : "s"} analysed${meta.providerLabel ? ` · ${esc(meta.providerLabel)}` : " · deterministic mock"}</div>
      <div class="badges">
        <span class="badge">CIRT-grade structured analysis</span>
        <span class="badge">MITRE ATT&CK-anchored</span>
        <span class="badge">Source-fetched</span>
      </div>
      ${profile}
    </section>

    ${result.overallAssessment ? `<section class="overview"><h2>📋 Overall Assessment</h2><p>${esc(result.overallAssessment)}</p></section>` : ""}

    <div class="cards">
      ${cards}
    </div>

    <footer>OptraSight · CIRT Deep Dive · Self-contained report — view offline or attach to incident tickets.</footer>
  </div>
</body>
</html>`;
  return html;
}



// ---------------------------------------------------------------------------
// v2.17 — Free-form chat converse. The floating AI assistant on the OSINT
// page can hold an open conversation with the analyst about the currently
// visible findings. Uses the same provider routing as triage/deep-dive
// (osint_overview lane) so a tenant only needs one provider configured.
// ---------------------------------------------------------------------------

import { liveChatJsonDiagnostic } from "./aiLive";

export interface ChatConverseMessage {
  role: "user" | "assistant";
  content: string;
}
export interface RunChatConverseOpts {
  tenantId: string;
  messages: ChatConverseMessage[];
  /** Optional list of finding IDs the conversation is currently scoped to. */
  contextFindingIds?: string[];
}
export interface RunChatConverseResult {
  reply: string;
  providerLabel: string;
  contextSize: number;
}

const CONVERSE_SYSTEM = `You are OptraSight's OSINT analyst assistant. You help cyber-security analysts triage open-source threat intelligence findings.

Tone: concise, technical, neutral. No marketing fluff.
Always answer in English.
Always return JSON with a single key "reply" whose value is the markdown answer.
Where useful, structure replies with short bullets, sub-headers, and inline code for technical artifacts (CVEs, IPs, file hashes, ATT&CK IDs).
If the analyst asks for something you do not have evidence for in the supplied findings, say so explicitly instead of guessing.`;

export async function runChatConverse(storage: any, opts: RunChatConverseOpts): Promise<RunChatConverseResult> {
  const messages = Array.isArray(opts.messages) ? opts.messages.slice(-12) : []; // bound the history sent to the LLM
  if (messages.length === 0 || messages[messages.length - 1].role !== "user") {
    throw new Error("the conversation must end with a user message");
  }

  // Compose the user-side payload: history + (optional) finding context.
  const findingCtx: any[] = [];
  if (opts.contextFindingIds && opts.contextFindingIds.length) {
    for (const fid of opts.contextFindingIds.slice(0, 12)) {
      const f = storage.getOsintFinding ? storage.getOsintFinding(opts.tenantId, fid) : null;
      if (!f) continue;
      findingCtx.push({
        id: f.id,
        title: f.title,
        severity: f.severity,
        source: f.sourceName,
        publishedAt: f.publishedAt,
        cveIds: f.cveIds,
        affectedTech: f.affectedTech,
        threatActors: f.threatActors,
        summary: f.summary,
        aiSummary: f.aiSummary,
        url: f.url,
      });
    }
  }

  const userPayload = {
    findings: findingCtx,
    conversation: messages,
  };

  const provider = storage.resolveAiProvider
    ? storage.resolveAiProvider(opts.tenantId, "osint_overview")
    : null;

  if (!provider || provider.provider === "mock") {
    // Deterministic mock so the UI still works during setup.
    const last = messages[messages.length - 1].content;
    const reply = `**(no live AI provider configured)**\n\nI heard: _${last.slice(0, 200)}_\n\nConfigure DeepSeek, OpenAI, Anthropic, or Gemini under **AI Setup** for live answers.`;
    return { reply, providerLabel: "mock", contextSize: findingCtx.length };
  }

  const diag = liveChatJsonDiagnostic(provider, {
    system: CONVERSE_SYSTEM,
    user: JSON.stringify(userPayload),
    temperature: 0.4,
    // v2.26 — unbounded tokens; let the provider use its full default budget
    timeoutSeconds: 300,
  });
  if (!diag.ok || !diag.result) {
    throw new ChatLiveAiError(provider.label || provider.provider, diag);
  }
  const reply = typeof (diag.result as any).reply === "string"
    ? (diag.result as any).reply
    : JSON.stringify(diag.result);
  return { reply, providerLabel: provider.label || provider.provider, contextSize: findingCtx.length };
}
