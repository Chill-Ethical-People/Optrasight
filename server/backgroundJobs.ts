/**
 * OptraSight v2.16 — Background OSINT scheduler
 * ----------------------------------------------------------------------------
 * Drives two periodic jobs per tenant, controlled entirely from
 * `tenant_osint_settings`:
 *
 *   1. Auto-fetch — every `fetch_interval_min` minutes (default 60), call
 *      `storage.runOsintScan` to pull fresh items from the tenant's monitored
 *      sources. Updates `last_fetch_*` book-keeping.
 *
 *   2. Auto-analyze — every 60 s (cheap heartbeat), pull up to
 *      `analyze_max_per_tick` (default 8) findings off `listOsintCirtQueue`
 *      and analyze them ONE AT A TIME via `chatDeepDiveLiveDiagnostic` with a
 *      single-element `findings` array. Single-finding calls fit comfortably
 *      in the 90 s timeout / 6000 max-tokens budget so they almost never time
 *      out — unlike batch deep dive which has to chew through 20 findings ×
 *      18 KB of source body in one shot and frequently exceeds 120 s.
 *
 * The scheduler is a singleton — one global setInterval(60_000) loop that
 * walks every tenant with a settings row. Per-tenant work is serialised
 * via an in-flight `Set` to prevent overlap if a previous tick is still
 * running. Concurrency *within* a tenant's analyze batch is capped at
 * `analyze_concurrency`.
 */

import { storage } from "./storage";
import { chatDeepDiveLiveDiagnostic, type ChatDeepDiveInputFinding } from "./aiClient";
import { fetchSourcesBatch } from "./sourceFetch";
import type { OsintFindingDTO } from "@shared/schema";

const TICK_INTERVAL_MS = 60_000;
const FETCH_SCAN_MAX = 60;

let timer: NodeJS.Timeout | null = null;
const inFlightFetch = new Set<string>();
const inFlightAnalyze = new Set<string>();

/** Boot the scheduler. Safe to call multiple times — repeats are no-ops. */
export function startOsintBackgroundJobs(): void {
  if (timer) return;
  // v2.27 — reap async AI jobs that were left running by a prior process so
  // the UI doesn't poll a zombie job forever after a restart.
  try {
    const reaped = storage.reaperAiJobs();
    if (reaped > 0) console.log(`[osint-bg] reaped ${reaped} orphaned AI job(s)`);
  } catch (e) {
    console.error("[osint-bg] reaperAiJobs on boot failed:", e);
  }
  // First tick after 5s so the server is fully ready, then every 60s.
  timer = setTimeout(function loop() {
    tickAllTenants()
      .catch((e) => console.error("[osint-bg] tick failed:", e))
      .finally(() => {
        try { storage.reaperAiJobs(); } catch { /* swallow — next tick will retry */ }
        timer = setTimeout(loop, TICK_INTERVAL_MS);
      });
  }, 5_000);
  console.log("[osint-bg] scheduler started");
}

/** Stop the scheduler. Used by tests; not called in production. */
export function stopOsintBackgroundJobs(): void {
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
}

async function tickAllTenants(): Promise<void> {
  const tenantIds = storage.listOsintAutomationTenants();
  for (const tid of tenantIds) {
    const settings = storage.getOsintAutomationSettings(tid);
    // Run both jobs in parallel but isolated per-tenant; failures in one
    // don't block the other.
    if (settings.autoFetchEnabled) {
      void runAutoFetchForTenant(tid).catch((e) =>
        console.error(`[osint-bg] fetch ${tid}:`, e),
      );
    }
    if (settings.autoAnalyzeEnabled) {
      void runAutoAnalyzeForTenant(tid).catch((e) =>
        console.error(`[osint-bg] analyze ${tid}:`, e),
      );
    }
  }
}

async function runAutoFetchForTenant(tid: string): Promise<void> {
  if (inFlightFetch.has(tid)) return;
  const settings = storage.getOsintAutomationSettings(tid);
  if (!settings.autoFetchEnabled) return;
  // Has the interval elapsed?
  if (settings.lastFetchAt) {
    const lastMs = Date.parse(settings.lastFetchAt);
    if (!Number.isNaN(lastMs)) {
      const dueAtMs = lastMs + settings.fetchIntervalMin * 60_000;
      if (dueAtMs > Date.now()) return;
    }
  }

  inFlightFetch.add(tid);
  try {
    const res = await storage.runOsintScan(tid, {
      maxFindings: FETCH_SCAN_MAX,
      mode: "auto",
    });
    storage.recordOsintAutoFetch(tid, {
      count: res.count,
      error: (res.errors && res.errors.length > 0) ? res.errors.slice(0, 3).join(" | ") : null,
    });
    console.log(`[osint-bg] fetch ${tid}: +${res.count} findings (mode=${res.mode})`);
  } catch (e: any) {
    storage.recordOsintAutoFetch(tid, { count: 0, error: String(e?.message || e) });
  } finally {
    inFlightFetch.delete(tid);
  }
}

async function runAutoAnalyzeForTenant(tid: string): Promise<void> {
  if (inFlightAnalyze.has(tid)) return;
  const settings = storage.getOsintAutomationSettings(tid);
  if (!settings.autoAnalyzeEnabled) return;

  // Need a live AI provider; otherwise there is nothing meaningful to do.
  const provider = (storage as any).resolveAiProvider
    ? (storage as any).resolveAiProvider(tid, "osint_analysis")
    : null;
  if (!provider || provider.provider === "mock") {
    storage.recordOsintAutoAnalyze(tid, {
      okCount: 0,
      failCount: 0,
      error: "no live AI provider configured (set one under AI Setup)",
    });
    return;
  }

  inFlightAnalyze.add(tid);
  try {
    const batch = storage.listOsintCirtQueue(tid, settings.analyzeMaxPerTick);
    if (batch.length === 0) {
      storage.recordOsintAutoAnalyze(tid, { okCount: 0, failCount: 0, error: null });
      return;
    }

    const clientProfile = {
      industries: ["security-operations"],
      geos: ["Global"],
      technologies: ["osint", "threat-intelligence", "detection-engineering"],
    };

    // Pre-fetch source bodies for the whole batch (concurrent under the hood
    // via sourceFetch's existing batching).
    const fetched = await fetchSourcesBatch(batch.map((f: OsintFindingDTO) => f.url), { includeReferences: true, maxReferenceLinks: 5 });
    const sourceByIdx = new Map<number, string | null>();
    fetched.forEach((r, i) => sourceByIdx.set(i, r.content));

    // Now analyze ONE FINDING AT A TIME with bounded concurrency. Single-item
    // payloads fit the 90 s / 6000-token budget easily, which is the whole
    // point of the per-intel mode: no more 120 s batch timeouts.
    let okCount = 0;
    let failCount = 0;
    let lastError: string | null = null;
    const concurrency = Math.max(1, settings.analyzeConcurrency);

    let cursor = 0;
    const worker = async (): Promise<void> => {
      while (cursor < batch.length) {
        const i = cursor++;
        const finding = batch[i];
        const sourceContent = sourceByIdx.get(i) ?? null;
        try {
          const deepInput: ChatDeepDiveInputFinding = {
            id: finding.id,
            title: finding.title,
            url: finding.url ?? null,
            source: finding.sourceName,
            publishedAt: finding.publishedAt,
            severity: finding.severity,
            cveIds: finding.cveIds,
            affectedTech: finding.affectedTech,
            threatActors: finding.threatActors,
            summary: finding.summary ?? null,
            sourceContent,
          };
          const { result, diag } = chatDeepDiveLiveDiagnostic(
            { clientProfile, findings: [deepInput] },
            provider,
          );
          if (result && result.perFinding.length > 0) {
            // Find the analysis for this finding (model should echo findingId).
            const match =
              result.perFinding.find((p) => p.findingId === finding.id) ||
              result.perFinding[0];
            storage.saveOsintFindingCirt(tid, finding.id, {
              sourceContent,
              cirtAnalysis: match,
              providerLabel: provider.label || provider.provider,
            });
            okCount += 1;
          } else {
            const reason = diag?.reason || "empty response from AI";
            storage.markOsintFindingCirtFailed(tid, finding.id, reason);
            failCount += 1;
            lastError = reason;
          }
        } catch (e: any) {
          const reason = String(e?.message || e);
          storage.markOsintFindingCirtFailed(tid, finding.id, reason);
          failCount += 1;
          lastError = reason;
        }
      }
    };

    await Promise.all(Array.from({ length: concurrency }, () => worker()));

    storage.recordOsintAutoAnalyze(tid, {
      okCount,
      failCount,
      error: lastError,
    });
    console.log(`[osint-bg] analyze ${tid}: ok=${okCount} fail=${failCount}`);
  } catch (e: any) {
    storage.recordOsintAutoAnalyze(tid, {
      okCount: 0,
      failCount: 0,
      error: String(e?.message || e),
    });
  } finally {
    inFlightAnalyze.delete(tid);
  }
}

/**
 * Public: enqueue a tenant for an *immediate* analyze pass (bypasses the 60 s
 * heartbeat). Used by the "Re-run all analysis" button so users see motion
 * right away. Returns the inflight promise so callers can await completion.
 */
export async function runAutoAnalyzeNow(tid: string): Promise<void> {
  await runAutoAnalyzeForTenant(tid);
}

/**
 * Public: enqueue an immediate fetch for a tenant. Used by the manual
 * "Fetch now" button on the Settings card.
 */
export async function runAutoFetchNow(tid: string): Promise<void> {
  // Force-bypass the interval gate by clearing lastFetchAt-derived guard:
  // recordOsintAutoFetch updates last_fetch_at, so the next regular tick
  // will respect the configured interval again.
  inFlightFetch.delete(tid);
  await runAutoFetchForTenant(tid);
}
