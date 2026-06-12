// v2.30.5 — Background AI jobs context + tray.
//
// Polls /api/v1/ai-jobs/active every 4s. Tracks completion transitions in a
// React state set (NO localStorage — sandboxed iframe blocks it). When a job
// transitions from running/queued to a terminal state we:
//   1. Fire a shadcn toast with an "Open" action that jumps to the target URL.
//   2. Invalidate the relevant React-Query keys so any visible page picks up
//      the AI's freshly-persisted output without a manual refresh.
//
// Wire this provider once near the root of <App />. The <AiJobsTray /> bell
// component renders the popover in the AppShell top bar.

import { createContext, useContext, useEffect, useMemo, useRef, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { ToastAction } from "@/components/ui/toast";

export interface AiJobSummary {
  id: string;
  kind: string;
  status: "queued" | "running" | "succeeded" | "failed" | "completed" | "completed_with_errors" | "cancelled";
  progressPct: number;
  providerLabel?: string | null;
  createdBy?: string | null;
  createdAt: string;
  startedAt?: string | null;
  completedAt?: string | null;
  targetLabel?: string | null;
  targetUrl?: string | null;
  heartbeatAt?: string | null;
  errorMessage?: string | null;
  resultBytes?: number;
}

export interface BackgroundJobStart {
  jobId: string;
  status: string;
  kind: string;
  targetLabel?: string | null;
  targetUrl?: string | null;
  [key: string]: any;
}

export async function startBackgroundJob(path: string, body?: any): Promise<BackgroundJobStart> {
  const r = await apiRequest("POST", path, body);
  const json = await r.json();
  if (!json?.jobId) throw new Error("server did not return a job id");
  return json;
}

function normalizeAiJobHash(hash: string): string {
  // v2.31 compatibility: older CIRT jobs pointed at the retired Intel route.
  // Keep their tray/toast Open buttons useful without rewriting historical rows.
  if (hash === "#/intel" || hash.startsWith("#/intel?")) {
    return hash.replace("#/intel", "#/osint");
  }
  return hash;
}

export function navigateToAiJobTarget(url: string) {
  let normalized = url;
  try {
    const parsed = new URL(url, window.location.origin);
    if (parsed.origin === window.location.origin) {
      normalized = parsed.hash || `${parsed.pathname}${parsed.search}`;
    }
  } catch {
    normalized = url;
  }
  const nextHash = normalized.startsWith("#")
    ? normalized
    : normalized.startsWith("/#/")
      ? normalized.slice(1)
      : normalized.startsWith("/")
        ? `#${normalized}`
        : null;
  if (nextHash) {
    const targetHash = normalizeAiJobHash(nextHash);
    const prev = window.location.hash;
    if (prev !== targetHash) window.location.hash = targetHash;
    // React hash routers do not always re-run route effects when the page path
    // is already mounted and only the query string changes. Also, native
    // hashchange timing varies when the click originates inside a popover.
    // Fire both a normal hashchange and an app-level event so page-level
    // deep-link consumers can open their dialogs deterministically.
    const dispatchDeepLink = () => {
      window.dispatchEvent(new HashChangeEvent("hashchange", {
        oldURL: window.location.href,
        newURL: window.location.href,
      }));
      window.dispatchEvent(new CustomEvent("optrasight:ai-job-open", {
        detail: { url, hash: targetHash },
      }));
    };
    dispatchDeepLink();
    window.setTimeout(dispatchDeepLink, 0);
    return;
  }
  window.location.href = url;
}

interface AiJobsContextValue {
  jobs: AiJobSummary[];
  running: AiJobSummary[];
  recent: AiJobSummary[];
  loading: boolean;
}

const AiJobsContext = createContext<AiJobsContextValue>({
  jobs: [], running: [], recent: [], loading: false,
});

// Map a job kind to the React-Query keys that should be invalidated on completion.
// Kept narrow on purpose — anything that doesn't match still gets a toast, just no
// auto-refresh. This avoids accidentally nuking large parts of the cache.
function queryKeysForKind(kind: string): unknown[][] {
  switch (kind) {
    case "threat_actor_enrichment":
      return [["/api/v1/threat-actors"], ["/api/v1/operations/audit"]];
    case "chat_triage":
    case "osint_triage":
      return [["/api/v1/osint/findings"], ["/api/v1/osint/sources/health"], ["/api/v1/operations/audit"]];
    case "chat_deep_dive":
    case "osint_deep_dive":
      return [["/api/v1/osint/findings"], ["/api/v1/operations/audit"]];
    case "finding_ai_triage":
    case "osint_analysis":
      return [["/api/v1/osint/findings"], ["/api/v1/osint/sources/scorecard"], ["/api/v1/osint/sources/quadrant"], ["/api/v1/osint/sources/overlap"], ["/api/v1/osint/sources/heatmaps"], ["/api/v1/operations/audit"]];
    case "hunt_query_generation":
      return [["/api/v1/osint/hunt-queries"], ["/api/v1/operations/audit"]];
    case "osint_run":
      return [["/api/v1/osint/findings"], ["/api/v1/osint/sources/health"], ["/api/v1/operations/audit"]];
    default:
      return [];
  }
}

function isTerminal(status: AiJobSummary["status"]): boolean {
  return status === "succeeded" || status === "failed" || status === "completed" || status === "completed_with_errors" || status === "cancelled";
}

function statusBucket(status: AiJobSummary["status"]): "success" | "failure" | "running" {
  if (status === "succeeded" || status === "completed") return "success";
  if (status === "failed" || status === "cancelled") return "failure";
  if (status === "completed_with_errors") return "failure";
  return "running";
}

export function AiJobsProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { toast } = useToast();
  const lastStatusRef = useRef<Map<string, AiJobSummary["status"]>>(new Map());
  const mountedAtRef = useRef(Date.now());
  // Tracks ids we've already fired a completion toast for, so even on stale
  // polls or page navigations we won't double-fire.
  const notifiedRef = useRef<Set<string>>(new Set());

  const enabled = !!user;

  const { data, isLoading } = useQuery<{ jobs: AiJobSummary[] }>({
    queryKey: ["/api/v1/ai-jobs/active"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/v1/ai-jobs/active");
      return r.json();
    },
    enabled,
    // 4s while user is on the page; React-Query already pauses when window blurs.
    refetchInterval: 4000,
    refetchIntervalInBackground: false,
    staleTime: 0,
  });

  const jobs = data?.jobs ?? [];

  useEffect(() => {
    if (!jobs.length) return;
    if (jobs.some((job) => job.status === "running" || job.status === "queued")) {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/operations/audit"] });
    }
    const last = lastStatusRef.current;
    const notifyJob = (job: AiJobSummary) => {
      if (notifiedRef.current.has(job.id)) return;
      notifiedRef.current.add(job.id);

      const bucket = statusBucket(job.status);
      const label = job.targetLabel ?? job.kind.replaceAll("_", " ");
      const url = job.targetUrl ?? undefined;
      const title =
        bucket === "success" ? "AI analysis complete"
          : bucket === "failure" ? "AI analysis failed"
            : "AI analysis updated";
      const description = job.errorMessage
        ? `${label} — ${job.errorMessage}`
        : label;

      toast({
        title,
        description,
        variant: bucket === "failure" ? "destructive" : "default",
        action: url ? (
          <ToastAction
            altText="Open"
            onClick={() => navigateToAiJobTarget(url)}
          >
            Open
          </ToastAction>
        ) : undefined,
      });

      // Auto-invalidate the relevant cache entries so any open page refreshes.
      for (const key of queryKeysForKind(job.kind)) {
        queryClient.invalidateQueries({ queryKey: key });
      }
    };

    for (const job of jobs) {
      const prev = last.get(job.id);
      // First time we see a job: just record its status. Don't fire a "completed"
      // toast for old jobs that completed before this tab was opened. Fast jobs
      // can start and finish between two polls, though, so notify when the
      // completion timestamp is newer than this provider instance.
      if (prev === undefined) {
        last.set(job.id, job.status);
        if (isTerminal(job.status)) {
          const completedAt = job.completedAt ? new Date(job.completedAt).getTime() : 0;
          if (completedAt >= mountedAtRef.current) notifyJob(job);
          else notifiedRef.current.add(job.id);
        }
        continue;
      }
      last.set(job.id, job.status);
      if (prev === job.status) continue;
      if (!isTerminal(job.status)) continue;
      notifyJob(job);
    }
  }, [jobs, toast]);

  const value = useMemo<AiJobsContextValue>(() => {
    const running = jobs.filter((j) => j.status === "running" || j.status === "queued");
    const recent = jobs.filter((j) => isTerminal(j.status));
    return { jobs, running, recent, loading: isLoading };
  }, [jobs, isLoading]);

  return <AiJobsContext.Provider value={value}>{children}</AiJobsContext.Provider>;
}

export function useAiJobs(): AiJobsContextValue {
  return useContext(AiJobsContext);
}
