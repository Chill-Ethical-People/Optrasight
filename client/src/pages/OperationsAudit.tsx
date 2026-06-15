import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, Ban, CheckCircle2, Clock, ExternalLink,
  FileText, Loader2, RefreshCw, ShieldCheck, TerminalSquare, XCircle,
} from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/SeverityBadge";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { navigateToAiJobTarget, useAiJobs, type AiJobSummary } from "@/lib/aiJobs";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";

type OperationJob = {
  source: "ai_job" | "scan" | "osint_reanalyze" | "global_ingest";
  id: string;
  kind: string;
  label: string;
  status: string;
  progressPct?: number;
  providerLabel?: string | null;
  actor?: string | null;
  createdAt?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
  heartbeatAt?: string | null;
  target?: string | null;
  targetUrl?: string | null;
  errorMessage?: string | null;
  logTail?: string | null;
  findingCount?: number;
  totalCount?: number;
  doneCount?: number;
  failCount?: number;
  cancellable?: boolean;
};

type AuditEntry = {
  id: string;
  tenantId: string;
  actor: string;
  action: string;
  target: string | null;
  detail: string;
  createdAt: string;
};

type OperationsPayload = {
  summary: { active: number; failed: number; completed: number; cancelled: number };
  jobs: OperationJob[];
  auditEntries: AuditEntry[];
  globalIngest: OperationJob | null;
};

const SOURCE_LABEL: Record<string, string> = {
  ai_job: "AI job",
  scan: "Scanner",
  osint_reanalyze: "OSINT reanalysis",
  global_ingest: "Global ingest",
};

const KIND_LABEL: Record<string, string> = {
  threat_actor_enrichment: "Threat actor enrichment",
  chat_triage: "CIRT triage",
  chat_deep_dive: "CIRT deep-dive",
  finding_ai_triage: "Finding AI triage",
  osint_analysis: "OSINT AI analysis",
  hunt_query_generation: "Hunt query generation",
  detection_rule_generation: "Detection rule generation",
  osint_reanalyze: "OSINT bulk reanalysis",
  osint_global_ingest: "Global OSINT ingest",
};

export function isOperationJobActive(status: string): boolean {
  return status === "queued" || status === "running";
}

export function isOperationJobComplete(status: string): boolean {
  return ["completed", "done", "succeeded"].includes(status);
}

export function isOperationJobFailed(job: Pick<OperationJob, "status" | "errorMessage">): boolean {
  return job.status === "failed" || !!job.errorMessage;
}

export function operationJobProgress(job: Pick<OperationJob, "status" | "progressPct" | "errorMessage">): number {
  if (isOperationJobFailed(job)) return 0;
  const pct = Math.max(0, Math.min(100, Math.round(job.progressPct ?? 0)));
  if (isOperationJobComplete(job.status)) return 100;
  return Math.max(5, pct);
}

function operationJobFromAiJob(job: AiJobSummary): OperationJob {
  return {
    source: "ai_job",
    id: job.id,
    kind: job.kind,
    label: job.targetLabel || job.kind,
    status: job.status,
    progressPct: job.progressPct,
    providerLabel: job.providerLabel ?? null,
    actor: job.createdBy ?? null,
    createdAt: job.createdAt,
    startedAt: job.startedAt ?? null,
    finishedAt: job.completedAt ?? null,
    heartbeatAt: job.heartbeatAt ?? null,
    target: job.targetLabel ?? null,
    targetUrl: job.targetUrl ?? null,
    errorMessage: job.errorMessage ?? null,
    cancellable: isOperationJobActive(job.status),
  };
}

function jobTitle(job: OperationJob): string {
  return KIND_LABEL[job.kind] ?? job.kind.replaceAll("_", " ");
}

function detailObject(entry: AuditEntry): Record<string, unknown> | string {
  try {
    const parsed = JSON.parse(entry.detail || "{}");
    return parsed && typeof parsed === "object" ? parsed : entry.detail;
  } catch {
    return entry.detail || "{}";
  }
}

function formatDuration(job: OperationJob): string {
  const start = job.startedAt || job.createdAt;
  if (!start) return "—";
  const end = job.finishedAt ? new Date(job.finishedAt).getTime() : Date.now();
  const ms = Math.max(0, end - new Date(start).getTime());
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  return `${hr}h ${min % 60}m`;
}

function StatTile({
  label, value, icon, tone,
}: { label: string; value: number | string; icon: ReactNode; tone: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-[11px] uppercase text-muted-foreground font-medium" style={{ letterSpacing: "0.08em" }}>
            {label}
          </div>
          <div className="text-2xl font-semibold mt-1">{value}</div>
        </div>
        <div className={cn("h-10 w-10 rounded-lg flex items-center justify-center", tone)}>
          {icon}
        </div>
      </div>
    </Card>
  );
}

function JobRow({
  job, cancelling, onCancel, compact = false,
}: { job: OperationJob; cancelling: boolean; onCancel: (job: OperationJob) => void; compact?: boolean }) {
  const pct = operationJobProgress(job);
  const stateIcon = isOperationJobActive(job.status) ? (
    <Loader2 size={compact ? 12 : 14} className="animate-spin" />
  ) : isOperationJobFailed(job) ? (
    <AlertTriangle size={compact ? 12 : 14} />
  ) : (
    <CheckCircle2 size={compact ? 12 : 14} />
  );
  const stateTone = isOperationJobActive(job.status) ? "bg-cyan-500/10 text-cyan-600 dark:text-cyan-300" :
    isOperationJobFailed(job) ? "bg-red-500/10 text-red-600 dark:text-red-300" :
      "bg-emerald-500/10 text-emerald-600 dark:text-emerald-300";

  if (compact) {
    return (
      <tr className="border-t hover:bg-muted/30 transition-colors" data-testid={`row-operation-job-${job.source}-${job.id}`}>
        <td className="px-3 py-2 align-middle">
          <div className="flex items-center gap-2 min-w-[260px]">
            <div className={cn("h-5 w-5 rounded flex items-center justify-center shrink-0", stateTone)}>
              {stateIcon}
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 min-w-0">
                <span className="font-medium text-xs truncate">{jobTitle(job)}</span>
                {job.errorMessage && <AlertTriangle size={11} className="shrink-0 text-red-600 dark:text-red-300" />}
              </div>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="text-[11px] text-muted-foreground truncate max-w-[420px] cursor-help">
                    {job.errorMessage || job.label || job.target || job.id}
                  </div>
                </TooltipTrigger>
                <TooltipContent className="max-w-[360px] text-xs">
                  {job.errorMessage || job.label || job.target || job.id}
                </TooltipContent>
              </Tooltip>
            </div>
          </div>
        </td>
        <td className="px-3 py-2 align-middle">
          <div className="flex items-center gap-1.5 min-w-[82px]">
            {job.providerLabel ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="inline-flex cursor-help">
                    <Badge variant="outline" className="text-[9px] px-1.5 py-0">
                      {SOURCE_LABEL[job.source] ?? job.source}
                    </Badge>
                  </span>
                </TooltipTrigger>
                <TooltipContent className="max-w-[360px] text-xs">
                  <div className="font-medium">{SOURCE_LABEL[job.source] ?? job.source}</div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground break-words">
                    {job.providerLabel}
                  </div>
                </TooltipContent>
              </Tooltip>
            ) : (
              <Badge variant="outline" className="text-[9px] px-1.5 py-0">
                {SOURCE_LABEL[job.source] ?? job.source}
              </Badge>
            )}
          </div>
        </td>
        <td className="px-3 py-2 align-middle whitespace-nowrap">
          <StatusPill status={job.status} />
        </td>
        <td className="px-3 py-2 align-middle min-w-[112px]">
          <div className="flex items-center gap-1.5">
            <Progress value={pct} className="h-1 w-16" />
            <span className="text-[10px] font-mono text-muted-foreground w-7 text-right">{pct}%</span>
          </div>
        </td>
        <td className="px-3 py-2 align-middle text-[11px] text-muted-foreground whitespace-nowrap">
          {formatDuration(job)}
        </td>
        <td className="px-3 py-2 align-middle text-right">
          <div className="flex items-center justify-end gap-1">
            {job.targetUrl && (
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 cursor-pointer"
                onClick={() => navigateToAiJobTarget(job.targetUrl!)}
                aria-label="Open job target"
                data-testid={`button-operation-open-${job.id}`}
              >
                <ExternalLink size={13} />
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 cursor-pointer"
              disabled={!job.cancellable || cancelling}
              onClick={() => onCancel(job)}
              aria-label="Cancel job"
              data-testid={`button-operation-cancel-${job.id}`}
            >
              {cancelling ? <Loader2 size={13} className="animate-spin" /> : <Ban size={13} />}
            </Button>
          </div>
        </td>
      </tr>
    );
  }

  return (
    <tr className="border-t hover:bg-muted/30 transition-colors" data-testid={`row-operation-job-${job.source}-${job.id}`}>
      <td className="px-4 py-3 align-top">
        <div className="flex items-start gap-2.5 min-w-[220px]">
          <div className={cn(
            "mt-0.5 h-7 w-7 rounded-md flex items-center justify-center shrink-0",
            stateTone,
          )}>
            {stateIcon}
          </div>
          <div className="min-w-0">
            <div className="font-medium text-sm truncate" title={job.label}>{jobTitle(job)}</div>
            <div className="text-xs text-muted-foreground truncate max-w-[360px]" title={job.label}>
              {job.label || job.target || job.id}
            </div>
          </div>
        </div>
      </td>
      <td className="px-4 py-3 align-top">
        <div className="flex flex-wrap gap-1.5">
          <Badge variant="outline" className="text-[10px]">{SOURCE_LABEL[job.source] ?? job.source}</Badge>
          {job.providerLabel && <Badge variant="secondary" className="text-[10px]">{job.providerLabel}</Badge>}
        </div>
      </td>
      <td className="px-4 py-3 align-top">
        <StatusPill status={job.status} />
        {job.errorMessage && (
          <div className="mt-1 text-xs text-red-600 dark:text-red-300 max-w-[320px] line-clamp-2" title={job.errorMessage}>
            {job.errorMessage}
          </div>
        )}
      </td>
      <td className="px-4 py-3 align-top min-w-[160px]">
        <div className="flex items-center gap-2">
          <Progress value={pct} className="h-1.5" />
          <span className="text-[11px] font-mono text-muted-foreground w-9 text-right">{pct}%</span>
        </div>
        {(job.doneCount != null || job.findingCount != null) && (
          <div className="text-[11px] text-muted-foreground mt-1">
            {job.totalCount != null
              ? `${job.doneCount ?? 0} done · ${job.failCount ?? 0} failed · ${job.totalCount} total`
              : `${job.findingCount ?? 0} findings`}
          </div>
        )}
      </td>
      <td className="px-4 py-3 align-top text-xs text-muted-foreground">
        <div>{formatDuration(job)}</div>
        <div className="font-mono text-[10px] mt-0.5">{job.heartbeatAt ? `hb ${relativeTime(job.heartbeatAt)}` : relativeTime(job.startedAt || job.createdAt)}</div>
      </td>
      <td className="px-4 py-3 align-top">
        <div className="flex items-center justify-end gap-1.5">
          {job.targetUrl && (
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 cursor-pointer"
              onClick={() => navigateToAiJobTarget(job.targetUrl!)}
              aria-label="Open job target"
              data-testid={`button-operation-open-${job.id}`}
            >
              <ExternalLink size={14} />
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            className="h-8 cursor-pointer"
            disabled={!job.cancellable || cancelling}
            onClick={() => onCancel(job)}
            data-testid={`button-operation-cancel-${job.id}`}
          >
            {cancelling ? <Loader2 size={12} className="mr-1.5 animate-spin" /> : <Ban size={12} className="mr-1.5" />}
            Cancel
          </Button>
        </div>
      </td>
    </tr>
  );
}

export default function OperationsAudit() {
  const { toast } = useToast();
  const { jobs: liveAiJobs, loading: liveAiJobsLoading } = useAiJobs();
  const [tab, setTab] = useState("active");
  const [cancellingIds, setCancellingIds] = useState<Set<string>>(new Set());

  const { data, isLoading, isFetching, refetch } = useQuery<OperationsPayload>({
    queryKey: ["/api/v1/operations/audit"],
    refetchInterval: (q: any) => {
      const payload = q?.state?.data as OperationsPayload | undefined;
      const hasActiveJob = payload?.jobs?.some((j) => isOperationJobActive(j.status)) || (payload?.globalIngest ? isOperationJobActive(payload.globalIngest.status) : false);
      if (hasActiveJob) return 5_000;
      return tab === "active" ? 30_000 : false;
    },
    refetchIntervalInBackground: false,
  });

  const jobs = useMemo(() => {
    const rows = data?.globalIngest && data.globalIngest.status !== "idle"
      ? [data.globalIngest, ...(data?.jobs ?? [])]
      : (data?.jobs ?? []);
    const mergedRows = [...liveAiJobs.map(operationJobFromAiJob), ...rows];
    const seen = new Set<string>();
    return mergedRows.filter((job) => {
      const key = `${job.source}:${job.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [data, liveAiJobs]);

  const activeJobs = jobs.filter((job) => isOperationJobActive(job.status));
  const failedJobs = jobs.filter(isOperationJobFailed);
  const completedJobs = jobs.filter((job) => !isOperationJobActive(job.status) && !isOperationJobFailed(job));
  const visibleJobs = tab === "active" ? activeJobs : tab === "failed" ? failedJobs : jobs;

  const cancelOne = useMutation({
    mutationFn: async (job: OperationJob) => {
      setCancellingIds((prev) => new Set(prev).add(`${job.source}:${job.id}`));
      const r = await apiRequest("POST", `/api/v1/operations/jobs/${job.source}/${job.id}/cancel`);
      return { job, result: await r.json() };
    },
    onSuccess: ({ job }) => {
      toast({ title: "Job cancelled", description: `${jobTitle(job)} · ${job.label}` });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/operations/audit"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/ai-jobs/active"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/scans"] });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Cancel failed", description: String(e.message ?? e) }),
    onSettled: (_data, _err, job) => {
      if (!job) return;
      setCancellingIds((prev) => {
        const next = new Set(prev);
        next.delete(`${job.source}:${job.id}`);
        return next;
      });
    },
  });

  const cancelAll = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", "/api/v1/operations/jobs/cancel-running");
      return r.json() as Promise<{ results: Array<{ ok: boolean }> }>;
    },
    onSuccess: (out) => {
      const count = out.results.filter((r) => r.ok).length;
      toast({ title: "Running jobs cancelled", description: `${count} job${count === 1 ? "" : "s"} updated.` });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/operations/audit"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/ai-jobs/active"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/scans"] });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Cancel all failed", description: String(e.message ?? e) }),
  });

  return (
    <AppShell>
      <div className="px-6 md:px-10 py-8 max-w-[1500px]">
        <PageHeader
          eyebrow="Operations"
          title="Job Control"
          description="Track background work, inspect the latest job state and error details, and cancel queued or running jobs from one control surface."
          actions={
            <>
              <Button
                variant="outline"
                onClick={() => refetch()}
                disabled={isFetching}
                className="cursor-pointer"
                data-testid="button-operations-refresh"
              >
                <RefreshCw size={14} className={cn("mr-1.5", isFetching && "animate-spin")} />
                Refresh
              </Button>
              <Button
                variant="destructive"
                onClick={() => cancelAll.mutate()}
                disabled={activeJobs.length === 0 || cancelAll.isPending}
                className="cursor-pointer"
                data-testid="button-operations-cancel-all"
              >
                {cancelAll.isPending ? <Loader2 size={14} className="mr-1.5 animate-spin" /> : <XCircle size={14} className="mr-1.5" />}
                Cancel running
              </Button>
            </>
          }
        />

        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4 mb-6">
          <StatTile label="Active jobs" value={activeJobs.length} icon={<Activity size={18} />} tone="bg-cyan-500/10 text-cyan-600 dark:text-cyan-300" />
          <StatTile label="Failures with diagnostics" value={failedJobs.length} icon={<AlertTriangle size={18} />} tone="bg-red-500/10 text-red-600 dark:text-red-300" />
          <StatTile label="Completed recent" value={completedJobs.length} icon={<ShieldCheck size={18} />} tone="bg-emerald-500/10 text-emerald-600 dark:text-emerald-300" />
          <StatTile label="Audit rows" value={data?.auditEntries?.length ?? 0} icon={<FileText size={18} />} tone="bg-[hsl(var(--brand-soft))] text-[hsl(var(--brand))]" />
        </div>

        <Tabs value={tab} onValueChange={setTab} className="space-y-4">
          <TabsList>
            <TabsTrigger value="active" className="cursor-pointer">Active <span className="ml-1 text-[10px]">{activeJobs.length}</span></TabsTrigger>
            <TabsTrigger value="failed" className="cursor-pointer">Errors <span className="ml-1 text-[10px]">{failedJobs.length}</span></TabsTrigger>
            <TabsTrigger value="all" className="cursor-pointer">All jobs <span className="ml-1 text-[10px]">{jobs.length}</span></TabsTrigger>
            <TabsTrigger value="audit" className="cursor-pointer">Audit log</TabsTrigger>
          </TabsList>

          <TabsContent value="active" className="mt-0">
            <JobsTable jobs={visibleJobs} loading={isLoading || liveAiJobsLoading} cancellingIds={cancellingIds} onCancel={(job) => cancelOne.mutate(job)} />
          </TabsContent>
          <TabsContent value="failed" className="mt-0">
            <JobsTable jobs={visibleJobs} loading={isLoading || liveAiJobsLoading} cancellingIds={cancellingIds} onCancel={(job) => cancelOne.mutate(job)} />
          </TabsContent>
          <TabsContent value="all" className="mt-0">
            <JobsTable jobs={visibleJobs} loading={isLoading || liveAiJobsLoading} cancellingIds={cancellingIds} onCancel={(job) => cancelOne.mutate(job)} compact />
          </TabsContent>
          <TabsContent value="audit" className="mt-0">
            <AuditTable entries={data?.auditEntries ?? []} loading={isLoading} />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}

function JobsTable({
  jobs, loading, cancellingIds, onCancel, compact = false,
}: {
  jobs: OperationJob[];
  loading: boolean;
  cancellingIds: Set<string>;
  onCancel: (job: OperationJob) => void;
  compact?: boolean;
}) {
  if (loading) {
    return <Card className="p-12 text-center text-sm text-muted-foreground">Loading backend jobs...</Card>;
  }
  if (jobs.length === 0) {
    return (
      <Card className="p-12 text-center">
        <Clock size={28} className="mx-auto mb-3 text-muted-foreground" />
        <div className="text-sm font-medium">No jobs in this view</div>
        <div className="text-xs text-muted-foreground mt-1">Running AI tasks, scans, and reanalysis work will appear here.</div>
      </Card>
    );
  }
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className={cn("w-full", compact ? "text-xs" : "text-sm")}>
          <thead className="bg-muted/40 text-[11px] uppercase text-muted-foreground">
            <tr>
              <th className={cn("text-left font-medium", compact ? "px-3 py-2" : "px-4 py-2.5")}>Job</th>
              <th className={cn("text-left font-medium", compact ? "px-3 py-2" : "px-4 py-2.5")}>Source</th>
              <th className={cn("text-left font-medium", compact ? "px-3 py-2" : "px-4 py-2.5")}>Status</th>
              <th className={cn("text-left font-medium", compact ? "px-3 py-2" : "px-4 py-2.5")}>Progress</th>
              <th className={cn("text-left font-medium", compact ? "px-3 py-2" : "px-4 py-2.5")}>Runtime</th>
              <th className={cn("text-right font-medium", compact ? "px-3 py-2" : "px-4 py-2.5")}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((job) => (
              <JobRow
                key={`${job.source}:${job.id}`}
                job={job}
                cancelling={cancellingIds.has(`${job.source}:${job.id}`)}
                onCancel={onCancel}
                compact={compact}
              />
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function AuditTable({ entries, loading }: { entries: AuditEntry[]; loading: boolean }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  if (loading) return <Card className="p-12 text-center text-sm text-muted-foreground">Loading audit log...</Card>;
  if (entries.length === 0) return <Card className="p-12 text-center text-sm text-muted-foreground">No audit events recorded yet.</Card>;
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted/40 text-[11px] uppercase text-muted-foreground">
            <tr>
              <th className="px-4 py-2.5 text-left font-medium">Event</th>
              <th className="px-4 py-2.5 text-left font-medium">Actor</th>
              <th className="px-4 py-2.5 text-left font-medium">Target</th>
              <th className="px-4 py-2.5 text-left font-medium">Time</th>
              <th className="px-4 py-2.5 text-right font-medium">Detail</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => {
              const detail = detailObject(entry);
              const open = expanded === entry.id;
              return (
                <tr key={entry.id} className="border-t align-top hover:bg-muted/30 transition-colors" data-testid={`row-audit-${entry.id}`}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <TerminalSquare size={14} className="text-[hsl(var(--brand))]" />
                      <span className="font-medium">{entry.action}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{entry.actor}</td>
                  <td className="px-4 py-3 text-xs font-mono text-muted-foreground max-w-[260px] truncate">{entry.target || "-"}</td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{relativeTime(entry.createdAt)}</td>
                  <td className="px-4 py-3 text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 cursor-pointer"
                      onClick={() => setExpanded(open ? null : entry.id)}
                      data-testid={`button-audit-detail-${entry.id}`}
                    >
                      {open ? "Hide" : "Inspect"}
                    </Button>
                    {open && (
                      <pre className="mt-2 p-3 rounded-md bg-muted/60 text-left text-[11px] overflow-x-auto max-w-[520px] whitespace-pre-wrap">
                        {typeof detail === "string" ? detail : JSON.stringify(detail, null, 2)}
                      </pre>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
