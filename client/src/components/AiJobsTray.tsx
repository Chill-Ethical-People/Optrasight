// v2.30.5 — AI jobs tray (bell icon in top bar).
//
// Lists running + recently completed AI jobs from the global AiJobsProvider.
// Click "Open" to jump to the page/sheet that owns the job. Failed jobs show
// the truncated error message inline so the user understands what to do next.

import { useMemo } from "react";
import { Bell, CheckCircle2, Loader2, AlertTriangle, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { navigateToAiJobTarget, useAiJobs, type AiJobSummary } from "@/lib/aiJobs";
import { cn } from "@/lib/utils";

const KIND_LABEL: Record<string, string> = {
  threat_actor_enrichment: "Threat actor enrichment",
  chat_triage: "CIRT triage",
  chat_deep_dive: "CIRT deep-dive",
  finding_ai_triage: "Finding AI triage",
  osint_analysis: "OSINT AI analysis",
  hunt_query_generation: "Hunt query generation",
  detection_rule_generation: "Detection rule generation",
  osint_triage: "CIRT triage",
  osint_deep_dive: "CIRT deep-dive",
  osint_run: "OSINT collection run",
};

export function aiJobKindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind.replaceAll("_", " ");
}

function elapsed(job: AiJobSummary): string {
  const start = job.startedAt ?? job.createdAt;
  if (!start) return "";
  const end = job.completedAt ? new Date(job.completedAt).getTime() : Date.now();
  const ms = end - new Date(start).getTime();
  if (ms < 0) return "";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return rem === 0 ? `${m}m` : `${m}m ${rem}s`;
}

export function aiJobRowState(job: AiJobSummary, variant: "running" | "finished") {
  const kindLabel = aiJobKindLabel(job.kind);
  const target = job.targetLabel ?? "";
  const ok = job.status === "succeeded" || job.status === "completed";
  const fail = job.status === "failed" || job.status === "completed_with_errors";
  return {
    kindLabel,
    target,
    ok,
    fail,
    openUrl: job.targetUrl ?? null,
    isRunning: variant === "running",
  };
}

export function AiJobsTray() {
  const { running, recent } = useAiJobs();

  const orderedRecent = useMemo(() =>
    [...recent].sort((a, b) => {
      const tA = new Date(a.completedAt ?? a.createdAt).getTime();
      const tB = new Date(b.completedAt ?? b.createdAt).getTime();
      return tB - tA;
    }).slice(0, 20),
    [recent],
  );

  const hasRunning = running.length > 0;

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="relative h-9 w-9"
          aria-label="AI background jobs"
          data-testid="button-aijobs-tray"
        >
          <Bell size={16} className={cn(hasRunning && "text-primary")} />
          {hasRunning && (
            <span className="absolute top-1.5 right-1.5 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-primary text-[10px] font-semibold text-primary-foreground px-1">
              {running.length}
            </span>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[360px] p-0 max-h-[70vh] overflow-y-auto" data-testid="popover-aijobs-tray">
        <div className="border-b px-3 py-2.5">
          <div className="font-semibold text-sm">AI background jobs</div>
          <div className="text-[11px] text-muted-foreground">
            {hasRunning ? `${running.length} running` : "Nothing in flight"}
            {orderedRecent.length > 0 && ` · last ${orderedRecent.length} completed`}
          </div>
        </div>

        <div className="divide-y">
          {running.length === 0 && orderedRecent.length === 0 ? (
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              When the AI is busy on something — like enriching a threat actor or running CIRT triage — you'll see it here.
            </div>
          ) : null}

          {running.map((j) => (
            <JobRow key={j.id} job={j} variant="running" />
          ))}
          {orderedRecent.map((j) => (
            <JobRow key={j.id} job={j} variant="finished" />
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}

function JobRow({ job, variant }: { job: AiJobSummary; variant: "running" | "finished" }) {
  const { kindLabel, target, ok, fail } = aiJobRowState(job, variant);

  return (
    <div className="px-3 py-2.5 flex items-start gap-2.5" data-testid={`aijob-row-${job.id}`}>
      <div className="mt-0.5 shrink-0">
        {variant === "running" ? (
          <Loader2 size={14} className="animate-spin text-primary" />
        ) : ok ? (
          <CheckCircle2 size={14} className="text-emerald-600 dark:text-emerald-400" />
        ) : (
          <AlertTriangle size={14} className="text-amber-600 dark:text-amber-400" />
        )}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <div className="text-xs font-medium truncate">{kindLabel}</div>
          <Badge
            variant="outline"
            className={cn(
              "text-[9px] px-1.5 py-0 font-normal",
              variant === "running" && "border-primary/40 text-primary",
              ok && "border-emerald-400 text-emerald-700 dark:text-emerald-300",
              fail && "border-amber-400 text-amber-700 dark:text-amber-300",
            )}
          >
            {job.status}
          </Badge>
        </div>
        {target && (
          <div className="text-[11px] text-muted-foreground truncate" title={target}>{target}</div>
        )}
        <div className="text-[10px] text-muted-foreground/80 mt-0.5 flex items-center gap-2">
          {job.providerLabel && <span>{job.providerLabel}</span>}
          {(job.startedAt || job.createdAt) && <span>· {elapsed(job)}</span>}
        </div>
        {fail && job.errorMessage && (
          <div className="text-[11px] text-amber-700 dark:text-amber-300 mt-1 line-clamp-2">
            {job.errorMessage}
          </div>
        )}
      </div>
      {job.targetUrl && (
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-[11px]"
          onClick={() => navigateToAiJobTarget(job.targetUrl!)}
          data-testid={`button-aijob-open-${job.id}`}
        >
          Open <ExternalLink size={11} className="ml-1" />
        </Button>
      )}
    </div>
  );
}
