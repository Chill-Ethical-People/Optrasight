import type { AiJobSummary } from "./aiJobs";

export function aiJobElapsed(job: Pick<AiJobSummary, "createdAt" | "startedAt" | "completedAt">, nowMs = Date.now()): string {
  const start = job.startedAt ?? job.createdAt;
  if (!start) return "";
  const end = job.completedAt ? new Date(job.completedAt).getTime() : nowMs;
  const ms = end - new Date(start).getTime();
  if (ms < 0) return "";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return rem === 0 ? `${m}m` : `${m}m ${rem}s`;
}

export function aiJobCompleted(status: AiJobSummary["status"]): boolean {
  return status === "succeeded" || status === "completed";
}

export function aiJobFailed(status: AiJobSummary["status"]): boolean {
  return status === "failed" || status === "completed_with_errors";
}

export function aiJobOpenUrl(job: Pick<AiJobSummary, "kind" | "targetUrl" | "resultBytes">): string | null | undefined {
  if ((job.kind === "chat_triage" || job.kind === "chat_deep_dive") && (job.resultBytes ?? 0) <= 0) {
    return "/#/osint";
  }
  return job.targetUrl;
}
