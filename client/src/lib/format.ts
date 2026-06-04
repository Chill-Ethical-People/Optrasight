export function relativeTime(iso?: string | null): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return "just now";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function severityColor(sev: string): string {
  switch (sev) {
    case "critical": return "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30";
    case "high": return "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30";
    case "medium": return "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border-yellow-500/30";
    case "low": return "bg-sky-500/15 text-sky-600 dark:text-sky-400 border-sky-500/30";
    case "info": default: return "bg-muted text-muted-foreground border-border";
  }
}

export function statusColor(status: string): string {
  switch (status) {
    case "open": return "bg-red-500/10 text-red-600 dark:text-red-400";
    case "investigating": return "bg-amber-500/10 text-amber-600 dark:text-amber-400";
    case "takedown": return "bg-purple-500/10 text-purple-600 dark:text-purple-400";
    case "false_positive": return "bg-muted text-muted-foreground";
    case "resolved": return "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400";
    case "queued": return "bg-sky-500/10 text-sky-600 dark:text-sky-400";
    case "running": return "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400";
    case "succeeded": return "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400";
    case "completed":
    case "done": return "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400";
    case "cancelled": return "bg-slate-500/10 text-slate-600 dark:text-slate-300";
    case "failed": return "bg-red-500/10 text-red-600 dark:text-red-400";
    default: return "bg-muted text-muted-foreground";
  }
}
