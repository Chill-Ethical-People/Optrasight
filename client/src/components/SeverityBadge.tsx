import { severityColor, statusColor } from "@/lib/format";
import { cn } from "@/lib/utils";

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      data-testid={`badge-severity-${severity}`}
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded-md border text-[11px] font-medium uppercase tracking-wide",
        severityColor(severity),
      )}
    >
      {severity}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  return (
    <span
      data-testid={`badge-status-${status}`}
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium",
        statusColor(status),
      )}
    >
      {status.replace("_", " ")}
    </span>
  );
}
