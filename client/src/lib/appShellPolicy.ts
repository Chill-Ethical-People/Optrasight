import type { AccessMode } from "../../../shared/accessPolicy";

export function appShellAccessLabel(opts: {
  batchOne: boolean;
  accessMode?: AccessMode | null;
  role?: string | null;
  tenantName?: string | null;
}): string | null | undefined {
  if (opts.batchOne && opts.accessMode === "guest") return "Read-only reviewer";
  if (opts.batchOne && opts.accessMode === "credentialed") return "Threat analyst";
  if (opts.role === "admin") return "Platform admin";
  return opts.tenantName;
}

export function useReviewOnlyNav(opts: {
  batchOne: boolean;
  accessMode?: AccessMode | null;
}): boolean {
  return opts.batchOne && opts.accessMode === "guest";
}
