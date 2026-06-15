export type AccessMode = "credentialed" | "guest";

export type Capability =
  | "view_intel"
  | "view_tap"
  | "view_hunt_queries"
  | "task_analysis"
  | "manage_sources"
  | "configure_ai"
  | "view_jobs"
  | "manage_jobs"
  | "global_view"
  | "full_platform";

const BATCH_ONE_REVIEW_CAPABILITIES: Capability[] = [
  "view_intel",
  "view_tap",
  "view_hunt_queries",
  "task_analysis",
  "view_jobs",
];

const BATCH_ONE_OPERATOR_CAPABILITIES: Capability[] = [
  ...BATCH_ONE_REVIEW_CAPABILITIES,
  "manage_sources",
  "configure_ai",
  "manage_jobs",
];

const FULL_PLATFORM_ADMIN_CAPABILITIES: Capability[] = [
  ...BATCH_ONE_OPERATOR_CAPABILITIES,
  "global_view",
  "full_platform",
];

export function resolveCapabilities(opts: {
  role?: string | null;
  accessMode?: AccessMode | null;
  batchOne?: boolean;
}): Capability[] {
  const role = opts.role ?? "analyst";
  const accessMode = opts.accessMode ?? "credentialed";
  const unique = (items: Capability[]) => Array.from(new Set(items));

  if (opts.batchOne) {
    return unique(accessMode === "guest" || role === "reviewer"
      ? BATCH_ONE_REVIEW_CAPABILITIES
      : BATCH_ONE_OPERATOR_CAPABILITIES);
  }

  if (role === "admin" || role === "owner") return unique(FULL_PLATFORM_ADMIN_CAPABILITIES);
  return unique(BATCH_ONE_REVIEW_CAPABILITIES);
}

export function hasCapability(
  capabilities: readonly Capability[] | undefined | null,
  capability: Capability,
): boolean {
  return !!capabilities?.includes(capability);
}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

function matches(path: string, pattern: string | RegExp): boolean {
  return typeof pattern === "string" ? path === pattern : pattern.test(path);
}

const BATCH_ONE_GUEST_API_ALLOW: Partial<Record<Method, Array<string | RegExp>>> = {
  GET: [
    "/api/v1/me",
    "/api/v1/search",
    "/api/v1/auth/mfa/setup",
    "/api/v1/taxonomies",
    "/api/v1/ai/providers",
    "/api/v1/ai/assignments",
    "/api/v1/threat-actors",
    "/api/v1/threat-actors/_meta",
    "/api/v1/threat-actors/portrait-generator/availability",
    /^\/api\/v1\/threat-actors\/[^/]+(?:\/full|\/export\.docx)?$/,
    "/api/v1/osint/findings",
    /^\/api\/v1\/osint\/findings\/[^/]+$/,
    /^\/api\/v1\/osint\/findings\/[^/]+\/cirt-cache$/,
    "/api/v1/osint/sources",
    "/api/v1/osint/hunt-queries",
    "/api/v1/osint/ai-jobs/history",
    /^\/api\/v1\/osint\/ai-jobs\/[^/]+$/,
    "/api/v1/ai-jobs/active",
    /^\/api\/v1\/ai-jobs\/[^/]+(?:\/full)?$/,
    "/api/v1/operations/audit",
    /^\/api\/v1\/exchange\/stix\/preview$/,
  ],
  POST: [
    "/api/v1/auth/logout",
    "/api/v1/auth/change-password",
    "/api/v1/auth/mfa/verify",
    "/api/v1/osint/findings/ai-analyze",
    "/api/v1/osint/chat/triage",
    "/api/v1/osint/chat/deep-dive",
    "/api/v1/osint/chat/converse",
  ],
};

const BATCH_ONE_OPERATOR_API_ALLOW: Partial<Record<Method, Array<string | RegExp>>> = {
  GET: [
    ...(BATCH_ONE_GUEST_API_ALLOW.GET ?? []),
    "/api/v1/admin/platform-users",
    "/api/v1/osint/sources/analytics",
    "/api/v1/osint/sources/health",
    "/api/v1/osint/sources/heatmaps",
    "/api/v1/osint/sources/overlap",
    "/api/v1/osint/sources/quadrant",
    "/api/v1/osint/sources/scorecard",
    "/api/v1/osint/automation/settings",
    "/api/v1/admin/osint/ingest/status",
    /^\/api\/v1\/osint\/reanalyze-jobs\/[^/]+$/,
    "/api/v1/osint/dictionaries",
    "/api/v1/operations/audit",
    "/api/v1/scans",
  ],
  POST: [
    ...(BATCH_ONE_GUEST_API_ALLOW.POST ?? []),
    "/api/v1/osint/sources/bulk",
    "/api/v1/osint/findings/reanalyze",
    "/api/v1/osint/scan",
    "/api/v1/osint/automation/fetch-now",
    "/api/v1/osint/automation/analyze-now",
    "/api/v1/osint/automation/reset-cache",
    "/api/v1/admin/osint/ingest",
    "/api/v1/osint/overview",
    "/api/v1/osint/hunt-queries",
    "/api/v1/ai/providers",
    /^\/api\/v1\/ai\/providers\/[^/]+\/test$/,
    "/api/v1/threat-actors",
    "/api/v1/admin/platform-users",
    /^\/api\/v1\/admin\/platform-users\/[^/]+\/(?:reset-mfa|disable)$/,
    /^\/api\/v1\/threat-actors\/[^/]+\/(?:portrait|portrait\/upload|enrich|ttps|tools|campaigns|iocs|references|rule-links)$/,
    "/api/v1/operations/jobs/cancel-running",
    /^\/api\/v1\/operations\/jobs\/[^/]+\/[^/]+\/cancel$/,
  ],
  PUT: [
    /^\/api\/v1\/ai\/providers\/[^/]+$/,
    /^\/api\/v1\/admin\/platform-users\/[^/]+$/,
    "/api/v1/ai/assignments",
  ],
  PATCH: [
    /^\/api\/v1\/osint\/findings\/[^/]+$/,
    /^\/api\/v1\/threat-actors\/[^/]+$/,
    "/api/v1/osint/automation/settings",
  ],
  DELETE: [
    /^\/api\/v1\/ai\/providers\/[^/]+$/,
    /^\/api\/v1\/admin\/platform-users\/[^/]+$/,
    /^\/api\/v1\/threat-actors\/[^/]+\/portrait$/,
    /^\/api\/v1\/threat-actors\/[^/]+$/,
    /^\/api\/v1\/threat-actors\/[^/]+\/(?:ttps|tools|campaigns|iocs|references)\/[^/]+$/,
    /^\/api\/v1\/threat-actors\/[^/]+\/rule-links\/[^/]+$/,
  ],
};

export function isBatchOneApiAllowed(opts: {
  method: string;
  path: string;
  accessMode?: AccessMode | null;
}): boolean {
  const method = opts.method.toUpperCase() as Method;
  if (method === "HEAD" || method === "OPTIONS") return true;
  const policy = opts.accessMode === "guest"
    ? BATCH_ONE_GUEST_API_ALLOW
    : BATCH_ONE_OPERATOR_API_ALLOW;
  return (policy[method] ?? []).some((pattern) => matches(opts.path, pattern));
}
