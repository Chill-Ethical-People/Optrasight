import type {
  OsintFindingDTO,
  ThreatActorDTO,
  ThreatActorFullDTO,
} from "@shared/schema";
import { apiRequest, queryClient } from "@/lib/queryClient";

type OsintFindingsResp = { findings: OsintFindingDTO[] };
type ThreatActorsResp = { actors: ThreatActorDTO[] };
export type WarmExistingIntelScope = "startup" | "osint" | "tap" | "all";

const WARM_STALE_MS = 5 * 60 * 1000;

function emptyFullThreatActor(actor: ThreatActorDTO): ThreatActorFullDTO {
  return {
    ...actor,
    ttps: [],
    tools: [],
    campaigns: [],
    iocs: [],
    references: [],
    ruleLinks: [],
    relevantTenants: [],
  };
}

function seedOsintFindingsCache(data: OsintFindingsResp) {
  queryClient.setQueryData(["/api/v1/osint/findings"], data);
  queryClient.setQueryData(["/api/v1/osint/findings", "_all", "_all", "", "_all", "_all"], data);
  queryClient.setQueryData(["/api/v1/osint/findings", "_all", "_all", "", "_all"], data);
  for (const finding of data.findings ?? []) {
    queryClient.setQueryData(
      ["/api/v1/osint/findings", finding.id],
      (existing: OsintFindingDTO | undefined) => existing ?? finding,
      { updatedAt: 0 },
    );
  }
}

function seedThreatActorsCache(data: ThreatActorsResp) {
  queryClient.setQueryData(["/api/v1/threat-actors"], data);
  queryClient.setQueryData(["/api/v1/threat-actors", "all"], data);
  for (const actor of data.actors ?? []) {
    queryClient.setQueryData(
      ["/api/v1/threat-actors", actor.id],
      (existing: ThreatActorDTO | undefined) => existing ?? actor,
      { updatedAt: 0 },
    );
    queryClient.setQueryData(
      ["/api/v1/threat-actors", actor.id, "full"],
      (existing: ThreatActorFullDTO | undefined) => existing ?? emptyFullThreatActor(actor),
      { updatedAt: 0 },
    );
  }
}

async function warmJson<T>(path: string): Promise<T> {
  const r = await apiRequest("GET", path);
  return r.json();
}

function hasFreshCache(queryKey: readonly unknown[]) {
  const state = queryClient.getQueryState(queryKey);
  return Boolean(state?.dataUpdatedAt && Date.now() - state.dataUpdatedAt < WARM_STALE_MS);
}

async function prefetchIfCold<T>(
  queryKey: readonly unknown[],
  queryFn: () => Promise<T>,
  onData?: (data: T) => void,
) {
  if (hasFreshCache(queryKey)) return;
  const data = await queryClient.prefetchQuery({
    queryKey,
    queryFn,
    staleTime: WARM_STALE_MS,
  });
  onData?.(data);
}

export async function warmExistingIntelCache(scope: WarmExistingIntelScope = "all") {
  const jobs: Array<() => Promise<void>> = [];
  const includeOsintSources = scope === "startup" || scope === "osint" || scope === "all";
  const includeThreatActors = scope === "startup" || scope === "tap" || scope === "all";
  const includeOsintFindings = scope === "osint" || scope === "all";

  if (includeOsintSources) {
    jobs.push(() => prefetchIfCold(
      ["/api/v1/osint/sources", "filter"],
      () => warmJson("/api/v1/osint/sources"),
    ));
  }
  if (includeThreatActors) {
    jobs.push(() => prefetchIfCold(
      ["/api/v1/threat-actors"],
      () => warmJson<ThreatActorsResp>("/api/v1/threat-actors"),
      seedThreatActorsCache,
    ));
  }
  if (includeOsintFindings) {
    jobs.push(() => prefetchIfCold(
      ["/api/v1/osint/findings"],
      () => warmJson<OsintFindingsResp>("/api/v1/osint/findings"),
      seedOsintFindingsCache,
    ));
  }

  const results = [];
  for (const job of jobs) {
    results.push(await job().then(
      () => ({ status: "fulfilled" as const, value: undefined }),
      (reason) => ({ status: "rejected" as const, reason }),
    ));
  }
  return results;
}
