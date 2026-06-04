import { useMemo, useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { AppShell, GLOBAL_TENANT_ID } from "@/components/AppShell";
import { ScopeBar, type ScopeDimension } from "@/components/ScopeBar";
import { useAuth } from "@/lib/auth";
import { PageHeader } from "@/components/PageHeader";
import { StartInvestigationButton } from "@/components/StartInvestigationButton";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription, DialogTrigger,
} from "@/components/ui/dialog";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from "@/components/ui/sheet";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { relativeTime } from "@/lib/format";
import type {
  OsintFindingDTO, HuntQueryDTO, OsintSourceRowDTO, OsintOverviewResultDTO,
  FindingIoCs, OsintFindingPatch,
} from "@shared/schema";

/** Findings response shape when scoped to a tenant (the standard endpoint). */
type TenantFindingsResp = { findings: OsintFindingDTO[] };
/** Findings response shape from /global/osint/findings — enriched with tenant info. */
type GlobalOsintFinding = OsintFindingDTO & {
  tenantName: string;
  tenantSlug: string;
  // v2.12 dedup mode — when the same intel is shared across N tenants, the row
  // collapses and carries the full list of associated tenants as tags.
  tenantTags?: Array<{ id: string; name: string; slug: string }>;
  duplicateCount?: number;
};
type GlobalFindingsResp = { findings: GlobalOsintFinding[] };
type GlobalHuntQuery = HuntQueryDTO & { tenantName: string; tenantSlug: string };
type GlobalDraftFinding = OsintFindingDTO & { tenantName: string; tenantSlug: string };
type StixPreviewResp = {
  valid: boolean;
  objectCount: number;
  objectCounts: Record<string, number>;
  indicatorCount: number;
  reportCount: number;
  attackPatternCount: number;
  findingCount: number;
  warnings: string[];
  errors: string[];
};
import {
  Radar, Sparkles, Mail, Search, Loader2, Code2, ExternalLink, Copy, ChevronRight, Brain, RefreshCw,
  Pencil, X as XIcon, Plus, Check as CheckIcon, ArrowUpDown, ArrowUp, ArrowDown, Power, PowerOff,
  Trash2, BarChart3, Megaphone, FileText, ShieldAlert, ShieldCheck, FileJson, Download,
} from "lucide-react";
import OsintChatbot, { type RangeKey } from "@/components/OsintChatbot";
import OsintTriagePanel from "@/components/OsintTriagePanel";
import OsintAutomationCard from "@/components/OsintAutomationCard";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { startBackgroundJob } from "@/lib/aiJobs";
import { useAiAvailability } from "@/lib/aiAvailability";

// v2.15 — Day-range filter (matches server osintChat.ts RANGE_HOURS).
const RANGE_HOURS: Record<RangeKey, number | null> = {
  "1d": 24, "7d": 168, "1m": 720, "1q": 2160, "1y": 8760, "all": null,
};
const RANGE_BUTTON_LABEL: Record<RangeKey, string> = {
  "1d": "1d", "7d": "7d", "1m": "1m", "1q": "1q", "1y": "1y", "all": "All",
};

function relevancePercent(score: number | null | undefined) {
  if (score == null || !Number.isFinite(Number(score))) return null;
  const n = Number(score);
  return Math.round(n <= 1 ? n * 100 : n);
}

function iocCount(iocs?: FindingIoCs | null) {
  if (!iocs) return 0;
  return Object.values(iocs).reduce((acc, vals) => acc + (Array.isArray(vals) ? vals.length : 0), 0);
}

function freshnessTier(publishedAt?: string | null) {
  const ts = Date.parse(publishedAt || "");
  if (!Number.isFinite(ts)) return { label: "undated", tone: "border-muted text-muted-foreground" };
  const hours = (Date.now() - ts) / 3_600_000;
  if (hours <= 24) return { label: "fresh <24h", tone: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" };
  if (hours <= 168) return { label: "fresh 7d", tone: "border-cyan-500/40 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300" };
  if (hours <= 720) return { label: "aging 30d", tone: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300" };
  return { label: "stale >30d", tone: "border-muted text-muted-foreground" };
}

function confidenceTier(f: OsintFindingDTO) {
  let score = 0;
  if (f.aiSummary) score += 2;
  if (f.attackTechniques?.length) score += 2;
  if (iocCount(f.iocs) > 0) score += 2;
  if (f.cveIds.length) score += 1;
  if (f.threatActors.length) score += 1;
  const rel = relevancePercent(f.aiRelevanceScore);
  if (rel != null && rel >= 70) score += 1;
  if (score >= 6) return { label: "confidence high", tone: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" };
  if (score >= 3) return { label: "confidence medium", tone: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300" };
  return { label: "confidence low", tone: "border-muted text-muted-foreground" };
}

function clientRelevanceReason(f: OsintFindingDTO) {
  const rel = relevancePercent(f.aiRelevanceScore);
  const reasons = [
    rel != null ? `${rel}% relevance` : null,
    f.affectedTech.length ? `${f.affectedTech.slice(0, 2).join(", ")} in scope` : null,
    f.cveIds.length ? `${f.cveIds.length} CVE${f.cveIds.length === 1 ? "" : "s"}` : null,
    f.attackTechniques?.length ? `${f.attackTechniques.length} ATT&CK tag${f.attackTechniques.length === 1 ? "" : "s"}` : null,
  ].filter(Boolean);
  return reasons.length ? reasons.join(" · ") : "No client relevance evidence yet";
}

interface SourcesResp {
  sources: OsintSourceRowDTO[];
  summary: { category: string; label: string; count: number }[];
}
interface FindingsResp { findings: OsintFindingDTO[] }
interface ScopedTabProps { isGlobal: boolean; dimension: ScopeDimension; selectedIds: string[]; onDimensionChange: (d: ScopeDimension) => void; onSelectedIdsChange: (ids: string[]) => void; }
type FindingsTabProps = ScopedTabProps;
interface HuntQueriesResp { queries: HuntQueryDTO[] }
interface TaxonomiesResp {
  huntLanguages: { id: string; label: string }[];
  osintOverviewPersonas?: { id: string; label: string; blurb: string }[];
  osintCategoryLabels?: Record<string, string>;
}

function severityColor(s: string) {
  switch (s) {
    case "critical": return "bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30";
    case "high":     return "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30";
    case "medium":   return "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30";
    case "low":      return "bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30";
    default:         return "bg-muted text-muted-foreground border-border";
  }
}

// v2.29 — Intel-category chip used on finding rows + detail panel.
function IntelCategoryChip({
  category,
  size = "sm",
  testId,
}: {
  category?: "threat_intel" | "regular_report" | "advertisement" | string | null;
  size?: "sm" | "md";
  testId?: string;
}) {
  if (!category) return null;
  const conf =
    category === "threat_intel"
      ? {
          Icon: ShieldAlert,
          label: "Threat Intel",
          cls: "bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30",
        }
      : category === "regular_report"
      ? {
          Icon: FileText,
          label: "Regular Report",
          cls: "bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30",
        }
      : category === "advertisement"
      ? {
          Icon: Megaphone,
          label: "Advertisement",
          cls: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
        }
      : null;
  if (!conf) return null;
  const Icon = conf.Icon;
  const pad = size === "md" ? "px-1.5 py-0.5" : "px-1.5 py-0";
  const text = size === "md" ? "text-[11px]" : "text-[10px]";
  const iconSize = size === "md" ? 11 : 10;
  return (
    <Badge
      variant="outline"
      className={`${pad} ${text} uppercase border whitespace-nowrap inline-flex items-center gap-1 ${conf.cls}`}
      data-testid={testId}
    >
      <Icon size={iconSize} />
      {conf.label}
    </Badge>
  );
}

// ---- Sources tab ----------------------------------------------------------
interface IngestStatus {
  busy: boolean;
  startedAt: string | null;
  finishedAt: string | null;
  summary: { count: number; tenants: number; feedsTried: number; feedsOk: number; errors: string[]; durationMs: number } | null;
  error: string | null;
}

// v2.29 — KPI card payload shape (mirrors OsintSourcesKpisDTO).
interface SourcesKpisResp {
  totalSources: number;
  sourcesReturningIntel: number;
  intelParsedToday: number;
  enabledCount: number;
  disabledCount: number;
}

// v2.29 — Sources table sort + filter state.
type SourceSortKey = "name" | "category" | "status" | "lastFetched" | "findings";
type SourceSortDir = "asc" | "desc";
type StatusFilter = "all" | "enabled" | "disabled";

function SourcesTab({ isGlobal, dimension, selectedIds: scopeIds, onDimensionChange, onSelectedIdsChange }: ScopedTabProps) {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const { toast } = useToast();
  const [q, setQ] = useState("");
  const [category, setCategory] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [sortKey, setSortKey] = useState<SourceSortKey>("findings");
  const [sortDir, setSortDir] = useState<SourceSortDir>("desc");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const scopeKey = scopeIds.join(",");

  // v2.29 — KPI strip.
  const { data: kpis } = useQuery<SourcesKpisResp>({
    queryKey: isGlobal
      ? ["/api/v1/osint/sources/kpis", "global"]
      : ["/api/v1/osint/sources/kpis", "tenant"],
    queryFn: async () => {
      const u = new URL("/api/v1/osint/sources/kpis", window.location.origin);
      if (isGlobal) u.searchParams.set("crossTenant", "true");
      const r = await apiRequest("GET", u.pathname + u.search);
      return r.json();
    },
  });

  // v2.7 — broad ingest progress (admin-only).
  const { data: ingestStatus } = useQuery<IngestStatus>({
    queryKey: ["/api/v1/admin/osint/ingest/status"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/v1/admin/osint/ingest/status");
      return r.json();
    },
    enabled: isAdmin,
    refetchInterval: (query) => (query.state.data?.busy ? 4000 : false),
  });

  const refresh = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", "/api/v1/admin/osint/ingest", {
        days: 365, maxPerSource: 60, maxTotal: 10000,
      });
      return r.json();
    },
    onSuccess: (resp: any) => {
      if (resp.status === "already_running") {
        toast({ title: "Ingest already running", description: "Polling for completion…" });
      } else {
        toast({ title: "Broad ingest started", description: "Walking the full source catalog — takes ~3-5 minutes" });
      }
      queryClient.invalidateQueries({ queryKey: ["/api/v1/admin/osint/ingest/status"] });
    },
    onError: (e: any) => {
      toast({ title: "Failed to start ingest", description: String(e?.message || e), variant: "destructive" });
    },
  });

  // When an ingest finishes, refetch the sources list so the parsed counts update.
  const wasBusy = useMemo(() => ingestStatus?.busy, [ingestStatus?.busy]);
  if (ingestStatus && !ingestStatus.busy && wasBusy === false && ingestStatus.finishedAt) {
    // no-op, react-query already invalidated above on completion
  }

  // v2.29 — Bulk enable / disable / delete mutation.
  const bulk = useMutation({
    mutationFn: async ({ ids, action }: { ids: string[]; action: "enable" | "disable" | "delete" }) => {
      const r = await apiRequest("POST", "/api/v1/osint/sources/bulk", { ids, action });
      return r.json();
    },
    onSuccess: (resp: any, vars) => {
      toast({ title: `${vars.action[0].toUpperCase() + vars.action.slice(1)}d sources`, description: `${resp.changed ?? 0} rows updated.` });
      setSelected(new Set());
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/sources"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/sources/kpis"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/global/osint/sources"] });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Bulk update failed", description: String(e?.message || e) }),
  });

  const { data, isLoading, refetch: refetchSources } = useQuery<SourcesResp>({
    queryKey: isGlobal
      ? ["/api/v1/global/osint/sources", dimension, scopeKey, category, q]
      : ["/api/v1/osint/sources", category, q],
    queryFn: async () => {
      const path = isGlobal ? "/api/v1/global/osint/sources" : "/api/v1/osint/sources";
      const u = new URL(path, window.location.origin);
      if (category && category !== "_all") u.searchParams.set("category", category);
      if (q) u.searchParams.set("q", q);
      if (isGlobal) {
        u.searchParams.set("dimension", dimension);
        if (scopeIds.length) u.searchParams.set("ids", scopeIds.join(","));
      }
      const r = await apiRequest("GET", u.pathname + u.search);
      return r.json();
    },
  });

  const sources = data?.sources || [];
  const summary = data?.summary || [];
  const total = summary.reduce((acc, s) => acc + s.count, 0);
  const totalParsed = sources.reduce((acc, s) => acc + (s.findingCount || 0), 0);

  // v2.29 — client-side filter + sort. Server already filters by category + q;
  // we still apply enabled-status filter and any sort key client-side so the
  // user can re-order without a round-trip.
  const visibleSources = useMemo(() => {
    let arr = sources.filter((s) => {
      if (statusFilter === "enabled" && !s.enabled) return false;
      if (statusFilter === "disabled" && s.enabled) return false;
      return true;
    });
    const cmp = (a: OsintSourceRowDTO, b: OsintSourceRowDTO): number => {
      switch (sortKey) {
        case "name":     return a.englishName.localeCompare(b.englishName);
        case "category": return a.categoryLabel.localeCompare(b.categoryLabel);
        case "status":   return (Number(a.enabled) - Number(b.enabled));
        case "lastFetched": {
          const av = a.lastFetchedAt || ""; const bv = b.lastFetchedAt || "";
          return av.localeCompare(bv);
        }
        case "findings": return a.findingCount - b.findingCount;
      }
      return 0;
    };
    arr = [...arr].sort((a, b) => {
      const c = cmp(a, b);
      return sortDir === "asc" ? c : -c;
    });
    return arr;
  }, [sources, statusFilter, sortKey, sortDir]);

  // Multi-select helpers.
  const visibleIds = useMemo(() => visibleSources.map((s) => s.id), [visibleSources]);
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => selected.has(id));
  const someVisibleSelected = visibleIds.some((id) => selected.has(id));
  const toggleOne = (id: string) => setSelected((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const toggleAllVisible = () => setSelected((prev) => {
    const next = new Set(prev);
    if (allVisibleSelected) {
      for (const id of visibleIds) next.delete(id);
    } else {
      for (const id of visibleIds) next.add(id);
    }
    return next;
  });
  const clickSort = (k: SourceSortKey) => {
    if (sortKey === k) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortKey(k);
      // sensible defaults: numbers desc, text asc
      setSortDir(k === "findings" || k === "lastFetched" ? "desc" : "asc");
    }
  };
  const SortIcon = ({ k }: { k: SourceSortKey }) => {
    if (sortKey !== k) return <ArrowUpDown className="w-3 h-3 inline ml-1 text-muted-foreground/60" />;
    return sortDir === "asc"
      ? <ArrowUp className="w-3 h-3 inline ml-1 text-primary" />
      : <ArrowDown className="w-3 h-3 inline ml-1 text-primary" />;
  };

  return (
    <div className="space-y-4">
      {isGlobal && (
        <ScopeBar
          dimension={dimension}
          selectedIds={scopeIds}
          onDimensionChange={onDimensionChange}
          onSelectedIdsChange={onSelectedIdsChange}
        />
      )}
      {/* v2.29 — KPI strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Card className="p-4" data-testid="card-kpi-returning">
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Sources returning intel</div>
          <div className="text-2xl font-semibold mt-1 tabular-nums">
            {kpis ? `${kpis.sourcesReturningIntel} / ${kpis.totalSources}` : "—"}
          </div>
          <div className="text-[11px] text-muted-foreground mt-1">Last 30 days</div>
        </Card>
        <Card className="p-4" data-testid="card-kpi-parsed-today">
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Intel parsed today</div>
          <div className="text-2xl font-semibold mt-1 tabular-nums">
            {kpis ? kpis.intelParsedToday.toLocaleString() : "—"}
          </div>
          <div className="text-[11px] text-muted-foreground mt-1">UTC midnight → now</div>
        </Card>
        <Card className="p-4" data-testid="card-kpi-enabled">
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Enabled · Disabled</div>
          <div className="text-2xl font-semibold mt-1 tabular-nums">
            {kpis ? `${kpis.enabledCount} · ` : "—"}
            {kpis && <span className="text-muted-foreground">{kpis.disabledCount}</span>}
          </div>
          <div className="text-[11px] text-muted-foreground mt-1">Across all sources</div>
        </Card>
      </div>

      <Card className="p-4">
        <div className="flex items-center justify-between gap-3 mb-3">
          <div>
            <div className="text-sm font-medium">Monitored OSINT sources {isGlobal ? "— Global" : ""}</div>
            <div className="text-xs text-muted-foreground mt-0.5">
              {total} feeds across {summary.length} buckets. {totalParsed} threat-intel items parsed {isGlobal ? "across the selected scope" : "for this client"}.
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="font-mono text-xs" data-testid="badge-source-total">
              {total} sources
            </Badge>
            <Badge variant="default" className="font-mono text-xs bg-primary/15 text-primary border-primary/30 border" data-testid="badge-source-parsed-total">
              {totalParsed} parsed
            </Badge>
            {isAdmin && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => refresh.mutate()}
                disabled={refresh.isPending || ingestStatus?.busy}
                data-testid="button-refresh-all-sources"
                className="gap-1.5 text-xs"
                title="Walk the full source catalog and pull the last 12 months of threat intel (admin only)"
              >
                {ingestStatus?.busy ? (
                  <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Ingesting…</>
                ) : (
                  <><RefreshCw className="w-3.5 h-3.5" /> Refresh all sources</>
                )}
              </Button>
            )}
          </div>
        </div>
        {isAdmin && ingestStatus?.summary && !ingestStatus.busy && (
          <div className="mb-3 text-[11px] text-muted-foreground bg-muted/40 border rounded px-3 py-2 flex flex-wrap items-center gap-x-4 gap-y-1" data-testid="text-ingest-summary">
            <span>Last broad ingest: <span className="font-mono">{ingestStatus.summary.count}</span> findings inserted across <span className="font-mono">{ingestStatus.summary.tenants}</span> tenants</span>
            <span>Feeds OK: <span className="font-mono">{ingestStatus.summary.feedsOk}/{ingestStatus.summary.feedsTried}</span></span>
            <span>Duration: <span className="font-mono">{Math.round(ingestStatus.summary.durationMs / 1000)}s</span></span>
            <Button size="sm" variant="ghost" className="h-6 text-[11px] gap-1" onClick={() => refetchSources()} data-testid="button-reload-source-counts">
              <RefreshCw className="w-3 h-3" /> Reload parsed counts
            </Button>
          </div>
        )}
        {isAdmin && ingestStatus?.busy && (
          <div className="mb-3 text-[11px] text-muted-foreground bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900 rounded px-3 py-2 flex items-center gap-2" data-testid="text-ingest-busy">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Broad OSINT ingest in progress — walking 500+ sources with deep custom parsers. Started {ingestStatus.startedAt ? new Date(ingestStatus.startedAt).toLocaleTimeString() : ""}.
          </div>
        )}
        <div className="flex flex-wrap gap-2">
          <Input
            value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="Search sources by name or URL…"
            className="flex-1 min-w-[240px]"
            data-testid="input-source-filter"
          />
          <Select value={category || "_all"} onValueChange={(v) => setCategory(v)}>
            <SelectTrigger className="w-[240px]" data-testid="select-source-category">
              <SelectValue placeholder="All categories" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All categories ({total})</SelectItem>
              {summary.map((s) => (
                <SelectItem key={s.category} value={s.category}>{s.label} ({s.count})</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as StatusFilter)}>
            <SelectTrigger className="w-[160px]" data-testid="select-source-status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="enabled">Enabled only</SelectItem>
              <SelectItem value="disabled">Disabled only</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* v2.29 — Bulk-action toolbar. Visible only when at least one row is selected. */}
        {isAdmin && selected.size > 0 && (
          <div className="mt-3 flex items-center gap-2 rounded border bg-primary/5 px-3 py-2 text-xs" data-testid="toolbar-bulk">
            <span className="font-medium">{selected.size} selected</span>
            <span className="text-muted-foreground">— apply to all</span>
            <div className="flex-1" />
            <Button
              size="sm" variant="outline" className="gap-1.5 h-7"
              disabled={bulk.isPending}
              onClick={() => bulk.mutate({ ids: [...selected], action: "enable" })}
              data-testid="button-bulk-enable"
            >
              <Power className="w-3.5 h-3.5 text-emerald-600" /> Enable selected
            </Button>
            <Button
              size="sm" variant="outline" className="gap-1.5 h-7"
              disabled={bulk.isPending}
              onClick={() => bulk.mutate({ ids: [...selected], action: "disable" })}
              data-testid="button-bulk-disable"
            >
              <PowerOff className="w-3.5 h-3.5 text-amber-600" /> Disable selected
            </Button>
            <Button
              size="sm" variant="outline" className="gap-1.5 h-7 text-rose-600 hover:text-rose-700"
              disabled={bulk.isPending}
              onClick={() => {
                if (window.confirm(`Permanently delete ${selected.size} source(s)? This cannot be undone.`)) {
                  bulk.mutate({ ids: [...selected], action: "delete" });
                }
              }}
              data-testid="button-bulk-delete"
            >
              <Trash2 className="w-3.5 h-3.5" /> Delete selected
            </Button>
            <Button
              size="sm" variant="ghost" className="h-7 text-xs"
              onClick={() => setSelected(new Set())}
              data-testid="button-bulk-clear"
            >
              Clear
            </Button>
          </div>
        )}
      </Card>

      {isLoading ? (
        <Card className="p-12 text-center text-sm text-muted-foreground">Loading sources…</Card>
      ) : visibleSources.length === 0 ? (
        <Card className="p-12 text-center text-sm text-muted-foreground">No sources match your filters.</Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 text-[11px] uppercase tracking-wide text-muted-foreground sticky top-0">
                <tr>
                  {isAdmin && (
                    <th className="text-left px-3 py-2 w-8">
                      <Checkbox
                        checked={allVisibleSelected ? true : someVisibleSelected ? "indeterminate" : false}
                        onCheckedChange={toggleAllVisible}
                        aria-label="Select all visible sources"
                        data-testid="checkbox-source-select-all"
                      />
                    </th>
                  )}
                  <th className="text-left px-4 py-2 font-medium cursor-pointer select-none" onClick={() => clickSort("name")} data-testid="th-source-name">
                    Name (English)<SortIcon k="name" />
                  </th>
                  <th className="text-left px-4 py-2 font-medium cursor-pointer select-none" onClick={() => clickSort("category")} data-testid="th-source-category">
                    Category<SortIcon k="category" />
                  </th>
                  <th className="text-left px-4 py-2 font-medium cursor-pointer select-none" onClick={() => clickSort("status")} data-testid="th-source-status">
                    Status<SortIcon k="status" />
                  </th>
                  <th className="text-left px-4 py-2 font-medium">Type</th>
                  <th className="text-left px-4 py-2 font-medium">URL</th>
                  <th className="text-left px-4 py-2 font-medium cursor-pointer select-none" onClick={() => clickSort("lastFetched")} data-testid="th-source-last">
                    Last fetched<SortIcon k="lastFetched" />
                  </th>
                  <th className="text-right px-4 py-2 font-medium cursor-pointer select-none" onClick={() => clickSort("findings")} data-testid="th-source-findings">
                    Parsed<SortIcon k="findings" />
                  </th>
                </tr>
              </thead>
              <tbody>
                {visibleSources.slice(0, 1000).map((s) => (
                  <tr key={s.id} className="border-t" data-testid={`row-source-${s.id}`}>
                    {isAdmin && (
                      <td className="px-3 py-1.5">
                        <Checkbox
                          checked={selected.has(s.id)}
                          onCheckedChange={() => toggleOne(s.id)}
                          aria-label={`Select ${s.englishName}`}
                          data-testid={`checkbox-source-${s.id}`}
                        />
                      </td>
                    )}
                    <td className="px-4 py-1.5 text-xs font-medium max-w-[280px]">
                      <div className="truncate" data-testid={`text-source-english-${s.id}`} title={s.englishName}>{s.englishName}</div>
                      {s.englishName !== s.name && (
                        <div className="text-[10px] text-muted-foreground truncate" title={s.name}>{s.name}</div>
                      )}
                    </td>
                    <td className="px-4 py-1.5 text-xs text-muted-foreground">{s.categoryLabel}</td>
                    <td className="px-4 py-1.5" data-testid={`text-source-status-${s.id}`}>
                      {s.enabled ? (
                        <Badge variant="outline" className="text-[10px] gap-1 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30">
                          <Power className="w-3 h-3" /> Enabled
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-[10px] gap-1 bg-muted text-muted-foreground border-border">
                          <PowerOff className="w-3 h-3" /> Disabled
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-1.5 text-[10px] font-mono text-muted-foreground">{s.kind}</td>
                    <td className="px-4 py-1.5 text-xs">
                      <a href={s.url || "#"} target="_blank" rel="noreferrer" className="font-mono text-[11px] text-primary hover:underline truncate inline-block max-w-[320px]">
                        {s.url}
                      </a>
                    </td>
                    <td className="px-4 py-1.5 text-[11px] text-muted-foreground whitespace-nowrap" title={s.lastFetchedAt || ""}>
                      {s.lastFetchedAt ? relativeTime(s.lastFetchedAt) : "—"}
                    </td>
                    <td className="px-4 py-1.5 text-right">
                      <Badge variant={s.findingCount > 0 ? "secondary" : "outline"} className="font-mono text-[10px]" data-testid={`badge-source-count-${s.id}`}>
                        {s.findingCount} parsed
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {visibleSources.length > 1000 && (
              <div className="px-4 py-2 text-[11px] text-muted-foreground border-t bg-muted/20">
                Showing first 1000 of {visibleSources.length}.
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

// ---- AI Overview panel (REMOVED in v2.17) --------------------------------
//
// The persona-based "AI overview — Analyst briefing" card has been retired in
// favour of the Triage + Deep-dive panel (`OsintTriagePanel`) rendered above
// the findings list. The free-form chat lives in `OsintChatbot` (floating).
//
// The legacy /api/v1/osint/overview and /api/v1/global/osint/overview routes
// remain on the backend for now to avoid breaking any cron / external caller.
//
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _LegacyAiOverviewPanel_DO_NOT_USE({
  isGlobal, dimension, scopeIds, severity, sourceId, category, categoryLabels, personas,
}: {
  isGlobal: boolean;
  dimension: ScopeDimension;
  scopeIds: string[];
  severity?: string;
  sourceId?: string;
  category?: string;
  categoryLabels: Record<string, string>;
  personas: { id: string; label: string; blurb: string }[];
}) {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const [persona, setPersona] = useState<string>("ir");
  const [overviewCategory, setOverviewCategory] = useState<string>(category || "_all");
  const [result, setResult] = useState<OsintOverviewResultDTO | null>(null);

  // If the user has chosen a category filter on Findings, prefer that as starting point.
  // Otherwise let the analyst pick a category from the overview's own dropdown.
  const effectiveCategory = (overviewCategory && overviewCategory !== "_all") ? overviewCategory : undefined;

  const generate = useMutation({
    mutationFn: async () => {
      const path = isGlobal ? "/api/v1/global/osint/overview" : "/api/v1/osint/overview";
      const body: any = {
        persona,
        severity: severity && severity !== "_all" ? severity : undefined,
        category: effectiveCategory,
        scope: isGlobal ? "global" : "client",
        scopeIds: isGlobal && scopeIds.length ? scopeIds : undefined,
      };
      const r = await apiRequest("POST", path, body);
      return r.json() as Promise<OsintOverviewResultDTO>;
    },
    onSuccess: (r) => {
      setResult(r);
      toast({ title: "AI overview ready", description: `${r.personaLabel} · ${r.scopeLabel} · ${r.findingCount} findings` });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Overview failed", description: String(e.message ?? e) }),
  });

  const personaMeta = personas.find((p) => p.id === persona) || personas[0];

  return (
    <Card className="p-4 border-primary/30 bg-gradient-to-br from-primary/5 via-background to-background" data-testid="card-ai-overview">
      <div className="flex items-center gap-2 mb-2">
        <Brain size={14} className="text-primary" />
        <div className="text-sm font-medium">AI overview — Analyst briefing</div>
        {sourceId && sourceId !== "_all" && (
          <Badge variant="outline" className="text-[10px]">filtered by source</Badge>
        )}
      </div>
      <div className="text-xs text-muted-foreground mb-3">
        Persona-tuned narrative across the currently scoped findings — not per-row analysis. Pick a lens and category, then generate.
      </div>
      <div className="flex flex-wrap gap-2 items-center mb-3">
        <Select value={persona} onValueChange={setPersona}>
          <SelectTrigger className="w-[220px]" data-testid="select-overview-persona">
            <SelectValue placeholder="Persona" />
          </SelectTrigger>
          <SelectContent>
            {personas.map((p) => (
              <SelectItem key={p.id} value={p.id}>{p.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={overviewCategory} onValueChange={setOverviewCategory}>
          <SelectTrigger className="w-[260px]" data-testid="select-overview-category">
            <SelectValue placeholder="Source category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All categories</SelectItem>
            {Object.entries(categoryLabels).map(([code, label]) => (
              <SelectItem key={code} value={code}>{label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          onClick={() => generate.mutate()}
          disabled={generate.isPending || aiDisabled}
          title={aiAvailability.disabledReason}
          data-testid="button-generate-overview"
        >
          {generate.isPending
            ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Generating</>
            : <><Sparkles size={14} className="mr-1.5" />Generate overview</>}
        </Button>
      </div>
      <div className="text-[11px] text-muted-foreground italic mb-3">{personaMeta?.blurb}</div>
      {result && (
        <div className="space-y-3 mt-2 border-t pt-3">
          <div className="flex flex-wrap items-center gap-2 text-[10px]">
            <Badge variant="default" className="bg-primary/15 text-primary border-primary/30 border">{result.personaLabel}</Badge>
            <Badge variant="outline">{result.scopeLabel}</Badge>
            <Badge variant="secondary" className="font-mono">{result.findingCount} findings</Badge>
            {result.category && <Badge variant="outline">{categoryLabels[result.category] || result.category}</Badge>}
            {result.severityFilter && <Badge variant="outline">severity: {result.severityFilter}</Badge>}
            {result.providerLabel && <span className="ml-auto text-muted-foreground">{result.providerLabel}</span>}
          </div>
          <div className="text-sm leading-relaxed whitespace-pre-wrap" data-testid="text-overview-summary">
            {result.summary || "(no summary)"}
          </div>
          {result.keyTakeaways?.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Key takeaways</div>
              <ul className="text-xs list-disc pl-5 space-y-1" data-testid="list-overview-takeaways">
                {result.keyTakeaways.map((t, i) => <li key={i}>{t}</li>)}
              </ul>
            </div>
          )}
          {result.recommendations?.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Recommendations</div>
              <ul className="text-xs list-disc pl-5 space-y-1" data-testid="list-overview-recommendations">
                {result.recommendations.map((t, i) => <li key={i}>{t}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

// ---- Findings tab ----------------------------------------------------------
function FindingsTab({ isGlobal, dimension, selectedIds: scopeIds, onDimensionChange, onSelectedIdsChange }: FindingsTabProps) {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const [severity, setSeverity] = useState<string>("_all");
  const [status, setStatus] = useState<string>("_all");
  const [tech, setTech] = useState<string>("");
  const [sourceId, setSourceId] = useState<string>("_all");
  const [category, setCategory] = useState<string>("_all");
  // v2.9 — free-text keyword filter (client-side, matches across title / summary /
  // url / source name / CVEs / threat actors / affected tech / IoCs).
  const [keyword, setKeyword] = useState<string>("");
  // v2.15 — day-range filter (also drives chatbot triage scope).
  const [range, setRange] = useState<RangeKey>("7d");
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [huntOpen, setHuntOpen] = useState(false);
  const [stixOpen, setStixOpen] = useState(false);
  const [detailId, setDetailId] = useState<string | null>(null);

  useEffect(() => {
    const syncDeepLink = () => {
      const raw = window.location.hash || "";
      const qix = raw.indexOf("?");
      if (qix < 0) return;
      const qs = new URLSearchParams(raw.slice(qix + 1));
      const techParam = qs.get("tech");
      const findingParam = qs.get("finding");
      if (techParam) setTech(techParam.trim().toUpperCase());
      if (findingParam) setDetailId(findingParam);
    };
    syncDeepLink();
    window.addEventListener("hashchange", syncDeepLink);
    return () => window.removeEventListener("hashchange", syncDeepLink);
  }, []);

  function clearTechniqueScope() {
    setTech("");
    const raw = window.location.hash || "#/osint";
    const [path, query = ""] = raw.split("?");
    const qs = new URLSearchParams(query);
    qs.delete("tech");
    const next = qs.toString();
    window.location.hash = next ? `${path}?${next}` : path;
  }

  const { data: tax } = useQuery<TaxonomiesResp>({ queryKey: ["/api/v1/taxonomies"] });
  const personas = tax?.osintOverviewPersonas || [
    { id: "ir", label: "Incident Response", blurb: "" },
    { id: "ti", label: "Threat Intelligence", blurb: "" },
    { id: "secops", label: "Security Operations", blurb: "" },
  ];
  const categoryLabels = tax?.osintCategoryLabels || {};

  const scopeKey = scopeIds.join(",");

  // Fetch the source list for the Source filter dropdown.
  const { data: sourcesData } = useQuery<SourcesResp>({
    queryKey: isGlobal
      ? ["/api/v1/global/osint/sources", dimension, scopeKey, "filter"]
      : ["/api/v1/osint/sources", "filter"],
    queryFn: async () => {
      const path = isGlobal ? "/api/v1/global/osint/sources" : "/api/v1/osint/sources";
      const u = new URL(path, window.location.origin);
      if (isGlobal) {
        u.searchParams.set("dimension", dimension);
        if (scopeIds.length) u.searchParams.set("ids", scopeIds.join(","));
      }
      const r = await apiRequest("GET", u.pathname + u.search);
      return r.json();
    },
  });
  // v2.10 — sources listed alphabetically (by English name) so analysts can scan
  // the dropdown visually. When a category bucket is selected, restrict the
  // dropdown to sources in that bucket so source-filter scope matches the
  // active category filter.
  const sourceOptions = useMemo(() => {
    const all = sourcesData?.sources || [];
    const filtered = (category && category !== "_all")
      ? all.filter((s) => s.category === category)
      : all;
    return filtered
      .filter((s) => s.findingCount > 0)
      .sort((a, b) => (a.englishName || "").localeCompare(b.englishName || "", undefined, { sensitivity: "base" }))
      .slice(0, 500);
  }, [sourcesData, category]);

  // v2.12 — in Global view, collapse same intel across tenants into one row tagged with every client.
  const [dedup, setDedup] = useState(true);
  const { data, isLoading } = useQuery<TenantFindingsResp | GlobalFindingsResp>({
    queryKey: isGlobal
      ? ["/api/v1/global/osint/findings", dimension, scopeKey, severity, status, tech, sourceId, category, dedup]
      : ["/api/v1/osint/findings", severity, status, tech, sourceId, category],
    queryFn: async () => {
      const path = isGlobal ? "/api/v1/global/osint/findings" : "/api/v1/osint/findings";
      const u = new URL(path, window.location.origin);
      if (severity && severity !== "_all") u.searchParams.set("severity", severity);
      if (status && status !== "_all") u.searchParams.set("status", status);
      if (tech) u.searchParams.set("tech", tech);
      if (sourceId && sourceId !== "_all") u.searchParams.set("sourceId", sourceId);
      if (category && category !== "_all") u.searchParams.set("category", category);
      if (isGlobal) {
        u.searchParams.set("dimension", dimension);
        if (scopeIds.length) u.searchParams.set("ids", scopeIds.join(","));
        if (dedup) u.searchParams.set("dedup", "1");
      }
      const r = await apiRequest("GET", u.pathname + u.search);
      return r.json();
    },
    placeholderData: () => {
      if (isGlobal) return undefined;
      const cached = queryClient.getQueryData<TenantFindingsResp>(["/api/v1/osint/findings"]);
      if (!cached?.findings) return undefined;
      const filtered = cached.findings.filter((f) => {
        if (severity !== "_all" && f.severity !== severity) return false;
        if (status !== "_all" && f.status !== status) return false;
        if (tech) {
          const t = tech.toUpperCase();
          const ids = (f.attackTechniques || []).map((x) => x.id.toUpperCase());
          if (!ids.includes(t)) return false;
        }
        if (sourceId !== "_all" && f.sourceId !== sourceId) return false;
        if (category !== "_all" && f.sourceCategory !== category) return false;
        return true;
      });
      return { findings: filtered };
    },
  });
  const rawFindings = (data?.findings as Array<OsintFindingDTO & Partial<{ tenantName: string; tenantSlug: string }>>) || [];
  // v2.15 — day-range filter: keep findings whose publishedAt/createdAt is within
  // the selected window. "All" returns everything.
  const allFindings = useMemo(() => {
    const hours = RANGE_HOURS[range];
    if (!hours) return rawFindings;
    const cutoff = Date.now() - hours * 3_600_000;
    return rawFindings.filter((f) => {
      const ts = Date.parse((f.publishedAt as any) || (f.createdAt as any) || "");
      if (!isFinite(ts)) return true; // keep undated items rather than silently drop them
      return ts >= cutoff;
    });
  }, [rawFindings, range]);
  // v2.9 — keyword filter: matches any token (whitespace-split) against any
  // searchable string in the finding. All tokens must match (AND).
  const findings = useMemo(() => {
    const q = keyword.trim().toLowerCase();
    if (!q) return allFindings;
    const tokens = q.split(/\s+/).filter(Boolean);
    return allFindings.filter((f) => {
      const iocFields = f.iocs ? Object.values(f.iocs).flat() : [];
      const haystack = [
        f.title, f.summary, f.url, f.sourceName, f.sourceCategory,
        f.aiSummary, f.aiRecommendation, f.severity, f.status,
        // v2.18 — search the full raw body and analyst tags. The "gentleman"
        // miss was because rawSnippet (full ingested body) wasn't in the
        // haystack — so any keyword that lives only in the article body
        // never matched.
        f.rawSnippet,
        ...(f.cveIds || []),
        ...(f.affectedTech || []),
        ...(f.threatActors || []),
        ...(f.analystTags || []),
        ...iocFields,
        (f as any).tenantName,
      ].filter(Boolean).join(" \u241F ").toLowerCase();
      return tokens.every((t) => haystack.includes(t));
    });
  }, [allFindings, keyword]);
  const selectedIds = Object.entries(selected).filter(([, v]) => v).map(([k]) => k);
  const selectedQuery = selectedIds.join(",");

  const stixPreview = useQuery<StixPreviewResp>({
    queryKey: ["/api/v1/exchange/stix/preview", selectedQuery],
    enabled: stixOpen && selectedIds.length > 0 && !isGlobal,
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/v1/exchange/stix/preview?findingIds=${encodeURIComponent(selectedQuery)}`);
      return r.json();
    },
  });

  const scan = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", "/api/v1/osint/scan", { maxFindings: 60, mode: "auto" });
      return r.json();
    },
    onSuccess: (r: any) => {
      const count = r?.count ?? r?.added ?? 0;
      const mode = r?.mode ?? "unknown";
      const feedsOk = r?.feedsOk;
      const feedsTried = r?.feedsTried;
      let desc = `${count} findings ingested across the watchlist.`;
      if (mode === "real" && feedsOk != null && feedsTried != null) {
        desc += ` Live feeds: ${feedsOk}/${feedsTried} healthy.`;
      } else if (mode === "mock") {
        desc += ` Live feeds unreachable — using cached templates.`;
      }
      toast({ title: `OSINT scan complete (${mode})`, description: desc });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/findings"] });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Scan failed", description: String(e.message ?? e) }),
  });

  // v2.30.1.1 — bulk AI analyse no longer blocks the HTTP request. When the
  // backend decides the workload exceeds the proxy timeout (no selection or
  // many ids) it returns 202 with a jobId. We poll the existing reanalyze-job
  // status endpoint and keep the toast live until the job is done/failed.
  const analyze = useMutation({
    mutationFn: async () => {
      return startBackgroundJob("/api/v1/osint/findings/ai-analyze", {
        ids: selectedIds.length ? selectedIds : undefined,
        onlyUnanalyzed: !selectedIds.length,
      });
    },
    onSuccess: (r: any) => {
      toast({ title: "AI analysis queued", description: r.targetLabel ?? "The background jobs tray will show progress and completion." });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Analyze failed", description: String(e.message ?? e) }),
  });

  const draft = useMutation({
    mutationFn: async () => {
      return startBackgroundJob("/api/v1/osint/findings/email-draft", { ids: selectedIds });
    },
    onSuccess: (r: any) => {
      toast({ title: "Draft email job queued", description: r.targetLabel ?? "The Drafts tab will refresh when the job completes." });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Draft failed", description: String(e.message ?? e) }),
  });

  function toggle(id: string) { setSelected((s) => ({ ...s, [id]: !s[id] })); }
  function selectAllVisible() {
    const next: Record<string, boolean> = {};
    for (const f of findings) next[f.id] = true;
    setSelected(next);
  }
  function clearSelection() { setSelected({}); }
  function exportSelectedStix() {
    if (!selectedIds.length) return;
    window.location.href = `/api/v1/exchange/stix/export?findingIds=${encodeURIComponent(selectedIds.join(","))}`;
  }

  const techScopeBanner = tech ? (
    <div
      className="sticky top-16 z-10 flex flex-col gap-2 rounded-lg border border-primary/20 bg-background/95 px-3 py-2 text-xs shadow-sm backdrop-blur sm:flex-row sm:items-center sm:justify-between"
      data-testid="chip-osint-attack-scope"
    >
      <div className="flex flex-wrap items-center gap-2 min-w-0">
        <Badge variant="default" className="bg-primary text-primary-foreground border-primary">
          ATT&amp;CK: {tech}
        </Badge>
        <span className="text-muted-foreground">
          Scoped from Coverage Radar; {findings.length} observed finding{findings.length === 1 ? "" : "s"} in the active range.
        </span>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {findings.length > 0 && (
          <Button
            size="sm"
            variant="secondary"
            className="h-7 px-2 text-[11px]"
            onClick={() => { window.location.hash = `#/detection-rules?technique=${encodeURIComponent(tech)}`; }}
            data-testid="button-osint-tech-detection-pivot"
          >
            <ShieldCheck size={12} className="mr-1" />
            Generate detection draft
          </Button>
        )}
        <Button
          size="sm"
          variant="ghost"
          className="h-7 px-2 text-[11px]"
          onClick={clearTechniqueScope}
          data-testid="button-clear-attack-scope"
        >
          <XIcon size={12} className="mr-1" />
          Remove scope
        </Button>
      </div>
    </div>
  ) : null;

  return (
    <div className="space-y-4">
      {isGlobal && (
        <ScopeBar
          dimension={dimension}
          selectedIds={scopeIds}
          onDimensionChange={onDimensionChange}
          onSelectedIdsChange={onSelectedIdsChange}
        />
      )}
      {techScopeBanner}
      {/* v2.17 — Triage + Deep-dive panel replaces the old AiOverviewPanel.
          The free-form chat moved into the floating widget at the bottom-right. */}
      <OsintTriagePanel
        range={range}
        findings={findings as any}
        isGlobal={isGlobal}
      />
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger className="w-[150px]" data-testid="select-severity"><SelectValue placeholder="Severity" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All severities</SelectItem>
              {["critical","high","medium","low","info"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger className="w-[150px]" data-testid="select-status"><SelectValue placeholder="Status" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All statuses</SelectItem>
              {["new","reviewed","relevant","not_relevant","escalated"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={category} onValueChange={setCategory}>
            <SelectTrigger className="w-[200px]" data-testid="select-category-filter"><SelectValue placeholder="Category" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All categories</SelectItem>
              {Object.entries(categoryLabels).map(([code, label]) => (
                <SelectItem key={code} value={code}>{label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={sourceId} onValueChange={setSourceId}>
            <SelectTrigger className="w-[220px]" data-testid="select-source-filter"><SelectValue placeholder="Source" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All sources</SelectItem>
              {sourceOptions.map((s) => (
                <SelectItem key={s.id} value={s.id}>{s.englishName} ({s.findingCount})</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {/* v2.9 — free-text keyword search across all finding fields.
              v2.17 — separate tech-id input removed; the keyword box already
              matches against affectedTech so the dedicated input was redundant. */}
          <div className="relative">
            <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
            <Input
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              placeholder="Search title, IoC, CVE, actor…"
              className="w-[260px] pl-7 text-xs"
              data-testid="input-keyword-search"
            />
            {keyword && (
              <button
                onClick={() => setKeyword("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground text-xs"
                data-testid="button-clear-keyword"
                aria-label="Clear search"
              >✕</button>
            )}
          </div>
          {/* v2.15 — day-range segmented control. Filters the list AND drives the chatbot triage scope. */}
          <div className="inline-flex rounded-md border bg-muted/30 p-0.5" data-testid="segmented-range">
            {(Object.keys(RANGE_BUTTON_LABEL) as RangeKey[]).map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => setRange(k)}
                className={`text-[11px] font-medium px-2 py-1 rounded transition-colors ${
                  range === k
                    ? "bg-primary text-primary-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/60"
                }`}
                data-testid={`button-range-${k}`}
                title={`Show findings from ${k === "all" ? "all time" : "the last " + k}`}
              >
                {RANGE_BUTTON_LABEL[k]}
              </button>
            ))}
          </div>
          {/* v2.12 — Global view only: collapse same intel across tenants into one row tagged with every client. */}
          {isGlobal && (
            <button
              type="button"
              onClick={() => setDedup((d) => !d)}
              className={`text-[11px] px-2 py-1 rounded border transition-colors ${dedup ? "bg-primary text-primary-foreground border-primary" : "bg-muted/40 hover:bg-muted text-muted-foreground border-border"}`}
              data-testid="button-toggle-dedup"
              title="When ON, same intel shared across N clients shows up as a single row with every client tagged."
            >
              {dedup ? "✓ Dedupe across clients" : "Dedupe across clients"}
            </button>
          )}
          <div className="flex-1" />
          <Button onClick={() => scan.mutate()} disabled={scan.isPending || isGlobal} variant="outline" data-testid="button-osint-scan" title={isGlobal ? "Switch to a single client to run a scan" : ""}>
            {scan.isPending ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Scanning</> : <><Search size={14} className="mr-1.5" />Scan now</>}
          </Button>
          <Button onClick={() => analyze.mutate()} disabled={analyze.isPending || aiDisabled} title={aiAvailability.disabledReason} data-testid="button-osint-analyze">
            {analyze.isPending ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Analysing</> : <><Sparkles size={14} className="mr-1.5" />AI analyse</>}
          </Button>
          <Button
            onClick={() => draft.mutate()}
            disabled={draft.isPending || aiDisabled || !selectedIds.length}
            title={aiAvailability.disabledReason}
            data-testid="button-osint-draft-email"
            variant="secondary"
          >
            {draft.isPending ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Drafting</> : <><Mail size={14} className="mr-1.5" />Draft email ({selectedIds.length})</>}
          </Button>
          <Dialog open={huntOpen} onOpenChange={setHuntOpen}>
            <DialogTrigger asChild>
              <Button
                variant="default"
                disabled={aiDisabled || !selectedIds.length}
                title={aiAvailability.disabledReason}
                data-testid="button-open-hunt-dialog"
              >
                <Code2 size={14} className="mr-1.5" /> Hunt query ({selectedIds.length})
              </Button>
            </DialogTrigger>
            <HuntQueryDialog
              findingIds={selectedIds}
              languages={tax?.huntLanguages || []}
              onClose={() => setHuntOpen(false)}
              onCreated={() => { setHuntOpen(false); clearSelection(); }}
            />
          </Dialog>
          {/* v2.30.2 — Hand selected intel off to Detection Rule Studio. */}
          <Button
            variant="secondary"
            disabled={aiDisabled || !selectedIds.length}
            data-testid="button-create-detection-rule"
            title={aiAvailability.disabledReason ?? "Open Detection Rule Studio with the selected findings to draft a versioned detection rule."}
            onClick={() => {
              const q = encodeURIComponent(selectedIds.join(","));
              window.location.hash = `#/detection-rules?newFrom=${q}`;
            }}
          >
            <ShieldCheck size={14} className="mr-1.5" /> Detection rule ({selectedIds.length})
          </Button>
          <Button
            variant="outline"
            disabled={isGlobal || !selectedIds.length}
            data-testid="button-preview-stix"
            title={isGlobal ? "Switch to a single client to export STIX." : "Preview STIX object counts and validation before export."}
            onClick={() => setStixOpen(true)}
          >
            <FileJson size={14} className="mr-1.5" /> STIX preview ({selectedIds.length})
          </Button>
        </div>
        {findings.length > 0 && (
          <div className="flex items-center gap-3 mt-3 text-xs text-muted-foreground">
            <button className="underline" onClick={selectAllVisible} data-testid="link-select-all">Select all visible</button>
            <button className="underline" onClick={clearSelection} data-testid="link-clear-selection">Clear</button>
            <span className="font-mono">{selectedIds.length} selected · {findings.length} shown</span>
          </div>
        )}
      </Card>

      <Dialog open={stixOpen} onOpenChange={setStixOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>STIX export preview</DialogTitle>
            <DialogDescription>
              Validate object counts and quality warnings before exporting selected OSINT findings.
            </DialogDescription>
          </DialogHeader>
          {stixPreview.isLoading ? (
            <div className="py-8 text-sm text-muted-foreground flex items-center gap-2">
              <Loader2 size={16} className="animate-spin" /> Building preview…
            </div>
          ) : stixPreview.data ? (
            <div className="space-y-4 text-sm">
              <div className="grid grid-cols-2 gap-2">
                <PreviewMetric label="Findings" value={stixPreview.data.findingCount} />
                <PreviewMetric label="Objects" value={stixPreview.data.objectCount} />
                <PreviewMetric label="Indicators" value={stixPreview.data.indicatorCount} />
                <PreviewMetric label="ATT&CK patterns" value={stixPreview.data.attackPatternCount} />
              </div>
              <div className="rounded-md border p-3">
                <div className="text-xs font-medium mb-2">Object types</div>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(stixPreview.data.objectCounts).map(([k, v]) => (
                    <Badge key={k} variant="outline" className="font-mono text-[10px]">{k}: {v}</Badge>
                  ))}
                </div>
              </div>
              {stixPreview.data.errors.length > 0 && (
                <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs">
                  <div className="font-medium text-destructive mb-1">Validation errors</div>
                  {stixPreview.data.errors.map((e) => <div key={e}>{e}</div>)}
                </div>
              )}
              {stixPreview.data.warnings.length > 0 && (
                <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs">
                  <div className="font-medium mb-1">Warnings</div>
                  {stixPreview.data.warnings.map((w) => <div key={w}>{w}</div>)}
                </div>
              )}
            </div>
          ) : (
            <div className="py-8 text-sm text-muted-foreground">Select findings to preview a STIX export.</div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setStixOpen(false)}>Cancel</Button>
            <Button onClick={exportSelectedStix} disabled={!selectedIds.length || stixPreview.data?.valid === false}>
              <Download size={14} className="mr-1.5" /> Export STIX
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {isLoading ? (
        <Card className="p-12 text-center text-sm text-muted-foreground">Loading findings…</Card>
      ) : findings.length === 0 ? (
        <Card className="p-12 text-center">
          <Radar className="mx-auto mb-3 text-muted-foreground" size={28} />
          <div className="text-sm font-medium">No findings yet</div>
          <div className="text-xs text-muted-foreground mt-1">Run an OSINT scan to ingest the latest threat intel.</div>
        </Card>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => (
            <Card
              key={f.id}
              className="p-3 flex items-start gap-3 hover-elevate cursor-pointer"
              data-testid={`card-finding-${f.id}`}
              onClick={() => setDetailId(f.id)}
            >
              <div onClick={(e) => e.stopPropagation()}>
                <Checkbox
                  checked={!!selected[f.id]}
                  onCheckedChange={() => toggle(f.id)}
                  className="mt-1"
                  data-testid={`checkbox-finding-${f.id}`}
                />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <Badge className={`text-[10px] uppercase border ${severityColor(f.severity)}`}>{f.severity}</Badge>
                  <IntelCategoryChip
                    category={f.intelCategory ?? null}
                    testId={`badge-intel-category-${f.id}`}
                  />
                  {isGlobal && (f as any).tenantTags && (f as any).tenantTags.length > 0 ? (
                    <>
                      {/* Case-fold + slug-dedupe tenants so 'Perplexity' and 'perplexity' merge to one chip. */}
                      {(() => {
                        const raw = (f as any).tenantTags as Array<{ id: string; name: string; slug: string }>;
                        const seen = new Set<string>();
                        const deduped: Array<{ id: string; name: string; slug: string }> = [];
                        for (const t of raw) {
                          const k = (t.slug || t.name || "").trim().toLowerCase();
                          if (k && !seen.has(k)) { seen.add(k); deduped.push(t); }
                        }
                        const visible = deduped.slice(0, 3);
                        const overflow = deduped.length - visible.length;
                        return <>
                          {visible.map((tag) => (
                            <Badge
                              key={tag.slug}
                              variant="default"
                              className="text-[10px] bg-primary/15 text-primary border-primary/30 border whitespace-nowrap"
                              data-testid={`badge-tenant-tag-${f.id}-${tag.slug}`}
                            >
                              {tag.name}
                            </Badge>
                          ))}
                          {overflow > 0 && (
                            <Badge variant="outline" className="text-[10px] whitespace-nowrap" title={deduped.slice(3).map(t => t.name).join(", ")}>
                              +{overflow} tenant{overflow === 1 ? "" : "s"}
                            </Badge>
                          )}
                        </>;
                      })()}
                      {(f as any).duplicateCount > 1 && (
                        <Badge variant="secondary" className="text-[10px] font-mono" data-testid={`badge-dup-count-${f.id}`}>
                          ×{(f as any).duplicateCount}
                        </Badge>
                      )}
                    </>
                  ) : isGlobal && f.tenantName ? (
                    <Badge variant="default" className="text-[10px] bg-primary/15 text-primary border-primary/30 border" data-testid={`badge-tenant-${f.id}`}>
                      {f.tenantName}
                    </Badge>
                  ) : null}
                  <Badge variant="outline" className="text-[10px] whitespace-nowrap">{f.sourceCategory}</Badge>
                  <span className="text-[10px] font-mono text-muted-foreground truncate max-w-[200px]" title={f.sourceName}>{f.sourceName}</span>
                  <span className="text-[10px] text-muted-foreground/60">•</span>
                  <span className="text-[10px] text-muted-foreground whitespace-nowrap">{relativeTime(f.publishedAt)}</span>
                  {f.aiRelevanceScore != null && (
                    <Badge variant="secondary" className="text-[10px] font-mono" data-testid={`badge-relevance-${f.id}`}>
                      relevance {relevancePercent(f.aiRelevanceScore)}%
                    </Badge>
                  )}
                  {(() => {
                    const fresh = freshnessTier(f.publishedAt);
                    const conf = confidenceTier(f);
                    const count = iocCount(f.iocs);
                    return <>
                      <Badge variant="outline" className={`text-[10px] ${fresh.tone}`} data-testid={`badge-freshness-${f.id}`}>{fresh.label}</Badge>
                      <Badge variant="outline" className={`text-[10px] ${conf.tone}`} data-testid={`badge-confidence-${f.id}`}>{conf.label}</Badge>
                      {count > 0 && <Badge variant="outline" className="text-[10px] font-mono" data-testid={`badge-ioc-count-${f.id}`}>{count} IoCs</Badge>}
                      {f.attackTechniques?.length ? <Badge variant="outline" className="text-[10px] font-mono">{f.attackTechniques.length} ATT&CK</Badge> : null}
                    </>;
                  })()}
                </div>
                <div className="text-sm font-medium truncate" data-testid={`text-finding-title-${f.id}`}>{f.title}</div>
                {f.summary && <div className="text-xs text-muted-foreground mt-1 line-clamp-2">{f.summary}</div>}
                {f.aiSummary && (
                  <div className="text-xs mt-2 p-2 rounded border border-primary/20 bg-primary/5" data-testid={`text-ai-summary-${f.id}`}>
                    <div className="text-[10px] uppercase tracking-wide text-primary mb-0.5">AI summary {f.aiProviderLabel ? `· ${f.aiProviderLabel}` : ""}</div>
                    {f.aiSummary}
                  </div>
                )}
                <div className="flex flex-wrap items-center gap-1.5 mt-1.5 text-[10px] font-mono text-muted-foreground">
                  {f.cveIds.slice(0, 6).map((c) => (
                    <Badge key={c} variant="outline" className="text-[10px]" data-testid={`badge-cve-${c}`}>{c}</Badge>
                  ))}
                  {f.affectedTech.slice(0, 6).map((t) => (
                    <Badge key={t} variant="secondary" className="text-[10px]" data-testid={`badge-tech-${t}`}>{t}</Badge>
                  ))}
                  {f.url && (
                    <a
                      href={f.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-primary hover:underline ml-auto"
                      onClick={(e) => e.stopPropagation()}
                    >
                      source <ExternalLink size={10} />
                    </a>
                  )}
                </div>
                <div className="mt-1 text-[10px] text-muted-foreground" data-testid={`text-client-relevance-${f.id}`}>
                  Client relevance: {clientRelevanceReason(f)}
                </div>
                <div className="mt-2" onClick={(e) => e.stopPropagation()}>
                  <StartInvestigationButton
                    entityType="osint_finding"
                    entityId={f.id}
                    title={f.title}
                    severity={f.severity as any}
                    summary={f.aiSummary || f.summary || undefined}
                    size="sm"
                    variant="outline"
                    className="h-7 text-[11px]"
                  />
                </div>
              </div>
              <ChevronRight size={16} className="text-muted-foreground self-center shrink-0" aria-hidden="true" />
            </Card>
          ))}
        </div>
      )}

      <FindingDetailSheet
        findingId={detailId}
        onClose={() => setDetailId(null)}
      />

      {/* v2.17 — Floating AI chat (free-form) — available in tenant AND global view.
          Triage / Deep-dive moved to the inline panel above. */}
      <OsintChatbot range={range} findings={findings as any} />
    </div>
  );
}

function PreviewMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border bg-muted/20 p-3">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold tabular-nums">{value}</div>
    </div>
  );
}

// ---- v2.8 — IoC pretty-print for the right-side drawer --------------------
const IOC_GROUPS: Array<{ key: keyof NonNullable<OsintFindingDTO["iocs"]>; label: string }> = [
  { key: "ipv4",   label: "IPv4 addresses" },
  { key: "ipv6",   label: "IPv6 addresses" },
  { key: "domain", label: "Domains" },
  { key: "url",    label: "URLs" },
  { key: "sha256", label: "SHA-256 hashes" },
  { key: "sha1",   label: "SHA-1 hashes" },
  { key: "md5",    label: "MD5 hashes" },
  { key: "email",  label: "Emails" },
  { key: "btc",    label: "BTC addresses" },
];

function IocSection({ iocs }: { iocs?: OsintFindingDTO["iocs"] }) {
  const { toast } = useToast();
  if (!iocs) return null;
  const present = IOC_GROUPS.filter((g) => Array.isArray(iocs[g.key]) && (iocs[g.key]!.length > 0));
  if (present.length === 0) return null;
  const totalCount = present.reduce((acc, g) => acc + (iocs[g.key]?.length ?? 0), 0);
  return (
    <div data-testid="section-detail-iocs">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 flex items-center justify-between">
        <span>Indicators of compromise</span>
        <span className="font-mono">{totalCount}</span>
      </div>
      <div className="space-y-2">
        {present.map((g) => {
          const values = iocs[g.key] || [];
          return (
            <div key={g.key as string} className="rounded border bg-muted/20 p-2">
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 flex items-center justify-between">
                <span>{g.label}</span>
                <span className="font-mono">{values.length}</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {values.map((v) => (
                  <button
                    type="button"
                    key={v}
                    onClick={() => {
                      navigator.clipboard?.writeText(v).then(() => {
                        toast({ title: "Copied", description: v.length > 96 ? v.slice(0, 96) + "…" : v });
                      }).catch(() => {});
                    }}
                    className="font-mono text-[10px] px-1.5 py-0.5 rounded border bg-background hover:bg-primary/10 hover:border-primary/40 transition-colors max-w-full truncate"
                    title={v + " — click to copy"}
                    data-testid={`ioc-chip-${g.key as string}`}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---- Finding detail right-side drawer (v2.18 overhaul) -------------------
//
// Reordered for analyst workflow:
//   1. AI analysis (summary + recommendation)
//   2. Status / Published (metadata grid)
//   3. CVE references
//   4. Indicators of Compromise (IoC)
//   5. Affected technology + Threat actors + Analyst tags  ("tags" group)
//   6. Raw intel snippet, drafted email (when present)
//   7. Original source card (MOVED to bottom — v2.17 requirement)
//
// v2.18 — the global Edit / Save / Cancel toggle is replaced by *per-field*
// affordances: each chip has an inline `×` delete button, and each field
// header carries a pencil (when there is content) or a `+` (when empty)
// that opens an inline editor. Every action PATCHes only the field it owns
// via `/api/v1/osint/findings/:fid` — the server's analyst-edit audit
// columns capture the last write.

// Per-field label with an optional action icon (pencil / plus / delete-all).
function FieldLabel({
  label, onAction, actionIcon = "pencil", actionAriaLabel, testId, count,
}: {
  label: string;
  onAction: (() => void) | null;
  actionIcon?: "pencil" | "plus";
  actionAriaLabel?: string;
  testId?: string;
  count?: number;
}) {
  return (
    <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 flex items-center justify-between gap-2">
      <span className="flex items-center gap-1.5">
        {label}
        {count != null && <span className="font-mono normal-case">{count}</span>}
      </span>
      {onAction && (
        <button
          type="button"
          onClick={onAction}
          className="text-muted-foreground hover:text-primary inline-flex items-center justify-center h-5 w-5 rounded hover:bg-primary/10 transition-colors"
          aria-label={actionAriaLabel || (actionIcon === "plus" ? `Add ${label}` : `Edit ${label}`)}
          data-testid={testId}
        >
          {actionIcon === "plus" ? <Plus size={11} /> : <Pencil size={10} />}
        </button>
      )}
    </div>
  );
}

// v2.28 — dictionary types + shared loader hook used by the two typeahead
// chip editors (Affected technology + Threat actors). The lists are static
// reference data shipped with the build (see server/data/*.json), loaded
// once per session and cached by React Query.
type DictTechnology = { name: string; aliases: string[]; category: string; vendor?: string; notes?: string };
type DictThreatActor = { name: string; aliases: string[]; category: string; country?: string; active?: boolean; notes?: string };
type DictionariesResp = { technologies: DictTechnology[]; threatActors: DictThreatActor[] };

function useDictionaries() {
  return useQuery<DictionariesResp>({
    queryKey: ["/api/v1/osint/dictionaries"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/v1/osint/dictionaries");
      return r.json();
    },
    staleTime: 60 * 60 * 1000, // dictionaries are static — cache for an hour
  });
}

// Match a free-text input against a dictionary entry by name or any alias.
// Returns the canonical entry name if matched, otherwise the raw trimmed input.
function resolveAlias<T extends { name: string; aliases: string[] }>(input: string, dict: T[]): { canonical: string; matched: T | null } {
  const needle = input.trim().toLowerCase();
  if (!needle) return { canonical: "", matched: null };
  for (const entry of dict) {
    if (entry.name.toLowerCase() === needle) return { canonical: entry.name, matched: entry };
    for (const a of entry.aliases || []) {
      if (a.toLowerCase() === needle) return { canonical: entry.name, matched: entry };
    }
  }
  return { canonical: input.trim(), matched: null };
}

// Score dictionary entries against a search needle for the typeahead dropdown.
// Higher score = better match. 0 = no match.
function scoreEntry<T extends { name: string; aliases: string[] }>(entry: T, needle: string): number {
  if (!needle) return 1; // show all on empty
  const n = needle.toLowerCase();
  const nm = entry.name.toLowerCase();
  if (nm === n) return 100;
  if (nm.startsWith(n)) return 80;
  if (nm.includes(n)) return 60;
  for (const a of entry.aliases || []) {
    const al = a.toLowerCase();
    if (al === n) return 90;
    if (al.startsWith(n)) return 70;
    if (al.includes(n)) return 50;
  }
  return 0;
}

// Typeahead chip editor backed by a dictionary. Behaves like ChipFieldEditor
// but the inline editor is a search-input + dropdown of suggestions instead
// of a plain text field. When the user picks a suggestion it expands the
// alias to the canonical entry name. When the input doesn't match the
// dictionary, the user can press Enter (or click "Add custom") to commit
// the literal string — satisfying the v2.28 "allow custom-add" requirement.
function TypeaheadChipFieldEditor<T extends { name: string; aliases: string[] }>({
  label, values, onChange, dict, dictLoading, placeholder, emptyLabel,
  renderChip, testIdPrefix, listTestId, getMeta,
}: {
  label: string;
  values: string[];
  onChange: (next: string[]) => void;
  dict: T[];
  dictLoading: boolean;
  placeholder: string;
  emptyLabel: string;
  renderChip: (v: string, meta: T | null) => React.ReactNode;
  testIdPrefix: string;
  listTestId?: string;
  getMeta?: (v: string) => T | null;
}) {
  const [editing, setEditing] = useState(false);
  const [query, setQuery] = useState("");
  const start = () => { setQuery(""); setEditing(true); };
  const cancel = () => { setQuery(""); setEditing(false); };

  // Lookup metadata for a chip (when in view mode) by resolving alias → entry.
  const lookupMeta = (v: string): T | null => {
    if (getMeta) return getMeta(v);
    const { matched } = resolveAlias(v, dict);
    return matched;
  };

  // Ranked suggestions for the current query (cap at 10 for keyboard sanity).
  const suggestions = useMemo(() => {
    if (!dict || dict.length === 0) return [];
    const scored = dict
      .map((e) => ({ e, s: scoreEntry(e, query) }))
      .filter((x) => x.s > 0)
      .sort((a, b) => b.s - a.s || a.e.name.localeCompare(b.e.name))
      .slice(0, 10)
      .map((x) => x.e);
    // Exclude entries already chosen.
    const chosen = new Set(values.map((v) => v.toLowerCase()));
    return scored.filter((e) => !chosen.has(e.name.toLowerCase()));
  }, [dict, query, values]);

  const commitOne = (raw: string) => {
    const { canonical } = resolveAlias(raw, dict);
    if (!canonical) return;
    if (values.some((v) => v.toLowerCase() === canonical.toLowerCase())) {
      // already chosen — just close
      cancel();
      return;
    }
    onChange([...values, canonical]);
    setQuery("");
  };

  if (editing) {
    const exactMatch = suggestions.find((e) => e.name.toLowerCase() === query.trim().toLowerCase());
    const showCustomAdd = query.trim().length > 0 && !exactMatch;
    return (
      <div data-testid={`field-${testIdPrefix}-editing`}>
        <FieldLabel label={label} onAction={null} />
        <div className="relative">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            autoFocus
            className="text-xs"
            data-testid={`input-detail-${testIdPrefix}`}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                if (suggestions.length > 0 && !showCustomAdd) commitOne(suggestions[0].name);
                else if (query.trim()) commitOne(query);
              }
              if (e.key === "Escape") cancel();
            }}
          />
          {/* Dropdown */}
          <div className="mt-1 border rounded-md bg-popover shadow-sm max-h-[240px] overflow-y-auto" data-testid={`dropdown-${testIdPrefix}`}>
            {dictLoading && (
              <div className="flex items-center justify-center gap-2 py-3 text-[11px] text-muted-foreground">
                <Loader2 size={11} className="animate-spin" />
                <span>Loading dictionary…</span>
              </div>
            )}
            {!dictLoading && suggestions.length === 0 && !showCustomAdd && (
              <div className="py-3 text-center text-[11px] text-muted-foreground">No matches in dictionary.</div>
            )}
            {!dictLoading && suggestions.map((s) => (
              <button
                type="button"
                key={s.name}
                onMouseDown={(e) => { e.preventDefault(); commitOne(s.name); }}
                className="w-full text-left px-2.5 py-1.5 text-xs hover:bg-accent/60 border-b last:border-b-0"
                data-testid={`suggestion-${testIdPrefix}-${s.name.replace(/\s+/g, "-").toLowerCase()}`}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium">{s.name}</span>
                  <Badge variant="outline" className="text-[9px]">{s.category}</Badge>
                  {(s as any).vendor && <span className="text-[10px] text-muted-foreground">{(s as any).vendor}</span>}
                  {(s as any).country && <span className="text-[10px] text-muted-foreground">{(s as any).country}</span>}
                </div>
                {s.aliases && s.aliases.length > 0 && (
                  <div className="text-[10px] text-muted-foreground mt-0.5 truncate">aka {s.aliases.slice(0, 4).join(", ")}</div>
                )}
              </button>
            ))}
            {!dictLoading && showCustomAdd && (
              <button
                type="button"
                onMouseDown={(e) => { e.preventDefault(); commitOne(query); }}
                className="w-full text-left px-2.5 py-1.5 text-xs hover:bg-accent/60 bg-emerald-500/5 border-t border-emerald-500/30"
                data-testid={`suggestion-custom-${testIdPrefix}`}
              >
                <span className="text-emerald-700 dark:text-emerald-300 font-medium">+ Add custom: “{query.trim()}”</span>
                <div className="text-[10px] text-muted-foreground mt-0.5">Not in dictionary — will be saved as-is.</div>
              </button>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1.5 mt-1.5">
          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={cancel} data-testid={`button-cancel-${testIdPrefix}`}>
            <XIcon size={10} className="mr-1" /> Close
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div data-testid={`field-${testIdPrefix}`}>
      <FieldLabel
        label={label}
        onAction={start}
        actionIcon={values.length === 0 ? "plus" : "pencil"}
        actionAriaLabel={values.length === 0 ? `Add ${label}` : `Edit ${label}`}
        testId={`button-edit-${testIdPrefix}`}
      />
      {values.length > 0 ? (
        <div className="flex flex-wrap gap-1.5" data-testid={listTestId}>
          {values.map((v) => (
            <span key={v} className="inline-flex items-center gap-1 group">
              {renderChip(v, lookupMeta(v))}
              <button
                type="button"
                onClick={() => onChange(values.filter((x) => x !== v))}
                className="text-muted-foreground/60 hover:text-destructive text-[10px] opacity-0 group-hover:opacity-100 transition-opacity"
                aria-label={`Remove ${v}`}
                data-testid={`button-remove-${testIdPrefix}-${v.replace(/\s+/g, "-").toLowerCase()}`}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      ) : (
        <div className="text-[11px] text-muted-foreground italic">{emptyLabel}</div>
      )}
    </div>
  );
}

// Reusable chip-list editor. Renders chips with a per-chip `×` delete and
// either a pencil ("edit existing list") or `+` ("add first items") icon
// that swaps the view into an inline textarea. Save commits via `onChange`.
function ChipFieldEditor<T extends string>({
  label, values, placeholder, emptyLabel, onChange, renderChip,
  fontMono = false, testIdPrefix, listTestId,
}: {
  label: string;
  values: T[];
  placeholder: string;
  emptyLabel: string;
  onChange: (next: T[]) => void;
  renderChip: (v: T) => React.ReactNode;
  fontMono?: boolean;
  testIdPrefix: string;
  listTestId?: string;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const startEdit = () => { setDraft(values.join(", ")); setEditing(true); };
  const cancel = () => { setDraft(""); setEditing(false); };
  const save = () => {
    const next = splitCommas(draft) as T[];
    onChange(next);
    setEditing(false);
  };
  const removeOne = (v: T) => {
    onChange(values.filter((x) => x !== v));
  };

  if (editing) {
    return (
      <div data-testid={`field-${testIdPrefix}-editing`}>
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5">{label}</div>
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={placeholder}
          autoFocus
          className={`text-xs ${fontMono ? "font-mono" : ""}`}
          data-testid={`input-detail-${testIdPrefix}`}
          onKeyDown={(e) => { if (e.key === "Enter") save(); if (e.key === "Escape") cancel(); }}
        />
        <div className="flex items-center gap-1.5 mt-1.5">
          <Button size="sm" className="h-6 px-2 text-[10px]" onClick={save} data-testid={`button-save-${testIdPrefix}`}>
            <CheckIcon size={10} className="mr-1" /> Save
          </Button>
          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={cancel} data-testid={`button-cancel-${testIdPrefix}`}>
            <XIcon size={10} className="mr-1" /> Cancel
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div data-testid={`field-${testIdPrefix}`}>
      <FieldLabel
        label={label}
        onAction={startEdit}
        actionIcon={values.length === 0 ? "plus" : "pencil"}
        actionAriaLabel={values.length === 0 ? `Add ${label}` : `Edit ${label}`}
        testId={`button-edit-${testIdPrefix}`}
      />
      {values.length > 0 ? (
        // v2.22 — chips are read-only in view mode. The pencil icon is the
        // only edit affordance; clicking it swaps the panel into an inline
        // textarea where individual values can be deleted. This avoids the
        // sea of × buttons that made the detail panel feel unstable.
        <div className="flex flex-wrap gap-1.5" data-testid={listTestId}>
          {values.map((v) => (
            <span key={v} className="inline-flex items-center">
              {renderChip(v)}
            </span>
          ))}
        </div>
      ) : (
        <div className="text-[11px] text-muted-foreground italic">{emptyLabel}</div>
      )}
    </div>
  );
}

// IoC section with per-type inline editors. Each IoC group (ipv4, domain, etc.)
// renders independently with its own pencil/add icon + per-chip delete.
function IocSectionEditable({
  iocs, onChangeGroup, disabled,
}: {
  iocs?: OsintFindingDTO["iocs"];
  onChangeGroup: (key: keyof FindingIoCs, next: string[]) => void;
  disabled?: boolean;
}) {
  const { toast } = useToast();
  const safe = iocs || {};
  const totalCount = IOC_EDIT_GROUPS.reduce((acc, g) => acc + ((safe as any)[g.key]?.length || 0), 0);
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [draft, setDraft] = useState("");

  const startEdit = (key: string) => {
    const list = ((safe as any)[key] as string[] | undefined) || [];
    setDraft(list.join("\n"));
    setOpenKey(key);
  };
  const save = (key: keyof FindingIoCs) => {
    onChangeGroup(key, splitLines(draft));
    setOpenKey(null);
  };
  const removeOne = (key: keyof FindingIoCs, v: string) => {
    const list = ((safe as any)[key] as string[] | undefined) || [];
    onChangeGroup(key, list.filter((x) => x !== v));
  };

  // Show only groups that already have data OR are actively being edited.
  // All other (empty) groups collapse behind a single "Add IoC type" dropdown
  // so we don't waste ~9 rows of vertical real estate on stubs.
  const populatedGroups = IOC_EDIT_GROUPS.filter((g) => {
    const list = ((safe as any)[g.key] as string[] | undefined) || [];
    return list.length > 0 || openKey === g.key;
  });
  const emptyGroups = IOC_EDIT_GROUPS.filter((g) => {
    const list = ((safe as any)[g.key] as string[] | undefined) || [];
    return list.length === 0 && openKey !== g.key;
  });

  return (
    <div data-testid="section-detail-iocs">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 flex items-center justify-between">
        <span>Indicators of compromise</span>
        <span className="font-mono">{totalCount}</span>
      </div>
      <div className="space-y-2">
        {populatedGroups.length === 0 && (
          <div className="text-[11px] text-muted-foreground italic px-2 py-1">no indicators of compromise parsed yet</div>
        )}
        {populatedGroups.map((g) => {
          const list = ((safe as any)[g.key] as string[] | undefined) || [];
          const isOpen = openKey === g.key;
          return (
            <div key={g.key as string} className="rounded border bg-muted/20 p-2">
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 flex items-center justify-between">
                <span className="flex items-center gap-1.5">{g.label} <span className="font-mono normal-case">{list.length}</span></span>
                {!isOpen && (
                  <button
                    type="button"
                    onClick={() => startEdit(g.key as string)}
                    disabled={disabled}
                    className="text-muted-foreground hover:text-primary inline-flex items-center justify-center h-5 w-5 rounded hover:bg-primary/10 transition-colors disabled:opacity-50"
                    aria-label={`Edit ${g.label}`}
                    data-testid={`button-edit-ioc-${g.key as string}`}
                  >
                    <Pencil size={10} />
                  </button>
                )}
              </div>
              {isOpen ? (
                <>
                  <Textarea
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    placeholder={g.placeholder}
                    rows={4}
                    className="text-[11px] font-mono min-h-[80px]"
                    autoFocus
                    data-testid={`textarea-detail-ioc-${g.key as string}`}
                  />
                  <div className="flex items-center gap-1.5 mt-1.5">
                    <Button size="sm" className="h-6 px-2 text-[10px]" onClick={() => save(g.key)} data-testid={`button-save-ioc-${g.key as string}`}>
                      <CheckIcon size={10} className="mr-1" /> Save
                    </Button>
                    <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => setOpenKey(null)} data-testid={`button-cancel-ioc-${g.key as string}`}>
                      <XIcon size={10} className="mr-1" /> Cancel
                    </Button>
                  </div>
                </>
              ) : (
                <div className="flex flex-wrap gap-1 w-full min-w-0">
                  {list.map((v) => (
                    <button
                      key={v}
                      type="button"
                      onClick={() => {
                        navigator.clipboard?.writeText(v).then(() => {
                          toast({ title: "Copied", description: v.length > 96 ? v.slice(0, 96) + "…" : v });
                        }).catch(() => {});
                      }}
                      className="font-mono text-[10px] px-1.5 py-0.5 rounded border bg-background hover:bg-primary/10 hover:border-primary/40 transition-colors block max-w-full truncate text-left"
                      title={v + " — click to copy"}
                      data-testid={`ioc-chip-${g.key as string}`}
                    >
                      {v}
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
        {emptyGroups.length > 0 && (
          <Select
            value=""
            onValueChange={(v) => v && startEdit(v)}
            disabled={disabled}
          >
            <SelectTrigger className="h-7 text-[11px] w-full" data-testid="select-add-ioc-type">
              <SelectValue placeholder={`+ Add IoC type (${emptyGroups.length} available)`} />
            </SelectTrigger>
            <SelectContent>
              {emptyGroups.map((g) => (
                <SelectItem key={g.key as string} value={g.key as string} className="text-[11px]">
                  {g.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>
    </div>
  );
}

const STATUS_OPTIONS: Array<{ value: "new" | "triaged" | "assessed" | "dismissed" | "escalated"; label: string }> = [
  { value: "new",       label: "new" },
  { value: "triaged",   label: "triaged" },
  { value: "assessed",  label: "assessed" },
  { value: "dismissed", label: "dismissed" },
  { value: "escalated", label: "escalated" },
];
const IOC_EDIT_GROUPS: Array<{ key: keyof FindingIoCs; label: string; placeholder: string }> = [
  { key: "ipv4",   label: "IPv4",    placeholder: "one per line" },
  { key: "ipv6",   label: "IPv6",    placeholder: "one per line" },
  { key: "domain", label: "Domain",  placeholder: "one per line" },
  { key: "url",    label: "URL",     placeholder: "one per line" },
  { key: "md5",    label: "MD5",     placeholder: "one per line" },
  { key: "sha1",   label: "SHA-1",   placeholder: "one per line" },
  { key: "sha256", label: "SHA-256", placeholder: "one per line" },
  { key: "email",  label: "Email",   placeholder: "one per line" },
  { key: "btc",    label: "BTC",     placeholder: "one per line" },
];

function splitCommas(s: string): string[] {
  return s.split(/[,\n]/g).map((x) => x.trim()).filter(Boolean);
}
function splitLines(s: string): string[] {
  return s.split(/\n/g).map((x) => x.trim()).filter(Boolean);
}

function FindingDetailSheet({ findingId, onClose }: { findingId: string | null; onClose: () => void }) {
  const { toast } = useToast();
  const open = !!findingId;
  const { data, isLoading } = useQuery<OsintFindingDTO>({
    queryKey: ["/api/v1/osint/findings", findingId],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/v1/osint/findings/${findingId}`);
      return r.json();
    },
    enabled: !!findingId,
    placeholderData: () => {
      if (!findingId) return undefined;
      const cachedLists = queryClient.getQueriesData<TenantFindingsResp | GlobalFindingsResp>({
        queryKey: ["/api/v1/osint/findings"],
      });
      for (const [, value] of cachedLists) {
        const found = value?.findings?.find((f: any) => f.id === findingId);
        if (found) return found as OsintFindingDTO;
      }
      return undefined;
    },
  });

  // v2.28 — load typeahead dictionaries (technologies + threat actors).
  const { data: dicts, isLoading: dictsLoading } = useDictionaries();

  const analyzeOne = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", "/api/v1/osint/findings/ai-analyze", {
        ids: [findingId], onlyUnanalyzed: false,
      });
      return r.json();
    },
    // Force a synchronous refetch of the open finding so the panel is
    // visibly up-to-date (new IoCs / summary / relevance) the moment
    // the spinner stops — not whenever React Query lazily refetches.
    onSuccess: async (result: any) => {
      await Promise.all([
        queryClient.refetchQueries({ queryKey: ["/api/v1/osint/findings", findingId], exact: true }),
        queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/findings"] }),
      ]);
      const provider = result?.provider || result?.providerLabel;
      toast({
        title: "AI analysis ready",
        description: provider ? `Re-analysed via ${provider}. IoCs and summary refreshed.` : "Finding re-analysed. IoCs and summary refreshed.",
      });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Analyze failed", description: String(e.message ?? e) }),
  });

  // v2.18 — single mutation that PATCHes an arbitrary subset of fields. Used
  // by every per-field inline editor + chip-delete affordance.
  const patchField = useMutation({
    mutationFn: async (patch: OsintFindingPatch) => {
      const r = await apiRequest("PATCH", `/api/v1/osint/findings/${findingId}`, patch);
      return r.json();
    },
    // v2.28.1 — await the refetch of the open finding before the mutation
    // resolves. This keeps `isPending` true (and the panel overlay visible)
    // until the data is actually fresh, fixing the perceived latency where
    // the spinner ended but the chip list still showed stale state.
    onSuccess: async () => {
      await queryClient.refetchQueries({ queryKey: ["/api/v1/osint/findings", findingId], exact: true });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/findings"] });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Save failed", description: String(e.message ?? e) }),
  });

  // Build the iocs patch payload for a single group key by replacing its list.
  function patchIocGroup(key: keyof FindingIoCs, list: string[]) {
    const current: any = { ...(data?.iocs || {}) };
    if (list.length) current[key] = list;
    else delete current[key];
    patchField.mutate({ iocs: current });
  }

  // v2.28 — the panel-level loading overlay also covers IoC patches so the
  // analyst sees clear feedback while their edits round-trip to the server.
  const patchHasIocs = patchField.isPending && patchField.variables && Object.prototype.hasOwnProperty.call(patchField.variables, "iocs");
  const showPanelLoading = analyzeOne.isPending || !!patchHasIocs;
  const loadingMessage = analyzeOne.isPending
    ? { title: "Running AI analysis…", body: "Fetching the source article, extracting IoCs, scoring relevance and writing the summary. This usually takes 10–30 seconds." }
    : { title: "Updating indicators…", body: "Saving your IoC changes to this finding." };

  return (
    <Sheet open={open} onOpenChange={(v) => !v && onClose()}>
      {/* v2.21 — DO NOT add `relative` to SheetContent: Tailwind's last-wins
          ordering overrides Radix's base `fixed inset-y-0 right-0`, which
          pushes the entire panel out of the viewport. The loading overlay
          and a11y title live inside an inner `relative` wrapper instead. */}
      <SheetContent side="right" className="w-full sm:max-w-xl overflow-y-auto" data-testid="sheet-finding-detail">
        <div className="relative min-h-full">
        {/* Full-panel loading overlay shown during AI re-analyse AND IoC patches
            so the analyst sees a clear progress indicator while data refreshes. */}
        {showPanelLoading && (
          <div
            className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-3 bg-background/85 backdrop-blur-sm pointer-events-auto text-center"
            data-testid="overlay-detail-analyzing"
            aria-live="polite"
            role="status"
          >
            <div className="flex items-center justify-center gap-2 text-sm font-medium">
              <Loader2 size={18} className="animate-spin text-primary" />
              <span>{loadingMessage.title}</span>
            </div>
            <div className="text-xs text-muted-foreground max-w-[320px] text-center leading-relaxed">
              {loadingMessage.body}
            </div>
          </div>
        )}
        {!data && isLoading && (
          <>
            {/* Always render a SheetTitle for Radix a11y, even while loading. */}
            <SheetHeader>
              <SheetTitle className="sr-only">Loading finding</SheetTitle>
              <SheetDescription className="sr-only">Loading finding detail</SheetDescription>
            </SheetHeader>
            {/* Absolute-positioned overlay so the spinner is dead-centre of
                the entire panel regardless of SheetHeader height. */}
            <div
              className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-sm text-muted-foreground text-center"
              data-testid="overlay-detail-loading"
              aria-live="polite"
              role="status"
            >
              <Loader2 size={20} className="animate-spin text-primary" />
              <span>Loading finding…</span>
            </div>
          </>
        )}
        {data && (
          <>
            <SheetHeader className="space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <Badge className={`text-[10px] uppercase border ${severityColor(data.severity)}`}>{data.severity}</Badge>
                <IntelCategoryChip
                  category={data.intelCategory ?? null}
                  size="md"
                  testId="badge-detail-intel-category"
                />
                <Badge variant="outline" className="text-[10px]">{data.sourceCategory}</Badge>
                <span className="text-[10px] font-mono text-muted-foreground">{data.sourceName}</span>
                <span className="text-[10px] text-muted-foreground">{relativeTime(data.publishedAt)}</span>
                <Badge variant="outline" className={`text-[10px] ${freshnessTier(data.publishedAt).tone}`}>{freshnessTier(data.publishedAt).label}</Badge>
                <Badge variant="outline" className={`text-[10px] ${confidenceTier(data).tone}`}>{confidenceTier(data).label}</Badge>
              </div>
              <SheetTitle className="text-base leading-snug" data-testid="text-detail-title">{data.title}</SheetTitle>
              {data.summary && (
                <SheetDescription className="text-xs leading-relaxed">{data.summary}</SheetDescription>
              )}
            </SheetHeader>

            <div className="mt-5 space-y-4 text-sm">
              {/* Action bar — v2.18: only Analyse stays. The old global Edit
                  toggle is replaced by per-field pencil / add / delete icons. */}
              <div className="flex items-center gap-2 flex-wrap">
                <Button
                  size="sm"
                  onClick={() => analyzeOne.mutate()}
                  disabled={analyzeOne.isPending}
                  data-testid="button-detail-analyze"
                >
                  {analyzeOne.isPending
                    ? <><Loader2 size={12} className="mr-1.5 animate-spin" />Analysing</>
                    : <><Sparkles size={12} className="mr-1.5" />{data.aiSummary ? "Re-analyse" : "AI analyse"}</>}
                </Button>
                <StartInvestigationButton
                  entityType="osint_finding"
                  entityId={data.id}
                  title={data.title}
                  severity={data.severity as any}
                  summary={data.aiSummary || data.summary || undefined}
                  size="sm"
                  variant="outline"
                />
                {data.analystEditedAt && (
                  <span className="text-[10px] text-muted-foreground ml-auto" data-testid="text-detail-edited-by">
                    edited {relativeTime(data.analystEditedAt)}{data.analystEditedBy ? ` by ${data.analystEditedBy}` : ""}
                  </span>
                )}
              </div>

              {/* AI summary */}
              {data.aiSummary && (
                <Card className="p-3 border-primary/20 bg-primary/5">
                  <div className="text-[10px] uppercase tracking-wide text-primary mb-1">
                    AI summary{data.aiProviderLabel ? ` · ${data.aiProviderLabel}` : ""}
                    {data.aiRelevanceScore != null && (
                      <span className="ml-2 font-mono">relevance {relevancePercent(data.aiRelevanceScore)}%</span>
                    )}
                  </div>
                  <div className="text-xs whitespace-pre-wrap leading-relaxed" data-testid="text-detail-ai-summary">
                    {data.aiSummary}
                  </div>
                  {data.aiRecommendation && (
                    <div className="text-xs mt-2 pt-2 border-t border-primary/20">
                      <span className="text-[10px] uppercase tracking-wide text-primary">Recommendation: </span>
                      {data.aiRecommendation}
                    </div>
                  )}
                </Card>
              )}

              <Card className="p-3">
                <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Intel scoring & lineage</div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <div className="text-muted-foreground">Client relevance</div>
                    <div className="mt-0.5">{clientRelevanceReason(data)}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Extraction density</div>
                    <div className="mt-0.5">{iocCount(data.iocs)} IoCs · {data.cveIds.length} CVEs · {data.attackTechniques?.length ?? 0} ATT&CK</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Source</div>
                    <div className="mt-0.5">{data.sourceName} · {data.sourceCategory}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Freshness</div>
                    <div className="mt-0.5">{freshnessTier(data.publishedAt).label}</div>
                  </div>
                </div>
                {data.attackTechniques?.length ? (
                  <div className="mt-3">
                    <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Mapped ATT&CK techniques</div>
                    <div className="flex flex-wrap gap-1">
                      {data.attackTechniques.slice(0, 10).map((t) => (
                        <Badge key={t.id} variant="outline" className="font-mono text-[10px]">{t.id}{t.name ? ` · ${t.name}` : ""}</Badge>
                      ))}
                    </div>
                  </div>
                ) : null}
              </Card>

              {/* Metadata grid — Status is now editable via inline dropdown */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <FieldLabel
                    label="Status"
                    onAction={null /* status uses inline select — no add/edit icon needed */}
                  />
                  <Select
                    value={data.status}
                    onValueChange={(v) => patchField.mutate({ status: v as any })}
                    disabled={patchField.isPending}
                  >
                    <SelectTrigger className="h-8 text-xs w-full" data-testid="select-detail-status">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {STATUS_OPTIONS.map((s) => (
                        <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Published</div>
                  <div className="font-mono text-[11px]">{new Date(data.publishedAt).toLocaleString()}</div>
                </div>
              </div>

              {/* CVEs — chip list with per-chip delete + add-icon editor */}
              <ChipFieldEditor
                label="CVE references"
                values={data.cveIds || []}
                placeholder="CVE-2024-1234, CVE-2024-5678"
                emptyLabel="no CVE references parsed"
                fontMono
                onChange={(next) => patchField.mutate({ cveIds: next })}
                renderChip={(c) => (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${c}`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-block"
                  >
                    <Badge variant="outline" className="text-[10px] font-mono hover:border-primary cursor-pointer" data-testid={`badge-detail-cve-${c}`}>
                      {c} <ExternalLink size={9} className="ml-1" />
                    </Badge>
                  </a>
                )}
                testIdPrefix="cves"
              />

              {/* Indicators of Compromise — per-type chips with delete + add */}
              <IocSectionEditable
                iocs={data.iocs}
                onChangeGroup={patchIocGroup}
                disabled={patchField.isPending}
              />

              {/* Tag groups (Affected tech / Threat actors / Analyst tags)
                  v2.28 — Affected tech + Threat actors are dictionary-backed
                  typeahead inputs with custom-add support. Analyst tags remain
                  free-form. */}
              <div className="space-y-3">
                <TypeaheadChipFieldEditor<DictTechnology>
                  label="Affected technology"
                  values={data.affectedTech || []}
                  onChange={(next) => patchField.mutate({ affectedTech: next })}
                  dict={dicts?.technologies || []}
                  dictLoading={dictsLoading}
                  placeholder="Type to search 100+ tracked technologies…"
                  emptyLabel="none"
                  renderChip={(t, meta) => (
                    <Badge
                      variant="secondary"
                      className="text-[10px] font-mono"
                      title={meta ? `${meta.category}${meta.vendor ? " · " + meta.vendor : ""}` : "Custom entry (not in dictionary)"}
                      data-testid={`badge-detail-tech-${t}`}
                    >
                      {t}
                    </Badge>
                  )}
                  testIdPrefix="tech"
                />
                <TypeaheadChipFieldEditor<DictThreatActor>
                  label="Threat actors"
                  values={data.threatActors || []}
                  onChange={(next) => patchField.mutate({ threatActors: next })}
                  dict={dicts?.threatActors || []}
                  dictLoading={dictsLoading}
                  placeholder="Type to search 100+ tracked threat actors…"
                  emptyLabel="none"
                  renderChip={(a, meta) => (
                    <span className="inline-flex items-center gap-0.5">
                      <Badge
                        className="text-[10px] bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/30"
                        title={meta ? `${meta.category}${meta.country ? " · " + meta.country : ""}${meta.active === false ? " · inactive" : ""}` : "Custom entry (not in dictionary)"}
                        data-testid={`badge-detail-actor-${a.replace(/\s+/g, "-").toLowerCase()}`}
                      >
                        {a}
                      </Badge>
                      <button
                        type="button"
                        title={`Open Threat Actor Profile for ${a}`}
                        onClick={() => {
                          (window as any).__pendingTapFocusName = a;
                          window.location.hash = `#/threat-actors`;
                          window.dispatchEvent(new Event("tap:focus"));
                        }}
                        className="text-[10px] px-1 py-0.5 rounded border border-rose-500/30 text-rose-700 dark:text-rose-300 hover:bg-rose-500/15 leading-none"
                        data-testid={`button-pivot-tap-${a.replace(/\s+/g, "-").toLowerCase()}`}
                      >
                        ↗ TAP
                      </button>
                    </span>
                  )}
                  testIdPrefix="actors"
                />
                <ChipFieldEditor
                  label="Analyst tags"
                  values={data.analystTags || []}
                  placeholder="comma-separated, e.g. payment-fraud, watchlist"
                  emptyLabel="no analyst tags yet"
                  onChange={(next) => patchField.mutate({ analystTags: next })}
                  renderChip={(t) => (
                    <Badge className="text-[10px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30 border" data-testid={`badge-detail-analyst-tag-${t}`}>
                      {t}
                    </Badge>
                  )}
                  testIdPrefix="analyst-tags"
                  listTestId="list-detail-analyst-tags"
                />
              </div>

              {/* Raw snippet */}
              {data.rawSnippet && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5">Raw intel snippet</div>
                  <div className="text-xs font-mono whitespace-pre-wrap bg-muted/40 border rounded p-3 max-h-[260px] overflow-y-auto" data-testid="text-detail-raw">
                    {data.rawSnippet}
                  </div>
                </div>
              )}

              {/* Draft email if present */}
              {data.draftEmail && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 flex items-center gap-2">
                    <Mail size={11} /> Drafted client email
                  </div>
                  <div className="text-xs whitespace-pre-wrap bg-muted/40 border rounded p-3 max-h-[260px] overflow-y-auto">
                    {data.draftEmail}
                  </div>
                </div>
              )}

              {/* v2.17 — Original source card MOVED to BOTTOM (analyst requested). */}
              {data.url && (
                <Card className="p-3 border-primary/30 bg-primary/5" data-testid="card-detail-source">
                  <div className="text-[10px] uppercase tracking-wide text-primary mb-2 flex items-center justify-between">
                    <span>Original source</span>
                    <button
                      type="button"
                      className="text-[10px] text-muted-foreground hover:text-primary inline-flex items-center gap-1"
                      onClick={() => {
                        navigator.clipboard?.writeText(data.url!).then(() => {
                          toast({ title: "Link copied", description: data.url! });
                        }).catch(() => {});
                      }}
                      data-testid="button-detail-copy-url"
                    >
                      <Copy size={10} /> copy link
                    </button>
                  </div>
                  <a
                    href={data.url}
                    target="_blank"
                    rel="noreferrer"
                    className="block"
                    data-testid="link-detail-source"
                  >
                    <Button size="sm" className="w-full justify-start" data-testid="button-detail-open-source">
                      <ExternalLink size={12} className="mr-1.5" /> Open source
                    </Button>
                  </a>
                  <div className="mt-2 font-mono text-[10px] text-muted-foreground break-all leading-relaxed" data-testid="text-detail-source-url">
                    {data.url}
                  </div>
                </Card>
              )}
            </div>
          </>
        )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ---- Hunt-query dialog -----------------------------------------------------
function HuntQueryDialog({
  findingIds, languages, onClose, onCreated,
}: {
  findingIds: string[];
  languages: { id: string; label: string }[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const [picked, setPicked] = useState<string[]>(["splunk", "kql_elk", "sigma"]);
  const [activeLang, setActiveLang] = useState<string>("splunk");
  const [generated, setGenerated] = useState<HuntQueryDTO | null>(null);
  const [title, setTitle] = useState("");

  function toggleLang(id: string) {
    setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));
  }

  const create = useMutation({
    mutationFn: async () => startBackgroundJob("/api/v1/osint/hunt-queries", {
      findingIds, languages: picked, title: title || undefined,
    }),
    onSuccess: (q: any) => {
      setGenerated(null);
      toast({ title: "Hunt query job queued", description: q.targetLabel ?? "The background jobs tray will show progress and completion." });
      onCreated();
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed", description: String(e.message ?? e) }),
  });

  const copyText = (txt: string) => {
    navigator.clipboard?.writeText(txt).then(
      () => toast({ title: "Copied to clipboard" }),
      () => toast({ variant: "destructive", title: "Copy failed" }),
    );
  };

  return (
    <DialogContent className="w-[min(1100px,94vw)] max-w-none max-h-[90vh] flex flex-col overflow-hidden">
      <DialogHeader className="shrink-0">
        <DialogTitle className="text-base">Generate threat-hunt queries</DialogTitle>
        <DialogDescription className="text-xs">
          {findingIds.length} OSINT finding{findingIds.length === 1 ? "" : "s"} selected. AI generates a query per language for your SIEM/EDR.
        </DialogDescription>
      </DialogHeader>

      <div className="min-h-0 flex-1 overflow-y-auto pr-1 space-y-3">
        <div>
          <Input
            value={title} onChange={(e) => setTitle(e.target.value)}
            placeholder="Optional title (defaults to top finding title)"
            data-testid="input-hunt-title"
          />
        </div>
        <div>
          <div className="text-[11px] text-muted-foreground mb-1.5">Query languages ({picked.length})</div>
          <div className="flex flex-wrap gap-1.5 max-w-full">
            {languages.map((l) => {
              const on = picked.includes(l.id);
              return (
                <button
                  key={l.id} type="button" onClick={() => toggleLang(l.id)}
                  data-testid={`chip-lang-${l.id}`}
                  className={`px-2.5 py-1 rounded-full text-[11px] border ${
                    on ? "bg-primary text-primary-foreground border-primary" : "bg-background hover:bg-muted border-border"
                  }`}
                >
                  {l.label}
                </button>
              );
            })}
          </div>
        </div>

        {generated && (
          <Card className="p-2 min-w-0">
            <Tabs value={activeLang} onValueChange={setActiveLang} className="min-w-0">
              <TabsList className="flex flex-wrap h-auto gap-1 max-w-full" data-testid="tabs-hunt-langs">
                {Object.keys(generated.queries).map((lid) => {
                  const meta = languages.find((x) => x.id === lid);
                  return (
                    <TabsTrigger key={lid} value={lid} className="text-[10px] h-7 max-w-full" data-testid={`tab-lang-${lid}`}>
                      {meta?.label ?? lid}
                    </TabsTrigger>
                  );
                })}
              </TabsList>
              {Object.entries(generated.queries).map(([lid, txt]) => {
                const arr: string[] = Array.isArray(txt) ? txt : [txt];
                const joined = arr.join("\n\n");
                return (
                <TabsContent key={lid} value={lid} className="mt-2 space-y-2 min-w-0">
                  {arr.length > 1 && (
                    <div className="flex justify-between items-center gap-2">
                      <div className="text-[10px] text-muted-foreground px-1">{arr.length} distinct queries</div>
                      <Button size="sm" variant="outline" onClick={() => copyText(joined)} data-testid={`button-copy-all-${lid}`}>
                        <Copy size={11} className="mr-1" /> Copy all
                      </Button>
                    </div>
                  )}
                  {arr.map((q, i) => (
                    <div key={i} className="space-y-1">
                      <div className="flex justify-between items-center gap-2">
                        <div className="text-[10px] font-medium text-muted-foreground px-1">
                          {arr.length > 1 ? `Query ${i + 1} of ${arr.length}` : "Query"}
                        </div>
                        <Button size="sm" variant="outline" onClick={() => copyText(q)} data-testid={`button-copy-${lid}-${i}`}>
                          <Copy size={11} className="mr-1" /> Copy{arr.length > 1 ? ` ${i + 1}` : ""}
                        </Button>
                      </div>
                      <pre className="text-[11px] font-mono p-3 bg-muted/30 border rounded max-h-[280px] max-w-full overflow-auto whitespace-pre-wrap break-words" data-testid={`pre-query-${lid}-${i}`}>
                        {q}
                      </pre>
                    </div>
                  ))}
                </TabsContent>
                );
              })}
            </Tabs>
            <div className="text-[10px] text-muted-foreground mt-1.5 px-1">
              Generated by {generated.aiProviderLabel ?? "AI"} · {Object.keys(generated.queries).length} languages · {Object.values(generated.queries).reduce((n, v) => n + (Array.isArray(v) ? v.length : 1), 0)} queries
            </div>
          </Card>
        )}
      </div>

      <DialogFooter className="shrink-0 border-t pt-3">
        <Button variant="ghost" onClick={onClose}>Close</Button>
        <Button
          onClick={() => create.mutate()}
          disabled={create.isPending || picked.length === 0 || findingIds.length === 0 || aiDisabled}
          title={aiAvailability.disabledReason}
          data-testid="button-generate-hunt"
        >
          {create.isPending ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Generating</> : <><Sparkles size={14} className="mr-1.5" />Generate</>}
        </Button>
        {generated && (
          <Button variant="secondary" onClick={onCreated} data-testid="button-done-hunt">Done</Button>
        )}
      </DialogFooter>
    </DialogContent>
  );
}

// ---- Drafts tab (email + hunt-queries history) ------------------------------
function DraftsTab({ isGlobal, dimension, selectedIds: scopeIds, onDimensionChange, onSelectedIdsChange }: ScopedTabProps) {
  const { toast } = useToast();
  const { data: tax } = useQuery<TaxonomiesResp>({ queryKey: ["/api/v1/taxonomies"] });
  const scopeKey = scopeIds.join(",");

  // Single-tenant: separate /findings + /hunt-queries calls.
  // Global: a single /global/osint/drafts call returns both.
  const { data: globalData } = useQuery<{ drafts: GlobalDraftFinding[]; huntQueries: GlobalHuntQuery[] }>({
    queryKey: ["/api/v1/global/osint/drafts", dimension, scopeKey],
    queryFn: async () => {
      const u = new URL("/api/v1/global/osint/drafts", window.location.origin);
      u.searchParams.set("dimension", dimension);
      if (scopeIds.length) u.searchParams.set("ids", scopeIds.join(","));
      const r = await apiRequest("GET", u.pathname + u.search);
      return r.json();
    },
    enabled: isGlobal,
  });
  const { data: hq } = useQuery<HuntQueriesResp>({
    queryKey: ["/api/v1/osint/hunt-queries"],
    enabled: !isGlobal,
  });
  const { data: f } = useQuery<FindingsResp>({
    queryKey: ["/api/v1/osint/findings", "withDrafts"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/v1/osint/findings");
      return r.json();
    },
    enabled: !isGlobal,
  });
  const drafts: Array<OsintFindingDTO & Partial<{ tenantName: string; tenantSlug: string }>> = isGlobal
    ? (globalData?.drafts || [])
    : (f?.findings || []).filter((x) => !!x.draftEmail);
  const huntQueries: Array<HuntQueryDTO & Partial<{ tenantName: string; tenantSlug: string }>> = isGlobal
    ? (globalData?.huntQueries || [])
    : (hq?.queries || []);

  const copy = (txt: string) =>
    navigator.clipboard?.writeText(txt).then(
      () => toast({ title: "Copied" }),
      () => toast({ variant: "destructive", title: "Copy failed" }),
    );

  return (
    <div className="space-y-6">
      {isGlobal && (
        <ScopeBar
          dimension={dimension}
          selectedIds={scopeIds}
          onDimensionChange={onDimensionChange}
          onSelectedIdsChange={onSelectedIdsChange}
        />
      )}
      <section>
        <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
          AI-drafted client emails ({drafts.length}) {isGlobal ? "— across all clients in scope" : ""}
        </div>
        {drafts.length === 0 ? (
          <Card className="p-8 text-center text-sm text-muted-foreground">
            No email drafts yet. Select findings on the Findings tab and click "Draft email".
          </Card>
        ) : (
          <div className="space-y-2">
            {drafts.map((d) => (
              <Card key={d.id} className="p-3" data-testid={`card-draft-${d.id}`}>
                <div className="flex items-center gap-2 mb-1">
                  <Mail size={12} className="text-primary" />
                  <span className="text-xs font-medium truncate">{d.title}</span>
                  {isGlobal && d.tenantName && (
                    <Badge variant="default" className="text-[10px] bg-primary/15 text-primary border-primary/30 border" data-testid={`badge-draft-tenant-${d.id}`}>
                      {d.tenantName}
                    </Badge>
                  )}
                  <span className="text-[10px] text-muted-foreground ml-auto">{relativeTime(d.draftEmailAt)}</span>
                </div>
                <pre className="text-[11px] font-mono p-2 bg-muted/30 border rounded whitespace-pre-wrap max-h-64 overflow-auto" data-testid={`pre-draft-${d.id}`}>
                  {d.draftEmail}
                </pre>
                <div className="flex justify-end mt-1.5">
                  <Button size="sm" variant="outline" onClick={() => copy(d.draftEmail || "")} data-testid={`button-copy-draft-${d.id}`}>
                    <Copy size={11} className="mr-1" /> Copy
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        )}
      </section>

      <section>
        <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
          Hunt-query history ({huntQueries.length}) {isGlobal ? "— across all clients in scope" : ""}
        </div>
        {huntQueries.length === 0 ? (
          <Card className="p-8 text-center text-sm text-muted-foreground">
            No hunt queries yet. Select findings and click "Hunt query".
          </Card>
        ) : (
          <div className="space-y-2">
            {huntQueries.map((q) => (
              <Card key={q.id} className="p-3" data-testid={`card-hunt-${q.id}`}>
                <div className="flex items-center gap-2 mb-1">
                  <Code2 size={12} className="text-primary" />
                  <span className="text-xs font-medium truncate">{q.title}</span>
                  {isGlobal && q.tenantName && (
                    <Badge variant="default" className="text-[10px] bg-primary/15 text-primary border-primary/30 border" data-testid={`badge-hunt-tenant-${q.id}`}>
                      {q.tenantName}
                    </Badge>
                  )}
                  <span className="text-[10px] text-muted-foreground ml-auto">{relativeTime(q.createdAt)}</span>
                </div>
                <div className="flex flex-wrap gap-1 mb-1.5">
                  {Object.keys(q.queries).map((lid) => {
                    const meta = tax?.huntLanguages.find((x) => x.id === lid);
                    return (
                      <Badge key={lid} variant="secondary" className="text-[10px]">{meta?.label ?? lid}</Badge>
                    );
                  })}
                </div>
                <details>
                  <summary className="text-[11px] cursor-pointer text-muted-foreground">Show {Object.keys(q.queries).length} queries</summary>
                  <div className="mt-2 space-y-2">
                    {Object.entries(q.queries).map(([lid, txt]) => {
                      const meta = tax?.huntLanguages.find((x) => x.id === lid);
                      return (
                        <div key={lid}>
                          <div className="flex items-center justify-between gap-2 mb-1">
                            <span className="text-[10px] font-mono uppercase text-muted-foreground">{meta?.label ?? lid}</span>
                            <Button size="sm" variant="outline" onClick={() => copy(txt)} data-testid={`button-copy-history-${q.id}-${lid}`}>
                              <Copy size={11} className="mr-1" /> Copy
                            </Button>
                          </div>
                          <pre className="text-[10px] font-mono p-2 bg-muted/30 border rounded whitespace-pre-wrap max-h-48 overflow-auto">
                            {txt}
                          </pre>
                        </div>
                      );
                    })}
                  </div>
                </details>
              </Card>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

// ---- Page ------------------------------------------------------------------
export default function OsintMonitoring() {
  const { user, activeTenantId, setActiveTenant } = useAuth();
  // v2.17 — OSINT page defaults to Global View. Admins land in global scope
  // on page mount unless they have already pivoted somewhere else. Analysts
  // (single-tenant role) keep their own tenant.
  useEffect(() => {
    if (user?.role === "admin" && activeTenantId !== GLOBAL_TENANT_ID) {
      setActiveTenant(GLOBAL_TENANT_ID);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.role]);
  const isGlobal = activeTenantId === GLOBAL_TENANT_ID;
  const [dimension, setDimension] = useState<ScopeDimension>("client");
  const [scopeIds, setScopeIds] = useState<string[]>([]);
  return (
    <AppShell>
      <div className="px-6 md:px-10 py-8 max-w-[1400px]">
        <PageHeader
          title={isGlobal ? "Intel Inbox — Global" : "Intel Inbox"}
          description={isGlobal
            ? "Cross-client signal intake for spotting shared exposure, campaign overlap, and client-specific urgency."
            : "Triage live threat intelligence, extract indicators, and hand relevant signal into investigations, detections, or client-ready advisories."}
        />
        <Tabs defaultValue="findings" className="space-y-4">
          <TabsList data-testid="tabs-osint">
            <TabsTrigger value="findings" data-testid="tab-osint-findings">Findings</TabsTrigger>
            <TabsTrigger value="sources" data-testid="tab-osint-sources">Sources</TabsTrigger>
            <TabsTrigger value="drafts" data-testid="tab-osint-drafts">Drafts &amp; queries</TabsTrigger>
            <TabsTrigger value="automation" data-testid="tab-osint-automation">Automation</TabsTrigger>
          </TabsList>
          <TabsContent value="findings" className="mt-0">
            <FindingsTab
              isGlobal={isGlobal}
              dimension={dimension}
              selectedIds={scopeIds}
              onDimensionChange={setDimension}
              onSelectedIdsChange={setScopeIds}
            />
          </TabsContent>
          <TabsContent value="sources" className="mt-0">
            <SourcesTab
              isGlobal={isGlobal}
              dimension={dimension}
              selectedIds={scopeIds}
              onDimensionChange={setDimension}
              onSelectedIdsChange={setScopeIds}
            />
          </TabsContent>
          <TabsContent value="drafts" className="mt-0">
            <DraftsTab
              isGlobal={isGlobal}
              dimension={dimension}
              selectedIds={scopeIds}
              onDimensionChange={setDimension}
              onSelectedIdsChange={setScopeIds}
            />
          </TabsContent>
          <TabsContent value="automation" className="mt-0">
            <OsintAutomationCard />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
