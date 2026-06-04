// v2.30.5 — Threat Actor Profiles (TAP)
//
// Renders the canonical 13-section + 4-appendix Threat Actor Profile model
// pioneered in the user's TAP-001/002/003 reference documents:
//   1. Exec Summary    8. Infrastructure
//   2. Identity        9. Detection (rule links)
//   3. Victimology    10. IR Actions
//   4. Capability     11. Countermeasures
//   5. TTPs (MITRE)   12. Forecast
//   6. Diamond Model  13. Confidence / Sources
//   7. Campaigns       A. IOCs   B. STIX 2.1   C. References   D. Version
//
// TAP enrichment runs through the shared AI job pipeline so long-running
// profile rebuilds are visible in the background jobs tray and Job control.
//
// English-only AI output. NEVER add `relative` to Radix SheetContent — children
// must be wrapped in `<div className="relative min-h-full">`.

import { useCallback, useEffect, useMemo, useRef, useState, memo, createContext, useContext } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient, resolveAssetUrl } from "@/lib/queryClient";
import { startBackgroundJob, type BackgroundJobStart } from "@/lib/aiJobs";
import { useAiAvailability } from "@/lib/aiAvailability";
import { BATCH_ONE_RELEASE } from "@/lib/release";
import {
  DndContext, DragOverlay, useDraggable, useDroppable,
  PointerSensor, TouchSensor, KeyboardSensor, useSensor, useSensors,
  type DragStartEvent, type DragEndEvent, closestCorners,
} from "@dnd-kit/core";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { StartInvestigationButton } from "@/components/StartInvestigationButton";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from "@/components/ui/sheet";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { relativeTime } from "@/lib/format";
import {
  Loader2, Sparkles, Skull, Plus, Pencil, Trash2, Download, FileDown,
  Crosshair, Target, AlertTriangle, Globe2, Network, Shield, BookOpen,
  Tag, ListChecks, MapPin, Activity, Calendar, ExternalLink, FileText,
  LayoutGrid, List as ListIcon, CheckCircle2, Clock, AlertCircle,
  Building2, GripVertical, X, Save, RotateCcw, MoreHorizontal,
  Camera, Upload, RefreshCw,
} from "lucide-react";
import {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import type {
  ThreatActorDTO, ThreatActorFullDTO, ThreatActorTtpDTO, ThreatActorToolDTO,
  ThreatActorCampaignDTO, ThreatActorIocDTO, ThreatActorReferenceDTO,
  ThreatActorRuleLinkDTO, ThreatActorTenantDTO, TenantRelevance,
  TapStatus, ActorType, ThreatLevel, TlpLevel,
  SponsorshipLevel, SophisticationLevel, IntentProximity, WepConfidence,
  AdmiraltySource, AdmiraltyInfo,
  AiProviderSummary,
} from "@shared/schema";
import {
  ACTOR_TYPES, SPONSORSHIP_LEVELS, TLP_LEVELS, THREAT_LEVELS,
  SOPHISTICATION_LEVELS, INTENT_PROXIMITY, WEP_CONFIDENCE,
  ADMIRALTY_SOURCE, ADMIRALTY_INFO, TAP_STATUSES,
} from "@shared/schema";

// ---- Tenant tagging types --------------------------------------------------
interface TenantTagsResp {
  tags: ThreatActorTenantDTO[];
  available: Array<{ id: string; name: string; sector: string | null; region: string | null; orgSize: string | null }>;
  relevances: TenantRelevance[];
}

const RELEVANCE_BADGE: Record<TenantRelevance, string> = {
  "targeted":     "bg-red-600 text-white dark:bg-red-700",
  "sector-match": "bg-amber-500 text-white dark:bg-amber-600",
  "watching":     "bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200",
};
const RELEVANCE_LABEL: Record<TenantRelevance, string> = {
  "targeted":     "Targeted",
  "sector-match": "Sector match",
  "watching":     "Watching",
};
const RELEVANCE_ORDER: TenantRelevance[] = ["targeted", "sector-match", "watching"];

// Resolves the per-tenant AI provider configured for the `threat_actor_enrichment`
// task in AI Setup. Falls back to the generic phrase "the configured AI provider"
// when nothing is configured yet so copy never says the wrong vendor name.
function useAiTaskProviderLabel(task: string): string {
  const { data: assignments } = useQuery<{ assignments: Record<string, string> }>({
    queryKey: ["/api/v1/ai/assignments"],
  });
  const { data: providers } = useQuery<{ providers: AiProviderSummary[] }>({
    queryKey: ["/api/v1/ai/providers"],
  });
  const providerId = assignments?.assignments?.[task];
  const provider = providers?.providers?.find((p) => p.id === providerId);
  return provider?.label ?? "The configured AI provider";
}

function useEnrichProviderLabel(): string {
  return useAiTaskProviderLabel("threat_actor_enrichment");
}

/** Lowercased variant for mid-sentence positions (e.g. after "with"). */
function toMidSentence(label: string): string {
  // Real provider names (DeepSeek, OpenAI, Anthropic, Google Gemini, Azure OpenAI,
  // Ollama, Perplexity) are proper nouns and stay capitalized. Only the generic
  // fallback should drop its leading capital when it appears mid-sentence.
  return label === "The configured AI provider" ? "the configured AI provider" : label;
}

// ---- Types -----------------------------------------------------------------
interface ListResp { actors: ThreatActorDTO[] }
interface CreateResp { id?: string; status?: string; actor?: ThreatActorDTO; enriched?: boolean; existing?: boolean; providerLabel?: string | null }
interface EnrichResp extends BackgroundJobStart {}
interface PortraitGeneratorAvailabilityResp {
  available: boolean;
  tool: string;
  installHint?: string;
  message?: string;
}

// ---- Badge helpers ---------------------------------------------------------
const TAP_STATUS_BADGE: Record<TapStatus, string> = {
  draft:    "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200",
  reviewed: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200",
  approved: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  archived: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400",
};
const THREAT_LEVEL_BADGE: Record<ThreatLevel, string> = {
  CRITICAL: "bg-red-600 text-white dark:bg-red-700",
  HIGH:     "bg-orange-500 text-white dark:bg-orange-600",
  MODERATE: "bg-amber-500 text-white dark:bg-amber-600",
  LOW:      "bg-emerald-500 text-white dark:bg-emerald-600",
};
const TLP_BADGE: Record<TlpLevel, string> = {
  "CLEAR":          "bg-white text-slate-900 border border-slate-300 dark:bg-slate-100 dark:text-slate-900",
  "GREEN":          "bg-emerald-500 text-white dark:bg-emerald-600",
  "AMBER":          "bg-amber-500 text-white dark:bg-amber-600",
  "AMBER+STRICT":   "bg-orange-500 text-white dark:bg-orange-600",
  "RED":            "bg-red-600 text-white dark:bg-red-700",
};
const ACTOR_TYPE_LABEL: Record<ActorType, string> = {
  "Nation-State":              "Nation-State / APT",
  "Ransomware-as-a-Service":   "Ransomware-as-a-Service",
  "Ransomware Affiliate":      "Ransomware Affiliate",
  "Organized Cybercrime":      "Organized Cybercrime",
  "Hacktivist":                "Hacktivist",
  "Insider":                   "Insider",
  "Mercenary":                 "Cyber Mercenary",
  "Lone Actor":                "Lone Actor",
  "Unknown":                   "Unknown",
};

type KdotTone = "muted" | "indigo" | "cyan" | "emerald" | "amber" | "rose" | "violet";
const KANBAN_COLS: { id: TapStatus; label: string; tone: KdotTone }[] = [
  { id: "draft",    label: "DRAFT",    tone: "muted"   },
  { id: "reviewed", label: "REVIEWED", tone: "indigo"  },
  { id: "approved", label: "APPROVED", tone: "emerald" },
  { id: "archived", label: "ARCHIVED", tone: "muted"   },
];

function MetaCell({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="space-y-0.5">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="text-sm font-medium break-words">{value || <span className="text-muted-foreground">—</span>}</div>
    </div>
  );
}

// ---- Page ------------------------------------------------------------------
export default function ThreatActors() {
  const { toast } = useToast();
  const [view, setView] = useState<"list" | "kanban">("list");
  const [statusFilter, setStatusFilter] = useState<"all" | TapStatus>("all");
  const [clientFilter, setClientFilter] = useState<"all" | string>("all");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [kanbanGroupBy, setKanbanGroupBy] = useState<"status" | "client">("status");

  // Pivot deep-link support. Triggered when OSINT or Detection-Rule pages set
  // `window.__pendingTapFocusName` (or `__pendingTapFocusId`) and dispatch a
  // `tap:focus` event before navigating to `#/threat-actors`. We use a global
  // hand-off rather than a query-string because wouter's hash router treats
  // "?..." as part of the path and would 404.
  useEffect(() => {
    const consume = () => {
      const w = window as any;
      const id: string | undefined = w.__pendingTapFocusId;
      const name: string | undefined = w.__pendingTapFocusName;
      if (id) {
        setSelectedId(id);
        delete w.__pendingTapFocusId;
        return;
      }
      if (name) {
        // Idempotent: server returns existing TAP if name already present, else creates a shell.
        apiRequest("POST", "/api/v1/threat-actors", { primaryName: name })
          .then((r) => r.json())
          .then((a: { id: string }) => {
            setSelectedId(a.id);
            queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors"] });
          })
          .catch(() => { /* swallow — user can use create dialog manually */ });
        delete w.__pendingTapFocusName;
      }
    };
    const raw = window.location.hash || "";
    const qix = raw.indexOf("?");
    if (qix >= 0) {
      const qs = new URLSearchParams(raw.slice(qix + 1));
      const focus = qs.get("focus");
      if (focus) setSelectedId(focus);
    }
    // Run once on mount (covers the case where the page is freshly entered).
    consume();
    window.addEventListener("tap:focus", consume);
    return () => window.removeEventListener("tap:focus", consume);
  }, []);

  const { data, isLoading } = useQuery<ListResp>({
    queryKey: ["/api/v1/threat-actors", statusFilter],
    queryFn: async () => {
      const qs = new URLSearchParams();
      if (statusFilter !== "all") qs.set("status", statusFilter);
      const r = await apiRequest("GET", `/api/v1/threat-actors${qs.toString() ? `?${qs.toString()}` : ""}`);
      return r.json();
    },
    placeholderData: () => {
      const cached = queryClient.getQueryData<ListResp>(["/api/v1/threat-actors"]);
      if (!cached?.actors) return undefined;
      if (statusFilter === "all") return cached;
      return { actors: cached.actors.filter((a) => a.status === statusFilter) };
    },
  });

  // Batch tenant-tag summary keyed by actor_id — single round-trip rather than
  // per-card. Refetches automatically when the AI completes an enrichment job
  // (the global AiJobsProvider invalidates ["/api/v1/threat-actors"]).
  const { data: tagsResp } = useQuery<{
    tags: ThreatActorTenantDTO[];
    available: { id: string; name: string; sector: string | null; region: string | null; orgSize: string | null }[];
    relevances: TenantRelevance[];
  }>({
    queryKey: ["/api/v1/threat-actors-tenant-tags"],
    enabled: !BATCH_ONE_RELEASE,
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/v1/threat-actors-tenant-tags");
      return r.json();
    },
  });

  const tagsByActor = useMemo(() => {
    const map = new Map<string, ThreatActorTenantDTO[]>();
    for (const t of tagsResp?.tags ?? []) {
      const arr = map.get(t.actorId) ?? [];
      arr.push(t);
      map.set(t.actorId, arr);
    }
    return map;
  }, [tagsResp]);

  const availableTenants = tagsResp?.available ?? [];

  const actors = data?.actors ?? [];
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    let arr = actors;
    if (q) {
      arr = arr.filter((a) =>
        a.primaryName.toLowerCase().includes(q) ||
        a.aliases.some((x) => x.toLowerCase().includes(q)) ||
        (a.mitreGroupId ?? "").toLowerCase().includes(q) ||
        a.profileId.toLowerCase().includes(q),
      );
    }
    if (!BATCH_ONE_RELEASE && clientFilter !== "all") {
      arr = arr.filter((a) => {
        const tags = tagsByActor.get(a.id) ?? [];
        if (clientFilter === "__untagged__") return tags.length === 0;
        return tags.some((t) => t.tenantId === clientFilter);
      });
    }
    return arr;
  }, [actors, search, clientFilter, tagsByActor]);

  return (
    <AppShell>
      <div className="px-4 md:px-10 py-6 md:py-8 max-w-[1400px]">
      <PageHeader
        title="Actor Observatory"
        description="Maintain threat actor profiles, TTPs, detection posture, and forecasted relevance for blue-team operations."
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center gap-1 rounded-md border bg-muted/30 p-0.5">
              <Button
                size="sm" variant={view === "list" ? "default" : "ghost"}
                onClick={() => setView("list")}
                data-testid="button-view-list"
                className="h-7 px-2"
              >
                <ListIcon size={14} className="mr-1" /> List
              </Button>
              <Button
                size="sm" variant={view === "kanban" ? "default" : "ghost"}
                onClick={() => setView("kanban")}
                data-testid="button-view-kanban"
                className="h-7 px-2"
              >
                <LayoutGrid size={14} className="mr-1" /> Kanban
              </Button>
            </div>
            <Button size="sm" onClick={() => setCreateOpen(true)} data-testid="button-create-tap">
              <Plus size={14} className="mr-1" /> New profile
            </Button>
          </div>
        }
      />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 mb-4">
        <div className="relative w-full sm:w-auto">
          <Input
            placeholder="Search by name / alias / MITRE id…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-9 w-full sm:w-72"
            data-testid="input-search-tap"
          />
        </div>
        <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as any)}>
          <SelectTrigger className="h-9 w-36" data-testid="select-status-filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="draft">Draft</SelectItem>
            <SelectItem value="reviewed">Reviewed</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="archived">Archived</SelectItem>
          </SelectContent>
        </Select>
        {!BATCH_ONE_RELEASE && (
          <Select value={clientFilter} onValueChange={(v) => setClientFilter(v as any)}>
            <SelectTrigger className="h-9 w-44" data-testid="select-client-filter">
              <SelectValue placeholder="Client relevance" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All clients</SelectItem>
              <SelectItem value="__untagged__">No client tagged</SelectItem>
              {availableTenants.map((t) => (
                <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {view === "kanban" && (
          <div className="flex items-center gap-1 rounded-md border bg-muted/30 p-0.5">
            <Button
              size="sm" variant={kanbanGroupBy === "status" ? "default" : "ghost"}
              onClick={() => setKanbanGroupBy("status")}
              data-testid="button-groupby-status"
              className="h-7 px-2 text-xs"
            >
              By status
            </Button>
            {!BATCH_ONE_RELEASE && (
              <Button
                size="sm" variant={kanbanGroupBy === "client" ? "default" : "ghost"}
                onClick={() => setKanbanGroupBy("client")}
                data-testid="button-groupby-client"
                className="h-7 px-2 text-xs"
              >
                By client
              </Button>
            )}
          </div>
        )}
        <div className="ml-auto text-xs text-muted-foreground">
          {filtered.length} of {actors.length} profile{actors.length === 1 ? "" : "s"}
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2 className="animate-spin mr-2" size={16} /> Loading profiles…
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState onCreate={() => setCreateOpen(true)} />
      ) : view === "list" ? (
        <div className="grid gap-3 grid-cols-1 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((a) => (
            <TapCard
              key={a.id}
              actor={a}
              tags={tagsByActor.get(a.id) ?? []}
              onOpen={() => setSelectedId(a.id)}
            />
          ))}
        </div>
      ) : (
        <KanbanBoard
          actors={filtered}
          tagsByActor={tagsByActor}
          availableTenants={availableTenants}
          groupBy={BATCH_ONE_RELEASE ? "status" : kanbanGroupBy}
          onOpen={setSelectedId}
        />
      )}

      <CreateTapDialog open={createOpen} onClose={() => setCreateOpen(false)} onCreated={(aid) => { setCreateOpen(false); setSelectedId(aid); }} />
      <DetailSheet actorId={selectedId} onClose={() => setSelectedId(null)} />
      </div>
    </AppShell>
  );
}

function EmptyState({ onCreate }: { onCreate: () => void }) {
  const provider = useEnrichProviderLabel();
  return (
    <Card className="p-12 text-center">
      <Skull className="mx-auto mb-3 text-muted-foreground" size={36} />
      <div className="text-base font-semibold mb-1">No threat actor profiles yet</div>
      <div className="text-sm text-muted-foreground mb-4">
        Create one from a primary name (e.g. <span className="font-mono">APT41</span>, <span className="font-mono">Scattered Spider</span>, <span className="font-mono">LockBit</span>) and {toMidSentence(provider)} will enrich all 13 sections.
      </div>
      <Button onClick={onCreate} data-testid="button-empty-create-tap">
        <Plus size={14} className="mr-1" /> Create your first profile
      </Button>
    </Card>
  );
}

// Tenant chip row — small pills for each tagged tenant. Falls back to a hint
// when the actor has no tags so analysts know to enrich or tag manually.
function TenantTagsRow({ tags, compact = false }: { tags: ThreatActorTenantDTO[]; compact?: boolean }) {
  if (BATCH_ONE_RELEASE) return null;
  if (tags.length === 0) {
    return (
      <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
        <Building2 size={10} /> No client tagged
      </div>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      {tags.slice(0, compact ? 2 : 4).map((t) => (
        <Badge
          key={t.id}
          className={cn(
            "text-[10px] font-medium px-1.5 py-0",
            RELEVANCE_BADGE[t.relevance],
          )}
          title={`${RELEVANCE_LABEL[t.relevance]}${t.rationale ? " — " + t.rationale : ""}`}
        >
          {t.tenantName ?? "Client"}
          {t.taggedByAi && <Sparkles size={9} className="ml-1 opacity-80" />}
        </Badge>
      ))}
      {tags.length > (compact ? 2 : 4) && (
        <Badge variant="outline" className="text-[10px] px-1.5 py-0">
          +{tags.length - (compact ? 2 : 4)}
        </Badge>
      )}
    </div>
  );
}

// ActorPortrait — deterministic, stylized "threat sigil" generated entirely
// in SVG from a hash of the actor name. Every actor gets a unique, art-like
// avatar (gradient orb + abstract glyph + initials overlay) with no API cost
// and no async latency. The hue rotates by threat level so escalation reads
// visually — cold blues for LOW, ambers for MODERATE, reds for HIGH/CRITICAL.
//
// This is the first-pass placeholder; an upgrade path to real AI portraits
// just needs to set `actor.portraitUrl` from a future backend endpoint and
// the component will prefer that over the generated sigil.
function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  }
  return h >>> 0;
}
/** Lazy-generate portrait on first viewport entry. We POST to
 *  /api/v1/threat-actors/:id/portrait at most ONCE per session per actor; the
 *  server coalesces parallel requests and the result is cached on the row, so
 *  subsequent loads see portraitUrl pre-populated and skip generation entirely.
 */
function useLazyPortrait(
  actorId: string | undefined,
  portraitUrl: string | null | undefined,
  portraitStatus: "idle" | "generating" | "ready" | "failed" | undefined,
) {
  const aiAvailability = useAiAvailability();
  const ref = useRef<HTMLDivElement | null>(null);
  const [resolvedUrl, setResolvedUrl] = useState<string | null>(portraitUrl ?? null);
  const [busy, setBusy] = useState(false);
  const firedRef = useRef(false);

  useEffect(() => {
    // Sync incoming prop changes (e.g. when list query refetches).
    setResolvedUrl(portraitUrl ?? null);
  }, [portraitUrl]);

  useEffect(() => {
    if (!actorId) return;
    if (!aiAvailability.hasUsableProvider) return;
    if (resolvedUrl) return;
    if (firedRef.current) return;
    if (portraitStatus === "failed") return; // don't auto-retry failures
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting && !firedRef.current) {
            firedRef.current = true;
            setBusy(true);
            apiRequest("POST", `/api/v1/threat-actors/${actorId}/portrait`)
              .then((r) => r.json())
              .then((data) => {
                if (data?.portraitUrl) setResolvedUrl(data.portraitUrl);
              })
              .catch(() => { /* silently fall back to SVG sigil */ })
              .finally(() => setBusy(false));
            io.disconnect();
          }
        }
      },
      { rootMargin: "200px" } // start generating just before the card scrolls into view
    );
    io.observe(el);
    return () => io.disconnect();
  }, [actorId, resolvedUrl, portraitStatus, aiAvailability.hasUsableProvider]);

  return { ref, resolvedUrl, busy };
}

function ActorPortrait({
  name, threatLevel, size = 64, portraitUrl, actorId, portraitStatus, editable,
}: {
  name: string;
  threatLevel?: string;
  size?: number;
  portraitUrl?: string | null;
  actorId?: string;
  portraitStatus?: "idle" | "generating" | "ready" | "failed";
  /** When true, render a hover-revealed camera button that opens a dropdown
   *  with Upload · Regenerate · Remove. The button uses stopPropagation so it
   *  doesn't trigger the surrounding card's onClick. */
  editable?: boolean;
}) {
  const { ref, resolvedUrl, busy } = useLazyPortrait(actorId, portraitUrl, portraitStatus);

  const h = hashString(name || "actor");
  // Threat-level hue bias — escalation flows from cool to hot.
  const baseHue = (() => {
    const t = (threatLevel || "MODERATE").toUpperCase();
    if (t === "CRITICAL" || t === "SEVERE") return 0;      // red
    if (t === "HIGH")                       return 18;     // orange
    if (t === "MODERATE" || t === "MEDIUM") return 32;     // amber
    if (t === "LOW")                        return 145;    // green-cyan
    return 220;                                            // blue
  })();
  // Add a per-actor hue jitter so two CRITICAL actors don't look identical.
  const hueA = (baseHue + (h % 30) - 15 + 360) % 360;
  const hueB = (hueA + 35) % 360;
  const initials = (name || "")
    .split(/[\s\-_]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0])
    .join("")
    .toUpperCase() || "?";
  // 3 decorative "glyph" arcs whose positions are seeded from the hash so each
  // actor gets a unique sigil that still looks part of the same family.
  const arcs = [0, 1, 2].map((i) => {
    const a = ((h >> (i * 5)) & 0xff) / 255;
    const b = ((h >> (i * 5 + 4)) & 0xff) / 255;
    return {
      cx: 32 + (a - 0.5) * 22,
      cy: 32 + (b - 0.5) * 22,
      r:  6 + ((h >> (i * 3)) & 7),
      op: 0.18 + i * 0.06,
    };
  });
  const gradId = `tap-grad-${h}`;

  // The SVG sigil is always rendered — either as the primary visual when no AI
  // portrait is available, or as a soft background that the AI portrait
  // crossfades on top of, so the card never shows a broken-image placeholder.
  const sigil = (
    <svg
      viewBox="0 0 64 64" width={size} height={size}
      className="rounded-full block"
      aria-label={`${name} portrait sigil`}
    >
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0"  stopColor={`hsl(${hueA} 82% 56%)`} />
          <stop offset="1"  stopColor={`hsl(${hueB} 70% 36%)`} />
        </linearGradient>
      </defs>
      <rect x="0" y="0" width="64" height="64" fill={`url(#${gradId})`} />
      {arcs.map((a, i) => (
        <circle
          key={i} cx={a.cx} cy={a.cy} r={a.r}
          fill="none" stroke="white" strokeWidth="1.5" strokeOpacity={a.op}
        />
      ))}
      <text
        x="32" y="38"
        textAnchor="middle"
        fontSize="22" fontWeight="700"
        fill="white"
        style={{ letterSpacing: "-0.02em" }}
      >
        {initials}
      </text>
    </svg>
  );

  // The circular portrait + (optional) hover-revealed camera button sit inside
  // a `group/portrait` wrapper. The button is OUTSIDE the rounded-full clip so
  // it can extend past the circle's edge without being clipped.
  const circle = (
    <div
      ref={ref}
      className="relative rounded-full ring-2 ring-border shadow-sm overflow-hidden"
      style={{ width: size, height: size }}
    >
      {sigil}
      {resolvedUrl && (
        <img
          src={resolveAssetUrl(resolvedUrl) ?? resolvedUrl}
          alt={`${name} portrait`}
          className="absolute inset-0 w-full h-full object-cover transition-opacity duration-500"
          style={{ opacity: 1 }}
          loading="lazy"
          onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = "none"; }}
        />
      )}
      {busy && !resolvedUrl && (
        <div className="absolute inset-0 flex items-center justify-center bg-black/30 backdrop-blur-[1px]">
          <Loader2 className="animate-spin text-white" size={Math.max(14, Math.round(size * 0.28))} />
        </div>
      )}
    </div>
  );

  if (!editable || !actorId) return circle;

  return (
    <div
      className="relative group/portrait"
      style={{ width: size, height: size }}
    >
      {circle}
      <PortraitActionMenu actorId={actorId} hasPortrait={!!resolvedUrl} size={size} />
    </div>
  );
}

// v2.32.1 — small dropdown menu attached to the portrait circle. Lets the
// analyst Upload an image / Regenerate the AI portrait / Remove the current
// portrait. The trigger is a circular camera button anchored to the bottom-
// right of the portrait. It's visible on hover (or always on touch devices)
// and uses stopPropagation so the surrounding card click handler stays put.
function PortraitActionMenu({
  actorId, hasPortrait, size,
}: { actorId: string; hasPortrait: boolean; size: number }) {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const { data: portraitGenerator } = useQuery<PortraitGeneratorAvailabilityResp>({
    queryKey: ["/api/v1/threat-actors/portrait-generator/availability"],
    staleTime: 60_000,
  });
  const portraitGeneratorUnavailable = portraitGenerator?.available === false;
  const aiDisabled = !aiAvailability.hasUsableProvider || portraitGeneratorUnavailable;
  const fileRef = useRef<HTMLInputElement | null>(null);
  const [busy, setBusy] = useState<"upload" | "regen" | "remove" | null>(null);

  const refreshActors = () => {
    // Both list and detail queries hang off /api/v1/threat-actors — invalidating
    // the list root re-fetches everything and propagates the new portraitUrl.
    queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors"] });
    queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors", actorId] });
  };

  const handleFile = async (file: File) => {
    if (!/^image\/(png|jpe?g|webp|gif)$/i.test(file.type)) {
      toast({ title: "Unsupported file type", description: "Use PNG, JPEG, WebP, or GIF.", variant: "destructive" });
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      toast({ title: "File too large", description: "Portrait images must be 5MB or smaller.", variant: "destructive" });
      return;
    }
    setBusy("upload");
    try {
      // Read as base64 — keeps us on the existing JSON upload pattern so we
      // don't need to introduce multer or multipart parsing on the server.
      const contentBase64 = await new Promise<string>((resolve, reject) => {
        const r = new FileReader();
        r.onerror = () => reject(r.error);
        r.onload = () => {
          const result = String(r.result || "");
          // result is `data:image/png;base64,AAAA...` — strip the prefix.
          const comma = result.indexOf(",");
          resolve(comma >= 0 ? result.slice(comma + 1) : result);
        };
        r.readAsDataURL(file);
      });
      await apiRequest("POST", `/api/v1/threat-actors/${actorId}/portrait/upload`, {
        fileName: file.name,
        contentBase64,
      });
      refreshActors();
      toast({ title: "Portrait uploaded", description: file.name });
    } catch (e: any) {
      toast({ title: "Upload failed", description: String(e?.message ?? e), variant: "destructive" });
    } finally {
      setBusy(null);
    }
  };

  const handleRegen = async () => {
    if (portraitGeneratorUnavailable) {
      toast({
        title: "Portrait generator unavailable",
        description: portraitGenerator?.message ?? portraitGenerator?.installHint ?? "Install asi-generate-image or upload a portrait image.",
        variant: "destructive",
      });
      return;
    }
    if (aiDisabled) {
      toast({ title: "AI Setup incomplete", description: aiAvailability.disabledReason, variant: "destructive" });
      return;
    }
    setBusy("regen");
    try {
      await apiRequest("POST", `/api/v1/threat-actors/${actorId}/portrait?force=true`);
      refreshActors();
      toast({ title: "AI portrait regenerated" });
    } catch (e: any) {
      toast({ title: "Regenerate failed", description: String(e?.message ?? e), variant: "destructive" });
    } finally {
      setBusy(null);
    }
  };

  const handleRemove = async () => {
    setBusy("remove");
    try {
      await apiRequest("DELETE", `/api/v1/threat-actors/${actorId}/portrait`);
      refreshActors();
      toast({ title: "Portrait removed" });
    } catch (e: any) {
      toast({ title: "Remove failed", description: String(e?.message ?? e), variant: "destructive" });
    } finally {
      setBusy(null);
    }
  };

  // Size the button proportionally to the portrait. 28px on the 72px card
  // avatar, 36px on the larger detail-view avatar.
  const btnSize = Math.max(24, Math.round(size * 0.36));

  return (
    <>
      <input
        ref={fileRef}
        type="file"
        accept="image/png,image/jpeg,image/webp,image/gif"
        className="sr-only"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) handleFile(f);
          // Reset so selecting the same file twice still fires onChange.
          e.target.value = "";
        }}
        data-testid={`input-portrait-file-${actorId}`}
      />
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            onClick={(e) => e.stopPropagation()}
            className={cn(
              "absolute bottom-0 right-0 inline-flex items-center justify-center rounded-full",
              "bg-foreground text-background shadow-md ring-2 ring-background",
              "opacity-0 group-hover/portrait:opacity-100 focus-visible:opacity-100",
              "transition-opacity hover:bg-foreground/90",
            )}
            style={{ width: btnSize, height: btnSize }}
            aria-label="Manage portrait"
            title="Manage portrait"
            data-testid={`button-portrait-menu-${actorId}`}
          >
            {busy ? (
              <Loader2 className="animate-spin" size={Math.round(btnSize * 0.5)} />
            ) : (
              <Camera size={Math.round(btnSize * 0.5)} />
            )}
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align="end"
          className="w-52"
          onClick={(e) => e.stopPropagation()}
        >
          <DropdownMenuItem
            onClick={(e) => { e.stopPropagation(); fileRef.current?.click(); }}
            data-testid={`menuitem-portrait-upload-${actorId}`}
          >
            <Upload size={14} className="mr-2" /> Upload image…
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={(e) => { e.stopPropagation(); handleRegen(); }}
            disabled={aiDisabled}
            title={portraitGeneratorUnavailable ? (portraitGenerator?.installHint ?? portraitGenerator?.message) : aiAvailability.disabledReason}
            data-testid={`menuitem-portrait-regen-${actorId}`}
          >
            <RefreshCw size={14} className="mr-2" /> Regenerate AI portrait
          </DropdownMenuItem>
          {hasPortrait && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={(e) => { e.stopPropagation(); handleRemove(); }}
                className="text-red-600 focus:text-red-600"
                data-testid={`menuitem-portrait-remove-${actorId}`}
              >
                <Trash2 size={14} className="mr-2" /> Remove portrait
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}

function formatStamp(iso: string): string {
  try {
    const d = new Date(iso);
    const pad = (n: number) => n.toString().padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  } catch { return ""; }
}

const TapCard = memo(function TapCard({
  actor, tags, onOpen,
}: { actor: ThreatActorDTO; tags: ThreatActorTenantDTO[]; onOpen: () => void }) {
  const isEnriched = (actor.execWhat ?? "").length > 0;
  return (
    <Card
      className="p-4 hover:shadow-md transition-shadow cursor-pointer relative"
      onClick={onOpen}
      data-testid={`card-tap-${actor.id}`}
    >
      {/* Top row: profile id (left) + last-updated stamp + status (right) */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="text-[10px] font-mono text-muted-foreground">{actor.profileId}</div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-muted-foreground/80 tabular-nums" title="Last updated">
            {formatStamp(actor.updatedAt)}
          </span>
          <Badge className={cn("text-[10px]", TAP_STATUS_BADGE[actor.status])}>{actor.status}</Badge>
        </div>
      </div>

      {/* Portrait — center-aligned, AI-style stylized sigil with a hover-
          revealed camera button for upload / regenerate / remove. */}
      <div className="flex justify-center mb-3">
        <ActorPortrait
          name={actor.primaryName}
          threatLevel={actor.threatLevel}
          portraitUrl={actor.portraitUrl}
          portraitStatus={actor.portraitStatus}
          actorId={actor.id}
          size={72}
          editable
        />
      </div>

      {/* Name + aliases row */}
      <div className="text-center mb-2">
        <div className="font-semibold truncate" data-testid={`text-tap-name-${actor.id}`}>{actor.primaryName}</div>
        {actor.mitreGroupId && (
          <div className="text-[11px] text-muted-foreground font-mono">{actor.mitreGroupId}</div>
        )}
      </div>

      {actor.aliases.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2 justify-center">
          {actor.aliases.slice(0, 4).map((a) => (
            <Badge key={a} variant="outline" className="text-[10px] font-normal">{a}</Badge>
          ))}
          {actor.aliases.length > 4 && (
            <Badge variant="outline" className="text-[10px] font-normal">+{actor.aliases.length - 4}</Badge>
          )}
        </div>
      )}

      {!BATCH_ONE_RELEASE && (
        <div className="mb-3">
          <TenantTagsRow tags={tags} />
        </div>
      )}

      <div className="grid grid-cols-3 gap-2 text-xs">
        <div>
          <div className="text-[9px] uppercase tracking-wider text-muted-foreground">Threat</div>
          <Badge className={cn("text-[10px] mt-0.5", THREAT_LEVEL_BADGE[actor.threatLevel])}>{actor.threatLevel}</Badge>
        </div>
        <div>
          <div className="text-[9px] uppercase tracking-wider text-muted-foreground">TLP</div>
          <Badge className={cn("text-[10px] mt-0.5", TLP_BADGE[actor.tlp])}>{actor.tlp}</Badge>
        </div>
        <div>
          <div className="text-[9px] uppercase tracking-wider text-muted-foreground">Type</div>
          <div className="text-[11px] mt-0.5 truncate">{ACTOR_TYPE_LABEL[actor.actorType]}</div>
        </div>
      </div>

      <div className="mt-3 pt-3 border-t flex items-center justify-between text-[11px] text-muted-foreground">
        <span>v{actor.version} · {relativeTime(actor.updatedAt)}</span>
        {isEnriched ? (
          <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 size={11} /> AI-enriched
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400">
            <Clock size={11} /> Shell — needs enrichment
          </span>
        )}
      </div>
      {!BATCH_ONE_RELEASE && (
        <div className="mt-2" onClick={(e) => e.stopPropagation()}>
          <StartInvestigationButton
            entityType="threat_actor"
            entityId={actor.id}
            title={actor.primaryName}
            severity={actor.threatLevel}
            summary={actor.execWhat}
            className="h-7 px-2 text-[11px]"
          />
        </div>
      )}
    </Card>
  );
});

// ---- Kanban (real DnD) ------------------------------------------------------
// v2.30.5 replaces the previous static columns with @dnd-kit drag and drop.
// Two grouping modes: by status (PATCH /threat-actors/:aid { status }) and by
// client (POST /threat-actors/:aid/tenants to retag). Dropping is optimistic
// — the card moves immediately and we rollback on error.

// Stable, lightweight card body shared between the column list and the drag
// overlay so the dragging visual is identical to the source.
const KanbanCardBody = memo(function KanbanCardBody({
  actor, tags,
}: { actor: ThreatActorDTO; tags: ThreatActorTenantDTO[] }) {
  return (
    <>
      <div className="font-mono text-[9px] text-muted-foreground">{actor.profileId}</div>
      <div className="font-semibold truncate text-xs">{actor.primaryName}</div>
      <div className="flex items-center gap-1 mt-1">
        <Badge className={cn("text-[9px] px-1 py-0", THREAT_LEVEL_BADGE[actor.threatLevel])}>{actor.threatLevel}</Badge>
        <Badge className={cn("text-[9px] px-1 py-0", TLP_BADGE[actor.tlp])}>{actor.tlp}</Badge>
      </div>
      {tags.length > 0 && (
        <div className="mt-1.5"><TenantTagsRow tags={tags} compact /></div>
      )}
    </>
  );
});

function KanbanCard({
  actor, tags, onOpen,
}: { actor: ThreatActorDTO; tags: ThreatActorTenantDTO[]; onOpen: (id: string) => void }) {
  // v2.30.6 — entire card is draggable so users don't have to find the
  // grip icon. A pointer-down tracker disambiguates click-to-open from
  // drag-to-move: if the pointer moved more than the dnd-kit activation
  // distance, we suppress the click; otherwise we treat it as an open.
  const { attributes, listeners, setNodeRef, isDragging } = useDraggable({ id: actor.id });
  const downRef = useRef<{ x: number; y: number; moved: boolean } | null>(null);

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    downRef.current = { x: e.clientX, y: e.clientY, moved: false };
  };
  const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const d = downRef.current;
    if (!d) return;
    if (Math.abs(e.clientX - d.x) > 4 || Math.abs(e.clientY - d.y) > 4) d.moved = true;
  };
  const onClick = (e: React.MouseEvent) => {
    const d = downRef.current;
    downRef.current = null;
    if (d?.moved) {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    onOpen(actor.id);
  };

  return (
    <Card
      ref={setNodeRef}
      className={cn(
        // touch-none disables browser scroll on touch drag
        "p-2 hover:shadow text-xs touch-none cursor-grab active:cursor-grabbing",
        isDragging && "opacity-40",
      )}
      data-testid={`kanban-card-${actor.id}`}
      {...attributes}
      {...listeners}
      onPointerDownCapture={onPointerDown}
      onPointerMoveCapture={onPointerMove}
      onClick={onClick}
    >
      <div className="flex items-start gap-1">
        {/* Small grip kept as a visual affordance only — dragging works anywhere on the card. */}
        <span
          aria-hidden
          className="shrink-0 mt-0.5 text-muted-foreground/60"
          data-testid={`kanban-drag-${actor.id}`}
        >
          <GripVertical size={12} />
        </span>
        <div className="min-w-0 flex-1">
          <KanbanCardBody actor={actor} tags={tags} />
        </div>
      </div>
    </Card>
  );
}

function KanbanColumn({
  id, label, count, tone, children,
}: {
  id: string; label: string; count: number; tone: KdotTone; children: React.ReactNode;
}) {
  const { setNodeRef, isOver } = useDroppable({ id });
  return (
    <div
      ref={setNodeRef}
      className={cn(
        "flex flex-col rounded-card border bg-muted/20 transition-colors min-w-[260px]",
        isOver && "ring-2 ring-brand/40 bg-brand/5 border-brand/30",
      )}
      data-testid={`kanban-col-${id}`}
    >
      <div className="flex items-center gap-2 px-4 py-3 border-b">
        <span className={cn("inline-block h-2 w-2 rounded-full os-kdot", `os-kdot-${tone}`)} aria-hidden />
        <span className="os-mono text-[12px] font-semibold tracking-[0.08em] uppercase truncate">{label}</span>
        <span className="os-mono text-[12px] text-muted-foreground tabular-nums">{count}</span>
      </div>
      <div className="flex-1 p-2 space-y-2 max-h-[70vh] overflow-y-auto">
        {children}
      </div>
    </div>
  );
}

interface KanbanColDef {
  id: string;
  label: string;
  tone: KdotTone;
}

function KanbanBoard({
  actors, tagsByActor, availableTenants, groupBy, onOpen,
}: {
  actors: ThreatActorDTO[];
  tagsByActor: Map<string, ThreatActorTenantDTO[]>;
  availableTenants: Array<{ id: string; name: string; sector: string | null; region: string | null; orgSize: string | null }>;
  groupBy: "status" | "client";
  onOpen: (id: string) => void;
}) {
  const { toast } = useToast();
  const [activeId, setActiveId] = useState<string | null>(null);

  // v2.30.6 — since the whole card is draggable, we use:
  //   - PointerSensor with distance: 4 so a static click still opens the
  //     detail sheet (no drag fires under 4px of movement)
  //   - TouchSensor with a 200ms delay so users can still scroll the kanban
  //     on mobile without accidentally dragging cards; long-press starts the
  //     drag.
  //   - KeyboardSensor for accessibility (space to pick up, arrows to move).
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(TouchSensor, { activationConstraint: { delay: 200, tolerance: 8 } }),
    useSensor(KeyboardSensor),
  );

  // Build columns + a lookup function from groupBy mode.
  const cols: KanbanColDef[] = useMemo(() => {
    if (groupBy === "status") {
      return KANBAN_COLS.map((c) => ({ id: `status:${c.id}`, label: c.label, tone: c.tone }));
    }
    const clientCols: KanbanColDef[] = availableTenants.map((t) => ({
      id: `client:${t.id}`,
      label: t.name.toUpperCase(),
      tone: "indigo" as KdotTone,
    }));
    clientCols.push({
      id: `client:__untagged__`,
      label: "NOT TAGGED",
      tone: "muted" as KdotTone,
    });
    return clientCols;
  }, [groupBy, availableTenants]);

  // Group actors into their columns. Actors may appear in multiple client
  // columns (if tagged against multiple tenants), but only once per status
  // column.
  const itemsByCol = useMemo(() => {
    const map = new Map<string, ThreatActorDTO[]>();
    for (const col of cols) map.set(col.id, []);
    for (const a of actors) {
      if (groupBy === "status") {
        const key = `status:${a.status}`;
        if (map.has(key)) map.get(key)!.push(a);
      } else {
        const tags = tagsByActor.get(a.id) ?? [];
        if (tags.length === 0) {
          map.get(`client:__untagged__`)?.push(a);
        } else {
          for (const t of tags) {
            const key = `client:${t.tenantId}`;
            if (map.has(key)) map.get(key)!.push(a);
          }
        }
      }
    }
    return map;
  }, [actors, cols, groupBy, tagsByActor]);

  const activeActor = useMemo(() => actors.find((a) => a.id === activeId) ?? null, [actors, activeId]);

  // Status mutation — PATCH /threat-actors/:aid { status }. Optimistic: we
  // patch the cached list in place and rollback on error.
  const statusMut = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: TapStatus }) => {
      const r = await apiRequest("PATCH", `/api/v1/threat-actors/${id}`, { status });
      return r.json();
    },
    onMutate: async ({ id, status }) => {
      await queryClient.cancelQueries({ queryKey: ["/api/v1/threat-actors"] });
      const snapshots: Array<[unknown, any]> = [];
      queryClient.getQueriesData<{ actors: ThreatActorDTO[] }>({ queryKey: ["/api/v1/threat-actors"] }).forEach(([key, value]) => {
        if (!value?.actors) return;
        snapshots.push([key, value]);
        queryClient.setQueryData(key, {
          ...value,
          actors: value.actors.map((a) => (a.id === id ? { ...a, status } : a)),
        });
      });
      return { snapshots };
    },
    onError: (e: any, _vars, ctx) => {
      ctx?.snapshots?.forEach(([key, value]) => queryClient.setQueryData(key as readonly unknown[], value));
      toast({ title: "Move failed", description: String(e?.message ?? e), variant: "destructive" });
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors"] });
    },
  });

  // Tenant tag mutation — POST /threat-actors/:aid/tenants (upsert behaviour
  // in the route handler, so dropping onto an existing column just refreshes
  // its relevance to "watching").
  const clientMut = useMutation({
    mutationFn: async ({ actorId, tenantId }: { actorId: string; tenantId: string }) => {
      const r = await apiRequest("POST", `/api/v1/threat-actors/${actorId}/tenants`, {
        tenantId,
        relevance: "watching",
        rationale: "Tagged via kanban drag-and-drop",
      });
      return r.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors-tenant-tags"] });
    },
    onError: (e: any) => toast({
      title: "Tag failed",
      description: String(e?.message ?? e),
      variant: "destructive",
    }),
  });

  const handleStart = useCallback((e: DragStartEvent) => {
    setActiveId(String(e.active.id));
  }, []);

  const handleEnd = useCallback((e: DragEndEvent) => {
    setActiveId(null);
    if (!e.over) return;
    const actorId = String(e.active.id);
    const overId = String(e.over.id);
    if (groupBy === "status") {
      const newStatus = overId.replace(/^status:/, "") as TapStatus;
      const current = actors.find((a) => a.id === actorId);
      if (!current || current.status === newStatus) return;
      statusMut.mutate({ id: actorId, status: newStatus });
    } else {
      const tenantId = overId.replace(/^client:/, "");
      if (tenantId === "__untagged__") return; // can't drop into untagged
      clientMut.mutate({ actorId, tenantId });
    }
  }, [actors, groupBy, statusMut, clientMut]);

  return (
    <DndContext sensors={sensors} collisionDetection={closestCorners} onDragStart={handleStart} onDragEnd={handleEnd}>
      {/* Horizontal scroll on narrow viewports keeps every column reachable. */}
      <div className="flex gap-3 overflow-x-auto pb-2 snap-x">
        {cols.map((col) => {
          const items = itemsByCol.get(col.id) ?? [];
          return (
            <div key={col.id} className="snap-start shrink-0 w-[280px] md:w-[300px]">
              <KanbanColumn id={col.id} label={col.label} count={items.length} tone={col.tone}>
                {items.length === 0 ? (
                  <div className="text-center text-[11px] text-muted-foreground py-4">
                    Drop a profile here
                  </div>
                ) : (
                  items.map((a) => (
                    <KanbanCard
                      key={col.id + ":" + a.id}
                      actor={a}
                      tags={tagsByActor.get(a.id) ?? []}
                      onOpen={onOpen}
                    />
                  ))
                )}
              </KanbanColumn>
            </div>
          );
        })}
      </div>
      {/* Drag overlay — fixed-position ghost that follows the cursor smoothly
          even when columns reflow. This is what makes the drag feel snappy. */}
      <DragOverlay>
        {activeActor ? (
          <Card className="p-2 text-xs shadow-lg ring-2 ring-primary/40 bg-background w-[260px]">
            <KanbanCardBody actor={activeActor} tags={tagsByActor.get(activeActor.id) ?? []} />
          </Card>
        ) : null}
      </DragOverlay>
    </DndContext>
  );
}

// ---- Create dialog ---------------------------------------------------------
function CreateTapDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (aid: string) => void }) {
  const { toast } = useToast();
  const provider = useEnrichProviderLabel();
  const exerciseProvider = useAiTaskProviderLabel("exercise_generation");
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const [primaryName, setPrimaryName] = useState("");
  const [aliasesText, setAliasesText] = useState("");
  const [enrichNow, setEnrichNow] = useState(true);

  useEffect(() => {
    if (!open) {
      setPrimaryName(""); setAliasesText(""); setEnrichNow(true);
    }
  }, [open]);

  const create = useMutation({
    mutationFn: async () => {
      const aliases = aliasesText.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
      const r = await apiRequest("POST", "/api/v1/threat-actors", {
        primaryName: primaryName.trim(),
        aliases,
        enrich: enrichNow && !aiDisabled,
      });
      return r.json() as Promise<CreateResp>;
    },
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors"] });
      const aid = resp.actor?.id ?? resp.id ?? null;
      if (aid) {
        if (resp.enriched) {
          queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors", aid, "full"] });
          toast({
            title: resp.existing ? "Existing profile enriched" : "Profile created and enriched",
            description: `${resp.providerLabel ?? provider} populated all TAP sections.`,
          });
        } else {
          toast({ title: resp.existing ? "Existing profile opened" : "Profile created" });
        }
        onCreated(aid);
      }
    },
    onError: (e: any) => toast({ title: "Failed", description: String(e?.message ?? e), variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && !create.isPending && onClose()}>
      <DialogContent data-testid="dialog-create-tap">
        <DialogHeader>
          <DialogTitle>New threat actor profile</DialogTitle>
          <DialogDescription>
            Provide a primary name and optional aliases. {provider} will enrich Exec Summary, Identity, Victimology, Capability, TTPs, Diamond Model, Campaigns, Infrastructure, IR Actions, Countermeasures, Forecast, IOCs and References.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
            <div>
              <label className="text-xs font-medium mb-1 block">Primary name <span className="text-red-500">*</span></label>
              <Input
                value={primaryName}
                onChange={(e) => setPrimaryName(e.target.value)}
                placeholder="e.g. APT41 / Scattered Spider / LockBit"
                autoFocus
                data-testid="input-primary-name"
              />
            </div>
            <div>
              <label className="text-xs font-medium mb-1 block">Aliases (one per line or comma-separated)</label>
              <Textarea
                value={aliasesText}
                onChange={(e) => setAliasesText(e.target.value)}
                placeholder="Brass Typhoon&#10;UNC3944&#10;0ktapus"
                rows={3}
                data-testid="textarea-aliases"
              />
            </div>
            <div className="flex items-center gap-2 pt-1">
              <Checkbox
                id="enrich-now"
                checked={enrichNow}
                onCheckedChange={(v) => setEnrichNow(!!v)}
                disabled={aiDisabled}
                data-testid="checkbox-enrich-now"
              />
              <label htmlFor="enrich-now" className="text-sm cursor-pointer">
                {aiDisabled ? aiAvailability.disabledReason : <>Enrich now with {toMidSentence(provider)} (recommended — may take up to 9 minutes)</>}
              </label>
            </div>
          {create.isPending && enrichNow && (
            <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
              <Loader2 className="mr-2 inline animate-spin" size={13} />
              Sending profile context to {provider}; this request stays open until the provider returns.
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={create.isPending}>Cancel</Button>
          <Button
            onClick={() => create.mutate()}
            disabled={!primaryName.trim() || create.isPending || (enrichNow && aiDisabled)}
            title={enrichNow ? aiAvailability.disabledReason : undefined}
            data-testid="button-submit-create-tap"
          >
            {create.isPending
              ? <><Loader2 className="animate-spin mr-1" size={14} /> {enrichNow ? "Enriching…" : "Creating…"}</>
              : "Create profile"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---- TAP detail sheet helpers (v2.30.6) ------------------------------------
//
// Sub-tab layout switched from a single horizontally-scrolling pill strip to
// a grouped vertical rail (variant A in the proposals deck). Eighteen
// sections grouped into six categories so the analyst can scan the full
// outline at a glance and click directly to the one they want — no more
// "swipe-and-pray" tab strip.

interface TabDef { id: string; label: string; icon?: React.ReactNode }
interface TabGroupDef { id: string; label: string; dot: string; tabs: TabDef[] }

const TAB_GROUPS: TabGroupDef[] = [
  { id: "briefing",  label: "Briefing",       dot: "bg-teal-500",    tabs: [
    { id: "exec",       label: "Executive brief", icon: <BookOpen size={11} className="mr-1" /> },
    { id: "identity",   label: "Identity & aliases", icon: <Tag size={11} className="mr-1" /> },
    { id: "victim",     label: "Targeting", icon: <Target size={11} className="mr-1" /> },
    { id: "relevance",  label: "Client relevance", icon: <Building2 size={11} className="mr-1" /> },
  ]},
  { id: "tradecraft", label: "Tradecraft",    dot: "bg-violet-500",  tabs: [
    { id: "capability", label: "Capabilities", icon: <Sparkles size={11} className="mr-1" /> },
    { id: "ttps",       label: "ATT&CK TTPs", icon: <Crosshair size={11} className="mr-1" /> },
    { id: "diamond",    label: "Diamond model", icon: <LayoutGrid size={11} className="mr-1" /> },
    { id: "campaigns",  label: "Campaigns", icon: <Calendar size={11} className="mr-1" /> },
  ]},
  { id: "evidence",   label: "Evidence",       dot: "bg-blue-500",   tabs: [
    { id: "infra",      label: "Infrastructure", icon: <Network size={11} className="mr-1" /> },
    { id: "iocs",       label: "Indicators", icon: <AlertCircle size={11} className="mr-1" /> },
    { id: "refs",       label: "Sources", icon: <FileText size={11} className="mr-1" /> },
  ]},
  { id: "defence",    label: "Defence",       dot: "bg-emerald-500", tabs: [
    { id: "detection",  label: "Detection coverage", icon: <Shield size={11} className="mr-1" /> },
    { id: "ir",         label: "IR playbook", icon: <ListChecks size={11} className="mr-1" /> },
    { id: "counter",    label: "Controls", icon: <CheckCircle2 size={11} className="mr-1" /> },
  ]},
  { id: "assessment", label: "Assessment",    dot: "bg-amber-500",   tabs: [
    { id: "forecast",   label: "Forecast", icon: <Activity size={11} className="mr-1" /> },
    { id: "confidence", label: "Confidence", icon: <Clock size={11} className="mr-1" /> },
  ]},
  { id: "meta",       label: "Meta",          dot: "bg-slate-400",   tabs: [
    { id: "stix",       label: "STIX export", icon: <Download size={11} className="mr-1" /> },
    { id: "version",    label: "Versioning", icon: <FileDown size={11} className="mr-1" /> },
  ]},
];

const ACTIVE_TAB_GROUPS: TabGroupDef[] = BATCH_ONE_RELEASE
  ? TAB_GROUPS.map((g) => ({
      ...g,
      tabs: g.tabs.filter((t) => t.id !== "relevance"),
    })).filter((g) => g.tabs.length > 0)
  : TAB_GROUPS;

const ALL_TAB_IDS: string[] = ACTIVE_TAB_GROUPS.flatMap((g) => g.tabs.map((t) => t.id));

const TAB_CONTEXT: Record<string, { title: string; purpose: string; principle: string }> = {
  exec: {
    title: "Executive threat brief",
    purpose: "Frame who the actor is, why they matter, and which actions should happen next.",
    principle: "One-page briefing: who, motivation, recent risk, priority actions.",
  },
  identity: {
    title: "Identity, aliases, and attribution",
    purpose: "Separate known identity, vendor naming, sponsorship, origin, and confidence so analysts avoid alias conflation.",
    principle: "Attribution is probabilistic; preserve source and confidence qualifiers.",
  },
  victim: {
    title: "Targeting and victimology",
    purpose: "Show sector, geography, organization-size, and technology alignment against the client environment.",
    principle: "Prioritize actors by sector and technology relevance, not notoriety alone.",
  },
  relevance: {
    title: "Client relevance",
    purpose: "Map the actor to tenant exposure, sector fit, and analyst-owned rationale.",
    principle: "Profiles become operational when tied to named clients and business context.",
  },
  capability: {
    title: "Capabilities and tooling",
    purpose: "Summarize malware, tooling, access methods, and operational maturity.",
    principle: "Prefer durable capabilities over short-lived infrastructure.",
  },
  ttps: {
    title: "ATT&CK tradecraft",
    purpose: "Group observed techniques by tactic so SOC teams can hunt, tune logging, and close detection gaps.",
    principle: "TTPs are the durable behavioral fingerprint; use them ahead of IOCs.",
  },
  diamond: {
    title: "Diamond model",
    purpose: "Connect adversary, capability, infrastructure, and victim dimensions in one analytic frame.",
    principle: "Use the model to challenge assumptions and expose missing evidence.",
  },
  campaigns: {
    title: "Campaign history",
    purpose: "Track operations, periods, initial access, targets, and outcomes to identify actor evolution.",
    principle: "Profiles stale quickly unless campaign history is maintained.",
  },
  infra: {
    title: "Infrastructure patterns",
    purpose: "Capture hosting, C2, phishing, relay, and delivery infrastructure patterns without over-weighting volatile IOCs.",
    principle: "Infrastructure rotates; patterns and procedures last longer.",
  },
  iocs: {
    title: "Indicators",
    purpose: "Provide actionable indicators with confidence, TLP, lifetime, and recommended response.",
    principle: "Treat IOCs as enrichment and scoping aids, not the profile backbone.",
  },
  refs: {
    title: "Source references",
    purpose: "Keep profile claims traceable to reports, advisories, ISAC notes, and internal observations.",
    principle: "Every strong claim should have evidence or a confidence caveat.",
  },
  detection: {
    title: "Detection coverage",
    purpose: "Show mapped rules and coverage posture so gaps can become Sigma, KQL, SPL, or hunt work.",
    principle: "Compare actor TTPs against detection coverage and prioritize no-rule gaps.",
  },
  ir: {
    title: "Incident response playbook",
    purpose: "Translate profile knowledge into containment, triage, scoping, and communications actions.",
    principle: "During incidents, contain first; attribution refinement can wait.",
  },
  counter: {
    title: "Countermeasures",
    purpose: "List prevention, hardening, monitoring, and compensating controls mapped to actor behavior.",
    principle: "Controls should answer the observed TTPs and exposed client technologies.",
  },
  forecast: {
    title: "Forecast and business impact",
    purpose: "Assess likely actor evolution, extortion pressure, and business consequences.",
    principle: "Forecasts should be qualified by confidence and recency.",
  },
  confidence: {
    title: "Confidence and handling",
    purpose: "Expose TLP, Admiralty, WEP confidence, cut-off date, and preparation metadata.",
    principle: "Distribution and decision-making depend on source reliability and information credibility.",
  },
  stix: {
    title: "STIX package",
    purpose: "Package the actor profile and indicators for downstream TIP/SIEM exchange.",
    principle: "Structured export should preserve identity, markings, and object relationships.",
  },
  version: {
    title: "Version and audit metadata",
    purpose: "Show creation, update, cut-off, status, and preparation metadata for governance.",
    principle: "Quarterly profile review prevents stale adversary assumptions.",
  },
};

/** Vertical grouped tab rail used on lg+ viewports. */
function TabRail({
  activeTab, onSelect,
}: { activeTab: string; onSelect: (id: string) => void }) {
  return (
    <nav className="py-3 px-2" aria-label="Sections" data-testid="tap-tab-rail">
      {ACTIVE_TAB_GROUPS.map((g) => (
        <div key={g.id} className="mb-3">
          <div className="flex items-center gap-1.5 px-2 mb-1 text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
            <span className={cn("w-1.5 h-1.5 rounded-full", g.dot)} aria-hidden />
            {g.label}
          </div>
          <div className="space-y-0.5">
            {g.tabs.map((t) => {
              const on = t.id === activeTab;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => onSelect(t.id)}
                  data-testid={`tab-${t.id}`}
                  className={cn(
                    "w-full text-left text-[12px] px-2 py-1.5 rounded flex items-center transition-colors",
                    on
                      ? "bg-primary text-primary-foreground font-medium"
                      : "text-foreground/80 hover:bg-accent hover:text-foreground",
                  )}
                >
                  {t.icon}
                  <span>{t.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}

function TapDossierAside({ a }: { a: ThreatActorFullDTO }) {
  const topTactics = useMemo(() => {
    const counts = new Map<string, number>();
    for (const t of a.ttps) counts.set(t.tactic, (counts.get(t.tactic) ?? 0) + 1);
    return Array.from(counts.entries())
      .sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))
      .slice(0, 4);
  }, [a.ttps]);
  const activeCampaigns = a.campaigns.length;
  const sourceCount = a.references.length;
  const ruleCount = a.ruleLinks.length;
  const uncovered = Math.max(0, a.ttps.length - ruleCount);
  const analystPriority = a.threatLevel === "CRITICAL" || uncovered >= 5
    ? "Escalate"
    : a.threatLevel === "HIGH" || uncovered >= 2
      ? "Hunt"
      : "Monitor";
  const priorityReason = uncovered > 0
    ? `${uncovered} TTP${uncovered === 1 ? "" : "s"} without mapped rules`
    : `${ruleCount} mapped rule${ruleCount === 1 ? "" : "s"} in profile`;

  return (
    <div className="border-b bg-background/80 p-4">
      <div className="flex flex-col items-center text-center">
        <ActorPortrait
          name={a.primaryName}
          threatLevel={a.threatLevel}
          portraitUrl={a.portraitUrl}
          portraitStatus={a.portraitStatus}
          actorId={a.id}
          size={112}
          editable
        />
        <div className="mt-3 font-semibold leading-tight">{a.primaryName}</div>
        <div className="mt-1 text-[11px] text-muted-foreground font-mono">
          {a.mitreGroupId || a.profileId}
        </div>
        <div className="mt-3 flex flex-wrap justify-center gap-1.5">
          <Badge className={cn("text-[10px]", THREAT_LEVEL_BADGE[a.threatLevel])}>{a.threatLevel}</Badge>
          <Badge className={cn("text-[10px]", TLP_BADGE[a.tlp])}>TLP:{a.tlp}</Badge>
          <Badge variant="outline" className="text-[10px]">WEP {a.wepConfidence}</Badge>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-2">
        <TapAsideMetric label="TTPs" value={a.ttps.length} />
        <TapAsideMetric label="Rules" value={ruleCount} />
        <TapAsideMetric label="Sources" value={sourceCount} />
      </div>

      <div className="mt-4 space-y-3 text-xs">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Analyst lens</div>
          <div className="rounded-lg border bg-muted/30 p-2 leading-relaxed text-muted-foreground">
            Use identity cautiously, prioritize TTPs for hunting, then compare techniques against detection coverage.
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Analyst priority</div>
          <div className="rounded-lg border border-primary/15 bg-primary/5 p-2">
            <div className="font-semibold text-primary">{analystPriority}</div>
            <div className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">{priorityReason}</div>
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Top tactics</div>
          {topTactics.length === 0 ? (
            <div className="text-muted-foreground italic">No ATT&CK tactics mapped.</div>
          ) : (
            <div className="flex flex-wrap gap-1">
              {topTactics.map(([tactic, count]) => (
                <Badge key={tactic} variant="secondary" className="text-[10px]">
                  {tactic} {count}
                </Badge>
              ))}
            </div>
          )}
        </div>
        <div className="grid grid-cols-2 gap-2">
          <TapAsideMetric label="Campaigns" value={activeCampaigns} />
          <TapAsideMetric label="IOCs" value={a.iocs.length} />
        </div>
      </div>
    </div>
  );
}

function TapAsideMetric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border bg-card/70 px-2 py-2 text-center">
      <div className="text-sm font-semibold">{value}</div>
      <div className="text-[9px] uppercase tracking-wider text-muted-foreground">{label}</div>
    </div>
  );
}

function TapTabContextHeader({ activeTab, a }: { activeTab: string; a: ThreatActorFullDTO }) {
  const meta = TAB_CONTEXT[activeTab] ?? TAB_CONTEXT.exec;
  const contextStats: Record<string, React.ReactNode> = {
    exec: `${a.threatLevel} · ${a.status}`,
    identity: `${a.aliases.length} aliases`,
    victim: `${a.targetSectors.length} sectors · ${a.targetRegions.length} regions`,
    relevance: `${a.relevantTenants?.length ?? 0} clients`,
    capability: `${a.tools.length} tools`,
    ttps: `${a.ttps.length} techniques`,
    diamond: "4 model dimensions",
    campaigns: `${a.campaigns.length} campaigns`,
    infra: "Pattern profile",
    iocs: `${a.iocs.length} indicators`,
    refs: `${a.references.length} sources`,
    detection: `${a.ruleLinks.length} mapped rules`,
    ir: "Response actions",
    counter: "Controls",
    forecast: a.cutoffDate ? `Cut-off ${a.cutoffDate}` : "Forecast",
    confidence: `Admiralty ${a.admiraltySource}/${a.admiraltyInfo}`,
    stix: `${a.iocs.length + 1} objects`,
    version: `v${a.version}`,
  };

  return (
    <div className="mb-4 rounded-xl border bg-card/80 p-4 shadow-sm">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <div className="text-[10px] uppercase tracking-wider text-primary font-semibold">Threat actor dossier</div>
          <h3 className="mt-1 text-base font-semibold">{meta.title}</h3>
          <p className="mt-1 text-sm text-muted-foreground leading-relaxed">{meta.purpose}</p>
        </div>
        <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
          {contextStats[activeTab] ?? a.profileId}
        </Badge>
      </div>
      <div className="mt-3 border-t pt-3 text-xs text-muted-foreground">
        <span className="font-medium text-foreground">Profiling principle:</span> {meta.principle}
      </div>
    </div>
  );
}

/** Mobile/tablet fallback — group dropdown + sub-pills (variant B from the proposals deck). */
function TabRailCompact({
  activeTab, onSelect,
}: { activeTab: string; onSelect: (id: string) => void }) {
  const activeGroup = ACTIVE_TAB_GROUPS.find((g) => g.tabs.some((t) => t.id === activeTab)) ?? ACTIVE_TAB_GROUPS[0];
  return (
    <div className="border-b bg-background" data-testid="tap-tab-rail-compact">
      <div className="px-3 pt-2 flex flex-wrap gap-1">
        {ACTIVE_TAB_GROUPS.map((g) => {
          const on = g.id === activeGroup.id;
          return (
            <button
              key={g.id}
              type="button"
              onClick={() => onSelect(g.tabs[0]?.id ?? "exec")}
              data-testid={`tab-group-${g.id}`}
              className={cn(
                "text-[11px] rounded-t-md px-2.5 py-1.5 border-b-2 flex items-center gap-1.5",
                on ? "border-primary text-foreground font-semibold" : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <span className={cn("w-1.5 h-1.5 rounded-full", g.dot)} aria-hidden />
              {g.label}
              <span className="text-[9px] text-muted-foreground/70">{g.tabs.length}</span>
            </button>
          );
        })}
      </div>
      <div className="px-3 py-2 flex gap-1 overflow-x-auto">
        {activeGroup.tabs.map((t) => {
          const on = t.id === activeTab;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => onSelect(t.id)}
              data-testid={`tab-${t.id}`}
              className={cn(
                "text-[11px] rounded-full px-2.5 py-1 whitespace-nowrap flex items-center",
                on ? "bg-foreground text-background" : "bg-secondary text-secondary-foreground hover:bg-accent",
              )}
            >
              {t.icon}
              {t.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/** Provider picker dropdown shown next to the Re-enrich button. */
function ProviderPicker({
  providers, value, onChange, disabled,
}: {
  providers: AiProviderSummary[];
  value: string | null;
  onChange: (id: string | null) => void;
  disabled?: boolean;
}) {
  if (!providers.length) return null;
  return (
    <Select
      value={value ?? "__default__"}
      onValueChange={(v) => onChange(v === "__default__" ? null : v)}
      disabled={disabled}
    >
      <SelectTrigger
        className="h-8 w-[140px] text-[11px]"
        data-testid="select-enrich-provider"
      >
        <SelectValue placeholder="Default provider" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="__default__">Default (AI Setup)</SelectItem>
        {providers.filter((p) => p.enabled && p.hasKey && p.lastTestOk === true).map((p) => (
          <SelectItem key={p.id} value={p.id}>
            {p.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}


// ---- Detail sheet ----------------------------------------------------------
function DetailSheet({ actorId, onClose }: { actorId: string | null; onClose: () => void }) {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const [activeTab, setActiveTab] = useState("exec");
  const [overrideProviderId, setOverrideProviderId] = useState<string | null>(null);

  // v2.30.7: full inline edit mode — one toggle, all tabs editable, one PATCH on save.
  const [editMode, setEditMode] = useState(false);
  const [draft, setDraft] = useState<EditDraft>({});
  const setField = useCallback((patch: EditDraft) => setDraft((d) => ({ ...d, ...patch })), []);

  // Reset all local edit state when the sheet closes (actorId → null) so reopening starts clean.
  useEffect(() => {
    if (!actorId) {
      setEditMode(false);
      setDraft({});
    }
  }, [actorId]);

  const { data: full, isLoading } = useQuery<ThreatActorFullDTO>({
    queryKey: ["/api/v1/threat-actors", actorId, "full"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/v1/threat-actors/${actorId}/full`);
      return r.json();
    },
    enabled: !!actorId,
    placeholderData: () => {
      if (!actorId) return undefined;
      const cachedLists = queryClient.getQueriesData<ListResp>({ queryKey: ["/api/v1/threat-actors"] });
      for (const [, value] of cachedLists) {
        const actor = value?.actors?.find((a) => a.id === actorId);
        if (!actor) continue;
        return {
          ...actor,
          ttps: [],
          tools: [],
          campaigns: [],
          iocs: [],
          references: [],
          ruleLinks: [],
          relevantTenants: [],
        } as ThreatActorFullDTO;
      }
      return undefined;
    },
  });

  const { data: providersResp } = useQuery<{ providers: AiProviderSummary[] }>({
    queryKey: ["/api/v1/ai/providers"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/v1/ai/providers");
      return r.json();
    },
    enabled: !!actorId,
  });
  const providers = providersResp?.providers ?? [];

  const enrich = useMutation({
    mutationFn: async (vars: { force: boolean; providerId: string | null }) => {
      const body: Record<string, unknown> = { force: vars.force };
      if (vars.providerId) body.providerId = vars.providerId;
      return startBackgroundJob(`/api/v1/threat-actors/${actorId}/enrich`, body) as Promise<EnrichResp>;
    },
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors"] });
      toast({
        title: "TAP re-analysis queued",
        description: resp.targetLabel ?? "The background jobs tray and Job control will show progress.",
      });
    },
    onError: (e: any) => toast({ title: "Enrichment failed", description: String(e?.message ?? e), variant: "destructive" }),
  });

  // PATCH only fields where the draft differs from the loaded actor. Object/array diffs use JSON.stringify.
  const saveMut = useMutation({
    mutationFn: async () => {
      if (!full) throw new Error("actor not loaded");
      const dirty: Record<string, unknown> = {};
      for (const k of Object.keys(draft) as (keyof ThreatActorFullDTO)[]) {
        const a = (draft as any)[k];
        const b = (full as any)[k];
        if (JSON.stringify(a) !== JSON.stringify(b)) {
          dirty[k as string] = a;
        }
      }
      if (Object.keys(dirty).length === 0) return null;
      const r = await apiRequest("PATCH", `/api/v1/threat-actors/${actorId}`, dirty);
      return r.json();
    },
    onSuccess: (resp) => {
      if (resp === null) {
        toast({ title: "No changes to save" });
        return;
      }
      queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors", actorId, "full"] });
      toast({ title: "Saved" });
      setDraft({});
      setEditMode(false);
    },
    onError: (e: any) =>
      toast({ title: "Save failed", description: String(e?.message ?? e), variant: "destructive" }),
  });

  const deleteMut = useMutation({
    mutationFn: async () => {
      if (!full) throw new Error("actor not loaded");
      await apiRequest("DELETE", `/api/v1/threat-actors/${full.id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors-tenant-tags"] });
      toast({ title: "Threat actor deleted" });
      onClose();
    },
    onError: (e: any) =>
      toast({ title: "Delete failed", description: String(e?.message ?? e), variant: "destructive" }),
  });

  function downloadJson() {
    if (!full) return;
    const blob = new Blob([JSON.stringify(full, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${full.profileId}_${full.primaryName.replace(/\s+/g, "_")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Sheet open={!!actorId} onOpenChange={(v) => !v && onClose()}>
      <SheetContent side="right" hideClose className="w-full sm:w-[720px] lg:w-[1120px] xl:w-[1240px] sm:max-w-none lg:max-w-none p-0 overflow-y-auto">
        {/* NEVER add `relative` to SheetContent — wrap in a relative container instead. */}
        <div className="relative min-h-full">
          {isLoading || !full ? (
            <div className="flex items-center justify-center py-32 text-muted-foreground">
              <Loader2 className="animate-spin mr-2" size={16} /> Loading profile…
            </div>
          ) : (
            <>
              {/* Hero band — round-6 redesign:
                  Single-row layout at lg+ with title on the left and a tight,
                  prioritized action cluster on the right. Edit mode swaps the
                  cluster to ONLY Save/Reset/Cancel — JSON/DOCX/Generate/Re-enrich
                  are hidden in edit mode (they were disabled anyway). View mode
                  surfaces Re-enrich + AI Setup as primary, with a More overflow
                  menu housing the export and exercise-generation actions. */}
              <div className="sticky top-0 z-20 border-b bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-950 backdrop-blur supports-[backdrop-filter]:bg-background/80">
                <div className="px-5 sm:px-6 py-4 flex items-start gap-4">
                  <div className="shrink-0">
                    <ActorPortrait
                      name={full.primaryName}
                      threatLevel={full.threatLevel}
                      portraitUrl={full.portraitUrl}
                      portraitStatus={full.portraitStatus}
                      actorId={full.id}
                      size={64}
                      editable
                    />
                  </div>
                  {/* Title block — flexes to absorb remaining width */}
                  <SheetHeader className="space-y-2 text-left flex-1 min-w-0">
                    <div className="min-w-0">
                      <div className="font-mono text-[10px] text-muted-foreground">{full.profileId} · v{full.version}</div>
                      <SheetTitle className="text-xl truncate" data-testid="text-detail-name">{full.primaryName}</SheetTitle>
                      {full.aliases.length > 0 && (
                        <SheetDescription className="text-xs truncate">
                          aka {full.aliases.join(" · ")}
                          {full.mitreGroupId && <span className="font-mono ml-2">[{full.mitreGroupId}]</span>}
                        </SheetDescription>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      <Badge className={cn("text-[10px]", TAP_STATUS_BADGE[full.status])}>{full.status}</Badge>
                      <Badge className={cn("text-[10px]", THREAT_LEVEL_BADGE[full.threatLevel])}>{full.threatLevel}</Badge>
                      <Badge className={cn("text-[10px]", TLP_BADGE[full.tlp])}>TLP:{full.tlp}</Badge>
                      <Badge variant="outline" className="text-[10px]">{ACTOR_TYPE_LABEL[full.actorType]}</Badge>
                      <Badge variant="outline" className="text-[10px]">{full.sponsorship}</Badge>
                      <Badge variant="outline" className="text-[10px]">Admiralty {full.admiraltySource}/{full.admiraltyInfo} · WEP {full.wepConfidence}</Badge>
                    </div>
                  </SheetHeader>

                  {/* Action cluster — fixed to right; single row at lg+, wraps gracefully below. */}
                  <div className="flex items-center gap-1.5 shrink-0 flex-wrap justify-end max-w-[60%]">
                    {!editMode ? (
                      <>
                        {/* Primary AI actions — kept inline for fast access */}
                        <ProviderPicker
                          providers={providers}
                          value={overrideProviderId}
                          onChange={setOverrideProviderId}
                          disabled={enrich.isPending || aiDisabled}
                        />
                        <Button
                          size="sm"
                          onClick={() => enrich.mutate({ force: true, providerId: overrideProviderId })}
                          disabled={enrich.isPending || aiDisabled}
                          title={aiAvailability.disabledReason}
                          data-testid="button-reenrich"
                        >
                          {enrich.isPending ? (
                            <><Loader2 className="animate-spin mr-1" size={14} /> Queuing…</>
                          ) : (
                            <><Sparkles size={14} className="mr-1" /> Re-enrich</>
                          )}
                        </Button>
                        {/* More menu — keeps the toolbar to a single row */}
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button size="sm" variant="outline" data-testid="button-more-actions" aria-label="More actions">
                              <MoreHorizontal size={14} />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="w-56">
                            <DropdownMenuItem onClick={downloadJson} data-testid="menuitem-export-json">
                              <FileDown size={14} className="mr-2" /> Export JSON
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              data-testid="menuitem-export-docx"
                              onClick={async () => {
                                try {
                                  const r = await apiRequest("GET", `/api/v1/threat-actors/${full.id}/export.docx`);
                                  const blob = await r.blob();
                                  const url = URL.createObjectURL(blob);
                                  const a = document.createElement("a");
                                  a.href = url;
                                  a.download = `${full.profileId}_${full.primaryName.replace(/\s+/g, "_")}.docx`;
                                  document.body.appendChild(a); a.click(); a.remove();
                                  setTimeout(() => URL.revokeObjectURL(url), 1000);
                                } catch (e) {
                                  toast({ title: "DOCX export failed", description: (e as Error).message, variant: "destructive" });
                                }
                              }}
                            >
                              <FileDown size={14} className="mr-2" /> Export DOCX
                            </DropdownMenuItem>
                            {!BATCH_ONE_RELEASE && (
                              <>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                  data-testid="menuitem-generate-exercise"
                                  onClick={async () => {
                                    try {
                                      const r = await apiRequest("POST", "/api/v1/exercises", {
                                        title: `TTX — ${full.primaryName}`,
                                        framework: "hkma",
                                        scenarioType: "ransomware-affiliate",
                                        severity: full.threatLevel === "low" ? "MODERATE" : "HIGH",
                                        durationMin: 120,
                                        sourceTapIds: [full.id],
                                      });
                                      const ex = await r.json();
                                      toast({ title: "Exercise created", description: `${ex.code} — open the Generator tab to populate with ${exerciseProvider}.` });
                                      window.location.hash = "#/exercises";
                                    } catch (e: any) {
                                      toast({ title: "Could not create exercise", description: String(e?.message ?? e), variant: "destructive" });
                                    }
                                  }}
                                >
                                  <Sparkles size={14} className="mr-2" /> Generate exercise
                                </DropdownMenuItem>
                              </>
                            )}
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive focus:text-destructive"
                              data-testid="menuitem-delete-tap"
                              disabled={deleteMut.isPending}
                              onClick={() => {
                                const ok = window.confirm(`Delete ${full.primaryName}? This removes the profile, TTPs, IOCs, references, tenant tags, and portrait.`);
                                if (ok) deleteMut.mutate();
                              }}
                            >
                              {deleteMut.isPending ? (
                                <Loader2 size={14} className="mr-2 animate-spin" />
                              ) : (
                                <Trash2 size={14} className="mr-2" />
                              )}
                              Delete profile
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                        <Button
                          size="sm" variant="outline"
                          onClick={() => { setDraft({}); setEditMode(true); }}
                          data-testid="button-edit-tap"
                        >
                          <Pencil size={14} className="mr-1" /> Edit
                        </Button>
                      </>
                    ) : (
                      <>
                        {/* Edit mode — keep it to the three relevant actions only */}
                        <Button
                          size="sm" variant="ghost"
                          onClick={() => { setDraft({}); setEditMode(false); }}
                          disabled={saveMut.isPending}
                          data-testid="button-edit-cancel"
                        >
                          Cancel
                        </Button>
                        <Button
                          size="sm" variant="outline"
                          onClick={() => setDraft({})}
                          disabled={saveMut.isPending || Object.keys(draft).length === 0}
                          data-testid="button-edit-reset"
                          title="Discard local changes"
                        >
                          <RotateCcw size={14} className="mr-1" /> Reset
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => saveMut.mutate()}
                          disabled={saveMut.isPending || Object.keys(draft).length === 0}
                          data-testid="button-edit-save"
                        >
                          {saveMut.isPending
                            ? <><Loader2 className="animate-spin mr-1" size={14} /> Saving…</>
                            : <><Save size={14} className="mr-1" /> Save changes</>}
                        </Button>
                      </>
                    )}
                    {/* Close — always present, separated visually with a left border on lg+ */}
                    <div className="h-6 w-px bg-border mx-1 hidden sm:block" aria-hidden />
                    <Button
                      size="sm" variant="ghost" onClick={onClose}
                      data-testid="button-close-detail"
                      aria-label="Close"
                      className="h-8 w-8 p-0"
                    >
                      <X size={16} />
                    </Button>
                  </div>
                </div>
              </div>

              {/* Tabs — grouped vertical rail on lg+, compact group pills below lg */}
              <EditCtx.Provider value={{ editMode, draft, set: setField }}>
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <div className="lg:hidden">
                  <TabRailCompact activeTab={activeTab} onSelect={setActiveTab} />
                </div>
                <div className="lg:grid lg:grid-cols-[260px_1fr] lg:gap-0">
                  <aside className="hidden lg:block border-r bg-muted/30 sticky top-[104px] self-start max-h-[calc(100vh-104px)] overflow-y-auto">
                    <TapDossierAside a={full} />
                    <TabRail activeTab={activeTab} onSelect={setActiveTab} />
                  </aside>
                  <div className="px-6 py-4 min-w-0">
                    <TapTabContextHeader activeTab={activeTab} a={full} />
                    <TabsContent value="exec"><ExecTab a={full} /></TabsContent>
                    <TabsContent value="identity"><IdentityTab a={full} /></TabsContent>
                    <TabsContent value="victim"><VictimTab a={full} /></TabsContent>
                    <TabsContent value="capability"><CapabilityTab a={full} /></TabsContent>
                    {!BATCH_ONE_RELEASE && <TabsContent value="relevance"><RelevanceTab a={full} /></TabsContent>}
                    <TabsContent value="ttps"><TtpsTab a={full} /></TabsContent>
                    <TabsContent value="diamond"><DiamondTab a={full} /></TabsContent>
                    <TabsContent value="campaigns"><CampaignsTab a={full} /></TabsContent>
                    <TabsContent value="infra"><InfraTab a={full} /></TabsContent>
                    <TabsContent value="detection"><DetectionTab a={full} /></TabsContent>
                    <TabsContent value="ir"><IrTab a={full} /></TabsContent>
                    <TabsContent value="counter"><CounterTab a={full} /></TabsContent>
                    <TabsContent value="forecast"><ForecastTab a={full} /></TabsContent>
                    <TabsContent value="confidence"><ConfidenceTab a={full} /></TabsContent>
                    <TabsContent value="iocs"><IocsTab a={full} /></TabsContent>
                    <TabsContent value="stix"><StixTab a={full} /></TabsContent>
                    <TabsContent value="refs"><RefsTab a={full} /></TabsContent>
                    <TabsContent value="version"><VersionTab a={full} /></TabsContent>
                  </div>
                </div>
              </Tabs>
              </EditCtx.Provider>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ---- Relevance tab (v2.30.5) ----------------------------------------------
function RelevanceTab({ a }: { a: ThreatActorFullDTO }) {
  const { toast } = useToast();
  const { data, isLoading } = useQuery<TenantTagsResp>({
    queryKey: ["/api/v1/threat-actors", a.id, "tenants"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/v1/threat-actors/${a.id}/tenants`);
      return r.json();
    },
  });
  const tags = data?.tags ?? a.relevantTenants ?? [];
  const available = data?.available ?? [];
  const relevances = data?.relevances ?? RELEVANCE_ORDER;

  // Tenants not yet tagged on this actor
  const taggedIds = new Set(tags.map((t) => t.tenantId));
  const untagged = available.filter((t) => !taggedIds.has(t.id));

  const [addOpen, setAddOpen] = useState(false);
  const [newTenantId, setNewTenantId] = useState<string>("");
  const [newRelevance, setNewRelevance] = useState<TenantRelevance>("sector-match");
  const [newRationale, setNewRationale] = useState("");

  function resetAddForm() {
    setNewTenantId("");
    setNewRelevance("sector-match");
    setNewRationale("");
  }

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors", a.id, "tenants"] });
    queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors", a.id, "full"] });
    queryClient.invalidateQueries({ queryKey: ["/api/v1/threat-actors-tenant-tags"] });
  }

  const addMut = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", `/api/v1/threat-actors/${a.id}/tenants`, {
        tenantId: newTenantId, relevance: newRelevance,
        rationale: newRationale.trim() || null,
      });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Client tagged" });
      setAddOpen(false); resetAddForm(); invalidate();
    },
    onError: (e: any) => toast({ title: "Failed to tag client", description: String(e?.message ?? e), variant: "destructive" }),
  });

  const patchMut = useMutation({
    mutationFn: async ({ tagId, relevance, rationale }: { tagId: string; relevance: TenantRelevance; rationale: string | null }) => {
      const r = await apiRequest("PATCH", `/api/v1/threat-actors/${a.id}/tenants/${tagId}`, { relevance, rationale });
      return r.json();
    },
    onSuccess: () => { toast({ title: "Tag updated" }); invalidate(); },
    onError: (e: any) => toast({ title: "Update failed", description: String(e?.message ?? e), variant: "destructive" }),
  });

  const deleteMut = useMutation({
    mutationFn: async (tagId: string) => {
      const r = await apiRequest("DELETE", `/api/v1/threat-actors/${a.id}/tenants/${tagId}`);
      if (!r.ok && r.status !== 204) throw new Error(await r.text());
    },
    onSuccess: () => { toast({ title: "Tag removed" }); invalidate(); },
    onError: (e: any) => toast({ title: "Remove failed", description: String(e?.message ?? e), variant: "destructive" }),
  });

  return (
    <div className="space-y-5 pt-2">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold inline-flex items-center gap-1.5">
            <Building2 size={14} className="text-amber-600" /> Client relevance
          </h3>
          <p className="text-xs text-muted-foreground mt-1 max-w-prose">
            Mark which of your clients this actor is relevant to. AI enrichment may auto-tag clients whose sector matches the actor's targeting; analysts can add, edit, or remove tags below.
          </p>
        </div>
        <Button
          size="sm"
          onClick={() => { resetAddForm(); setAddOpen(true); }}
          disabled={untagged.length === 0}
          data-testid="button-add-relevance"
        >
          <Plus size={14} className="mr-1" /> Tag client
        </Button>
      </div>

      {isLoading ? (
        <div className="text-sm text-muted-foreground py-6"><Loader2 className="animate-spin mr-1 inline" size={14} /> Loading…</div>
      ) : tags.length === 0 ? (
        <Card className="p-6 text-center text-sm text-muted-foreground" data-testid="empty-relevance">
          <Building2 size={20} className="mx-auto mb-2 opacity-40" />
          No clients tagged yet. Add a client manually, or run AI enrichment to auto-tag.
        </Card>
      ) : (
        <div className="space-y-2">
          {tags.map((t) => (
            <RelevanceRow
              key={t.id}
              tag={t}
              relevances={relevances}
              onPatch={(rel, rat) => patchMut.mutate({ tagId: t.id, relevance: rel, rationale: rat })}
              onRemove={() => deleteMut.mutate(t.id)}
              isPending={patchMut.isPending || deleteMut.isPending}
            />
          ))}
        </div>
      )}

      {/* Add dialog */}
      <Dialog open={addOpen} onOpenChange={(v) => !v && (setAddOpen(false), resetAddForm())}>
        <DialogContent data-testid="dialog-add-relevance">
          <DialogHeader>
            <DialogTitle>Tag a client</DialogTitle>
            <DialogDescription>Pick the client this actor is relevant to, then describe how.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Client</label>
              <Select value={newTenantId} onValueChange={setNewTenantId}>
                <SelectTrigger data-testid="select-relevance-tenant"><SelectValue placeholder="Select a client…" /></SelectTrigger>
                <SelectContent>
                  {untagged.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name}{t.sector ? <span className="text-muted-foreground text-xs ml-2">{t.sector}</span> : null}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Relevance</label>
              <Select value={newRelevance} onValueChange={(v) => setNewRelevance(v as TenantRelevance)}>
                <SelectTrigger data-testid="select-relevance-level"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {relevances.map((r) => (
                    <SelectItem key={r} value={r}>{RELEVANCE_LABEL[r]}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Rationale <span className="opacity-60">(optional)</span></label>
              <Textarea
                value={newRationale}
                onChange={(e) => setNewRationale(e.target.value)}
                placeholder="Why is this actor relevant to this client?"
                rows={3}
                data-testid="textarea-relevance-rationale"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setAddOpen(false); resetAddForm(); }}>Cancel</Button>
            <Button
              onClick={() => addMut.mutate()}
              disabled={!newTenantId || addMut.isPending}
              data-testid="button-confirm-add-relevance"
            >
              {addMut.isPending ? <><Loader2 className="animate-spin mr-1" size={14} /> Saving…</> : "Save tag"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function RelevanceRow({
  tag, relevances, onPatch, onRemove, isPending,
}: {
  tag: ThreatActorTenantDTO;
  relevances: TenantRelevance[];
  onPatch: (rel: TenantRelevance, rat: string | null) => void;
  onRemove: () => void;
  isPending: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [rel, setRel] = useState<TenantRelevance>(tag.relevance);
  const [rat, setRat] = useState(tag.rationale ?? "");

  useEffect(() => {
    setRel(tag.relevance);
    setRat(tag.rationale ?? "");
  }, [tag.relevance, tag.rationale]);

  return (
    <Card className="p-3" data-testid={`row-relevance-${tag.id}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-sm">{tag.tenantName ?? tag.tenantId}</span>
            <Badge className={cn("text-[10px]", RELEVANCE_BADGE[tag.relevance])}>
              {RELEVANCE_LABEL[tag.relevance]}
            </Badge>
            {tag.taggedByAi && (
              <span className="inline-flex items-center gap-1 text-[10px] text-amber-600" title="Tagged by AI">
                <Sparkles size={10} /> AI
              </span>
            )}
            {!tag.taggedByAi && tag.taggedBy && (
              <span className="text-[10px] text-muted-foreground">by {tag.taggedBy}</span>
            )}
          </div>
          {(tag.tenantSector || tag.tenantRegion) && (
            <div className="text-[11px] text-muted-foreground mt-1">
              {tag.tenantSector ? <span>{tag.tenantSector}</span> : null}
              {tag.tenantSector && tag.tenantRegion ? " · " : null}
              {tag.tenantRegion ? <span>{tag.tenantRegion}</span> : null}
            </div>
          )}
          {!editing && tag.rationale && (
            <p className="text-xs text-muted-foreground mt-2 leading-relaxed">{tag.rationale}</p>
          )}
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {!editing ? (
            <>
              <Button size="sm" variant="ghost" onClick={() => setEditing(true)} data-testid={`button-edit-relevance-${tag.id}`}>
                <Pencil size={12} />
              </Button>
              <Button size="sm" variant="ghost" onClick={onRemove} disabled={isPending} data-testid={`button-remove-relevance-${tag.id}`}>
                <Trash2 size={12} className="text-red-500" />
              </Button>
            </>
          ) : (
            <Button size="sm" variant="ghost" onClick={() => { setEditing(false); setRel(tag.relevance); setRat(tag.rationale ?? ""); }}>
              <X size={12} />
            </Button>
          )}
        </div>
      </div>
      {editing && (
        <div className="mt-3 space-y-2 pt-3 border-t">
          <div className="flex items-center gap-2 flex-wrap">
            <label className="text-xs text-muted-foreground">Relevance</label>
            <Select value={rel} onValueChange={(v) => setRel(v as TenantRelevance)}>
              <SelectTrigger className="h-8 w-[160px]"><SelectValue /></SelectTrigger>
              <SelectContent>
                {relevances.map((r) => (
                  <SelectItem key={r} value={r}>{RELEVANCE_LABEL[r]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Textarea
            value={rat}
            onChange={(e) => setRat(e.target.value)}
            placeholder="Rationale"
            rows={2}
            className="text-xs"
          />
          <div className="flex justify-end gap-2">
            <Button size="sm" variant="outline" onClick={() => { setEditing(false); setRel(tag.relevance); setRat(tag.rationale ?? ""); }}>Cancel</Button>
            <Button
              size="sm"
              onClick={() => { onPatch(rel, rat.trim() || null); setEditing(false); }}
              disabled={isPending}
              data-testid={`button-save-relevance-${tag.id}`}
            >
              {isPending ? <Loader2 className="animate-spin" size={12} /> : "Save"}
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

// ---- Tab components --------------------------------------------------------
function Section({ title, icon, children }: { title: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold inline-flex items-center gap-1.5">{icon}{title}</h3>
      <div className="text-sm leading-relaxed">{children}</div>
    </div>
  );
}

function ProsePara({ text }: { text: string | null | undefined }) {
  if (!text || text.trim().length === 0) {
    return <p className="text-sm text-muted-foreground italic">Not yet populated — run enrichment.</p>;
  }
  return <p className="text-sm whitespace-pre-wrap leading-relaxed">{text}</p>;
}

// ---- v2.30.7 inline edit mode infrastructure ------------------------------
//
// One Edit toggle on the DetailSheet header flips every tab content section
// into an editable input. A single Save button dispatches the dirty diff via
// PATCH /api/v1/threat-actors/:aid. Designed to avoid the v2.30.6 problem
// where the Edit button only updated the header bar's identity fields and
// could not change Diamond / IR / Counter / Forecast / etc.
//
// Strategy:
//   - DetailSheet owns `editMode` + `draft` (a partial ThreatActorFullDTO
//     shaped subset).
//   - On Save, we diff `draft` against the original `full` and PATCH only the
//     fields that changed.
//   - Object record fields (diamondAdversary, irActions, capabilityProfile,
//     extortionTactics, businessImpact, vendorNames, infrastructureProfile,
//     countermeasures) are edited via a JSON textarea with parse-on-blur so
//     analysts can correct AI mistakes without a custom key/value UI.
//   - List-typed sub-resources (TTPs, tools, campaigns, IOCs, references,
//     rule links) keep their own dedicated UIs because they live on separate
//     endpoints.

interface EditDraft extends Partial<ThreatActorFullDTO> {}

interface EditCtxValue {
  editMode: boolean;
  draft: EditDraft;
  set: (patch: EditDraft) => void;
}
const EditCtx = createContext<EditCtxValue | null>(null);
function useEditCtx(): EditCtxValue {
  // Defensive default so a tab rendered outside the provider never crashes.
  return useContext(EditCtx) ?? { editMode: false, draft: {}, set: () => {} };
}

/** Returns the live value for a field — draft if dirty, otherwise actor. */
function useField<K extends keyof ThreatActorFullDTO>(a: ThreatActorFullDTO, key: K): ThreatActorFullDTO[K] {
  const { draft, editMode } = useEditCtx();
  if (!editMode) return a[key];
  // hasOwnProperty handles `undefined` and `null` correctly.
  return Object.prototype.hasOwnProperty.call(draft, key) ? (draft as any)[key] : a[key];
}

function EFieldLabel({ children }: { children: React.ReactNode }) {
  return <label className="text-[10px] uppercase tracking-wider text-muted-foreground block mb-1">{children}</label>;
}

/** Single-line text input bound to `key`. */
function EText({
  a, k, label, placeholder, type = "text",
}: { a: ThreatActorFullDTO; k: keyof ThreatActorFullDTO; label: string; placeholder?: string; type?: "text" | "number" }) {
  const ctx = useEditCtx();
  const v = useField(a, k);
  if (!ctx.editMode) {
    return <MetaCell label={label} value={v as any} />;
  }
  return (
    <div>
      <EFieldLabel>{label}</EFieldLabel>
      <Input
        value={v == null ? "" : String(v)}
        type={type}
        placeholder={placeholder}
        onChange={(e) => {
          const raw = e.target.value;
          let next: any = raw;
          if (type === "number") next = raw.trim() === "" ? null : Number(raw);
          else next = raw === "" ? null : raw;
          ctx.set({ [k]: next } as EditDraft);
        }}
        data-testid={`edit-${String(k)}`}
      />
    </div>
  );
}

/** Multi-line prose textarea. */
function ETextarea({
  a, k, label, rows = 4, placeholder,
}: { a: ThreatActorFullDTO; k: keyof ThreatActorFullDTO; label: string; rows?: number; placeholder?: string }) {
  const ctx = useEditCtx();
  const v = useField(a, k);
  if (!ctx.editMode) {
    // Section header is rendered by the parent — just emit the prose.
    return <ProsePara text={v as any} />;
  }
  return (
    <div>
      <EFieldLabel>{label}</EFieldLabel>
      <Textarea
        value={(v as string | null | undefined) ?? ""}
        rows={rows}
        placeholder={placeholder}
        onChange={(e) => ctx.set({ [k]: e.target.value === "" ? null : e.target.value } as EditDraft)}
        data-testid={`edit-${String(k)}`}
      />
    </div>
  );
}

/** Comma-separated string-array input. */
function EArray({
  a, k, label, placeholder,
}: { a: ThreatActorFullDTO; k: keyof ThreatActorFullDTO; label: string; placeholder?: string }) {
  const ctx = useEditCtx();
  const v = useField(a, k) as string[] | undefined;
  if (!ctx.editMode) {
    return (
      <div>
        <EFieldLabel>{label}</EFieldLabel>
        <div className="flex flex-wrap gap-1">
          {(v ?? []).length === 0
            ? <span className="text-muted-foreground italic text-sm">—</span>
            : (v ?? []).map((x) => <Badge key={x} variant="outline" className="text-[10px]">{x}</Badge>)}
        </div>
      </div>
    );
  }
  return (
    <div>
      <EFieldLabel>{label}</EFieldLabel>
      <Input
        value={(v ?? []).join(", ")}
        placeholder={placeholder ?? "comma separated"}
        onChange={(e) => {
          const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
          ctx.set({ [k]: arr } as EditDraft);
        }}
        data-testid={`edit-${String(k)}`}
      />
    </div>
  );
}

/** Select dropdown bound to one of the enum constants. */
function ESelect<T extends string>({
  a, k, label, options, allowNone = false,
}: { a: ThreatActorFullDTO; k: keyof ThreatActorFullDTO; label: string; options: readonly T[]; allowNone?: boolean }) {
  const ctx = useEditCtx();
  const v = useField(a, k);
  if (!ctx.editMode) {
    return <MetaCell label={label} value={v as any} />;
  }
  const cur = (v as string | null | undefined) ?? "";
  return (
    <div>
      <EFieldLabel>{label}</EFieldLabel>
      <Select
        value={cur === "" ? "__none__" : cur}
        onValueChange={(nv) => ctx.set({ [k]: nv === "__none__" ? null : (nv as any) } as EditDraft)}
      >
        <SelectTrigger data-testid={`edit-${String(k)}`}><SelectValue /></SelectTrigger>
        <SelectContent>
          {allowNone && <SelectItem value="__none__">— not set —</SelectItem>}
          {options.map((o) => <SelectItem key={o} value={o}>{o}</SelectItem>)}
        </SelectContent>
      </Select>
    </div>
  );
}

/** Boolean checkbox. */
function EBool({
  a, k, label,
}: { a: ThreatActorFullDTO; k: keyof ThreatActorFullDTO; label: string }) {
  const ctx = useEditCtx();
  const v = useField(a, k);
  if (!ctx.editMode) {
    return <MetaCell label={label} value={v ? "Yes" : "No"} />;
  }
  return (
    <div>
      <EFieldLabel>{label}</EFieldLabel>
      <div className="flex items-center gap-2">
        <Checkbox
          checked={!!v}
          onCheckedChange={(c) => ctx.set({ [k]: !!c } as EditDraft)}
          data-testid={`edit-${String(k)}`}
        />
        <span className="text-xs text-muted-foreground">{v ? "Yes" : "No"}</span>
      </div>
    </div>
  );
}

/** Object-record JSON textarea. Parsed on blur; bad JSON shows a toast and
 *  leaves the previous value untouched (so a slip doesn't clobber the field).
 */
function EJson({
  a, k, label, emptyText, inline,
}: {
  a: ThreatActorFullDTO; k: keyof ThreatActorFullDTO; label?: string;
  emptyText: string; inline?: boolean;
}) {
  const { toast } = useToast();
  const ctx = useEditCtx();
  const v = useField(a, k) as Record<string, any> | null | undefined;
  // Local text so the user can type freely (including invalid JSON between keystrokes).
  const initial = useMemo(() => JSON.stringify(v ?? {}, null, 2), [v]);
  const [text, setText] = useState(initial);
  // Re-sync local text when entering edit mode OR when the upstream value changes
  // (e.g. Reset or a successful save invalidates the cached actor).
  useEffect(() => { setText(initial); }, [initial]);

  if (!ctx.editMode) {
    return <SimpleObjectGrid obj={v ?? {}} emptyText={emptyText} inline={inline} />;
  }
  return (
    <div>
      {label && <EFieldLabel>{label}</EFieldLabel>}
      <Textarea
        value={text}
        rows={10}
        className="font-mono text-[11px]"
        onChange={(e) => setText(e.target.value)}
        onBlur={() => {
          if (text.trim() === "") { ctx.set({ [k]: {} } as EditDraft); return; }
          try {
            const parsed = JSON.parse(text);
            if (typeof parsed !== "object" || Array.isArray(parsed) || parsed === null) {
              throw new Error("Expected a JSON object");
            }
            ctx.set({ [k]: parsed } as EditDraft);
          } catch (err: any) {
            toast({
              title: `Invalid JSON in ${String(k)}`,
              description: String(err?.message ?? err),
              variant: "destructive",
            });
            // Reset local text to the last good value so the field doesn't stay corrupted.
            setText(JSON.stringify(v ?? {}, null, 2));
          }
        }}
        data-testid={`edit-${String(k)}`}
      />
      <p className="text-[10px] text-muted-foreground mt-1">JSON object. Validated on blur.</p>
    </div>
  );
}

function ExecTab({ a }: { a: ThreatActorFullDTO }) {
  const { editMode } = useEditCtx();
  return (
    <div className="space-y-5">
      <Section title="What" icon={<Crosshair size={14} className="text-primary" />}>
        <ETextarea a={a} k="execWhat" label="What" rows={4} placeholder="One-paragraph description of the actor…" />
      </Section>
      <Section title="So what" icon={<AlertTriangle size={14} className="text-amber-500" />}>
        <ETextarea a={a} k="execSoWhat" label="So what" rows={4} placeholder="Why does this actor matter to the tenant?" />
      </Section>
      <Section title="What now" icon={<ListChecks size={14} className="text-emerald-500" />}>
        <ETextarea a={a} k="execWhatNow" label="What now" rows={4} placeholder="Top 3 actions for the next 30 days…" />
      </Section>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 pt-2 border-t">
        {editMode
          ? <ESelect a={a} k="threatLevel" label="Threat level" options={THREAT_LEVELS} />
          : <MetaCell label="Threat level" value={<Badge className={cn(THREAT_LEVEL_BADGE[a.threatLevel])}>{a.threatLevel}</Badge>} />}
        <EBool a={a} k="sectorActivelyTargeted" label="Sector actively targeted" />
        <EText a={a} k="threatLevelRationale" label="Rationale" />
      </div>
    </div>
  );
}

function IdentityTab({ a }: { a: ThreatActorFullDTO }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <EText a={a} k="primaryName" label="Primary name" />
        <EText a={a} k="mitreGroupId" label="MITRE Group" placeholder="G1037" />
        <EText a={a} k="activeSince" label="Active since" type="number" placeholder="2019" />
        <ESelect a={a} k="sophistication" label="Sophistication" options={SOPHISTICATION_LEVELS} />
        <ESelect a={a} k="actorType" label="Actor type" options={ACTOR_TYPES} />
        <ESelect a={a} k="sponsorship" label="Sponsorship" options={SPONSORSHIP_LEVELS} />
        <EText a={a} k="assessedOrigin" label="Assessed origin" placeholder="China" />
        <ESelect a={a} k="originConfidence" label="Origin confidence" options={WEP_CONFIDENCE} allowNone />
        <EText a={a} k="sponsoringEntity" label="Sponsoring entity" />
      </div>
      <Section title="Aliases">
        <EArray a={a} k="aliases" label="Aliases" placeholder="Brass Typhoon, UNC3944, 0ktapus" />
      </Section>
      <Section title="Vendor naming">
        <EJson a={a} k="vendorNames" label="Vendor naming (object: vendor -> aliases[])" emptyText="None" />
      </Section>
      <Section title="Motivation">
        <EArray a={a} k="motivation" label="Motivation" placeholder="Espionage, Geopolitical, Financial" />
      </Section>
    </div>
  );
}

function VictimTab({ a }: { a: ThreatActorFullDTO }) {
  return (
    <div className="space-y-4">
      <Section title="Target sectors" icon={<Target size={14} />}>
        <EArray a={a} k="targetSectors" label="Target sectors" placeholder="Financial, Government, Healthcare" />
      </Section>
      <Section title="Target regions" icon={<Globe2 size={14} />}>
        <EArray a={a} k="targetRegions" label="Target regions" placeholder="APAC, Hong Kong, Singapore" />
      </Section>
      <Section title="Target tech stack" icon={<Network size={14} />}>
        <EArray a={a} k="targetTechStack" label="Target tech stack" placeholder="Microsoft 365, VMware ESXi, Citrix" />
      </Section>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 pt-2 border-t">
        <EText a={a} k="orgSizePreference" label="Org size preference" />
        <ESelect a={a} k="intentProximity" label="Intent proximity" options={INTENT_PROXIMITY} />
        <EText a={a} k="relevanceRating" label="Relevance rating" />
      </div>
    </div>
  );
}

function CapabilityTab({ a }: { a: ThreatActorFullDTO }) {
  return (
    <div className="space-y-4">
      <Section title="Capability profile">
        <EJson a={a} k="capabilityProfile" label="Capability profile (JSON object)" emptyText="Not yet populated — run enrichment." />
      </Section>
      <Section title="Tools / malware">
        {a.tools.length === 0 ? <span className="text-muted-foreground italic text-sm">No tools listed</span> : (
          <div className="space-y-2">
            {a.tools.map((t) => <ToolRow key={t.id} t={t} />)}
          </div>
        )}
        <p className="text-[10px] text-muted-foreground mt-2">Tools are managed on a separate endpoint — add or edit them outside edit mode.</p>
      </Section>
    </div>
  );
}

function ToolRow({ t }: { t: ThreatActorToolDTO }) {
  return (
    <Card className="p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="font-semibold text-sm">{t.name}</div>
          {t.category && <div className="text-[11px] text-muted-foreground">{t.category}</div>}
        </div>
        <Badge variant="outline" className="text-[10px]">{t.confidence}</Badge>
      </div>
      {t.purpose && <div className="text-xs mt-1">{t.purpose}</div>}
      {t.variants.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1.5">
          {t.variants.map((v) => <Badge key={v} variant="secondary" className="text-[9px]">{v}</Badge>)}
        </div>
      )}
      {t.hashOrRule && <div className="text-[10px] font-mono mt-1 text-muted-foreground break-all">{t.hashOrRule}</div>}
    </Card>
  );
}

function TtpsTab({ a }: { a: ThreatActorFullDTO }) {
  // Group by tactic for matrix display
  const byTactic = useMemo(() => {
    const m = new Map<string, ThreatActorTtpDTO[]>();
    for (const t of a.ttps) {
      if (!m.has(t.tactic)) m.set(t.tactic, []);
      m.get(t.tactic)!.push(t);
    }
    return Array.from(m.entries()).sort((x, y) => x[0].localeCompare(y[0]));
  }, [a.ttps]);
  const coverageByTtp = useMemo(() => buildTtpCoverage(a), [a]);

  if (a.ttps.length === 0) {
    return <p className="text-sm text-muted-foreground italic">No TTPs yet — run enrichment to populate the MITRE ATT&CK matrix.</p>;
  }

  return (
    <div className="space-y-3">
      <div className="text-xs text-muted-foreground">{a.ttps.length} technique{a.ttps.length === 1 ? "" : "s"} across {byTactic.length} tactic{byTactic.length === 1 ? "" : "s"}</div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {byTactic.map(([tactic, techs]) => (
          <Card key={tactic} className="p-3">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">{tactic}</div>
            <div className="space-y-1.5">
              {techs.map((t) => (
                <div key={t.id} className="text-xs border-l-2 pl-2" style={{ borderColor: TTP_STATUS_COLOR[t.status] }}>
                  <div className="flex flex-wrap items-center gap-1">
                    <span className="font-mono font-semibold">{tapTtpId(t)}</span>
                    <Badge variant="outline" className="text-[9px] px-1 py-0">{t.detectionPriority}</Badge>
                    <CoverageBadge coverage={coverageByTtp.get(t.id)} />
                  </div>
                  <div className="text-[11px]">{t.techniqueName}</div>
                  {t.evidence && <div className="text-[10px] text-muted-foreground mt-0.5 italic">{t.evidence}</div>}
                </div>
              ))}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
const TTP_STATUS_COLOR: Record<string, string> = {
  confirmed: "rgb(239 68 68)", suspected: "rgb(245 158 11)", "not-observed": "rgb(148 163 184)",
};

type TtpCoverage = {
  state: "no_rule" | "draft" | "reviewed" | "deployed";
  label: string;
  rules: ThreatActorRuleLinkDTO[];
};

function tapTtpId(t: ThreatActorTtpDTO): string {
  return t.subTechniqueId || t.techniqueId;
}

function linkedRuleTechniqueIds(link: ThreatActorRuleLinkDTO): string[] {
  return (link.ruleMitreTechniques ?? [])
    .map((t) => String(t.id || "").trim().toUpperCase())
    .filter(Boolean);
}

function linkCoversTtp(link: ThreatActorRuleLinkDTO, t: ThreatActorTtpDTO): boolean {
  const primary = t.techniqueId.trim().toUpperCase();
  const sub = (t.subTechniqueId || "").trim().toUpperCase();
  return linkedRuleTechniqueIds(link).some((id) => id === primary || (!!sub && id === sub));
}

function buildTtpCoverage(a: ThreatActorFullDTO): Map<string, TtpCoverage> {
  const out = new Map<string, TtpCoverage>();
  for (const t of a.ttps) {
    const rules = a.ruleLinks.filter((l) => linkCoversTtp(l, t));
    if (rules.length === 0) {
      out.set(t.id, { state: "no_rule", label: "No rule", rules });
      continue;
    }
    const statuses = rules.map((r) => String(r.ruleStatus || "").toLowerCase());
    if (statuses.some((s) => /deploy|validat/.test(s))) {
      out.set(t.id, { state: "deployed", label: "Deployed", rules });
    } else if (statuses.some((s) => /review|approved/.test(s))) {
      out.set(t.id, { state: "reviewed", label: "Reviewed", rules });
    } else {
      out.set(t.id, { state: "draft", label: "Draft rule", rules });
    }
  }
  return out;
}

function CoverageBadge({ coverage }: { coverage?: TtpCoverage }) {
  const c = coverage ?? { state: "no_rule", label: "No rule", rules: [] };
  const cls = c.state === "deployed"
    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
    : c.state === "reviewed"
      ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300"
      : c.state === "draft"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
        : "border-slate-300 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300";
  return <Badge variant="outline" className={cn("text-[9px] px-1 py-0", cls)}>{c.label}</Badge>;
}

function DiamondTab({ a }: { a: ThreatActorFullDTO }) {
  const { editMode } = useEditCtx();
  const cells: Array<{ title: string; icon: React.ReactNode; k: keyof ThreatActorFullDTO; data: any }> = [
    { title: "Adversary", icon: <Skull size={14} className="text-red-500" />, k: "diamondAdversary", data: a.diamondAdversary },
    { title: "Capability", icon: <Sparkles size={14} className="text-amber-500" />, k: "diamondCapability", data: a.diamondCapability },
    { title: "Infrastructure", icon: <Network size={14} className="text-blue-500" />, k: "diamondInfrastructure", data: a.diamondInfrastructure },
    { title: "Victim", icon: <Target size={14} className="text-emerald-500" />, k: "diamondVictim", data: a.diamondVictim },
  ];
  if (!editMode) {
    return (
      <div className="space-y-4">
        <div className="relative min-h-[620px] overflow-hidden rounded-2xl border bg-gradient-to-br from-card via-background to-[hsl(var(--brand-soft))]/55 p-4 md:p-6">
          <div className="absolute inset-0 pointer-events-none opacity-80">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-full w-full">
              <path d="M50 8 L88 50 L50 92 L12 50 Z" fill="none" stroke="hsl(var(--brand) / 0.18)" strokeWidth="0.8" />
              <path d="M50 8 L50 92 M12 50 L88 50" fill="none" stroke="hsl(var(--signal) / 0.18)" strokeWidth="0.55" strokeDasharray="2 2" />
              <circle cx="50" cy="50" r="12" fill="hsl(var(--background) / 0.72)" stroke="hsl(var(--border))" strokeWidth="0.5" />
            </svg>
          </div>

          <div className="relative z-10 grid min-h-[560px] grid-cols-1 gap-4 md:grid-cols-[1fr_0.86fr_1fr] md:grid-rows-[auto_auto_auto] md:items-center">
            <div className="md:col-start-2 md:row-start-1">
              <DiamondNode
                title="Adversary"
                subtitle="Actor identity and assessed intent"
                icon={<Skull size={16} className="text-red-500" />}
                tone="border-red-500/20 bg-red-500/5"
                data={a.diamondAdversary}
              />
            </div>

            <div className="md:col-start-1 md:row-start-2">
              <DiamondNode
                title="Infrastructure"
                subtitle="C2, delivery, hosting, relay, and staging patterns"
                icon={<Network size={16} className="text-blue-500" />}
                tone="border-blue-500/20 bg-blue-500/5"
                data={a.diamondInfrastructure}
              />
            </div>

            <div className="md:col-start-2 md:row-start-2">
              <div className="rounded-xl border bg-background/88 p-4 text-center shadow-sm backdrop-blur">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Meta-features</div>
                <div className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  Pivot around timing, phase, result, directionality, methodology, and confidence. Use this center to challenge weak attribution assumptions.
                </div>
                {Object.keys(a.diamondMeta ?? {}).length > 0 && (
                  <div className="mt-3 max-h-36 overflow-y-auto rounded-lg border bg-muted/25 p-2 text-left text-[11px]">
                    {renderAny(a.diamondMeta)}
                  </div>
                )}
              </div>
            </div>

            <div className="md:col-start-3 md:row-start-2">
              <DiamondNode
                title="Capability"
                subtitle="Malware, tooling, access methods, and operational maturity"
                icon={<Sparkles size={16} className="text-amber-500" />}
                tone="border-amber-500/20 bg-amber-500/5"
                data={a.diamondCapability}
              />
            </div>

            <div className="md:col-start-2 md:row-start-3">
              <DiamondNode
                title="Victim"
                subtitle="Target sectors, regions, technologies, and client relevance"
                icon={<Target size={16} className="text-emerald-500" />}
                tone="border-emerald-500/20 bg-emerald-500/5"
                data={a.diamondVictim}
              />
            </div>
          </div>
        </div>
        <Card className="p-4">
          <div className="text-sm font-semibold">Analyst use</div>
          <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
            Read the diamond clockwise to test whether identity, capability, infrastructure, and victim evidence support each other. Weak or missing edges are collection gaps, not certainty.
          </p>
        </Card>
      </div>
    );
  }
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {cells.map((c) => (
        <Card key={c.title} className="p-4">
          <div className="text-sm font-semibold mb-2 inline-flex items-center gap-1.5">{c.icon}{c.title}</div>
          {editMode
            ? <EJson a={a} k={c.k} emptyText="—" />
            : <div className="text-xs whitespace-pre-wrap">{renderAny(c.data)}</div>}
        </Card>
      ))}
      <Card className={cn("p-4 md:col-span-2", !editMode && Object.keys(a.diamondMeta ?? {}).length === 0 && "hidden")}>
        <div className="text-sm font-semibold mb-2">Meta-features</div>
        {editMode
          ? <EJson a={a} k="diamondMeta" emptyText="—" />
          : <div className="text-xs whitespace-pre-wrap">{renderAny(a.diamondMeta)}</div>}
      </Card>
    </div>
  );
}

function DiamondNode({
  title, subtitle, icon, tone, data,
}: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  tone: string;
  data: Record<string, any> | null | undefined;
}) {
  const keys = data ? Object.keys(data) : [];
  return (
    <div className={cn("relative rounded-xl border p-4 shadow-sm backdrop-blur", tone)}>
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border bg-background/70">
          {icon}
        </div>
        <div className="min-w-0">
          <div className="text-sm font-semibold">{title}</div>
          <div className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">{subtitle}</div>
        </div>
      </div>
      <div className="mt-3 max-h-44 overflow-y-auto rounded-lg border bg-background/72 p-2 text-xs leading-relaxed">
        {keys.length === 0 ? (
          <span className="text-muted-foreground italic">Not yet populated.</span>
        ) : (
          renderAny(data)
        )}
      </div>
    </div>
  );
}

function CampaignsTab({ a }: { a: ThreatActorFullDTO }) {
  if (a.campaigns.length === 0) {
    return <p className="text-sm text-muted-foreground italic">No campaigns logged — run enrichment or add manually.</p>;
  }
  return (
    <div className="space-y-2">
      {a.campaigns.map((c) => (
        <Card key={c.id} className="p-3">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <div className="font-semibold text-sm flex items-center gap-2">
                <Calendar size={12} className="text-muted-foreground" />
                {c.name}
              </div>
              {c.period && <div className="text-[11px] text-muted-foreground font-mono">{c.period}</div>}
            </div>
            {c.sourceUrl && (
              <a href={c.sourceUrl} target="_blank" rel="noreferrer" className="text-xs inline-flex items-center gap-0.5 text-primary hover:underline">
                source <ExternalLink size={10} />
              </a>
            )}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-2 text-[11px]">
            <MetaCell label="Sector" value={c.targetSector} />
            <MetaCell label="Geography" value={c.targetGeography} />
            <MetaCell label="Initial access" value={c.initialAccess} />
            <MetaCell label="Outcome" value={c.outcome} />
          </div>
        </Card>
      ))}
    </div>
  );
}

function InfraTab({ a }: { a: ThreatActorFullDTO }) {
  return <EJson a={a} k="infrastructureProfile" emptyText="Infrastructure profile not populated." />;
}
function IrTab({ a }: { a: ThreatActorFullDTO }) {
  return <EJson a={a} k="irActions" emptyText="IR actions not populated." />;
}
function CounterTab({ a }: { a: ThreatActorFullDTO }) {
  return <EJson a={a} k="countermeasures" emptyText="Countermeasures not populated." />;
}

function ForecastTab({ a }: { a: ThreatActorFullDTO }) {
  return (
    <div className="space-y-4">
      <Section title="Forecast" icon={<Activity size={14} className="text-primary" />}>
        <ETextarea a={a} k="forecast" label="Forecast" rows={5} placeholder="12-month forecast…" />
      </Section>
      <Section title="Extortion tactics">
        <EJson a={a} k="extortionTactics" emptyText="Not applicable." inline />
      </Section>
      <Section title="Business impact">
        <EJson a={a} k="businessImpact" emptyText="Not populated." inline />
      </Section>
    </div>
  );
}

function ConfidenceTab({ a }: { a: ThreatActorFullDTO }) {
  const { editMode } = useEditCtx();
  const confidenceDrivers = [
    a.references.length > 0 ? `${a.references.length} source reference${a.references.length === 1 ? "" : "s"}` : null,
    a.ttps.some((t) => t.status === "confirmed") ? "Confirmed ATT&CK procedures present" : null,
    a.iocs.length > 0 ? `${a.iocs.length} indicator${a.iocs.length === 1 ? "" : "s"} captured` : null,
    a.ruleLinks.length > 0 ? `${a.ruleLinks.length} mapped detection rule${a.ruleLinks.length === 1 ? "" : "s"}` : null,
    a.cutoffDate ? `Reviewed through ${a.cutoffDate}` : null,
  ].filter(Boolean) as string[];
  const confidenceReducers = [
    a.references.length === 0 ? "No source references attached" : null,
    !a.originConfidence ? "Origin confidence not assessed" : null,
    a.ttps.length === 0 ? "No ATT&CK procedures populated" : null,
    a.ruleLinks.length === 0 ? "No mapped detection coverage" : null,
    !a.cutoffDate ? "No intelligence cut-off date" : null,
  ].filter(Boolean) as string[];
  const collectionGaps = [
    a.references.length === 0 ? "Attach source reporting for key claims." : null,
    a.ttps.length === 0 ? "Run enrichment or add observed ATT&CK TTPs." : null,
    a.iocs.length === 0 ? "Add validated IoCs with first/last seen and recommended action." : null,
    a.ruleLinks.length === 0 ? "Map top priority TTPs to reviewed detection rules." : null,
    a.relevantTenants.length === 0 ? "Tag affected or watching tenants with rationale." : null,
  ].filter(Boolean) as string[];
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        {editMode
          ? <ESelect a={a} k="tlp" label="TLP" options={TLP_LEVELS} />
          : <MetaCell label="TLP" value={<Badge className={cn(TLP_BADGE[a.tlp])}>{a.tlp}</Badge>} />}
        {editMode ? (
          <>
            <ESelect a={a} k="admiraltySource" label="Admiralty source" options={ADMIRALTY_SOURCE} />
            <ESelect a={a} k="admiraltyInfo" label="Admiralty info" options={ADMIRALTY_INFO} />
          </>
        ) : (
          <MetaCell label="Admiralty (source/info)" value={`${a.admiraltySource} / ${a.admiraltyInfo}`} />
        )}
        <ESelect a={a} k="wepConfidence" label="WEP confidence" options={WEP_CONFIDENCE} />
        <ESelect a={a} k="originConfidence" label="Origin confidence" options={WEP_CONFIDENCE} allowNone />
        <ESelect a={a} k="sophistication" label="Sophistication" options={SOPHISTICATION_LEVELS} />
        <ESelect a={a} k="intentProximity" label="Intent proximity" options={INTENT_PROXIMITY} />
        {editMode
          ? <ESelect a={a} k="threatLevel" label="Threat level" options={THREAT_LEVELS} />
          : <MetaCell label="Threat level" value={<Badge className={cn(THREAT_LEVEL_BADGE[a.threatLevel])}>{a.threatLevel}</Badge>} />}
        <EText a={a} k="cutoffDate" label="Cut-off date" placeholder="2025-04-15" />
        <EText a={a} k="preparedBy" label="Prepared by" />
        <MetaCell label="AI provider" value={a.aiProviderLabel} />
      </div>
      {!editMode && (
        <div className="grid gap-3 lg:grid-cols-3">
          <ConfidenceList title="Confidence drivers" items={confidenceDrivers} empty="No positive confidence drivers recorded yet." />
          <ConfidenceList title="Confidence reducers" items={confidenceReducers} empty="No obvious reducers from populated fields." />
          <ConfidenceList title="Collection gaps" items={collectionGaps} empty="No immediate collection gaps from profile metadata." />
        </div>
      )}
    </div>
  );
}

function ConfidenceList({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <Card className="p-4">
      <div className="text-sm font-semibold">{title}</div>
      {items.length === 0 ? (
        <div className="mt-2 text-xs text-muted-foreground italic">{empty}</div>
      ) : (
        <ul className="mt-2 space-y-1.5 text-xs text-muted-foreground">
          {items.map((item) => <li key={item} className="leading-relaxed">- {item}</li>)}
        </ul>
      )}
    </Card>
  );
}

function DetectionTab({ a }: { a: ThreatActorFullDTO }) {
  const coverageByTtp = useMemo(() => buildTtpCoverage(a), [a]);
  const uncovered = a.ttps.filter((t) => coverageByTtp.get(t.id)?.state === "no_rule")
    .sort((x, y) => x.detectionPriority.localeCompare(y.detectionPriority))
    .slice(0, 8);
  const openTechnique = (techniqueId: string) => {
    window.location.hash = `#/detection-rules?technique=${encodeURIComponent(techniqueId)}`;
  };

  if (a.ruleLinks.length === 0) {
    return (
      <div className="space-y-3">
        <Card className="p-6 text-center text-sm text-muted-foreground">
          <Shield className="mx-auto mb-2 text-muted-foreground" size={24} />
          <div className="font-medium text-foreground">No detection rules linked yet</div>
          <div className="mt-1">Open Detection Rules filtered to a priority TTP, generate coverage, then attach reviewed rules back to this profile.</div>
          {uncovered[0] && (
            <Button className="mt-4" size="sm" onClick={() => openTechnique(tapTtpId(uncovered[0]))}>
              <ExternalLink size={13} className="mr-1.5" /> Open top gap: {tapTtpId(uncovered[0])}
            </Button>
          )}
        </Card>
        {uncovered.length > 0 && (
          <Card className="p-4">
            <div className="text-sm font-semibold mb-2">Top uncovered TTPs</div>
            <div className="grid gap-2 md:grid-cols-2">
              {uncovered.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => openTechnique(tapTtpId(t))}
                  className="rounded-md border p-2 text-left text-xs hover:bg-muted/50"
                  data-testid={`button-open-ttp-gap-${tapTtpId(t)}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-semibold">{tapTtpId(t)}</span>
                    <Badge variant="outline" className="text-[9px]">{t.detectionPriority}</Badge>
                  </div>
                  <div className="mt-0.5 truncate text-muted-foreground">{t.techniqueName}</div>
                </button>
              ))}
            </div>
          </Card>
        )}
      </div>
    );
  }
  return (
    <div className="space-y-4">
      {uncovered.length > 0 && (
        <Card className="p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold">Coverage gaps</div>
              <div className="text-xs text-muted-foreground">{uncovered.length} priority TTP{uncovered.length === 1 ? "" : "s"} still have no linked rule.</div>
            </div>
            <Button size="sm" variant="outline" onClick={() => openTechnique(tapTtpId(uncovered[0]))}>
              <ExternalLink size={13} className="mr-1.5" /> Open top gap
            </Button>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {uncovered.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => openTechnique(tapTtpId(t))}
                className="rounded-full border px-2 py-1 text-[10px] font-mono hover:bg-muted"
              >
                {tapTtpId(t)}
              </button>
            ))}
          </div>
        </Card>
      )}
      {a.ruleLinks.map((l) => (
        <Card key={l.id} className="p-3 flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="font-semibold text-sm truncate">{l.ruleTitle ?? l.ruleId}</div>
            <div className="text-[11px] text-muted-foreground font-mono">{l.ruleId}</div>
            {linkedRuleTechniqueIds(l).length > 0 && (
              <div className="mt-1 flex flex-wrap gap-1">
                {linkedRuleTechniqueIds(l).slice(0, 6).map((id) => <Badge key={id} variant="secondary" className="text-[9px]">{id}</Badge>)}
              </div>
            )}
            {l.notes && <div className="text-xs mt-1 italic">{l.notes}</div>}
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <Badge variant="outline" className="text-[10px]">{l.priority}</Badge>
            {l.ruleStatus && <Badge variant="outline" className="text-[10px]">{l.ruleStatus}</Badge>}
            <Button
              size="sm" variant="ghost"
              onClick={() => { window.location.hash = `#/detection-rules`; }}
              data-testid={`link-detection-rule-${l.ruleId}`}
            >
              <ExternalLink size={12} />
            </Button>
          </div>
        </Card>
      ))}
    </div>
  );
}

function IocsTab({ a }: { a: ThreatActorFullDTO }) {
  if (a.iocs.length === 0) {
    return <p className="text-sm text-muted-foreground italic">No IOCs catalogued — run enrichment.</p>;
  }
  return (
    <div className="space-y-1">
      <div className="text-xs text-muted-foreground mb-2">{a.iocs.length} indicators</div>
      <div className="overflow-x-auto border rounded-md">
        <table className="w-full text-xs">
          <thead className="bg-muted/40">
            <tr className="text-left">
              <th className="px-2 py-1.5 font-semibold">Type</th>
              <th className="px-2 py-1.5 font-semibold">Value</th>
              <th className="px-2 py-1.5 font-semibold">First seen</th>
              <th className="px-2 py-1.5 font-semibold">Last conf.</th>
              <th className="px-2 py-1.5 font-semibold">Conf.</th>
              <th className="px-2 py-1.5 font-semibold">TLP</th>
              <th className="px-2 py-1.5 font-semibold">Action</th>
            </tr>
          </thead>
          <tbody>
            {a.iocs.map((i) => (
              <tr key={i.id} className="border-t hover:bg-muted/30">
                <td className="px-2 py-1 font-mono uppercase text-[10px]">{i.iocType}</td>
                <td className="px-2 py-1 font-mono break-all">{i.value}</td>
                <td className="px-2 py-1">{i.firstSeen ?? "—"}</td>
                <td className="px-2 py-1">{i.lastConfirmed ?? "—"}</td>
                <td className="px-2 py-1">{i.confidence}</td>
                <td className="px-2 py-1"><Badge className={cn("text-[9px] px-1 py-0", TLP_BADGE[i.tlp])}>{i.tlp}</Badge></td>
                <td className="px-2 py-1">{i.recommendedAction ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StixTab({ a }: { a: ThreatActorFullDTO }) {
  const stix = useMemo(() => buildStix(a), [a]);
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-xs text-muted-foreground">STIX 2.1 bundle preview ({stix.objects.length} objects)</div>
        <Button
          size="sm" variant="outline"
          onClick={() => {
            const blob = new Blob([JSON.stringify(stix, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url; link.download = `${a.profileId}_stix2.json`;
            link.click(); URL.revokeObjectURL(url);
          }}
          data-testid="button-export-stix"
        >
          <Download size={12} className="mr-1" /> Download bundle
        </Button>
      </div>
      <pre className="text-[10px] font-mono whitespace-pre-wrap break-all border rounded p-3 bg-muted/30 max-h-[60vh] overflow-y-auto">
        {JSON.stringify(stix, null, 2)}
      </pre>
    </div>
  );
}

function RefsTab({ a }: { a: ThreatActorFullDTO }) {
  if (a.references.length === 0) {
    return <p className="text-sm text-muted-foreground italic">No references — run enrichment.</p>;
  }
  return (
    <ol className="space-y-2 list-none">
      {a.references.map((r) => (
        <li key={r.id} className="text-sm flex items-start gap-2">
          <span className="font-mono text-[10px] text-muted-foreground shrink-0 w-6">[{r.refNum}]</span>
          <div className="min-w-0">
            <div className="font-medium">{r.title}</div>
            <div className="text-xs text-muted-foreground flex flex-wrap gap-2">
              {r.sourceType && <span>{r.sourceType}</span>}
              {r.date && <span>· {r.date}</span>}
              {r.url && <a href={r.url} target="_blank" rel="noreferrer" className="text-primary hover:underline inline-flex items-center gap-0.5">source <ExternalLink size={10} /></a>}
              {r.archiveUrl && <a href={r.archiveUrl} target="_blank" rel="noreferrer" className="text-primary hover:underline inline-flex items-center gap-0.5">archive <ExternalLink size={10} /></a>}
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

function VersionTab({ a }: { a: ThreatActorFullDTO }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      <MetaCell label="Profile ID" value={<span className="font-mono">{a.profileId}</span>} />
      <MetaCell label="Version" value={`v${a.version}`} />
      <MetaCell label="Status" value={<Badge className={cn(TAP_STATUS_BADGE[a.status])}>{a.status}</Badge>} />
      <MetaCell label="Created" value={new Date(a.createdAt).toLocaleString()} />
      <MetaCell label="Created by" value={a.createdBy} />
      <MetaCell label="Updated" value={new Date(a.updatedAt).toLocaleString()} />
      <MetaCell label="Cut-off date" value={a.cutoffDate} />
      <MetaCell label="Prepared by" value={a.preparedBy} />
      <MetaCell label="AI provider" value={a.aiProviderLabel} />
    </div>
  );
}

// ---- Helpers ---------------------------------------------------------------
function SimpleObjectGrid({ obj, emptyText, inline }: { obj: Record<string, any>; emptyText: string; inline?: boolean }) {
  const keys = obj ? Object.keys(obj) : [];
  if (keys.length === 0) return <p className="text-sm text-muted-foreground italic">{emptyText}</p>;
  if (inline) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
        {keys.map((k) => (
          <div key={k}>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{k}</div>
            <div className="whitespace-pre-wrap">{renderAny(obj[k])}</div>
          </div>
        ))}
      </div>
    );
  }
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {keys.map((k) => (
        <Card key={k} className="p-3">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">{k}</div>
          <div className="text-sm whitespace-pre-wrap">{renderAny(obj[k])}</div>
        </Card>
      ))}
    </div>
  );
}

function renderAny(v: any): React.ReactNode {
  if (v === null || v === undefined) return <span className="text-muted-foreground italic">—</span>;
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return v.length === 0 ? <span className="text-muted-foreground italic">—</span> : (
    <ul className="list-disc list-inside space-y-0.5">
      {v.map((x, i) => <li key={i}>{renderAny(x)}</li>)}
    </ul>
  );
  if (typeof v === "object") {
    return (
      <div className="space-y-0.5">
        {Object.entries(v).map(([k, val]) => (
          <div key={k} className="text-xs">
            <span className="font-semibold text-muted-foreground">{k}:</span>{" "}
            <span>{renderAny(val)}</span>
          </div>
        ))}
      </div>
    );
  }
  return String(v);
}

// Minimal STIX 2.1 bundle builder. Produces threat-actor + indicator objects.
function buildStix(a: ThreatActorFullDTO) {
  const taId = `threat-actor--${a.id}`;
  const now = new Date().toISOString();
  const objects: any[] = [
    {
      type: "threat-actor",
      spec_version: "2.1",
      id: taId,
      created: a.createdAt,
      modified: a.updatedAt,
      name: a.primaryName,
      aliases: a.aliases,
      threat_actor_types: [a.actorType],
      sophistication: a.sophistication,
      resource_level: a.sponsorship,
      primary_motivation: a.motivation[0] ?? "unknown",
      secondary_motivations: a.motivation.slice(1),
      object_marking_refs: [`marking-definition--TLP-${a.tlp.replace(/[^A-Z]/g, "")}`],
    },
  ];
  for (const i of a.iocs) {
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: `indicator--${i.id}`,
      created: i.createdAt,
      modified: i.createdAt,
      name: `${i.iocType}: ${i.value}`,
      pattern: stixPatternFor(i),
      pattern_type: "stix",
      valid_from: i.firstSeen ?? now,
      labels: [i.confidence.toLowerCase().replace(/\s/g, "-")],
      created_by_ref: taId,
    });
  }
  return { type: "bundle", id: `bundle--${a.id}`, objects };
}

function stixPatternFor(i: ThreatActorIocDTO): string {
  const v = i.value.replace(/'/g, "\\'");
  switch (i.iocType) {
    case "ipv4":   return `[ipv4-addr:value = '${v}']`;
    case "ipv6":   return `[ipv6-addr:value = '${v}']`;
    case "domain": return `[domain-name:value = '${v}']`;
    case "url":    return `[url:value = '${v}']`;
    case "md5":    return `[file:hashes.MD5 = '${v}']`;
    case "sha1":   return `[file:hashes.'SHA-1' = '${v}']`;
    case "sha256": return `[file:hashes.'SHA-256' = '${v}']`;
    case "email":  return `[email-addr:value = '${v}']`;
    default:       return `[x-custom:${i.iocType} = '${v}']`;
  }
}
