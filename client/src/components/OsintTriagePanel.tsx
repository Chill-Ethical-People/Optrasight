// v2.17 — Inline OSINT AI panel that replaces the old "AI overview — Analyst
// briefing" card on the OSINT page. Contains the Initial Triage + Deep Dive
// tabs (formerly inside the floating chatbot sheet). The floating chatbot
// itself is now reserved for free-form chat (see OsintChatbot.tsx).
import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { AlertTriangle, Brain, Check, Clock, Copy, Download, Eye, FileText, Loader2, Search, Sparkles } from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { useAiAvailability } from "@/lib/aiAvailability";
import type { OsintFindingDTO } from "@shared/schema";

export type RangeKey = "1d" | "7d" | "1m" | "1q" | "1y" | "all";

const RANGE_LABEL: Record<RangeKey, string> = {
  "1d": "the last 24 hours",
  "7d": "the last 7 days",
  "1m": "the last month",
  "1q": "the last quarter",
  "1y": "the last year",
  "all": "all available intel",
};

interface ChatTriageResponse {
  reportMd: string;
  rangeLabel: string;
  itemsAnalysed: number;
  providerLabel: string | null;
  generatedAt: string;
}

interface ChatDeepDiveResponse {
  perFinding: Array<any>;
  overallAssessment: string;
  htmlReport: string;
  htmlFileName: string;
  providerLabel: string | null;
  generatedAt: string;
}

// v2.27 — Async AI job poller. The CIRT triage and deep-dive endpoints
// return 202 {jobId} immediately so the request finishes well under the
// Perplexity sites edge-proxy timeout (~100s). The browser then polls the
// new GET /api/v1/osint/ai-jobs/:id endpoint every few seconds until the
// job hits a terminal state (completed/failed).
interface AiJobSnapshot<T = any> {
  id: string;
  kind?: string;
  status: "queued" | "running" | "completed" | "failed";
  progressPct: number;
  result: T | null;
  error: { name?: string; message: string; aiDiagnostic?: any; providerLabel?: string | null } | null;
  providerLabel: string | null;
  createdAt?: string;
  startedAt: string | null;
  completedAt: string | null;
}

interface CirtJobSummary {
  id: string;
  kind: "chat_triage" | "chat_deep_dive";
  status: "completed" | "failed";
  payload: { range?: RangeKey; findingIds?: string[] };
  providerLabel: string | null;
  createdAt: string;
  completedAt: string | null;
  targetLabel: string | null;
  errorMessage: string | null;
  resultBytes: number;
}

interface PreviewResult {
  kind: "chat_triage" | "chat_deep_dive";
  status: "completed" | "failed";
  result: ChatTriageResponse | ChatDeepDiveResponse | null;
  error?: { message?: string } | null;
  label: string;
  providerLabel?: string | null;
  completedAt?: string | null;
}

export function parseCirtDeepLink(hash: string): { mode: "triage" | "deepdive"; jobId: string | null } | null {
  const qix = hash.indexOf("?");
  if (qix < 0) return null;
  const qs = new URLSearchParams(hash.slice(qix + 1));
  const ai = qs.get("ai");
  if (ai !== "triage" && ai !== "deep-dive" && ai !== "deepdive") return null;
  return {
    mode: ai === "triage" ? "triage" : "deepdive",
    jobId: qs.get("job"),
  };
}

async function startAiJob(path: string, body: any): Promise<string> {
  const r = await apiRequest("POST", path, body);
  const json = await r.json();
  if (!json?.jobId) throw new Error("server did not return a job id");
  return String(json.jobId);
}

function parseApiError(e: any): { isAiFailure: boolean; message: string } {
  const raw = String(e?.message || e || "");
  const m = raw.match(/^(\d{3}):\s*(.*)$/s);
  if (!m) return { isAiFailure: false, message: raw };
  const status = Number(m[1]);
  const body = m[2];
  try {
    const parsed = JSON.parse(body);
    if (status === 502 && parsed?.aiDiagnostic) {
      const diag = parsed.aiDiagnostic;
      const provider = parsed.providerLabel ? `"${parsed.providerLabel}" ` : "";
      return {
        isAiFailure: true,
        message: `${provider}returned ${diag.httpStatus ? `HTTP ${diag.httpStatus}` : "no response"} after ${diag.latencyMs}ms — ${diag.reason}.`,
      };
    }
    return { isAiFailure: false, message: parsed.detail || body };
  } catch {
    return { isAiFailure: false, message: body || raw };
  }
}

function downloadDeepDiveReport(result: ChatDeepDiveResponse) {
  const blob = new Blob([result.htmlReport], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = result.htmlFileName || "osint-deep-dive.html";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function formatJobTime(value?: string | null): string {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function cirtJobLabel(job: Pick<CirtJobSummary, "kind" | "payload" | "targetLabel">): string {
  if (job.targetLabel) return job.targetLabel;
  if (job.kind === "chat_triage") {
    const range = job.payload?.range ? RANGE_LABEL[job.payload.range] ?? job.payload.range : "selected range";
    return `CIRT triage — ${range}`;
  }
  const count = job.payload?.findingIds?.length ?? 0;
  return `CIRT deep-dive — ${count} finding${count === 1 ? "" : "s"}`;
}

function previewFromJob(job: AiJobSnapshot<any> | undefined): PreviewResult | null {
  if (!job || (job.kind !== "chat_triage" && job.kind !== "chat_deep_dive")) return null;
  return {
    kind: job.kind,
    status: job.status === "failed" ? "failed" : "completed",
    result: job.result,
    error: job.error,
    label: job.kind === "chat_triage" ? "CIRT triage" : "CIRT deep-dive",
    providerLabel: job.providerLabel,
    completedAt: job.completedAt,
  };
}

interface Props {
  range: RangeKey;
  findings: OsintFindingDTO[];
}

/** Inline triage + deep-dive panel — replaces the old AI Overview card. */
export default function OsintTriagePanel({ range, findings }: Props) {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const [mode, setMode] = useState<"triage" | "deepdive">("triage");
  const [previewJobId, setPreviewJobId] = useState<string | null>(null);
  const [inlinePreview, setInlinePreview] = useState<PreviewResult | null>(null);

  const { data: historyData, refetch: refetchCirtHistory } = useQuery<{ jobs: CirtJobSummary[] }>({
    queryKey: ["/api/v1/osint/ai-jobs/history"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/v1/osint/ai-jobs/history?max=20");
      return r.json();
    },
  });

  const { data: previewJob, isFetching: previewLoading } = useQuery<AiJobSnapshot<any>>({
    queryKey: ["/api/v1/ai-jobs/full", previewJobId],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/v1/ai-jobs/${previewJobId}/full`);
      return r.json();
    },
    enabled: !!previewJobId,
  });

  const cirtHistory = historyData?.jobs ?? [];
  const activePreview = inlinePreview ?? previewFromJob(previewJob);

  useEffect(() => {
    const link = parseCirtDeepLink(window.location.hash || "");
    if (!link) return;
    setMode(link.mode);
    if (link.jobId) setPreviewJobId(link.jobId);
  }, []);

  // Triage state
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageReport, setTriageReport] = useState<ChatTriageResponse | null>(null);
  // v2.27 — surface progress while the server-side AI job is running.
  const [triageStatus, setTriageStatus] = useState<string>("");
  const [triageStartedAt, setTriageStartedAt] = useState<number | null>(null);
  const [, forceTick] = useState(0);
  const tickerRef = useRef<number | null>(null);

  // Re-render once a second while a job is running so the elapsed counter
  // ticks forward without re-fetching.
  useEffect(() => {
    if ((triageLoading || false) && tickerRef.current == null) {
      tickerRef.current = window.setInterval(() => forceTick((n) => n + 1), 1000);
    }
    if (!triageLoading && tickerRef.current != null) {
      clearInterval(tickerRef.current);
      tickerRef.current = null;
    }
    return () => {
      if (tickerRef.current != null) {
        clearInterval(tickerRef.current);
        tickerRef.current = null;
      }
    };
  }, [triageLoading]);

  // Deep dive state
  const [deepLoading, setDeepLoading] = useState(false);
  const [deepStatus, setDeepStatus] = useState<string>("");
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [search, setSearch] = useState("");
  const [lastDeep, setLastDeep] = useState<ChatDeepDiveResponse | null>(null);

  const selectedIds = useMemo(
    () => Object.entries(selected).filter(([, v]) => v).map(([k]) => k),
    [selected],
  );

  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return findings;
    return findings.filter((f) =>
      [f.title, f.summary, f.sourceName, f.severity, ...(f.cveIds || []), ...(f.affectedTech || [])]
        .filter(Boolean).join(" ").toLowerCase().includes(q),
    );
  }, [findings, search]);

  async function runTriage() {
    setTriageLoading(true);
    setTriageReport(null);
    setTriageStatus("Submitting job…");
    setTriageStartedAt(Date.now());
    try {
      // v2.27 — async job + poll. POST returns instantly; the long-running
      // model call happens server-side, immune to edge-proxy timeouts.
      await startAiJob("/api/v1/osint/chat/triage", { range });
      refetchCirtHistory();
      toast({
        title: "CIRT triage queued",
        description: "It will keep running server-side. Open it from the background jobs tray or Recent CIRT Results.",
      });
    } catch (e: any) {
      const parsed = parseApiError(e);
      toast({ variant: "destructive", title: parsed.isAiFailure ? "AI provider failed" : "Triage failed", description: parsed.message });
    } finally {
      setTriageLoading(false);
      setTriageStatus("");
      setTriageStartedAt(null);
    }
  }

  async function runDeepDive() {
    if (selectedIds.length === 0) {
      toast({ variant: "destructive", title: "Select findings first" });
      return;
    }
    setDeepLoading(true);
    setLastDeep(null);
    setDeepStatus("Submitting job…");
    try {
      await startAiJob("/api/v1/osint/chat/deep-dive", { findingIds: selectedIds });
      refetchCirtHistory();
      toast({
        title: "Deep dive queued",
        description: "It will keep running server-side. Open it from the background jobs tray or Recent CIRT Results.",
      });
    } catch (e: any) {
      const parsed = parseApiError(e);
      toast({ variant: "destructive", title: parsed.isAiFailure ? "AI provider failed" : "Deep dive failed", description: parsed.message });
    } finally {
      setDeepLoading(false);
      setDeepStatus("");
    }
  }

  function fmtElapsed(startedAt: number | null): string {
    if (!startedAt) return "";
    const sec = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
  }

  function toggleOne(id: string) { setSelected((s) => ({ ...s, [id]: !s[id] })); }
  function selectAllVisible() {
    const next: Record<string, boolean> = {};
    for (const f of filteredFindings.slice(0, 20)) next[f.id] = true;
    setSelected(next);
  }
  function clearAll() { setSelected({}); }
  function closePreview() {
    setInlinePreview(null);
    setPreviewJobId(null);
  }

  return (
    <Card className="p-4 border-primary/30 bg-gradient-to-br from-primary/5 via-background to-background" data-testid="card-ai-triage-panel">
      <div className="flex items-center gap-2 mb-2">
        <Brain size={14} className="text-primary" />
        <div className="text-sm font-medium">CIRT Triage &amp; Deep Dive</div>
      </div>
      <div className="text-xs text-muted-foreground mb-3">
        CIRT triage groups current findings into priority buckets and preserves source context for review. Deep Dive runs per-finding analysis on a selected subset.
      </div>

      <Tabs value={mode} onValueChange={(v) => setMode(v as any)} className="space-y-3">
        <TabsList data-testid="tabs-triage-panel-mode" className="w-full">
          <TabsTrigger value="triage" className="flex-1" data-testid="tab-triage-inline">
            <Sparkles size={13} className="mr-1.5" /> Initial Triage
          </TabsTrigger>
          <TabsTrigger value="deepdive" className="flex-1" data-testid="tab-deepdive-inline">
            <Search size={13} className="mr-1.5" /> Deep Dive
          </TabsTrigger>
        </TabsList>

        <TabsContent value="triage" className="space-y-3 mt-2">
          <div className="text-xs text-muted-foreground">
            Generates a CIRT Tier 1-4 bucketed report scoped to <strong>{RANGE_LABEL[range]}</strong>. OptraSight fetches source context before triage so the report stays tied to the original evidence.
          </div>
          <Button
            onClick={runTriage}
            disabled={triageLoading || aiDisabled}
            title={aiAvailability.disabledReason}
            data-testid="button-run-triage-inline"
          >
            {triageLoading
              ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Running CIRT triage…</>
              : <><Sparkles size={14} className="mr-1.5" />Run CIRT Triage on {RANGE_LABEL[range]}</>}
          </Button>
          {triageLoading && (
            <div className="text-[11px] text-muted-foreground flex flex-wrap items-center justify-center gap-x-2 gap-y-1 text-center" data-testid="text-triage-status">
              <span className="flex items-center gap-1.5">
                <Loader2 size={11} className="animate-spin" />
                <span>{triageStatus || "Working…"}</span>
              </span>
              {triageStartedAt && <span className="font-mono opacity-70">· {fmtElapsed(triageStartedAt)}</span>}
              <span className="opacity-60">· reasoning runs can take up to ~5 min</span>
            </div>
          )}

          {triageReport && (
            <Card className="p-4 space-y-3" data-testid="card-triage-report-inline">
              <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Badge variant="secondary" className="text-[10px]">{triageReport.itemsAnalysed} items · {triageReport.rangeLabel}</Badge>
                  <span>via {triageReport.providerLabel ?? "configured provider"}</span>
                </div>
                <Button
                  size="sm" variant="outline"
                  onClick={() => { navigator.clipboard.writeText(triageReport.reportMd); toast({ title: "Copied to clipboard" }); }}
                  data-testid="button-copy-triage-inline"
                >
                  Copy Markdown
                </Button>
              </div>
              <div className="prose prose-sm dark:prose-invert max-w-none text-sm leading-relaxed max-h-[420px] overflow-y-auto">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{triageReport.reportMd}</ReactMarkdown>
              </div>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="deepdive" className="space-y-3 mt-2">
          <div className="text-xs text-muted-foreground">
            Multi-select up to 20 findings → AI fetches each source URL, runs per-finding CIRT analysis, and emits a downloadable self-contained HTML report.
          </div>

          <Card className="p-3 bg-muted/30 space-y-2">
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search findings…"
                  className="pl-7 text-xs h-8"
                  data-testid="input-search-findings-inline"
                />
              </div>
              <button type="button" onClick={selectAllVisible} className="text-[11px] underline text-muted-foreground" data-testid="button-select-all-visible-inline">All visible (≤20)</button>
              <button type="button" onClick={clearAll} className="text-[11px] underline text-muted-foreground" data-testid="button-clear-all-inline">Clear</button>
            </div>
            <div className="text-[10px] text-muted-foreground font-mono">
              {selectedIds.length} selected · {filteredFindings.length} visible
            </div>
          </Card>

          <div className="max-h-[320px] overflow-y-auto space-y-1.5 pr-1" data-testid="list-deepdive-findings-inline">
            {filteredFindings.length === 0 ? (
              <Card className="p-6 text-center text-xs text-muted-foreground">
                No findings in the current view. Adjust filters or run a scan first.
              </Card>
            ) : (
              filteredFindings.slice(0, 200).map((f) => {
                const isSelected = !!selected[f.id];
                return (
                  <button
                    type="button"
                    key={f.id}
                    onClick={() => toggleOne(f.id)}
                    className={`w-full text-left p-2 rounded border transition-all ${
                      isSelected ? "bg-primary/10 border-primary/40 ring-1 ring-primary/30" : "bg-card border-border hover:bg-muted/50"
                    }`}
                    data-testid={`button-toggle-finding-inline-${f.id}`}
                  >
                    <div className="flex items-start gap-2">
                      <div className="mt-0.5 shrink-0">
                        {isSelected
                          ? <div className="h-4 w-4 rounded bg-primary text-primary-foreground flex items-center justify-center"><Check size={11} /></div>
                          : <div className="h-4 w-4 rounded border border-muted-foreground/40" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                          <Badge className={`text-[9px] uppercase border ${severityChip(f.severity)}`}>{f.severity}</Badge>
                          <span className="text-[10px] text-muted-foreground truncate">{f.sourceName}</span>
                        </div>
                        <div className="text-xs font-medium truncate">{f.title}</div>
                        {f.cveIds.length > 0 && (
                          <div className="text-[10px] font-mono text-muted-foreground mt-0.5 truncate">{f.cveIds.slice(0, 4).join(" · ")}</div>
                        )}
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>

          <Button
            onClick={runDeepDive}
            disabled={deepLoading || aiDisabled || selectedIds.length === 0 || selectedIds.length > 20}
            title={aiAvailability.disabledReason}
            className="w-full"
            data-testid="button-run-deepdive-inline"
          >
            {deepLoading
              ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Running deep analysis…</>
              : <><Download size={14} className="mr-1.5" />Execute Deep Analysis ({selectedIds.length})</>}
          </Button>
          {deepLoading && (
            <div className="text-[11px] text-muted-foreground flex flex-wrap items-center justify-center gap-x-2 gap-y-1 text-center" data-testid="text-deepdive-status">
              <span className="flex items-center gap-1.5">
                <Loader2 size={11} className="animate-spin" />
                <span>{deepStatus || "Working…"}</span>
              </span>
              <span className="opacity-60">· deep dive runs the AI per finding</span>
            </div>
          )}

          {lastDeep && (
            <Card className="p-3 border-emerald-500/40 bg-emerald-500/5" data-testid="card-deepdive-result-inline">
              <div className="flex items-center gap-2 text-xs text-emerald-600 dark:text-emerald-300 font-medium mb-1">
                <Check size={14} /> Report ready
              </div>
              <div className="text-xs text-muted-foreground mb-2">
                <strong>{lastDeep.htmlFileName}</strong> · {lastDeep.perFinding.length} findings · via {lastDeep.providerLabel ?? "configured provider"}
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setInlinePreview({
                    kind: "chat_deep_dive",
                    status: "completed",
                    result: lastDeep,
                    label: "CIRT deep-dive",
                    providerLabel: lastDeep.providerLabel,
                    completedAt: lastDeep.generatedAt,
                  })}
                  data-testid="button-preview-latest-deepdive"
                >
                  <Eye size={12} className="mr-1.5" />Preview
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => downloadDeepDiveReport(lastDeep)}
                  data-testid="button-download-latest-deepdive"
                >
                  <Download size={12} className="mr-1.5" />Download HTML
                </Button>
              </div>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      <Card className="mt-3 p-3 bg-background/70" data-testid="card-cirt-history">
        <div className="flex items-center justify-between gap-2 mb-2">
          <div className="flex items-center gap-2 text-xs font-medium">
            <Clock size={13} className="text-primary" />
            Recent CIRT results
          </div>
          <Button size="sm" variant="ghost" className="h-7 px-2 text-[11px]" onClick={() => refetchCirtHistory()}>
            Refresh
          </Button>
        </div>
        {cirtHistory.length === 0 ? (
          <div className="text-[11px] text-muted-foreground">No cached CIRT results yet. Completed triage and deep-dive jobs will appear here.</div>
        ) : (
          <div className="space-y-1.5">
            {cirtHistory.slice(0, 5).map((job) => {
              const ok = job.status === "completed";
              return (
                <div key={job.id} className="flex items-center gap-2 rounded-md border bg-card px-2 py-1.5" data-testid={`row-cirt-history-${job.id}`}>
                  <div className="shrink-0">
                    {ok ? <FileText size={13} className="text-primary" /> : <AlertTriangle size={13} className="text-amber-600" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate text-xs font-medium">{cirtJobLabel(job)}</span>
                      <Badge variant="outline" className="text-[9px] px-1.5 py-0">{job.status}</Badge>
                    </div>
                    <div className="text-[10px] text-muted-foreground truncate">
                      {job.providerLabel ?? "AI"} · {formatJobTime(job.completedAt ?? job.createdAt)}
                      {job.errorMessage ? ` · ${job.errorMessage}` : ""}
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 px-2 text-[11px]"
                    disabled={!ok}
                    onClick={() => { setInlinePreview(null); setPreviewJobId(job.id); }}
                    data-testid={`button-preview-cirt-${job.id}`}
                  >
                    <Eye size={11} className="mr-1" />{ok ? "Preview" : "Pending"}
                  </Button>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <Dialog open={!!activePreview || previewLoading} onOpenChange={(open) => { if (!open) closePreview(); }}>
        <DialogContent className="w-[min(1100px,94vw)] max-w-none max-h-[90vh] flex flex-col overflow-hidden">
          <DialogHeader>
            <DialogTitle className="text-base">{activePreview?.label ?? "Loading CIRT result"}</DialogTitle>
            <DialogDescription className="text-xs">
              {activePreview?.providerLabel ?? "AI"}{activePreview?.completedAt ? ` · ${formatJobTime(activePreview.completedAt)}` : ""}
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-y-auto rounded-md border bg-background p-3">
            {previewLoading && !activePreview ? (
              <div className="py-12 text-center text-sm text-muted-foreground">
                <Loader2 size={18} className="mx-auto mb-2 animate-spin" />
                Loading cached result…
              </div>
            ) : activePreview?.status === "failed" ? (
              <div className="text-sm text-amber-700 dark:text-amber-300">
                {activePreview.error?.message ?? "This CIRT job failed without a stored result."}
              </div>
            ) : activePreview?.kind === "chat_triage" && activePreview.result ? (
              <div className="prose prose-sm dark:prose-invert max-w-none">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{(activePreview.result as ChatTriageResponse).reportMd}</ReactMarkdown>
              </div>
            ) : activePreview?.kind === "chat_deep_dive" && activePreview.result ? (
              <iframe
                title="CIRT deep-dive preview"
                className="h-[65vh] w-full rounded bg-white"
                sandbox=""
                srcDoc={(activePreview.result as ChatDeepDiveResponse).htmlReport}
                data-testid="iframe-cirt-deepdive-preview"
              />
            ) : (
              <div className="text-sm text-muted-foreground">No cached result body is available.</div>
            )}
          </div>
          <DialogFooter>
            {activePreview?.kind === "chat_triage" && activePreview.result && (
              <Button
                variant="outline"
                onClick={() => { navigator.clipboard.writeText((activePreview.result as ChatTriageResponse).reportMd); toast({ title: "Copied to clipboard" }); }}
                data-testid="button-copy-cirt-preview"
              >
                <Copy size={13} className="mr-1.5" />Copy Markdown
              </Button>
            )}
            {activePreview?.kind === "chat_deep_dive" && activePreview.result && (
              <Button
                variant="outline"
                onClick={() => downloadDeepDiveReport(activePreview.result as ChatDeepDiveResponse)}
                data-testid="button-download-cirt-preview"
              >
                <Download size={13} className="mr-1.5" />Download HTML
              </Button>
            )}
            <Button variant="secondary" onClick={closePreview}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

function severityChip(s: string) {
  switch (s) {
    case "critical": return "bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30";
    case "high":     return "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30";
    case "medium":   return "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30";
    case "low":      return "bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30";
    default:         return "bg-muted text-muted-foreground border-border";
  }
}
