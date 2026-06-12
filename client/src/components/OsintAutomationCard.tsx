/**
 * OptraSight v2.16 — OSINT automation settings card
 * ----------------------------------------------------------------------------
 * Lets operators toggle "fetch every N minutes" and "analyze every new intel
 * in the background" so deep-dive becomes an instant retrieval against the
 * pre-populated per-finding CIRT cache instead of a 60-120s synchronous AI
 * call. Polls /api/v1/osint/automation/settings every 15s while open so the
 * "last run / queue depth / last error" pills update without a page refresh.
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useAiAvailability } from "@/lib/aiAvailability";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { AlertCircle, CheckCircle2, Clock, Loader2, RefreshCw, Zap, RotateCcw } from "lucide-react";

interface AutomationSettings {
  tenantId: string;
  autoFetchEnabled: boolean;
  fetchIntervalMin: number;
  autoAnalyzeEnabled: boolean;
  analyzeConcurrency: number;
  analyzeMaxPerTick: number;
  lastFetchAt: string | null;
  lastFetchCount: number | null;
  lastFetchError: string | null;
  lastAnalyzeAt: string | null;
  lastAnalyzeOkCount: number;
  lastAnalyzeFailCount: number;
  lastAnalyzeError: string | null;
  updatedAt: string;
}
interface QueueStats {
  pending: number;
  done: number;
  failed: number;
  total: number;
}
interface AutomationResponse {
  settings: AutomationSettings;
  queue: QueueStats;
}

export function relativeTime(iso: string | null, nowMs = Date.now()): string {
  if (!iso) return "never";
  const ms = nowMs - Date.parse(iso);
  if (Number.isNaN(ms) || ms < 0) return "just now";
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

export function canRunAnalyzeNow(opts: {
  mutationPending: boolean;
  autoAnalyzeEnabled: boolean;
  aiDisabled: boolean;
}): boolean {
  return !opts.mutationPending && opts.autoAnalyzeEnabled && !opts.aiDisabled;
}

export default function OsintAutomationCard() {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const qc = useQueryClient();

  const { data, isLoading } = useQuery<AutomationResponse>({
    queryKey: ["/api/v1/osint/automation/settings"],
    refetchInterval: 15_000,
  });

  // Local draft so the user can type into number inputs without each keystroke
  // hammering the API. Synced from server data on first load and on save.
  const [draft, setDraft] = useState<AutomationSettings | null>(null);
  useEffect(() => {
    if (data?.settings && !draft) setDraft(data.settings);
  }, [data, draft]);

  const patchMutation = useMutation({
    mutationFn: async (patch: Partial<AutomationSettings>) => {
      const r = await apiRequest("PATCH", "/api/v1/osint/automation/settings", patch);
      return (await r.json()) as AutomationResponse;
    },
    onSuccess: (resp) => {
      setDraft(resp.settings);
      qc.setQueryData(["/api/v1/osint/automation/settings"], resp);
      toast({ title: "Automation settings updated" });
    },
    onError: (e: any) => {
      toast({ variant: "destructive", title: "Could not save", description: String(e?.message || e) });
    },
  });

  const fetchNowMutation = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", "/api/v1/osint/automation/fetch-now", {});
      return await r.json();
    },
    onSuccess: () => {
      toast({ title: "Fetch started in the background", description: "Status will appear here when it completes." });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["/api/v1/osint/automation/settings"] }), 3_000);
    },
  });

  const analyzeNowMutation = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", "/api/v1/osint/automation/analyze-now", {});
      return await r.json();
    },
    onSuccess: () => {
      toast({ title: "Analysis started in the background", description: "Each new intel is analyzed individually — watch the queue counters update." });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["/api/v1/osint/automation/settings"] }), 3_000);
    },
  });

  const resetCacheMutation = useMutation({
    mutationFn: async (failedOnly: boolean) => {
      const r = await apiRequest("POST", "/api/v1/osint/automation/reset-cache", { failedOnly });
      return await r.json();
    },
    onSuccess: (resp: any) => {
      toast({ title: "Cache reset", description: `${resp.reset} finding(s) re-queued for analysis.` });
      qc.invalidateQueries({ queryKey: ["/api/v1/osint/automation/settings"] });
      qc.invalidateQueries({ queryKey: ["/api/v1/osint/findings"] });
    },
  });

  if (isLoading || !draft || !data) {
    return (
      <Card>
        <CardHeader><CardTitle>OSINT automation</CardTitle></CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          <Loader2 className="inline h-4 w-4 mr-2 animate-spin" /> Loading settings…
        </CardContent>
      </Card>
    );
  }

  const q = data.queue;
  const s = data.settings;
  const dirty =
    draft.autoFetchEnabled !== s.autoFetchEnabled ||
    draft.fetchIntervalMin !== s.fetchIntervalMin ||
    draft.autoAnalyzeEnabled !== s.autoAnalyzeEnabled ||
    draft.analyzeConcurrency !== s.analyzeConcurrency ||
    draft.analyzeMaxPerTick !== s.analyzeMaxPerTick;

  return (
    <Card data-testid="card-osint-automation">
      <CardHeader className="space-y-1">
        <CardTitle className="flex items-center gap-2">
          <Zap className="h-4 w-4 text-amber-500" />
          OSINT automation
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          Run intel fetching on a schedule and let the AI analyse each new finding in the background. Deep dive then
          returns instantly because the per-intel CIRT analysis is already cached.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Auto-fetch row */}
        <section className="space-y-3">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1">
              <Label className="text-sm font-medium">Auto-fetch new intel</Label>
              <p className="text-xs text-muted-foreground">
                Pulls the workspace's monitored sources every interval. Same logic as the manual <em>Scan now</em> button.
              </p>
            </div>
            <Switch
              data-testid="switch-auto-fetch"
              checked={draft.autoFetchEnabled}
              onCheckedChange={(v) => setDraft({ ...draft, autoFetchEnabled: v })}
            />
          </div>
          <div className="flex items-center gap-3">
            <Label className="text-xs w-24 text-muted-foreground">Every</Label>
            <Input
              type="number"
              min={15}
              max={1440}
              step={15}
              className="w-24"
              value={draft.fetchIntervalMin}
              onChange={(e) => setDraft({ ...draft, fetchIntervalMin: Number(e.target.value || 60) })}
              disabled={!draft.autoFetchEnabled}
              data-testid="input-fetch-interval"
            />
            <span className="text-xs text-muted-foreground">minutes (15\u20131440)</span>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge variant="outline" className="font-normal">
              <Clock className="h-3 w-3 mr-1" /> Last fetch: {relativeTime(s.lastFetchAt)}
            </Badge>
            {s.lastFetchCount != null && (
              <Badge variant="outline" className="font-normal">+{s.lastFetchCount} findings</Badge>
            )}
            {s.lastFetchError && (
              <Badge variant="destructive" className="font-normal" title={s.lastFetchError}>
                <AlertCircle className="h-3 w-3 mr-1" />
                Last fetch error: {s.lastFetchError.slice(0, 80)}
              </Badge>
            )}
            <Button
              size="sm"
              variant="outline"
              className="h-7"
              onClick={() => fetchNowMutation.mutate()}
              disabled={fetchNowMutation.isPending}
              data-testid="button-fetch-now"
            >
              {fetchNowMutation.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <RefreshCw className="h-3 w-3 mr-1" />}
              Fetch now
            </Button>
          </div>
        </section>

        <Separator />

        {/* Auto-analyze row */}
        <section className="space-y-3">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1">
              <Label className="text-sm font-medium">Auto-analyse each new intel</Label>
              <p className="text-xs text-muted-foreground">
                The background analyser pulls findings off the queue and runs <strong>one CIRT deep-dive per finding</strong>{" "}
                against the configured AI provider. Single-finding calls fit the 90s/6000-token budget, so they almost
                never time out (unlike the 20-finding batch deep-dive). Requires a live AI provider under AI Setup.
              </p>
            </div>
            <Switch
              data-testid="switch-auto-analyze"
              checked={draft.autoAnalyzeEnabled}
              onCheckedChange={(v) => setDraft({ ...draft, autoAnalyzeEnabled: v })}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Concurrent calls</Label>
              <Input
                type="number" min={1} max={8} step={1}
                value={draft.analyzeConcurrency}
                onChange={(e) => setDraft({ ...draft, analyzeConcurrency: Number(e.target.value || 2) })}
                disabled={!draft.autoAnalyzeEnabled}
                data-testid="input-analyze-concurrency"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Max per minute</Label>
              <Input
                type="number" min={1} max={50} step={1}
                value={draft.analyzeMaxPerTick}
                onChange={(e) => setDraft({ ...draft, analyzeMaxPerTick: Number(e.target.value || 8) })}
                disabled={!draft.autoAnalyzeEnabled}
                data-testid="input-analyze-max"
              />
            </div>
          </div>

          {/* Queue stats */}
          <div className="grid grid-cols-3 gap-2">
            <div className="rounded border p-2 text-center">
              <div className="text-xs text-muted-foreground">Pending</div>
              <div className="text-lg font-semibold" data-testid="stat-pending">{q.pending}</div>
            </div>
            <div className="rounded border p-2 text-center bg-emerald-50 dark:bg-emerald-950/40">
              <div className="text-xs text-muted-foreground">Analysed</div>
              <div className="text-lg font-semibold text-emerald-700 dark:text-emerald-300" data-testid="stat-done">{q.done}</div>
            </div>
            <div className="rounded border p-2 text-center bg-rose-50 dark:bg-rose-950/40">
              <div className="text-xs text-muted-foreground">Failed</div>
              <div className="text-lg font-semibold text-rose-700 dark:text-rose-300" data-testid="stat-failed">{q.failed}</div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge variant="outline" className="font-normal">
              <Clock className="h-3 w-3 mr-1" /> Last analyse: {relativeTime(s.lastAnalyzeAt)}
            </Badge>
            {(s.lastAnalyzeOkCount > 0 || s.lastAnalyzeFailCount > 0) && (
              <Badge variant="outline" className="font-normal">
                <CheckCircle2 className="h-3 w-3 mr-1 text-emerald-500" />
                {s.lastAnalyzeOkCount} ok / {s.lastAnalyzeFailCount} fail
              </Badge>
            )}
            {s.lastAnalyzeError && (
              <Badge variant="destructive" className="font-normal" title={s.lastAnalyzeError}>
                <AlertCircle className="h-3 w-3 mr-1" />
                {s.lastAnalyzeError.slice(0, 80)}
              </Badge>
            )}
            <Button
              size="sm" variant="outline" className="h-7"
              onClick={() => analyzeNowMutation.mutate()}
              disabled={!canRunAnalyzeNow({
                mutationPending: analyzeNowMutation.isPending,
                autoAnalyzeEnabled: s.autoAnalyzeEnabled,
                aiDisabled,
              })}
              title={aiAvailability.disabledReason}
              data-testid="button-analyze-now"
            >
              {analyzeNowMutation.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Zap className="h-3 w-3 mr-1" />}
              Analyse now
            </Button>
            <Button
              size="sm" variant="ghost" className="h-7"
              onClick={() => resetCacheMutation.mutate(true)}
              disabled={resetCacheMutation.isPending || q.failed === 0}
              data-testid="button-retry-failed"
            >
              <RotateCcw className="h-3 w-3 mr-1" />
              Retry failed ({q.failed})
            </Button>
            <Button
              size="sm" variant="ghost" className="h-7 text-muted-foreground"
              onClick={() => {
                if (window.confirm(`Reset CIRT analysis cache for ALL ${q.total} findings? The background analyser will re-run each one.`)) {
                  resetCacheMutation.mutate(false);
                }
              }}
              disabled={resetCacheMutation.isPending}
              data-testid="button-reset-all"
            >
              Reset all
            </Button>
          </div>
        </section>

        <Separator />

        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Background scheduler runs every 60s and respects the interval above.
          </p>
          <Button
            size="sm"
            disabled={!dirty || patchMutation.isPending}
            onClick={() => patchMutation.mutate({
              autoFetchEnabled: draft.autoFetchEnabled,
              fetchIntervalMin: draft.fetchIntervalMin,
              autoAnalyzeEnabled: draft.autoAnalyzeEnabled,
              analyzeConcurrency: draft.analyzeConcurrency,
              analyzeMaxPerTick: draft.analyzeMaxPerTick,
            })}
            data-testid="button-save-automation"
          >
            {patchMutation.isPending && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
            Save changes
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
