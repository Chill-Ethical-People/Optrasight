import { useEffect, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import {
  AI_TASKS, AI_PROVIDERS, type AiProviderSummary, type AiTask, type AiProviderKind,
} from "@shared/schema";
import {
  Sparkles, Eye, EyeOff, Save, Loader2, CheckCircle2, XCircle, Plus, Trash2, Settings2,
} from "lucide-react";

const PROVIDER_META: Record<AiProviderKind, { label: string; defaultModel: string; defaultBase?: string; tone: string; needsKey: boolean }> = {
  "openai":         { label: "OpenAI",         defaultModel: "gpt-5.5",              tone: "from-emerald-500/15 to-emerald-500/5 border-emerald-500/30", needsKey: true },
  "anthropic":      { label: "Anthropic",      defaultModel: "claude-sonnet-4-6",    tone: "from-orange-500/15 to-orange-500/5 border-orange-500/30",   needsKey: true },
  "gemini":         { label: "Google Gemini",  defaultModel: "gemini-2.5-flash",     tone: "from-blue-500/15 to-blue-500/5 border-blue-500/30",         needsKey: true },
  "azure-openai":   { label: "Azure OpenAI",   defaultModel: "gpt-5.4",              tone: "from-cyan-500/15 to-cyan-500/5 border-cyan-500/30",         needsKey: true },
  "ollama":         { label: "Ollama (self-hosted)", defaultModel: "llama3.1:8b",    defaultBase: "http://localhost:11434", tone: "from-slate-500/15 to-slate-500/5 border-slate-500/30", needsKey: false },
  "perplexity":     { label: "Perplexity",     defaultModel: "sonar-pro",            tone: "from-violet-500/15 to-violet-500/5 border-violet-500/30",   needsKey: true },
  "deepseek":       { label: "DeepSeek",       defaultModel: "deepseek-v4-flash",    defaultBase: "https://api.deepseek.com", tone: "from-indigo-500/15 to-indigo-500/5 border-indigo-500/30", needsKey: true },
  "kimi":           { label: "Kimi (Moonshot)", defaultModel: "kimi-latest",         defaultBase: "https://api.moonshot.ai", tone: "from-fuchsia-500/15 to-fuchsia-500/5 border-fuchsia-500/30", needsKey: true },
};

// Quick-pick model presets per provider — surfaced as clickable chips under the
// Model input in the provider edit dialog so users don't have to hand-type names.
// Latest verified IDs as of May 2026 — confirmed against each vendor's docs.
const MODEL_PRESETS: Record<AiProviderKind, string[]> = {
  "openai":         ["gpt-5.5", "gpt-5.5-pro", "gpt-5.4", "gpt-5.4-mini", "gpt-5.4-nano", "gpt-4o-mini", "gpt-4o"],
  "anthropic":      ["claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5", "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"],
  "gemini":         ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.5-flash-lite", "gemini-1.5-pro"],
  "azure-openai":   ["gpt-5.4", "gpt-5.4-mini", "gpt-4o", "gpt-4o-mini"],
  "ollama":         ["llama3.1:8b", "llama3.1:70b", "qwen2.5:14b", "mistral:7b", "deepseek-r1:14b"],
  "perplexity":     ["sonar-pro", "sonar", "sonar-reasoning-pro", "sonar-deep-research"],
  "deepseek":       ["deepseek-v4-flash", "deepseek-v4-pro", "deepseek-chat", "deepseek-reasoner"],
  // Moonshot Kimi — OpenAI-compatible endpoint, multiple vision-capable models.
  "kimi":           ["kimi-latest", "kimi-k2-instruct", "moonshot-v1-128k", "moonshot-v1-32k", "moonshot-v1-8k"],
};

// Short note shown next to each model chip on hover so the user knows what each is for.
const MODEL_DESCRIPTIONS: Record<string, string> = {
  // OpenAI
  "gpt-5.5":            "Flagship reasoning + coding (2026)",
  "gpt-5.5-pro":        "Highest-quality GPT-5.5 (more compute)",
  "gpt-5.4":            "Cheaper GPT-5.4 for coding & pro work",
  "gpt-5.4-mini":       "Strongest mini — agents, computer use",
  "gpt-5.4-nano":       "Cheapest GPT-5.4 for high-volume",
  "gpt-4o-mini":        "Fast, affordable GPT-4o",
  "gpt-4o":             "Older flagship — multimodal",
  // Anthropic
  "claude-opus-4-7":          "Most capable Claude — agentic coding",
  "claude-sonnet-4-6":        "Best speed/intelligence balance",
  "claude-haiku-4-5":         "Fastest Claude with frontier-near IQ",
  "claude-3-5-sonnet-latest": "Legacy Sonnet 3.5 (still supported)",
  "claude-3-5-haiku-latest":  "Legacy Haiku 3.5",
  // Gemini
  "gemini-2.5-pro":        "Adaptive thinking, 1M context",
  "gemini-2.5-flash":      "Balanced speed/quality",
  "gemini-2.5-flash-lite": "Cheapest Gemini 2.5",
  "gemini-1.5-pro":        "Legacy multimodal Gemini",
  // DeepSeek
  "deepseek-v4-flash":  "284B/13B active — fast, cheap, 1M ctx",
  "deepseek-v4-pro":    "1.6T/49B active — rivals top closed models",
  "deepseek-chat":      "Legacy alias of v4-flash non-thinking mode (deprecates 2026-07-24)",
  "deepseek-reasoner":  "Legacy alias of v4-flash thinking mode (deprecates 2026-07-24)",
  // Perplexity
  "sonar-pro":          "Advanced search with grounding",
  "sonar":              "Lightweight, cost-effective search",
  "sonar-reasoning-pro":"Chain-of-Thought reasoning + search",
  "sonar-deep-research":"Exhaustive multi-source research reports",
  // Ollama
  "llama3.1:8b":        "Meta Llama 3.1 8B — fast local",
  "llama3.1:70b":       "Meta Llama 3.1 70B — heavy local",
  "qwen2.5:14b":        "Alibaba Qwen 2.5 14B",
  "mistral:7b":         "Mistral 7B — small, fast",
  "deepseek-r1:14b":    "DeepSeek-R1 distilled — local reasoning",
  // Kimi / Moonshot
  "kimi-latest":         "Vision-capable, auto-routes to current Kimi flagship",
  "kimi-k2-instruct":    "Open-weights K2, agentic + tool use, 128K ctx",
  "moonshot-v1-128k":    "128K-context, balanced quality/cost",
  "moonshot-v1-32k":     "32K-context for shorter prompts (cheaper)",
  "moonshot-v1-8k":      "8K-context for low-volume cheap calls",
};

const TASK_META: Record<AiTask, { label: string; description: string }> = {
  triage:         { label: "Finding triage",       description: "Classify each finding (severity, recommended status, IOCs)." },
  analysis:       { label: "Deep analysis",        description: "Free-form follow-on analysis on demand." },
  young_domain:   { label: "Young-domain verdict", description: "Phishing / impersonation classification with screenshot context." },
  report_summary: { label: "Report summary",       description: "Executive summary, key findings and recommendations." },
  logo_abuse:     { label: "Logo / trademark abuse", description: "Compare scraped imagery against client logo and trademark assets." },
  osint_analysis: { label: "OSINT analysis",       description: "Score relevance of OSINT findings to the client and recommend response." },
  hunt_query:     { label: "Threat-hunt query",    description: "Generate SIEM/EDR hunting queries (Splunk, KQL, Chronicle, Sigma…) from selected findings." },
  threat_landscape: { label: "Threat landscape",   description: "Synthesize a markdown threat-landscape report from recent OSINT and client profile." },
  email_draft:    { label: "Client email draft",   description: "Draft a notification email to client contacts based on selected findings." },
  osint_overview: { label: "OSINT AI overview",    description: "Persona-tuned (IR / TI / SecOps) summary, takeaways and recommendations across scoped OSINT findings." },
  detection_rule:  { label: "Detection rule",       description: "Generate Sigma YAML + per-SIEM compiled queries (Splunk, KQL, FQL, XQL, YARA-L…) with MITRE mapping from selected intel." },
  threat_actor_enrichment: { label: "Threat actor profile", description: "Enrich a Threat Actor Profile (TAP) end-to-end from primaryName + aliases — 13 sections + IOCs, references, MITRE TTPs." },
  exercise_generation: { label: "Tabletop exercise",   description: "Generate a scenario narrative, role briefs, inject timeline, and evaluation rubric for a tabletop exercise." },
};

// Defensive fallback: if a new AiTask is added to shared/schema.ts but the
// label dictionary above is not updated in the same commit, render a humanised
// version of the task id rather than crashing the whole page.
function taskMeta(t: AiTask): { label: string; description: string } {
  const m = TASK_META[t];
  if (m) return m;
  const label = String(t).replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  return { label, description: "" };
}

interface AssignmentsResp { assignments: Record<string, string> }
interface ProvidersResp { providers: AiProviderSummary[]; hasUsableProvider?: boolean }

function fmtTime(s: string | null | undefined) {
  if (!s) return "Never";
  try { return new Date(s).toLocaleString(); } catch { return s; }
}

function ProviderCard({
  p,
  onEdit,
  onDelete,
}: {
  p: AiProviderSummary;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { toast } = useToast();
  const meta = PROVIDER_META[p.provider];

  const toggle = useMutation({
    mutationFn: async (enabled: boolean) => {
      // v2.12 fix: server schema requires provider/label/model on PUT, so send the
      // full provider summary plus the new enabled flag rather than just { enabled }.
      const r = await apiRequest("PUT", `/api/v1/ai/providers/${p.id}`, {
        provider: p.provider,
        label: p.label,
        model: p.model,
        baseUrl: p.baseUrl ?? "",
        enabled,
        isDefault: p.isDefault,
      });
      return r.json();
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/v1/ai/providers"] }),
    onError: (e: any) => toast({ variant: "destructive", title: "Failed", description: String(e.message ?? e) }),
  });

  const test = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", `/api/v1/ai/providers/${p.id}/test`);
      return r.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/ai/providers"] });
      toast({
        title: data.ok ? "Connected" : "Connection failed",
        description: `${p.label} · ${data.message}${data.latencyMs ? ` (${data.latencyMs}ms)` : ""}`,
        variant: data.ok ? undefined : "destructive",
      });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Test failed", description: String(e.message ?? e) }),
  });

  const dot =
    p.lastTestOk == null ? "bg-muted-foreground/40" :
    p.lastTestOk ? "bg-emerald-500" : "bg-rose-500";

  return (
    <Card className={`p-4 flex flex-col gap-3 border bg-gradient-to-br ${meta.tone}`} data-testid={`card-provider-${p.id}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <div className="font-semibold text-sm truncate" data-testid={`text-provider-label-${p.id}`}>{p.label}</div>
            {p.isDefault && (
              <Badge variant="secondary" className="text-[10px] uppercase tracking-wide">Default</Badge>
            )}
          </div>
          <div className="text-xs text-muted-foreground font-mono truncate">{meta.label} · {p.model}</div>
          {p.baseUrl && (
            <div className="text-[10px] text-muted-foreground/70 font-mono truncate" title={p.baseUrl}>{p.baseUrl}</div>
          )}
        </div>
        <Switch
          checked={p.enabled}
          onCheckedChange={(v) => toggle.mutate(v)}
          disabled={toggle.isPending}
          data-testid={`switch-provider-${p.id}`}
          aria-label={`Enable ${p.label}`}
        />
      </div>

      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">API key</span>
        {meta.needsKey ? (
          <span className="font-mono text-muted-foreground/80 truncate ml-2" data-testid={`text-key-mask-${p.id}`}>
            {p.apiKeyMask || "(not set)"}
          </span>
        ) : (
          <span className="text-muted-foreground/70 italic">no key required</span>
        )}
      </div>

      <div className="flex items-center justify-between gap-2 pt-1 border-t">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className={`size-2 rounded-full ${dot}`} />
          <span className="text-[11px] text-muted-foreground truncate" title={p.lastTestMessage || ""} data-testid={`text-last-test-${p.id}`}>
            {p.lastTestedAt ? `Tested ${fmtTime(p.lastTestedAt)}` : "Never tested"}
          </span>
        </div>
        <div className="flex items-center gap-1">
          <Button
            type="button" variant="outline" size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => test.mutate()}
            disabled={test.isPending || !p.enabled}
            data-testid={`button-test-provider-${p.id}`}
          >
            {test.isPending ? <><Loader2 size={12} className="mr-1 animate-spin" />Testing</> :
             p.lastTestOk === true ? <><CheckCircle2 size={12} className="mr-1" />Test</> :
             p.lastTestOk === false ? <><XCircle size={12} className="mr-1" />Retry</> :
             "Test"}
          </Button>
          <Button
            type="button" variant="ghost" size="icon"
            className="h-7 w-7"
            onClick={onEdit}
            data-testid={`button-edit-provider-${p.id}`}
            aria-label="Edit provider"
          >
            <Settings2 size={13} />
          </Button>
          {!p.isDefault && (
            <Button
              type="button" variant="ghost" size="icon"
              className="h-7 w-7 text-muted-foreground hover:text-destructive"
              onClick={onDelete}
              data-testid={`button-delete-provider-${p.id}`}
              aria-label="Delete provider"
            >
              <Trash2 size={13} />
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

function ProviderEditDialog({
  open, onOpenChange, initial,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  initial: Partial<AiProviderSummary> | null;
}) {
  const { toast } = useToast();
  const [provider, setProvider] = useState<AiProviderKind>("openai");
  const [label, setLabel] = useState("");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [isDefault, setIsDefault] = useState(false);

  useEffect(() => {
    if (open) {
      const p = initial?.provider ?? "openai";
      setProvider(p);
      setLabel(initial?.label ?? PROVIDER_META[p].label);
      setModel(initial?.model ?? PROVIDER_META[p].defaultModel);
      setBaseUrl(initial?.baseUrl ?? PROVIDER_META[p].defaultBase ?? "");
      setApiKey("");
      setShowKey(false);
      setIsDefault(initial?.isDefault ?? false);
    }
  }, [open, initial]);

  const save = useMutation({
    mutationFn: async () => {
      const payload: any = {
        provider, label, model,
        baseUrl: baseUrl || undefined,
        enabled: true,
        isDefault,
      };
      if (apiKey) payload.apiKey = apiKey;
      if (initial?.id) {
        await apiRequest("PUT", `/api/v1/ai/providers/${initial.id}`, payload);
      } else {
        await apiRequest("POST", "/api/v1/ai/providers", payload);
      }
    },
    onSuccess: () => {
      setApiKey("");
      setShowKey(false);
      toast({ title: initial?.id ? "Provider updated" : "Provider added", description: label });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/ai/providers"] });
      onOpenChange(false);
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed", description: String(e.message ?? e) }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">{initial?.id ? "Edit AI provider" : "Add AI provider"}</DialogTitle>
          <DialogDescription className="text-xs">
            Credentials are encrypted at rest and never leave the tenant.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label className="text-xs text-muted-foreground">Provider</Label>
            <Select
              value={provider}
              onValueChange={(v) => {
                const p = v as AiProviderKind;
                setProvider(p);
                if (!initial?.id) {
                  setLabel(PROVIDER_META[p].label);
                  setModel(PROVIDER_META[p].defaultModel);
                  setBaseUrl(PROVIDER_META[p].defaultBase ?? "");
                }
              }}
              disabled={!!initial?.id}
            >
              <SelectTrigger data-testid="select-provider-kind"><SelectValue /></SelectTrigger>
              <SelectContent>
                {AI_PROVIDERS.map((k) => (
                  <SelectItem key={k} value={k}>{PROVIDER_META[k].label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground">Label</Label>
            <Input
              value={label} onChange={(e) => setLabel(e.target.value)}
              placeholder="OpenAI Production" data-testid="input-provider-label"
            />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground">Model</Label>
            <Input
              value={model} onChange={(e) => setModel(e.target.value)}
              placeholder="gpt-4o-mini" className="font-mono text-sm"
              data-testid="input-provider-model"
            />
            {MODEL_PRESETS[provider]?.length > 0 && (
              <div className="mt-1.5 space-y-1">
                <div className="flex flex-wrap gap-1">
                  {MODEL_PRESETS[provider].map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setModel(m)}
                      title={MODEL_DESCRIPTIONS[m] ?? ""}
                      className={`text-[10px] px-1.5 py-0.5 rounded font-mono border transition-colors ${model === m ? "bg-primary text-primary-foreground border-primary" : "bg-muted/40 hover:bg-muted text-muted-foreground border-border"}`}
                      data-testid={`button-model-preset-${m}`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
                {MODEL_DESCRIPTIONS[model] && (
                  <p className="text-[10px] text-muted-foreground italic" data-testid="text-model-description">
                    {MODEL_DESCRIPTIONS[model]}
                  </p>
                )}
              </div>
            )}
          </div>
          {(provider === "ollama" || provider === "azure-openai") && (
            <div>
              <Label className="text-xs text-muted-foreground">Base URL</Label>
              <Input
                value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://localhost:11434" className="font-mono text-sm"
                data-testid="input-provider-base-url"
              />
            </div>
          )}
          {PROVIDER_META[provider].needsKey && (
            <div>
              <Label className="text-xs text-muted-foreground">
                API key {initial?.id ? "(leave blank to keep existing)" : ""}
              </Label>
              <div className="flex items-center gap-1.5">
                <Input
                  type={showKey ? "text" : "password"}
                  value={apiKey} onChange={(e) => setApiKey(e.target.value)}
                  placeholder="sk-…" className="font-mono text-sm"
                  autoComplete="off"
                  spellCheck={false}
                  data-testid="input-provider-key"
                />
                <Button
                  type="button" variant="ghost" size="icon" className="h-9 w-9 shrink-0"
                  onClick={() => setShowKey((v) => !v)} aria-label="Toggle visibility"
                  data-testid="button-toggle-key-visibility"
                >
                  {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                </Button>
              </div>
            </div>
          )}
          <label className="flex items-center gap-2 text-xs cursor-pointer">
            <Switch checked={isDefault} onCheckedChange={setIsDefault} data-testid="switch-provider-default" />
            <span>Use as default for unassigned tasks</span>
          </label>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} data-testid="button-cancel-provider">Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !label || !model} data-testid="button-save-provider">
            {save.isPending ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Saving</> : <><Save size={14} className="mr-1.5" />Save</>}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function AISetup() {
  const { toast } = useToast();
  const [editing, setEditing] = useState<Partial<AiProviderSummary> | null>(null);
  const [editOpen, setEditOpen] = useState(false);

  const { data: providersData, isLoading: providersLoading } = useQuery<ProvidersResp>({
    queryKey: ["/api/v1/ai/providers"],
  });
  const providers = providersData?.providers ?? [];

  const { data: assignmentsData } = useQuery<AssignmentsResp>({
    queryKey: ["/api/v1/ai/assignments"],
  });
  const assignments = assignmentsData?.assignments ?? {};

  const [draftAssignments, setDraftAssignments] = useState<Record<string, string>>({});
  useEffect(() => {
    setDraftAssignments({ ...assignments });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assignmentsData]);

  const dirty =
    Object.keys(draftAssignments).length > 0 &&
    AI_TASKS.some((t) => draftAssignments[t] !== assignments[t]);

  const saveAssignments = useMutation({
    mutationFn: async () => {
      await apiRequest("PUT", "/api/v1/ai/assignments", { assignments: draftAssignments });
    },
    onSuccess: () => {
      toast({ title: "Routing saved", description: "AI tasks will use the new providers." });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/ai/assignments"] });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed", description: String(e.message ?? e) }),
  });

  const del = useMutation({
    mutationFn: async (id: string) => { await apiRequest("DELETE", `/api/v1/ai/providers/${id}`); },
    onSuccess: () => {
      toast({ title: "Provider removed" });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/ai/providers"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/ai/assignments"] });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Delete failed", description: String(e.message ?? e) }),
  });

  const enabledProviders = providers.filter((p) => p.enabled);
  const keyedProviders = providers.filter((p) => p.enabled && p.hasKey && p.lastTestOk === true);
  const enabledCount = enabledProviders.length;
  const usableCount = keyedProviders.length;

  return (
    <AppShell>
      <div className="px-6 md:px-10 py-8 max-w-[1400px]">
        <PageHeader
          title="AI provider setup"
          description="Configure language-model providers and route each OptraSight AI task to the model best suited for it."
          actions={
            <div className="flex items-center gap-2">
              <Badge variant="secondary" className="font-mono">
                <Sparkles size={12} className="mr-1" />
                {usableCount}/{providers.length} live
              </Badge>
              <Button
                size="sm" onClick={() => { setEditing(null); setEditOpen(true); }}
                data-testid="button-add-provider"
              >
                <Plus size={14} className="mr-1.5" /> Add provider
              </Button>
            </div>
          }
        />

        <section className="mb-8">
          <div className="flex items-center gap-2 mb-3">
            <div className="text-sm font-semibold">Providers</div>
            <div className="text-xs text-muted-foreground">{providers.length} configured</div>
          </div>

          {providersLoading ? (
            <Card className="p-12 text-center text-sm text-muted-foreground">Loading…</Card>
          ) : providers.length === 0 ? (
            <Card className="p-12 text-center">
              <Sparkles className="mx-auto mb-3 text-muted-foreground" size={28} />
              <div className="text-sm font-medium">No AI providers configured</div>
              <div className="text-xs text-muted-foreground mt-1">Add one to enable triage and analysis.</div>
            </Card>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {providers.map((p) => (
                <ProviderCard
                  key={p.id}
                  p={p}
                  onEdit={() => { setEditing(p); setEditOpen(true); }}
                  onDelete={() => del.mutate(p.id)}
                />
              ))}
            </div>
          )}
        </section>

        <section>
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-sm font-semibold">Task routing</div>
              <div className="text-xs text-muted-foreground">Pick which provider handles each AI workload across OptraSight.</div>
            </div>
            <Button
              onClick={() => saveAssignments.mutate()}
              disabled={!dirty || saveAssignments.isPending || usableCount === 0}
              data-testid="button-save-assignments"
            >
              {saveAssignments.isPending ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Saving</> : <><Save size={14} className="mr-1.5" />Save routing</>}
            </Button>
          </div>

          {/* Routing grid — `auto-rows-fr` makes every row stretch to the tallest
           *  cell, so the dropdown row at the bottom of each card aligns across
           *  columns regardless of how long the task description is. */}
          <Card className="overflow-hidden">
            <div className="grid grid-cols-1 md:grid-cols-2 auto-rows-fr md:divide-x divide-y md:divide-y-0">
              {AI_TASKS.map((task, idx) => {
                const meta = taskMeta(task);
                const value = draftAssignments[task] ?? "";
                // Row separator: every cell from index 2 onward sits on a new
                // grid row in 2-col layout, so it needs a top border to keep
                // the divider rhythm intact when `divide-y` is hidden at `md`.
                const needsRowBorder = idx >= 2;
                return (
                  <div
                    key={task}
                    className={`p-4 flex flex-col h-full ${needsRowBorder ? "md:border-t" : ""}`}
                  >
                    <div className="flex items-start justify-between gap-3 mb-2">
                      <div className="min-w-0">
                        <div className="text-sm font-medium" data-testid={`text-task-label-${task}`}>{meta.label}</div>
                        <div className="text-xs text-muted-foreground mt-0.5">{meta.description}</div>
                      </div>
                      <Badge variant="outline" className="text-[10px] font-mono shrink-0 uppercase">{task}</Badge>
                    </div>
                    <Select
                      value={value}
                      onValueChange={(v) => setDraftAssignments((d) => ({ ...d, [task]: v }))}
                      disabled={keyedProviders.length === 0}
                    >
                      <SelectTrigger className="h-9 text-sm mt-auto" data-testid={`select-assignment-${task}`}>
                        <SelectValue placeholder={keyedProviders.length === 0 ? "No live-tested providers" : "Pick a provider…"} />
                      </SelectTrigger>
                      <SelectContent>
                        {keyedProviders.map((p) => (
                          <SelectItem key={p.id} value={p.id} data-testid={`option-provider-${task}-${p.id}`}>
                            <span className="font-medium">{p.label}</span>
                            <span className="text-muted-foreground font-mono text-[10px] ml-2">{p.model}</span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                );
              })}
            </div>
          </Card>

          {usableCount === 0 && (
            <div className="mt-3 text-xs text-muted-foreground">Save an API key, enable the provider, and pass its live test to assign tasks and unlock AI features.</div>
          )}
        </section>

        <ProviderEditDialog open={editOpen} onOpenChange={setEditOpen} initial={editing} />
      </div>
    </AppShell>
  );
}
