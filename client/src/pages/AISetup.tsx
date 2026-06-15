import { useEffect, useMemo, useState } from "react";
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
  BATCH_ONE_AI_TASKS, AI_PROVIDERS, type AiProviderSummary, type AiTask, type AiProviderKind,
} from "@shared/schema";
import {
  Sparkles, Eye, EyeOff, Save, Loader2, CheckCircle2, XCircle, Plus, Trash2, Settings2,
} from "lucide-react";

const PROVIDER_META: Record<AiProviderKind, { label: string; defaultModel: string; defaultBase?: string; tone: string; needsKey: boolean }> = {
  "openai":         { label: "OpenAI",         defaultModel: "gpt-4.1-mini",         tone: "from-emerald-500/15 to-emerald-500/5 border-emerald-500/30", needsKey: true },
  "anthropic":      { label: "Anthropic",      defaultModel: "claude-sonnet-4-20250514", tone: "from-orange-500/15 to-orange-500/5 border-orange-500/30", needsKey: true },
  "gemini":         { label: "Google Gemini",  defaultModel: "gemini-flash-latest",  tone: "from-blue-500/15 to-blue-500/5 border-blue-500/30",       needsKey: true },
  "azure-openai":   { label: "Azure OpenAI",   defaultModel: "gpt-4.1-mini",         tone: "from-cyan-500/15 to-cyan-500/5 border-cyan-500/30",         needsKey: true },
  "ollama":         { label: "Ollama (self-hosted)", defaultModel: "llama3.1:8b",    defaultBase: "http://localhost:11434", tone: "from-slate-500/15 to-slate-500/5 border-slate-500/30", needsKey: false },
  "perplexity":     { label: "Perplexity",     defaultModel: "sonar-pro",            tone: "from-violet-500/15 to-violet-500/5 border-violet-500/30",   needsKey: true },
  "deepseek":       { label: "DeepSeek",       defaultModel: "deepseek-chat",        defaultBase: "https://api.deepseek.com", tone: "from-indigo-500/15 to-indigo-500/5 border-indigo-500/30", needsKey: true },
  "kimi":           { label: "Kimi (Moonshot)", defaultModel: "moonshot-v1-128k",    defaultBase: "https://api.moonshot.ai", tone: "from-fuchsia-500/15 to-fuchsia-500/5 border-fuchsia-500/30", needsKey: true },
};

// Quick-pick model presets per provider — surfaced as clickable chips under the
// Model input in the provider edit dialog so users don't have to hand-type names.
// Provider quick-picks favor API-valid model ids for this chat-completions
// integration. Users can still type a newer account/deployment-specific id.
const MODEL_PRESETS: Record<AiProviderKind, string[]> = {
  "openai":         ["gpt-image-2", "gpt-image-1.5", "gpt-image-1", "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano", "gpt-4o", "gpt-4o-mini", "o3", "o4-mini"],
  "anthropic":      ["claude-opus-4-1-20250805", "claude-opus-4-20250514", "claude-sonnet-4-20250514", "claude-3-7-sonnet-20250219", "claude-3-5-haiku-20241022"],
  "gemini":         ["gemini-flash-latest", "gemini-3.5-flash", "gemini-3.1-pro", "gemini-3-flash", "gemini-3.1-flash-image", "gemini-3-pro-image"],
  "azure-openai":   ["gpt-4.1", "gpt-4.1-mini", "gpt-4o", "gpt-4o-mini", "o3-mini"],
  "ollama":         ["llama3.1:8b", "llama3.1:70b", "qwen2.5:14b", "mistral:7b", "deepseek-r1:14b"],
  "perplexity":     ["sonar-pro", "sonar", "sonar-reasoning-pro", "sonar-deep-research"],
  "deepseek":       ["deepseek-chat", "deepseek-reasoner"],
  // Moonshot Kimi — OpenAI-compatible endpoint, multiple vision-capable models.
  "kimi":           ["moonshot-v1-128k", "moonshot-v1-32k", "moonshot-v1-8k", "kimi-k2-0711-preview"],
};

// Short note shown next to each model chip on hover so the user knows what each is for.
const MODEL_DESCRIPTIONS: Record<string, string> = {
  // OpenAI
  "gpt-image-2":         "Latest OpenAI image generation model for TAP portraits",
  "gpt-image-1.5":       "OpenAI image generation model",
  "gpt-image-1":         "OpenAI image generation model",
  "gpt-4.1":            "Flagship GPT-4.1 text model",
  "gpt-4.1-mini":       "Balanced GPT-4.1 model",
  "gpt-4.1-nano":       "Low-cost GPT-4.1 model",
  "gpt-4o":             "Multimodal GPT-4o",
  "gpt-4o-mini":        "Fast, affordable GPT-4o",
  "o3":                 "Reasoning model",
  "o4-mini":            "Fast reasoning model",
  // Anthropic
  "claude-opus-4-1-20250805": "Claude Opus 4.1",
  "claude-opus-4-20250514":   "Claude Opus 4",
  "claude-sonnet-4-20250514": "Claude Sonnet 4",
  "claude-3-7-sonnet-20250219":"Claude 3.7 Sonnet",
  "claude-3-5-haiku-20241022":"Claude 3.5 Haiku",
  // Gemini
  "gemini-3.1-flash-image": "Gemini 3.1 Flash Image for TAP portraits",
  "gemini-3-pro-image":     "Gemini 3 Pro Image for higher-quality TAP portraits",
  "gemini-flash-latest":   "Latest Gemini Flash alias",
  "gemini-3.5-flash":      "Current stable Gemini Flash model",
  "gemini-3.1-pro":        "Preview Gemini Pro model",
  "gemini-3-flash":        "Preview Gemini Flash model",
  // DeepSeek
  "deepseek-chat":      "DeepSeek chat model",
  "deepseek-reasoner":  "DeepSeek reasoning model",
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
  "moonshot-v1-128k":    "128K-context, balanced quality/cost",
  "moonshot-v1-32k":     "32K-context for shorter prompts (cheaper)",
  "moonshot-v1-8k":      "8K-context for low-volume cheap calls",
  "kimi-k2-0711-preview":"Kimi K2 preview where enabled",
};

function normaliseModelForProvider(provider: AiProviderKind, model?: string | null): string {
  const m = (model || "").trim();
  const key = m.toLowerCase();
  if (!m) return PROVIDER_META[provider].defaultModel;
  if (provider === "gemini" && (/^gemini-1(?:\.|$|-)/i.test(m) || /^gemini-2(?:\.|$|-)/i.test(m) || key === "gemini-pro" || key === "gemini-3.1-flash-lite")) return "gemini-flash-latest";
  if ((provider === "openai" || provider === "azure-openai") && (/^gpt-5\./.test(key) || key === "gpt-5")) return "gpt-4.1-mini";
  if (provider === "anthropic") {
    const aliases: Record<string, string> = {
      "claude-opus-4-7": "claude-opus-4-1-20250805",
      "claude-sonnet-4-6": "claude-sonnet-4-20250514",
      "claude-haiku-4-5": "claude-3-5-haiku-20241022",
      "claude-3-5-sonnet": "claude-3-7-sonnet-20250219",
      "claude-3-5-sonnet-latest": "claude-3-7-sonnet-20250219",
      "claude-3-5-haiku-latest": "claude-3-5-haiku-20241022",
    };
    return aliases[key] || m;
  }
  if (provider === "deepseek") {
    if (key === "deepseek-v4-pro") return "deepseek-reasoner";
    if (key === "deepseek-v4-flash") return "deepseek-chat";
  }
  if (provider === "perplexity" && key === "sonar-large") return "sonar-pro";
  if (provider === "kimi") {
    if (key === "kimi-latest") return "moonshot-v1-128k";
    if (key === "kimi-k2-instruct") return "kimi-k2-0711-preview";
  }
  return m;
}

function providerTestDescription(providerLabel: string, data: { ok?: boolean; message?: string; latencyMs?: number | null }) {
  const raw = String(data.message || "").trim();
  const labelLower = providerLabel.toLowerCase();
  const withoutDuplicateLabel = raw.toLowerCase().startsWith(`${labelLower}:`)
    ? raw.slice(providerLabel.length + 1).trim()
    : raw.toLowerCase().startsWith(labelLower)
      ? raw.slice(providerLabel.length).trim()
      : raw;
  const cleaned = withoutDuplicateLabel
    .replace(/^[-·:]\s*/, "")
    .replace(/\s+—\s+connected via generateContent$/i, " connected")
    .replace(/\s+—\s+connected via chat$/i, " connected")
    .replace(/\s+—\s+connected$/i, " connected")
    .replace(/\bHTTP 200 but response had no candidate text\b/i, "Google returned an empty response body for this model")
    .trim();
  const latency = data.latencyMs ? ` Response time: ${data.latencyMs}ms.` : "";
  if (data.ok) {
    const okDetail = cleaned || "connected";
    const sentence = okDetail.toLowerCase().startsWith(providerLabel.toLowerCase())
      ? okDetail
      : `${providerLabel} ${okDetail}`;
    return `${sentence.replace(/\.$/, "")}.${latency}`;
  }
  return `${providerLabel} test failed${cleaned ? `: ${cleaned}` : "."}${latency}`;
}

const TASK_META: Partial<Record<AiTask, { label: string; description: string }>> = {
  osint_analysis: { label: "Intel analysis",       description: "Score source findings, run deep-dive analysis, and preserve evidence context." },
  hunt_query:     { label: "Hunt query",           description: "Generate SIEM/EDR hunt queries from selected findings." },
  osint_overview: { label: "CIRT overview",        description: "Run CIRT triage, analyst chat, and overview summaries across scoped findings." },
  osint_chat:     { label: "Analyst chat",         description: "Power the floating OSINT chatroom with scoped findings and fetched URL context." },
  threat_actor_enrichment: { label: "Threat actor profile", description: "Enrich TAP dossiers with identity, tradecraft, IOCs, references, and MITRE TTPs." },
  tap_portrait: { label: "TAP portrait", description: "Generate fictional actor portrait art from TAP attributes using an image-capable provider." },
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

function providerSupportsTask(provider: AiProviderSummary, task: AiTask): boolean {
  if (task !== "tap_portrait") return true;
  if (provider.provider === "openai" || provider.provider === "azure-openai" || provider.provider === "gemini") return true;
  return false;
}

interface AssignmentsResp { assignments: Record<string, string>; tasks?: AiTask[] }
interface ProvidersResp { providers: AiProviderSummary[]; hasUsableProvider?: boolean; tasks?: AiTask[] }

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
        title: data.ok ? "Provider connected" : "Provider test failed",
        description: providerTestDescription(p.label, data),
        variant: data.ok ? undefined : "destructive",
      });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Provider test failed", description: String(e.message ?? e) }),
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
      setModel(normaliseModelForProvider(p, initial?.model));
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
            Credentials are encrypted at rest and never leave the workspace.
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
  const assignments = assignmentsData?.assignments;
  const visibleTasks = useMemo(
    () => assignmentsData?.tasks ?? providersData?.tasks ?? [...BATCH_ONE_AI_TASKS],
    [assignmentsData?.tasks, providersData?.tasks],
  );

  const [draftAssignments, setDraftAssignments] = useState<Record<string, string>>({});
  const keyedProviders = providers.filter((p) => p.enabled && p.hasKey && p.lastTestOk === true);
  const providerById = useMemo(() => new Map(providers.map((p) => [p.id, p])), [providers]);
  const usableCount = keyedProviders.length;

  useEffect(() => {
    const current = assignments ?? {};
    setDraftAssignments(Object.fromEntries(
      visibleTasks.map((task) => [task, current[task] ?? ""]),
    ));
  }, [assignments, visibleTasks]);

  const dirty =
    visibleTasks.length > 0 &&
    visibleTasks.some((t) => (draftAssignments[t] ?? "") !== (assignments?.[t] ?? ""));

  const saveAssignments = useMutation({
    mutationFn: async () => {
      const payload = Object.fromEntries(
        visibleTasks
          .map((task) => [task, draftAssignments[task]] as const)
          .filter((entry): entry is readonly [AiTask, string] => {
            if (typeof entry[1] !== "string" || entry[1].length === 0) return false;
            const provider = providerById.get(entry[1]);
            return !!provider && providerSupportsTask(provider, entry[0]);
          }),
      );
      await apiRequest("PUT", "/api/v1/ai/assignments", { assignments: payload });
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
              <div className="text-xs text-muted-foreground">Pick which provider handles BatchOne intel and TAP workloads.</div>
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
              {visibleTasks.map((task, idx) => {
                const meta = taskMeta(task);
                const taskProviders = keyedProviders.filter((p) => providerSupportsTask(p, task));
                const assigned = draftAssignments[task] ?? "";
                const assignedProvider = assigned ? providerById.get(assigned) : undefined;
                const value = assignedProvider && providerSupportsTask(assignedProvider, task) ? assigned : "";
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
                      disabled={taskProviders.length === 0}
                    >
                      <SelectTrigger className="h-9 text-sm mt-auto" data-testid={`select-assignment-${task}`}>
                        <SelectValue placeholder={taskProviders.length === 0 ? "No compatible live-tested providers" : "Pick a provider…"} />
                      </SelectTrigger>
                      <SelectContent>
                        {taskProviders.map((p) => (
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
