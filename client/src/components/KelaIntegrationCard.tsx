import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, DatabaseZap, ExternalLink, Eye, EyeOff, KeyRound, Loader2, Save } from "lucide-react";
import type { KelaIntegrationSettingsDTO } from "@shared/schema";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ConnectorPanel } from "@/components/integrations/ConnectorPanel";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { showStaticDemoNotice } from "@/lib/staticDemoNotice";

function fmtTime(value: string | null | undefined): string {
  if (!value) return "Never";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export function KelaIntegrationCard({ readOnly = false }: { readOnly?: boolean }) {
  const { toast } = useToast();
  const [enabled, setEnabled] = useState(false);
  const [feedUrl, setFeedUrl] = useState("");
  const [authMode, setAuthMode] = useState<"bearer" | "x-api-key">("bearer");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [clearApiKey, setClearApiKey] = useState(false);

  const { data: settings, isLoading } = useQuery<KelaIntegrationSettingsDTO>({
    queryKey: ["/api/v1/integrations/kela"],
    enabled: !readOnly,
  });

  useEffect(() => {
    if (!settings) return;
    setEnabled(settings.enabled);
    setFeedUrl(settings.feedUrl);
    setAuthMode(settings.authMode);
    setApiKey("");
    setShowKey(false);
    setClearApiKey(false);
  }, [settings]);

  const save = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("PUT", "/api/v1/integrations/kela", {
        enabled,
        feedUrl,
        authMode,
        apiKey: apiKey || undefined,
        clearApiKey,
      });
      return response.json() as Promise<KelaIntegrationSettingsDTO>;
    },
    onSuccess: async (saved) => {
      setApiKey("");
      setClearApiKey(false);
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/integrations/kela"] });
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/sources"] });
      toast({
        title: "KELA integration saved",
        description: saved.enabled ? "Licensed KELA STIX ingestion is enabled." : "KELA ingestion is disabled.",
      });
    },
    onError: (error: Error) =>
      toast({
        title: "Could not save KELA integration",
        description: error.message,
        variant: "destructive",
      }),
  });

  const test = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/v1/integrations/kela/test", {});
      return response.json() as Promise<{ ok: true; objectCount: number }>;
    },
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/integrations/kela"] });
      toast({ title: "KELA connection verified", description: `${result.objectCount} STIX objects returned.` });
    },
    onError: (error: Error) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/integrations/kela"] });
      toast({ title: "KELA connection failed", description: error.message, variant: "destructive" });
    },
  });

  const configured = settings?.configured === true;
  const status = !enabled
    ? { label: "Disabled", tone: "border-border bg-muted/40 text-muted-foreground" }
    : configured
      ? { label: "Configured", tone: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" }
      : { label: "Setup required", tone: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300" };
  const canSave = !readOnly && !isLoading && !save.isPending && !!feedUrl && (!enabled || configured || !!apiKey);

  return (
    <ConnectorPanel
      icon={<DatabaseZap size={18} />}
      title="KELA technical intelligence"
      description="Import compromised infrastructure and cybercrime context from a customer-licensed KELA STIX feed."
      iconClassName="border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-300"
      badges={
        <>
          <Badge variant="outline" className={status.tone}>
            {status.label}
          </Badge>
          <Badge variant="outline" className="font-mono text-[10px]">
            Licensed
          </Badge>
        </>
      }
      action={
        <div className="flex items-center gap-3">
          <Label htmlFor="kela-integration-enabled" className="text-xs text-muted-foreground">
            Enable ingest
          </Label>
          <Switch
            id="kela-integration-enabled"
            checked={enabled}
            onCheckedChange={setEnabled}
            disabled={readOnly}
            aria-label="Enable KELA ingestion"
          />
        </div>
      }
    >
      <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_280px]">
        <div className="space-y-5 px-5 py-5">
          <div>
            <div className="flex items-center justify-between gap-3">
              <Label htmlFor="kela-feed-url">KELA STIX feed URL</Label>
              <a
                href="https://docs.ke-la.com/kela-docs"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
              >
                KELA documentation <ExternalLink size={12} />
              </a>
            </div>
            <Input
              id="kela-feed-url"
              value={feedUrl}
              onChange={(event) => setFeedUrl(event.target.value)}
              placeholder="https://api.ke-la.com/.../stix"
              className="mt-2 font-mono text-xs"
              disabled={readOnly}
              spellCheck={false}
            />
            <p className="mt-2 text-xs text-muted-foreground">
              Use the exact Technical Intelligence feed URL assigned to your KELA subscription.
            </p>
          </div>

          <div className="grid gap-4 sm:grid-cols-[180px_minmax(0,1fr)]">
            <div>
              <Label>Authentication header</Label>
              <Select
                value={authMode}
                onValueChange={(value) => setAuthMode(value as "bearer" | "x-api-key")}
                disabled={readOnly}
              >
                <SelectTrigger className="mt-2">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="bearer">Bearer token</SelectItem>
                  <SelectItem value="x-api-key">X-API-Key</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="kela-api-key">KELA API key</Label>
              <div className="mt-2 flex gap-2">
                <div className="relative flex-1">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={14} />
                  <Input
                    id="kela-api-key"
                    type={showKey ? "text" : "password"}
                    value={apiKey}
                    onChange={(event) => {
                      setApiKey(event.target.value);
                      setClearApiKey(false);
                    }}
                    placeholder={configured ? "Saved, leave blank to keep" : "Paste API key"}
                    className="pl-9 font-mono"
                    autoComplete="new-password"
                    spellCheck={false}
                    disabled={readOnly}
                  />
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  onClick={() => setShowKey((value) => !value)}
                  disabled={readOnly}
                  aria-label={showKey ? "Hide KELA API key" : "Show KELA API key"}
                >
                  {showKey ? <EyeOff size={15} /> : <Eye size={15} />}
                </Button>
              </div>
            </div>
          </div>

          {settings?.hasApiKey ? (
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
              <Checkbox
                checked={clearApiKey}
                onCheckedChange={(checked) => {
                  setClearApiKey(checked === true);
                  if (checked) setApiKey("");
                }}
                disabled={readOnly}
              />
              Remove the saved API key when settings are saved
            </label>
          ) : null}
        </div>

        <aside className="border-t bg-muted/10 px-5 py-5 lg:border-l lg:border-t-0">
          <div className="text-xs font-medium uppercase text-muted-foreground">Connection health</div>
          <div className="mt-4 space-y-3 text-xs">
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted-foreground">Feed URL</span>
              <span className="font-medium">{settings?.feedUrl ? "Available" : "Not configured"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted-foreground">Credential</span>
              <span className="font-medium">{settings?.hasApiKey ? "Available" : "Not configured"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted-foreground">Format</span>
              <span className="font-medium">STIX JSON</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted-foreground">Last tested</span>
              <span className="text-right font-medium">{fmtTime(settings?.lastTestedAt)}</span>
            </div>
          </div>
          {settings?.lastTestMessage ? (
            <div
              className={`mt-4 rounded-md border px-3 py-2 text-xs ${settings.lastTestOk ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300" : "border-rose-500/20 bg-rose-500/5 text-rose-700 dark:text-rose-300"}`}
            >
              {settings.lastTestMessage}
            </div>
          ) : null}
          <div className="mt-5 flex flex-col gap-2">
            <Button
              variant="outline"
              onClick={() => test.mutate()}
              disabled={readOnly || test.isPending || !configured || !enabled}
            >
              {test.isPending ? (
                <Loader2 size={14} className="mr-2 animate-spin" />
              ) : (
                <CheckCircle2 size={14} className="mr-2" />
              )}
              Test connection
            </Button>
            <Button
              onClick={() => {
                if (readOnly) {
                  showStaticDemoNotice({ kind: "write", action: "KELA integration changes restricted" });
                  return;
                }
                save.mutate();
              }}
              disabled={!canSave}
            >
              {save.isPending ? (
                <Loader2 size={14} className="mr-2 animate-spin" />
              ) : (
                <Save size={14} className="mr-2" />
              )}
              Save integration
            </Button>
          </div>
        </aside>
      </div>
    </ConnectorPanel>
  );
}
