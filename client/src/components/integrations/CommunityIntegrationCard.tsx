import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  CheckCircle2,
  Database,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Radar,
  Save,
  Search,
  SearchCode,
  ServerCog,
  ShieldCheck,
} from "lucide-react";
import type { CommunityIntegrationKind, CommunityIntegrationSettingsDTO } from "@shared/schema";
import { ConnectorPanel } from "./ConnectorPanel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";

const META: Record<
  CommunityIntegrationKind,
  {
    title: string;
    description: string;
    credential: string;
    docs: string;
    icon: typeof Radar;
    mode: "ingestion" | "enrichment";
  }
> = {
  abusech: {
    title: "abuse.ch community feeds",
    description: "Ingest ThreatFox IOCs, MalwareBazaar samples, and URLhaus malware URLs with one community Auth-Key.",
    credential: "abuse.ch Auth-Key",
    docs: "https://auth.abuse.ch/",
    icon: ShieldCheck,
    mode: "ingestion",
  },
  taxii: {
    title: "TAXII 2.1 collection",
    description: "Import STIX 2.1 objects from a configured TAXII collection using bearer or basic authentication.",
    credential: "TAXII credential",
    docs: "https://www.oasis-open.org/standard/taxii2-1/",
    icon: ServerCog,
    mode: "ingestion",
  },
  misp: {
    title: "MISP community",
    description:
      "Import attributed indicators and event context from a trusted MISP instance through its Automation API.",
    credential: "MISP automation key",
    docs: "https://www.misp-project.org/openapi/",
    icon: Database,
    mode: "ingestion",
  },
  urlscan: {
    title: "urlscan.io",
    description: "Enable analyst-driven URL and domain enrichment without bulk collection or automatic submissions.",
    credential: "urlscan API key",
    docs: "https://urlscan.io/docs/api/",
    icon: SearchCode,
    mode: "enrichment",
  },
  greynoise: {
    title: "GreyNoise Community",
    description: "Enable analyst-driven IP reputation checks while preserving the Community API lookup quota.",
    credential: "GreyNoise API key",
    docs: "https://docs.greynoise.io/docs/using-the-greynoise-community-api",
    icon: Radar,
    mode: "enrichment",
  },
};

function formatTime(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "Never";
}

export function CommunityIntegrationCard({
  kind,
  readOnly = false,
}: {
  kind: CommunityIntegrationKind;
  readOnly?: boolean;
}) {
  const meta = META[kind];
  const Icon = meta.icon;
  const { toast } = useToast();
  const [enabled, setEnabled] = useState(false);
  const [endpoint, setEndpoint] = useState("");
  const [collectionId, setCollectionId] = useState("");
  const [username, setUsername] = useState("");
  const [authMode, setAuthMode] = useState<"api-key" | "bearer" | "basic">("api-key");
  const [credential, setCredential] = useState("");
  const [showCredential, setShowCredential] = useState(false);
  const [clearCredential, setClearCredential] = useState(false);
  const [observable, setObservable] = useState("");
  const [lookupResult, setLookupResult] = useState<Record<string, unknown> | null>(null);
  const path = `/api/v1/integrations/community/${kind}`;

  const { data: settings, isLoading } = useQuery<CommunityIntegrationSettingsDTO>({
    queryKey: [path],
    enabled: !readOnly,
  });
  useEffect(() => {
    if (!settings) return;
    setEnabled(settings.enabled);
    setEndpoint(settings.endpoint);
    setCollectionId(settings.collectionId);
    setUsername(settings.username);
    setAuthMode(settings.authMode);
    setCredential("");
    setShowCredential(false);
    setClearCredential(false);
  }, [settings]);

  const save = useMutation({
    mutationFn: async () =>
      (
        await apiRequest("PUT", path, {
          enabled,
          endpoint,
          collectionId,
          username,
          authMode,
          credential: credential || undefined,
          clearCredential,
        })
      ).json() as Promise<CommunityIntegrationSettingsDTO>,
    onSuccess: async (saved) => {
      setCredential("");
      setClearCredential(false);
      await queryClient.invalidateQueries({ queryKey: [path] });
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/sources"] });
      toast({
        title: `${meta.title} saved`,
        description: saved.enabled
          ? `${saved.mode === "ingestion" ? "Collection" : "Enrichment"} is enabled.`
          : "Integration is disabled.",
      });
    },
    onError: (error: Error) =>
      toast({ title: `Could not save ${meta.title}`, description: error.message, variant: "destructive" }),
  });
  const test = useMutation({
    mutationFn: async () =>
      (await apiRequest("POST", `${path}/test`, {})).json() as Promise<{ ok: true; message: string }>,
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: [path] });
      toast({ title: "Connection verified", description: result.message });
    },
    onError: (error: Error) => {
      queryClient.invalidateQueries({ queryKey: [path] });
      toast({ title: "Connection failed", description: error.message, variant: "destructive" });
    },
  });
  const lookup = useMutation({
    mutationFn: async () =>
      (await apiRequest("POST", `${path}/lookup`, { observable })).json() as Promise<Record<string, unknown>>,
    onSuccess: setLookupResult,
    onError: (error: Error) => toast({ title: "Lookup failed", description: error.message, variant: "destructive" }),
  });
  const configured = settings?.configured === true;
  const status = !enabled
    ? { label: "Disabled", tone: "border-border bg-muted/40 text-muted-foreground" }
    : configured
      ? { label: "Configured", tone: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" }
      : { label: "Setup required", tone: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300" };
  const needsEndpoint = kind === "taxii" || kind === "misp";
  const canSave =
    !readOnly &&
    !isLoading &&
    !save.isPending &&
    (!enabled || configured || !!credential) &&
    (!needsEndpoint || !!endpoint) &&
    (kind !== "taxii" || !!collectionId);

  return (
    <ConnectorPanel
      icon={<Icon size={18} />}
      title={meta.title}
      description={meta.description}
      badges={
        <>
          <Badge variant="outline" className={status.tone}>
            {status.label}
          </Badge>
          <Badge variant="outline" className="text-[10px]">
            Free
          </Badge>
          <Badge variant="secondary" className="text-[10px]">
            {meta.mode === "ingestion" ? "Ingestion" : "Enrichment only"}
          </Badge>
        </>
      }
      action={
        <div className="flex items-center gap-3">
          <Label htmlFor={`${kind}-enabled`} className="text-xs text-muted-foreground">
            Enable
          </Label>
          <Switch id={`${kind}-enabled`} checked={enabled} onCheckedChange={setEnabled} disabled={readOnly} />
        </div>
      }
    >
      <div className="grid lg:grid-cols-[minmax(0,1fr)_280px]">
        <div className="space-y-5 px-5 py-5">
          {needsEndpoint ? (
            <div>
              <Label htmlFor={`${kind}-endpoint`}>{kind === "taxii" ? "TAXII API root" : "MISP base URL"}</Label>
              <Input
                id={`${kind}-endpoint`}
                value={endpoint}
                onChange={(event) => setEndpoint(event.target.value)}
                placeholder={kind === "taxii" ? "https://taxii.example/api2" : "https://misp.example"}
                className="mt-2 font-mono text-xs"
                disabled={readOnly}
              />
              <p className="mt-2 text-xs text-muted-foreground">
                Publicly routable HTTPS endpoints only; private network targets are rejected by outbound request policy.
              </p>
            </div>
          ) : null}
          {kind === "taxii" ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <Label htmlFor="taxii-collection">Collection ID</Label>
                <Input
                  id="taxii-collection"
                  value={collectionId}
                  onChange={(event) => setCollectionId(event.target.value)}
                  className="mt-2 font-mono text-xs"
                  disabled={readOnly}
                />
              </div>
              <div>
                <Label>Authentication</Label>
                <Select
                  value={authMode}
                  onValueChange={(value) => setAuthMode(value as typeof authMode)}
                  disabled={readOnly}
                >
                  <SelectTrigger className="mt-2">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="bearer">Bearer token</SelectItem>
                    <SelectItem value="basic">Basic authentication</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          ) : null}
          {kind === "taxii" && authMode === "basic" ? (
            <div>
              <Label htmlFor="taxii-username">Username</Label>
              <Input
                id="taxii-username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                className="mt-2"
                disabled={readOnly}
              />
            </div>
          ) : null}
          <div>
            <div className="flex items-center justify-between gap-3">
              <Label htmlFor={`${kind}-credential`}>{meta.credential}</Label>
              <a
                href={meta.docs}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-muted-foreground hover:text-foreground"
              >
                Setup documentation
              </a>
            </div>
            <div className="mt-2 flex gap-2">
              <div className="relative flex-1">
                <KeyRound size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id={`${kind}-credential`}
                  type={showCredential ? "text" : "password"}
                  value={credential}
                  onChange={(event) => {
                    setCredential(event.target.value);
                    setClearCredential(false);
                  }}
                  placeholder={configured ? "Saved, leave blank to keep" : "Paste credential"}
                  className="pl-9 font-mono"
                  disabled={readOnly}
                  autoComplete="new-password"
                />
              </div>
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={() => setShowCredential((value) => !value)}
                disabled={readOnly}
                aria-label={showCredential ? "Hide credential" : "Show credential"}
              >
                {showCredential ? <EyeOff size={15} /> : <Eye size={15} />}
              </Button>
            </div>
          </div>
          {settings?.hasCredential ? (
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <Checkbox
                checked={clearCredential}
                onCheckedChange={(checked) => {
                  setClearCredential(checked === true);
                  if (checked) setCredential("");
                }}
                disabled={readOnly}
              />
              Remove saved credential when settings are saved
            </label>
          ) : null}
          {meta.mode === "enrichment" ? (
            <div className="rounded-md border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-xs text-muted-foreground">
              This connector is intentionally excluded from scheduled bulk ingestion. It is reserved for analyst-driven
              observable lookups.
            </div>
          ) : null}
          {meta.mode === "enrichment" ? (
            <div>
              <Label htmlFor={`${kind}-observable`}>Observable lookup</Label>
              <div className="mt-2 flex gap-2">
                <Input
                  id={`${kind}-observable`}
                  value={observable}
                  onChange={(event) => {
                    setObservable(event.target.value);
                    setLookupResult(null);
                  }}
                  placeholder={kind === "greynoise" ? "Public IPv4 address" : "Domain, URL, or public IPv4"}
                  disabled={!enabled || !configured}
                />
                <Button
                  variant="outline"
                  onClick={() => lookup.mutate()}
                  disabled={!enabled || !configured || !observable || lookup.isPending}
                >
                  {lookup.isPending ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                  <span className="ml-2">Lookup</span>
                </Button>
              </div>
              {lookupResult ? (
                <pre className="mt-3 max-h-48 overflow-auto rounded-md border bg-muted/30 p-3 text-[11px] leading-5">
                  {JSON.stringify(lookupResult, null, 2)}
                </pre>
              ) : null}
              <p className="mt-2 text-xs text-muted-foreground">
                The observable is sent to {kind === "greynoise" ? "GreyNoise" : "urlscan.io"} only when Lookup is
                selected.
              </p>
            </div>
          ) : null}
        </div>
        <aside className="border-t bg-muted/10 px-5 py-5 lg:border-l lg:border-t-0">
          <div className="text-xs font-medium uppercase text-muted-foreground">Connection health</div>
          <div className="mt-4 space-y-3 text-xs">
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Credential</span>
              <span className="font-medium">{settings?.hasCredential ? "Available" : "Not configured"}</span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Operation</span>
              <span className="font-medium">{meta.mode === "ingestion" ? "Scheduled ingest" : "On demand"}</span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Last tested</span>
              <span className="text-right font-medium">{formatTime(settings?.lastTestedAt)}</span>
            </div>
          </div>
          {settings?.lastTestMessage ? (
            <div
              className={`mt-4 rounded-md border px-3 py-2 text-xs ${settings.lastTestOk ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-700" : "border-rose-500/20 bg-rose-500/5 text-rose-700"}`}
            >
              {settings.lastTestMessage}
            </div>
          ) : null}
          <div className="mt-5 flex flex-col gap-2">
            <Button
              variant="outline"
              onClick={() => test.mutate()}
              disabled={readOnly || test.isPending || !configured}
            >
              {test.isPending ? (
                <Loader2 size={14} className="mr-2 animate-spin" />
              ) : (
                <CheckCircle2 size={14} className="mr-2" />
              )}
              Test connection
            </Button>
            <Button onClick={() => save.mutate()} disabled={!canSave}>
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
