import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { useMutation, useQuery } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  Archive,
  Bell,
  Building2,
  Check,
  ChevronRight,
  Clock3,
  Copy,
  Download,
  Eye,
  FileText,
  Globe2,
  Image as ImageIcon,
  Layers3,
  Loader2,
  Mail,
  Plus,
  Save,
  Search,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
} from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { startBackgroundJob } from "@/lib/aiJobs";
import { relativeTime } from "@/lib/format";
import type { ClientDigestDTO, ClientProfileDTO, ClientTaxonomyKind, ClientTaxonomyOptionDTO } from "@shared/schema";
import {
  CLIENT_DIGEST_TEMPLATE_PLACEHOLDERS,
  DEFAULT_CLIENT_DIGEST_BODY_TEMPLATE,
  DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE,
  unsupportedClientDigestPlaceholders,
} from "@shared/clientDigestTemplate";

type ProfilesResp = { profiles: ClientProfileDTO[] };
type OptionsResp = { options: ClientTaxonomyOptionDTO[] };
type TaxonomiesResp = { clientTypes: Array<{ id: string; label: string }> };
type DigestsResp = { digests: ClientDigestDTO[] };

function toggle(values: string[], id: string) {
  return values.includes(id) ? values.filter((value) => value !== id) : [...values, id];
}

function splitEmails(value: string) {
  return value
    .split(/[,\n]/g)
    .map((item) => item.trim())
    .filter(Boolean);
}

function splitMappingTerms(value: string) {
  return Array.from(
    new Set(
      value
        .split(/\n/g)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
}

function sameValues(left: string[], right: string[]) {
  return left.length === right.length && [...left].sort().every((value, index) => value === [...right].sort()[index]);
}

function cadenceLabel(cadence: ClientProfileDTO["digestCadence"]) {
  return cadence === "biweekly" ? "Bi-weekly" : `${cadence.slice(0, 1).toUpperCase()}${cadence.slice(1)}`;
}

function demoClientEmail(
  clientName: string,
  cadence: ClientProfileDTO["digestCadence"],
  subjectTemplate: string,
  bodyTemplate: string,
) {
  const replacements: Record<string, string> = {
    "{{client_name}}": clientName,
    "{{cadence}}": cadenceLabel(cadence),
    "{{period_start}}": "10 Jul 2026",
    "{{period_end}}": "17 Jul 2026",
    "{{overall_risk}}": "High",
    "{{risk_trend}}": "Stable",
    "{{executive_summary}}":
      "We reviewed 12 client-relevant intelligence items. One critical item requires immediate exposure validation; two high-priority items should be reviewed this week.",
    "{{tier_1}}":
      "### Critical edge-system vulnerability\n\n**Why this matters:** The affected product is part of the monitored technology scope.\n\n**Required action:** Validate exposure and apply the vendor mitigation.\n\n**Owner and timing:** Vulnerability Management - within 24 hours.",
    "{{tier_2}}":
      "### Credential-theft campaign targeting the sector\n\nReview identity telemetry and deploy the recommended detections this week.",
    "{{tier_3}}":
      "- Monitor the emerging campaign for infrastructure or tactics that intersect with the client environment.",
    "{{fyi}}": "- Regional threat-activity update with no immediate action required.",
    "{{recommended_actions}}":
      "1. Validate external exposure - Vulnerability Management - 24 hours.\n2. Deploy identity detections - Detection Engineering - this week.\n3. Monitor campaign infrastructure - Threat Intelligence - next review.",
    "{{indicator_summary}}": "18 indicators available; 2 relevant CVEs; detection guidance available on request.",
    "{{sources}}":
      "- [Vendor security advisory](https://example.com/advisory)\n- [Threat research report](https://example.com/report)",
  };
  const render = (template: string) =>
    Object.entries(replacements).reduce(
      (value, [token, replacement]) => value.split(token).join(replacement),
      template,
    );
  return { subject: render(subjectTemplate), body: render(bodyTemplate) };
}

function ScopeEditor({
  title,
  description,
  kind,
  values,
  options,
  onChange,
  onCreate,
}: {
  title: string;
  description: string;
  kind?: ClientTaxonomyKind;
  values: string[];
  options: Array<{ id: string; label: string; category?: string; optionKind?: string; source?: string }>;
  onChange: (next: string[]) => void;
  onCreate?: (kind: ClientTaxonomyKind, label: string) => Promise<string>;
}) {
  const [query, setQuery] = useState("");
  const [customLabel, setCustomLabel] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase("en-US");
    const matches = needle
      ? options.filter((option) =>
          `${option.label} ${option.category ?? ""}`.toLocaleLowerCase("en-US").includes(needle),
        )
      : options;
    return matches;
  }, [options, query]);

  const addCustom = async () => {
    if (!kind || !onCreate || customLabel.trim().length < 2) return;
    setCreating(true);
    try {
      const optionId = await onCreate(kind, customLabel.trim());
      if (!values.includes(optionId)) onChange([...values, optionId]);
      setCustomLabel("");
      setShowCreate(false);
    } finally {
      setCreating(false);
    }
  };

  return (
    <section aria-labelledby={`scope-${kind ?? "service"}`}>
      <div className="flex flex-col gap-4 border-b border-border/70 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 id={`scope-${kind ?? "service"}`} className="text-lg font-semibold text-foreground">
              {title}
            </h2>
            <Badge variant="secondary" className="rounded-md font-medium">
              {values.length} selected
            </Badge>
          </div>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">{description}</p>
        </div>
        {kind && onCreate && !showCreate && (
          <Button type="button" variant="outline" size="sm" className="shrink-0" onClick={() => setShowCreate(true)}>
            <Plus size={14} className="mr-2" /> Add option
          </Button>
        )}
      </div>

      <AnimatePresence initial={false}>
        {showCreate && kind && onCreate && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="mt-5 rounded-md border border-primary/25 bg-primary/[0.035] p-4">
              <Label htmlFor={`add-${kind}`} className="text-sm font-medium">
                New {kind === "geo" ? "geography" : kind}
              </Label>
              <p className="mt-1 text-xs text-muted-foreground">
                Add a canonical option for this workspace. It will be stored and assigned by ID.
              </p>
              <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                <Input
                  id={`add-${kind}`}
                  value={customLabel}
                  onChange={(event) => setCustomLabel(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      void addCustom();
                    }
                  }}
                  placeholder={`Enter ${kind === "geo" ? "geography" : kind} name`}
                  className="h-10 bg-background"
                  data-testid={`input-add-${kind}`}
                  autoFocus
                />
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="ghost"
                    className="h-10"
                    onClick={() => {
                      setShowCreate(false);
                      setCustomLabel("");
                    }}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="button"
                    className="h-10"
                    onClick={() => void addCustom()}
                    disabled={creating || customLabel.trim().length < 2}
                  >
                    {creating ? (
                      <Loader2 size={14} className="mr-2 animate-spin" />
                    ) : (
                      <Plus size={14} className="mr-2" />
                    )}
                    Add option
                  </Button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="relative mt-5 max-w-md">
        <Search
          size={15}
          className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
        />
        <Input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={`Search ${title.toLocaleLowerCase("en-US")}`}
          className="h-10 pl-9"
        />
      </div>

      <div className="mt-4 grid max-h-[440px] gap-2 overflow-y-auto pr-1 sm:grid-cols-2 xl:grid-cols-3">
        {filtered.map((option) => {
          const checked = values.includes(option.id);
          return (
            <label
              key={option.id}
              className={`group flex min-h-14 cursor-pointer items-center gap-3 rounded-md border px-3 py-2.5 transition-colors duration-200 focus-within:ring-2 focus-within:ring-primary/50 ${checked ? "border-primary/45 bg-primary/[0.055]" : "border-border bg-background hover:border-primary/25 hover:bg-muted/40"}`}
            >
              <Checkbox
                checked={checked}
                onCheckedChange={() => onChange(toggle(values, option.id))}
                aria-label={`${checked ? "Remove" : "Add"} ${option.label}`}
              />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium leading-5 text-foreground">{option.label}</span>
                {(option.category || option.optionKind || option.source === "custom") && (
                  <span className="mt-0.5 block text-xs capitalize text-muted-foreground">
                    {option.category ?? option.optionKind ?? "Custom option"}
                  </span>
                )}
              </span>
              {checked && <Check size={14} className="shrink-0 text-primary" aria-hidden="true" />}
            </label>
          );
        })}
        {filtered.length === 0 && (
          <div className="col-span-full rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">
            No options match “{query}”.
          </div>
        )}
      </div>
    </section>
  );
}

function CreateClientDialog({ onCreated }: { onCreated: (profile: ClientProfileDTO) => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/v1/client-profiles", {
        name,
        clientTypes: [],
        geos: [],
        industries: [],
        monitoredTechnologies: [],
        mappingTerms: [],
        notificationEmails: [],
        digestEnabled: false,
        digestCadence: "weekly",
        digestSubjectTemplate: DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE,
        digestBodyTemplate: DEFAULT_CLIENT_DIGEST_BODY_TEMPLATE,
      });
      return response.json() as Promise<ClientProfileDTO>;
    },
    onSuccess: (profile) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profiles"] });
      onCreated(profile);
      setName("");
      setOpen(false);
      toast({ title: "Client created", description: `${profile.name} is ready for scope configuration.` });
    },
    onError: (error: any) =>
      toast({ title: "Create failed", description: String(error?.message ?? error), variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="h-10">
          <Plus size={15} className="mr-2" /> New client
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add client</DialogTitle>
          <DialogDescription>Create a protected client record inside this workspace.</DialogDescription>
        </DialogHeader>
        <div className="py-2">
          <Label htmlFor="new-client-name">Client name</Label>
          <Input
            id="new-client-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            className="mt-2"
            autoFocus
          />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending || name.trim().length < 2}>
            {create.isPending && <Loader2 size={14} className="mr-2 animate-spin" />} Create client
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ArchiveClientDialog({
  clientName,
  disabled,
  pending,
  onArchive,
}: {
  clientName: string;
  disabled: boolean;
  pending: boolean;
  onArchive: () => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="text-muted-foreground hover:text-destructive"
          disabled={disabled}
          title={disabled ? "Keep at least one active client" : "Archive client"}
        >
          <Archive size={14} className="mr-2" /> Archive
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Archive {clientName}?</DialogTitle>
          <DialogDescription>
            The client will be removed from active analysis scope. Existing threat-intelligence assignments remain
            available for audit history.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={() => {
              onArchive();
              setOpen(false);
            }}
            disabled={pending}
          >
            {pending && <Loader2 size={14} className="mr-2 animate-spin" />} Archive client
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ClientProfile() {
  const { toast } = useToast();
  const { data, isLoading } = useQuery<ProfilesResp>({ queryKey: ["/api/v1/client-profiles"] });
  const { data: optionData } = useQuery<OptionsResp>({ queryKey: ["/api/v1/client-taxonomy-options"] });
  const { data: tax } = useQuery<TaxonomiesResp>({ queryKey: ["/api/v1/taxonomies"] });
  const profiles = data?.profiles ?? [];
  const options = optionData?.options ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("profile");
  const [demoEmailOpen, setDemoEmailOpen] = useState(false);
  const [templateAction, setTemplateAction] = useState<"logo" | "remove-logo" | "docx" | "eml" | null>(null);
  const logoFileRef = useRef<HTMLInputElement | null>(null);
  const [clientQuery, setClientQuery] = useState("");
  const selected = profiles.find((profile) => profile.id === selectedId) ?? profiles[0] ?? null;

  useEffect(() => {
    const syncDeepLink = () => {
      const raw = window.location.hash || "";
      const queryIndex = raw.indexOf("?");
      if (queryIndex < 0) return;
      const params = new URLSearchParams(raw.slice(queryIndex + 1));
      const clientId = params.get("client");
      const tab = params.get("tab");
      if (clientId) setSelectedId(clientId);
      if (tab === "profile" || tab === "services" || tab === "scope" || tab === "communications") setActiveTab(tab);
    };
    syncDeepLink();
    window.addEventListener("hashchange", syncDeepLink);
    window.addEventListener("optrasight:ai-job-open", syncDeepLink as EventListener);
    return () => {
      window.removeEventListener("hashchange", syncDeepLink);
      window.removeEventListener("optrasight:ai-job-open", syncDeepLink as EventListener);
    };
  }, []);

  const [name, setName] = useState("");
  const [clientTypes, setClientTypes] = useState<string[]>([]);
  const [geos, setGeos] = useState<string[]>([]);
  const [industries, setIndustries] = useState<string[]>([]);
  const [technologies, setTechnologies] = useState<string[]>([]);
  const [mappingTerms, setMappingTerms] = useState("");
  const [notificationEmails, setNotificationEmails] = useState("");
  const [digestEnabled, setDigestEnabled] = useState(false);
  const [digestCadence, setDigestCadence] = useState<ClientProfileDTO["digestCadence"]>("weekly");
  const [digestSubjectTemplate, setDigestSubjectTemplate] = useState(DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE);
  const [digestBodyTemplate, setDigestBodyTemplate] = useState(DEFAULT_CLIENT_DIGEST_BODY_TEMPLATE);
  const { data: digestData } = useQuery<DigestsResp>({
    queryKey: ["/api/v1/client-profiles", selected?.id, "digests"],
    queryFn: async () => {
      const response = await apiRequest("GET", `/api/v1/client-profiles/${selected!.id}/digests`);
      return response.json();
    },
    enabled: !!selected?.id,
  });
  const digests = digestData?.digests ?? [];

  useEffect(() => {
    if (!selected) return;
    setSelectedId(selected.id);
    setName(selected.name);
    setClientTypes(selected.clientTypes);
    setGeos(selected.geos);
    setIndustries(selected.industries);
    setTechnologies(selected.monitoredTechnologies);
    setMappingTerms((selected.mappingTerms ?? []).join("\n"));
    setNotificationEmails(selected.notificationEmails.join("\n"));
    setDigestEnabled(selected.digestEnabled ?? false);
    setDigestCadence(selected.digestCadence ?? "weekly");
    setDigestSubjectTemplate(selected.digestSubjectTemplate ?? DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE);
    setDigestBodyTemplate(selected.digestBodyTemplate ?? DEFAULT_CLIENT_DIGEST_BODY_TEMPLATE);
  }, [selected?.id, selected?.updatedAt]);

  const hasChanges =
    Boolean(selected) &&
    (name.trim() !== selected?.name ||
      !sameValues(clientTypes, selected?.clientTypes ?? []) ||
      !sameValues(geos, selected?.geos ?? []) ||
      !sameValues(industries, selected?.industries ?? []) ||
      !sameValues(technologies, selected?.monitoredTechnologies ?? []) ||
      !sameValues(splitMappingTerms(mappingTerms), selected?.mappingTerms ?? []) ||
      !sameValues(splitEmails(notificationEmails), selected?.notificationEmails ?? []) ||
      digestEnabled !== (selected?.digestEnabled ?? false) ||
      digestCadence !== (selected?.digestCadence ?? "weekly") ||
      digestSubjectTemplate !== (selected?.digestSubjectTemplate ?? DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE) ||
      digestBodyTemplate !== (selected?.digestBodyTemplate ?? DEFAULT_CLIENT_DIGEST_BODY_TEMPLATE));

  const save = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("Select a client first.");
      const response = await apiRequest("PATCH", `/api/v1/client-profiles/${selected.id}`, {
        name,
        clientTypes,
        geos,
        industries,
        monitoredTechnologies: technologies,
        mappingTerms: splitMappingTerms(mappingTerms),
        notificationEmails: splitEmails(notificationEmails),
        digestEnabled,
        digestCadence,
        digestSubjectTemplate,
        digestBodyTemplate,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profiles"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profile"] });
      toast({ title: "Changes saved", description: "Future AI analysis will use the updated ID-based client scope." });
    },
    onError: (error: any) =>
      toast({ title: "Save failed", description: String(error?.message ?? error), variant: "destructive" }),
  });

  const archive = useMutation({
    mutationFn: async () => {
      if (!selected) return;
      await apiRequest("DELETE", `/api/v1/client-profiles/${selected.id}`);
    },
    onSuccess: () => {
      setSelectedId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profiles"] });
      toast({ title: "Client archived" });
    },
    onError: (error: any) =>
      toast({ title: "Archive failed", description: String(error?.message ?? error), variant: "destructive" }),
  });

  const generateDigest = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("Select a client first.");
      return startBackgroundJob(`/api/v1/client-profiles/${selected.id}/digests/generate`, { cadence: digestCadence });
    },
    onSuccess: () => {
      toast({ title: "Client digest queued", description: "The AI jobs tray will show generation progress." });
    },
    onError: (error: any) =>
      toast({
        title: "Digest generation failed",
        description: String(error?.message ?? error),
        variant: "destructive",
      }),
  });

  const updateDigest = useMutation({
    mutationFn: async ({ digestId, status }: { digestId: string; status: ClientDigestDTO["status"] }) => {
      if (!selected) throw new Error("Select a client first.");
      const response = await apiRequest("PATCH", `/api/v1/client-profiles/${selected.id}/digests/${digestId}`, {
        status,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profiles", selected?.id, "digests"] });
      toast({ title: "Digest status updated" });
    },
    onError: (error: any) =>
      toast({ title: "Digest update failed", description: String(error?.message ?? error), variant: "destructive" }),
  });

  const uploadEmailLogo = async (file: File) => {
    if (!selected) return;
    if (!/^image\/(png|jpeg)$/i.test(file.type)) {
      toast({ title: "Unsupported logo", description: "Use a PNG or JPEG image.", variant: "destructive" });
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      toast({ title: "Logo is too large", description: "Use an image smaller than 2MB.", variant: "destructive" });
      return;
    }
    setTemplateAction("logo");
    try {
      const contentBase64 = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onerror = () => reject(reader.error);
        reader.onload = () =>
          resolve(
            String(reader.result || "")
              .split(",")
              .pop() || "",
          );
        reader.readAsDataURL(file);
      });
      await apiRequest("POST", `/api/v1/client-profiles/${selected.id}/email-logo`, {
        fileName: file.name,
        contentBase64,
      });
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profiles"] });
      toast({ title: "Email logo updated", description: "Preview and future exports now use the uploaded logo." });
    } catch (error: any) {
      toast({ title: "Logo upload failed", description: String(error?.message ?? error), variant: "destructive" });
    } finally {
      setTemplateAction(null);
      if (logoFileRef.current) logoFileRef.current.value = "";
    }
  };

  const removeEmailLogo = async () => {
    if (!selected) return;
    setTemplateAction("remove-logo");
    try {
      await apiRequest("DELETE", `/api/v1/client-profiles/${selected.id}/email-logo`);
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profiles"] });
      toast({ title: "Email logo removed" });
    } catch (error: any) {
      toast({ title: "Logo removal failed", description: String(error?.message ?? error), variant: "destructive" });
    } finally {
      setTemplateAction(null);
    }
  };

  const downloadEmailTemplate = async (format: "docx" | "eml") => {
    if (!selected) return;
    setTemplateAction(format);
    try {
      const response = await apiRequest("GET", `/api/v1/client-profiles/${selected.id}/email-template.${format}`);
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      const safeName = selected.name.replace(/[^A-Za-z0-9._-]+/g, "_") || "client";
      anchor.href = objectUrl;
      anchor.download = `${safeName}_Threat_Intelligence_Email_Template.${format}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
      toast({ title: `${format === "docx" ? "Word" : "EML"} template downloaded` });
    } catch (error: any) {
      toast({ title: "Download failed", description: String(error?.message ?? error), variant: "destructive" });
    } finally {
      setTemplateAction(null);
    }
  };

  const createOption = async (kind: ClientTaxonomyKind, label: string) => {
    const response = await apiRequest("POST", "/api/v1/client-taxonomy-options", { kind, label, aliases: [] });
    const option = (await response.json()) as ClientTaxonomyOptionDTO;
    await queryClient.invalidateQueries({ queryKey: ["/api/v1/client-taxonomy-options"] });
    toast({ title: "Scope option added", description: option.label });
    return option.id;
  };

  const optionsFor = (kind: ClientTaxonomyKind) => options.filter((option) => option.kind === kind);
  const clientTypeOptions = tax?.clientTypes ?? [];
  const visibleProfiles = profiles.filter((profile) =>
    profile.name.toLocaleLowerCase("en-US").includes(clientQuery.trim().toLocaleLowerCase("en-US")),
  );
  const scopeTotal = geos.length + industries.length + technologies.length;
  const demoEmail = demoClientEmail(
    selected?.name ?? "Client",
    digestCadence,
    digestSubjectTemplate,
    digestBodyTemplate,
  );
  const unsupportedTemplateTokens = Array.from(
    new Set([
      ...unsupportedClientDigestPlaceholders(digestSubjectTemplate),
      ...unsupportedClientDigestPlaceholders(digestBodyTemplate),
    ]),
  );

  return (
    <AppShell>
      <main className="w-full max-w-[1520px] overflow-x-hidden px-4 py-6 sm:px-6 lg:px-10 lg:py-8">
        <PageHeader
          title="Client Profiles"
          description="Define each client's operational context for precise, ID-based threat-intelligence analysis."
          actions={<CreateClientDialog onCreated={(profile) => setSelectedId(profile.id)} />}
        />

        <div className="overflow-hidden rounded-lg border border-border bg-background shadow-sm">
          <div className="grid min-h-[680px] lg:grid-cols-[292px_minmax(0,1fr)]">
            <aside className="border-b border-border bg-muted/20 lg:border-b-0 lg:border-r" aria-label="Client list">
              <div className="border-b border-border px-4 py-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-semibold">Clients</h2>
                    <p className="mt-0.5 text-xs text-muted-foreground">{profiles.length} active profiles</p>
                  </div>
                  <span className="flex h-8 w-8 items-center justify-center rounded-md border bg-background text-primary">
                    <Building2 size={15} />
                  </span>
                </div>
                <div className="relative mt-4">
                  <Search
                    size={14}
                    className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                  />
                  <Input
                    value={clientQuery}
                    onChange={(event) => setClientQuery(event.target.value)}
                    placeholder="Find a client"
                    className="h-9 bg-background pl-9"
                  />
                </div>
              </div>

              <div className="max-h-[250px] overflow-y-auto p-2 lg:max-h-[calc(100vh-320px)]">
                {isLoading ? (
                  <div className="flex items-center gap-2 px-3 py-8 text-sm text-muted-foreground">
                    <Loader2 size={15} className="animate-spin" /> Loading clients
                  </div>
                ) : visibleProfiles.length === 0 ? (
                  <div className="rounded-md border border-dashed px-3 py-8 text-center text-sm text-muted-foreground">
                    No clients found.
                  </div>
                ) : (
                  visibleProfiles.map((profile) => {
                    const active = selected?.id === profile.id;
                    return (
                      <button
                        key={profile.id}
                        type="button"
                        onClick={() => setSelectedId(profile.id)}
                        aria-current={active ? "true" : undefined}
                        className={`group mb-1 flex min-h-16 w-full items-center gap-3 rounded-md px-3 py-2 text-left transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${active ? "bg-primary text-primary-foreground shadow-sm" : "hover:bg-muted"}`}
                      >
                        <span
                          className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-md border text-sm font-semibold ${active ? "border-white/25 bg-white/10" : "bg-background text-primary"}`}
                        >
                          {profile.name.trim().slice(0, 1).toLocaleUpperCase("en-US") || <Building2 size={15} />}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm font-semibold">{profile.name}</span>
                          <span
                            className={`mt-0.5 block truncate text-xs ${active ? "text-primary-foreground/75" : "text-muted-foreground"}`}
                          >
                            {profile.industries.length} industries · {profile.monitoredTechnologies.length} technologies
                          </span>
                        </span>
                        <ChevronRight
                          size={15}
                          className={`shrink-0 ${active ? "opacity-90" : "text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100"}`}
                        />
                      </button>
                    );
                  })
                )}
              </div>
            </aside>

            {selected ? (
              <motion.section
                key={selected.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.18 }}
                className="min-w-0"
              >
                <div className="flex flex-col gap-4 border-b border-border px-5 py-5 sm:flex-row sm:items-center sm:justify-between lg:px-7">
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-md bg-primary/10 text-lg font-semibold text-primary">
                      {selected.name.trim().slice(0, 1).toLocaleUpperCase("en-US")}
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <h2 className="truncate text-xl font-semibold">{selected.name}</h2>
                        {hasChanges && (
                          <Badge className="rounded-md bg-amber-100 text-amber-800 hover:bg-amber-100">Unsaved</Badge>
                        )}
                      </div>
                      <p className="mt-0.5 text-sm text-muted-foreground">
                        {scopeTotal} threat-scope signals · {clientTypes.length} services
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 self-end sm:self-auto">
                    <ArchiveClientDialog
                      clientName={selected.name}
                      disabled={archive.isPending || profiles.length <= 1}
                      pending={archive.isPending}
                      onArchive={() => archive.mutate()}
                    />
                    <Button
                      onClick={() => save.mutate()}
                      disabled={
                        save.isPending || !hasChanges || name.trim().length < 2 || unsupportedTemplateTokens.length > 0
                      }
                      className="h-10"
                    >
                      {save.isPending ? (
                        <Loader2 size={15} className="mr-2 animate-spin" />
                      ) : (
                        <Save size={15} className="mr-2" />
                      )}{" "}
                      Save changes
                    </Button>
                  </div>
                </div>

                <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                  <div className="border-b border-border px-5 lg:px-7">
                    <TabsList className="h-12 w-full justify-start gap-6 rounded-none bg-transparent p-0">
                      <TabsTrigger
                        value="profile"
                        className="h-12 rounded-none border-b-2 border-transparent px-0 data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
                      >
                        <Building2 size={14} className="mr-2" /> Profile
                      </TabsTrigger>
                      <TabsTrigger
                        value="services"
                        className="h-12 rounded-none border-b-2 border-transparent px-0 data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
                      >
                        <ShieldCheck size={14} className="mr-2" /> Services{" "}
                        <span className="ml-2 text-xs text-muted-foreground">{clientTypes.length}</span>
                      </TabsTrigger>
                      <TabsTrigger
                        value="scope"
                        className="h-12 rounded-none border-b-2 border-transparent px-0 data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
                      >
                        <Layers3 size={14} className="mr-2" /> Threat scope{" "}
                        <span className="ml-2 text-xs text-muted-foreground">{scopeTotal}</span>
                      </TabsTrigger>
                      <TabsTrigger
                        value="communications"
                        className="h-12 rounded-none border-b-2 border-transparent px-0 data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
                      >
                        <Mail size={14} className="mr-2" /> Client emails{" "}
                        <span className="ml-2 text-xs text-muted-foreground">{digests.length}</span>
                      </TabsTrigger>
                    </TabsList>
                  </div>

                  <TabsContent value="profile" className="m-0 p-5 lg:p-7">
                    <div className="max-w-3xl">
                      <div className="mb-7">
                        <h2 className="text-lg font-semibold">Profile details</h2>
                        <p className="mt-1 text-sm text-muted-foreground">
                          Identity and notification routing for this client.
                        </p>
                      </div>
                      <div className="space-y-6">
                        <div>
                          <Label htmlFor="client-name">Client name</Label>
                          <Input
                            id="client-name"
                            value={name}
                            onChange={(event) => setName(event.target.value)}
                            className="mt-2 max-w-xl"
                          />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <Label htmlFor="notification-emails">Notification emails</Label>
                            <Bell size={13} className="text-muted-foreground" />
                          </div>
                          <p className="mt-1 text-xs text-muted-foreground">
                            Enter one address per line. Alerts generated for this client will use these recipients.
                          </p>
                          <Textarea
                            id="notification-emails"
                            rows={5}
                            value={notificationEmails}
                            onChange={(event) => setNotificationEmails(event.target.value)}
                            className="mt-2 max-w-xl font-mono text-sm"
                            placeholder={"soc@example.com\ncti@example.com"}
                          />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <Label htmlFor="mapping-terms">Semantic mapping signals</Label>
                            <Sparkles size={13} className="text-muted-foreground" />
                          </div>
                          <p className="mt-1 max-w-2xl text-xs leading-5 text-muted-foreground">
                            Enter one free-form signal per line, such as business units, internal product names, brand
                            names, domains, subsidiaries, or analyst shorthand. AI uses these as contextual meaning and
                            returns only the client profile ID; the platform does not perform direct string matching.
                          </p>
                          <Textarea
                            id="mapping-terms"
                            rows={7}
                            value={mappingTerms}
                            onChange={(event) => setMappingTerms(event.target.value)}
                            className="mt-2 max-w-2xl font-mono text-sm"
                            placeholder={"Tesla Energy\nGigafactory Berlin\nsupercharger infrastructure\ntesla.com"}
                            data-testid="textarea-client-mapping-terms"
                          />
                          <div className="mt-2 text-xs text-muted-foreground">
                            {splitMappingTerms(mappingTerms).length} mapping signals
                          </div>
                        </div>
                        <div className="rounded-md border border-cyan-200 bg-cyan-50/70 p-4 text-sm text-slate-700">
                          <div className="flex gap-3">
                            <Sparkles size={17} className="mt-0.5 shrink-0 text-cyan-700" />
                            <p className="leading-6">
                              AI analysis interprets taxonomy labels, aliases, and mapping signals semantically.
                              Persisted client relationships always use canonical profile IDs rather than matching raw
                              text.
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="services" className="m-0 p-5 lg:p-7">
                    <ScopeEditor
                      title="Service coverage"
                      description="Select the services delivered to this client so analysts can frame recommendations against the actual engagement."
                      values={clientTypes}
                      options={clientTypeOptions}
                      onChange={setClientTypes}
                    />
                  </TabsContent>

                  <TabsContent value="scope" className="m-0 p-5 lg:p-7">
                    <Tabs defaultValue="geographies" className="w-full">
                      <TabsList className="mb-7 grid h-auto w-full max-w-2xl grid-cols-3 rounded-md bg-muted p-1">
                        <TabsTrigger value="geographies" className="min-h-10 gap-2">
                          <Globe2 size={14} /> Geographies <span className="text-xs opacity-70">{geos.length}</span>
                        </TabsTrigger>
                        <TabsTrigger value="industries" className="min-h-10 gap-2">
                          <Building2 size={14} /> Industries{" "}
                          <span className="text-xs opacity-70">{industries.length}</span>
                        </TabsTrigger>
                        <TabsTrigger value="technologies" className="min-h-10 gap-2">
                          <Layers3 size={14} /> Technologies{" "}
                          <span className="text-xs opacity-70">{technologies.length}</span>
                        </TabsTrigger>
                      </TabsList>
                      <TabsContent value="geographies" className="m-0">
                        <ScopeEditor
                          title="Geographies"
                          description="Regions where the client operates, hosts critical assets, or requires threat monitoring."
                          kind="geo"
                          values={geos}
                          options={optionsFor("geo")}
                          onChange={setGeos}
                          onCreate={createOption}
                        />
                      </TabsContent>
                      <TabsContent value="industries" className="m-0">
                        <ScopeEditor
                          title="Industries"
                          description="Sectors that define the client's business exposure and relevant threat landscape."
                          kind="industry"
                          values={industries}
                          options={optionsFor("industry")}
                          onChange={setIndustries}
                          onCreate={createOption}
                        />
                      </TabsContent>
                      <TabsContent value="technologies" className="m-0">
                        <ScopeEditor
                          title="Monitored technologies"
                          description="Platforms, products, and infrastructure that should influence analysis and prioritisation."
                          kind="technology"
                          values={technologies}
                          options={optionsFor("technology")}
                          onChange={setTechnologies}
                          onCreate={createOption}
                        />
                      </TabsContent>
                    </Tabs>
                  </TabsContent>

                  <TabsContent value="communications" className="m-0 p-5 lg:p-7">
                    <div className="max-w-4xl space-y-7">
                      <section>
                        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                          <div>
                            <h2 className="text-lg font-semibold">Client email summaries</h2>
                            <p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">
                              Generate client-specific drafts from intelligence assigned to this profile after AI or
                              analyst triage. Drafts require analyst review before external sending.
                            </p>
                          </div>
                          <div className="flex shrink-0 flex-wrap gap-2">
                            <Dialog open={demoEmailOpen} onOpenChange={setDemoEmailOpen}>
                              <DialogTrigger asChild>
                                <Button variant="outline">
                                  <Eye size={14} className="mr-2" /> Preview format
                                </Button>
                              </DialogTrigger>
                              <DialogContent className="max-h-[92vh] overflow-y-auto p-0 sm:max-w-5xl">
                                <DialogHeader>
                                  <div className="px-6 pt-6">
                                    <DialogTitle>Client email preview</DialogTitle>
                                    <DialogDescription>
                                      Sample content rendered with the current template and client branding.
                                    </DialogDescription>
                                  </div>
                                </DialogHeader>
                                <div className="bg-[#eef1f5] px-4 py-6 sm:px-8">
                                  <article className="mx-auto w-full max-w-[760px] overflow-hidden border border-[#d0d5dd] bg-white shadow-sm">
                                    <header className="border-t-[5px] border-t-primary px-6 py-5 sm:px-8">
                                      <div className="flex min-h-[64px] items-center justify-between gap-4">
                                        <div className="min-w-0">
                                          {selected?.emailLogoUrl ? (
                                            <img
                                              src={selected.emailLogoUrl}
                                              alt={`${selected.name} email logo`}
                                              className="mb-3 h-14 w-[180px] object-contain object-left"
                                            />
                                          ) : (
                                            <div className="mb-3 flex h-14 w-[180px] items-center gap-3 text-primary">
                                              <span className="flex h-11 w-11 items-center justify-center rounded-md bg-primary/10">
                                                <ImageIcon size={20} />
                                              </span>
                                              <span className="text-xs text-muted-foreground">Client logo</span>
                                            </div>
                                          )}
                                          <div className="truncate text-xl font-semibold text-[#111827]">
                                            {selected?.name ?? "Client"}
                                          </div>
                                          <div className="mt-1 text-[10px] font-semibold uppercase text-primary">
                                            Threat Intelligence
                                          </div>
                                        </div>
                                        <Badge className="self-start rounded-md bg-red-50 text-red-700 hover:bg-red-50">
                                          Draft
                                        </Badge>
                                      </div>
                                    </header>
                                    <div className="border-y border-[#d0d5dd] bg-[#eef0fe] px-6 py-4 sm:px-8">
                                      <div className="text-[10px] font-semibold uppercase text-[#667085]">Subject</div>
                                      <div className="mt-1 break-words text-sm font-semibold text-[#111827]">
                                        {demoEmail.subject}
                                      </div>
                                    </div>
                                    <div className="px-6 py-6 sm:px-8">
                                      <div className="prose prose-sm max-w-none prose-headings:font-semibold prose-headings:text-[#111827] prose-h2:mt-7 prose-h2:border-b prose-h2:border-[#e4e7ec] prose-h2:pb-2 prose-h2:text-lg prose-h3:text-base prose-p:leading-7 prose-a:text-primary prose-li:leading-6">
                                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{demoEmail.body}</ReactMarkdown>
                                      </div>
                                    </div>
                                    <footer className="bg-[#111827] px-6 py-4 text-[11px] text-[#98a2b3] sm:px-8">
                                      Confidential draft. Analyst approval is required before client distribution.
                                    </footer>
                                  </article>
                                </div>
                                <DialogFooter className="border-t border-border px-6 py-4">
                                  <div className="mr-auto text-xs text-muted-foreground">
                                    Preview uses sample intelligence; exports retain template placeholders.
                                  </div>
                                  <Button
                                    variant="outline"
                                    onClick={() =>
                                      navigator.clipboard?.writeText(
                                        `Subject: ${demoEmail.subject}\n\n${demoEmail.body}`,
                                      )
                                    }
                                  >
                                    <Copy size={14} className="mr-2" /> Copy preview
                                  </Button>
                                  <Button onClick={() => setDemoEmailOpen(false)}>Done</Button>
                                </DialogFooter>
                              </DialogContent>
                            </Dialog>
                            <Button
                              onClick={() => generateDigest.mutate()}
                              disabled={generateDigest.isPending || splitEmails(notificationEmails).length === 0}
                            >
                              {generateDigest.isPending ? (
                                <Loader2 size={14} className="mr-2 animate-spin" />
                              ) : (
                                <Sparkles size={14} className="mr-2" />
                              )}
                              Generate AI draft
                            </Button>
                          </div>
                        </div>

                        <div className="mt-5 grid gap-4 rounded-md border border-border bg-muted/15 p-4 sm:grid-cols-[1fr_220px]">
                          <div>
                            <Label htmlFor="digest-enabled">Automatic draft generation</Label>
                            <p className="mt-1 text-xs leading-5 text-muted-foreground">
                              The scheduler creates a draft when the selected period is due and qualifying client-tagged
                              intelligence exists.
                            </p>
                            <label className="mt-3 flex cursor-pointer items-center gap-3 text-sm">
                              <Checkbox
                                id="digest-enabled"
                                checked={digestEnabled}
                                onCheckedChange={(checked) => setDigestEnabled(checked === true)}
                              />
                              Enable scheduled client drafts
                            </label>
                          </div>
                          <div>
                            <Label>Summary cadence</Label>
                            <Select
                              value={digestCadence}
                              onValueChange={(value) => setDigestCadence(value as ClientProfileDTO["digestCadence"])}
                            >
                              <SelectTrigger className="mt-2">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="daily">Daily</SelectItem>
                                <SelectItem value="weekly">Weekly</SelectItem>
                                <SelectItem value="biweekly">Bi-weekly</SelectItem>
                                <SelectItem value="monthly">Monthly</SelectItem>
                              </SelectContent>
                            </Select>
                            <div className="mt-2 flex items-center gap-1.5 text-[11px] text-muted-foreground">
                              <Clock3 size={12} /> Last generated{" "}
                              {selected.lastDigestAt ? relativeTime(selected.lastDigestAt) : "never"}
                            </div>
                          </div>
                        </div>
                        {splitEmails(notificationEmails).length === 0 ? (
                          <div className="mt-3 rounded-md border border-amber-300/60 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                            Add at least one notification email before generating a client summary.
                          </div>
                        ) : null}

                        <div className="mt-7 border-t border-border pt-6">
                          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                            <div>
                              <h3 className="text-sm font-semibold">Email template</h3>
                              <p className="mt-1 max-w-2xl text-xs leading-5 text-muted-foreground">
                                Static wording is preserved. AI replaces supported placeholders with client-scoped
                                content when a draft is generated.
                              </p>
                            </div>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              onClick={() => {
                                setDigestSubjectTemplate(DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE);
                                setDigestBodyTemplate(DEFAULT_CLIENT_DIGEST_BODY_TEMPLATE);
                              }}
                            >
                              Restore default
                            </Button>
                          </div>

                          <div className="mt-5 grid gap-4 border-y border-border bg-muted/15 py-5 md:grid-cols-[220px_minmax(0,1fr)]">
                            <div className="flex h-[96px] w-[220px] items-center justify-center overflow-hidden rounded-md border border-border bg-background px-4">
                              {selected.emailLogoUrl ? (
                                <img
                                  src={selected.emailLogoUrl}
                                  alt={`${selected.name} email logo`}
                                  className="h-16 w-[180px] object-contain"
                                />
                              ) : (
                                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                  <ImageIcon size={18} /> No client logo
                                </div>
                              )}
                            </div>
                            <div className="min-w-0">
                              <div className="text-sm font-medium">Client email branding</div>
                              <div className="mt-1 text-xs leading-5 text-muted-foreground">
                                PNG or JPEG, up to 2MB. The logo is embedded into Word and EML exports.
                              </div>
                              <input
                                ref={logoFileRef}
                                type="file"
                                accept="image/png,image/jpeg"
                                className="hidden"
                                onChange={(event) => {
                                  const file = event.target.files?.[0];
                                  if (file) void uploadEmailLogo(file);
                                }}
                                data-testid="input-client-email-logo"
                              />
                              <div className="mt-3 flex flex-wrap gap-2">
                                <Button
                                  type="button"
                                  size="sm"
                                  variant="outline"
                                  onClick={() => logoFileRef.current?.click()}
                                  disabled={templateAction !== null}
                                >
                                  {templateAction === "logo" ? (
                                    <Loader2 size={14} className="mr-2 animate-spin" />
                                  ) : (
                                    <Upload size={14} className="mr-2" />
                                  )}
                                  {selected.emailLogoUrl ? "Replace logo" : "Upload logo"}
                                </Button>
                                {selected.emailLogoUrl ? (
                                  <Button
                                    type="button"
                                    size="icon"
                                    variant="ghost"
                                    className="h-9 w-9 text-muted-foreground hover:text-destructive"
                                    onClick={() => void removeEmailLogo()}
                                    disabled={templateAction !== null}
                                    title="Remove email logo"
                                    aria-label="Remove email logo"
                                  >
                                    {templateAction === "remove-logo" ? (
                                      <Loader2 size={14} className="animate-spin" />
                                    ) : (
                                      <Trash2 size={14} />
                                    )}
                                  </Button>
                                ) : null}
                              </div>
                            </div>
                          </div>

                          <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                              <div className="text-sm font-medium">Download template</div>
                              <div className="mt-1 text-xs text-muted-foreground">
                                Exports use the last saved subject, body, and logo.
                              </div>
                            </div>
                            <div className="flex flex-wrap gap-2">
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                onClick={() => void downloadEmailTemplate("docx")}
                                disabled={templateAction !== null || hasChanges}
                                title={hasChanges ? "Save changes before exporting" : "Download Word template"}
                              >
                                {templateAction === "docx" ? (
                                  <Loader2 size={14} className="mr-2 animate-spin" />
                                ) : (
                                  <FileText size={14} className="mr-2" />
                                )}{" "}
                                Word
                              </Button>
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                onClick={() => void downloadEmailTemplate("eml")}
                                disabled={templateAction !== null || hasChanges}
                                title={hasChanges ? "Save changes before exporting" : "Download EML template"}
                              >
                                {templateAction === "eml" ? (
                                  <Loader2 size={14} className="mr-2 animate-spin" />
                                ) : (
                                  <Download size={14} className="mr-2" />
                                )}{" "}
                                EML
                              </Button>
                            </div>
                          </div>

                          <div className="mt-5 space-y-5">
                            <div>
                              <Label htmlFor="digest-subject-template">Subject template</Label>
                              <Input
                                id="digest-subject-template"
                                value={digestSubjectTemplate}
                                onChange={(event) => setDigestSubjectTemplate(event.target.value)}
                                className="mt-2 font-mono text-xs"
                                data-testid="input-digest-subject-template"
                              />
                            </div>
                            <div>
                              <Label htmlFor="digest-body-template">Body template</Label>
                              <Textarea
                                id="digest-body-template"
                                value={digestBodyTemplate}
                                onChange={(event) => setDigestBodyTemplate(event.target.value)}
                                rows={24}
                                className="mt-2 font-mono text-xs leading-5"
                                data-testid="textarea-digest-body-template"
                              />
                            </div>
                          </div>

                          {unsupportedTemplateTokens.length > 0 ? (
                            <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
                              Unsupported placeholders: {unsupportedTemplateTokens.join(", ")}
                            </div>
                          ) : null}

                          <div className="mt-5 overflow-x-auto rounded-md border border-border">
                            <div className="grid min-w-[720px] grid-cols-[minmax(150px,0.8fr)_90px_minmax(0,1.5fr)_40px] gap-3 bg-muted/50 px-3 py-2 text-[10px] font-semibold uppercase text-muted-foreground">
                              <span>Placeholder</span>
                              <span>Placement</span>
                              <span>Generated content</span>
                              <span />
                            </div>
                            {CLIENT_DIGEST_TEMPLATE_PLACEHOLDERS.map((item) => (
                              <div
                                key={item.token}
                                className="grid min-w-[720px] grid-cols-[minmax(150px,0.8fr)_90px_minmax(0,1.5fr)_40px] items-center gap-3 border-t border-border px-3 py-2.5 text-xs"
                              >
                                <code className="break-all font-mono font-medium text-primary">{item.token}</code>
                                <span className="text-muted-foreground">{item.placement}</span>
                                <span className="leading-5 text-muted-foreground">{item.description}</span>
                                <Button
                                  type="button"
                                  size="icon"
                                  variant="ghost"
                                  className="h-8 w-8"
                                  title={`Copy ${item.token}`}
                                  aria-label={`Copy ${item.label} placeholder`}
                                  onClick={() => navigator.clipboard?.writeText(item.token)}
                                >
                                  <Copy size={13} />
                                </Button>
                              </div>
                            ))}
                          </div>
                        </div>
                      </section>

                      <section className="border-t border-border pt-6">
                        <div className="flex items-center justify-between">
                          <div>
                            <h3 className="text-sm font-semibold">Draft history</h3>
                            <p className="mt-1 text-xs text-muted-foreground">
                              Generated summaries remain auditable and editable through their review lifecycle.
                            </p>
                          </div>
                        </div>
                        <div className="mt-4 space-y-3">
                          {digests.length === 0 ? (
                            <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
                              No client email drafts generated yet.
                            </div>
                          ) : (
                            digests.map((digest) => (
                              <article key={digest.id} className="overflow-hidden rounded-md border border-border">
                                <div className="flex flex-col gap-3 border-b border-border bg-muted/20 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                                  <div className="min-w-0">
                                    <div className="truncate text-sm font-semibold">{digest.subject}</div>
                                    <div className="mt-1 text-[11px] text-muted-foreground">
                                      {cadenceLabel(digest.cadence)} · {digest.findingIds.length} findings ·{" "}
                                      {digest.recipients.length} recipients · {relativeTime(digest.createdAt)}
                                      {digest.aiProviderLabel ? ` · Drafted with ${digest.aiProviderLabel}` : ""}
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <Select
                                      value={digest.status}
                                      onValueChange={(status) =>
                                        updateDigest.mutate({
                                          digestId: digest.id,
                                          status: status as ClientDigestDTO["status"],
                                        })
                                      }
                                    >
                                      <SelectTrigger className="h-8 w-32 text-xs">
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent>
                                        <SelectItem value="draft">Draft</SelectItem>
                                        <SelectItem value="reviewed">Reviewed</SelectItem>
                                        <SelectItem value="approved">Approved</SelectItem>
                                        <SelectItem value="sent">Sent</SelectItem>
                                      </SelectContent>
                                    </Select>
                                    <Button
                                      size="icon"
                                      variant="outline"
                                      className="h-8 w-8"
                                      onClick={() =>
                                        navigator.clipboard?.writeText(`Subject: ${digest.subject}\n\n${digest.bodyMd}`)
                                      }
                                      aria-label="Copy client email draft"
                                    >
                                      <Copy size={13} />
                                    </Button>
                                  </div>
                                </div>
                                <div className="whitespace-pre-wrap px-4 py-4 text-xs leading-6 text-foreground">
                                  {digest.bodyMd}
                                </div>
                              </article>
                            ))
                          )}
                        </div>
                      </section>
                    </div>
                  </TabsContent>
                </Tabs>
              </motion.section>
            ) : (
              <div className="flex min-h-[520px] items-center justify-center p-8 text-center">
                <div>
                  <Building2 size={28} className="mx-auto text-muted-foreground" />
                  <h2 className="mt-4 font-semibold">No client selected</h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Create a client to begin configuring analysis scope.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </AppShell>
  );
}
