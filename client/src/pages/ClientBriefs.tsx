import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  CheckCircle2,
  CircleAlert,
  Download,
  ExternalLink,
  FilePenLine,
  Mail,
  PencilLine,
  Loader2,
  MailCheck,
  Inbox,
  Save,
  Send,
  Settings2,
  Sparkles,
} from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { EmailDeliverySettingsDialog } from "@/components/EmailDeliverySettingsDialog";
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
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { startBackgroundJob } from "@/lib/aiJobs";
import { relativeTime } from "@/lib/format";
import { ApiError, apiRequest, queryClient } from "@/lib/queryClient";
import type { ClientDigestDTO, ClientProfileDTO, OsintFindingDTO, SmtpSettingsDTO } from "@shared/schema";

type ProfilesResponse = { profiles: ClientProfileDTO[] };
type FindingsResponse = { findings: OsintFindingDTO[] };
type DigestsResponse = { digests: ClientDigestDTO[] };

const cadenceDays: Record<ClientProfileDTO["digestCadence"], number> = {
  daily: 1,
  weekly: 7,
  biweekly: 14,
  monthly: 30,
};

function cadenceLabel(value: ClientProfileDTO["digestCadence"]) {
  return value === "biweekly" ? "Bi-weekly" : value[0].toUpperCase() + value.slice(1);
}

function severityClass(severity: string) {
  if (severity === "critical") return "border-red-200 bg-red-50 text-red-700";
  if (severity === "high") return "border-orange-200 bg-orange-50 text-orange-700";
  if (severity === "medium") return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-sky-200 bg-sky-50 text-sky-700";
}

function emailHeadingTone(label: string) {
  const value = label.toLowerCase();
  if (value.startsWith("critical")) return "border-red-500 bg-red-50 text-red-800";
  if (value.startsWith("high")) return "border-orange-500 bg-orange-50 text-orange-800";
  if (value.startsWith("medium")) return "border-amber-500 bg-amber-50 text-amber-900";
  if (value.startsWith("low") || value.startsWith("fyi")) return "border-sky-500 bg-sky-50 text-sky-800";
  return "border-primary bg-[#EEF0FE] text-[#312e81]";
}

export default function ClientBriefs() {
  const { toast } = useToast();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const { data: profileData, isLoading: profilesLoading } = useQuery<ProfilesResponse>({
    queryKey: ["/api/v1/client-profiles"],
  });
  const { data: findingData } = useQuery<FindingsResponse>({ queryKey: ["/api/v1/osint/findings"] });
  const profiles = profileData?.profiles.filter((profile) => profile.isActive) ?? [];
  const [clientId, setClientId] = useState("");
  const client = profiles.find((profile) => profile.id === clientId) ?? profiles[0];
  const [cadence, setCadence] = useState<ClientProfileDTO["digestCadence"]>("weekly");
  const [candidateIds, setCandidateIds] = useState<string[]>([]);
  const [activeDigestId, setActiveDigestId] = useState("");
  const [draftView, setDraftView] = useState<"preview" | "edit">("preview");
  const [emailSettingsOpen, setEmailSettingsOpen] = useState(false);
  const [sendConfirmOpen, setSendConfirmOpen] = useState(false);

  const { data: smtpSettings } = useQuery<SmtpSettingsDTO>({
    queryKey: ["/api/v1/email-delivery/settings"],
    enabled: isAdmin,
  });

  useEffect(() => {
    if (!clientId && profiles[0]) setClientId(profiles[0].id);
  }, [clientId, profiles]);

  useEffect(() => {
    if (client) setCadence(client.digestCadence);
  }, [client?.id]);

  const { data: digestData } = useQuery<DigestsResponse>({
    queryKey: ["/api/v1/client-profiles", client?.id, "digests"],
    queryFn: async () => {
      const response = await apiRequest("GET", `/api/v1/client-profiles/${client!.id}/digests`);
      return response.json();
    },
    enabled: Boolean(client?.id),
    refetchInterval: 5000,
  });
  const digests = digestData?.digests ?? [];
  const activeDigest = digests.find((digest) => digest.id === activeDigestId) ?? digests[0];
  const [preparedEml, setPreparedEml] = useState<{ url: string; fileName: string } | null>(null);

  useEffect(() => {
    setActiveDigestId(digests[0]?.id ?? "");
  }, [client?.id, digests[0]?.id]);

  useEffect(() => {
    let cancelled = false;
    let objectUrl = "";
    setPreparedEml(null);
    if (!client || !activeDigest) return;
    apiRequest("GET", `/api/v1/client-profiles/${client.id}/digests/${activeDigest.id}/email.eml`)
      .then(async (response) => {
        const blob = await response.blob();
        if (cancelled) return;
        const disposition = response.headers.get("content-disposition") || "";
        const headerName = disposition.match(/filename="([^"]+)"/i)?.[1];
        const safeClientName = client.name.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60) || "client";
        objectUrl = URL.createObjectURL(blob);
        setPreparedEml({
          url: objectUrl,
          fileName: headerName || `${safeClientName}_${activeDigest.cadence}_Threat_Intelligence_Draft.eml`,
        });
      })
      .catch(() => {
        if (!cancelled) setPreparedEml(null);
      });
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [client?.id, client?.name, activeDigest?.id, activeDigest?.subject, activeDigest?.bodyMd]);

  const eligibleFindings = useMemo(() => {
    if (!client) return [];
    const cutoff = Date.now() - cadenceDays[cadence] * 86400_000;
    return (findingData?.findings ?? [])
      .filter((finding) => finding.clientTags?.includes(client.id))
      .filter((finding) => ["triaged", "assessed", "escalated"].includes(finding.status))
      .filter((finding) => {
        const published = Date.parse(finding.publishedAt);
        return !Number.isNaN(published) && published >= cutoff;
      })
      .sort((left, right) => {
        const statusRank = { escalated: 0, assessed: 1, triaged: 2 } as Record<string, number>;
        const severityRank = { critical: 0, high: 1, medium: 2, low: 3 } as Record<string, number>;
        return (
          (statusRank[left.status] ?? 9) - (statusRank[right.status] ?? 9) ||
          (severityRank[left.severity] ?? 9) - (severityRank[right.severity] ?? 9) ||
          Date.parse(right.publishedAt) - Date.parse(left.publishedAt)
        );
      })
      .slice(0, 60);
  }, [cadence, client?.id, findingData?.findings]);

  useEffect(() => {
    setCandidateIds(eligibleFindings.map((finding) => finding.id));
  }, [client?.id, cadence, eligibleFindings.map((finding) => finding.id).join("|")]);

  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  useEffect(() => {
    setSubject(activeDigest?.subject ?? "");
    setBody(activeDigest?.bodyMd ?? "");
    setDraftView("preview");
  }, [activeDigest?.id, activeDigest?.subject, activeDigest?.bodyMd]);

  const generate = useMutation({
    mutationFn: async () => {
      if (!client) throw new Error("Select a client");
      return startBackgroundJob(`/api/v1/client-profiles/${client.id}/digests/generate`, {
        cadence,
        findingIds: candidateIds,
      });
    },
    onSuccess: () =>
      toast({
        title: "AI brief queued",
        description: "AI will select the defensibly relevant intelligence and prepare an analyst-review draft.",
      }),
    onError: (error: Error) =>
      toast({ title: "Could not generate brief", description: error.message, variant: "destructive" }),
  });

  const updateDraft = useMutation({
    mutationFn: async (patch: { subject?: string; bodyMd?: string; status?: ClientDigestDTO["status"] }) => {
      if (!client || !activeDigest) throw new Error("Select a draft");
      const response = await apiRequest(
        "PATCH",
        `/api/v1/client-profiles/${client.id}/digests/${activeDigest.id}`,
        patch,
      );
      return response.json();
    },
    onSuccess: async (_data, patch) => {
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profiles", client?.id, "digests"] });
      if (patch.subject !== undefined || patch.bodyMd !== undefined) setDraftView("preview");
      toast({ title: "Client brief updated" });
    },
    onError: (error: Error) =>
      toast({ title: "Could not update draft", description: error.message, variant: "destructive" }),
  });

  const sendDraft = useMutation({
    mutationFn: async () => {
      if (!client || !activeDigest) throw new Error("Select a draft");
      const response = await apiRequest(
        "POST",
        `/api/v1/client-profiles/${client.id}/digests/${activeDigest.id}/send`,
        {},
      );
      return response.json() as Promise<{
        recipientCount: number;
        acceptedCount: number;
        rejectedCount: number;
        messageId: string;
      }>;
    },
    onSuccess: async (result) => {
      setSendConfirmOpen(false);
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/client-profiles", client?.id, "digests"] });
      toast({
        title: "Client brief sent",
        description: `${result.acceptedCount} of ${result.recipientCount} recipient deliveries accepted by the SMTP server.`,
      });
    },
    onError: (error: Error) => {
      setSendConfirmOpen(false);
      const apiError = error instanceof ApiError ? error : null;
      const deferred = apiError?.code === "smtp_temporarily_deferred";
      const timedOut = apiError?.code === "smtp_submission_timeout";
      const coolingDown = apiError?.code === "smtp_cooldown_active";
      const retryable = apiError?.retryable === true;
      toast({
        title: deferred
          ? "SMTP provider deferred delivery"
          : timedOut
            ? "SMTP submission timed out"
            : coolingDown
              ? "SMTP delivery is cooling down"
              : "Email was not sent",
        description: retryable
          ? `${error.message} Retry after about ${Math.ceil((apiError?.retryAfterSeconds || 300) / 60)} minutes.`
          : error.message,
        variant: "destructive",
      });
    },
  });

  const selectedEvidence = activeDigest
    ? (findingData?.findings ?? []).filter((finding) => activeDigest.findingIds.includes(finding.id))
    : [];
  const draftChanged = Boolean(activeDigest && (subject !== activeDigest.subject || body !== activeDigest.bodyMd));
  const cancelDraftEdit = () => {
    setSubject(activeDigest?.subject ?? "");
    setBody(activeDigest?.bodyMd ?? "");
    setDraftView("preview");
  };

  return (
    <AppShell>
      <main className="mx-auto min-h-screen w-full max-w-[1760px] overflow-x-hidden px-5 py-7 sm:px-7 lg:px-10 lg:py-9 xl:px-12">
        <PageHeader
          eyebrow="Client delivery"
          title="Client Briefs"
          description="Turn client-scoped, analyst-triaged intelligence into an AI-curated summary and an auditable email draft."
          actions={
            client ? (
              <div className="flex flex-wrap items-center gap-2">
                {isAdmin ? (
                  <Button variant="outline" onClick={() => setEmailSettingsOpen(true)}>
                    <Settings2 size={15} className="mr-2" />
                    Email settings
                    {smtpSettings?.enabled && smtpSettings.configured ? (
                      <span
                        className="ml-2 h-2 w-2 rounded-full bg-emerald-500"
                        aria-label="Email delivery configured"
                      />
                    ) : null}
                  </Button>
                ) : null}
                <Button
                  onClick={() => generate.mutate()}
                  disabled={generate.isPending || candidateIds.length === 0 || client.notificationEmails.length === 0}
                >
                  {generate.isPending ? (
                    <Loader2 size={15} className="mr-2 animate-spin" />
                  ) : (
                    <Sparkles size={15} className="mr-2" />
                  )}
                  Generate AI draft
                </Button>
              </div>
            ) : null
          }
        />

        {profilesLoading ? (
          <div className="flex min-h-[420px] items-center justify-center">
            <Loader2 className="animate-spin text-primary" />
          </div>
        ) : profiles.length === 0 ? (
          <div className="border border-dashed p-10 text-center text-sm text-muted-foreground">
            Create a Client Profile before preparing a client brief.
          </div>
        ) : (
          <div>
            <section className="mb-5 grid overflow-hidden rounded-md border border-border bg-background lg:grid-cols-[minmax(260px,1.35fr)_220px_minmax(360px,1fr)]">
              <div className="border-b border-border px-5 py-4 lg:border-b-0 lg:border-r">
                <Label className="text-xs">Client</Label>
                <Select value={client?.id} onValueChange={setClientId}>
                  <SelectTrigger className="mt-2 h-10 bg-muted/15" aria-label="Client">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.map((profile) => (
                      <SelectItem key={profile.id} value={profile.id}>
                        {profile.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="border-b border-border px-5 py-4 lg:border-b-0 lg:border-r">
                <Label className="text-xs">Reporting period</Label>
                <Select
                  value={cadence}
                  onValueChange={(value) => setCadence(value as ClientProfileDTO["digestCadence"])}
                >
                  <SelectTrigger className="mt-2 h-10 bg-muted/15" aria-label="Reporting period">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="biweekly">Bi-weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid min-h-[86px] grid-cols-3 divide-x divide-border bg-muted/10">
                <div className="flex flex-col justify-center px-4 py-3">
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Eligible</div>
                  <div className="mt-1 font-mono text-xl font-semibold">{eligibleFindings.length}</div>
                  <div className="mt-0.5 text-[10px] text-muted-foreground">In period</div>
                </div>
                <div className="flex flex-col justify-center px-4 py-3">
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Candidates</div>
                  <div className="mt-1 font-mono text-xl font-semibold">{candidateIds.length}</div>
                  <div className="mt-0.5 text-[10px] text-muted-foreground">For AI review</div>
                </div>
                <div className="flex flex-col justify-center px-4 py-3">
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Drafts</div>
                  <div className="mt-1 font-mono text-xl font-semibold">{digests.length}</div>
                  <div className="mt-0.5 text-[10px] text-muted-foreground">Saved briefs</div>
                </div>
              </div>
            </section>

            {client && client.notificationEmails.length === 0 ? (
              <div className="mb-5 flex flex-col gap-3 rounded-md border border-amber-200 bg-amber-50/80 px-4 py-3 text-sm text-amber-900 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 items-center gap-3">
                  <CircleAlert size={17} className="shrink-0 text-amber-700" />
                  <span>Add at least one notification recipient before generating a client brief.</span>
                </div>
                <Button
                  asChild
                  variant="outline"
                  size="sm"
                  className="shrink-0 border-amber-300 bg-white/70 text-amber-900 hover:bg-white"
                >
                  <Link href="/client-profile">Open Client Profile</Link>
                </Button>
              </div>
            ) : null}

            <div className="grid min-h-0 gap-6 pb-8 lg:grid-cols-[360px_minmax(0,1fr)] xl:grid-cols-[400px_minmax(0,1fr)]">
              <aside className="flex h-[420px] min-h-0 flex-col overflow-hidden rounded-md border border-border bg-background sm:h-[540px] lg:sticky lg:top-20 lg:h-[calc(100vh-17rem)] lg:min-h-[620px] lg:max-h-[860px]">
                <div className="border-b border-border px-5 py-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <h2 className="text-sm font-semibold">Candidate intelligence</h2>
                      <p className="mt-1 text-xs text-muted-foreground">Analyst-controlled input to AI selection.</p>
                    </div>
                    <label className="flex cursor-pointer items-center gap-2 text-[11px] text-muted-foreground">
                      <span className="hidden sm:inline">Select all</span>
                      <Checkbox
                        checked={eligibleFindings.length > 0 && candidateIds.length === eligibleFindings.length}
                        onCheckedChange={(checked) =>
                          setCandidateIds(checked ? eligibleFindings.map((finding) => finding.id) : [])
                        }
                        aria-label="Select all eligible intelligence"
                      />
                    </label>
                  </div>
                </div>
                <div className="min-h-0 flex-1 overflow-y-auto">
                  {eligibleFindings.length === 0 ? (
                    <div className="flex h-full min-h-[280px] items-center justify-center px-8 py-10 text-center">
                      <div className="max-w-[240px]">
                        <span className="mx-auto flex h-10 w-10 items-center justify-center rounded-md border border-border bg-muted/20 text-muted-foreground">
                          <Inbox size={18} />
                        </span>
                        <div className="mt-4 text-sm font-medium text-foreground">No eligible intelligence</div>
                        <p className="mt-1.5 text-xs leading-5 text-muted-foreground">
                          Client-tagged findings appear here after triage or assessment.
                        </p>
                      </div>
                    </div>
                  ) : (
                    eligibleFindings.map((finding) => (
                      <label
                        key={finding.id}
                        className="flex cursor-pointer gap-3 border-b border-border px-4 py-3 hover:bg-muted/30"
                      >
                        <Checkbox
                          className="mt-0.5"
                          checked={candidateIds.includes(finding.id)}
                          onCheckedChange={(checked) =>
                            setCandidateIds((current) =>
                              checked ? [...current, finding.id] : current.filter((id) => id !== finding.id),
                            )
                          }
                        />
                        <span className="min-w-0 flex-1">
                          <span className="line-clamp-2 text-sm font-medium leading-5">{finding.title}</span>
                          <span className="mt-2 flex flex-wrap items-center gap-1.5">
                            <Badge variant="outline" className={`text-[10px] ${severityClass(finding.severity)}`}>
                              {finding.severity}
                            </Badge>
                            <Badge variant="outline" className="text-[10px]">
                              {finding.status}
                            </Badge>
                            <span className="text-[10px] text-muted-foreground">{finding.sourceName}</span>
                          </span>
                        </span>
                      </label>
                    ))
                  )}
                </div>
              </aside>

              <section className="h-[600px] min-w-0 overflow-hidden rounded-md border border-border bg-background sm:h-[680px] lg:h-[calc(100vh-17rem)] lg:min-h-[620px] lg:max-h-[860px]">
                <div className="flex min-h-[73px] flex-col gap-3 border-b border-border px-5 py-4 md:flex-row md:items-center md:justify-between lg:px-6">
                  <div>
                    <h2 className="text-sm font-semibold">AI-selected brief and email draft</h2>
                    <p className="mt-1 text-xs text-muted-foreground">
                      The evidence list records exactly which candidate items AI used.
                    </p>
                  </div>
                  {digests.length ? (
                    <Select value={activeDigest?.id} onValueChange={setActiveDigestId}>
                      <SelectTrigger className="h-9 w-full text-xs md:w-[260px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {digests.map((digest) => (
                          <SelectItem key={digest.id} value={digest.id}>
                            {cadenceLabel(digest.cadence)} · {relativeTime(digest.createdAt)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : null}
                </div>

                {!activeDigest ? (
                  <div className="flex h-[calc(100%_-_73px)] min-h-[460px] items-center justify-center px-8 py-12 text-center">
                    <div className="max-w-sm">
                      <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-md border border-border bg-muted/20 text-muted-foreground">
                        <MailCheck size={22} />
                      </span>
                      <h3 className="mt-5 font-semibold">No client brief yet</h3>
                      <p className="mt-2 text-sm leading-6 text-muted-foreground">
                        Select candidate intelligence and generate a draft. AI will retain only the evidence it can
                        relate defensibly to this client.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="grid h-[calc(100%_-_73px)] min-h-0 overflow-y-auto 2xl:grid-cols-[minmax(0,1fr)_310px] 2xl:overflow-hidden">
                    <div className="min-w-0 border-b border-border 2xl:h-full 2xl:overflow-y-auto 2xl:border-b-0 2xl:border-r">
                      <div className="flex flex-col gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="outline">{activeDigest.status}</Badge>
                          <span className="text-xs text-muted-foreground">
                            {activeDigest.findingIds.length} AI-selected · {activeDigest.aiProviderLabel || "AI"}
                          </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          {draftView === "preview" ? (
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              className="h-8 px-2.5 text-xs"
                              onClick={() => setDraftView("edit")}
                            >
                              <PencilLine size={13} className="mr-1.5" />
                              Edit draft
                            </Button>
                          ) : (
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="h-8 px-2.5 text-xs"
                              onClick={cancelDraftEdit}
                              disabled={updateDraft.isPending}
                            >
                              Cancel
                            </Button>
                          )}
                          {preparedEml ? (
                            <Button asChild variant="outline" size="sm" className="h-8 px-2.5 text-xs">
                              <a
                                href={preparedEml.url}
                                download={preparedEml.fileName}
                                title="Download this email draft as an EML file"
                              >
                                <Download size={13} className="mr-1.5" />
                                EML
                              </a>
                            </Button>
                          ) : (
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              className="h-8 px-2.5 text-xs"
                              disabled
                              title="Preparing the EML file"
                            >
                              <Loader2 size={13} className="mr-1.5 animate-spin" />
                              EML
                            </Button>
                          )}
                          <Select
                            value={activeDigest.status}
                            onValueChange={(status) =>
                              updateDraft.mutate({ status: status as ClientDigestDTO["status"] })
                            }
                          >
                            <SelectTrigger className="h-8 w-24 text-xs">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="draft">Draft</SelectItem>
                              <SelectItem value="reviewed">Reviewed</SelectItem>
                              <SelectItem value="approved">Approved</SelectItem>
                              {activeDigest.status === "sent" ? (
                                <SelectItem value="sent" disabled>
                                  Sent
                                </SelectItem>
                              ) : null}
                            </SelectContent>
                          </Select>
                          {draftView === "edit" ? (
                            <Button
                              size="sm"
                              onClick={() => updateDraft.mutate({ subject, bodyMd: body })}
                              disabled={!draftChanged || updateDraft.isPending}
                              title="Save subject and email body"
                            >
                              {updateDraft.isPending ? (
                                <Loader2 size={13} className="mr-2 animate-spin" />
                              ) : (
                                <Save size={13} className="mr-2" />
                              )}{" "}
                              Save changes
                            </Button>
                          ) : null}
                          {isAdmin && activeDigest.status !== "sent" ? (
                            <Button
                              type="button"
                              size="sm"
                              className="h-8 px-2.5 text-xs"
                              onClick={() => setSendConfirmOpen(true)}
                              disabled={
                                activeDigest.status !== "approved" ||
                                !smtpSettings?.enabled ||
                                !smtpSettings.configured ||
                                sendDraft.isPending
                              }
                              title={
                                activeDigest.status !== "approved"
                                  ? "Approve this unchanged draft before sending"
                                  : !smtpSettings?.enabled || !smtpSettings.configured
                                    ? "Configure and enable email delivery first"
                                    : "Send the approved brief to Client Profile recipients"
                              }
                            >
                              {sendDraft.isPending ? (
                                <Loader2 size={13} className="mr-1.5 animate-spin" />
                              ) : (
                                <Send size={13} className="mr-1.5" />
                              )}
                              Send email
                            </Button>
                          ) : null}
                        </div>
                      </div>
                      <div className="bg-[#eef1f5] p-4 sm:p-6 lg:p-8">
                        <article className="mx-auto w-full max-w-[760px] overflow-hidden border border-[#d0d5dd] bg-white text-[#111827] shadow-sm">
                          <div className="border-b border-[#e4e7ec] bg-[#f8f9fb] px-5 py-4 text-xs sm:px-7">
                            <div className="grid grid-cols-[58px_minmax(0,1fr)] gap-x-3 gap-y-2">
                              <span className="font-medium text-[#667085]">From</span>
                              <span className="font-medium">OptraSight Threat Intelligence</span>
                              <span className="font-medium text-[#667085]">To</span>
                              <span className="break-words">
                                {activeDigest.recipients.length
                                  ? activeDigest.recipients.join(", ")
                                  : "Recipient to be added before distribution"}
                              </span>
                              <span className="self-center font-medium text-[#667085]">Subject</span>
                              {draftView === "edit" ? (
                                <Input
                                  id="brief-subject"
                                  value={subject}
                                  onChange={(event) => setSubject(event.target.value)}
                                  aria-label="Email subject"
                                  className="h-8 border-[#cbd5e1] bg-white text-xs font-semibold text-[#111827]"
                                />
                              ) : (
                                <span className="break-words font-semibold">{subject}</span>
                              )}
                            </div>
                          </div>
                          <header className="border-t-[5px] border-t-primary px-6 py-5 sm:px-8">
                            <div className="flex min-h-[58px] items-start justify-between gap-4">
                              <div className="min-w-0">
                                {client?.emailLogoUrl ? (
                                  <img
                                    src={client.emailLogoUrl}
                                    alt={`${client.name} logo`}
                                    className="mb-3 h-12 w-[170px] object-contain object-left"
                                  />
                                ) : (
                                  <Mail size={24} className="mb-3 text-primary" />
                                )}
                                <div className="truncate text-lg font-semibold">{client?.name}</div>
                                <div className="mt-1 text-[10px] font-semibold uppercase text-primary">
                                  Threat Intelligence Brief
                                </div>
                              </div>
                              <span
                                className={`rounded-md border px-2 py-1 text-[10px] font-semibold uppercase ${activeDigest.status === "sent" ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700"}`}
                              >
                                {activeDigest.status}
                              </span>
                            </div>
                          </header>
                          <div className="border-y border-[#d0d5dd] bg-[#EEF0FE] px-6 py-3 text-xs text-[#475467] sm:px-8">
                            {cadenceLabel(activeDigest.cadence)} brief ·{" "}
                            {new Date(activeDigest.periodStart).toLocaleDateString()} -{" "}
                            {new Date(activeDigest.periodEnd).toLocaleDateString()}
                          </div>
                          <div className="px-6 py-6 sm:px-8 sm:py-8">
                            {draftView === "edit" ? (
                              <div>
                                <div className="mb-2 flex items-center justify-between gap-3">
                                  <Label htmlFor="brief-body" className="text-xs text-[#344054]">
                                    Email body
                                  </Label>
                                  <span className="text-[10px] text-[#667085]">Markdown supported</span>
                                </div>
                                <Textarea
                                  id="brief-body"
                                  value={body}
                                  onChange={(event) => setBody(event.target.value)}
                                  rows={28}
                                  aria-label="Email body"
                                  className="min-h-[520px] resize-y border-[#cbd5e1] bg-white font-sans text-sm leading-6 text-[#111827] focus-visible:ring-primary"
                                />
                                <p className="mt-2 text-[10px] leading-4 text-[#667085]">
                                  Keep severity headings, assessment, recommendations, and reference links in the
                                  message body. Save changes to refresh the formatted preview and EML export.
                                </p>
                              </div>
                            ) : (
                              <div className="prose prose-sm max-w-none prose-headings:font-semibold prose-headings:text-[#111827] prose-h3:mb-2 prose-h3:mt-5 prose-h3:text-sm prose-p:leading-6 prose-a:font-medium prose-a:text-primary prose-li:leading-6">
                                <ReactMarkdown
                                  remarkPlugins={[remarkGfm]}
                                  components={{
                                    h2: ({ children }) => {
                                      const label = String(children);
                                      return (
                                        <h2
                                          className={`mt-8 border-l-4 px-3 py-2 text-sm font-semibold ${emailHeadingTone(label)}`}
                                        >
                                          {children}
                                        </h2>
                                      );
                                    },
                                  }}
                                >
                                  {body}
                                </ReactMarkdown>
                              </div>
                            )}
                          </div>
                          <footer className="border-t border-[#e4e7ec] bg-[#111827] px-6 py-3 text-[10px] text-[#d0d5dd] sm:px-8">
                            {activeDigest.status === "sent"
                              ? "SENT · Delivery outcome recorded in the audit log."
                              : "DRAFT · Analyst approval is required before client distribution."}
                          </footer>
                        </article>
                      </div>
                    </div>

                    <aside className="min-w-0 2xl:h-full 2xl:overflow-y-auto">
                      <div className="border-b border-border px-4 py-4">
                        <h3 className="text-sm font-semibold">Selected evidence</h3>
                        <p className="mt-1 text-xs text-muted-foreground">AI’s auditable source set for this draft.</p>
                      </div>
                      <div className="divide-y divide-border">
                        {selectedEvidence.map((finding) => (
                          <article key={finding.id} className="px-4 py-4">
                            <div className="flex items-start gap-2">
                              <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-emerald-600" />
                              <div className="min-w-0">
                                <div className="text-xs font-semibold leading-5">{finding.title}</div>
                                <div className="mt-2 flex flex-wrap gap-1">
                                  <Badge variant="outline" className={`text-[9px] ${severityClass(finding.severity)}`}>
                                    {finding.severity}
                                  </Badge>
                                  <Badge variant="outline" className="text-[9px]">
                                    {finding.status}
                                  </Badge>
                                </div>
                                {finding.aiSummary || finding.analystAssessment ? (
                                  <p className="mt-2 line-clamp-4 text-[11px] leading-5 text-muted-foreground">
                                    {finding.analystAssessment || finding.aiSummary}
                                  </p>
                                ) : null}
                                {finding.url ? (
                                  <a
                                    href={finding.url}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="mt-2 inline-flex items-center gap-1 text-[11px] text-primary hover:underline"
                                  >
                                    {finding.sourceName}
                                    <ExternalLink size={10} />
                                  </a>
                                ) : null}
                              </div>
                            </div>
                          </article>
                        ))}
                      </div>
                      <div className="border-t border-border bg-muted/20 px-4 py-3 text-[11px] leading-5 text-muted-foreground">
                        <FilePenLine size={13} className="mr-1 inline" />
                        Analyst approval remains mandatory before distribution.
                      </div>
                    </aside>
                  </div>
                )}
              </section>
            </div>
          </div>
        )}
      </main>
      {isAdmin ? (
        <EmailDeliverySettingsDialog
          open={emailSettingsOpen}
          onOpenChange={setEmailSettingsOpen}
          settings={smtpSettings}
        />
      ) : null}
      <Dialog
        open={sendConfirmOpen}
        onOpenChange={(open) => {
          if (!sendDraft.isPending) setSendConfirmOpen(open);
        }}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Send approved client brief?</DialogTitle>
            <DialogDescription>
              This external delivery cannot be recalled. OptraSight will record the SMTP result and mark the brief as
              sent only after the server accepts it.
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-md border border-border bg-muted/20 px-4 py-3 text-sm">
            <div className="text-xs font-semibold uppercase text-muted-foreground">Recipients</div>
            <div className="mt-2 break-words leading-6">
              {activeDigest?.recipients.join(", ") || "No recipients configured"}
            </div>
            <div className="mt-3 border-t border-border pt-3 text-xs text-muted-foreground">Subject: {subject}</div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setSendConfirmOpen(false)} disabled={sendDraft.isPending}>
              Cancel
            </Button>
            <Button
              onClick={() => sendDraft.mutate()}
              disabled={sendDraft.isPending || !activeDigest?.recipients.length}
            >
              {sendDraft.isPending ? (
                <Loader2 size={14} className="mr-2 animate-spin" />
              ) : (
                <Send size={14} className="mr-2" />
              )}
              Send now
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
