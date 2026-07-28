import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Building2,
  CheckCircle2,
  CircleDashed,
  Code2,
  Copy,
  Database,
  FileCode2,
  Filter,
  FlaskConical,
  History,
  Loader2,
  Plus,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { relativeTime } from "@/lib/format";
import { useAuth } from "@/lib/auth";
import type {
  ClientProfileDTO,
  DetectionRuleDTO,
  RuleFalsePositiveRisk,
  RuleSeverity,
  RuleSyntaxStatus,
  RuleTestStatus,
  RuleStatus,
} from "@shared/schema";

type RulesResp = { rules: DetectionRuleDTO[] };
type TaxonomiesResp = { huntLanguages: Array<{ id: string; label: string }> };
type ProfilesResp = { profiles: ClientProfileDTO[] };

const RULE_STATUSES: RuleStatus[] = ["draft", "reviewed", "validated", "approved", "archived"];
const RULE_SEVERITIES: RuleSeverity[] = ["low", "medium", "high", "critical"];

function severityClass(severity: string) {
  if (severity === "critical") return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300";
  if (severity === "high") return "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300";
  if (severity === "medium") return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300";
  return "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300";
}

function statusClass(status: RuleStatus) {
  if (status === "approved") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  if (status === "validated") return "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-300";
  if (status === "reviewed") return "border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300";
  if (status === "archived") return "border-border bg-muted text-muted-foreground";
  return "border-violet-500/20 bg-violet-500/10 text-violet-700 dark:text-violet-300";
}

function titleCase(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function splitIds(value: string) {
  return value
    .split(/[,\n]/g)
    .map((item) => item.trim())
    .filter(Boolean);
}

function RuleCodeBlock({ label, value }: { label: string; value: string }) {
  const { toast } = useToast();
  return (
    <div className="overflow-hidden rounded-md border border-border bg-background">
      <div className="flex items-center justify-between gap-2 border-b border-border bg-muted/30 px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <FileCode2 size={13} className="shrink-0 text-primary" />
          <div className="truncate text-[11px] font-semibold text-foreground">{label}</div>
        </div>
        <Button
          size="sm"
          variant="ghost"
          className="h-7 px-2 text-[11px]"
          onClick={() => navigator.clipboard?.writeText(value).then(() => toast({ title: "Copied" }))}
          data-testid={`button-copy-rule-${label.toLowerCase().replace(/\W+/g, "-")}`}
        >
          <Copy size={12} className="mr-1.5" /> Copy
        </Button>
      </div>
      <pre className="min-h-64 overflow-x-hidden bg-muted/10 p-5 font-mono text-[12px] leading-5 whitespace-pre-wrap break-words">
        {value || "No rule content yet."}
      </pre>
    </div>
  );
}

function CreateRuleDialog() {
  const { toast } = useToast();
  const { user } = useAuth();
  const mssMode = user?.tenant.operatingMode === "mss";
  const { data: tax } = useQuery<TaxonomiesResp>({ queryKey: ["/api/v1/taxonomies"] });
  const { data: profileData } = useQuery<ProfilesResp>({ queryKey: ["/api/v1/client-profiles"], enabled: mssMode });
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [findingIds, setFindingIds] = useState("");
  const [severity, setSeverity] = useState<RuleSeverity>("medium");
  const [generate, setGenerate] = useState(true);
  const [languages, setLanguages] = useState<string[]>(["sigma", "splunk", "kql_elk"]);
  const [clientIds, setClientIds] = useState<string[]>([]);
  const profiles = profileData?.profiles ?? [];

  function toggleLanguage(language: string) {
    setLanguages((current) =>
      current.includes(language) ? current.filter((item) => item !== language) : [...current, language],
    );
  }

  const create = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/v1/detection-rules", {
        title: title || undefined,
        findingIds: splitIds(findingIds),
        languages,
        clientIds,
        severity,
        generate,
      });
      return response.json();
    },
    onSuccess: (rule: DetectionRuleDTO) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/detection-rules"] });
      toast({ title: "Detection rule created", description: rule.title });
      setOpen(false);
      setTitle("");
      setFindingIds("");
      setClientIds([]);
    },
    onError: (error: any) =>
      toast({ title: "Rule creation failed", description: String(error?.message ?? error), variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button data-testid="button-open-create-rule">
          <Plus size={14} className="mr-2" /> New rule
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Create detection rule</DialogTitle>
          <DialogDescription>
            Generate from OSINT finding IDs or create an empty draft for manual authoring.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="rule-title">Title</Label>
            <Input
              id="rule-title"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="Optional rule title"
              className="mt-2"
            />
          </div>
          <div>
            <Label htmlFor="rule-finding-ids">Source finding IDs</Label>
            <Textarea
              id="rule-finding-ids"
              value={findingIds}
              onChange={(event) => setFindingIds(event.target.value)}
              rows={4}
              placeholder="fid-1, fid-2"
              className="mt-2 font-mono text-xs"
            />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label>Severity</Label>
              <Select value={severity} onValueChange={(value) => setSeverity(value as RuleSeverity)}>
                <SelectTrigger className="mt-2">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RULE_SEVERITIES.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Authoring mode</Label>
              <Select
                value={generate ? "generate" : "manual"}
                onValueChange={(value) => setGenerate(value === "generate")}
              >
                <SelectTrigger className="mt-2">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="generate">AI generate from intel</SelectItem>
                  <SelectItem value="manual">Manual draft</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          {generate ? (
            <div>
              <div className="flex items-center justify-between gap-3">
                <Label>Query targets</Label>
                <span className="text-[10px] text-muted-foreground">{languages.length} selected</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {(tax?.huntLanguages ?? []).map((language) => {
                  const selected = languages.includes(language.id);
                  return (
                    <button
                      key={language.id}
                      type="button"
                      onClick={() => toggleLanguage(language.id)}
                      className={`rounded-md border px-2.5 py-1.5 text-[11px] transition-colors ${
                        selected
                          ? "border-primary bg-primary/10 text-primary"
                          : "border-border bg-background text-muted-foreground hover:bg-muted/40"
                      }`}
                      aria-pressed={selected}
                    >
                      {language.label}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : null}
          {mssMode ? (
            <div>
              <div className="flex items-center justify-between gap-3">
                <Label>Client scope</Label>
                <span className="text-[10px] text-muted-foreground">{clientIds.length} assigned</span>
              </div>
              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
                Assign the rule to the clients whose telemetry, exposure, or service scope it supports.
              </p>
              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                {profiles.map((profile) => {
                  const selected = clientIds.includes(profile.id);
                  return (
                    <button
                      key={profile.id}
                      type="button"
                      onClick={() =>
                        setClientIds((current) =>
                          selected ? current.filter((id) => id !== profile.id) : [...current, profile.id],
                        )
                      }
                      className={`flex min-h-11 items-center gap-2 rounded-md border px-3 py-2 text-left text-xs transition-colors ${
                        selected ? "border-primary/50 bg-primary/5 text-foreground" : "border-border hover:bg-muted/40"
                      }`}
                      aria-pressed={selected}
                    >
                      <Building2 size={13} className={selected ? "text-primary" : "text-muted-foreground"} />
                      <span className="min-w-0 flex-1 truncate font-medium">{profile.name}</span>
                      {selected ? <CheckCircle2 size={13} className="text-primary" /> : null}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : null}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending || (generate && languages.length === 0)}>
            {create.isPending ? (
              <Loader2 size={14} className="mr-2 animate-spin" />
            ) : (
              <ShieldCheck size={14} className="mr-2" />
            )}
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ValidationWorkspace({
  rule,
  profiles,
  targets,
  readOnly,
  canValidate,
  mssMode,
}: {
  rule: DetectionRuleDTO;
  profiles: ClientProfileDTO[];
  targets: Array<{ id: string; label: string }>;
  readOnly: boolean;
  canValidate: boolean;
  mssMode: boolean;
}) {
  const { toast } = useToast();
  const profileById = new Map(profiles.map((profile) => [profile.id, profile]));
  const validations = rule.validations ?? [];
  const availableTargets = [
    ...(rule.sigmaYaml ? [{ id: "sigma", label: "Sigma YAML" }] : []),
    ...Object.keys(rule.queries).map((id) => ({
      id,
      label: targets.find((target) => target.id === id)?.label ?? id,
    })),
  ];
  const validationScopes = mssMode ? rule.clientIds : ["__workspace__"];
  const [clientId, setClientId] = useState(mssMode ? (rule.clientIds[0] ?? "") : "__workspace__");
  const [siemId, setSiemId] = useState(availableTargets[0]?.id ?? "");
  const current = validations.find(
    (validation) => validation.clientId === clientId && validation.siemId === siemId && validation.isCurrentVersion,
  );
  const [telemetry, setTelemetry] = useState("");
  const [syntaxStatus, setSyntaxStatus] = useState<RuleSyntaxStatus>("not_checked");
  const [testStatus, setTestStatus] = useState<RuleTestStatus>("not_tested");
  const [falsePositiveRisk, setFalsePositiveRisk] = useState<RuleFalsePositiveRisk>("unknown");
  const [testMethod, setTestMethod] = useState("");
  const [expectedResult, setExpectedResult] = useState("");
  const [observedResult, setObservedResult] = useState("");
  const [externalReference, setExternalReference] = useState("");
  const [validationNotes, setValidationNotes] = useState("");

  useEffect(() => {
    setTelemetry((current?.telemetrySources ?? []).join(", "));
    setSyntaxStatus(current?.syntaxStatus ?? "not_checked");
    setTestStatus(current?.testStatus ?? "not_tested");
    setFalsePositiveRisk(current?.falsePositiveRisk ?? "unknown");
    setTestMethod(current?.testMethod ?? "");
    setExpectedResult(current?.expectedResult ?? "");
    setObservedResult(current?.observedResult ?? "");
    setExternalReference(current?.externalReference ?? "");
    setValidationNotes(current?.notes ?? "");
  }, [current?.id, clientId, siemId]);

  const save = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("PUT", `/api/v1/detection-rules/${rule.id}/validation`, {
        clientId,
        siemId,
        telemetrySources: splitIds(telemetry),
        syntaxStatus,
        testStatus,
        falsePositiveRisk,
        testMethod: testMethod || null,
        expectedResult: expectedResult || null,
        observedResult: observedResult || null,
        externalReference: externalReference || null,
        notes: validationNotes || null,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/detection-rules"] });
      toast({ title: "Validation evidence saved", description: `Recorded against rule version ${rule.version}.` });
    },
    onError: (error: any) =>
      toast({ title: "Validation failed", description: String(error?.message ?? error), variant: "destructive" }),
  });

  const stale = validations.filter((validation) => !validation.isCurrentVersion);

  return (
    <section className="border-t border-border pt-5" aria-labelledby={`rule-validation-${rule.id}`}>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <FlaskConical size={14} className="text-primary" />
            <h3 id={`rule-validation-${rule.id}`} className="text-sm font-semibold">
              Validation workspace
            </h3>
          </div>
          <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
            Prove telemetry, syntax, and expected behavior for this exact rule version before approval or deployment.
          </p>
        </div>
        <Badge variant="outline" className="w-fit font-mono text-[10px]">
          Rule v{rule.version}
        </Badge>
      </div>

      {mssMode && rule.clientIds.length === 0 ? (
        <div className="mt-4 flex items-center gap-2 rounded-md border border-amber-300/60 bg-amber-50 px-3 py-2 text-[11px] text-amber-900">
          <AlertTriangle size={13} /> Assign a client before recording validation evidence.
        </div>
      ) : (
        <>
          <div className="mt-4 overflow-x-auto rounded-md border border-border">
            <table className="w-full min-w-[620px] text-left text-[11px]">
              <thead className="bg-muted/30 text-[10px] uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">{mssMode ? "Client" : "Scope"}</th>
                  {availableTargets.map((target) => (
                    <th key={target.id} className="px-3 py-2 font-medium">
                      {target.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {validationScopes.map((assignedClientId) => (
                  <tr key={assignedClientId} className="border-t border-border">
                    <td className="px-3 py-2 font-medium">
                      {mssMode ? (profileById.get(assignedClientId)?.name ?? "Archived client") : "Workspace"}
                    </td>
                    {availableTargets.map((target) => {
                      const validation = validations.find(
                        (item) =>
                          item.clientId === assignedClientId && item.siemId === target.id && item.isCurrentVersion,
                      );
                      return (
                        <td key={target.id} className="px-3 py-2">
                          {validation?.passed ? (
                            <span className="inline-flex items-center gap-1 text-emerald-700">
                              <CheckCircle2 size={12} /> Passed
                            </span>
                          ) : validation ? (
                            <span className="inline-flex items-center gap-1 text-amber-700">
                              <AlertTriangle size={12} /> {titleCase(validation.testStatus)}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-muted-foreground">
                              <CircleDashed size={12} /> Not tested
                            </span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className={`mt-4 grid gap-3 sm:grid-cols-2 ${mssMode ? "xl:grid-cols-4" : "xl:grid-cols-3"}`}>
            {mssMode ? (
              <div>
                <Label className="text-[10px] uppercase text-muted-foreground">Client</Label>
                <Select value={clientId} onValueChange={setClientId}>
                  <SelectTrigger className="mt-1 h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {rule.clientIds.map((id) => (
                      <SelectItem key={id} value={id}>
                        {profileById.get(id)?.name ?? "Archived client"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ) : null}
            <div>
              <Label className="text-[10px] uppercase text-muted-foreground">Target</Label>
              <Select value={siemId} onValueChange={setSiemId}>
                <SelectTrigger className="mt-1 h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {availableTargets.map((target) => (
                    <SelectItem key={target.id} value={target.id}>
                      {target.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-[10px] uppercase text-muted-foreground">Syntax check</Label>
              <Select
                value={syntaxStatus}
                onValueChange={(value) => setSyntaxStatus(value as RuleSyntaxStatus)}
                disabled={!canValidate}
              >
                <SelectTrigger className="mt-1 h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="not_checked">Not checked</SelectItem>
                  <SelectItem value="passed">Passed</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-[10px] uppercase text-muted-foreground">Test outcome</Label>
              <Select
                value={testStatus}
                onValueChange={(value) => setTestStatus(value as RuleTestStatus)}
                disabled={!canValidate}
              >
                <SelectTrigger className="mt-1 h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="not_tested">Not tested</SelectItem>
                  <SelectItem value="passed">Passed</SelectItem>
                  <SelectItem value="needs_tuning">Needs tuning</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="mt-3 grid gap-3 lg:grid-cols-2">
            <div>
              <Label htmlFor={`telemetry-${rule.id}`}>Required telemetry</Label>
              <div className="relative mt-1">
                <Database size={13} className="absolute left-2.5 top-2.5 text-muted-foreground" />
                <Input
                  id={`telemetry-${rule.id}`}
                  value={telemetry}
                  onChange={(event) => setTelemetry(event.target.value)}
                  disabled={!canValidate}
                  className="pl-8 text-xs"
                  placeholder="Sysmon Event 1, DeviceProcessEvents, EDR process telemetry"
                />
              </div>
            </div>
            <div>
              <Label htmlFor={`method-${rule.id}`}>Test method</Label>
              <Input
                id={`method-${rule.id}`}
                value={testMethod}
                onChange={(event) => setTestMethod(event.target.value)}
                disabled={!canValidate}
                className="mt-1 text-xs"
                placeholder="Historical replay, Atomic Red Team, controlled simulation..."
              />
            </div>
            <div>
              <Label htmlFor={`expected-${rule.id}`}>Expected result</Label>
              <Textarea
                id={`expected-${rule.id}`}
                value={expectedResult}
                onChange={(event) => setExpectedResult(event.target.value)}
                disabled={!canValidate}
                rows={3}
                className="mt-1 text-xs"
                placeholder="What should match, and why?"
              />
            </div>
            <div>
              <Label htmlFor={`observed-${rule.id}`}>Observed result</Label>
              <Textarea
                id={`observed-${rule.id}`}
                value={observedResult}
                onChange={(event) => setObservedResult(event.target.value)}
                disabled={!canValidate}
                rows={3}
                className="mt-1 text-xs"
                placeholder="Match count, misses, unexpected fields, tuning performed..."
              />
            </div>
          </div>

          <div className="mt-3 grid gap-3 sm:grid-cols-[180px_minmax(0,1fr)]">
            <div>
              <Label className="text-[10px] uppercase text-muted-foreground">False-positive risk</Label>
              <Select
                value={falsePositiveRisk}
                onValueChange={(value) => setFalsePositiveRisk(value as RuleFalsePositiveRisk)}
                disabled={!canValidate}
              >
                <SelectTrigger className="mt-1 h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="unknown">Unknown</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor={`reference-${rule.id}`}>External reference</Label>
              <Input
                id={`reference-${rule.id}`}
                value={externalReference}
                onChange={(event) => setExternalReference(event.target.value)}
                disabled={!canValidate}
                className="mt-1 text-xs"
                placeholder="SIEM search URL, change ticket, test case, or evidence ID"
              />
            </div>
          </div>
          <div className="mt-3">
            <Label htmlFor={`validation-notes-${rule.id}`}>Engineering notes</Label>
            <Textarea
              id={`validation-notes-${rule.id}`}
              value={validationNotes}
              onChange={(event) => setValidationNotes(event.target.value)}
              disabled={!canValidate}
              rows={3}
              className="mt-1 text-xs"
              placeholder="Field mappings, exclusions, thresholds, residual limitations..."
            />
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <div className="text-[10px] text-muted-foreground">
              {current?.testedAt
                ? `Passed by ${current.testedBy ?? "engineer"} ${relativeTime(current.testedAt)}`
                : "No passing evidence recorded for this selection."}
            </div>
            {canValidate ? (
              <Button
                size="sm"
                onClick={() => save.mutate()}
                disabled={save.isPending || !clientId || !siemId || splitIds(telemetry).length === 0}
              >
                {save.isPending ? (
                  <Loader2 size={12} className="mr-2 animate-spin" />
                ) : (
                  <ShieldCheck size={12} className="mr-2" />
                )}
                Save validation
              </Button>
            ) : !readOnly ? (
              <span className="text-[10px] text-muted-foreground">
                Detection engineer or admin role required to record evidence.
              </span>
            ) : null}
          </div>
          {stale.length > 0 ? (
            <div className="mt-4 flex items-center gap-2 border-t border-border pt-3 text-[10px] text-amber-700">
              <History size={12} /> {stale.length} validation record{stale.length === 1 ? "" : "s"} belong to an earlier
              rule version and no longer satisfy readiness gates.
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}

function RuleDetail({
  rule,
  readOnly,
  canValidate,
  mssMode,
}: {
  rule: DetectionRuleDTO;
  readOnly: boolean;
  canValidate: boolean;
  mssMode: boolean;
}) {
  const { toast } = useToast();
  const { data: tax } = useQuery<TaxonomiesResp>({ queryKey: ["/api/v1/taxonomies"] });
  const { data: profileData } = useQuery<ProfilesResp>({ queryKey: ["/api/v1/client-profiles"], enabled: mssMode });
  const [notes, setNotes] = useState(rule.notes ?? "");
  const [activeQuery, setActiveQuery] = useState(Object.keys(rule.queries)[0] ?? "sigma");
  const [clientDraft, setClientDraft] = useState("");
  const profiles = profileData?.profiles ?? [];
  const profileById = new Map(profiles.map((profile) => [profile.id, profile]));
  const availableProfiles = profiles.filter((profile) => !rule.clientIds.includes(profile.id));

  const patch = useMutation({
    mutationFn: async (body: Partial<DetectionRuleDTO>) => {
      const response = await apiRequest("PATCH", `/api/v1/detection-rules/${rule.id}`, body);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/detection-rules"] });
      toast({ title: "Rule updated" });
    },
    onError: (error: any) =>
      toast({ title: "Update failed", description: String(error?.message ?? error), variant: "destructive" }),
  });

  const deploy = useMutation({
    mutationFn: async (siemId: string) => {
      const response = await apiRequest("POST", `/api/v1/detection-rules/${rule.id}/deploy`, {
        siemId,
        mode: "manual",
        status: "deployed",
        message: "Marked deployed by analyst in Batch Two.",
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/detection-rules"] });
      toast({ title: "Deployment state updated" });
    },
    onError: (error: any) =>
      toast({
        title: "Deployment update failed",
        description: String(error?.message ?? error),
        variant: "destructive",
      }),
  });

  const queryEntries = Object.entries(rule.queries);
  const deployedTargets = new Set(
    rule.deployments.filter((deployment) => deployment.status === "deployed").map((deployment) => deployment.siemId),
  );
  const currentPassedValidations = (rule.validations ?? []).filter((validation) => validation.passed);
  const validatedClients = new Set(currentPassedValidations.map((validation) => validation.clientId));
  const readinessComplete = mssMode
    ? rule.clientIds.length > 0 && rule.clientIds.every((clientId) => validatedClients.has(clientId))
    : validatedClients.has("__workspace__");
  const deploymentScopeReady = !mssMode || rule.clientIds.length > 0;
  const metrics = [
    ["Source findings", rule.sourceFindingIds.length],
    ...(mssMode ? [["Clients", rule.clientIds.length]] : []),
    ["ATT&CK", rule.mitreTechniques.length],
    ["Validations", currentPassedValidations.length],
    ["Deployed", `${deployedTargets.size}/${queryEntries.length}`],
    ["Updated", relativeTime(rule.updatedAt)],
  ];

  return (
    <Card className="min-h-full overflow-hidden border-border shadow-none">
      <div className="border-b border-border px-4 py-4 lg:px-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge variant="outline" className={severityClass(rule.severity)}>
                {titleCase(rule.severity)}
              </Badge>
              <Badge variant="outline" className={statusClass(rule.status)}>
                {titleCase(rule.status)}
              </Badge>
              <span className="font-mono text-[10px] text-muted-foreground">Version {rule.version}</span>
              {rule.aiProviderLabel ? (
                <span className="text-[10px] text-muted-foreground">Generated with {rule.aiProviderLabel}</span>
              ) : null}
            </div>
            <h2 className="mt-2 text-lg font-semibold leading-snug text-foreground">{rule.title}</h2>
            <p className="mt-1 max-w-3xl text-xs leading-5 text-muted-foreground">
              {rule.description || "No rule description has been recorded."}
            </p>
          </div>
          {!readOnly && (
            <div className="grid shrink-0 grid-cols-2 gap-2">
              <div>
                <Label className="text-[10px] uppercase text-muted-foreground">Lifecycle</Label>
                <Select
                  value={rule.status}
                  onValueChange={(value) => {
                    if ((value === "validated" || value === "approved") && !canValidate) {
                      toast({
                        title: "Detection engineer approval required",
                        description: "Your role can prepare and review rules, but cannot validate or approve them.",
                        variant: "destructive",
                      });
                      return;
                    }
                    if ((value === "validated" || value === "approved") && !readinessComplete) {
                      toast({
                        title: "Validation evidence required",
                        description: mssMode
                          ? "Every assigned client needs a passing validation for this rule version."
                          : "The workspace needs a passing validation for this rule version.",
                        variant: "destructive",
                      });
                      return;
                    }
                    patch.mutate({ status: value as RuleStatus } as any);
                  }}
                >
                  <SelectTrigger className="mt-1 h-8 w-36 text-xs" data-testid="select-rule-lifecycle">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RULE_STATUSES.map((item) => (
                      <SelectItem key={item} value={item}>
                        {titleCase(item)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-[10px] uppercase text-muted-foreground">Severity</Label>
                <Select
                  value={rule.severity}
                  onValueChange={(value) => patch.mutate({ severity: value as RuleSeverity } as any)}
                >
                  <SelectTrigger className="mt-1 h-8 w-32 text-xs" data-testid="select-rule-severity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RULE_SEVERITIES.map((item) => (
                      <SelectItem key={item} value={item}>
                        {titleCase(item)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}
        </div>
      </div>

      <div
        className={`grid grid-cols-1 border-b border-border sm:grid-cols-3 ${mssMode ? "2xl:grid-cols-6" : "2xl:grid-cols-5"}`}
      >
        {metrics.map(([label, value]) => (
          <div
            key={label}
            className="border-b border-border px-4 py-3 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0"
          >
            <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
            <div className="mt-1 font-mono text-xs font-semibold text-foreground">{value}</div>
          </div>
        ))}
      </div>

      {rule.mitreTechniques.length > 0 ? (
        <div className="flex flex-wrap gap-1.5 border-b border-border px-4 py-3 lg:px-5">
          {rule.mitreTechniques.map((technique) => (
            <Badge key={`${technique.id}-${technique.name ?? ""}`} variant="outline" className="font-mono text-[10px]">
              {technique.id}
              {technique.name ? ` · ${technique.name}` : ""}
            </Badge>
          ))}
        </div>
      ) : null}

      {mssMode ? (
        <section className="border-b border-border px-4 py-4 lg:px-5" aria-labelledby={`rule-client-scope-${rule.id}`}>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <Building2 size={14} className="text-primary" />
                <h3 id={`rule-client-scope-${rule.id}`} className="text-sm font-semibold">
                  Client operational scope
                </h3>
              </div>
              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
                Identify which clients should validate, tune, or deploy this detection. Assignments use canonical Client
                Profile IDs.
              </p>
            </div>
            {!readOnly && availableProfiles.length > 0 ? (
              <div className="flex w-full gap-2 sm:w-auto">
                <Select value={clientDraft} onValueChange={setClientDraft}>
                  <SelectTrigger className="h-8 min-w-52 text-xs">
                    <SelectValue placeholder="Assign a client" />
                  </SelectTrigger>
                  <SelectContent>
                    {availableProfiles.map((profile) => (
                      <SelectItem key={profile.id} value={profile.id}>
                        {profile.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  size="sm"
                  className="h-8"
                  onClick={() =>
                    patch.mutate({ clientIds: [...rule.clientIds, clientDraft] } as any, {
                      onSuccess: () => setClientDraft(""),
                    })
                  }
                  disabled={!clientDraft || patch.isPending}
                >
                  <Plus size={12} className="mr-1.5" /> Assign
                </Button>
              </div>
            ) : null}
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {rule.clientIds.map((clientId) => (
              <Badge
                key={clientId}
                variant="outline"
                className="gap-1.5 border-primary/30 bg-primary/5 text-[10px] text-primary"
              >
                {profileById.get(clientId)?.name ?? "Archived client"}
                {!readOnly ? (
                  <button
                    type="button"
                    onClick={() => patch.mutate({ clientIds: rule.clientIds.filter((id) => id !== clientId) } as any)}
                    aria-label={`Remove ${profileById.get(clientId)?.name ?? "client"}`}
                  >
                    <X size={10} />
                  </button>
                ) : null}
              </Badge>
            ))}
            {rule.clientIds.length === 0 ? (
              <div className="flex items-center gap-2 rounded-md border border-amber-300/60 bg-amber-50 px-3 py-2 text-[11px] text-amber-900">
                <AlertTriangle size={13} /> No client scope assigned. Confirm relevance before approval or deployment.
              </div>
            ) : null}
          </div>
        </section>
      ) : null}

      <div className="p-4 lg:p-5">
        <div className="mb-3">
          <h3 className="text-sm font-semibold">Detection logic</h3>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Compare the portable Sigma source with each compiled platform query before validation.
          </p>
        </div>
        <Tabs value={activeQuery} onValueChange={setActiveQuery}>
          <div className="overflow-x-auto border-b border-border">
            <TabsList className="h-9 min-w-max justify-start gap-0 rounded-none bg-transparent p-0">
              <TabsTrigger
                value="sigma"
                className="h-9 rounded-none border-b-2 border-transparent px-3 text-xs data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
              >
                Sigma
              </TabsTrigger>
              {queryEntries.map(([language]) => {
                const meta = tax?.huntLanguages.find((item) => item.id === language);
                const deployment = rule.deployments.find(
                  (item) => item.siemId === language && item.status === "deployed",
                );
                const deployed = !!deployment;
                return (
                  <TabsTrigger
                    key={language}
                    value={language}
                    className="h-9 gap-1.5 rounded-none border-b-2 border-transparent px-3 text-xs data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
                  >
                    {deployment?.isStale ? (
                      <AlertTriangle size={11} className="text-amber-600" />
                    ) : deployed ? (
                      <CheckCircle2 size={11} className="text-emerald-600" />
                    ) : null}
                    {meta?.label ?? language}
                  </TabsTrigger>
                );
              })}
            </TabsList>
          </div>
          <TabsContent value="sigma" className="mt-3">
            <RuleCodeBlock label="Sigma YAML" value={rule.sigmaYaml ?? ""} />
          </TabsContent>
          {queryEntries.map(([language, query]) => {
            const meta = tax?.huntLanguages.find((item) => item.id === language);
            const deployment = rule.deployments.find((item) => item.siemId === language && item.status === "deployed");
            const deployed = !!deployment;
            return (
              <TabsContent key={language} value={language} className="mt-3">
                <RuleCodeBlock label={meta?.label ?? language} value={query} />
                {!readOnly && (
                  <div className="mt-3 flex justify-end">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => deploy.mutate(language)}
                      disabled={
                        deploy.isPending ||
                        (deployed && !deployment?.isStale) ||
                        !deploymentScopeReady ||
                        rule.status !== "approved"
                      }
                      title={
                        !deploymentScopeReady ? "Assign at least one client before recording deployment." : undefined
                      }
                    >
                      {deploy.isPending ? (
                        <Loader2 size={12} className="mr-2 animate-spin" />
                      ) : deployment?.isStale ? (
                        <AlertTriangle size={12} className="mr-2 text-amber-600" />
                      ) : deployed ? (
                        <CheckCircle2 size={12} className="mr-2 text-emerald-600" />
                      ) : (
                        <ShieldCheck size={12} className="mr-2" />
                      )}
                      {deployment?.isStale
                        ? "Redeploy current version"
                        : deployed
                          ? "Marked deployed"
                          : !deploymentScopeReady
                            ? "Assign client first"
                            : rule.status !== "approved"
                              ? "Approve before deployment"
                              : "Mark manually deployed"}
                    </Button>
                  </div>
                )}
              </TabsContent>
            );
          })}
        </Tabs>

        <div className="mt-5">
          <ValidationWorkspace
            rule={rule}
            profiles={profiles}
            targets={tax?.huntLanguages ?? []}
            readOnly={readOnly}
            canValidate={canValidate}
            mssMode={mssMode}
          />
        </div>

        <div className="mt-5 border-t border-border pt-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <Label htmlFor={`rule-notes-${rule.id}`}>Tuning and validation notes</Label>
              <p className="mt-1 text-[11px] text-muted-foreground">
                Capture expected false positives, required telemetry, and deployment validation.
              </p>
            </div>
            {!readOnly && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => patch.mutate({ notes } as any)}
                disabled={patch.isPending}
              >
                Save notes
              </Button>
            )}
          </div>
          <Textarea
            id={`rule-notes-${rule.id}`}
            value={notes}
            onChange={(event) => setNotes(event.target.value)}
            disabled={readOnly}
            rows={4}
            className="mt-3 text-xs"
            placeholder="False positives, log source requirements, deployment notes..."
          />
        </div>
      </div>
    </Card>
  );
}

export default function DetectionRules() {
  const { user } = useAuth();
  const { toast } = useToast();
  const mssMode = user?.tenant.operatingMode === "mss";
  const readOnly = user?.access_mode === "guest" || user?.role === "reviewer";
  const canValidate = user?.role === "admin" || user?.role === "detection_engineer";
  const [status, setStatus] = useState<"all" | RuleStatus>("all");
  const [severity, setSeverity] = useState<"all" | RuleSeverity>("all");
  const [clientFilter, setClientFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const { data: profileData } = useQuery<ProfilesResp>({ queryKey: ["/api/v1/client-profiles"], enabled: mssMode });
  const profiles = profileData?.profiles ?? [];
  const profileById = useMemo(() => new Map(profiles.map((profile) => [profile.id, profile])), [profiles]);

  useEffect(() => {
    const syncFocusedRule = () => {
      const raw = window.location.hash || "";
      const queryIndex = raw.indexOf("?");
      if (queryIndex < 0) return;
      const params = new URLSearchParams(raw.slice(queryIndex + 1));
      const ruleId = params.get("rule");
      if (ruleId) setFocusedId(ruleId);
    };
    syncFocusedRule();
    window.addEventListener("hashchange", syncFocusedRule);
    window.addEventListener("optrasight:ai-job-open", syncFocusedRule as EventListener);
    return () => {
      window.removeEventListener("hashchange", syncFocusedRule);
      window.removeEventListener("optrasight:ai-job-open", syncFocusedRule as EventListener);
    };
  }, []);

  const { data, isLoading } = useQuery<RulesResp>({
    queryKey: ["/api/v1/detection-rules", status],
    queryFn: async () => {
      const qs = status === "all" ? "" : `?status=${encodeURIComponent(status)}`;
      const response = await apiRequest("GET", `/api/v1/detection-rules${qs}`);
      return response.json();
    },
  });
  const rules = data?.rules ?? [];
  const visibleRules = useMemo(() => {
    const query = search.trim().toLowerCase();
    return rules.filter((rule) => {
      if (severity !== "all" && rule.severity !== severity) return false;
      if (mssMode && clientFilter === "unassigned" && rule.clientIds.length > 0) return false;
      if (mssMode && clientFilter !== "all" && clientFilter !== "unassigned" && !rule.clientIds.includes(clientFilter))
        return false;
      if (!query) return true;
      return [
        rule.title,
        rule.description,
        rule.status,
        rule.severity,
        ...rule.affectedTech,
        ...rule.threatActors,
        ...(mssMode ? rule.clientIds.map((clientId) => profileById.get(clientId)?.name ?? "") : []),
        ...rule.mitreTechniques.flatMap((technique) => [technique.id, technique.name ?? ""]),
      ].some((value) =>
        String(value ?? "")
          .toLowerCase()
          .includes(query),
      );
    });
  }, [rules, search, severity, clientFilter, profileById, mssMode]);
  const focused = visibleRules.find((rule) => rule.id === focusedId) ?? visibleRules[0] ?? null;
  const queueStats = useMemo(
    () => ({
      needsReview: rules.filter((rule) => rule.status === "draft").length,
      clientUnassigned: rules.filter((rule) => rule.clientIds.length === 0).length,
      highPriority: rules.filter((rule) => rule.severity === "high" || rule.severity === "critical").length,
      deployed: rules.filter((rule) => rule.deployments.some((deployment) => deployment.status === "deployed")).length,
    }),
    [rules],
  );
  const summaryStats = [
    ["Needs review", queueStats.needsReview, "Draft rules awaiting analyst validation"],
    ...(mssMode ? [["Client unassigned", queueStats.clientUnassigned, "Rules without an operational owner"]] : []),
    ["High priority", queueStats.highPriority, "High and critical severity"],
    ["Deployment started", queueStats.deployed, "Rules deployed to at least one target"],
  ];

  const remove = useMutation({
    mutationFn: async (ruleId: string) => {
      const response = await apiRequest("DELETE", `/api/v1/detection-rules/${ruleId}`);
      if (!response.ok) throw new Error(await response.text());
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/detection-rules"] });
      setFocusedId(null);
      toast({ title: "Rule deleted" });
    },
    onError: (error: any) =>
      toast({ title: "Delete failed", description: String(error?.message ?? error), variant: "destructive" }),
  });

  return (
    <AppShell>
      <div className="mx-auto w-full max-w-[1760px] overflow-x-hidden px-6 py-8 md:px-12 md:py-10 xl:px-14">
        <PageHeader
          title="Detection Rules"
          eyebrow="Detection engineering"
          description={
            mssMode
              ? "Turn threat intelligence into client-scoped detections, validate platform logic, and track review and deployment."
              : "Turn threat intelligence into workspace detections, validate platform logic, and track review and deployment."
          }
          actions={!readOnly ? <CreateRuleDialog /> : undefined}
        />

        <div
          className={`mb-5 grid overflow-hidden rounded-md border border-border bg-background ${mssMode ? "sm:grid-cols-4" : "sm:grid-cols-3"}`}
        >
          {summaryStats.map(([label, value, description]) => (
            <div
              key={label}
              className="border-b border-border px-4 py-3 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0"
            >
              <div className="text-[10px] font-medium uppercase text-muted-foreground">{label}</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="font-mono text-lg font-semibold text-foreground">{value}</span>
                <span className="text-[10px] text-muted-foreground">{description}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="grid min-h-0 gap-6 pb-8 xl:grid-cols-[400px_minmax(0,1fr)] xl:gap-7">
          <Card className="flex h-[600px] flex-col overflow-hidden border-border shadow-none sm:h-[720px] xl:sticky xl:top-4 xl:h-[calc(100vh-9rem)] xl:min-h-[680px]">
            <div className="border-b border-border px-6 py-5">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold text-foreground">Rule queue</div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    {visibleRules.length === rules.length
                      ? `${rules.length} rules in scope`
                      : `${visibleRules.length} of ${rules.length} rules`}
                  </div>
                </div>
                <div className="flex h-7 items-center gap-1.5 rounded-md border border-border bg-muted/30 px-2 text-[10px] font-medium text-muted-foreground">
                  <Filter size={11} />
                  {status === "all" && severity === "all" && (!mssMode || clientFilter === "all")
                    ? "All rules"
                    : "Filtered"}
                </div>
              </div>
              <div className="relative mt-3">
                <Search
                  size={13}
                  className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground"
                />
                <Input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search rules, ATT&CK, technology..."
                  className="h-8 pl-8 text-xs"
                  data-testid="input-search-detection-rules"
                />
              </div>
              <div
                className={`mt-2 grid grid-cols-1 gap-2 ${mssMode ? "sm:grid-cols-3 xl:grid-cols-1 2xl:grid-cols-3" : "sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2"}`}
              >
                <Select value={status} onValueChange={(value) => setStatus(value as any)}>
                  <SelectTrigger className="h-8 text-xs" data-testid="select-rule-status-filter">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All lifecycle</SelectItem>
                    {RULE_STATUSES.map((item) => (
                      <SelectItem key={item} value={item}>
                        {titleCase(item)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={severity} onValueChange={(value) => setSeverity(value as any)}>
                  <SelectTrigger className="h-8 text-xs" data-testid="select-rule-severity-filter">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All severity</SelectItem>
                    {RULE_SEVERITIES.map((item) => (
                      <SelectItem key={item} value={item}>
                        {titleCase(item)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {mssMode ? (
                  <Select value={clientFilter} onValueChange={setClientFilter}>
                    <SelectTrigger className="h-8 text-xs" data-testid="select-rule-client-filter">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All clients</SelectItem>
                      <SelectItem value="unassigned">Client unassigned</SelectItem>
                      {profiles.map((profile) => (
                        <SelectItem key={profile.id} value={profile.id}>
                          {profile.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : null}
              </div>
            </div>
            <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto p-4">
              {isLoading ? (
                <div className="flex items-center justify-center gap-2 py-12 text-xs text-muted-foreground">
                  <Loader2 size={15} className="animate-spin" /> Loading rules
                </div>
              ) : visibleRules.length === 0 ? (
                <div className="m-2 rounded-md border border-dashed p-8 text-center text-xs leading-5 text-muted-foreground">
                  {rules.length === 0
                    ? "No detection rules yet. Create a manual draft or generate one from selected findings."
                    : "No rules match the current search and filters."}
                </div>
              ) : (
                visibleRules.map((rule) => (
                  <button
                    key={rule.id}
                    type="button"
                    onClick={() => setFocusedId(rule.id)}
                    className={`group relative w-full cursor-pointer rounded-md border px-3 py-2.5 text-left transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 ${
                      focused?.id === rule.id
                        ? "border-primary/50 bg-primary/5"
                        : "border-transparent bg-background hover:border-border hover:bg-muted/35"
                    }`}
                    data-testid={`button-open-rule-${rule.id}`}
                  >
                    {focused?.id === rule.id ? (
                      <span className="absolute inset-y-2 left-0 w-0.5 rounded-r bg-primary" />
                    ) : null}
                    <div className="flex items-start gap-2.5">
                      <Code2 size={14} className="mt-0.5 shrink-0 text-primary/80" />
                      <div className="min-w-0 flex-1">
                        <div className="line-clamp-2 break-words text-xs font-semibold leading-4 text-foreground [overflow-wrap:anywhere]">
                          {rule.title}
                        </div>
                        <div className="mt-2 flex flex-wrap items-center gap-1">
                          <Badge variant="outline" className={`h-5 px-1.5 text-[9px] ${severityClass(rule.severity)}`}>
                            {titleCase(rule.severity)}
                          </Badge>
                          <Badge variant="outline" className={`h-5 px-1.5 text-[9px] ${statusClass(rule.status)}`}>
                            {titleCase(rule.status)}
                          </Badge>
                          <span className="ml-auto font-mono text-[9px] text-muted-foreground">v{rule.version}</span>
                        </div>
                        <div className="mt-1.5 flex items-center justify-between gap-2 text-[10px] text-muted-foreground">
                          <span>
                            {rule.sourceFindingIds.length} findings · {Object.keys(rule.queries).length + 1} targets
                          </span>
                          <span className="shrink-0">{relativeTime(rule.updatedAt)}</span>
                        </div>
                        {mssMode ? (
                          <div className="mt-1.5 flex min-h-5 flex-wrap items-center gap-1">
                            {rule.clientIds.slice(0, 2).map((clientId) => (
                              <span
                                key={clientId}
                                className="max-w-28 truncate rounded-sm bg-muted px-1.5 py-0.5 text-[9px] text-muted-foreground"
                              >
                                {profileById.get(clientId)?.name ?? "Archived client"}
                              </span>
                            ))}
                            {rule.clientIds.length > 2 ? (
                              <span className="text-[9px] text-muted-foreground">+{rule.clientIds.length - 2}</span>
                            ) : null}
                            {rule.clientIds.length === 0 ? (
                              <span className="text-[9px] font-medium text-amber-700">Client unassigned</span>
                            ) : null}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </button>
                ))
              )}
            </div>
          </Card>

          {focused ? (
            <div className="flex h-[600px] min-h-0 flex-col sm:h-[720px] xl:h-[calc(100vh-9rem)] xl:min-h-[680px]">
              <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
                <RuleDetail
                  key={focused.id}
                  rule={focused}
                  readOnly={readOnly}
                  canValidate={canValidate}
                  mssMode={mssMode}
                />
              </div>
              {!readOnly && (
                <div className="flex shrink-0 items-center justify-between gap-5 border-t border-border px-5 py-5">
                  <p className="text-[11px] text-muted-foreground">
                    Deleting a rule removes its compiled queries and deployment history from this workspace.
                  </p>
                  <Button
                    variant="ghost"
                    className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                    size="sm"
                    onClick={() => remove.mutate(focused.id)}
                    disabled={remove.isPending}
                  >
                    <Trash2 size={12} className="mr-2" /> Delete rule
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <Card className="flex min-h-[360px] items-center justify-center p-8 text-center text-sm text-muted-foreground">
              Select a detection rule to inspect Sigma, compiled queries, ATT&CK mapping, and deployment state.
            </Card>
          )}
        </div>
      </div>
    </AppShell>
  );
}
