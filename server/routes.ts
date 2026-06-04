import type { Express, Request, Response, NextFunction } from "express";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { storage } from "./storage";
import {
  loginSchema, insertScopeSchema, scanRequestSchema, triageSchema,
  evidenceUrlScanSchema, integrationUpdateSchema, reportRequestSchema,
  investigationCreateSchema, investigationPatchSchema, investigationLinkSchema, investigationNoteSchema,
  tenantCreateSchema, clientAssetUploadSchema, keywordExpandSchema,
  aiProviderUpsertSchema, aiAssignmentUpdateSchema, youngDomainScanSchema,
  youngDomainAnalyzeSchema, youngDomainAssessmentSchema,
  clientProfileUpdateSchema, clientContactUpsertSchema,
  osintScanSchema, osintAnalyzeSchema, osintEmailDraftSchema, osintOverviewSchema,
  huntQueryCreateSchema, threatLandscapeGenerateSchema, multiScanRequestSchema,
  detectionRuleCreateSchema, detectionRulePatchSchema, detectionRuleDeploySchema,
  SIEM_TARGETS, RULE_STATUSES, DEPLOYMENT_STATUSES, DEPLOYMENT_MODES, RULE_SEVERITIES,
  // v2.30.3 — Threat Actor Profile (TAP) schemas
  threatActorCreateSchema, threatActorPatchSchema, threatActorEnrichSchema,
  threatActorTtpSchema, threatActorToolSchema, threatActorCampaignSchema,
  threatActorIocSchema, threatActorReferenceSchema, threatActorRuleLinkSchema,
  threatActorTenantSchema, threatActorTenantPatchSchema, TENANT_RELEVANCES,
  TAP_STATUSES, ACTOR_TYPES, THREAT_LEVELS, TLP_LEVELS, IOC_TYPES,
  DETECTION_PRIORITIES, TTP_STATUSES, type TapStatus,
  // v2.31.0 — Tabletop Exercise (TTX) schemas
  exerciseCreateSchema, exercisePatchSchema,
  exerciseInjectSchema, exerciseInjectPatchSchema,
  exerciseRoleSchema, exerciseRolePatchSchema,
  exerciseParticipantSchema, exerciseEventCreateSchema,
  EXERCISE_STATUSES, EXERCISE_FRAMEWORKS, EXERCISE_SCENARIO_TYPES,
  EXERCISE_SEVERITIES,
  type ExerciseStatus,
  YOUNG_DOMAIN_PRESETS, AI_TASKS, AI_PROVIDERS,
  CLIENT_TYPES, GEOS, INDUSTRIES, MONITORED_TECHNOLOGIES, HUNT_LANGUAGES,
  OSINT_CATEGORY_LABELS, OSINT_CATEGORY_ORDER, OSINT_OVERVIEW_PERSONAS,
  SCAN_KINDS, type ScanKind, type User, type RuleStatus,
} from "@shared/schema";

// HOSTING_MODE="multi" enables ?tenant=<slug> based tenant pivoting (in addition to X-Tenant-Id).
const HOSTING_MODE = (process.env.HOSTING_MODE || "single").toLowerCase();
import { fromZodError } from "zod-validation-error";
import { runChatTriage, runChatDeepDive, runChatConverse, ChatLiveAiError, type ChatRangeKey } from "./osintChat";
import { runAutoAnalyzeNow, runAutoFetchNow } from "./backgroundJobs";
import { buildThreatActorDocx } from "./tapDocx";
import { generateActorPortrait, getPortraitGeneratorAvailability, PORTRAITS_DIR } from "./tapPortrait";
import express from "express";
// v2.31.0 — Tabletop Exercise hybrid generator + PPTX exports
import { generateExercise } from "./exercises";
import { buildFacilitatorPptx, buildParticipantPptx } from "./pptxExercise";
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { detectTools } from "./tools/availability";
import { DNSTWIST_SCREENSHOTS_DIR } from "./storage";

// v2.31.0 — SSE registry for participant portal (token → res list).
// Lives in-process; safe because the dashboard runs as a single Node process.
type SseClient = { res: Response; lastTs: string };
const _ttxSseClients = new Map<string /* exerciseId */, Set<SseClient>>();
function _sseBroadcast(eid: string | string[], event: { type: string; payload: any; ts?: string }) {
  const key = Array.isArray(eid) ? eid[0] : eid;
  const set = _ttxSseClients.get(key);
  if (!set || set.size === 0) return;
  const payload = `event: ${event.type}\ndata: ${JSON.stringify({ ...event, ts: event.ts ?? new Date().toISOString() })}\n\n`;
  set.forEach((c) => {
    try { c.res.write(payload); } catch { /* dead conn, will be cleaned on close */ }
  });
}

type RunAiJobOptions<T = any> = {
  tenantId: string;
  kind: string;
  payload: any;
  createdBy?: string | null;
  targetLabel: string;
  targetUrl: string | ((jobId: string) => string);
  work: (jobId: string) => Promise<T> | T;
  providerLabel?: (result: T) => string | null | undefined;
};

function runAiJob<T = any>(opts: RunAiJobOptions<T>) {
  const jobId = storage.createAiJob({
    tenantId: opts.tenantId,
    kind: opts.kind,
    payload: opts.payload,
    createdBy: opts.createdBy ?? null,
    targetLabel: opts.targetLabel,
    targetUrl: typeof opts.targetUrl === "string" ? opts.targetUrl : null,
  });
  const targetUrl = typeof opts.targetUrl === "function" ? opts.targetUrl(jobId) : opts.targetUrl;
  if (targetUrl) storage.updateAiJobTarget(jobId, { targetUrl });
  setImmediate(async () => {
    storage.markAiJobRunning(jobId);
    const hb = setInterval(() => { try { storage.setAiJobHeartbeat(jobId); } catch { /* ignore */ } }, 30000);
    try {
      const out = await opts.work(jobId);
      storage.completeAiJob(jobId, out, opts.providerLabel?.(out) ?? (out as any)?.providerLabel ?? (out as any)?.aiProviderLabel ?? null);
    } catch (e: any) {
      storage.failAiJob(jobId, e);
    } finally {
      clearInterval(hb);
    }
  });
  return { jobId, status: "queued", kind: opts.kind, targetLabel: opts.targetLabel, targetUrl };
}

// ---- v2.28 dictionaries (technologies + threat actors) ----
// Loaded once at boot and cached — these are static reference data shipped
// with the build, used by typeahead inputs in the OSINT detail sheet.
let _dictTechnologies: any[] | null = null;
let _dictThreatActors: any[] | null = null;
function resolveDataDir(): string {
  const tries: string[] = [];
  try {
    const dn = (globalThis as any).__dirname;
    if (typeof dn === "string" && dn.length > 0) tries.push(join(dn, "data"));
  } catch {}
  tries.push(join(process.cwd(), "server", "data"));
  tries.push(join(process.cwd(), "dist", "data"));
  tries.push(join(process.cwd(), "data"));
  for (const p of tries) { if (existsSync(p)) return p; }
  return tries[0];
}
function loadDictionaries() {
  if (_dictTechnologies && _dictThreatActors) return { technologies: _dictTechnologies, threatActors: _dictThreatActors };
  const dir = resolveDataDir();
  try {
    const tech = JSON.parse(readFileSync(join(dir, "dict-technologies.json"), "utf-8"));
    _dictTechnologies = Array.isArray(tech) ? tech : [];
  } catch { _dictTechnologies = []; }
  try {
    const actors = JSON.parse(readFileSync(join(dir, "dict-threat-actors.json"), "utf-8"));
    _dictThreatActors = Array.isArray(actors) ? actors : [];
  } catch { _dictThreatActors = []; }
  return { technologies: _dictTechnologies!, threatActors: _dictThreatActors! };
}

interface AuthedRequest extends Request {
  user?: User;
  /** effective tenant id after applying admin X-Tenant-Id override */
  effectiveTenantId?: string;
}

// v2.7 — singleton tracker for the broad OSINT ingest. Module-level so both
// the POST trigger and the GET status endpoint share state.
const globalOsintRun: {
  busy: boolean;
  startedAt: string | null;
  finishedAt: string | null;
  summary: any;
  error: string | null;
} = { busy: false, startedAt: null, finishedAt: null, summary: null, error: null };

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.header("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return res.status(401).json({ detail: "missing bearer token" });
  const u = storage.getUser(m[1]);
  if (!u) return res.status(401).json({ detail: "invalid token" });
  req.user = u;
  // Admins may pivot the active tenant via X-Tenant-Id header. Analysts cannot.
  const override = req.header("x-tenant-id");
  if (override && u.role === "admin") {
    const t = storage.getTenant(String(override));
    req.effectiveTenantId = t ? t.id : u.tenantId;
  } else {
    req.effectiveTenantId = u.tenantId;
  }
  // HOSTING_MODE="multi" allows admins to pivot via ?tenant=<slug> too
  if (HOSTING_MODE === "multi" && u.role === "admin") {
    const slugQ = req.query.tenant;
    const slug = Array.isArray(slugQ) ? slugQ[0] : slugQ;
    if (slug && typeof slug === "string") {
      const t = storage.getTenantBySlug(slug);
      if (t) req.effectiveTenantId = t.id;
    }
  }
  next();
}

export async function registerRoutes(httpServer: Server, app: Express): Promise<Server> {
  // ---- health ----
  // Unauthenticated. Used by load balancers / k8s probes. Returns the
  // production-mode banner state so monitoring can alert when a host falls
  // out of strict mode unexpectedly.
  app.get("/api/v1/health", (_req, res) => {
    res.json({
      ok: true,
      service: "optrasight",
      strict: process.env.OPTRASIGHT_STRICT === "1" || process.env.NODE_ENV === "production",
      nodeEnv: process.env.NODE_ENV ?? "development",
      time: new Date().toISOString(),
    });
  });

  // ---- tool availability ----
  // Reports which external CLI scanners (DNSTwist, openSquat, whois, …) are
  // installed on this host. Authenticated because it leaks host detail. UI
  // uses this to gray-out unavailable scan buttons and render install hints.
  app.get("/api/v1/tools/availability", requireAuth, async (req: AuthedRequest, res, next) => {
    try {
      const fresh = String(req.query.fresh || "") === "1";
      const tools = await detectTools({ fresh });
      res.json({ tools });
    } catch (err) {
      next(err);
    }
  });

  // ---- auth ----
  app.post("/api/v1/auth/login", (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const u = storage.login(parsed.data.email, parsed.data.password);
    if (!u) return res.status(401).json({ detail: "invalid credentials" });
    res.json({ access_token: u.accessToken, token_type: "bearer", tenant_id: u.tenantId, role: u.role, email: u.email });
  });

  app.post("/api/v1/auth/logout", requireAuth, (req: AuthedRequest, res) => {
    const auth = req.header("authorization") || "";
    const m = /^Bearer\s+(.+)$/i.exec(auth);
    if (m) storage.logout(m[1]);
    res.json({ ok: true });
  });

  app.get("/api/v1/me", requireAuth, (req: AuthedRequest, res) => {
    const u = req.user!;
    const t = storage.getTenant(u.tenantId);
    res.json({ id: u.id, email: u.email, role: u.role, tenant: t });
  });

  // ---- tenants ----
  app.get("/api/v1/tenants", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.listTenants(req.user!.role, req.user!.tenantId));
  });
  app.get("/api/v1/tenants/:tid/scope", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin" && req.user!.tenantId !== req.params.tid)
      return res.status(403).json({ detail: "tenant mismatch" });
    res.json(storage.getScope(req.params.tid));
  });
  app.put("/api/v1/tenants/:tid/scope", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin" && req.user!.tenantId !== req.params.tid)
      return res.status(403).json({ detail: "tenant mismatch" });
    const parsed = insertScopeSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    storage.setScope(req.params.tid, parsed.data);
    res.json({ ok: true });
  });

  // ---- assets ----
  app.get("/api/v1/assets", requireAuth, (req: AuthedRequest, res) => {
    const kind = (req.query.kind as string) || undefined;
    const q = (req.query.q as string) || undefined;
    res.json(storage.listAssets(req.effectiveTenantId!, kind, q));
  });

  // ---- scans ----
  app.get("/api/v1/scans", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.listScans(req.effectiveTenantId!));
  });
  app.get("/api/v1/scans/:sid", requireAuth, (req: AuthedRequest, res) => {
    const s = storage.getScan(req.effectiveTenantId!, req.params.sid);
    if (!s) return res.status(404).json({ detail: "not found" });
    res.json(s);
  });
  // Cancel an in-flight scan. Tenant-scoped via storage.cancelScan(). Returns:
  //   202 {ok:true, status:"cancelled"} — abort fired, executor will finalise
  //   409 {ok:false, status:"<terminal>"} — scan already finished
  //   404 — wrong tenant or missing scan id
  app.post("/api/v1/scans/:sid/cancel", requireAuth, (req: AuthedRequest, res) => {
    const r = storage.cancelScan(req.effectiveTenantId!, req.params.sid);
    if (r.status === "not_found") return res.status(404).json({ detail: r.message ?? "not found" });
    if (!r.ok) return res.status(409).json({ detail: r.message, status: r.status });
    res.status(202).json(r);
  });
  app.post("/api/v1/scans/:kind", requireAuth, (req: AuthedRequest, res, next) => {
    const kind = req.params.kind;
    // Skip the generic handler for dedicated routes below
    if (kind === "malicious-site-scanner") return next();
    if (kind === "multi") return next();
    if (!SCAN_KINDS.includes(kind as ScanKind))
      return res.status(400).json({ detail: `unknown kind: ${kind}` });
    const parsed = scanRequestSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    // Admins may target a specific tenant via body.tenant_id; analysts cannot.
    const bodyTid = (req.body && (req.body.tenant_id || req.body.tenantId)) as string | undefined;
    let tid = req.effectiveTenantId!;
    if (bodyTid && req.user!.role === "admin") {
      const t = storage.getTenant(bodyTid);
      if (t) tid = t.id;
    }
    const s = storage.createScan(
      tid, kind as ScanKind,
      parsed.data.target, parsed.data.targets, parsed.data.config || {},
    );
    res.status(202).json(s);
  });

  // ---- findings ----
  app.get("/api/v1/findings", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.listFindings(
      req.effectiveTenantId!,
      req.query.type as string | undefined,
      req.query.severity as string | undefined,
      req.query.status as string | undefined,
    ));
  });
  app.post("/api/v1/findings/:fid/triage", requireAuth, (req: AuthedRequest, res) => {
    const parsed = triageSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const ok = storage.triageFinding(req.effectiveTenantId!, req.params.fid, parsed.data.status, parsed.data.note);
    if (!ok) return res.status(404).json({ detail: "not found" });
    res.json({ ok: true });
  });

  // ---- evidence ----
  app.get("/api/v1/evidence", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.listEvidence(req.effectiveTenantId!));
  });
  app.post("/api/v1/evidence/urlscan", requireAuth, async (req: AuthedRequest, res, next) => {
    const parsed = evidenceUrlScanSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      res.status(202).json(await storage.submitUrlScan(
        req.effectiveTenantId!, parsed.data.url, parsed.data.findingId,
      ));
    } catch (err) {
      next(err);
    }
  });

  // ---- metrics ----
  app.get("/api/v1/metrics", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.metrics(req.effectiveTenantId!));
  });

  // ---- global command/search palette ----
  app.get("/api/v1/search", requireAuth, (req: AuthedRequest, res) => {
    const q = String(req.query.q || "");
    const global = req.header("x-tenant-id") === "__global__";
    res.json(storage.searchPlatform(req.effectiveTenantId!, q, {
      global,
      role: req.user!.role,
    }));
  });

  // ---- tenant scope shortcut ----
  app.get("/api/v1/tenant/scope", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.getScope(req.effectiveTenantId!));
  });
  app.put("/api/v1/tenant/scope", requireAuth, (req: AuthedRequest, res) => {
    const parsed = insertScopeSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    storage.setScope(req.effectiveTenantId!, parsed.data);
    res.json({ ok: true });
  });

  // ---- integrations (per-tenant config + catalog) ----
  app.get("/api/v1/integrations", requireAuth, (req: AuthedRequest, res) => {
    res.json({ integrations: storage.listIntegrations(req.effectiveTenantId!) });
  });
  app.get("/api/v1/integrations/:tool", requireAuth, (req: AuthedRequest, res) => {
    const item = storage.getIntegration(req.effectiveTenantId!, req.params.tool);
    if (!item) return res.status(404).json({ detail: "unknown tool" });
    res.json(item);
  });
  app.put("/api/v1/integrations/:tool", requireAuth, (req: AuthedRequest, res) => {
    const parsed = integrationUpdateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const item = storage.saveIntegration(req.effectiveTenantId!, req.params.tool, parsed.data);
    if (!item) return res.status(404).json({ detail: "unknown tool" });
    res.json(item);
  });
  app.post("/api/v1/integrations/:tool/test", requireAuth, (req: AuthedRequest, res) => {
    const result = storage.testIntegration(req.effectiveTenantId!, req.params.tool);
    res.json(result);
  });

  // ---- reports ----
  app.get("/api/v1/reports", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.listReports(req.effectiveTenantId!, req.user!.role));
  });
  app.get("/api/v1/reports/:rid", requireAuth, (req: AuthedRequest, res) => {
    const r = storage.getReport(req.params.rid);
    if (!r) return res.status(404).json({ detail: "not found" });
    // analysts can only read reports they authored or that include their tenant
    if (req.user!.role !== "admin") {
      const tids: string[] = (() => { try { return JSON.parse(r.tenantIds || "[]"); } catch { return []; } })();
      if (r.authorTenantId !== req.user!.tenantId && !tids.includes(req.user!.tenantId)) {
        return res.status(403).json({ detail: "forbidden" });
      }
    }
    res.json(r);
  });
  app.post("/api/v1/reports", requireAuth, (req: AuthedRequest, res) => {
    const parsed = reportRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    // analysts may only generate reports for their own tenant
    let tenantIds = parsed.data.tenantIds;
    if (req.user!.role !== "admin") tenantIds = [req.user!.tenantId];
    const r = storage.createReport({
      authorTenantId: req.user!.tenantId,
      authorEmail: req.user!.email,
      tenantIds,
      kind: parsed.data.kind,
      title: parsed.data.title,
      scanIds: parsed.data.scanIds,
      includeEvidence: parsed.data.includeEvidence,
    });
    res.status(202).json(r);
  });
  // ---- AI summary on report ----
  app.post("/api/v1/reports/:rid/ai-summary", requireAuth, (req: AuthedRequest, res) => {
    const r = storage.getReport(req.params.rid);
    if (!r) return res.status(404).json({ detail: "not found" });
    if (req.user!.role !== "admin" && r.authorTenantId !== req.user!.tenantId) {
      return res.status(403).json({ detail: "forbidden" });
    }
    const summary = storage.aiSummarizeReport(req.params.rid);
    if (!summary) return res.status(409).json({ detail: "AI provider not configured" });
    res.json(summary);
  });

  app.get("/api/v1/reports/:rid/download", requireAuth, (req: AuthedRequest, res) => {
    const r = storage.getReport(req.params.rid);
    if (!r) return res.status(404).json({ detail: "not found" });
    if (req.user!.role !== "admin") {
      const tids: string[] = (() => { try { return JSON.parse(r.tenantIds || "[]"); } catch { return []; } })();
      if (r.authorTenantId !== req.user!.tenantId && !tids.includes(req.user!.tenantId)) {
        return res.status(403).json({ detail: "forbidden" });
      }
    }
    const format = (req.query.format as string) || "md";
    const safeTitle = (r.title || "report").replace(/[^a-z0-9._-]+/gi, "_").slice(0, 80);
    if (format === "html" || format === "pdf") {
      // PDF falls back to print-ready HTML (browser Save-as-PDF works perfectly)
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename=\"${safeTitle}.html\"`);
      return res.send(r.bodyHtml || "");
    }
    res.setHeader("Content-Type", "text/markdown; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename=\"${safeTitle}.md\"`);
    return res.send(r.bodyMd || "");
  });

  // ---- investigations ----
  app.get("/api/v1/investigations", requireAuth, (req: AuthedRequest, res) => {
    res.json({
      investigations: storage.listInvestigations(req.effectiveTenantId!, {
        status: req.query.status ? String(req.query.status) : undefined,
        q: req.query.q ? String(req.query.q) : undefined,
      }),
    });
  });
  app.post("/api/v1/investigations", requireAuth, (req: AuthedRequest, res) => {
    const parsed = investigationCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const inv = storage.createInvestigation(req.effectiveTenantId!, {
      ...parsed.data,
      createdBy: req.user!.email,
    });
    res.status(201).json(inv);
  });
  app.get("/api/v1/investigations/:id/full", requireAuth, (req: AuthedRequest, res) => {
    const inv = storage.getInvestigationFull(req.effectiveTenantId!, req.params.id);
    if (!inv) return res.status(404).json({ detail: "not found" });
    res.json(inv);
  });
  app.patch("/api/v1/investigations/:id", requireAuth, (req: AuthedRequest, res) => {
    const parsed = investigationPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const inv = storage.patchInvestigation(req.effectiveTenantId!, req.params.id, {
      ...parsed.data,
      actor: req.user!.email,
    });
    if (!inv) return res.status(404).json({ detail: "not found" });
    res.json(inv);
  });
  app.post("/api/v1/investigations/:id/links", requireAuth, (req: AuthedRequest, res) => {
    const parsed = investigationLinkSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const link = storage.addInvestigationLink(req.effectiveTenantId!, req.params.id, {
      ...parsed.data,
      createdBy: req.user!.email,
    });
    if (!link) return res.status(404).json({ detail: "not found" });
    res.status(201).json(link);
  });
  app.delete("/api/v1/investigations/:id/links/:linkId", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteInvestigationLink(req.effectiveTenantId!, req.params.id, req.params.linkId, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "not found" });
    res.json({ ok: true });
  });
  app.post("/api/v1/investigations/:id/notes", requireAuth, (req: AuthedRequest, res) => {
    const parsed = investigationNoteSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const note = storage.addInvestigationNote(req.effectiveTenantId!, req.params.id, {
      ...parsed.data,
      createdBy: req.user!.email,
    });
    if (!note) return res.status(404).json({ detail: "not found" });
    res.status(201).json(note);
  });

  // ---- tenant onboarding (admin only) ----
  app.post("/api/v1/tenants", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin") return res.status(403).json({ detail: "admin only" });
    const parsed = tenantCreateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const t = storage.createTenant(parsed.data);
      res.status(201).json(t);
    } catch (e: any) {
      res.status(409).json({ detail: e.message || "failed to create tenant" });
    }
  });

  // ---- client assets (logos / trademarks) ----
  app.get("/api/v1/tenants/:tid/assets", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin" && req.user!.tenantId !== req.params.tid)
      return res.status(403).json({ detail: "tenant mismatch" });
    const kind = (req.query.kind as string) || undefined;
    res.json({ assets: storage.listClientAssets(req.params.tid, kind) });
  });
  app.post("/api/v1/tenants/:tid/assets", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin" && req.user!.tenantId !== req.params.tid)
      return res.status(403).json({ detail: "tenant mismatch" });
    const parsed = clientAssetUploadSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      res.status(201).json(storage.addClientAsset(req.params.tid, parsed.data));
    } catch (e: any) {
      res.status(400).json({ detail: e.message || "upload failed" });
    }
  });
  app.delete("/api/v1/tenants/:tid/assets/:aid", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin" && req.user!.tenantId !== req.params.tid)
      return res.status(403).json({ detail: "tenant mismatch" });
    const ok = storage.deleteClientAsset(req.params.tid, req.params.aid);
    if (!ok) return res.status(404).json({ detail: "not found" });
    res.json({ ok: true });
  });

  // ---- keyword expansion (SOP §6) ----
  app.post("/api/v1/tenants/:tid/scope/expand", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin" && req.user!.tenantId !== req.params.tid)
      return res.status(403).json({ detail: "tenant mismatch" });
    const parsed = keywordExpandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    res.json(storage.expandKeywordsForTenant(req.params.tid, parsed.data));
  });

  // ---- AI providers ----
  app.get("/api/v1/ai/providers", requireAuth, (req: AuthedRequest, res) => {
    const providers = storage.listAiProviders(req.effectiveTenantId!);
    res.json({
      providers,
      hasUsableProvider: storage.hasUsableAiProvider(req.effectiveTenantId!),
      kinds: AI_PROVIDERS,
      tasks: AI_TASKS,
    });
  });
  app.post("/api/v1/ai/providers", requireAuth, (req: AuthedRequest, res) => {
    const parsed = aiProviderUpsertSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    res.json(storage.upsertAiProvider(req.effectiveTenantId!, parsed.data));
  });
  app.put("/api/v1/ai/providers/:pid", requireAuth, (req: AuthedRequest, res) => {
    const parsed = aiProviderUpsertSchema.safeParse({ ...req.body, id: req.params.pid });
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    res.json(storage.upsertAiProvider(req.effectiveTenantId!, parsed.data));
  });
  app.delete("/api/v1/ai/providers/:pid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteAiProvider(req.effectiveTenantId!, req.params.pid);
    if (!ok) return res.status(404).json({ detail: "not found" });
    res.json({ ok: true });
  });
  app.post("/api/v1/ai/providers/:pid/test", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.testAiProvider(req.effectiveTenantId!, req.params.pid));
  });

  // ---- AI task assignments ----
  app.get("/api/v1/ai/assignments", requireAuth, (req: AuthedRequest, res) => {
    res.json({
      assignments: storage.getAiAssignments(req.effectiveTenantId!),
      tasks: AI_TASKS,
    });
  });
  app.put("/api/v1/ai/assignments", requireAuth, (req: AuthedRequest, res) => {
    const parsed = aiAssignmentUpdateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    storage.setAiAssignments(req.effectiveTenantId!, parsed.data.assignments);
    res.json({ ok: true, assignments: storage.getAiAssignments(req.effectiveTenantId!) });
  });

  // ---- AI triage on a finding ----
  app.post("/api/v1/findings/:fid/ai-triage", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.effectiveTenantId!;
    const fid = req.params.fid;
    const finding = storage.getOsintFinding(tid, fid);
    if (!finding) return res.status(404).json({ detail: "finding not found" });
    if (!storage.resolveAiProvider(tid, "triage")) return res.status(409).json({ detail: "No AI provider configured for triage. Configure one in AI Setup." });
    const job = runAiJob({
      tenantId: tid,
      kind: "finding_ai_triage",
      payload: { findingId: fid },
      createdBy: req.user?.email ?? null,
      targetLabel: `Finding triage — ${finding.title}`,
      targetUrl: `/#/findings?focus=${encodeURIComponent(fid)}`,
      work: () => {
        const out = storage.aiTriageFinding(tid, fid);
        if (!out) throw new Error("finding not found or AI provider missing");
        return out;
      },
      providerLabel: (out: any) => out?.provider?.label ?? null,
    });
    res.status(202).json(job);
  });

  // ---- Malicious Site Scanner ----
  app.get("/api/v1/malicious-site-scanner/presets", requireAuth, (_req: AuthedRequest, res) => {
    res.json({ presets: YOUNG_DOMAIN_PRESETS });
  });
  app.post("/api/v1/scans/malicious-site-scanner", requireAuth, (req: AuthedRequest, res, next) => {
    const parsed = youngDomainScanSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      // Phase 1 — async-job pattern: this synchronously inserts a scans row
      // with status='running' and returns {scanId} immediately. The real
      // DNSTwist + openSquat + crt.sh + whois work runs detached in the
      // background. The client polls GET /api/v1/scans/:sid to surface
      // progress and status; candidates appear in /api/v1/malicious-site-scanner
      // once scans.status flips off 'running'.
      const r = storage.startYoungDomainScan(req.effectiveTenantId!, parsed.data);
      res.status(202).json({
        scanId: r.id,
        status: "running",
        kind: "malicious_site_scan",
        targetLabel: "Malicious Site Scanner",
        targetUrl: `/#/malicious-site-scanner?scan=${encodeURIComponent(r.id)}`,
      });
    } catch (err) {
      next(err);
    }
  });
  app.get("/api/v1/malicious-site-scanner", requireAuth, (req: AuthedRequest, res) => {
    const source = req.query.source as "tenant" | "global" | undefined;
    res.json({ candidates: storage.listYoungDomainCandidates(req.effectiveTenantId!, source) });
  });
  app.get("/api/v1/malicious-site-scanner/:fid", requireAuth, (req: AuthedRequest, res) => {
    const c = storage.getYoungDomainCandidate(req.effectiveTenantId!, req.params.fid);
    if (!c) return res.status(404).json({ detail: "not found" });
    res.json({ candidate: c });
  });
  // Bulk AI analysis across the candidate set.
  app.post("/api/v1/malicious-site-scanner/analyze", requireAuth, (req: AuthedRequest, res) => {
    const parsed = youngDomainAnalyzeSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const provider = storage.resolveAiProvider(tid, "young_domain");
    if (!provider) return res.status(409).json({ detail: "No AI provider configured for young_domain task. Configure one in AI Setup." });
    const job = runAiJob({
      tenantId: tid,
      kind: "young_domain_analysis",
      payload: parsed.data,
      createdBy: req.user?.email ?? null,
      targetLabel: "Malicious-site AI analysis",
      targetUrl: "/#/malicious-site-scanner",
      work: () => storage.runYoungDomainAnalysis(tid, parsed.data),
      providerLabel: (out) => out.provider,
    });
    res.status(202).json(job);
  });
  // Per-candidate AI review.
  app.post("/api/v1/malicious-site-scanner/:fid/ai-review", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.effectiveTenantId!;
    const fid = req.params.fid;
    const candidate = storage.getYoungDomainCandidate(tid, fid);
    if (!candidate) return res.status(404).json({ detail: "candidate not found" });
    const provider = storage.resolveAiProvider(tid, "young_domain");
    if (!provider) return res.status(409).json({ detail: "No AI provider configured for young_domain task. Configure one in AI Setup." });
    const job = runAiJob({
      tenantId: tid,
      kind: "young_domain_analysis",
      payload: { candidateId: fid },
      createdBy: req.user?.email ?? null,
      targetLabel: `AI review — ${candidate.domain}`,
      targetUrl: `/#/malicious-site-scanner?candidate=${encodeURIComponent(fid)}`,
      work: () => {
        const out = storage.runYoungDomainAnalysisOne(tid, fid);
        if (!out) throw new Error("AI provider unavailable or candidate missing");
        return { candidate: out };
      },
      providerLabel: () => provider.label,
    });
    res.status(202).json(job);
  });
  // Analyst assessment patch.
  app.patch("/api/v1/malicious-site-scanner/:fid/assessment", requireAuth, (req: AuthedRequest, res) => {
    const parsed = youngDomainAssessmentSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const c = storage.setYoungDomainAssessment(req.effectiveTenantId!, req.params.fid, {
      analystVerdict: parsed.data.analystVerdict,
      analystNotes: parsed.data.analystNotes ?? null,
      analystBy: req.user!.email,
    });
    if (!c) return res.status(404).json({ detail: "not found" });
    res.json({ candidate: c });
  });

  // ---- multi-kind scan ----
  app.post("/api/v1/scans/multi", requireAuth, (req: AuthedRequest, res) => {
    const parsed = multiScanRequestSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const created: any[] = [];
    for (const k of parsed.data.kinds) {
      const s = storage.createScan(tid, k as ScanKind, parsed.data.target ?? null, parsed.data.targets ?? null, parsed.data.config ?? {});
      created.push(s);
    }
    res.status(202).json({ scans: created });
  });

  // ---- Client Profile (rename of Tenant Scope, with extra fields) ----
  app.get("/api/v1/client-profile", requireAuth, (req: AuthedRequest, res) => {
    res.json(storage.getClientProfile(req.effectiveTenantId!));
  });
  app.put("/api/v1/client-profile", requireAuth, (req: AuthedRequest, res) => {
    const parsed = clientProfileUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    res.json(storage.setClientProfile(req.effectiveTenantId!, parsed.data));
  });

  // ---- Contacts ----
  app.get("/api/v1/client-profile/contacts", requireAuth, (req: AuthedRequest, res) => {
    res.json({ contacts: storage.listContacts(req.effectiveTenantId!) });
  });
  app.post("/api/v1/client-profile/contacts", requireAuth, (req: AuthedRequest, res) => {
    const parsed = clientContactUpsertSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    res.status(201).json(storage.upsertContact(req.effectiveTenantId!, parsed.data));
  });
  app.put("/api/v1/client-profile/contacts/:cid", requireAuth, (req: AuthedRequest, res) => {
    const parsed = clientContactUpsertSchema.safeParse({ ...req.body, id: req.params.cid });
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    res.json(storage.upsertContact(req.effectiveTenantId!, parsed.data));
  });
  app.delete("/api/v1/client-profile/contacts/:cid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteContact(req.effectiveTenantId!, req.params.cid);
    if (!ok) return res.status(404).json({ detail: "not found" });
    res.json({ ok: true });
  });

  // ---- Taxonomies (for UI dropdowns) ----
  app.get("/api/v1/taxonomies", requireAuth, (_req, res) => {
    res.json({
      clientTypes: CLIENT_TYPES,
      geos: GEOS,
      industries: INDUSTRIES,
      monitoredTechnologies: MONITORED_TECHNOLOGIES,
      huntLanguages: HUNT_LANGUAGES,
      osintOverviewPersonas: OSINT_OVERVIEW_PERSONAS,
      // v2.10: surface only the 5 active buckets in dropdowns; legacy codes
      // (CVE/GHSA/CERT/GOV/VENDOR/RANSOMWARE/RSS) remain in OSINT_CATEGORY_LABELS
      // for badge resolution on any pre-v2.10 row that survives, but should
      // not appear as filter options.
      osintCategoryLabels: Object.fromEntries(
        OSINT_CATEGORY_ORDER.map(
          (code) => [code, OSINT_CATEGORY_LABELS[code] ?? code],
        ),
      ),
      hostingMode: HOSTING_MODE,
    });
  });

  // ---- OSINT monitoring ----
  app.get("/api/v1/osint/sources", requireAuth, (req: AuthedRequest, res) => {
    const category = (req.query.category as string) || undefined;
    const q = (req.query.q as string) || undefined;
    res.json({
      sources: storage.listOsintSourceRows({ category, q, tenantId: req.effectiveTenantId }),
      summary: storage.countOsintSourcesByCategory(),
    });
  });

  // v2.29 — KPI strip data for the Sources tab.
  app.get("/api/v1/osint/sources/kpis", requireAuth, (req: AuthedRequest, res) => {
    const crossTenant = String(req.query.crossTenant ?? "") === "true";
    const tenantId = crossTenant ? undefined : req.effectiveTenantId;
    res.json(storage.getOsintSourcesKpis({ tenantId }));
  });

  // v2.29 — Bulk enable / disable / delete on osint_sources.
  app.post("/api/v1/osint/sources/bulk", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const body = req.body || {};
    const ids = Array.isArray(body.ids) ? body.ids.map((v: any) => String(v)).filter(Boolean) : [];
    const action = String(body.action || "");
    if (!ids.length) return res.status(400).json({ detail: "ids must be a non-empty array" });
    if (!(["enable", "disable", "delete"] as const).includes(action as any)) {
      return res.status(400).json({ detail: "action must be one of: enable | disable | delete" });
    }
    const changed = storage.bulkUpdateOsintSources(ids, action as any);
    storage.appendAudit(req.effectiveTenantId!, req.user?.email || "admin", `osint.sources.${action}`, null, { ids, changed });
    res.json({ changed });
  });

  // v2.29 — Sources usability dashboard payload.
  app.get("/api/v1/osint/sources/analytics", requireAuth, (req: AuthedRequest, res) => {
    const crossTenant = String(req.query.crossTenant ?? "") === "true";
    const tenantId = crossTenant ? undefined : req.effectiveTenantId;
    res.json(storage.getOsintSourcesAnalytics({ tenantId }));
  });

  // v2.30 — Deep Sources Analytics endpoints. Each one is independent so the
  // SourcesAnalytics page can load them in parallel and skeleton-render.
  app.get("/api/v1/osint/sources/scorecard", requireAuth, (req: AuthedRequest, res) => {
    const crossTenant = String(req.query.crossTenant ?? "") === "true";
    const tenantId = crossTenant ? undefined : req.effectiveTenantId;
    try { res.json(storage.getOsintSourceScorecard({ tenantId })); }
    catch (e: any) { res.status(500).json({ detail: String(e?.message || e) }); }
  });
  app.get("/api/v1/osint/sources/quadrant", requireAuth, (req: AuthedRequest, res) => {
    const crossTenant = String(req.query.crossTenant ?? "") === "true";
    const tenantId = crossTenant ? undefined : req.effectiveTenantId;
    try { res.json(storage.getOsintSourceQuadrant({ tenantId })); }
    catch (e: any) { res.status(500).json({ detail: String(e?.message || e) }); }
  });
  app.get("/api/v1/osint/sources/overlap", requireAuth, (req: AuthedRequest, res) => {
    const crossTenant = String(req.query.crossTenant ?? "") === "true";
    const tenantId = crossTenant ? undefined : req.effectiveTenantId;
    try { res.json(storage.getOsintSourceOverlap({ tenantId })); }
    catch (e: any) { res.status(500).json({ detail: String(e?.message || e) }); }
  });
  app.get("/api/v1/osint/sources/heatmaps", requireAuth, (req: AuthedRequest, res) => {
    const crossTenant = String(req.query.crossTenant ?? "") === "true";
    const tenantId = crossTenant ? undefined : req.effectiveTenantId;
    try { res.json(storage.getOsintSourceHeatmaps({ tenantId })); }
    catch (e: any) { res.status(500).json({ detail: String(e?.message || e) }); }
  });

  // v2.30 — Admin-triggered bulk re-analyse last N days. Async — returns the
  // job id immediately; UI polls /api/v1/osint/reanalyze-jobs/:id for status.
  app.post("/api/v1/osint/findings/reanalyze", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const sinceDays = Math.max(1, Math.min(Number(req.body?.sinceDays ?? 30), 365));
    try {
      const job = storage.createOsintReanalyzeJob(req.effectiveTenantId!, { sinceDays });
      storage.appendAudit(req.effectiveTenantId!, req.user?.email || "admin", "osint.reanalyze.start", job.id, { sinceDays, total: job.totalCount });
      res.status(202).json(job);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message || e) });
    }
  });
  app.get("/api/v1/osint/reanalyze-jobs/:id", requireAuth, (req: AuthedRequest, res) => {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ detail: "job id required" });
    const job = storage.getOsintReanalyzeJob(req.effectiveTenantId!, id);
    if (!job) return res.status(404).json({ detail: "job not found" });
    res.json(job);
  });

  // v2.28 — typeahead dictionaries for Affected Technology + Threat Actors.
  // Both lists are static reference data shipped with the build. Custom
  // additions made by the analyst at the form-input level are stored
  // directly on the finding (no API round-trip).
  app.get("/api/v1/osint/dictionaries", requireAuth, (_req: AuthedRequest, res) => {
    const dicts = loadDictionaries();
    res.json(dicts);
  });
  app.post("/api/v1/osint/scan", requireAuth, async (req: AuthedRequest, res) => {
    const parsed = osintScanSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const result = await storage.runOsintScan(req.effectiveTenantId!, parsed.data);
      res.status(202).json(result);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message || e) });
    }
  });

  // v2.7 broad OSINT ingest — walks the full 514-source catalog with deep
  // custom parsers + a generic RSS/Atom/RDF/JSON adapter, persists per tenant.
  // Tracked async via a singleton tracker so the UI can poll progress.
  app.post("/api/v1/admin/osint/ingest", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const days = Math.min(Math.max(Number(req.body?.days ?? 365), 1), 730);
    const maxPerSource = Math.min(Math.max(Number(req.body?.maxPerSource ?? 60), 5), 500);
    const maxTotal = Math.min(Math.max(Number(req.body?.maxTotal ?? 10000), 100), 50000);
    const actor = req.user?.email || "admin";
    if (globalOsintRun.busy) {
      return res.status(202).json({ status: "already_running", started: globalOsintRun.startedAt, durationMs: Date.now() - (globalOsintRun.startedAt ? new Date(globalOsintRun.startedAt).getTime() : Date.now()) });
    }
    globalOsintRun.busy = true;
    globalOsintRun.startedAt = new Date().toISOString();
    globalOsintRun.summary = null;
    globalOsintRun.error = null;
    // Fire-and-forget; client polls /api/v1/admin/osint/ingest/status.
    (async () => {
      try {
        const result = await storage.runGlobalOsintIngest({ days, maxPerSource, maxTotal, actor });
        globalOsintRun.summary = result;
      } catch (e: any) {
        globalOsintRun.error = String(e?.message || e);
      } finally {
        globalOsintRun.finishedAt = new Date().toISOString();
        globalOsintRun.busy = false;
      }
    })();
    res.status(202).json({ status: "started", startedAt: globalOsintRun.startedAt, params: { days, maxPerSource, maxTotal } });
  });

  app.get("/api/v1/admin/osint/ingest/status", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    res.json({
      busy: globalOsintRun.busy,
      startedAt: globalOsintRun.startedAt,
      finishedAt: globalOsintRun.finishedAt,
      summary: globalOsintRun.summary,
      error: globalOsintRun.error,
    });
  });
  app.get("/api/v1/osint/findings", requireAuth, (req: AuthedRequest, res) => {
    res.json({
      findings: storage.listOsintFindings(req.effectiveTenantId!, {
        severity: (req.query.severity as string) || undefined,
        status:   (req.query.status as string) || undefined,
        tech:     (req.query.tech as string) || undefined,
        sourceId: (req.query.sourceId as string) || undefined,
        category: (req.query.category as string) || undefined,
      }),
    });
  });
  app.post("/api/v1/osint/overview", requireAuth, (req: AuthedRequest, res) => {
    const parsed = osintOverviewSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const result = storage.generateOsintOverview({
        tid: req.effectiveTenantId!,
        persona: parsed.data.persona,
        category: parsed.data.category,
        severity: parsed.data.severity,
        scope: parsed.data.scope,
        scopeIds: parsed.data.scopeIds,
      });
      res.json(result);
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message || e) });
    }
  });
  app.get("/api/v1/osint/findings/:fid", requireAuth, (req: AuthedRequest, res) => {
    const f = storage.getOsintFinding(req.effectiveTenantId!, req.params.fid);
    if (!f) return res.status(404).json({ detail: "not found" });
    res.json(f);
  });
  // v2.17 — analyst override: status, CVE refs, IoCs, free-form tags, tech, actors.
  app.patch("/api/v1/osint/findings/:fid", requireAuth, (req: AuthedRequest, res) => {
    const body = (req.body || {}) as any;
    const editedBy = req.user?.email || "analyst";
    try {
      const updated = storage.updateOsintFinding(
        req.effectiveTenantId!,
        req.params.fid,
        {
          status: typeof body.status === "string" ? body.status : undefined,
          cveIds: Array.isArray(body.cveIds) ? body.cveIds : undefined,
          iocs: body.iocs && typeof body.iocs === "object" ? body.iocs : undefined,
          analystTags: Array.isArray(body.analystTags) ? body.analystTags : undefined,
          affectedTech: Array.isArray(body.affectedTech) ? body.affectedTech : undefined,
          threatActors: Array.isArray(body.threatActors) ? body.threatActors : undefined,
        },
        editedBy,
      );
      if (!updated) return res.status(404).json({ detail: "not found" });
      res.json(updated);
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message ?? e) });
    }
  });
  app.post("/api/v1/osint/findings/ai-analyze", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = osintAnalyzeSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const ids = parsed.data.ids ?? [];
    const onlyUnanalyzed = !!parsed.data.onlyUnanalyzed;
    if (!storage.resolveAiProvider(tid, "osint_analysis")) return res.status(409).json({ detail: "No AI provider configured for osint_analysis. Configure one in AI Setup." });
    const label = ids.length > 0
      ? `OSINT AI analysis — ${ids.length} selected`
      : `OSINT AI analysis — ${onlyUnanalyzed ? "unanalyzed findings" : "all findings"}`;
    const job = runAiJob({
      tenantId: tid,
      kind: "osint_analysis",
      payload: parsed.data,
      createdBy: req.user?.email ?? null,
      targetLabel: label,
      targetUrl: "/#/osint",
      work: () => storage.runOsintAnalysis(tid, parsed.data),
      providerLabel: (out) => out.provider,
    });
    storage.appendAudit(tid, req.user?.email || "system", "osint.analyze.ai_job.start", job.jobId, { onlyUnanalyzed, idCount: ids.length });
    res.status(202).json(job);
  });
  app.post("/api/v1/osint/findings/email-draft", requireAuth, (req: AuthedRequest, res) => {
    const parsed = osintEmailDraftSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    if (!storage.resolveAiProvider(tid, "email_draft")) return res.status(409).json({ detail: "No AI provider configured for email_draft." });
    const job = runAiJob({
      tenantId: tid,
      kind: "email_draft_generation",
      payload: { ids: parsed.data.ids },
      createdBy: req.user?.email ?? null,
      targetLabel: `Email drafts — ${parsed.data.ids.length} finding${parsed.data.ids.length === 1 ? "" : "s"}`,
      targetUrl: "/#/osint?tab=drafts",
      work: () => storage.generateOsintEmail(tid, parsed.data.ids),
      providerLabel: (out) => out.provider,
    });
    res.status(202).json(job);
  });

  // ---- Hunt queries ----
  app.get("/api/v1/osint/hunt-queries", requireAuth, (req: AuthedRequest, res) => {
    res.json({ queries: storage.listHuntQueries(req.effectiveTenantId!) });
  });
  app.post("/api/v1/osint/hunt-queries", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = huntQueryCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const job = runAiJob({
      tenantId: tid,
      kind: "hunt_query_generation",
      payload: parsed.data,
      createdBy: req.user?.email ?? null,
      targetLabel: `Hunt query — ${parsed.data.findingIds.length} finding${parsed.data.findingIds.length === 1 ? "" : "s"}`,
      targetUrl: "/#/osint?tab=drafts",
      work: () => storage.generateHuntQueries(tid, {
        findingIds: parsed.data.findingIds,
        languages: parsed.data.languages,
        title: parsed.data.title,
        createdBy: req.user!.email,
      }),
      providerLabel: (out) => out.aiProviderLabel,
    });
    res.status(202).json(job);
  });

  // ---- v2.30.2 Detection Rule Studio ----
  // Closed-loop intel → versioned detection rule → per-SIEM deployment.
  // Push mode attempts the live SIEM integration call (currently a stub that
  // checks the connector is enabled + connectivity-tested); manual mode lets
  // the analyst flip status directly without an API call.
  app.get("/api/v1/detection-rules/_meta", requireAuth, (_req: AuthedRequest, res) => {
    res.json({
      siemTargets: SIEM_TARGETS,
      ruleStatuses: RULE_STATUSES,
      deploymentStatuses: DEPLOYMENT_STATUSES,
      deploymentModes: DEPLOYMENT_MODES,
      severities: RULE_SEVERITIES,
    });
  });
  app.get("/api/v1/detection-rules", requireAuth, (req: AuthedRequest, res) => {
    const status = typeof req.query.status === "string" ? (req.query.status as RuleStatus) : undefined;
    const filter = status && (RULE_STATUSES as readonly string[]).includes(status) ? { status } : undefined;
    res.json({ rules: storage.listDetectionRules(req.effectiveTenantId!, filter) });
  });
  app.post("/api/v1/detection-rules", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = detectionRuleCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const shouldGenerate = !!parsed.data.generate && !!parsed.data.findingIds?.length;
    if (shouldGenerate) {
      const tid = req.effectiveTenantId!;
      const job = runAiJob({
        tenantId: tid,
        kind: "detection_rule_generation",
        payload: parsed.data,
        createdBy: req.user?.email ?? null,
        targetLabel: `Detection rule — ${parsed.data.findingIds?.length ?? 0} finding${parsed.data.findingIds?.length === 1 ? "" : "s"}`,
        targetUrl: "/#/detection-rules",
        work: () => storage.createDetectionRule(tid, {
          title: parsed.data.title,
          description: parsed.data.description,
          findingIds: parsed.data.findingIds,
          languages: parsed.data.languages,
          severity: parsed.data.severity,
          affectedTech: parsed.data.affectedTech,
          threatActors: parsed.data.threatActors,
          generate: true,
          createdBy: req.user!.email,
        }),
        providerLabel: (out) => out.aiProviderLabel,
      });
      return res.status(202).json(job);
    }
    try {
      const out = await storage.createDetectionRule(req.effectiveTenantId!, {
        title: parsed.data.title,
        description: parsed.data.description,
        findingIds: parsed.data.findingIds,
        languages: parsed.data.languages,
        severity: parsed.data.severity,
        affectedTech: parsed.data.affectedTech,
        threatActors: parsed.data.threatActors,
        generate: parsed.data.generate,
        createdBy: req.user!.email,
      });
      res.status(201).json(out);
    } catch (e: any) {
      if (e && e.name === "LiveAiError") return next(e);
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });
  app.get("/api/v1/detection-rules/:rid", requireAuth, (req: AuthedRequest, res) => {
    const rule = storage.getDetectionRule(req.effectiveTenantId!, req.params.rid);
    if (!rule) return res.status(404).json({ detail: "detection rule not found" });
    res.json(rule);
  });
  app.patch("/api/v1/detection-rules/:rid", requireAuth, (req: AuthedRequest, res) => {
    const parsed = detectionRulePatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const updated = storage.updateDetectionRule(req.effectiveTenantId!, req.params.rid, {
      ...parsed.data,
      actor: req.user!.email,
    });
    if (!updated) return res.status(404).json({ detail: "detection rule not found" });
    res.json(updated);
  });
  app.delete("/api/v1/detection-rules/:rid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteDetectionRule(req.effectiveTenantId!, req.params.rid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "detection rule not found" });
    res.status(204).end();
  });
  app.post("/api/v1/detection-rules/:rid/deploy", requireAuth, (req: AuthedRequest, res) => {
    const parsed = detectionRuleDeploySchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const result = storage.deployDetectionRule(req.effectiveTenantId!, req.params.rid, {
      siemId: parsed.data.siemId,
      mode: parsed.data.mode,
      status: parsed.data.status,
      externalId: parsed.data.externalId,
      message: parsed.data.message,
      actor: req.user!.email,
    });
    if ("error" in result) {
      const code = result.error.includes("not found") ? 404 : 400;
      return res.status(code).json({ detail: result.error });
    }
    res.status(201).json(result);
  });

  // ============================================================================
  // v2.30.3 — Threat Actor Profiles (TAP)
  // ============================================================================
  app.get("/api/v1/threat-actors/_meta", requireAuth, (_req: AuthedRequest, res) => {
    res.json({
      statuses: TAP_STATUSES,
      actorTypes: ACTOR_TYPES,
      threatLevels: THREAT_LEVELS,
      tlpLevels: TLP_LEVELS,
      iocTypes: IOC_TYPES,
      detectionPriorities: DETECTION_PRIORITIES,
      ttpStatuses: TTP_STATUSES,
    });
  });

  app.get("/api/v1/threat-actors", requireAuth, (req: AuthedRequest, res) => {
    const statusRaw = typeof req.query.status === "string" ? req.query.status : undefined;
    const status: TapStatus | undefined =
      statusRaw && (TAP_STATUSES as readonly string[]).includes(statusRaw) ? (statusRaw as TapStatus) : undefined;
    const q = typeof req.query.q === "string" && req.query.q.trim().length > 0 ? req.query.q.trim() : undefined;
    const filter = status || q ? { status, q } : undefined;
    res.json({ actors: storage.listThreatActors(req.effectiveTenantId!, filter) });
  });

  app.post("/api/v1/threat-actors", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = threatActorCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    // Idempotent: if name already exists, return the existing actor unless the
    // caller explicitly asked for enrichment. In that case, enrich the existing
    // TAP inline so "Create + enrich" never silently skips the AI provider.
    const existing = storage.findThreatActorByName(tid, parsed.data.primaryName);
    if (existing) {
      if (parsed.data.enrich) {
        try {
          const enriched = await storage.enrichThreatActor(tid, existing.id, { force: false, actor: req.user!.email });
          return res.status(200).json({
            actor: enriched,
            status: "succeeded",
            enriched: true,
            existing: true,
            providerLabel: enriched.aiProviderLabel ?? null,
          });
        } catch (err) {
          return next(err);
        }
      }
      return res.status(200).json(existing);
    }
    const created = storage.createThreatActor(tid, {
      primaryName: parsed.data.primaryName,
      aliases: parsed.data.aliases,
      actorType: parsed.data.actorType,
      sponsorship: parsed.data.sponsorship,
      mitreGroupId: parsed.data.mitreGroupId ?? null,
      motivation: parsed.data.motivation,
      tlp: parsed.data.tlp,
      createdBy: req.user!.email,
    });
    if (parsed.data.enrich) {
      try {
        const enriched = await storage.enrichThreatActor(tid, created.id, { force: false, actor: req.user!.email });
        return res.status(201).json({
          actor: enriched,
          status: "succeeded",
          enriched: true,
          providerLabel: enriched.aiProviderLabel ?? null,
        });
      } catch (err) {
        return next(err);
      }
    }
    res.status(201).json(created);
  });

  app.get("/api/v1/threat-actors/portrait-generator/availability", requireAuth, async (_req: AuthedRequest, res) => {
    res.json(await getPortraitGeneratorAvailability());
  });

  app.get("/api/v1/threat-actors/:aid", requireAuth, (req: AuthedRequest, res) => {
    const actor = storage.getThreatActor(req.effectiveTenantId!, req.params.aid);
    if (!actor) return res.status(404).json({ detail: "threat actor not found" });
    res.json(actor);
  });

  app.get("/api/v1/threat-actors/:aid/full", requireAuth, (req: AuthedRequest, res) => {
    const full = storage.getFullThreatActor(req.effectiveTenantId!, req.params.aid);
    if (!full) return res.status(404).json({ detail: "threat actor not found" });
    res.json(full);
  });

  app.get("/api/v1/threat-actors/:aid/export.docx", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    try {
      const full = storage.getFullThreatActor(req.effectiveTenantId!, req.params.aid);
      if (!full) return res.status(404).json({ detail: "threat actor not found" });
      const buf = await buildThreatActorDocx(full);
      const safeName = full.primaryName.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60);
      const filename = `${full.profileId}_${safeName}.docx`;
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", String(buf.byteLength));
      res.end(buf);
    } catch (err) {
      next(err);
    }
  });

  app.patch("/api/v1/threat-actors/:aid", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const updated = storage.updateThreatActor(req.effectiveTenantId!, req.params.aid, {
      ...parsed.data,
      actor: req.user!.email,
    });
    if (!updated) return res.status(404).json({ detail: "threat actor not found" });
    res.json(updated);
  });

  app.delete("/api/v1/threat-actors/:aid", requireAuth, (req: AuthedRequest, res) => {
    const aid = req.params.aid;
    const ok = storage.deleteThreatActor(req.effectiveTenantId!, aid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "threat actor not found" });
    try {
      for (const f of readdirSync(PORTRAITS_DIR)) {
        if (f.startsWith(`${aid}.`)) {
          try { unlinkSync(join(PORTRAITS_DIR, f)); } catch { /* swallow */ }
        }
      }
    } catch { /* ok */ }
    res.status(204).end();
  });

  // v2.32 — AI-generated portrait per threat actor (lazy fire on first card view).
  // Returns 202 + current status when generation kicks off, 200 + url when already
  // ready, or 200 + url when generation finishes inline (it usually takes 15-40s).
  // The frontend hits this endpoint at most ONCE per actor (gated by portraitStatus)
  // and shows a soft spinner over the existing sigil fallback while it works.
  app.post("/api/v1/threat-actors/:aid/portrait", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    try {
      const tid = req.effectiveTenantId!;
      const aid = req.params.aid;
      const actor = storage.getThreatActor(tid, aid);
      if (!actor) return res.status(404).json({ detail: "threat actor not found" });
      // If we already have a ready portrait, short-circuit unless force=true.
      const force = String(req.query.force ?? "").toLowerCase() === "true";
      if (actor.portraitUrl && actor.portraitStatus === "ready" && !force) {
        return res.json({ portraitUrl: actor.portraitUrl, status: "ready" });
      }
      const url = await generateActorPortrait(tid, aid);
      return res.json({ portraitUrl: url, status: "ready" });
    } catch (err) {
      next(err);
    }
  });

  // v2.32.1 — manual portrait upload. Lets analysts replace the AI-generated
  // sigil with their own image (mugshot, ATT&CK actor card screenshot, etc).
  // Accepts JSON `{ fileName, contentBase64 }` to stay consistent with the
  // exercise PPTX upload pattern — no multer dependency needed.
  //
  // The image is stored at  data/portraits/<aid>.<ext>  (original extension
  // preserved so we don't re-encode). Any previously saved portrait file for
  // this actor (regardless of extension) is removed first so we never leak
  // stale bytes through aggressive HTTP caching. The persisted URL gets a
  // `?v=<timestamp>` cache-buster so the <img> in the SPA picks up the new
  // image immediately even though `/portraits/*` is served `immutable`.
  app.post("/api/v1/threat-actors/:aid/portrait/upload", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.effectiveTenantId!;
    const aid = req.params.aid;
    const actor = storage.getThreatActor(tid, aid);
    if (!actor) return res.status(404).json({ detail: "threat actor not found" });

    const fileName = typeof req.body?.fileName === "string" ? req.body.fileName : "";
    const b64 = typeof req.body?.contentBase64 === "string" ? req.body.contentBase64 : "";
    if (!fileName || !b64) return res.status(400).json({ detail: "fileName + contentBase64 required" });

    // Whitelist common image formats. Default to .png if extension is unknown
    // so the file is still routable through express.static's mime lookup.
    const extMatch = fileName.toLowerCase().match(/\.(png|jpe?g|webp|gif)$/);
    if (!extMatch) return res.status(400).json({ detail: "file must be PNG, JPEG, WebP, or GIF" });
    const ext = extMatch[1] === "jpeg" ? "jpg" : extMatch[1];

    const buf = Buffer.from(b64, "base64");
    if (buf.byteLength === 0)         return res.status(400).json({ detail: "empty file" });
    if (buf.byteLength > 5 * 1024 * 1024) return res.status(413).json({ detail: "file too large (5MB max)" });

    // Sanity-check magic bytes — lightweight content-sniff so a renamed .exe
    // can't slip past the extension check. We check the first 12 bytes against
    // the canonical signatures for each allowed format.
    const head = buf.subarray(0, 12);
    const looksLikeImage = (
      // PNG: 89 50 4E 47 0D 0A 1A 0A
      (head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4E && head[3] === 0x47) ||
      // JPEG: FF D8 FF
      (head[0] === 0xFF && head[1] === 0xD8 && head[2] === 0xFF) ||
      // WebP: RIFF....WEBP
      (head[0] === 0x52 && head[1] === 0x49 && head[2] === 0x46 && head[3] === 0x46 && head[8] === 0x57 && head[9] === 0x45 && head[10] === 0x42 && head[11] === 0x50) ||
      // GIF: GIF87a / GIF89a
      (head[0] === 0x47 && head[1] === 0x49 && head[2] === 0x46 && head[3] === 0x38)
    );
    if (!looksLikeImage) return res.status(400).json({ detail: "file does not look like a valid image" });

    try { mkdirSync(PORTRAITS_DIR, { recursive: true }); } catch { /* ok */ }

    // Remove any prior portrait file for this actor regardless of extension.
    try {
      for (const f of readdirSync(PORTRAITS_DIR)) {
        if (f.startsWith(`${aid}.`)) {
          try { unlinkSync(join(PORTRAITS_DIR, f)); } catch { /* swallow */ }
        }
      }
    } catch { /* directory may be empty */ }

    const target = join(PORTRAITS_DIR, `${aid}.${ext}`);
    writeFileSync(target, buf);

    // Cache-bust on every upload so the browser re-fetches even though the
    // immutable Cache-Control would otherwise pin the old bytes for 7 days.
    const publicUrl = `/portraits/${aid}.${ext}?v=${Date.now()}`;
    storage.setThreatActorPortrait(tid, aid, publicUrl);
    res.status(201).json({ portraitUrl: publicUrl, status: "ready", bytes: buf.byteLength });
  });

  // v2.32.1 — remove uploaded / generated portrait. Resets state so the lazy
  // IntersectionObserver may auto-regenerate on the next viewport entry.
  app.delete("/api/v1/threat-actors/:aid/portrait", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.effectiveTenantId!;
    const aid = req.params.aid;
    const actor = storage.getThreatActor(tid, aid);
    if (!actor) return res.status(404).json({ detail: "threat actor not found" });
    try {
      for (const f of readdirSync(PORTRAITS_DIR)) {
        if (f.startsWith(`${aid}.`)) {
          try { unlinkSync(join(PORTRAITS_DIR, f)); } catch { /* swallow */ }
        }
      }
    } catch { /* ok */ }
    storage.clearThreatActorPortrait(tid, aid);
    res.status(204).end();
  });

  // Serve generated portraits as static PNGs. Public-ish: anyone with the
  // direct URL can fetch (they're already gated by needing the actor id and a
  // valid session to retrieve the URL in the first place). Aggressive cache
  // because URLs are content-addressed by actor id and only change on re-gen.
  app.use("/portraits", express.static(PORTRAITS_DIR, {
    maxAge: "7d",
    setHeaders: (res) => {
      res.setHeader("Cache-Control", "public, max-age=604800, immutable");
    },
  }));
  // Backward-compatible alias for deployments or browser cache entries that
  // reference the physical data path. The DB persists /portraits/*, but this
  // keeps /data/portraits/* from rendering as broken images after exports.
  app.use("/data/portraits", express.static(PORTRAITS_DIR, {
    maxAge: "7d",
    setHeaders: (res) => {
      res.setHeader("Cache-Control", "public, max-age=604800, immutable");
    },
  }));

  // Phase 1 — real DNSTwist landing-page screenshots (Playwright PNGs).
  // Served at /dnstwist-screenshots/<domain>.png. Cards include a ?v=<ts>
  // cache-bust so re-scans of the same domain are picked up immediately,
  // hence we don't mark these as immutable.
  app.use("/dnstwist-screenshots", express.static(DNSTWIST_SCREENSHOTS_DIR, {
    maxAge: "1h",
    setHeaders: (res) => {
      res.setHeader("Cache-Control", "public, max-age=3600");
    },
  }));

  // v2.30.6 — accepts an optional providerId override for one-off re-enrich
  // with a different model (e.g. DeepSeek vs Perplexity).
  app.post("/api/v1/threat-actors/:aid/enrich", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorEnrichSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const aid = req.params.aid;
    const head = storage.getThreatActor(tid, aid);
    if (!head) return res.status(404).json({ detail: "threat actor not found" });
    const job = runAiJob({
      tenantId: tid,
      kind: "threat_actor_enrichment",
      payload: {
        actorId: aid,
        force: parsed.data.force,
        providerId: parsed.data.providerId ?? null,
      },
      createdBy: req.user?.email ?? null,
      targetLabel: `TAP re-analysis — ${head.primaryName}`,
      targetUrl: `/#/threat-actors?focus=${encodeURIComponent(aid)}`,
      work: () => storage.enrichThreatActor(tid, aid, {
        force: parsed.data.force,
        actor: req.user!.email,
        providerId: parsed.data.providerId ?? null,
      }),
      providerLabel: (out) => out.aiProviderLabel ?? null,
    });
    res.status(202).json(job);
  });

  // ---- Sub-resource: TTPs ----
  app.post("/api/v1/threat-actors/:aid/ttps", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorTtpSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorTtp(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });
  app.delete("/api/v1/threat-actors/:aid/ttps/:ttpId", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorTtp(req.effectiveTenantId!, req.params.aid, req.params.ttpId, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "ttp not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: Tools ----
  app.post("/api/v1/threat-actors/:aid/tools", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorToolSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorTool(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });
  app.delete("/api/v1/threat-actors/:aid/tools/:toolId", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorTool(req.effectiveTenantId!, req.params.aid, req.params.toolId, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "tool not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: Campaigns ----
  app.post("/api/v1/threat-actors/:aid/campaigns", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorCampaignSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorCampaign(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });
  app.delete("/api/v1/threat-actors/:aid/campaigns/:cid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorCampaign(req.effectiveTenantId!, req.params.aid, req.params.cid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "campaign not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: IOCs ----
  app.post("/api/v1/threat-actors/:aid/iocs", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorIocSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorIoc(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });
  app.delete("/api/v1/threat-actors/:aid/iocs/:iid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorIoc(req.effectiveTenantId!, req.params.aid, req.params.iid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "ioc not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: References ----
  app.post("/api/v1/threat-actors/:aid/references", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorReferenceSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorReference(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });
  app.delete("/api/v1/threat-actors/:aid/references/:rid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorReference(req.effectiveTenantId!, req.params.aid, req.params.rid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "reference not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: Detection rule links (bridge for pivots) ----
  app.post("/api/v1/threat-actors/:aid/rule-links", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorRuleLinkSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.linkThreatActorDetectionRule(
        req.effectiveTenantId!, req.params.aid,
        { ruleId: parsed.data.ruleId, priority: parsed.data.priority, notes: parsed.data.notes ?? null },
        req.user!.email,
      );
      res.status(201).json(out);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });
  app.delete("/api/v1/threat-actors/:aid/rule-links/:ruleId", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.unlinkThreatActorDetectionRule(req.effectiveTenantId!, req.params.aid, req.params.ruleId, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "rule link not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: Tenant relevance tagging (v2.30.5) ----
  // Lets analysts and the AI mark which clients are relevant to a given
  // threat actor ("targeted", "sector-match", or "watching").

  // Batch summary used by the list/kanban views: returns every tenant tag
  // for every actor owned by the effective tenant. Keyed by actor_id on the
  // client so we never make N+1 calls.
  app.get("/api/v1/threat-actors-tenant-tags", requireAuth, (req: AuthedRequest, res) => {
    const tags = storage.listAllThreatActorTenants(req.effectiveTenantId!);
    const available = storage.listAvailableTenantsForTagging(req.effectiveTenantId!);
    res.json({ tags, available, relevances: TENANT_RELEVANCES });
  });

  app.get("/api/v1/threat-actors/:aid/tenants", requireAuth, (req: AuthedRequest, res) => {
    const head = storage.getThreatActor(req.effectiveTenantId!, req.params.aid);
    if (!head) return res.status(404).json({ detail: "threat actor not found" });
    const tags = storage.listThreatActorTenants(req.effectiveTenantId!, req.params.aid);
    const available = storage.listAvailableTenantsForTagging(req.effectiveTenantId!);
    res.json({ tags, available, relevances: TENANT_RELEVANCES });
  });

  app.post("/api/v1/threat-actors/:aid/tenants", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorTenantSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const head = storage.getThreatActor(req.effectiveTenantId!, req.params.aid);
    if (!head) return res.status(404).json({ detail: "threat actor not found" });
    try {
      const out = storage.addThreatActorTenant(
        req.effectiveTenantId!, req.params.aid,
        { tenantId: parsed.data.tenantId, relevance: parsed.data.relevance, rationale: parsed.data.rationale ?? null },
        { taggedBy: req.user!.email, taggedByAi: false },
      );
      res.status(201).json(out);
    } catch (e: any) {
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });

  app.patch("/api/v1/threat-actors/:aid/tenants/:tagId", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorTenantPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const out = storage.patchThreatActorTenant(
      req.effectiveTenantId!, req.params.aid, req.params.tagId,
      { relevance: parsed.data.relevance, rationale: parsed.data.rationale ?? null },
    );
    if (!out) return res.status(404).json({ detail: "tenant tag not found" });
    res.json(out);
  });

  app.delete("/api/v1/threat-actors/:aid/tenants/:tagId", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.removeThreatActorTenant(req.effectiveTenantId!, req.params.aid, req.params.tagId);
    if (!ok) return res.status(404).json({ detail: "tenant tag not found" });
    res.status(204).end();
  });

  // ---- v2.15 OSINT AI Chatbot ----
  // Tier-bucketed CIRT triage report over findings in a chosen day range.
  //
  // v2.27 — The DeepSeek v4-pro reasoning model can take 4+ minutes to
  // complete a triage over hundreds of findings. The Perplexity sites edge
  // proxy aborts inflight requests around the ~100s mark, so a synchronous
  // POST/await always surfaces as "Failed to fetch" in the browser even
  // when the server finishes successfully. This endpoint now enqueues an
  // async AI job and returns its id immediately; the client polls GET
  // /api/v1/osint/ai-jobs/:id until status is terminal.
  app.post("/api/v1/osint/chat/triage", requireAuth, (req: AuthedRequest, res) => {
    const range = String((req.body && req.body.range) || "1d") as ChatRangeKey;
    const allowed: ChatRangeKey[] = ["1d", "7d", "1m", "1q", "1y", "all"];
    if (!allowed.includes(range)) return res.status(400).json({ detail: `range must be one of ${allowed.join(", ")}` });
    const findingIds = Array.isArray(req.body?.findingIds)
      ? (req.body.findingIds as any[]).filter((x) => typeof x === "string")
      : undefined;
    const headerTenant = String(req.header("X-Tenant-Id") || "");
    const crossTenant = req.body?.crossTenant === true || headerTenant === "__global__";
    const tenantId = req.effectiveTenantId!;
    const jobId = storage.createAiJob({
      tenantId,
      kind: "chat_triage",
      payload: { range, findingIds, crossTenant },
      createdBy: req.user?.email ?? null,
      targetLabel: `CIRT triage — ${range}${crossTenant ? " (all tenants)" : ""}`,
      targetUrl: null,
    });
    const targetUrl = `/#/osint?ai=triage&job=${encodeURIComponent(jobId)}`;
    storage.updateAiJobTarget(jobId, { targetUrl });
    setImmediate(async () => {
      storage.markAiJobRunning(jobId);
      const hb = setInterval(() => { try { storage.setAiJobHeartbeat(jobId); } catch { /* ignore */ } }, 30000);
      try {
        const out = await runChatTriage(storage, { tenantId, range, findingIds, crossTenant });
        storage.completeAiJob(jobId, out, (out as any)?.providerLabel ?? null);
      } catch (e: any) {
        storage.failAiJob(jobId, e);
      } finally {
        clearInterval(hb);
      }
    });
    res.status(202).json({ jobId, status: "queued", kind: "chat_triage", targetLabel: `CIRT triage — ${range}${crossTenant ? " (all tenants)" : ""}`, targetUrl });
  });
  // v2.17 — Free-form chat with the integrated AI provider. The floating
  // AI assistant uses this for back-and-forth Q&A scoped to the current
  // OSINT findings.
  app.post("/api/v1/osint/chat/converse", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    const body = req.body || {};
    const messages = Array.isArray(body.messages) ? body.messages : [];
    const contextFindingIds = Array.isArray(body.contextFindingIds) ? body.contextFindingIds.filter((x: any) => typeof x === "string") : [];
    if (messages.length === 0) return res.status(400).json({ detail: "messages required" });
    try {
      const out = await runChatConverse(storage, { tenantId: req.effectiveTenantId!, messages, contextFindingIds });
      res.json(out);
    } catch (e: any) {
      if (e instanceof ChatLiveAiError) {
        return res.status(502).json({ detail: e.message, providerLabel: e.providerLabel, aiDiagnostic: e.diagnostic });
      }
      if (e && e.name === "LiveAiError") return next(e);
      res.status(500).json({ detail: String(e?.message ?? e) });
    }
  });
  // Per-finding deep CIRT analysis on a hand-picked subset; returns structured JSON
  // plus a downloadable HTML report.
  //
  // v2.27 — Same async-job pattern as chat/triage: deep dive over 5-20
  // findings routinely exceeds the proxy timeout, so the POST enqueues a
  // job and the UI polls GET /api/v1/osint/ai-jobs/:id.
  app.post("/api/v1/osint/chat/deep-dive", requireAuth, (req: AuthedRequest, res) => {
    const findingIds = Array.isArray(req.body?.findingIds) ? (req.body.findingIds as string[]).filter((x) => typeof x === "string") : [];
    if (findingIds.length === 0) return res.status(400).json({ detail: "findingIds required (non-empty array)" });
    if (findingIds.length > 20) return res.status(400).json({ detail: "max 20 findings per deep-dive request" });
    const headerTenant = String(req.header("X-Tenant-Id") || "");
    const crossTenant = req.body?.crossTenant === true || headerTenant === "__global__";
    const tenantId = req.effectiveTenantId!;
    const jobId = storage.createAiJob({
      tenantId,
      kind: "chat_deep_dive",
      payload: { findingIds, crossTenant },
      createdBy: req.user?.email ?? null,
      targetLabel: `CIRT deep-dive — ${findingIds.length} finding${findingIds.length === 1 ? "" : "s"}`,
      targetUrl: null,
    });
    const targetUrl = `/#/osint?ai=deep-dive&job=${encodeURIComponent(jobId)}`;
    storage.updateAiJobTarget(jobId, { targetUrl });
    setImmediate(async () => {
      storage.markAiJobRunning(jobId);
      const hb = setInterval(() => { try { storage.setAiJobHeartbeat(jobId); } catch { /* ignore */ } }, 30000);
      try {
        const out = await runChatDeepDive(storage, { tenantId, findingIds, crossTenant });
        storage.completeAiJob(jobId, out, (out as any)?.providerLabel ?? null);
      } catch (e: any) {
        storage.failAiJob(jobId, e);
      } finally {
        clearInterval(hb);
      }
    });
    res.status(202).json({ jobId, status: "queued", kind: "chat_deep_dive", targetLabel: `CIRT deep-dive — ${findingIds.length} finding${findingIds.length === 1 ? "" : "s"}`, targetUrl });
  });

  // v2.27 — Async AI job polling endpoint. Returns the job's current status
  // and (when terminal) result or error. By default the (potentially massive)
  // result payload is INCLUDED; use the /summary variant or /active list to
  // get a cheap response without the full body.
  app.get("/api/v1/osint/ai-jobs/history", requireAuth, (req: AuthedRequest, res) => {
    const max = Math.max(1, Math.min(100, parseInt(String(req.query.max || "20"), 10) || 20));
    const jobs = storage.listCirtAiJobs(req.effectiveTenantId!, { max });
    res.json({ jobs });
  });

  app.get("/api/v1/osint/ai-jobs/:id", requireAuth, (req: AuthedRequest, res) => {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ detail: "job id required" });
    const job = storage.getAiJob(req.effectiveTenantId!, id);
    if (!job) return res.status(404).json({ detail: "job not found" });
    res.json(job);
  });

  // v2.30.5 — generic AI-job endpoints used by the global notification tray.
  // These are NOT scoped to OSINT chat — they cover every kind (TAP enrich,
  // detection rule synthesis, OSINT analysis, etc.) so a single React provider
  // can monitor all background work in one place.
  app.get("/api/v1/ai-jobs/active", requireAuth, (req: AuthedRequest, res) => {
    const lookback = Math.max(1, Math.min(180, parseInt(String(req.query.lookbackMinutes || "30"), 10) || 30));
    const max = Math.max(1, Math.min(50, parseInt(String(req.query.max || "20"), 10) || 20));
    const jobs = storage.listActiveAiJobs(req.effectiveTenantId!, { lookbackMinutes: lookback, max });
    res.json({ jobs });
  });
  // Cheap variant of /ai-jobs/:id that omits the (potentially massive) result body.
  app.get("/api/v1/ai-jobs/:id", requireAuth, (req: AuthedRequest, res) => {
    const job = storage.getAiJob(req.effectiveTenantId!, String(req.params.id || ""), { includeResult: false });
    if (!job) return res.status(404).json({ detail: "job not found" });
    res.json(job);
  });
  // Full payload, including the result body. Used when the user opens a
  // completed job from the tray and we need the entire response. Stream-friendly
  // — SQLite TEXT has no size limit so a multi-megabyte JSON survives intact.
  app.get("/api/v1/ai-jobs/:id/full", requireAuth, (req: AuthedRequest, res) => {
    const job = storage.getAiJob(req.effectiveTenantId!, String(req.params.id || ""), { includeResult: true });
    if (!job) return res.status(404).json({ detail: "job not found" });
    res.json(job);
  });

  // ---------------------------------------------------------------------
  // v2.16 — OSINT automation: tenant settings + manual triggers + cache
  // status. Lets operators flip on "fetch every 60 min + analyze every new
  // intel in the background" so deep dive becomes instant retrieval.
  // ---------------------------------------------------------------------
  app.get("/api/v1/osint/automation/settings", requireAuth, (req: AuthedRequest, res) => {
    const settings = storage.getOsintAutomationSettings(req.effectiveTenantId!);
    const queue = storage.getOsintCirtQueueStats(req.effectiveTenantId!);
    res.json({ settings, queue });
  });

  app.patch("/api/v1/osint/automation/settings", requireAuth, (req: AuthedRequest, res) => {
    const body = req.body || {};
    const patch: any = {};
    if (typeof body.autoFetchEnabled === "boolean") patch.autoFetchEnabled = body.autoFetchEnabled;
    if (typeof body.fetchIntervalMin === "number") patch.fetchIntervalMin = body.fetchIntervalMin;
    if (typeof body.autoAnalyzeEnabled === "boolean") patch.autoAnalyzeEnabled = body.autoAnalyzeEnabled;
    if (typeof body.analyzeConcurrency === "number") patch.analyzeConcurrency = body.analyzeConcurrency;
    if (typeof body.analyzeMaxPerTick === "number") patch.analyzeMaxPerTick = body.analyzeMaxPerTick;
    const updated = storage.updateOsintAutomationSettings(req.effectiveTenantId!, patch);
    const queue = storage.getOsintCirtQueueStats(req.effectiveTenantId!);
    res.json({ settings: updated, queue });
  });

  app.post("/api/v1/osint/automation/fetch-now", requireAuth, async (req: AuthedRequest, res) => {
    // Fire-and-forget; client polls /settings for status.
    runAutoFetchNow(req.effectiveTenantId!).catch((e) =>
      console.error("[osint-bg] manual fetch:", e),
    );
    res.json({ status: "started" });
  });

  app.post("/api/v1/osint/automation/analyze-now", requireAuth, async (req: AuthedRequest, res) => {
    // Fire-and-forget; client polls /settings for status and individual
    // findings via the cache endpoint below.
    runAutoAnalyzeNow(req.effectiveTenantId!).catch((e) =>
      console.error("[osint-bg] manual analyze:", e),
    );
    res.json({ status: "started" });
  });

  app.post("/api/v1/osint/automation/reset-cache", requireAuth, (req: AuthedRequest, res) => {
    const failedOnly = !!(req.body && req.body.failedOnly);
    const out = storage.resetOsintCirtCache(req.effectiveTenantId!, { failedOnly });
    res.json(out);
  });

  app.get("/api/v1/osint/findings/:fid/cirt-cache", requireAuth, (req: AuthedRequest, res) => {
    const cache = storage.getOsintFindingCache(req.effectiveTenantId!, req.params.fid);
    if (!cache) return res.status(404).json({ detail: "not found" });
    res.json(cache);
  });

  // ---- Threat landscape ----
  app.get("/api/v1/threat-landscape", requireAuth, (req: AuthedRequest, res) => {
    res.json({ reports: storage.listThreatLandscapes(req.effectiveTenantId!) });
  });
  app.get("/api/v1/threat-landscape/:rid", requireAuth, (req: AuthedRequest, res) => {
    const r = storage.getThreatLandscape(req.effectiveTenantId!, req.params.rid);
    if (!r) return res.status(404).json({ detail: "not found" });
    res.json(r);
  });
  app.post("/api/v1/threat-landscape", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatLandscapeGenerateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    res.status(201).json(storage.generateThreatLandscape(req.effectiveTenantId!, {
      title: parsed.data.title,
      createdBy: req.user!.email,
    }));
  });

  // ---- Coverage Radar + CTI exchange ----
  app.get("/api/v1/coverage/attack", requireAuth, (req: AuthedRequest, res) => {
    const global = req.header("x-tenant-id") === "__global__";
    res.json(storage.getAttackCoverage(req.effectiveTenantId!, {
      global,
      role: req.user!.role,
    }));
  });

  function stixPreview(bundle: any, findingCount: number) {
    const objects = Array.isArray(bundle?.objects) ? bundle.objects : [];
    const objectCounts: Record<string, number> = {};
    const ids = new Set<string>();
    const errors: string[] = [];
    const warnings: string[] = [];
    if (bundle?.type !== "bundle") errors.push("Root object must be a STIX bundle.");
    if (!/^bundle--/.test(String(bundle?.id ?? ""))) errors.push("Bundle id must use bundle-- prefix.");
    for (const obj of objects) if (obj?.id) ids.add(obj.id);
    for (const obj of objects) {
      const type = String(obj?.type ?? "unknown");
      objectCounts[type] = (objectCounts[type] ?? 0) + 1;
      if (!obj?.id) errors.push(`${type} object is missing id.`);
      if (!obj?.spec_version && type !== "bundle") warnings.push(`${type} ${obj?.id ?? "(no id)"} is missing spec_version.`);
      if (type === "indicator" && !obj?.pattern) errors.push(`Indicator ${obj?.id ?? "(no id)"} is missing pattern.`);
      if (type === "report" && Array.isArray(obj.object_refs)) {
        for (const ref of obj.object_refs) {
          if (!ids.has(ref)) warnings.push(`Report ${obj.id} references an object that is not present in the bundle: ${ref}`);
        }
      }
    }
    const duplicateIds = objects.map((obj: any) => obj?.id).filter(Boolean).filter((id: string, ix: number, arr: string[]) => arr.indexOf(id) !== ix);
    for (const dup of Array.from(new Set(duplicateIds))) errors.push(`Duplicate STIX id: ${dup}`);
    if (objects.length === 0) warnings.push("Bundle contains no STIX objects.");
    if ((objectCounts.indicator ?? 0) === 0) warnings.push("No indicators will be exported. Select findings with IoCs or enrich the intel first.");
    return {
      valid: errors.length === 0,
      objectCount: objects.length,
      objectCounts,
      indicatorCount: objectCounts.indicator ?? 0,
      reportCount: objectCounts.report ?? 0,
      attackPatternCount: objectCounts["attack-pattern"] ?? 0,
      relationshipCount: objectCounts.relationship ?? 0,
      findingCount,
      warnings,
      errors,
    };
  }

  app.get("/api/v1/exchange/stix/preview", requireAuth, (req: AuthedRequest, res) => {
    const raw = req.query.findingIds;
    const findingIds = !raw
      ? undefined
      : Array.isArray(raw)
        ? raw.map(String)
        : String(raw).split(",").map((s) => s.trim()).filter(Boolean);
    const bundle = storage.exportStixBundle(req.effectiveTenantId!, {
      investigationId: req.query.investigationId ? String(req.query.investigationId) : undefined,
      actorId: req.query.actorId ? String(req.query.actorId) : undefined,
      findingIds,
      since: req.query.since ? String(req.query.since) : undefined,
      role: req.user!.role,
      actorEmail: req.user!.email,
    });
    res.json(stixPreview(bundle, findingIds?.length ?? 0));
  });

  app.get("/api/v1/exchange/stix/export", requireAuth, (req: AuthedRequest, res) => {
    const raw = req.query.findingIds;
    const findingIds = !raw
      ? undefined
      : Array.isArray(raw)
        ? raw.map(String)
        : String(raw).split(",").map((s) => s.trim()).filter(Boolean);
    const bundle = storage.exportStixBundle(req.effectiveTenantId!, {
      investigationId: req.query.investigationId ? String(req.query.investigationId) : undefined,
      actorId: req.query.actorId ? String(req.query.actorId) : undefined,
      findingIds,
      since: req.query.since ? String(req.query.since) : undefined,
      role: req.user!.role,
      actorEmail: req.user!.email,
    });
    const stamp = new Date().toISOString().slice(0, 10);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename=\"optrasight-stix-${stamp}.json\"`);
    res.json(bundle);
  });

  // ---- Global (cross-tenant) views — admin only ----
  function requireAdmin(req: AuthedRequest, res: Response): boolean {
    if (req.user?.role !== "admin") {
      res.status(403).json({ detail: "admin role required" });
      return false;
    }
    return true;
  }

  app.get("/api/v1/global/groups", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    res.json(storage.listGlobalGroups());
  });

  app.get("/api/v1/global/osint/findings", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const dimensionRaw = String(req.query.dimension ?? "client");
    const dimension = (["client", "industry", "geo"] as const).includes(dimensionRaw as any)
      ? (dimensionRaw as "client" | "industry" | "geo")
      : "client";
    const idsRaw = req.query.ids;
    const ids = !idsRaw
      ? []
      : Array.isArray(idsRaw)
        ? idsRaw.map((x) => String(x))
        : String(idsRaw).split(",").map((s) => s.trim()).filter(Boolean);
    const dedupRaw = req.query.dedup;
    const dedup = dedupRaw === "1" || dedupRaw === "true" || dedupRaw === "yes";
    const findings = storage.listGlobalOsintFindings({
      dimension,
      ids,
      severity: req.query.severity ? String(req.query.severity) : undefined,
      status: req.query.status ? String(req.query.status) : undefined,
      tech: req.query.tech ? String(req.query.tech) : undefined,
      sourceId: req.query.sourceId ? String(req.query.sourceId) : undefined,
      category: req.query.category ? String(req.query.category) : undefined,
      limit: req.query.limit ? Number(req.query.limit) : undefined,
      dedup,
    });
    res.json({ findings, dedup });
  });

  app.get("/api/v1/global/osint/sources", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const dimensionRaw = String(req.query.dimension ?? "client");
    const dimension = (["client", "industry", "geo"] as const).includes(dimensionRaw as any)
      ? (dimensionRaw as "client" | "industry" | "geo")
      : "client";
    const idsRaw = req.query.ids;
    const ids = !idsRaw
      ? []
      : Array.isArray(idsRaw)
        ? idsRaw.map((x) => String(x))
        : String(idsRaw).split(",").map((s) => s.trim()).filter(Boolean);
    const sources = storage.listGlobalOsintSourceRows({
      dimension, ids,
      category: req.query.category ? String(req.query.category) : undefined,
      q: req.query.q ? String(req.query.q) : undefined,
    });
    res.json({ sources, summary: storage.countOsintSourcesByCategory() });
  });

  app.get("/api/v1/global/osint/drafts", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const dimensionRaw = String(req.query.dimension ?? "client");
    const dimension = (["client", "industry", "geo"] as const).includes(dimensionRaw as any)
      ? (dimensionRaw as "client" | "industry" | "geo")
      : "client";
    const idsRaw = req.query.ids;
    const ids = !idsRaw
      ? []
      : Array.isArray(idsRaw)
        ? idsRaw.map((x) => String(x))
        : String(idsRaw).split(",").map((s) => s.trim()).filter(Boolean);
    res.json(storage.listGlobalDrafts({ dimension, ids }));
  });

  app.post("/api/v1/global/osint/overview", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const parsed = osintOverviewSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    // For global routes, force scope to non-client unless explicitly set; client scope here doesn't really apply.
    const scope = parsed.data.scope === "client" ? "global" : parsed.data.scope;
    try {
      const result = storage.generateOsintOverview({
        persona: parsed.data.persona,
        category: parsed.data.category,
        severity: parsed.data.severity,
        scope,
        scopeIds: parsed.data.scopeIds,
      });
      res.json(result);
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message || e) });
    }
  });

  app.post("/api/v1/global/threat-landscape", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const body = (req.body || {}) as { dimension?: string; ids?: string[]; title?: string };
    const dimension = (["client", "industry", "geo"] as const).includes(body.dimension as any)
      ? (body.dimension as "client" | "industry" | "geo")
      : null;
    if (!dimension) return res.status(400).json({ detail: "dimension must be 'client' | 'industry' | 'geo'" });
    const ids = Array.isArray(body.ids) ? body.ids.map(String) : [];
    if (ids.length === 0) return res.status(400).json({ detail: "ids must contain at least one group id" });
    const reports = storage.generateGlobalThreatLandscape({
      dimension,
      ids,
      title: body.title,
      createdBy: req.user!.email,
    });
    res.status(201).json({ reports });
  });

  app.get("/api/v1/global/threat-landscape", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const dim = req.query.dimension ? String(req.query.dimension) : undefined;
    res.json({ reports: storage.listGlobalThreatLandscapes(dim ? { dimension: dim } : undefined) });
  });

  // ---- Audit log ----
  app.get("/api/v1/audit", requireAuth, (req: AuthedRequest, res) => {
    res.json({ entries: storage.listAudit(req.effectiveTenantId!, { limit: 200 }) });
  });

  app.get("/api/v1/operations/audit", requireAuth, (req: AuthedRequest, res) => {
    const jobs = storage.listOperationsJobs(req.effectiveTenantId!, { max: 160 });
    const active = jobs.filter((j: any) => j.status === "queued" || j.status === "running");
    const failed = jobs.filter((j: any) => j.status === "failed" || j.errorMessage);
    res.json({
      summary: {
        active: active.length,
        failed: failed.length,
        completed: jobs.filter((j: any) => j.status === "completed" || j.status === "done" || j.status === "succeeded").length,
        cancelled: jobs.filter((j: any) => j.status === "cancelled").length,
      },
      jobs,
      auditEntries: storage.listAudit(req.effectiveTenantId!, { limit: 200 }),
      globalIngest: req.user?.role === "admin" ? {
        source: "global_ingest",
        id: "global-osint-ingest",
        kind: "osint_global_ingest",
        label: "Global OSINT ingest",
        status: globalOsintRun.busy ? "running" : (globalOsintRun.error ? "failed" : globalOsintRun.finishedAt ? "done" : "idle"),
        startedAt: globalOsintRun.startedAt,
        finishedAt: globalOsintRun.finishedAt,
        errorMessage: globalOsintRun.error,
        summary: globalOsintRun.summary,
        cancellable: false,
      } : null,
    });
  });

  app.post("/api/v1/operations/jobs/cancel-running", requireAuth, (req: AuthedRequest, res) => {
    const results = storage.cancelAllOperationsJobs(req.effectiveTenantId!, req.user?.email || "operator");
    storage.appendAudit(req.effectiveTenantId!, req.user?.email || "operator", "operations.jobs.cancel_all", null, {
      count: results.filter((r: any) => r.ok).length,
      results,
    });
    res.status(202).json({ results });
  });

  app.post("/api/v1/operations/jobs/:source/:id/cancel", requireAuth, (req: AuthedRequest, res) => {
    const source = String(req.params.source || "");
    const id = String(req.params.id || "");
    const result = storage.cancelOperationsJob(req.effectiveTenantId!, source, id, req.user?.email || "operator");
    if (result.status === "not_found") return res.status(404).json({ detail: result.message || "not found", status: result.status });
    if (!result.ok) return res.status(409).json({ detail: result.message || "not cancellable", status: result.status });
    storage.appendAudit(req.effectiveTenantId!, req.user?.email || "operator", `operations.job.cancel.${source}`, id, result);
    res.status(202).json(result);
  });

  // ---- deterministic SVG screenshots for malicious-site candidates ----
  // Public endpoint (no auth) so <img src="..."> works without a bearer token.
  // Renders a browser-chrome-styled SVG that simulates the captured landing page.
  app.get("/api/v1/malicious-site-scanner/screenshot/:domain.svg", (req, res) => {
    const domain = String(req.params.domain || "").toLowerCase().replace(/[^a-z0-9.\-]/g, "");
    const verdict = String(req.query.verdict || "benign").toLowerCase();
    const brand = String(req.query.brand || domain.split(".")[0] || "site").slice(0, 32);
    // Deterministic hash for layout variation
    function djb2(s: string) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return Math.abs(h); }
    const h = djb2(domain);
    // Verdict-tinted accent colour
    const palette: Record<string, { hero: string; band: string; cta: string; tag: string; tagBg: string; chrome: string }> = {
      phishing:      { hero: "#1f0f12", band: "#dc2626", cta: "#dc2626", tag: "#fecaca", tagBg: "#7f1d1d", chrome: "#fee2e2" },
      impersonation: { hero: "#1f160b", band: "#ea580c", cta: "#ea580c", tag: "#fed7aa", tagBg: "#7c2d12", chrome: "#ffedd5" },
      parked:        { hero: "#1c1917", band: "#a8a29e", cta: "#78716c", tag: "#e7e5e4", tagBg: "#44403c", chrome: "#f5f5f4" },
      benign:        { hero: "#0b1220", band: "#0ea5e9", cta: "#0ea5e9", tag: "#bae6fd", tagBg: "#075985", chrome: "#e0f2fe" },
      unreachable:   { hero: "#0f172a", band: "#475569", cta: "#475569", tag: "#cbd5e1", tagBg: "#1e293b", chrome: "#e2e8f0" },
    };
    const p = palette[verdict] || palette.benign;
    const layout = h % 3; // 0=login, 1=invoice, 2=parked-style
    const initials = brand.replace(/[^a-z0-9]/g, "").slice(0, 2).toUpperCase() || "BG";
    const titleText = layout === 0
      ? `Sign in to ${brand}`
      : layout === 1
        ? `Invoice #${(h % 90000 + 10000)} — ${brand}`
        : `${brand} — future home of something new`;
    const subtitle = layout === 0
      ? "Use your work or school account to continue"
      : layout === 1
        ? "Please review and approve the attached document"
        : "This domain has been registered. Inquire within.";
    const ctaLabel = layout === 0 ? "Sign in" : layout === 1 ? "Open document" : "Buy this domain";
    // Address bar URL with verdict-themed protocol indicator
    const protoIcon = verdict === "phishing" || verdict === "impersonation"
      ? "<text x='32' y='95' font-family='ui-monospace,monospace' font-size='14' fill='#dc2626'>\u26a0</text>"
      : "<text x='32' y='95' font-family='ui-monospace,monospace' font-size='14' fill='#16a34a'>\u25cf</text>";
    const showLockBar = layout === 0;

    const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 500" width="800" height="500" role="img" aria-label="Screenshot of ${domain}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${p.hero}"/>
      <stop offset="100%" stop-color="#000"/>
    </linearGradient>
    <linearGradient id="card" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#ffffff"/>
      <stop offset="100%" stop-color="#f8fafc"/>
    </linearGradient>
  </defs>
  <!-- browser chrome -->
  <rect x="0" y="0" width="800" height="500" fill="#0f172a"/>
  <rect x="0" y="0" width="800" height="72" fill="#1e293b"/>
  <circle cx="22" cy="22" r="6" fill="#ef4444"/>
  <circle cx="42" cy="22" r="6" fill="#f59e0b"/>
  <circle cx="62" cy="22" r="6" fill="#10b981"/>
  <rect x="22" y="42" width="120" height="24" rx="4" fill="#0f172a"/>
  <text x="34" y="58" font-family="ui-sans-serif,system-ui" font-size="11" fill="#94a3b8">${escapeXml(domain)}</text>
  <!-- address bar -->
  <rect x="22" y="82" width="756" height="28" rx="14" fill="${p.chrome}"/>
  ${protoIcon}
  <text x="54" y="100" font-family="ui-monospace,monospace" font-size="12" fill="#0f172a">https://${escapeXml(domain)}/${layout === 0 ? "login" : layout === 1 ? "invoice/view" : ""}</text>
  <!-- viewport -->
  <rect x="0" y="120" width="800" height="380" fill="url(#bg)"/>
  ${layout === 2 ? renderParked(p, brand, domain) : renderLoginOrInvoice(p, brand, initials, titleText, subtitle, ctaLabel, showLockBar)}
  <!-- verdict pill -->
  <g transform="translate(620,138)">
    <rect x="0" y="0" width="160" height="28" rx="14" fill="${p.tagBg}"/>
    <text x="80" y="19" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="12" font-weight="700" fill="${p.tag}" letter-spacing="0.5">${verdict.toUpperCase()}</text>
  </g>
  <text x="22" y="492" font-family="ui-sans-serif,system-ui" font-size="10" fill="#94a3b8">OptraSight · simulated capture · ${new Date().toISOString().slice(0,10)}</text>
</svg>`;
    res.set("Content-Type", "image/svg+xml; charset=utf-8");
    res.set("Cache-Control", "public, max-age=86400");
    res.send(svg);
  });

  // ===========================================================================
  // v2.31.0 — Tabletop Exercise (TTX) routes
  // ===========================================================================

  // ---- exercise meta / dictionary ----
  app.get("/api/v1/exercises/_meta", requireAuth, (_req: AuthedRequest, res) => {
    res.json({
      statuses: EXERCISE_STATUSES,
      frameworks: EXERCISE_FRAMEWORKS,
      scenarioTypes: EXERCISE_SCENARIO_TYPES,
      severities: EXERCISE_SEVERITIES,
    });
  });

  // ---- exercise CRUD ----
  app.get("/api/v1/exercises", requireAuth, (req: AuthedRequest, res) => {
    const statusRaw = typeof req.query.status === "string" ? req.query.status : undefined;
    const status = statusRaw && (EXERCISE_STATUSES as readonly string[]).includes(statusRaw)
      ? (statusRaw as ExerciseStatus) : undefined;
    const q = typeof req.query.q === "string" && req.query.q.trim().length > 0 ? req.query.q.trim() : undefined;
    const filter = status || q ? { status, q } : undefined;
    res.json({ exercises: storage.listExercises(req.effectiveTenantId!, filter) });
  });

  app.post("/api/v1/exercises", requireAuth, (req: AuthedRequest, res) => {
    const parsed = exerciseCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const created = storage.createExercise(tid, req.user!.email, {
      title: parsed.data.title,
      framework: parsed.data.framework,
      scenarioType: parsed.data.scenarioType,
      severity: parsed.data.severity,
      durationMin: parsed.data.durationMin,
      scheduledAt: parsed.data.scheduledAt ?? null,
      sourceTapIds: parsed.data.sourceTapIds,
      sourceFindingIds: parsed.data.sourceFindingIds,
    });
    res.status(201).json(created);
  });

  app.get("/api/v1/exercises/:eid", requireAuth, (req: AuthedRequest, res) => {
    const ex = storage.getExercise(req.effectiveTenantId!, req.params.eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    res.json(ex);
  });

  app.get("/api/v1/exercises/:eid/full", requireAuth, (req: AuthedRequest, res) => {
    const full = storage.getExerciseFull(req.effectiveTenantId!, req.params.eid);
    if (!full) return res.status(404).json({ detail: "exercise not found" });
    res.json(full);
  });

  app.patch("/api/v1/exercises/:eid", requireAuth, (req: AuthedRequest, res) => {
    const parsed = exercisePatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const updated = storage.patchExercise(req.effectiveTenantId!, req.params.eid, {
      ...parsed.data,
      actor: req.user!.email,
    });
    if (!updated) return res.status(404).json({ detail: "exercise not found" });
    // Broadcast phase changes to participants so portals stay in sync.
    if (parsed.data.status) {
      _sseBroadcast(String(req.params.eid), {
        type: "phase-change",
        payload: { status: parsed.data.status, exerciseId: String(req.params.eid) },
      });
    }
    res.json(updated);
  });

  app.delete("/api/v1/exercises/:eid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteExercise(req.effectiveTenantId!, req.params.eid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "exercise not found" });
    res.status(204).end();
  });

  // ---- generate (async-job pattern — LLM may take up to 540s) ----
  app.post("/api/v1/exercises/:eid/generate", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.effectiveTenantId!;
    const eid = String(req.params.eid);
    const head = storage.getExercise(tid, eid);
    if (!head) return res.status(404).json({ detail: "exercise not found" });
    const scenarioOverride = typeof req.body?.scenarioType === "string"
      && (EXERCISE_SCENARIO_TYPES as readonly string[]).includes(req.body.scenarioType)
      ? req.body.scenarioType : undefined;
    const frameworkOverride = typeof req.body?.framework === "string"
      && (EXERCISE_FRAMEWORKS as readonly string[]).includes(req.body.framework)
      ? req.body.framework : undefined;
    const providerId = typeof req.body?.providerId === "string" ? req.body.providerId : null;
    const jobId = storage.createAiJob({
      tenantId: tid,
      kind: "exercise_generation",
      payload: { exerciseId: eid, scenarioType: scenarioOverride, framework: frameworkOverride, providerId },
      createdBy: req.user?.email ?? null,
      targetLabel: `${head.code} — ${head.title}`,
      targetUrl: `/#/exercises?focus=${encodeURIComponent(String(eid))}`,
    });
    setImmediate(async () => {
      storage.markAiJobRunning(jobId);
      const hb = setInterval(() => { try { storage.setAiJobHeartbeat(jobId); } catch { /* ignore */ } }, 30000);
      try {
        const out = await generateExercise({
          tenantId: tid,
          exerciseId: eid,
          actor: req.user!.email,
          scenarioType: scenarioOverride as any,
          framework: frameworkOverride as any,
          providerId,
        });
        storage.completeAiJob(jobId, out, out.providerLabel ?? null);
        // Tell connected portals the brief was regenerated.
        _sseBroadcast(String(eid), { type: "exercise-updated", payload: { exerciseId: String(eid), source: out.source } });
      } catch (e: any) {
        storage.failAiJob(jobId, e);
      } finally {
        clearInterval(hb);
      }
    });
    res.status(202).json({ jobId, status: "queued", kind: "exercise_generation" });
  });

  // ---- PPTX upload (facilitator-uploaded deck — stored under data/) ----
  // Accepts JSON body { fileName, contentBase64 } to stay consistent with
  // the existing client-asset upload pattern (no multer dependency).
  app.post("/api/v1/exercises/:eid/upload-pptx", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.effectiveTenantId!;
    const eid = req.params.eid;
    const head = storage.getExercise(tid, eid);
    if (!head) return res.status(404).json({ detail: "exercise not found" });
    const fileName = typeof req.body?.fileName === "string" ? req.body.fileName : "";
    const b64 = typeof req.body?.contentBase64 === "string" ? req.body.contentBase64 : "";
    if (!fileName || !b64) return res.status(400).json({ detail: "fileName + contentBase64 required" });
    if (!/\.pptx$/i.test(fileName)) return res.status(400).json({ detail: "file must be .pptx" });
    const buf = Buffer.from(b64, "base64");
    if (buf.byteLength === 0) return res.status(400).json({ detail: "empty file" });
    if (buf.byteLength > 50 * 1024 * 1024) return res.status(413).json({ detail: "file too large (50MB max)" });
    const dir = join(process.cwd(), "data", "exercise-uploads");
    try { mkdirSync(dir, { recursive: true }); } catch { /* ok */ }
    const safeBase = fileName.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 80);
    const storedName = `${eid}__${Date.now()}__${safeBase}`;
    const fullPath = join(dir, storedName);
    writeFileSync(fullPath, buf);
    const updated = storage.patchExercise(tid, eid, {
      // Stored as opaque server paths — the facilitator deck download uses these.
      uploadedPptxPath: fullPath,
      uploadedPptxName: fileName,
      actor: req.user!.email,
    } as any);
    res.status(201).json({
      exercise: updated,
      uploadedPptxName: fileName,
      bytes: buf.byteLength,
    });
  });

  // ---- export.pptx (auto-generated facilitator + per-role decks) ----
  app.get("/api/v1/exercises/:eid/export.pptx", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    try {
      const full = storage.getExerciseFull(req.effectiveTenantId!, req.params.eid);
      if (!full) return res.status(404).json({ detail: "exercise not found" });
      const buf = await buildFacilitatorPptx(full);
      const safeName = full.title.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60);
      const filename = `${full.code}_${safeName}_facilitator.pptx`;
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.presentationml.presentation");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", String(buf.byteLength));
      res.end(buf);
    } catch (err) {
      next(err);
    }
  });

  app.get("/api/v1/exercises/:eid/export-participant.pptx", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    try {
      const rid = typeof req.query.roleId === "string" ? req.query.roleId : "";
      if (!rid) return res.status(400).json({ detail: "roleId query param required" });
      const full = storage.getExerciseFull(req.effectiveTenantId!, req.params.eid);
      if (!full) return res.status(404).json({ detail: "exercise not found" });
      const role = full.roles.find((r: any) => r.id === rid);
      if (!role) return res.status(404).json({ detail: "role not found" });
      const buf = await buildParticipantPptx(full, role);
      const safeRole = (role.label || role.roleKey).replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 40);
      const filename = `${full.code}_${safeRole}_participant.pptx`;
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.presentationml.presentation");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", String(buf.byteLength));
      res.end(buf);
    } catch (err) {
      next(err);
    }
  });

  app.get("/api/v1/exercises/:eid/uploaded-pptx", requireAuth, (req: AuthedRequest, res) => {
    const ex = storage.getExercise(req.effectiveTenantId!, req.params.eid) as any;
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    if (!ex.uploadedPptxPath || !existsSync(ex.uploadedPptxPath)) {
      return res.status(404).json({ detail: "no uploaded deck" });
    }
    const buf = readFileSync(ex.uploadedPptxPath);
    const filename = (ex.uploadedPptxName || `${ex.code}.pptx`).replace(/[^A-Za-z0-9._-]+/g, "_");
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.presentationml.presentation");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Length", String(buf.byteLength));
    res.end(buf);
  });

  // ---- inject CRUD ----
  app.get("/api/v1/exercises/:eid/injects", requireAuth, (req: AuthedRequest, res) => {
    const ex = storage.getExercise(req.effectiveTenantId!, req.params.eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    res.json({ injects: storage.listInjects(req.effectiveTenantId!, req.params.eid) });
  });

  app.post("/api/v1/exercises/:eid/injects", requireAuth, (req: AuthedRequest, res) => {
    const parsed = exerciseInjectSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const eid = req.params.eid;
    const ex = storage.getExercise(tid, eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    const inj = storage.addInject(tid, eid, parsed.data, req.user!.email);
    res.status(201).json(inj);
  });

  app.patch("/api/v1/exercises/:eid/injects/:iid", requireAuth, (req: AuthedRequest, res) => {
    const parsed = exerciseInjectPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const updated = storage.patchInject(req.effectiveTenantId!, req.params.iid, {
      ...parsed.data,
      actor: req.user!.email,
    });
    if (!updated) return res.status(404).json({ detail: "inject not found" });
    res.json(updated);
  });

  app.delete("/api/v1/exercises/:eid/injects/:iid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteInject(req.effectiveTenantId!, req.params.iid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "inject not found" });
    res.status(204).end();
  });

  // Mark an inject as sent (facilitator drops it to participants). Broadcasts
  // an inject-released event to all connected portals so role-scoped feeds
  // can pick it up live.
  app.post("/api/v1/exercises/:eid/injects/:iid/send", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.effectiveTenantId!;
    const eid = req.params.eid;
    const iid = req.params.iid;
    const sent = storage.markInjectSent(tid, iid, req.user!.email);
    if (!sent) return res.status(404).json({ detail: "inject not found" });
    storage.addEvent(tid, eid, {
      type: "inject-released",
      actorRole: "FACILITATOR",
      payload: { injectId: iid, title: sent.title, audienceRoles: sent.audienceRoles },
    });
    _sseBroadcast(String(eid), {
      type: "inject-released",
      payload: { injectId: String(iid), audienceRoles: sent.audienceRoles, title: sent.title, atMinute: sent.atMinute },
    });
    res.json(sent);
  });

  // ---- role CRUD ----
  app.get("/api/v1/exercises/:eid/roles", requireAuth, (req: AuthedRequest, res) => {
    const ex = storage.getExercise(req.effectiveTenantId!, req.params.eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    res.json({ roles: storage.listRoles(req.effectiveTenantId!, req.params.eid) });
  });

  app.post("/api/v1/exercises/:eid/roles", requireAuth, (req: AuthedRequest, res) => {
    const parsed = exerciseRoleSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const ex = storage.getExercise(tid, req.params.eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    const r = storage.upsertRole(tid, req.params.eid, parsed.data, req.user!.email);
    res.status(201).json(r);
  });

  app.patch("/api/v1/exercises/:eid/roles/:rid", requireAuth, (req: AuthedRequest, res) => {
    const parsed = exerciseRolePatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const updated = storage.patchRole(req.effectiveTenantId!, req.params.rid, {
      ...parsed.data, actor: req.user!.email,
    });
    if (!updated) return res.status(404).json({ detail: "role not found" });
    res.json(updated);
  });

  app.delete("/api/v1/exercises/:eid/roles/:rid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteRole(req.effectiveTenantId!, req.params.rid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "role not found" });
    res.status(204).end();
  });

  // ---- participant CRUD ----
  app.get("/api/v1/exercises/:eid/participants", requireAuth, (req: AuthedRequest, res) => {
    const ex = storage.getExercise(req.effectiveTenantId!, req.params.eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    res.json({ participants: storage.listParticipants(req.effectiveTenantId!, req.params.eid) });
  });

  app.post("/api/v1/exercises/:eid/participants", requireAuth, (req: AuthedRequest, res) => {
    const parsed = exerciseParticipantSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const ex = storage.getExercise(tid, req.params.eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    try {
      const p = storage.addParticipant(tid, req.params.eid, parsed.data, req.user!.email);
      res.status(201).json(p);
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message ?? e) });
    }
  });

  app.delete("/api/v1/exercises/:eid/participants/:pid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteParticipant(req.effectiveTenantId!, req.params.pid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "participant not found" });
    res.status(204).end();
  });

  // ---- events (facilitator can post manual events; clients can poll) ----
  app.get("/api/v1/exercises/:eid/events", requireAuth, (req: AuthedRequest, res) => {
    const ex = storage.getExercise(req.effectiveTenantId!, req.params.eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    const sinceTs = typeof req.query.sinceTs === "string" ? req.query.sinceTs : undefined;
    res.json({ events: storage.listEvents(req.effectiveTenantId!, req.params.eid, { sinceTs }) });
  });

  app.post("/api/v1/exercises/:eid/events", requireAuth, (req: AuthedRequest, res) => {
    const parsed = exerciseEventCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const ex = storage.getExercise(tid, req.params.eid);
    if (!ex) return res.status(404).json({ detail: "exercise not found" });
    const ev = storage.addEvent(tid, req.params.eid, {
      type: parsed.data.type,
      actorId: parsed.data.actorId ?? req.user!.email,
      actorRole: parsed.data.actorRole ?? "FACILITATOR",
      payload: parsed.data.payload,
    });
    _sseBroadcast(String(req.params.eid), { type: ev.type, payload: ev.payload, ts: ev.ts });
    res.status(201).json(ev);
  });

  // ===========================================================================
  // v2.31.0 — Participant Portal API (token-scoped, no auth required)
  // ===========================================================================
  // Magic-link resolve: returns the exercise brief + the role-scoped role +
  // already-released injects this participant should see.
  app.get("/api/v1/exercise-portal/:token", (req: Request, res: Response) => {
    const token = req.params.token;
    const p = storage.participantByToken(token);
    if (!p) return res.status(404).json({ detail: "invalid token" });
    const full = storage.getExerciseFull(p.tenantId, p.exerciseId);
    if (!full) return res.status(404).json({ detail: "exercise not found" });
    storage.touchParticipant(p.id);
    const role = full.roles.find((r: any) => r.id === p.roleId);
    const roleKey = role?.roleKey;
    // Released injects that mention this participant's roleKey (or have no
    // audience — broadcast).
    const visibleInjects = full.injects.filter((inj: any) => {
      if (!inj.sentAt) return false;
      if (!inj.audienceRoles || inj.audienceRoles.length === 0) return true;
      return !!roleKey && inj.audienceRoles.includes(roleKey);
    });
    res.json({
      exercise: {
        id: full.id, code: full.code, title: full.title,
        status: full.status, framework: full.framework,
        scenarioType: full.scenarioType, severity: full.severity,
        narrativeMd: full.narrativeMd, objectives: full.objectives,
        durationMin: full.durationMin, scheduledAt: full.scheduledAt,
      },
      participant: {
        id: p.id, displayName: p.displayName, roleId: p.roleId,
        joinedAt: p.joinedAt, lastSeenAt: p.lastSeenAt,
      },
      role,
      injects: visibleInjects,
    });
  });

  // SSE feed for the participant portal. Streams role-scoped events.
  app.get("/api/v1/exercise-portal/:token/feed", (req: Request, res: Response) => {
    const token = req.params.token;
    const p = storage.participantByToken(token);
    if (!p) return res.status(404).json({ detail: "invalid token" });
    const full = storage.getExerciseFull(p.tenantId, p.exerciseId);
    if (!full) return res.status(404).json({ detail: "exercise not found" });
    const role = full.roles.find((r: any) => r.id === p.roleId);
    const roleKey = role?.roleKey;

    res.status(200);
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders?.();

    // Initial replay: send any already-released injects this role should see
    // plus the current phase, so reconnecting clients catch up.
    for (const inj of full.injects) {
      if (!inj.sentAt) continue;
      if (inj.audienceRoles && inj.audienceRoles.length > 0 && (!roleKey || !inj.audienceRoles.includes(roleKey))) continue;
      res.write(`event: inject-released\ndata: ${JSON.stringify({
        type: "inject-released",
        payload: { injectId: inj.id, title: inj.title, atMinute: inj.atMinute, audienceRoles: inj.audienceRoles },
        ts: inj.sentAt,
      })}\n\n`);
    }
    res.write(`event: hello\ndata: ${JSON.stringify({
      type: "hello",
      payload: { exerciseId: full.id, status: full.status, roleKey, displayName: p.displayName },
      ts: new Date().toISOString(),
    })}\n\n`);

    // Wrap res.write to filter inject-released events by audienceRoles.
    const client: SseClient = {
      lastTs: new Date().toISOString(),
      res: new Proxy(res, {
        get(target, prop, recv) {
          if (prop !== "write") return Reflect.get(target, prop, recv);
          return (chunk: any) => {
            // Inspect the chunk — if it's an inject-released event and the
            // payload's audienceRoles don't include our roleKey, swallow it.
            try {
              const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
              const evMatch = s.match(/^event:\s*([\w-]+)\ndata:\s*(\{[\s\S]*\})\n\n$/);
              if (evMatch && evMatch[1] === "inject-released") {
                const data = JSON.parse(evMatch[2]);
                const aud: string[] | undefined = data?.payload?.audienceRoles;
                if (aud && aud.length > 0 && (!roleKey || !aud.includes(roleKey))) {
                  return true; // drop
                }
              }
            } catch { /* ignore parse errors, pass through */ }
            return (target.write as any).call(target, chunk);
          };
        },
      }) as any,
    };

    let set = _ttxSseClients.get(full.id);
    if (!set) { set = new Set(); _ttxSseClients.set(full.id, set); }
    set.add(client);

    // Heartbeat every 20s to keep proxies/load-balancers from dropping.
    const hb = setInterval(() => {
      try { res.write(`: heartbeat ${new Date().toISOString()}\n\n`); } catch { /* ignore */ }
      try { storage.touchParticipant(p.id); } catch { /* ignore */ }
    }, 20000);

    req.on("close", () => {
      clearInterval(hb);
      set?.delete(client);
      if (set && set.size === 0) _ttxSseClients.delete(full.id);
    });
  });

  // Participant submits a response to a specific inject. Stored as an event
  // with type "participant-response" so the facilitator timeline picks it up.
  app.post("/api/v1/exercise-portal/:token/respond", (req: Request, res: Response) => {
    const token = req.params.token;
    const p = storage.participantByToken(token);
    if (!p) return res.status(404).json({ detail: "invalid token" });
    const full = storage.getExerciseFull(p.tenantId, p.exerciseId);
    if (!full) return res.status(404).json({ detail: "exercise not found" });
    const injectId = typeof req.body?.injectId === "string" ? req.body.injectId : null;
    const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
    const decisions = Array.isArray(req.body?.decisions) ? req.body.decisions.slice(0, 20) : [];
    if (!text && decisions.length === 0) {
      return res.status(400).json({ detail: "text or decisions required" });
    }
    if (injectId && !full.injects.find((i: any) => i.id === injectId)) {
      return res.status(400).json({ detail: "inject not found" });
    }
    storage.touchParticipant(p.id);
    const role = full.roles.find((r: any) => r.id === p.roleId);
    const ev = storage.addEvent(p.tenantId, p.exerciseId, {
      type: "participant-response",
      actorId: p.id,
      actorRole: role?.roleKey ?? null,
      payload: {
        participantId: p.id,
        participantName: p.displayName,
        injectId, text, decisions,
      },
    });
    _sseBroadcast(p.exerciseId, { type: ev.type, payload: ev.payload, ts: ev.ts });
    res.status(201).json({ ok: true, eventId: ev.id });
  });

  return httpServer;
}

function escapeXml(s: string): string {
  return String(s).replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;" }[c]!));
}

function renderLoginOrInvoice(p: { hero: string; band: string; cta: string }, brand: string, initials: string, title: string, subtitle: string, cta: string, showLockBar: boolean): string {
  return `
  <!-- decorative band -->
  <rect x="0" y="120" width="800" height="4" fill="${p.band}"/>
  <!-- centered card -->
  <rect x="220" y="170" width="360" height="280" rx="12" fill="url(#card)" stroke="#e2e8f0" stroke-width="1"/>
  <!-- brand badge -->
  <circle cx="400" cy="206" r="22" fill="${p.band}"/>
  <text x="400" y="212" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="14" font-weight="700" fill="#ffffff">${escapeXml(initials)}</text>
  <text x="400" y="258" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="16" font-weight="700" fill="#0f172a">${escapeXml(title)}</text>
  <text x="400" y="282" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="12" fill="#64748b">${escapeXml(subtitle)}</text>
  <!-- input rows -->
  <rect x="260" y="304" width="280" height="34" rx="6" fill="#f1f5f9" stroke="#cbd5e1"/>
  <text x="272" y="326" font-family="ui-sans-serif,system-ui" font-size="12" fill="#94a3b8">name@${escapeXml(brand)}.com</text>
  ${showLockBar ? `<rect x="260" y="346" width="280" height="34" rx="6" fill="#f1f5f9" stroke="#cbd5e1"/><text x="272" y="368" font-family="ui-monospace,monospace" font-size="12" fill="#94a3b8">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</text>` : `<rect x="260" y="346" width="280" height="50" rx="6" fill="#fff7ed" stroke="#fed7aa"/><text x="272" y="368" font-family="ui-sans-serif,system-ui" font-size="11" fill="#9a3412">Document expires in 24h. Action required.</text>`}
  <!-- CTA -->
  <rect x="260" y="${showLockBar ? 392 : 408}" width="280" height="36" rx="6" fill="${p.cta}"/>
  <text x="400" y="${showLockBar ? 416 : 432}" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="13" font-weight="600" fill="#ffffff">${escapeXml(cta)}</text>`;
}

function renderParked(p: { hero: string; band: string; cta: string }, brand: string, domain: string): string {
  return `
  <text x="400" y="240" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="28" font-weight="700" fill="#e2e8f0">${escapeXml(domain)}</text>
  <text x="400" y="272" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="13" fill="#94a3b8">This domain may be for sale. Inquire within.</text>
  <rect x="320" y="310" width="160" height="38" rx="6" fill="${p.cta}"/>
  <text x="400" y="335" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="13" font-weight="600" fill="#ffffff">Buy this domain</text>
  <text x="400" y="390" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="11" fill="#64748b">Powered by GoParkPark · generic registrar landing</text>`;
}
