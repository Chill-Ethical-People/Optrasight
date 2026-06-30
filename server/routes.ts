import type { Express, Request, Response, NextFunction } from "express";
import type { Server } from "node:http";
import { storage } from "./storage";
import {
  loginSchema,
  passwordChangeSchema,
  mfaVerifySchema,
  platformUserCreateSchema,
  platformUserUpdateSchema,
  platformUserBulkActionSchema,
  aiProviderUpsertSchema, aiAssignmentUpdateSchema,
  osintScanSchema, osintAnalyzeSchema, osintOverviewSchema,
  huntQueryCreateSchema,
  // v2.30.3 — Threat Actor Profile (TAP) schemas
  threatActorCreateSchema, threatActorPatchSchema, threatActorEnrichSchema,
  threatActorTtpSchema, threatActorToolSchema, threatActorCampaignSchema,
  threatActorIocSchema, threatActorReferenceSchema,
  TAP_STATUSES, ACTOR_TYPES, THREAT_LEVELS, TLP_LEVELS, IOC_TYPES,
  DETECTION_PRIORITIES, TTP_STATUSES, type TapStatus,
  AI_TASKS, BATCH_ONE_AI_TASKS, AI_PROVIDERS,
  CLIENT_TYPES, GEOS, INDUSTRIES, MONITORED_TECHNOLOGIES, HUNT_LANGUAGES,
  OSINT_CATEGORY_LABELS, OSINT_CATEGORY_ORDER, OSINT_OVERVIEW_PERSONAS,
  type User,
} from "@shared/schema";
import { hasCapability, isBatchOneApiAllowed, resolveCapabilities, type AccessMode, type Capability } from "@shared/accessPolicy";

const BATCH_ONE_RELEASE = process.env.OPTRASIGHT_BATCH_ONE_RELEASE !== "0";
const AI_TASKS_FOR_RELEASE = BATCH_ONE_RELEASE ? BATCH_ONE_AI_TASKS : AI_TASKS;
import { fromZodError } from "zod-validation-error";
import { runChatTriage, runChatDeepDive, runChatConverse, ChatLiveAiError, type ChatRangeKey } from "./osintChat";
import { runAutoAnalyzeNow, runAutoFetchNow } from "./backgroundJobs";
import { buildThreatActorDocx } from "./tapDocx";
import { generateActorPortrait, getPortraitGeneratorAvailability, PORTRAITS_DIR } from "./tapPortrait";
import { validateAiProviderBaseUrl } from "./aiProviderSecurity";
import express from "express";
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, readdirSync } from "node:fs";
import { join } from "node:path";

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
  user?: User & { accessMode?: AccessMode; capabilities?: Capability[] };
  accessMode?: AccessMode;
  capabilities?: Capability[];
  /** Internal workspace id. BatchOne does not expose tenant switching. */
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
  progressPct: number;
  progressDetail: { attempted: number; total: number; parsed: number; feedsOk: number } | null;
  workspaceId: string | null;
} = { busy: false, startedAt: null, finishedAt: null, summary: null, error: null, progressPct: 0, progressDetail: null, workspaceId: null };

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.header("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return res.status(401).json({ detail: "missing bearer token" });
  const u = storage.getUser(m[1]);
  if (!u) return res.status(401).json({ detail: "invalid token" });
  req.user = u;
  req.accessMode = (u as any).accessMode ?? "credentialed";
  req.capabilities = resolveCapabilities({
    role: u.role,
    accessMode: req.accessMode,
    batchOne: BATCH_ONE_RELEASE,
  });
  req.user = { ...u, capabilities: req.capabilities };
  if (req.header("x-tenant-id")) {
    return res.status(403).json({ detail: "Tenant switching is not available in BatchOne." });
  }
  if (req.query.tenant) {
    return res.status(403).json({ detail: "Tenant switching is not available in BatchOne." });
  }
  if (accountSetupRequired(u) && !isAccountSetupRoute(req.path)) {
    return res.status(428).json({
      detail: "Account setup required before platform functions unlock.",
      passwordMustChange: !!(u as any).passwordMustChange,
      mfaRequired: !((u as any).mfaEnabled && (u as any).mfaVerifiedAt),
    });
  }
  if (!isBatchOneApiAllowed({ method: req.method, path: req.path, accessMode: req.accessMode })) {
    return res.status(403).json({
      detail: req.accessMode === "guest"
        ? "Read-only reviewer access is limited to approved review and analysis tasking."
        : "This workflow is outside the Batch One release scope.",
    });
  }
  req.effectiveTenantId = u.tenantId;
  next();
}

function accountSetupRequired(u: any): boolean {
  return !!u.passwordMustChange || !(u.mfaEnabled && u.mfaVerifiedAt);
}

function isAccountSetupRoute(path: string): boolean {
  return path === "/api/v1/me"
    || path === "/api/v1/auth/logout"
    || path === "/api/v1/auth/change-password"
    || path === "/api/v1/auth/mfa/setup"
    || path === "/api/v1/auth/mfa/verify";
}

function requestCrossTenant(req: AuthedRequest): boolean {
  return String(req.query.crossTenant ?? "") === "true"
    || req.body?.crossTenant === true;
}

function requireCrossTenantCapability(req: AuthedRequest, res: Response): boolean {
  if (BATCH_ONE_RELEASE) {
    res.status(403).json({ detail: "Cross-tenant access is not available in BatchOne." });
    return false;
  }
  if (!hasCapability(req.capabilities, "global_view")) {
    res.status(403).json({ detail: "Cross-tenant access requires platform administrator privileges." });
    return false;
  }
  return true;
}

function tenantScopeForRequest(req: AuthedRequest, res: Response): string | undefined | null {
  const crossTenant = requestCrossTenant(req);
  if (crossTenant && !requireCrossTenantCapability(req, res)) return null;
  return crossTenant ? undefined : req.effectiveTenantId;
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

  // ---- auth ----
  app.post("/api/v1/auth/login", (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const u = storage.login(parsed.data.email, parsed.data.password, parsed.data.mfaCode);
    if (!u) return res.status(401).json({ detail: "invalid credentials" });
    if ("mfaRequired" in u) return res.status(401).json({ detail: "MFA code required", mfaRequired: true });
    res.json({
      access_token: u.accessToken,
      token_type: "bearer",
      tenant_id: u.tenantId,
      role: u.role,
      email: u.email,
      access_mode: u.accessMode,
      capabilities: resolveCapabilities({
        role: u.role,
        accessMode: u.accessMode,
        batchOne: BATCH_ONE_RELEASE,
      }),
    });
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
    const body: Record<string, any> = {
      id: u.id,
      email: u.email,
      role: u.role,
      tenant: t,
      passwordMustChange: !!(u as any).passwordMustChange,
      mfaEnabled: !!(u as any).mfaEnabled,
      mfaVerifiedAt: (u as any).mfaVerifiedAt ?? null,
      access_mode: (u as any).accessMode ?? "credentialed",
      capabilities: req.capabilities ?? [],
    };
    if (String(req.query.mfaSetup || "") === "1" && !(u as any).mfaEnabled) {
      body.mfaSetup = storage.getMfaSetup(u.id);
    }
    res.json(body);
  });

  app.post("/api/v1/auth/change-password", requireAuth, (req: AuthedRequest, res) => {
    const parsed = passwordChangeSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const user = storage.changeOwnPassword(req.user!.id, parsed.data.currentPassword, parsed.data.newPassword);
      if (!user) return res.status(404).json({ detail: "user not found" });
      storage.appendAudit(req.user!.tenantId, req.user!.email, "auth.password.change", req.user!.id, {});
      res.json({ user });
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message ?? e) });
    }
  });

  app.get("/api/v1/auth/mfa/setup", requireAuth, (req: AuthedRequest, res) => {
    if ((req.user! as any).mfaEnabled) {
      return res.status(409).json({ detail: "MFA is already enabled. Ask an admin to reset MFA before enrolling a new authenticator." });
    }
    const setup = storage.getMfaSetup(req.user!.id);
    if (!setup) return res.status(404).json({ detail: "user not found" });
    res.json(setup);
  });

  app.post("/api/v1/auth/mfa/verify", requireAuth, (req: AuthedRequest, res) => {
    const parsed = mfaVerifySchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const user = storage.verifyMfaSetup(req.user!.id, parsed.data.code);
      if (!user) return res.status(404).json({ detail: "user not found" });
      storage.appendAudit(req.user!.tenantId, req.user!.email, "auth.mfa.enable", req.user!.id, {});
      res.json({ user });
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message ?? e) });
    }
  });

  // ---- Platform users (admin only, internal BatchOne users) ----
  app.get("/api/v1/admin/platform-users", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin") return res.status(403).json({ detail: "admin only" });
    res.json({ users: storage.listPlatformUsers() });
  });
  app.post("/api/v1/admin/platform-users", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin") return res.status(403).json({ detail: "admin only" });
    const parsed = platformUserCreateSchema.safeParse({
      ...(req.body || {}),
      tenantId: req.user!.tenantId,
    });
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const user = storage.createPlatformUser(parsed.data);
      storage.appendAudit(parsed.data.tenantId, req.user!.email, "platform_user.create", user?.id ?? null, {
        email: parsed.data.email,
        role: parsed.data.role,
      });
      res.status(201).json({ user });
    } catch (e: any) {
      const msg = String(e?.message ?? "");
      if (/UNIQUE constraint failed: users\.email/i.test(msg)) {
        return res.status(409).json({ detail: "A user with this email already exists." });
      }
      if (/workspace not found|tenant not found/i.test(msg)) return res.status(400).json({ detail: "workspace not found" });
      throw e;
    }
  });
  app.put("/api/v1/admin/platform-users/:uid", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin") return res.status(403).json({ detail: "admin only" });
    const parsed = platformUserUpdateSchema.safeParse({
      ...(req.body || {}),
      tenantId: req.user!.tenantId,
    });
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    if (req.params.uid === req.user!.id && parsed.data.status === "disabled") {
      return res.status(409).json({ detail: "You cannot disable your own platform account." });
    }
    try {
      const user = storage.updatePlatformUser(req.params.uid, parsed.data);
      if (!user) return res.status(404).json({ detail: "not found" });
      storage.appendAudit(user.tenantId, req.user!.email, "platform_user.update", user.id, {
        email: user.email,
        role: user.role,
        status: (user as any).status,
      });
      res.json({ user });
    } catch (e: any) {
      const msg = String(e?.message ?? "");
      if (/UNIQUE constraint failed: users\.email/i.test(msg)) {
        return res.status(409).json({ detail: "A user with this email already exists." });
      }
      if (/tenant not found/i.test(msg)) return res.status(400).json({ detail: "tenant not found" });
      throw e;
    }
  });
  app.post("/api/v1/admin/platform-users/:uid/reset-mfa", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin") return res.status(403).json({ detail: "admin only" });
    const user = storage.resetPlatformUserMfa(req.params.uid);
    if (!user) return res.status(404).json({ detail: "not found" });
    storage.appendAudit(user.tenantId, req.user!.email, "platform_user.mfa.reset", user.id, {
      email: user.email,
      role: user.role,
    });
    res.json({ user });
  });
  app.post("/api/v1/admin/platform-users/:uid/disable", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin") return res.status(403).json({ detail: "admin only" });
    if (req.params.uid === req.user!.id) {
      return res.status(409).json({ detail: "You cannot disable your own platform account." });
    }
    const user = storage.disablePlatformUser(req.params.uid);
    if (!user) return res.status(404).json({ detail: "not found" });
    storage.appendAudit(user.tenantId, req.user!.email, "platform_user.disable", user.id, {
      email: user.email,
      role: user.role,
    });
    res.json({ user });
  });
  app.post("/api/v1/admin/platform-users/bulk", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin") return res.status(403).json({ detail: "admin only" });
    const parsed = platformUserBulkActionSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const userIds = Array.from(new Set(parsed.data.userIds));
    if (userIds.includes(req.user!.id)) {
      return res.status(409).json({ detail: "You cannot bulk manage your own platform account." });
    }
    const changed: Array<{ id: string; email: string; role: string }> = [];
    const missing: string[] = [];
    for (const uid of userIds) {
      const user = parsed.data.action === "disable"
        ? storage.disablePlatformUser(uid)
        : storage.deletePlatformUser(uid);
      if (!user) {
        missing.push(uid);
        continue;
      }
      changed.push({ id: user.id, email: user.email, role: user.role });
      storage.appendAudit(user.tenantId, req.user!.email, `platform_user.bulk.${parsed.data.action}`, user.id, {
        email: user.email,
        role: user.role,
      });
    }
    res.json({ action: parsed.data.action, changed, missing });
  });
  app.delete("/api/v1/admin/platform-users/:uid", requireAuth, (req: AuthedRequest, res) => {
    if (req.user!.role !== "admin") return res.status(403).json({ detail: "admin only" });
    if (req.params.uid === req.user!.id) {
      return res.status(409).json({ detail: "You cannot delete your own platform account." });
    }
    const user = storage.deletePlatformUser(req.params.uid);
    if (!user) return res.status(404).json({ detail: "not found" });
    storage.appendAudit(user.tenantId, req.user!.email, "platform_user.delete", user.id, {
      email: user.email,
      role: user.role,
    });
    res.json({ user });
  });

  // ---- global command/search palette ----
  app.get("/api/v1/search", requireAuth, (req: AuthedRequest, res) => {
    const q = String(req.query.q || "");
    const global = !BATCH_ONE_RELEASE && req.header("x-tenant-id") === "__global__" && hasCapability(req.capabilities, "global_view");
    res.json(storage.searchPlatform(req.effectiveTenantId!, q, {
      global,
      role: req.user!.role,
    }));
  });

  // ---- AI providers ----
  app.get("/api/v1/ai/providers", requireAuth, (req: AuthedRequest, res) => {
    const providers = storage.listAiProviders(req.effectiveTenantId!);
    res.json({
      providers,
      hasUsableProvider: storage.hasUsableAiProvider(req.effectiveTenantId!),
      kinds: AI_PROVIDERS,
      tasks: AI_TASKS_FOR_RELEASE,
    });
  });
  app.post("/api/v1/ai/providers", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const parsed = aiProviderUpsertSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const baseUrlError = await validateAiProviderBaseUrl(parsed.data.provider, parsed.data.baseUrl);
    if (baseUrlError) return res.status(400).json({ detail: baseUrlError });
    const provider = storage.upsertAiProvider(req.effectiveTenantId!, parsed.data);
    const assignedDefaultTasks = parsed.data.isDefault
      ? storage.assignProviderToUnassignedAiTasks(req.effectiveTenantId!, provider.id, AI_TASKS_FOR_RELEASE)
      : [];
    res.json({ ...provider, assignedDefaultTasks });
  });
  app.put("/api/v1/ai/providers/:pid", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const parsed = aiProviderUpsertSchema.safeParse({ ...req.body, id: req.params.pid });
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const baseUrlError = await validateAiProviderBaseUrl(parsed.data.provider, parsed.data.baseUrl);
    if (baseUrlError) return res.status(400).json({ detail: baseUrlError });
    const provider = storage.upsertAiProvider(req.effectiveTenantId!, parsed.data);
    const assignedDefaultTasks = parsed.data.isDefault
      ? storage.assignProviderToUnassignedAiTasks(req.effectiveTenantId!, provider.id, AI_TASKS_FOR_RELEASE)
      : [];
    res.json({ ...provider, assignedDefaultTasks });
  });
  app.delete("/api/v1/ai/providers/:pid", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const ok = storage.deleteAiProvider(req.effectiveTenantId!, req.params.pid);
    if (!ok) return res.status(404).json({ detail: "not found" });
    res.json({ ok: true });
  });
  app.post("/api/v1/ai/providers/:pid/test", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    res.json(storage.testAiProvider(req.effectiveTenantId!, req.params.pid));
  });

  // ---- AI task assignments ----
  app.get("/api/v1/ai/assignments", requireAuth, (req: AuthedRequest, res) => {
    const allAssignments = storage.getAiAssignments(req.effectiveTenantId!);
    const assignments = Object.fromEntries(
      AI_TASKS_FOR_RELEASE
        .map((task) => [task, allAssignments[task]])
        .filter((entry): entry is [typeof AI_TASKS_FOR_RELEASE[number], string] => typeof entry[1] === "string" && entry[1].length > 0),
    );
    res.json({
      assignments,
      tasks: AI_TASKS_FOR_RELEASE,
    });
  });
  app.put("/api/v1/ai/assignments", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const parsed = aiAssignmentUpdateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const allowed = new Set<string>(AI_TASKS_FOR_RELEASE);
    const unsupported = Object.keys(parsed.data.assignments).filter((task) => !allowed.has(task));
    if (unsupported.length > 0) {
      return res.status(400).json({
        detail: `Batch One AI setup does not expose routing for: ${unsupported.join(", ")}`,
      });
    }
    storage.setAiAssignments(req.effectiveTenantId!, parsed.data.assignments);
    const allAssignments = storage.getAiAssignments(req.effectiveTenantId!);
    const assignments = Object.fromEntries(
      AI_TASKS_FOR_RELEASE
        .map((task) => [task, allAssignments[task]])
        .filter((entry): entry is [typeof AI_TASKS_FOR_RELEASE[number], string] => typeof entry[1] === "string" && entry[1].length > 0),
    );
    res.json({ ok: true, assignments, tasks: AI_TASKS_FOR_RELEASE });
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
      hostingMode: "single",
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
    const tenantId = tenantScopeForRequest(req, res);
    if (tenantId === null) return;
    res.json(storage.getOsintSourcesAnalytics({ tenantId }));
  });

  // v2.30 — Deep Sources Analytics endpoints. Each one is independent so the
  // SourcesAnalytics page can load them in parallel and skeleton-render.
  app.get("/api/v1/osint/sources/scorecard", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const tenantId = tenantScopeForRequest(req, res);
    if (tenantId === null) return;
    try { res.json(storage.getOsintSourceScorecard({ tenantId })); }
    catch (e) { next(e); }
  });
  app.get("/api/v1/osint/sources/quadrant", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const tenantId = tenantScopeForRequest(req, res);
    if (tenantId === null) return;
    try { res.json(storage.getOsintSourceQuadrant({ tenantId })); }
    catch (e) { next(e); }
  });
  app.get("/api/v1/osint/sources/overlap", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const tenantId = tenantScopeForRequest(req, res);
    if (tenantId === null) return;
    try { res.json(storage.getOsintSourceOverlap({ tenantId })); }
    catch (e) { next(e); }
  });
  app.get("/api/v1/osint/sources/heatmaps", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const tenantId = tenantScopeForRequest(req, res);
    if (tenantId === null) return;
    try { res.json(storage.getOsintSourceHeatmaps({ tenantId })); }
    catch (e) { next(e); }
  });

  // v2.30 — Admin-triggered bulk re-analyse last N days. Async — returns the
  // job id immediately; UI polls /api/v1/osint/reanalyze-jobs/:id for status.
  app.post("/api/v1/osint/findings/reanalyze", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    if (!requireAdmin(req, res)) return;
    const sinceDays = Math.max(1, Math.min(Number(req.body?.sinceDays ?? 30), 365));
    try {
      const job = storage.createOsintReanalyzeJob(req.effectiveTenantId!, { sinceDays });
      storage.appendAudit(req.effectiveTenantId!, req.user?.email || "admin", "osint.reanalyze.start", job.id, { sinceDays, total: job.totalCount });
      res.status(202).json(job);
    } catch (e) {
      next(e);
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
  app.post("/api/v1/osint/scan", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = osintScanSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const result = await storage.runOsintScan(req.effectiveTenantId!, parsed.data);
      res.status(202).json(result);
    } catch (e) {
      next(e);
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
    const workspaceId = req.effectiveTenantId!;
    if (globalOsintRun.busy) {
      return res.status(202).json({ status: "already_running", started: globalOsintRun.startedAt, durationMs: Date.now() - (globalOsintRun.startedAt ? new Date(globalOsintRun.startedAt).getTime() : Date.now()) });
    }
    globalOsintRun.busy = true;
    globalOsintRun.startedAt = new Date().toISOString();
    globalOsintRun.finishedAt = null;
    globalOsintRun.summary = null;
    globalOsintRun.error = null;
    globalOsintRun.progressPct = 0;
    globalOsintRun.progressDetail = null;
    globalOsintRun.workspaceId = workspaceId;
    // Fire-and-forget; client polls /api/v1/admin/osint/ingest/status.
    (async () => {
      try {
        const result = await storage.runGlobalOsintIngest({
          workspaceId,
          days,
          maxPerSource,
          maxTotal,
          actor,
          onProgress: (progress: { attempted: number; total: number; parsed: number; feedsOk: number }) => {
            globalOsintRun.progressDetail = progress;
            globalOsintRun.progressPct = progress.total > 0
              ? Math.min(99, Math.max(0, Math.round((progress.attempted / progress.total) * 100)))
              : 0;
          },
        });
        globalOsintRun.summary = result;
        globalOsintRun.progressPct = 100;
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
    const sameWorkspace = globalOsintRun.workspaceId === req.effectiveTenantId;
    res.json({
      busy: globalOsintRun.busy,
      startedAt: globalOsintRun.startedAt,
      finishedAt: globalOsintRun.finishedAt,
      summary: sameWorkspace ? globalOsintRun.summary : null,
      error: sameWorkspace ? globalOsintRun.error : null,
      progressPct: sameWorkspace ? globalOsintRun.progressPct : 0,
      progressDetail: sameWorkspace ? globalOsintRun.progressDetail : null,
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
  app.post("/api/v1/osint/findings/ai-analyze", requireAuth, async (req: AuthedRequest, res) => {
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
      targetUrl: ids.length === 1 ? `/#/osint?finding=${encodeURIComponent(ids[0])}` : "/#/osint",
      work: () => storage.runOsintAnalysis(tid, parsed.data),
      providerLabel: (out) => out.provider,
    });
    storage.appendAudit(tid, req.user?.email || "system", "osint.analyze.ai_job.start", job.jobId, { onlyUnanalyzed, idCount: ids.length });
    res.status(202).json(job);
  });
  // ---- Hunt queries ----
  app.get("/api/v1/osint/hunt-queries", requireAuth, (req: AuthedRequest, res) => {
    res.json({ queries: storage.listHuntQueries(req.effectiveTenantId!) });
  });
  app.post("/api/v1/osint/hunt-queries", requireAuth, async (req: AuthedRequest, res) => {
    const parsed = huntQueryCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const job = runAiJob({
      tenantId: tid,
      kind: "hunt_query_generation",
      payload: parsed.data,
      createdBy: req.user?.email ?? null,
      targetLabel: `Hunt query — ${parsed.data.findingIds.length} finding${parsed.data.findingIds.length === 1 ? "" : "s"}`,
      targetUrl: "/#/osint?tab=hunt-queries",
      work: (jobId) => {
        const out = storage.generateHuntQueries(tid, {
          findingIds: parsed.data.findingIds,
          languages: parsed.data.languages,
          title: parsed.data.title,
          createdBy: req.user!.email,
        });
        if (out?.id) {
          storage.updateAiJobTarget(jobId, {
            targetLabel: out.title,
            targetUrl: `/#/osint?tab=hunt-queries&hunt=${encodeURIComponent(out.id)}`,
          });
        }
        return out;
      },
      providerLabel: (out) => out.aiProviderLabel,
    });
    res.status(202).json(job);
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

  app.get("/api/v1/threat-actors/portrait-generator/availability", requireAuth, async (req: AuthedRequest, res) => {
    res.json(await getPortraitGeneratorAvailability(req.effectiveTenantId!));
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
      work: (jobId) => {
        storage.setAiJobProgress(jobId, 8);
        const out = storage.enrichThreatActor(tid, aid, {
          force: parsed.data.force,
          actor: req.user!.email,
          providerId: parsed.data.providerId ?? null,
        });
        storage.setAiJobProgress(jobId, 92);
        return out;
      },
      providerLabel: (out) => out.aiProviderLabel ?? null,
    });
    res.status(202).json(job);
  });

  // ---- Sub-resource: TTPs ----
  app.post("/api/v1/threat-actors/:aid/ttps", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = threatActorTtpSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorTtp(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e) {
      next(e);
    }
  });
  app.delete("/api/v1/threat-actors/:aid/ttps/:ttpId", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorTtp(req.effectiveTenantId!, req.params.aid, req.params.ttpId, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "ttp not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: Tools ----
  app.post("/api/v1/threat-actors/:aid/tools", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = threatActorToolSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorTool(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e) {
      next(e);
    }
  });
  app.delete("/api/v1/threat-actors/:aid/tools/:toolId", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorTool(req.effectiveTenantId!, req.params.aid, req.params.toolId, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "tool not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: Campaigns ----
  app.post("/api/v1/threat-actors/:aid/campaigns", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = threatActorCampaignSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorCampaign(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e) {
      next(e);
    }
  });
  app.delete("/api/v1/threat-actors/:aid/campaigns/:cid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorCampaign(req.effectiveTenantId!, req.params.aid, req.params.cid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "campaign not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: IOCs ----
  app.post("/api/v1/threat-actors/:aid/iocs", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = threatActorIocSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorIoc(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e) {
      next(e);
    }
  });
  app.delete("/api/v1/threat-actors/:aid/iocs/:iid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorIoc(req.effectiveTenantId!, req.params.aid, req.params.iid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "ioc not found" });
    res.status(204).end();
  });

  // ---- Sub-resource: References ----
  app.post("/api/v1/threat-actors/:aid/references", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = threatActorReferenceSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const out = storage.addThreatActorReference(req.effectiveTenantId!, req.params.aid, parsed.data, req.user!.email);
      res.status(201).json(out);
    } catch (e) {
      next(e);
    }
  });
  app.delete("/api/v1/threat-actors/:aid/references/:rid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteThreatActorReference(req.effectiveTenantId!, req.params.aid, req.params.rid, req.user!.email);
    if (!ok) return res.status(404).json({ detail: "reference not found" });
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
    const tenantId = req.effectiveTenantId!;
    const jobId = storage.createAiJob({
      tenantId,
      kind: "chat_triage",
      payload: { range, findingIds },
      createdBy: req.user?.email ?? null,
      targetLabel: `CIRT triage — ${range}`,
      targetUrl: null,
    });
    const targetUrl = `/#/osint?ai=triage&job=${encodeURIComponent(jobId)}`;
    storage.updateAiJobTarget(jobId, { targetUrl });
    setImmediate(async () => {
      let hb: ReturnType<typeof setInterval> | null = null;
      try {
        storage.markAiJobRunning(jobId);
        storage.setAiJobProgress(jobId, 15);
        if (!storage.resolveAiProvider(tenantId, "osint_overview")) {
          throw new Error("No live-tested AI provider is configured for CIRT triage. Open AI Setup, enable a provider, and assign it to OSINT overview.");
        }
        hb = setInterval(() => { try { storage.setAiJobHeartbeat(jobId); } catch { /* ignore */ } }, 30000);
        storage.setAiJobProgress(jobId, 35);
        const out = await runChatTriage(storage, { tenantId, range, findingIds });
        storage.setAiJobProgress(jobId, 90);
        storage.completeAiJob(jobId, out, (out as any)?.providerLabel ?? null);
      } catch (e: any) {
        try { storage.failAiJob(jobId, e); } catch { /* keep worker exceptions contained */ }
      } finally {
        if (hb) clearInterval(hb);
      }
    });
    res.status(202).json({ jobId, status: "queued", kind: "chat_triage", targetLabel: `CIRT triage — ${range}`, targetUrl });
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
      next(e);
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
    const tenantId = req.effectiveTenantId!;
    const jobId = storage.createAiJob({
      tenantId,
      kind: "chat_deep_dive",
      payload: { findingIds },
      createdBy: req.user?.email ?? null,
      targetLabel: `CIRT deep-dive — ${findingIds.length} finding${findingIds.length === 1 ? "" : "s"}`,
      targetUrl: null,
    });
    const targetUrl = `/#/osint?ai=deep-dive&job=${encodeURIComponent(jobId)}`;
    storage.updateAiJobTarget(jobId, { targetUrl });
    setImmediate(async () => {
      let hb: ReturnType<typeof setInterval> | null = null;
      try {
        storage.markAiJobRunning(jobId);
        storage.setAiJobProgress(jobId, 15);
        if (!storage.resolveAiProvider(tenantId, "osint_analysis")) {
          throw new Error("No live-tested AI provider is configured for CIRT deep dive. Open AI Setup, enable a provider, and assign it to OSINT analysis.");
        }
        hb = setInterval(() => { try { storage.setAiJobHeartbeat(jobId); } catch { /* ignore */ } }, 30000);
        storage.setAiJobProgress(jobId, 35);
        const out = await runChatDeepDive(storage, { tenantId, findingIds });
        storage.setAiJobProgress(jobId, 90);
        storage.completeAiJob(jobId, out, (out as any)?.providerLabel ?? null);
      } catch (e: any) {
        try { storage.failAiJob(jobId, e); } catch { /* keep worker exceptions contained */ }
      } finally {
        if (hb) clearInterval(hb);
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

  // Shared guard for BatchOne administrative actions such as source refresh
  // and source-catalog maintenance.
  function requireAdmin(req: AuthedRequest, res: Response): boolean {
    if (req.user?.role !== "admin") {
      res.status(403).json({ detail: "admin role required" });
      return false;
    }
    return true;
  }

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
      globalIngest: req.user?.role === "admin" && globalOsintRun.workspaceId === req.effectiveTenantId ? {
        source: "global_ingest",
        id: "global-osint-ingest",
        kind: "osint_global_ingest",
        label: "Global OSINT ingest",
        status: globalOsintRun.busy ? "running" : (globalOsintRun.error ? "failed" : globalOsintRun.finishedAt ? "done" : "idle"),
        progressPct: globalOsintRun.progressPct,
        startedAt: globalOsintRun.startedAt,
        finishedAt: globalOsintRun.finishedAt,
        errorMessage: globalOsintRun.error,
        summary: globalOsintRun.summary,
        target: globalOsintRun.progressDetail
          ? `${globalOsintRun.progressDetail.attempted}/${globalOsintRun.progressDetail.total} feeds checked`
          : null,
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

  return httpServer;
}
