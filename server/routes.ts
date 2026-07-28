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
  aiProviderUpsertSchema,
  aiAssignmentUpdateSchema,
  osintAnalyzeSchema,
  osintOverviewSchema,
  osintFindingPatchSchema,
  huntQueryCreateSchema,
  clientProfileCreateSchema,
  clientProfileUpdateSchema,
  clientProfileBulkCreateSchema,
  clientTaxonomyOptionCreateSchema,
  clientDigestGenerateSchema,
  clientDigestPatchSchema,
  smtpSettingsUpdateSchema,
  xIntegrationSettingsUpdateSchema,
  kelaIntegrationSettingsUpdateSchema,
  communityIntegrationKindSchema,
  communityIntegrationSettingsUpdateSchema,
  communityEnrichmentLookupSchema,
  detectionRuleCreateSchema,
  detectionRulePatchSchema,
  detectionRuleDeploySchema,
  detectionRuleValidationSchema,
  workspaceOperatingModeSchema,
  // v2.30.3 — Threat Actor Profile (TAP) schemas
  threatActorCreateSchema,
  threatActorPatchSchema,
  threatActorEnrichSchema,
  threatActorTtpSchema,
  threatActorToolSchema,
  threatActorCampaignSchema,
  threatActorIocSchema,
  threatActorReferenceSchema,
  TAP_STATUSES,
  ACTOR_TYPES,
  THREAT_LEVELS,
  TLP_LEVELS,
  IOC_TYPES,
  DETECTION_PRIORITIES,
  TTP_STATUSES,
  type TapStatus,
  AI_TASKS,
  BATCH_ONE_AI_TASKS,
  AI_PROVIDERS,
  CLIENT_TYPES,
  GEOS,
  INDUSTRIES,
  MONITORED_TECHNOLOGIES,
  HUNT_LANGUAGES,
  OSINT_CATEGORY_LABELS,
  OSINT_CATEGORY_ORDER,
  OSINT_OVERVIEW_PERSONAS,
  type User,
  type OsintFindingDTO,
} from "@shared/schema";
import {
  hasCapability,
  isBatchOneApiAllowed,
  resolveCapabilities,
  type AccessMode,
  type Capability,
} from "@shared/accessPolicy";

const BATCH_ONE_RELEASE = process.env.OPTRASIGHT_BATCH_ONE_RELEASE !== "0";
const AI_TASKS_FOR_RELEASE = BATCH_ONE_RELEASE ? BATCH_ONE_AI_TASKS : AI_TASKS;
const TEST_AUTH_BYPASS = process.env.OPTRASIGHT_TEST_AUTH_BYPASS === "1";
import { fromZodError } from "zod-validation-error";
import { runChatConverse, ChatLiveAiError, type ChatRangeKey } from "./osintChat";
import { runAutoAnalyzeNow, runAutoFetchNow } from "./backgroundJobs";
import { buildThreatActorDocx } from "./tapDocx";
import {
  buildClientTemplateDocx,
  buildClientTemplateEml,
  buildClientDigestEml,
  buildClientDigestEmailContent,
  type ClientEmailLogo,
} from "./clientDigestExport";
import { ClientDigestTemplateUploadError, parseClientDigestTemplateDocx } from "./clientDigestTemplateUpload";
import {
  classifySmtpFailure,
  clearSmtpCooldown,
  describeSmtpError,
  getSmtpCooldownSeconds,
  getSmtpSettings,
  saveSmtpSettings,
  sendSmtpEmail,
  setSmtpCooldown,
  verifySmtpConnection,
} from "./emailDelivery";
import { getXIntegrationSettings, saveXIntegrationSettings, testXIntegration } from "./socialIntegrations";
import { getKelaIntegrationSettings, saveKelaIntegrationSettings, testKelaIntegration } from "./kelaIntegration";
import {
  getCommunityIntegrationSettings,
  lookupCommunityEnrichment,
  saveCommunityIntegrationSettings,
  testCommunityIntegration,
} from "./communityIntegrations";
import { generateActorPortrait, getPortraitGeneratorAvailability, PORTRAITS_DIR } from "./tapPortrait";
import { ClientLogoUploadService, LocalImageObjectStore, UploadValidationError } from "./imageUploadService";
import { validateAiProviderBaseUrl } from "./aiProviderSecurity";
import { buildOsintStixBundle } from "./stixExport";
import express from "express";
import { readFileSync, existsSync, unlinkSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";

const CLIENT_EMAIL_LOGOS_DIR = join(process.cwd(), "data", "client-email-logos");
const clientLogoUploads = new ClientLogoUploadService(
  new LocalImageObjectStore(CLIENT_EMAIL_LOGOS_DIR, "/client-email-logos"),
);

async function loadClientEmailLogo(publicUrl: string | null | undefined): Promise<ClientEmailLogo | undefined> {
  const data = await clientLogoUploads.read(publicUrl);
  if (!data || !publicUrl) return undefined;
  return {
    data,
    mimeType: new URL(publicUrl, "http://optrasight.invalid").pathname.endsWith(".png") ? "image/png" : "image/jpeg",
  };
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
    const hb = setInterval(() => {
      try {
        storage.setAiJobHeartbeat(jobId);
      } catch {
        /* ignore */
      }
    }, 30000);
    try {
      const out = await opts.work(jobId);
      storage.completeAiJob(
        jobId,
        out,
        opts.providerLabel?.(out) ?? (out as any)?.providerLabel ?? (out as any)?.aiProviderLabel ?? null,
      );
    } catch (e: any) {
      storage.failAiJob(jobId, e);
    } finally {
      clearInterval(hb);
    }
  });
  return { jobId, status: "queued", kind: opts.kind, targetLabel: opts.targetLabel, targetUrl };
}

function runOsintAnalysisWorker(opts: {
  tenantId: string;
  payload: { ids?: string[]; onlyUnanalyzed?: boolean };
  createdBy?: string | null;
  targetLabel: string;
  targetUrl: string;
}) {
  const jobId = storage.createAiJob({
    tenantId: opts.tenantId,
    kind: "osint_analysis",
    payload: opts.payload,
    createdBy: opts.createdBy ?? null,
    targetLabel: opts.targetLabel,
    targetUrl: opts.targetUrl,
  });
  const workerArgs = [jobId, opts.tenantId, Buffer.from(JSON.stringify(opts.payload), "utf8").toString("base64url")];
  const productionWorker = join(process.cwd(), "dist", "osintAnalysisWorker.cjs");
  const command = existsSync(productionWorker) ? process.execPath : join(process.cwd(), "node_modules", ".bin", "tsx");
  const args = existsSync(productionWorker)
    ? [productionWorker, ...workerArgs]
    : [join(process.cwd(), "server", "osintAnalysisWorker.ts"), ...workerArgs];
  const child = spawn(command, args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: ["ignore", "inherit", "inherit"],
  });
  child.once("error", (error) => storage.failAiJob(jobId, error));
  child.once("exit", (code, signal) => {
    if (code === 0) return;
    const current = storage.getAiJob(opts.tenantId, jobId);
    if (current?.status === "queued" || current?.status === "running") {
      storage.failAiJob(jobId, new Error(`OSINT analysis worker exited (${signal || code || "unknown"}).`));
    }
  });
  return { jobId, status: "queued", kind: "osint_analysis", targetLabel: opts.targetLabel, targetUrl: opts.targetUrl };
}

function runChatTriageWorker(opts: {
  jobId: string;
  tenantId: string;
  payload: {
    range: ChatRangeKey;
    findingIds?: string[];
    analysisMode: "cirt" | "client_impact";
    clientIds: string[];
    actor: string;
    digestCadence?: "daily" | "weekly" | "biweekly" | "monthly";
  };
}) {
  const workerArgs = [
    opts.jobId,
    opts.tenantId,
    Buffer.from(JSON.stringify(opts.payload), "utf8").toString("base64url"),
  ];
  const productionWorker = join(process.cwd(), "dist", "chatTriageWorker.cjs");
  const command = existsSync(productionWorker) ? process.execPath : join(process.cwd(), "node_modules", ".bin", "tsx");
  const args = existsSync(productionWorker)
    ? [productionWorker, ...workerArgs]
    : [join(process.cwd(), "server", "chatTriageWorker.ts"), ...workerArgs];
  const child = spawn(command, args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: ["ignore", "inherit", "inherit"],
  });
  child.once("error", (error) => storage.failAiJob(opts.jobId, error));
  child.once("exit", (code, signal) => {
    if (code === 0) return;
    const current = storage.getAiJob(opts.tenantId, opts.jobId);
    if (current?.status === "queued" || current?.status === "running") {
      storage.failAiJob(opts.jobId, new Error(`Chat triage worker exited (${signal || code || "unknown"}).`));
    }
  });
}

function runIsolatedAiWork(opts: {
  tenantId: string;
  kind: "detection_rule_generation" | "threat_actor_enrichment" | "chat_deep_dive";
  payload: Record<string, unknown>;
  createdBy?: string | null;
  targetLabel: string;
  targetUrl: string | ((jobId: string) => string);
}) {
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
  const workerArgs = [
    jobId,
    opts.tenantId,
    opts.kind,
    Buffer.from(JSON.stringify(opts.payload), "utf8").toString("base64url"),
  ];
  const productionWorker = join(process.cwd(), "dist", "aiWorkWorker.cjs");
  const command = existsSync(productionWorker) ? process.execPath : join(process.cwd(), "node_modules", ".bin", "tsx");
  const args = existsSync(productionWorker)
    ? [productionWorker, ...workerArgs]
    : [join(process.cwd(), "server", "aiWorkWorker.ts"), ...workerArgs];
  const child = spawn(command, args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: ["ignore", "inherit", "inherit"],
  });
  child.once("error", (error) => storage.failAiJob(jobId, error));
  child.once("exit", (code, signal) => {
    if (code === 0) return;
    const current = storage.getAiJob(opts.tenantId, jobId, { includeResult: false });
    if (current?.status === "queued" || current?.status === "running") {
      storage.failAiJob(jobId, new Error(`AI worker exited (${signal || code || "unknown"}).`));
    }
  });
  return { jobId, status: "queued", kind: opts.kind, targetLabel: opts.targetLabel, targetUrl };
}

function runAiProviderWorker(action: "test" | "models", tenantId: string, providerId: string): Promise<any> {
  return new Promise((resolveWorker, rejectWorker) => {
    const productionWorker = join(process.cwd(), "dist", "aiProviderWorker.cjs");
    const command = existsSync(productionWorker)
      ? process.execPath
      : join(process.cwd(), "node_modules", ".bin", "tsx");
    const args = existsSync(productionWorker)
      ? [productionWorker, action, tenantId, providerId]
      : [join(process.cwd(), "server", "aiProviderWorker.ts"), action, tenantId, providerId];
    const child = spawn(command, args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: ["ignore", "ignore", "inherit", "ipc"],
    });
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      callback();
    };
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      finish(() => rejectWorker(new Error("Provider request timed out after 30 seconds.")));
    }, 30_000);
    child.once("message", (message: any) => {
      if (message?.ok) finish(() => resolveWorker(message.result));
      else finish(() => rejectWorker(new Error(message?.error || "Provider worker failed.")));
    });
    child.once("error", (error) => finish(() => rejectWorker(error)));
    child.once("exit", (code) => {
      finish(() =>
        rejectWorker(new Error(`Provider worker exited before returning data (code ${code ?? "unknown"}).`)),
      );
    });
  });
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
  for (const p of tries) {
    if (existsSync(p)) return p;
  }
  return tries[0];
}
function loadDictionaries() {
  if (_dictTechnologies && _dictThreatActors)
    return { technologies: _dictTechnologies, threatActors: _dictThreatActors };
  const dir = resolveDataDir();
  try {
    const tech = JSON.parse(readFileSync(join(dir, "dict-technologies.json"), "utf-8"));
    _dictTechnologies = Array.isArray(tech) ? tech : [];
  } catch {
    _dictTechnologies = [];
  }
  try {
    const actors = JSON.parse(readFileSync(join(dir, "dict-threat-actors.json"), "utf-8"));
    _dictThreatActors = Array.isArray(actors) ? actors : [];
  } catch {
    _dictThreatActors = [];
  }
  return { technologies: _dictTechnologies!, threatActors: _dictThreatActors! };
}

interface AuthedRequest extends Request {
  user?: User & { accessMode?: AccessMode; capabilities?: Capability[] };
  accessMode?: AccessMode;
  capabilities?: Capability[];
  /** Internal workspace id. BatchOne does not expose tenant switching. */
  effectiveTenantId?: string;
}

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
    const mfaEnrollmentRequired = !((u as any).mfaEnabled && (u as any).mfaVerifiedAt);
    const mfaChallengeRequired = !!(u as any).mfaEnabled && !(u as any).sessionMfaVerifiedAt;
    return res.status(428).json({
      detail: "Account setup required before platform functions unlock.",
      passwordMustChange: !!(u as any).passwordMustChange,
      mfaRequired: mfaEnrollmentRequired || mfaChallengeRequired,
      mfaEnrollmentRequired,
      mfaChallengeRequired,
    });
  }
  if (!isBatchOneApiAllowed({ method: req.method, path: req.path, accessMode: req.accessMode })) {
    return res.status(403).json({
      detail:
        req.accessMode === "guest"
          ? "Read-only reviewer access is limited to approved review and analysis tasking."
          : "This workflow is outside the Batch One release scope.",
    });
  }
  req.effectiveTenantId = u.tenantId;
  next();
}

function accountSetupRequired(u: any): boolean {
  if (TEST_AUTH_BYPASS) return false;
  return !!u.passwordMustChange || !(u.mfaEnabled && u.mfaVerifiedAt) || (u.mfaEnabled && !u.sessionMfaVerifiedAt);
}

function requireMssOperatingMode(req: AuthedRequest, res: Response): boolean {
  const mode = storage.getTenant(req.effectiveTenantId!)?.operatingMode;
  if (mode === "mss") return true;
  res.status(409).json({ detail: "Client management is available only when the workspace is in MSS mode." });
  return false;
}

function isAccountSetupRoute(path: string): boolean {
  return (
    path === "/api/v1/me" ||
    path === "/api/v1/auth/logout" ||
    path === "/api/v1/auth/change-password" ||
    path === "/api/v1/auth/mfa/setup" ||
    path === "/api/v1/auth/mfa/verify" ||
    path === "/api/v1/auth/mfa/challenge"
  );
}

function requestCrossTenant(req: AuthedRequest): boolean {
  return String(req.query.crossTenant ?? "") === "true" || req.body?.crossTenant === true;
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

function csvCell(value: unknown): string {
  let text =
    value == null
      ? ""
      : Array.isArray(value)
        ? value.join("; ")
        : typeof value === "object"
          ? JSON.stringify(value)
          : String(value);
  // Excel evaluates formula-like values even when quoted in CSV.
  // Prefixing them with an apostrophe prevents formula execution on open.
  if (/^[\t ]*[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/\r?\n/g, " ").replace(/"/g, '""')}"`;
}

function iocsToText(iocs: Record<string, string[] | undefined> | null | undefined): string {
  if (!iocs) return "";
  return Object.entries(iocs)
    .filter(([, values]) => Array.isArray(values) && values.length > 0)
    .map(([kind, values]) => `${kind}: ${(values ?? []).join(" | ")}`)
    .join("; ");
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
  app.get("/api/v1/auth/test-session", (_req, res) => {
    if (!TEST_AUTH_BYPASS) return res.status(404).json({ detail: "not found" });
    const u = storage.createTestSession();
    if (!u) return res.status(404).json({ detail: "no active test user available" });
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

  app.post("/api/v1/auth/login", (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const u = storage.login(parsed.data.email, parsed.data.password, parsed.data.mfaCode);
    if (!u) return res.status(401).json({ detail: "invalid credentials" });
    if ("mfaRequired" in u) {
      return res.status(401).json({
        detail: "MFA code required",
        code: "MFA_REQUIRED",
        mfaRequired: true,
      });
    }
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
      passwordMustChange: TEST_AUTH_BYPASS ? false : !!(u as any).passwordMustChange,
      mfaEnabled: TEST_AUTH_BYPASS ? true : !!(u as any).mfaEnabled,
      mfaVerifiedAt: TEST_AUTH_BYPASS
        ? ((u as any).mfaVerifiedAt ?? new Date().toISOString())
        : ((u as any).mfaVerifiedAt ?? null),
      mfaSessionVerifiedAt: TEST_AUTH_BYPASS ? new Date().toISOString() : ((u as any).sessionMfaVerifiedAt ?? null),
      access_mode: (u as any).accessMode ?? "credentialed",
      capabilities: req.capabilities ?? [],
    };
    if (String(req.query.mfaSetup || "") === "1" && !(u as any).mfaEnabled) {
      body.mfaSetup = storage.getMfaSetup(u.id);
    }
    res.json(body);
  });

  app.patch("/api/v1/workspace/operating-mode", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const parsed = workspaceOperatingModeSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tenant = storage.setTenantOperatingMode(
      req.effectiveTenantId!,
      parsed.data.operatingMode,
      req.user?.email || "admin",
    );
    if (!tenant) return res.status(404).json({ detail: "workspace not found" });
    res.json({ tenant });
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
      return res
        .status(409)
        .json({ detail: "MFA is already enabled. Ask an admin to reset MFA before enrolling a new authenticator." });
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
      const token = /^Bearer\s+(.+)$/i.exec(req.header("authorization") || "")?.[1];
      if (!token || !storage.markSessionMfaVerified(req.user!.id, token)) {
        return res.status(401).json({ detail: "authentication session is no longer active" });
      }
      storage.appendAudit(req.user!.tenantId, req.user!.email, "auth.mfa.enable", req.user!.id, {});
      res.json({ user });
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message ?? e) });
    }
  });

  app.post("/api/v1/auth/mfa/challenge", requireAuth, (req: AuthedRequest, res) => {
    const parsed = mfaVerifySchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const token = /^Bearer\s+(.+)$/i.exec(req.header("authorization") || "")?.[1];
    if (!token) return res.status(401).json({ detail: "missing bearer token" });
    try {
      const user = storage.verifyMfaChallenge(req.user!.id, parsed.data.code, token);
      if (!user) return res.status(404).json({ detail: "MFA enrollment not found" });
      storage.appendAudit(req.user!.tenantId, req.user!.email, "auth.mfa.challenge", req.user!.id, {});
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
      if (/workspace not found|tenant not found/i.test(msg))
        return res.status(400).json({ detail: "workspace not found" });
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
      const user =
        parsed.data.action === "disable" ? storage.disablePlatformUser(uid) : storage.deletePlatformUser(uid);
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
    const global =
      !BATCH_ONE_RELEASE &&
      req.header("x-tenant-id") === "__global__" &&
      hasCapability(req.capabilities, "global_view");
    res.json(
      storage.searchPlatform(req.effectiveTenantId!, q, {
        global,
        role: req.user!.role,
      }),
    );
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
  app.post("/api/v1/ai/providers/:pid/test", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      const provider = storage
        .listAiProviders(req.effectiveTenantId!)
        .find((item: { id: string }) => item.id === String(req.params.pid));
      if (!provider) return res.status(404).json({ detail: "not found" });
      const baseUrlError = await validateAiProviderBaseUrl(provider.provider, provider.baseUrl);
      if (baseUrlError) return res.status(400).json({ detail: baseUrlError });
      res.json(await runAiProviderWorker("test", req.effectiveTenantId!, String(req.params.pid)));
    } catch (error) {
      res.status(502).json({ detail: error instanceof Error ? error.message : "Provider test failed." });
    }
  });
  app.get("/api/v1/ai/providers/:pid/models", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      const provider = storage
        .listAiProviders(req.effectiveTenantId!)
        .find((item: { id: string }) => item.id === String(req.params.pid));
      if (!provider) return res.status(404).json({ detail: "not found" });
      const baseUrlError = await validateAiProviderBaseUrl(provider.provider, provider.baseUrl);
      if (baseUrlError) return res.status(400).json({ detail: baseUrlError });
      res.json(await runAiProviderWorker("models", req.effectiveTenantId!, String(req.params.pid)));
    } catch (error) {
      res.status(502).json({ detail: error instanceof Error ? error.message : "Model discovery failed." });
    }
  });

  // ---- AI task assignments ----
  app.get("/api/v1/ai/assignments", requireAuth, (req: AuthedRequest, res) => {
    const allAssignments = storage.getAiAssignments(req.effectiveTenantId!);
    const assignments = Object.fromEntries(
      AI_TASKS_FOR_RELEASE.map((task) => [task, allAssignments[task]]).filter(
        (entry): entry is [(typeof AI_TASKS_FOR_RELEASE)[number], string] =>
          typeof entry[1] === "string" && entry[1].length > 0,
      ),
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
      AI_TASKS_FOR_RELEASE.map((task) => [task, allAssignments[task]]).filter(
        (entry): entry is [(typeof AI_TASKS_FOR_RELEASE)[number], string] =>
          typeof entry[1] === "string" && entry[1].length > 0,
      ),
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
        OSINT_CATEGORY_ORDER.map((code) => [code, OSINT_CATEGORY_LABELS[code] ?? code]),
      ),
      hostingMode: "single",
    });
  });

  // ---- Batch Two client profile ----
  app.get("/api/v1/client-taxonomy-options", requireAuth, (req: AuthedRequest, res) => {
    if (!requireMssOperatingMode(req, res)) return;
    res.json({ options: storage.listClientTaxonomyOptions(req.effectiveTenantId!) });
  });

  app.post("/api/v1/client-taxonomy-options", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    if (!requireMssOperatingMode(req, res)) return;
    const parsed = clientTaxonomyOptionCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const option = storage.createClientTaxonomyOption(req.effectiveTenantId!, {
        ...parsed.data,
        actor: req.user?.email || "admin",
      });
      res.status(201).json(option);
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message ?? e) });
    }
  });

  app.get("/api/v1/client-profiles", requireAuth, (req: AuthedRequest, res) => {
    if (!requireMssOperatingMode(req, res)) return;
    const profiles = storage.listClientProfiles(req.effectiveTenantId!, {
      includeArchived: req.user?.role === "admin" && String(req.query.includeArchived || "") === "true",
    });
    res.json({
      profiles: profiles.map((profile) =>
        req.user?.role === "admin" ? profile : { ...profile, notificationEmails: [] },
      ),
    });
  });

  app.post("/api/v1/client-profiles", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    if (!requireMssOperatingMode(req, res)) return;
    const parsed = clientProfileCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const profile = storage.createClientProfile(req.effectiveTenantId!, {
        ...parsed.data,
        actor: req.user?.email || "admin",
      });
      res.status(201).json(profile);
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message ?? e) });
    }
  });

  app.post("/api/v1/client-profiles/bulk", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    if (!requireMssOperatingMode(req, res)) return;
    const parsed = clientProfileBulkCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const result = storage.createClientProfilesBulk(req.effectiveTenantId!, parsed.data.profiles, {
      createMissingTaxonomyOptions: parsed.data.createMissingTaxonomyOptions,
      actor: req.user?.email || "admin",
    });
    res.status(207).json({
      ...result,
      requested: parsed.data.profiles.length,
      createdCount: result.created.length,
      failedCount: result.results.filter((item: { status: string }) => item.status === "failed").length,
    });
  });

  app.patch("/api/v1/client-profiles/:cid", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    if (!requireMssOperatingMode(req, res)) return;
    const parsed = clientProfileUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const profile = storage.updateClientProfile(req.effectiveTenantId!, req.params.cid, {
        ...parsed.data,
        actor: req.user?.email || "admin",
      });
      if (!profile) return res.status(404).json({ detail: "client profile not found" });
      res.json(profile);
    } catch (e: any) {
      res.status(400).json({ detail: String(e?.message ?? e) });
    }
  });

  app.delete("/api/v1/client-profiles/:cid", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    if (!requireMssOperatingMode(req, res)) return;
    const profile = storage.updateClientProfile(req.effectiveTenantId!, req.params.cid, {
      isActive: false,
      actor: req.user?.email || "admin",
    });
    if (!profile) return res.status(404).json({ detail: "client profile not found" });
    res.status(204).end();
  });

  app.get("/api/v1/client-profiles/:cid/digests", requireAuth, (req: AuthedRequest, res) => {
    if (!requireMssOperatingMode(req, res)) return;
    res.json({ digests: storage.listClientDigests(req.effectiveTenantId!, req.params.cid) });
  });

  app.get("/api/v1/email-delivery/settings", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    res.json(getSmtpSettings(req.effectiveTenantId!));
  });

  app.put("/api/v1/email-delivery/settings", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const parsed = smtpSettingsUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const settings = saveSmtpSettings(req.effectiveTenantId!, parsed.data);
    storage.appendAudit(req.effectiveTenantId!, req.user?.email || "admin", "email_delivery.settings.update", "smtp", {
      enabled: settings.enabled,
      host: settings.host,
      port: settings.port,
      secure: settings.secure,
      fromAddress: settings.fromAddress,
      hasPassword: settings.hasPassword,
    });
    res.json(settings);
  });

  app.post("/api/v1/email-delivery/test", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      const result = await verifySmtpConnection(req.effectiveTenantId!);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "email_delivery.connection_test",
        "smtp",
        {
          verified: true,
        },
      );
      res.json(result);
    } catch (error) {
      const detail = describeSmtpError(error);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "email_delivery.connection_test_failed",
        "smtp",
        {
          error: detail.slice(0, 500),
        },
      );
      res.status(502).json({ detail });
    }
  });

  app.get("/api/v1/integrations/x", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    res.json(getXIntegrationSettings(req.effectiveTenantId!));
  });

  app.put("/api/v1/integrations/x", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const parsed = xIntegrationSettingsUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const settings = saveXIntegrationSettings(req.effectiveTenantId!, parsed.data);
    storage.bulkUpdateOsintSources(["osrc-1050"], settings.enabled ? "enable" : "disable");
    storage.appendAudit(
      req.effectiveTenantId!,
      req.user?.email || "admin",
      "integration.x.settings.update",
      "x-falconfeeds",
      {
        enabled: settings.enabled,
        configured: settings.configured,
        accountUsername: settings.accountUsername,
      },
    );
    res.json(settings);
  });

  app.post("/api/v1/integrations/x/test", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      const result = await testXIntegration(req.effectiveTenantId!);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "integration.x.connection_test",
        "x-falconfeeds",
        {
          verified: true,
          accountUsername: result.username,
        },
      );
      res.json(result);
    } catch (error: any) {
      const detail = String(error?.message || error).slice(0, 500);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "integration.x.connection_test_failed",
        "x-falconfeeds",
        {
          error: detail,
        },
      );
      res.status(502).json({ detail });
    }
  });

  app.get("/api/v1/integrations/kela", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    res.json(getKelaIntegrationSettings(req.effectiveTenantId!));
  });

  app.put("/api/v1/integrations/kela", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const parsed = kelaIntegrationSettingsUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const settings = await saveKelaIntegrationSettings(req.effectiveTenantId!, parsed.data);
      storage.bulkUpdateOsintSources(["osrc-1058"], settings.enabled ? "enable" : "disable");
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "integration.kela.settings.update",
        "kela-stix",
        {
          enabled: settings.enabled,
          configured: settings.configured,
          feedHost: settings.feedUrl ? new URL(settings.feedUrl).hostname : null,
          authMode: settings.authMode,
        },
      );
      res.json(settings);
    } catch (error: any) {
      res.status(400).json({ detail: String(error?.message || error) });
    }
  });

  app.post("/api/v1/integrations/kela/test", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      const result = await testKelaIntegration(req.effectiveTenantId!);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "integration.kela.connection_test",
        "kela-stix",
        {
          verified: true,
          objectCount: result.objectCount,
        },
      );
      res.json(result);
    } catch (error: any) {
      const detail = String(error?.message || error).slice(0, 500);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "integration.kela.connection_test_failed",
        "kela-stix",
        {
          error: detail,
        },
      );
      res.status(502).json({ detail });
    }
  });

  app.get("/api/v1/integrations/community/:kind", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const kind = communityIntegrationKindSchema.safeParse(req.params.kind);
    if (!kind.success) return res.status(404).json({ detail: "Unknown community connector." });
    res.json(getCommunityIntegrationSettings(req.effectiveTenantId!, kind.data));
  });

  app.put("/api/v1/integrations/community/:kind", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const kind = communityIntegrationKindSchema.safeParse(req.params.kind);
    if (!kind.success) return res.status(404).json({ detail: "Unknown community connector." });
    const parsed = communityIntegrationSettingsUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const settings = await saveCommunityIntegrationSettings(req.effectiveTenantId!, kind.data, parsed.data);
      const sourceIds: Record<string, string[]> = {
        abusech: ["osrc-1040", "osrc-1041", "osrc-1042"],
        taxii: ["osrc-1062"],
        misp: ["osrc-1063"],
        urlscan: [],
        greynoise: [],
      };
      if (sourceIds[kind.data].length)
        storage.bulkUpdateOsintSources(sourceIds[kind.data], settings.enabled ? "enable" : "disable");
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "integration.community.settings.update",
        kind.data,
        { enabled: settings.enabled, configured: settings.configured, mode: settings.mode },
      );
      res.json(settings);
    } catch (error: any) {
      res.status(400).json({ detail: String(error?.message || error) });
    }
  });

  app.post("/api/v1/integrations/community/:kind/test", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const kind = communityIntegrationKindSchema.safeParse(req.params.kind);
    if (!kind.success) return res.status(404).json({ detail: "Unknown community connector." });
    try {
      const result = await testCommunityIntegration(req.effectiveTenantId!, kind.data);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "integration.community.connection_test",
        kind.data,
        { verified: true },
      );
      res.json(result);
    } catch (error: any) {
      const detail = String(error?.message || error).slice(0, 500);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "admin",
        "integration.community.connection_test_failed",
        kind.data,
        { error: detail },
      );
      res.status(502).json({ detail });
    }
  });

  app.post("/api/v1/integrations/community/:kind/lookup", requireAuth, async (req: AuthedRequest, res) => {
    const kind = req.params.kind;
    if (kind !== "urlscan" && kind !== "greynoise")
      return res.status(404).json({ detail: "This connector does not provide analyst lookup." });
    const parsed = communityEnrichmentLookupSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const result = await lookupCommunityEnrichment(req.effectiveTenantId!, kind, parsed.data.observable);
      storage.appendAudit(
        req.effectiveTenantId!,
        req.user?.email || "analyst",
        "integration.community.observable_lookup",
        kind,
        {
          observableType: /^\d/.test(parsed.data.observable)
            ? "ip"
            : /^https?:/.test(parsed.data.observable)
              ? "url"
              : "domain",
        },
      );
      res.json(result);
    } catch (error: any) {
      res.status(502).json({ detail: String(error?.message || error).slice(0, 500) });
    }
  });

  app.get(
    "/api/v1/client-profiles/:cid/email-template.docx",
    requireAuth,
    async (req: AuthedRequest, res, next: NextFunction) => {
      try {
        if (!requireMssOperatingMode(req, res)) return;
        const client = storage.getClientProfile(req.effectiveTenantId!, req.params.cid);
        if (!client) return res.status(404).json({ detail: "client profile not found" });
        const buffer = await buildClientTemplateDocx(client, await loadClientEmailLogo(client.emailLogoUrl));
        const safeName = client.name.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60) || "client";
        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${safeName}_Threat_Intelligence_Email_Template.docx"`,
        );
        res.setHeader("Content-Length", String(buffer.byteLength));
        res.end(buffer);
      } catch (error) {
        next(error);
      }
    },
  );

  app.get(
    "/api/v1/client-profiles/:cid/email-template.eml",
    requireAuth,
    async (req: AuthedRequest, res, next: NextFunction) => {
      try {
        if (!requireMssOperatingMode(req, res)) return;
        const client = storage.getClientProfile(req.effectiveTenantId!, req.params.cid);
        if (!client) return res.status(404).json({ detail: "client profile not found" });
        const buffer = buildClientTemplateEml(client, await loadClientEmailLogo(client.emailLogoUrl));
        const safeName = client.name.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60) || "client";
        res.setHeader("Content-Type", "message/rfc822");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${safeName}_Threat_Intelligence_Email_Template.eml"`,
        );
        res.setHeader("Content-Length", String(buffer.byteLength));
        res.end(buffer);
      } catch (error) {
        next(error);
      }
    },
  );

  app.post(
    "/api/v1/client-profiles/:cid/email-template.docx",
    requireAuth,
    async (req: AuthedRequest, res, next: NextFunction) => {
      if (!requireAdmin(req, res)) return;
      if (!requireMssOperatingMode(req, res)) return;
      const client = storage.getClientProfile(req.effectiveTenantId!, req.params.cid);
      if (!client) return res.status(404).json({ detail: "client profile not found" });
      try {
        const parsed = await parseClientDigestTemplateDocx({
          fileName: typeof req.body?.fileName === "string" ? req.body.fileName : "",
          contentBase64: typeof req.body?.contentBase64 === "string" ? req.body.contentBase64 : "",
        });
        const profile = storage.updateClientProfile(req.effectiveTenantId!, client.id, {
          digestSubjectTemplate: parsed.subjectTemplate,
          digestBodyTemplate: parsed.bodyTemplate,
          actor: req.user?.email || "admin",
        });
        storage.appendAudit(
          req.effectiveTenantId!,
          req.user?.email || "admin",
          "client_email_template.upload",
          client.id,
          {
            fileName: String(req.body?.fileName || "").slice(0, 160),
            placeholders: parsed.placeholders,
          },
        );
        res.status(201).json({ ...parsed, profile });
      } catch (error) {
        if (error instanceof ClientDigestTemplateUploadError) {
          return res.status(error.statusCode).json({ detail: error.message });
        }
        next(error);
      }
    },
  );

  app.post(
    "/api/v1/client-profiles/:cid/email-logo",
    requireAuth,
    async (req: AuthedRequest, res, next: NextFunction) => {
      if (!requireAdmin(req, res)) return;
      if (!requireMssOperatingMode(req, res)) return;
      const client = storage.getClientProfile(req.effectiveTenantId!, req.params.cid);
      if (!client) return res.status(404).json({ detail: "client profile not found" });
      const fileName = typeof req.body?.fileName === "string" ? req.body.fileName : "";
      const contentBase64 = typeof req.body?.contentBase64 === "string" ? req.body.contentBase64 : "";
      try {
        const uploaded = await clientLogoUploads.store({ fileName, contentBase64 });
        const logoUrl = `${uploaded.publicUrl}?v=${Date.now()}`;
        const profile = storage.setClientEmailLogo(
          req.effectiveTenantId!,
          client.id,
          logoUrl,
          req.user?.email || "admin",
        );
        await clientLogoUploads.delete(client.emailLogoUrl);
        res.status(201).json({ emailLogoUrl: logoUrl, bytes: uploaded.bytes, profile });
      } catch (error) {
        if (error instanceof UploadValidationError) {
          return res.status(error.statusCode).json({ detail: error.message });
        }
        next(error);
      }
    },
  );

  app.delete(
    "/api/v1/client-profiles/:cid/email-logo",
    requireAuth,
    async (req: AuthedRequest, res, next: NextFunction) => {
      if (!requireAdmin(req, res)) return;
      if (!requireMssOperatingMode(req, res)) return;
      const client = storage.getClientProfile(req.effectiveTenantId!, req.params.cid);
      if (!client) return res.status(404).json({ detail: "client profile not found" });
      try {
        await clientLogoUploads.delete(client.emailLogoUrl);
        storage.setClientEmailLogo(req.effectiveTenantId!, client.id, null, req.user?.email || "admin");
        res.status(204).end();
      } catch (error) {
        next(error);
      }
    },
  );

  app.use(
    "/client-email-logos",
    express.static(CLIENT_EMAIL_LOGOS_DIR, {
      maxAge: "7d",
      setHeaders: (response) => response.setHeader("Cache-Control", "public, max-age=604800, immutable"),
    }),
  );

  app.post("/api/v1/client-profiles/:cid/digests/generate", requireAuth, (req: AuthedRequest, res) => {
    if (!requireMssOperatingMode(req, res)) return;
    const parsed = clientDigestGenerateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const client = storage.getClientProfile(req.effectiveTenantId!, req.params.cid);
    if (!client) return res.status(404).json({ detail: "client profile not found" });
    if (client.notificationEmails.length === 0) {
      return res.status(400).json({ detail: "add at least one notification email before generating a client digest" });
    }
    const tenantId = req.effectiveTenantId!;
    const cadence = parsed.data.cadence ?? client.digestCadence;
    const range: ChatRangeKey =
      cadence === "daily" ? "1d" : cadence === "weekly" ? "7d" : cadence === "biweekly" ? "2w" : "1m";
    const targetLabel = `${client.name} ${cadence} client-impact brief`;
    const jobId = storage.createAiJob({
      tenantId,
      kind: "client_digest_generation",
      payload: {
        clientId: client.id,
        cadence,
        findingIds: parsed.data.findingIds,
        analysisMode: "client_impact",
      },
      createdBy: req.user?.email ?? null,
      targetLabel,
      targetUrl: null,
    });
    const targetUrl = `/#/client-briefs?client=${encodeURIComponent(client.id)}&job=${encodeURIComponent(jobId)}`;
    storage.updateAiJobTarget(jobId, { targetUrl });
    runChatTriageWorker({
      jobId,
      tenantId,
      payload: {
        range,
        findingIds: parsed.data.findingIds,
        analysisMode: "client_impact",
        clientIds: [client.id],
        actor: req.user?.email ?? "analyst",
        digestCadence: cadence,
      },
    });
    res.status(202).json({ jobId, status: "queued", kind: "client_digest_generation", targetLabel, targetUrl });
  });

  app.patch("/api/v1/client-profiles/:cid/digests/:did", requireAuth, (req: AuthedRequest, res) => {
    if (!requireMssOperatingMode(req, res)) return;
    const parsed = clientDigestPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const digest = storage.updateClientDigest(req.effectiveTenantId!, req.params.cid, req.params.did, {
      ...parsed.data,
      actor: req.user?.email || "analyst",
    });
    if (!digest) return res.status(404).json({ detail: "client digest not found" });
    res.json(digest);
  });

  app.get(
    "/api/v1/client-profiles/:cid/digests/:did/email.eml",
    requireAuth,
    async (req: AuthedRequest, res, next: NextFunction) => {
      try {
        if (!requireMssOperatingMode(req, res)) return;
        const client = storage.getClientProfile(req.effectiveTenantId!, req.params.cid);
        if (!client) return res.status(404).json({ detail: "client profile not found" });
        const digest = storage
          .listClientDigests(req.effectiveTenantId!, client.id)
          .find((item: { id: string }) => item.id === req.params.did);
        if (!digest) return res.status(404).json({ detail: "client digest not found" });
        const buffer = buildClientDigestEml(client, digest, await loadClientEmailLogo(client.emailLogoUrl));
        const safeName = client.name.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60) || "client";
        res.setHeader("Content-Type", "message/rfc822");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${safeName}_${digest.cadence}_Threat_Intelligence_Draft.eml"`,
        );
        res.setHeader("Cache-Control", "private, no-store");
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Content-Length", String(buffer.byteLength));
        res.end(buffer);
      } catch (error) {
        next(error);
      }
    },
  );

  app.post(
    "/api/v1/client-profiles/:cid/digests/:did/send",
    requireAuth,
    async (req: AuthedRequest, res, next: NextFunction) => {
      try {
        if (!requireAdmin(req, res)) return;
        if (!requireMssOperatingMode(req, res)) return;
        const tenantId = req.effectiveTenantId!;
        const actor = req.user?.email || "admin";
        const client = storage.getClientProfile(tenantId, req.params.cid);
        if (!client) return res.status(404).json({ detail: "client profile not found" });
        const digest = storage
          .listClientDigests(tenantId, client.id)
          .find((item: { id: string }) => item.id === req.params.did);
        if (!digest) return res.status(404).json({ detail: "client digest not found" });
        if (digest.status !== "approved") {
          return res.status(409).json({ detail: "approve the client brief before sending" });
        }
        const existingJob = storage.getActiveAiJobByKindAndPayload(tenantId, "client_digest_delivery", {
          clientId: client.id,
          digestId: digest.id,
        });
        if (existingJob) {
          return res.status(202).json({
            jobId: existingJob.id,
            status: existingJob.status,
            kind: existingJob.kind,
            targetLabel: existingJob.targetLabel,
            targetUrl: existingJob.targetUrl,
            alreadyQueued: true,
          });
        }
        const cooldownSeconds = getSmtpCooldownSeconds(tenantId);
        if (cooldownSeconds > 0) {
          storage.appendAudit(tenantId, actor, "client_digest.send_suppressed", digest.id, {
            clientId: client.id,
            reason: "smtp_cooldown_active",
            retryAfterSeconds: cooldownSeconds,
          });
          res.setHeader("Retry-After", String(cooldownSeconds));
          return res.status(429).json({
            detail:
              "SMTP delivery is cooling down after a temporary provider failure. No new provider connection was attempted.",
            code: "smtp_cooldown_active",
            retryable: true,
            retryAfterSeconds: cooldownSeconds,
          });
        }
        const job = runAiJob({
          tenantId,
          kind: "client_digest_delivery",
          payload: { clientId: client.id, digestId: digest.id },
          createdBy: actor,
          targetLabel: `Send brief — ${client.name}`,
          targetUrl: "/#/client-briefs",
          work: async (jobId) => {
            storage.setAiJobProgress(jobId, 10);
            const currentClient = storage.getClientProfile(tenantId, client.id);
            const currentDigest = storage
              .listClientDigests(tenantId, client.id)
              .find((item: { id: string }) => item.id === digest.id);
            if (!currentClient || !currentDigest) throw new Error("The client brief is no longer available.");
            if (currentDigest.status !== "approved") {
              throw new Error(
                "The client brief changed after delivery was queued. Review and approve it again before sending.",
              );
            }
            const activeCooldown = getSmtpCooldownSeconds(tenantId);
            if (activeCooldown > 0) {
              storage.appendAudit(tenantId, actor, "client_digest.send_suppressed", currentDigest.id, {
                clientId: currentClient.id,
                reason: "smtp_cooldown_active",
                retryAfterSeconds: activeCooldown,
              });
              const cooldownError = new Error(
                "SMTP delivery is cooling down after a temporary provider failure.",
              ) as Error & {
                code?: string;
                retryable?: boolean;
                retryAfterSeconds?: number;
              };
              cooldownError.code = "smtp_cooldown_active";
              cooldownError.retryable = true;
              cooldownError.retryAfterSeconds = activeCooldown;
              throw cooldownError;
            }
            storage.setAiJobProgress(jobId, 25);
            const message = buildClientDigestEmailContent(
              currentClient,
              currentDigest,
              await loadClientEmailLogo(currentClient.emailLogoUrl),
            );
            storage.setAiJobProgress(jobId, 45);
            let delivery: Awaited<ReturnType<typeof sendSmtpEmail>>;
            try {
              delivery = await sendSmtpEmail(tenantId, message);
            } catch (error: any) {
              const failure = classifySmtpFailure(error);
              if (failure.retryable && failure.retryAfterSeconds) setSmtpCooldown(tenantId, failure.retryAfterSeconds);
              storage.appendAudit(tenantId, actor, "client_digest.send_failed", currentDigest.id, {
                clientId: currentClient.id,
                recipientCount: currentDigest.recipients.length,
                error: String(error?.message || error).slice(0, 500),
                retryable: failure.retryable,
                code: failure.code,
              });
              const deliveryError = new Error(describeSmtpError(error)) as Error & {
                code?: string;
                retryable?: boolean;
                retryAfterSeconds?: number;
              };
              deliveryError.name = "SmtpDeliveryError";
              deliveryError.code = failure.code;
              deliveryError.retryable = failure.retryable;
              deliveryError.retryAfterSeconds = failure.retryAfterSeconds;
              throw deliveryError;
            }
            storage.setAiJobProgress(jobId, 90);
            clearSmtpCooldown(tenantId);
            storage.updateClientDigest(tenantId, currentClient.id, currentDigest.id, { status: "sent", actor });
            storage.appendAudit(tenantId, actor, "client_digest.send", currentDigest.id, {
              clientId: currentClient.id,
              recipientCount: currentDigest.recipients.length,
              acceptedCount: delivery.accepted.length,
              rejectedCount: delivery.rejected.length,
              messageId: delivery.messageId,
            });
            return {
              status: "sent",
              recipientCount: currentDigest.recipients.length,
              acceptedCount: delivery.accepted.length,
              rejectedCount: delivery.rejected.length,
              messageId: delivery.messageId,
            };
          },
        });
        res.status(202).json(job);
      } catch (error) {
        next(error);
      }
    },
  );

  // Compatibility view for older clients that expect one workspace profile.
  app.get("/api/v1/client-profile", requireAuth, (req: AuthedRequest, res) => {
    if (!requireMssOperatingMode(req, res)) return;
    const profile = storage.getClientProfile(req.effectiveTenantId!);
    if (!profile) return res.status(404).json({ detail: "client profile not found" });
    // Notification contacts are operationally sensitive and are not needed
    // for read-only review or threat-intel analysis.
    res.json(req.user?.role === "admin" ? profile : { ...profile, notificationEmails: [] });
  });

  app.patch("/api/v1/client-profile", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    if (!requireMssOperatingMode(req, res)) return;
    const parsed = clientProfileUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const current = storage.getClientProfile(req.effectiveTenantId!);
    if (!current) return res.status(404).json({ detail: "client profile not found" });
    const updated = storage.updateClientProfile(req.effectiveTenantId!, current.id, {
      ...parsed.data,
      actor: req.user?.email || "admin",
    });
    if (!updated) return res.status(404).json({ detail: "client profile not found" });
    res.json(updated);
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
    storage.appendAudit(req.effectiveTenantId!, req.user?.email || "admin", `osint.sources.${action}`, null, {
      ids,
      changed,
    });
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
    try {
      res.json(storage.getOsintSourceScorecard({ tenantId }));
    } catch (e) {
      next(e);
    }
  });
  app.get("/api/v1/osint/sources/quadrant", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const tenantId = tenantScopeForRequest(req, res);
    if (tenantId === null) return;
    try {
      res.json(storage.getOsintSourceQuadrant({ tenantId }));
    } catch (e) {
      next(e);
    }
  });
  app.get("/api/v1/osint/sources/overlap", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const tenantId = tenantScopeForRequest(req, res);
    if (tenantId === null) return;
    try {
      res.json(storage.getOsintSourceOverlap({ tenantId }));
    } catch (e) {
      next(e);
    }
  });
  app.get("/api/v1/osint/sources/heatmaps", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    const tenantId = tenantScopeForRequest(req, res);
    if (tenantId === null) return;
    try {
      res.json(storage.getOsintSourceHeatmaps({ tenantId }));
    } catch (e) {
      next(e);
    }
  });

  // v2.30 — Admin-triggered bulk re-analyse last N days. Async — returns the
  // job id immediately; UI polls /api/v1/osint/reanalyze-jobs/:id for status.
  app.post("/api/v1/osint/findings/reanalyze", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    if (!requireAdmin(req, res)) return;
    const sinceDays = Math.max(1, Math.min(Number(req.body?.sinceDays ?? 30), 365));
    try {
      const job = storage.createOsintReanalyzeJob(req.effectiveTenantId!, { sinceDays });
      storage.appendAudit(req.effectiveTenantId!, req.user?.email || "admin", "osint.reanalyze.start", job.id, {
        sinceDays,
        total: job.totalCount,
      });
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
  // v2.7 broad OSINT ingest — walks the full 514-source catalog with deep
  // custom parsers + a generic RSS/Atom/RDF/JSON adapter, persists per tenant.
  // Tracked through the durable operations job table so history survives restarts.
  app.post("/api/v1/admin/osint/ingest", requireAuth, async (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const days = Math.min(Math.max(Number(req.body?.days ?? 365), 1), 730);
    const maxPerSource = Math.min(Math.max(Number(req.body?.maxPerSource ?? 60), 5), 500);
    const maxTotal = Math.min(Math.max(Number(req.body?.maxTotal ?? 10000), 100), 50000);
    const actor = req.user?.email || "admin";
    const workspaceId = req.effectiveTenantId!;
    const existing = storage
      .listOperationsJobs(workspaceId, { max: 100 })
      .find((job: any) => job.kind === "osint_global_ingest" && (job.status === "queued" || job.status === "running"));
    if (existing)
      return res
        .status(202)
        .json({ status: "already_running", jobId: existing.id, startedAt: existing.startedAt || existing.createdAt });
    const jobId = storage.createAiJob({
      tenantId: workspaceId,
      kind: "osint_global_ingest",
      payload: { days, maxPerSource, maxTotal },
      createdBy: actor,
      targetLabel: "Refresh all sources",
      targetUrl: "#/osint?tab=sources",
    });
    (async () => {
      try {
        storage.markAiJobRunning(jobId);
        const result = await storage.runGlobalOsintIngest({
          workspaceId,
          days,
          maxPerSource,
          maxTotal,
          actor,
          onProgress: (progress: { attempted: number; total: number; parsed: number; feedsOk: number }) => {
            const current = storage.getAiJob(workspaceId, jobId, { includeResult: false });
            if (!current || current.status === "cancelled") throw new Error("Source refresh cancelled by operator.");
            const progressPct =
              progress.total > 0
                ? Math.min(99, Math.max(0, Math.round((progress.attempted / progress.total) * 100)))
                : 0;
            storage.setAiJobProgressDetail(jobId, progressPct, progress);
          },
        });
        storage.completeAiJob(jobId, result);
      } catch (e: any) {
        storage.failAiJob(jobId, e);
      }
    })();
    res.status(202).json({ status: "started", jobId, params: { days, maxPerSource, maxTotal } });
  });

  app.get("/api/v1/admin/osint/ingest/status", requireAuth, (req: AuthedRequest, res) => {
    if (!requireAdmin(req, res)) return;
    const job = storage.getLatestAiJobByKind(req.effectiveTenantId!, "osint_global_ingest");
    const progressDetail = job?.status === "running" ? (job?.result?.progressDetail ?? null) : null;
    res.json({
      jobId: job?.id ?? null,
      busy: job?.status === "queued" || job?.status === "running",
      startedAt: job?.startedAt ?? null,
      finishedAt: job?.completedAt ?? null,
      summary: job?.status === "completed" ? job.result : null,
      error: job?.error?.message ?? null,
      progressPct: job?.progressPct ?? 0,
      progressDetail,
    });
  });
  app.get("/api/v1/osint/findings", requireAuth, (req: AuthedRequest, res) => {
    res.json({
      findings: storage.listOsintFindings(req.effectiveTenantId!, {
        severity: (req.query.severity as string) || undefined,
        status: (req.query.status as string) || undefined,
        tech: (req.query.tech as string) || undefined,
        sourceId: (req.query.sourceId as string) || undefined,
        category: (req.query.category as string) || undefined,
        publishedAfter: (req.query.publishedAfter as string) || undefined,
      }),
    });
  });
  app.get("/api/v1/osint/findings/export.csv", requireAuth, (req: AuthedRequest, res) => {
    const ids =
      typeof req.query.findingIds === "string"
        ? new Set(
            req.query.findingIds
              .split(",")
              .map((v) => v.trim())
              .filter(Boolean),
          )
        : null;
    const findings = storage
      .listOsintFindings(req.effectiveTenantId!, {
        severity: (req.query.severity as string) || undefined,
        status: (req.query.status as string) || undefined,
        tech: (req.query.tech as string) || undefined,
        sourceId: (req.query.sourceId as string) || undefined,
        category: (req.query.category as string) || undefined,
        publishedAfter: (req.query.publishedAfter as string) || undefined,
      })
      .filter((f) => !ids || ids.has(f.id));
    const clientNames = new Map(
      storage
        .listClientProfiles(req.effectiveTenantId!, { includeArchived: true })
        .map((profile) => [profile.id, profile.name]),
    );
    const header = [
      "Threat intel title",
      "Source",
      "Source URL",
      "Published date",
      "AI triage date",
      "Threat analyst assessment date",
      "Effective severity",
      "Publisher severity",
      "Technical severity",
      "Client impact severity",
      "Analyst final severity",
      "Severity rationale",
      "Status",
      "Client tags",
      "IoCs",
      "Analyst disposition",
      "Analyst confidence",
      "Business impact",
      "Next action",
      "Analyst analysed result",
      "AI summary",
      "AI recommendation",
    ];
    const rows = findings.map((f) => [
      f.title,
      f.sourceName,
      f.url ?? "",
      f.publishedAt,
      f.aiAnalyzedAt ?? "",
      f.analystAssessedAt ?? f.analystEditedAt ?? "",
      f.severity,
      f.publisherSeverity ?? "",
      f.technicalSeverity ?? "",
      f.clientImpactSeverity ?? "",
      f.analystFinalSeverity ?? "",
      f.analystSeverityRationale ?? "",
      f.status,
      (f.clientTags ?? []).map((clientId) => clientNames.get(clientId) ?? "Legacy client tag"),
      iocsToText(f.iocs as any),
      f.analystDisposition ?? "",
      f.analystConfidence ?? "",
      f.analystImpact ?? "",
      f.analystNextAction ?? "",
      f.analystAssessment ?? "",
      f.aiSummary ?? "",
      f.aiRecommendation ?? "",
    ]);
    const csv = [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="optrasight-threat-intel-${new Date().toISOString().slice(0, 10)}.csv"`,
    );
    res.send(`\uFEFF${csv}`);
  });
  const selectedExchangeFindings = (req: AuthedRequest) => {
    const ids = String(req.query.findingIds || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    if (ids.length === 0) throw new Error("Select at least one finding.");
    if (ids.length > 200) throw new Error("A single STIX export supports up to 200 findings.");
    const uniqueIds = new Set(ids);
    const findings = storage
      .listOsintFindings(req.effectiveTenantId!)
      .filter((finding: OsintFindingDTO) => uniqueIds.has(finding.id));
    if (findings.length !== uniqueIds.size) throw new Error("One or more findings were not found in this workspace.");
    return findings;
  };
  app.get("/api/v1/exchange/stix/preview", requireAuth, (req: AuthedRequest, res) => {
    try {
      const result = buildOsintStixBundle(selectedExchangeFindings(req), "OptraSight Threat Intelligence Unit");
      res.json({
        findingCount: result.findingCount,
        objectCount: result.bundle.objects.length,
        indicatorCount: result.indicatorCount,
        attackPatternCount: result.attackPatternCount,
        objectCounts: result.objectCounts,
        warnings: result.warnings,
        errors: result.errors,
        valid: result.valid,
      });
    } catch (error: any) {
      res.status(400).json({ detail: String(error?.message || error) });
    }
  });
  app.get("/api/v1/exchange/stix/export", requireAuth, (req: AuthedRequest, res) => {
    try {
      const findings = selectedExchangeFindings(req);
      const result = buildOsintStixBundle(findings, "OptraSight Threat Intelligence Unit");
      if (!result.valid) return res.status(422).json({ detail: "STIX validation failed.", errors: result.errors });
      storage.appendAudit(req.effectiveTenantId!, req.user?.email || "operator", "osint.stix.export", null, {
        findingCount: result.findingCount,
        objectCount: result.bundle.objects.length,
      });
      res.setHeader("Content-Type", "application/stix+json;version=2.1");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="optrasight-stix-${new Date().toISOString().slice(0, 10)}.json"`,
      );
      res.send(JSON.stringify(result.bundle, null, 2));
    } catch (error: any) {
      res.status(400).json({ detail: String(error?.message || error) });
    }
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
    const parsed = osintFindingPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    if (
      storage.getTenant(req.effectiveTenantId!)?.operatingMode === "individual" &&
      (parsed.data.clientTags !== undefined || parsed.data.clientMatchDecisions !== undefined)
    ) {
      return res.status(409).json({ detail: "Client tagging is available only when the workspace is in MSS mode." });
    }
    const editedBy = req.user?.email || "analyst";
    try {
      const existing = storage.getOsintFinding(req.effectiveTenantId!, req.params.fid);
      if (!existing) return res.status(404).json({ detail: "not found" });
      if (existing.status === "escalated") {
        return res.status(409).json({
          detail:
            "Escalated intelligence is immutable. Use a separately authorised reopen workflow before making corrections.",
          code: "finding_integrity_locked",
        });
      }
      const updated = storage.updateOsintFinding(req.effectiveTenantId!, req.params.fid, parsed.data, editedBy);
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
    if (!storage.resolveAiProvider(tid, "osint_analysis"))
      return res
        .status(409)
        .json({ detail: "No AI provider configured for osint_analysis. Configure one in AI Setup." });
    const activeAnalysis = storage
      .listOperationsJobs(tid, { max: 100 })
      .find(
        (candidate: any) =>
          candidate.source === "ai_job" &&
          candidate.kind === "osint_analysis" &&
          (candidate.status === "queued" || candidate.status === "running"),
      );
    if (activeAnalysis) {
      return res.status(409).json({
        detail: "An OSINT AI analysis job is already running. Wait for it to finish or cancel it from Job Control.",
        jobId: activeAnalysis.id,
      });
    }
    const label =
      ids.length > 0
        ? `OSINT AI analysis — ${ids.length} selected`
        : `OSINT AI analysis — ${onlyUnanalyzed ? "unanalyzed findings" : "all findings"}`;
    const job = runOsintAnalysisWorker({
      tenantId: tid,
      payload: parsed.data,
      createdBy: req.user?.email ?? null,
      targetLabel: label,
      targetUrl: ids.length === 1 ? `/#/osint?finding=${encodeURIComponent(ids[0])}` : "/#/osint",
    });
    storage.appendAudit(tid, req.user?.email || "system", "osint.analyze.ai_job.start", job.jobId, {
      onlyUnanalyzed,
      idCount: ids.length,
    });
    res.status(202).json(job);
  });
  // ---- Hunt queries ----
  app.get("/api/v1/osint/hunt-queries", requireAuth, (req: AuthedRequest, res) => {
    res.json({ queries: storage.listHuntQueries(req.effectiveTenantId!) });
  });
  // The OSINT path remains as a compatibility alias for older clients. New
  // product flows use the Detection Rules route as the canonical endpoint.
  app.post(
    ["/api/v1/detection-rules/generate", "/api/v1/osint/hunt-queries"],
    requireAuth,
    async (req: AuthedRequest, res) => {
      const parsed = huntQueryCreateSchema.safeParse(req.body || {});
      if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
      const tid = req.effectiveTenantId!;
      const job = runIsolatedAiWork({
        tenantId: tid,
        kind: "detection_rule_generation",
        payload: { ...parsed.data, actor: req.user!.email },
        createdBy: req.user?.email ?? null,
        targetLabel: `Detection rule — ${parsed.data.findingIds.length} finding${parsed.data.findingIds.length === 1 ? "" : "s"}`,
        targetUrl: "/#/detection-rules",
      });
      res.status(202).json(job);
    },
  );

  // ---- Batch Two Detection Rules ----
  app.get("/api/v1/detection-rules", requireAuth, (req: AuthedRequest, res) => {
    const status = typeof req.query.status === "string" ? req.query.status : undefined;
    res.json({
      rules: storage.listDetectionRules(req.effectiveTenantId!, status ? { status: status as any } : undefined),
    });
  });

  app.get("/api/v1/detection-rules/:rid", requireAuth, (req: AuthedRequest, res) => {
    const rule = storage.getDetectionRule(req.effectiveTenantId!, req.params.rid);
    if (!rule) return res.status(404).json({ detail: "detection rule not found" });
    res.json(rule);
  });

  app.post("/api/v1/detection-rules", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    const parsed = detectionRuleCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const individualMode = storage.getTenant(req.effectiveTenantId!)?.operatingMode === "individual";
    if (individualMode && (parsed.data.clientIds?.length ?? 0) > 0) {
      return res.status(409).json({ detail: "Client assignment is available only when the workspace is in MSS mode." });
    }
    try {
      const rule = await storage.createDetectionRule(req.effectiveTenantId!, {
        title: parsed.data.title,
        description: parsed.data.description,
        findingIds: parsed.data.findingIds,
        languages: parsed.data.languages,
        severity: parsed.data.severity,
        affectedTech: parsed.data.affectedTech,
        threatActors: parsed.data.threatActors,
        clientIds: parsed.data.clientIds,
        generate: parsed.data.generate,
        createdBy: req.user?.email || "analyst",
      });
      res.status(201).json(rule);
    } catch (e) {
      next(e);
    }
  });

  app.patch("/api/v1/detection-rules/:rid", requireAuth, (req: AuthedRequest, res) => {
    const parsed = detectionRulePatchSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const current = storage.getDetectionRule(req.effectiveTenantId!, req.params.rid);
    if (!current) return res.status(404).json({ detail: "detection rule not found" });
    if (
      (parsed.data.status === "validated" || parsed.data.status === "approved") &&
      req.user?.role !== "admin" &&
      req.user?.role !== "detection_engineer"
    ) {
      return res
        .status(403)
        .json({ detail: "detection engineer or platform admin role required for validation and approval" });
    }
    const individualMode = storage.getTenant(req.effectiveTenantId!)?.operatingMode === "individual";
    if (individualMode && parsed.data.clientIds !== undefined) {
      return res.status(409).json({ detail: "Client assignment is available only when the workspace is in MSS mode." });
    }
    const resultingClientIds = parsed.data.clientIds ?? current.clientIds;
    if (
      !individualMode &&
      (parsed.data.status === "validated" || parsed.data.status === "approved") &&
      resultingClientIds.length === 0
    ) {
      return res
        .status(400)
        .json({ detail: "assign at least one client before validating or approving a detection rule" });
    }
    if (parsed.data.status === "validated" || parsed.data.status === "approved") {
      const readiness = storage.getDetectionRuleReadiness(req.effectiveTenantId!, req.params.rid);
      if (!readiness.ready) {
        return res.status(400).json({
          detail: individualMode
            ? "a passing current-version workspace validation is required before this lifecycle transition"
            : "every assigned client requires a passing current-version validation before this lifecycle transition",
          missingClientIds: readiness.missingClientIds,
        });
      }
    }
    const rule = storage.updateDetectionRule(req.effectiveTenantId!, req.params.rid, {
      ...parsed.data,
      actor: req.user?.email || "analyst",
    });
    res.json(rule);
  });

  app.put("/api/v1/detection-rules/:rid/validation", requireAuth, (req: AuthedRequest, res, next: NextFunction) => {
    if (req.user?.role !== "admin" && req.user?.role !== "detection_engineer") {
      return res.status(403).json({ detail: "detection engineer or platform admin role required" });
    }
    const parsed = detectionRuleValidationSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    try {
      const rule = storage.upsertDetectionRuleValidation(req.effectiveTenantId!, req.params.rid, {
        ...parsed.data,
        actor: req.user?.email || "detection-engineer",
      });
      if (!rule) return res.status(404).json({ detail: "detection rule not found" });
      res.json(rule);
    } catch (error) {
      next(error);
    }
  });

  app.delete("/api/v1/detection-rules/:rid", requireAuth, (req: AuthedRequest, res) => {
    const ok = storage.deleteDetectionRule(req.effectiveTenantId!, req.params.rid, req.user?.email || "analyst");
    if (!ok) return res.status(404).json({ detail: "detection rule not found" });
    res.status(204).end();
  });

  app.post("/api/v1/detection-rules/:rid/deploy", requireAuth, (req: AuthedRequest, res) => {
    if (req.user?.role !== "admin" && req.user?.role !== "detection_engineer") {
      return res.status(403).json({ detail: "detection engineer or platform admin role required" });
    }
    const parsed = detectionRuleDeploySchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const result = storage.deployDetectionRule(req.effectiveTenantId!, req.params.rid, {
      ...parsed.data,
      actor: req.user?.email || "analyst",
    });
    if ("error" in result) return res.status(400).json({ detail: result.error });
    res.json(result);
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

  app.get(
    "/api/v1/threat-actors/:aid/export.docx",
    requireAuth,
    async (req: AuthedRequest, res, next: NextFunction) => {
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
    },
  );

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
          try {
            unlinkSync(join(PORTRAITS_DIR, f));
          } catch {
            /* swallow */
          }
        }
      }
    } catch {
      /* ok */
    }
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

  // Compatibility tombstone: browser-supplied portrait bytes are intentionally
  // unsupported. Curated assets and server-side AI generation remain available.
  app.post("/api/v1/threat-actors/:aid/portrait/upload", requireAuth, (_req: AuthedRequest, res) => {
    res.status(410).json({
      detail: "Manual portrait upload is disabled. Use a curated portrait or AI portrait generation.",
      code: "manual_portrait_upload_disabled",
    });
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
          try {
            unlinkSync(join(PORTRAITS_DIR, f));
          } catch {
            /* swallow */
          }
        }
      }
    } catch {
      /* ok */
    }
    storage.clearThreatActorPortrait(tid, aid);
    res.status(204).end();
  });

  // Serve generated portraits as static PNGs. Public-ish: anyone with the
  // direct URL can fetch (they're already gated by needing the actor id and a
  // valid session to retrieve the URL in the first place). Aggressive cache
  // because URLs are content-addressed by actor id and only change on re-gen.
  app.use(
    "/portraits",
    express.static(PORTRAITS_DIR, {
      maxAge: "7d",
      setHeaders: (res) => {
        res.setHeader("Cache-Control", "public, max-age=604800, immutable");
      },
    }),
  );
  // Backward-compatible alias for deployments or browser cache entries that
  // reference the physical data path. The DB persists /portraits/*, but this
  // keeps /data/portraits/* from rendering as broken images after exports.
  app.use(
    "/data/portraits",
    express.static(PORTRAITS_DIR, {
      maxAge: "7d",
      setHeaders: (res) => {
        res.setHeader("Cache-Control", "public, max-age=604800, immutable");
      },
    }),
  );

  // v2.30.6 — accepts an optional providerId override for one-off re-enrich
  // with a different model (e.g. DeepSeek vs Perplexity).
  app.post("/api/v1/threat-actors/:aid/enrich", requireAuth, (req: AuthedRequest, res) => {
    const parsed = threatActorEnrichSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ detail: fromZodError(parsed.error).message });
    const tid = req.effectiveTenantId!;
    const aid = req.params.aid;
    const head = storage.getThreatActor(tid, aid);
    if (!head) return res.status(404).json({ detail: "threat actor not found" });
    const job = runIsolatedAiWork({
      tenantId: tid,
      kind: "threat_actor_enrichment",
      payload: {
        actorId: aid,
        force: parsed.data.force,
        providerId: parsed.data.providerId ?? null,
        actor: req.user!.email,
      },
      createdBy: req.user?.email ?? null,
      targetLabel: `TAP re-analysis — ${head.primaryName}`,
      targetUrl: `/#/threat-actors?focus=${encodeURIComponent(aid)}`,
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
    const ok = storage.deleteThreatActorTool(
      req.effectiveTenantId!,
      req.params.aid,
      req.params.toolId,
      req.user!.email,
    );
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
    const ok = storage.deleteThreatActorCampaign(
      req.effectiveTenantId!,
      req.params.aid,
      req.params.cid,
      req.user!.email,
    );
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
    const ok = storage.deleteThreatActorReference(
      req.effectiveTenantId!,
      req.params.aid,
      req.params.rid,
      req.user!.email,
    );
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
    const allowed: ChatRangeKey[] = ["1d", "7d", "2w", "1m", "1q", "1y", "all"];
    if (!allowed.includes(range)) return res.status(400).json({ detail: `range must be one of ${allowed.join(", ")}` });
    const findingIds = Array.isArray(req.body?.findingIds)
      ? (req.body.findingIds as any[]).filter((x) => typeof x === "string")
      : undefined;
    const analysisMode = req.body?.analysisMode === "client_impact" ? "client_impact" : "cirt";
    const requestedClientIds = Array.isArray(req.body?.clientIds)
      ? Array.from(new Set((req.body.clientIds as any[]).filter((x): x is string => typeof x === "string"))).slice(
          0,
          12,
        )
      : [];
    const tenantId = req.effectiveTenantId!;
    if (analysisMode === "client_impact" && storage.getTenant(tenantId)?.operatingMode !== "mss") {
      return res.status(409).json({ detail: "Client-impact assessment is available only in MSS mode." });
    }
    const activeClientIds = new Set(storage.listClientProfiles(tenantId).map((profile: { id: string }) => profile.id));
    const clientIds = requestedClientIds.filter((clientId) => activeClientIds.has(clientId));
    if (analysisMode === "client_impact" && clientIds.length === 0) {
      return res
        .status(400)
        .json({ detail: "Select at least one active Client Profile for client-impact assessment." });
    }
    const targetLabel =
      analysisMode === "client_impact"
        ? `Client-impact assessment — ${clientIds.length} client${clientIds.length === 1 ? "" : "s"}`
        : `CIRT triage — ${range}`;
    const jobId = storage.createAiJob({
      tenantId,
      kind: "chat_triage",
      payload: { range, findingIds, analysisMode, clientIds },
      createdBy: req.user?.email ?? null,
      targetLabel,
      targetUrl: null,
    });
    const targetUrl = `/#/osint?ai=triage&job=${encodeURIComponent(jobId)}`;
    storage.updateAiJobTarget(jobId, { targetUrl });
    runChatTriageWorker({
      jobId,
      tenantId,
      payload: {
        range,
        findingIds,
        analysisMode,
        clientIds,
        actor: req.user?.email ?? "system",
      },
    });
    res.status(202).json({ jobId, status: "queued", kind: "chat_triage", targetLabel, targetUrl });
  });
  // v2.17 — Free-form chat with the integrated AI provider. The floating
  // AI assistant uses this for back-and-forth Q&A scoped to the current
  // OSINT findings.
  app.post("/api/v1/osint/chat/converse", requireAuth, async (req: AuthedRequest, res, next: NextFunction) => {
    const body = req.body || {};
    const messages = Array.isArray(body.messages) ? body.messages : [];
    const contextFindingIds = Array.isArray(body.contextFindingIds)
      ? body.contextFindingIds.filter((x: any) => typeof x === "string")
      : [];
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
    const findingIds = Array.isArray(req.body?.findingIds)
      ? (req.body.findingIds as string[]).filter((x) => typeof x === "string")
      : [];
    if (findingIds.length === 0) return res.status(400).json({ detail: "findingIds required (non-empty array)" });
    if (findingIds.length > 20) return res.status(400).json({ detail: "max 20 findings per deep-dive request" });
    const tenantId = req.effectiveTenantId!;
    const job = runIsolatedAiWork({
      tenantId,
      kind: "chat_deep_dive",
      payload: { findingIds },
      createdBy: req.user?.email ?? null,
      targetLabel: `CIRT deep-dive — ${findingIds.length} finding${findingIds.length === 1 ? "" : "s"}`,
      targetUrl: (jobId) => `/#/osint?ai=deep-dive&job=${encodeURIComponent(jobId)}`,
    });
    res.status(202).json(job);
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
    runAutoFetchNow(req.effectiveTenantId!).catch((e) => console.error("[osint-bg] manual fetch:", e));
    res.json({ status: "started" });
  });

  app.post("/api/v1/osint/automation/analyze-now", requireAuth, async (req: AuthedRequest, res) => {
    // Fire-and-forget; client polls /settings for status and individual
    // findings via the cache endpoint below.
    runAutoAnalyzeNow(req.effectiveTenantId!).catch((e) => console.error("[osint-bg] manual analyze:", e));
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
        completed: jobs.filter((j: any) => j.status === "completed" || j.status === "done" || j.status === "succeeded")
          .length,
        cancelled: jobs.filter((j: any) => j.status === "cancelled").length,
      },
      jobs,
      auditEntries: storage.listAudit(req.effectiveTenantId!, { limit: 200 }),
      globalIngest: null,
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
    if (result.status === "not_found")
      return res.status(404).json({ detail: result.message || "not found", status: result.status });
    if (!result.ok) return res.status(409).json({ detail: result.message || "not cancellable", status: result.status });
    storage.appendAudit(
      req.effectiveTenantId!,
      req.user?.email || "operator",
      `operations.job.cancel.${source}`,
      id,
      result,
    );
    res.status(202).json(result);
  });

  return httpServer;
}
