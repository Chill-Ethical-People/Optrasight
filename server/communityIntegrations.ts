import type { CommunityIntegrationKind, CommunityIntegrationSettingsDTO } from "@shared/schema";
import { isSafeSourceFetchUrl } from "./sourceFetch";
import { secretStore } from "./secretStore";

const OWNER_TYPE = "osint_integration";
const CONFIG_SECRET = "config";
const CREDENTIAL_SECRET = "credential";

const DEFINITIONS: Record<
  CommunityIntegrationKind,
  { mode: "ingestion" | "enrichment"; endpoint: string; authMode: CommunityIntegrationSettingsDTO["authMode"] }
> = {
  abusech: { mode: "ingestion", endpoint: "https://threatfox-api.abuse.ch/api/v1/", authMode: "api-key" },
  taxii: { mode: "ingestion", endpoint: "", authMode: "bearer" },
  misp: { mode: "ingestion", endpoint: "", authMode: "api-key" },
  urlscan: { mode: "enrichment", endpoint: "https://urlscan.io/api/v1/search/", authMode: "api-key" },
  greynoise: { mode: "enrichment", endpoint: "https://api.greynoise.io/v3/community", authMode: "api-key" },
};

type StoredConfig = Pick<
  CommunityIntegrationSettingsDTO,
  "enabled" | "endpoint" | "collectionId" | "username" | "authMode" | "lastTestedAt" | "lastTestOk" | "lastTestMessage"
>;

export interface CommunityIngestConfig {
  kind: "abusech" | "taxii" | "misp";
  endpoint: string;
  collectionId: string;
  username: string;
  authMode: CommunityIntegrationSettingsDTO["authMode"];
  credential: string;
}

function ownerId(kind: CommunityIntegrationKind): string {
  return `community-${kind}`;
}

function defaults(kind: CommunityIntegrationKind): StoredConfig {
  const definition = DEFINITIONS[kind];
  return {
    enabled: false,
    endpoint: definition.endpoint,
    collectionId: "",
    username: "",
    authMode: definition.authMode,
    lastTestedAt: null,
    lastTestOk: null,
    lastTestMessage: null,
  };
}

function readConfig(tenantId: string, kind: CommunityIntegrationKind): StoredConfig {
  const fallback = defaults(kind);
  const raw = secretStore.getSecret(tenantId, OWNER_TYPE, ownerId(kind), CONFIG_SECRET);
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw) as Partial<StoredConfig>;
    return {
      ...fallback,
      ...parsed,
      enabled: parsed.enabled === true,
      endpoint: String(parsed.endpoint || fallback.endpoint),
      collectionId: String(parsed.collectionId || ""),
      username: String(parsed.username || ""),
      authMode: parsed.authMode === "basic" || parsed.authMode === "bearer" ? parsed.authMode : "api-key",
      lastTestedAt: parsed.lastTestedAt || null,
      lastTestOk: typeof parsed.lastTestOk === "boolean" ? parsed.lastTestOk : null,
      lastTestMessage: parsed.lastTestMessage || null,
    };
  } catch {
    return fallback;
  }
}

function writeConfig(tenantId: string, kind: CommunityIntegrationKind, config: StoredConfig): void {
  secretStore.setSecret(tenantId, OWNER_TYPE, ownerId(kind), CONFIG_SECRET, JSON.stringify(config));
}

function credential(tenantId: string, kind: CommunityIntegrationKind): string | null {
  return secretStore.getSecret(tenantId, OWNER_TYPE, ownerId(kind), CREDENTIAL_SECRET);
}

async function validateEndpoint(kind: CommunityIntegrationKind, raw: string): Promise<string> {
  const fixed = DEFINITIONS[kind].endpoint;
  if (kind === "abusech" || kind === "urlscan" || kind === "greynoise") return fixed;
  const url = new URL(raw);
  if (url.protocol !== "https:") throw new Error("Connector endpoints must use HTTPS.");
  if (!(await isSafeSourceFetchUrl(url.toString())))
    throw new Error("Connector endpoint did not pass network safety validation.");
  return url.toString().replace(/\/$/, "");
}

function isConfigured(kind: CommunityIntegrationKind, config: StoredConfig, hasCredential: boolean): boolean {
  if (!hasCredential) return false;
  if (kind === "taxii")
    return !!config.endpoint && !!config.collectionId && (config.authMode !== "basic" || !!config.username);
  if (kind === "misp") return !!config.endpoint;
  return true;
}

export function getCommunityIntegrationSettings(
  tenantId: string,
  kind: CommunityIntegrationKind,
): CommunityIntegrationSettingsDTO {
  const config = readConfig(tenantId, kind);
  const hasCredential = !!credential(tenantId, kind);
  return {
    kind,
    mode: DEFINITIONS[kind].mode,
    ...config,
    hasCredential,
    configured: isConfigured(kind, config, hasCredential),
  };
}

export async function saveCommunityIntegrationSettings(
  tenantId: string,
  kind: CommunityIntegrationKind,
  input: {
    enabled: boolean;
    endpoint: string;
    collectionId: string;
    username: string;
    authMode: CommunityIntegrationSettingsDTO["authMode"];
    credential?: string;
    clearCredential?: boolean;
  },
): Promise<CommunityIntegrationSettingsDTO> {
  const current = readConfig(tenantId, kind);
  const endpoint = await validateEndpoint(kind, input.endpoint || current.endpoint);
  if (input.clearCredential) secretStore.deleteSecret(tenantId, OWNER_TYPE, ownerId(kind), CREDENTIAL_SECRET);
  if (input.credential)
    secretStore.setSecret(tenantId, OWNER_TYPE, ownerId(kind), CREDENTIAL_SECRET, input.credential.trim());
  const changed =
    endpoint !== current.endpoint ||
    input.collectionId !== current.collectionId ||
    input.username !== current.username ||
    input.authMode !== current.authMode ||
    !!input.credential ||
    !!input.clearCredential;
  writeConfig(tenantId, kind, {
    enabled: input.enabled,
    endpoint,
    collectionId: input.collectionId,
    username: input.username,
    authMode: input.authMode,
    lastTestedAt: changed ? null : current.lastTestedAt,
    lastTestOk: changed ? null : current.lastTestOk,
    lastTestMessage: changed ? null : current.lastTestMessage,
  });
  return getCommunityIntegrationSettings(tenantId, kind);
}

export function getCommunityIngestConfigs(tenantId: string): CommunityIngestConfig[] {
  const kinds: CommunityIntegrationKind[] = ["abusech", "taxii", "misp"];
  return kinds.flatMap((kind) => {
    const settings = getCommunityIntegrationSettings(tenantId, kind);
    const saved = credential(tenantId, kind);
    if (!settings.enabled || !settings.configured || !saved) return [];
    return [
      {
        kind,
        endpoint: settings.endpoint,
        collectionId: settings.collectionId,
        username: settings.username,
        authMode: settings.authMode,
        credential: saved,
      } as CommunityIngestConfig,
    ];
  });
}

function headersFor(
  config: CommunityIngestConfig | (CommunityIntegrationSettingsDTO & { credential: string }),
): Record<string, string> {
  if (config.authMode === "basic")
    return { authorization: `Basic ${Buffer.from(`${config.username}:${config.credential}`).toString("base64")}` };
  if (config.authMode === "bearer") return { authorization: `Bearer ${config.credential}` };
  if (config.kind === "misp") return { authorization: config.credential };
  if (config.kind === "abusech") return { "Auth-Key": config.credential };
  if (config.kind === "greynoise") return { key: config.credential };
  return { "api-key": config.credential };
}

function updateTestResult(tenantId: string, kind: CommunityIntegrationKind, ok: boolean, message: string): void {
  writeConfig(tenantId, kind, {
    ...readConfig(tenantId, kind),
    lastTestedAt: new Date().toISOString(),
    lastTestOk: ok,
    lastTestMessage: message.slice(0, 240),
  });
}

export async function testCommunityIntegration(
  tenantId: string,
  kind: CommunityIntegrationKind,
): Promise<{ ok: true; message: string }> {
  const settings = getCommunityIntegrationSettings(tenantId, kind);
  const saved = credential(tenantId, kind);
  if (!settings.configured || !saved) throw new Error("Save the required endpoint and credential before testing.");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    let url = settings.endpoint;
    let init: RequestInit = { headers: headersFor({ ...settings, credential: saved }) };
    if (kind === "abusech")
      init = {
        method: "POST",
        headers: { ...init.headers, "content-type": "application/json" },
        body: JSON.stringify({ query: "get_iocs", days: 1 }),
      };
    if (kind === "taxii")
      url = `${settings.endpoint}/collections/${encodeURIComponent(settings.collectionId)}/objects/?limit=1`;
    if (kind === "misp") {
      url = `${settings.endpoint}/attributes/restSearch`;
      init = {
        method: "POST",
        headers: { ...init.headers, accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify({ returnFormat: "json", limit: 1 }),
      };
    }
    if (kind === "urlscan") url = `${settings.endpoint}?q=task.time:%3Enow-1h&size=1`;
    if (kind === "greynoise") url = `${settings.endpoint}/8.8.8.8`;
    if (!(await isSafeSourceFetchUrl(url)))
      throw new Error("Connector test URL did not pass network safety validation.");
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) throw new Error(`Connection test failed with HTTP ${response.status}.`);
    const message = `Connected to ${kind === "abusech" ? "abuse.ch" : kind === "urlscan" ? "urlscan.io" : kind === "greynoise" ? "GreyNoise" : kind.toUpperCase()}.`;
    updateTestResult(tenantId, kind, true, message);
    return { ok: true, message };
  } catch (error: any) {
    const message = error?.name === "AbortError" ? "Connection test timed out." : String(error?.message || error);
    updateTestResult(tenantId, kind, false, message);
    throw new Error(message);
  } finally {
    clearTimeout(timeout);
  }
}

export function communityConnectorHeaders(config: CommunityIngestConfig): Record<string, string> {
  return headersFor(config);
}

export async function lookupCommunityEnrichment(
  tenantId: string,
  kind: "urlscan" | "greynoise",
  observable: string,
): Promise<Record<string, unknown>> {
  const settings = getCommunityIntegrationSettings(tenantId, kind);
  const saved = credential(tenantId, kind);
  if (!settings.enabled || !settings.configured || !saved)
    throw new Error("Enable and configure this enrichment connector first.");
  let url: string;
  if (kind === "greynoise") {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(observable))
      throw new Error("GreyNoise Community accepts a public IPv4 address.");
    url = `${settings.endpoint}/${encodeURIComponent(observable)}`;
  } else {
    const query = /^https?:\/\//i.test(observable)
      ? `task.url:"${observable.replace(/"/g, "")}"`
      : /^\d{1,3}(?:\.\d{1,3}){3}$/.test(observable)
        ? `page.ip:${observable}`
        : `domain:${observable.replace(/[^a-zA-Z0-9._-]/g, "")}`;
    url = `${settings.endpoint}?q=${encodeURIComponent(query)}&size=5`;
  }
  if (!(await isSafeSourceFetchUrl(url))) throw new Error("Enrichment request did not pass network safety validation.");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: headersFor({ ...settings, credential: saved }),
    });
    if (!response.ok)
      throw new Error(`${kind === "urlscan" ? "urlscan.io" : "GreyNoise"} lookup failed with HTTP ${response.status}.`);
    const payload = (await response.json()) as any;
    if (kind === "greynoise") {
      return {
        observable,
        noise: payload?.noise === true,
        riot: payload?.riot === true,
        classification: payload?.classification || "unknown",
        name: payload?.name || null,
        lastSeen: payload?.last_seen || null,
        message: payload?.message || null,
      };
    }
    const results = Array.isArray(payload?.results)
      ? payload.results.slice(0, 5).map((entry: any) => ({
          scanId: entry?._id || null,
          scannedAt: entry?.task?.time || null,
          url: entry?.task?.url || null,
          domain: entry?.page?.domain || null,
          ip: entry?.page?.ip || null,
          country: entry?.page?.country || null,
          verdict: entry?.verdicts?.overall?.malicious === true ? "malicious" : "not flagged",
        }))
      : [];
    return { observable, total: Number(payload?.total ?? results.length), results };
  } finally {
    clearTimeout(timeout);
  }
}
