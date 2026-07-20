import type { KelaIntegrationSettingsDTO } from "@shared/schema";
import { isSafeSourceFetchUrl } from "./sourceFetch";
import { secretStore } from "./secretStore";

const OWNER_TYPE = "osint_integration";
const OWNER_ID = "kela-stix";
const CONFIG_SECRET = "config";
const API_KEY_SECRET = "api_key";

type StoredKelaConfig = Pick<
  KelaIntegrationSettingsDTO,
  "enabled" | "feedUrl" | "authMode" | "lastTestedAt" | "lastTestOk" | "lastTestMessage"
>;

export interface KelaIngestConfig {
  feedUrl: string;
  authMode: "bearer" | "x-api-key";
  apiKey: string;
}

const DEFAULT_CONFIG: StoredKelaConfig = {
  enabled: false,
  feedUrl: "",
  authMode: "bearer",
  lastTestedAt: null,
  lastTestOk: null,
  lastTestMessage: null,
};

function readConfig(tenantId: string): StoredKelaConfig {
  const raw = secretStore.getSecret(tenantId, OWNER_TYPE, OWNER_ID, CONFIG_SECRET);
  if (!raw) return { ...DEFAULT_CONFIG };
  try {
    const parsed = JSON.parse(raw) as Partial<StoredKelaConfig>;
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      enabled: parsed.enabled === true,
      authMode: parsed.authMode === "x-api-key" ? "x-api-key" : "bearer",
      feedUrl: String(parsed.feedUrl || ""),
      lastTestedAt: parsed.lastTestedAt || null,
      lastTestOk: typeof parsed.lastTestOk === "boolean" ? parsed.lastTestOk : null,
      lastTestMessage: parsed.lastTestMessage || null,
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function writeConfig(tenantId: string, config: StoredKelaConfig): void {
  secretStore.setSecret(tenantId, OWNER_TYPE, OWNER_ID, CONFIG_SECRET, JSON.stringify(config));
}

function apiKey(tenantId: string): string | null {
  return secretStore.getSecret(tenantId, OWNER_TYPE, OWNER_ID, API_KEY_SECRET);
}

export async function validateKelaFeedUrl(rawUrl: string): Promise<string> {
  const url = new URL(rawUrl);
  const host = url.hostname.toLowerCase();
  if (url.protocol !== "https:") throw new Error("KELA feed URL must use HTTPS.");
  if (
    !(
      host === "ke-la.com" ||
      host.endsWith(".ke-la.com") ||
      host === "kelacyber.com" ||
      host.endsWith(".kelacyber.com")
    )
  ) {
    throw new Error("KELA feed URL must use an official ke-la.com or kelacyber.com host.");
  }
  if (!(await isSafeSourceFetchUrl(url.toString())))
    throw new Error("KELA feed URL did not pass network safety validation.");
  return url.toString();
}

export function getKelaIntegrationSettings(tenantId: string): KelaIntegrationSettingsDTO {
  const config = readConfig(tenantId);
  const hasApiKey = !!apiKey(tenantId);
  return {
    ...config,
    hasApiKey,
    configured: !!config.feedUrl && hasApiKey,
  };
}

export async function saveKelaIntegrationSettings(
  tenantId: string,
  input: {
    enabled: boolean;
    feedUrl: string;
    authMode: "bearer" | "x-api-key";
    apiKey?: string;
    clearApiKey?: boolean;
  },
): Promise<KelaIntegrationSettingsDTO> {
  const feedUrl = input.feedUrl ? await validateKelaFeedUrl(input.feedUrl) : "";
  const current = readConfig(tenantId);
  if (input.clearApiKey) secretStore.deleteSecret(tenantId, OWNER_TYPE, OWNER_ID, API_KEY_SECRET);
  if (input.apiKey) secretStore.setSecret(tenantId, OWNER_TYPE, OWNER_ID, API_KEY_SECRET, input.apiKey.trim());
  writeConfig(tenantId, {
    ...current,
    enabled: input.enabled,
    feedUrl,
    authMode: input.authMode,
    lastTestedAt: input.apiKey || input.clearApiKey || feedUrl !== current.feedUrl ? null : current.lastTestedAt,
    lastTestOk: input.apiKey || input.clearApiKey || feedUrl !== current.feedUrl ? null : current.lastTestOk,
    lastTestMessage: input.apiKey || input.clearApiKey || feedUrl !== current.feedUrl ? null : current.lastTestMessage,
  });
  return getKelaIntegrationSettings(tenantId);
}

export function getKelaIngestConfig(tenantId: string): KelaIngestConfig | null {
  const config = readConfig(tenantId);
  const key = apiKey(tenantId);
  if (!config.enabled || !config.feedUrl || !key) return null;
  return { feedUrl: config.feedUrl, authMode: config.authMode, apiKey: key };
}

export function kelaRequestHeaders(config: KelaIngestConfig): Record<string, string> {
  return {
    accept: "application/stix+json;version=2.1, application/json",
    ...(config.authMode === "x-api-key"
      ? { "x-api-key": config.apiKey }
      : { authorization: `Bearer ${config.apiKey}` }),
  };
}

function updateTestResult(tenantId: string, ok: boolean, message: string): void {
  writeConfig(tenantId, {
    ...readConfig(tenantId),
    lastTestedAt: new Date().toISOString(),
    lastTestOk: ok,
    lastTestMessage: message.slice(0, 240),
  });
}

export async function testKelaIntegration(tenantId: string): Promise<{ ok: true; objectCount: number }> {
  const config = getKelaIngestConfig(tenantId);
  if (!config) throw new Error("Save and enable a KELA feed URL and API key before testing.");
  await validateKelaFeedUrl(config.feedUrl);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(config.feedUrl, { signal: controller.signal, headers: kelaRequestHeaders(config) });
    if (!response.ok) {
      const message =
        response.status === 401 || response.status === 403
          ? "KELA rejected the API credential or the subscription lacks access to this feed."
          : response.status === 429
            ? "KELA API rate limit reached."
            : `KELA feed test failed with HTTP ${response.status}.`;
      updateTestResult(tenantId, false, message);
      throw new Error(message);
    }
    const payload = (await response.json()) as any;
    const objects = Array.isArray(payload?.objects)
      ? payload.objects
      : Array.isArray(payload?.data)
        ? payload.data
        : Array.isArray(payload?.items)
          ? payload.items
          : [];
    const message = `Connected to KELA; ${objects.length} object${objects.length === 1 ? "" : "s"} returned.`;
    updateTestResult(tenantId, true, message);
    return { ok: true, objectCount: objects.length };
  } catch (error: any) {
    if (error?.name === "AbortError") {
      const message = "KELA connection test timed out.";
      updateTestResult(tenantId, false, message);
      throw new Error(message);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
