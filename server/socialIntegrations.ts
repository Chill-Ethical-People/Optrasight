import type { XIntegrationSettingsDTO } from "@shared/schema";
import { secretStore } from "./secretStore";

const OWNER_TYPE = "osint_integration";
const OWNER_ID = "x-falconfeeds";
const CONFIG_SECRET = "config";
const TOKEN_SECRET = "bearer_token";
const ACCOUNT_USERNAME = "FalconFeedsio";
const ACCOUNT_URL = `https://x.com/${ACCOUNT_USERNAME}`;

type StoredXConfig = Pick<XIntegrationSettingsDTO, "enabled" | "lastTestedAt" | "lastTestOk" | "lastTestMessage">;

const DEFAULT_CONFIG: StoredXConfig = {
  enabled: false,
  lastTestedAt: null,
  lastTestOk: null,
  lastTestMessage: null,
};

function environmentToken(): string | null {
  const token = (process.env.X_BEARER_TOKEN || process.env.TWITTER_BEARER_TOKEN || "").trim();
  return token || null;
}

function readConfig(tenantId: string): StoredXConfig {
  const raw = secretStore.getSecret(tenantId, OWNER_TYPE, OWNER_ID, CONFIG_SECRET);
  if (!raw) return { ...DEFAULT_CONFIG };
  try {
    const parsed = JSON.parse(raw) as Partial<StoredXConfig>;
    return {
      enabled: parsed.enabled === true,
      lastTestedAt: parsed.lastTestedAt || null,
      lastTestOk: typeof parsed.lastTestOk === "boolean" ? parsed.lastTestOk : null,
      lastTestMessage: parsed.lastTestMessage || null,
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function writeConfig(tenantId: string, config: StoredXConfig): void {
  secretStore.setSecret(tenantId, OWNER_TYPE, OWNER_ID, CONFIG_SECRET, JSON.stringify(config));
}

function savedToken(tenantId: string): string | null {
  return secretStore.getSecret(tenantId, OWNER_TYPE, OWNER_ID, TOKEN_SECRET);
}

export function getXIntegrationSettings(tenantId: string): XIntegrationSettingsDTO {
  const config = readConfig(tenantId);
  const hasSavedToken = !!savedToken(tenantId);
  const hasEnvironmentToken = !!environmentToken();
  return {
    ...config,
    accountUsername: ACCOUNT_USERNAME,
    accountUrl: ACCOUNT_URL,
    hasBearerToken: hasSavedToken || hasEnvironmentToken,
    configured: hasSavedToken || hasEnvironmentToken,
    managedByEnvironment: !hasSavedToken && hasEnvironmentToken,
  };
}

export function saveXIntegrationSettings(
  tenantId: string,
  input: { enabled: boolean; bearerToken?: string; clearBearerToken?: boolean },
): XIntegrationSettingsDTO {
  const current = readConfig(tenantId);
  if (input.clearBearerToken) secretStore.deleteSecret(tenantId, OWNER_TYPE, OWNER_ID, TOKEN_SECRET);
  if (input.bearerToken) secretStore.setSecret(tenantId, OWNER_TYPE, OWNER_ID, TOKEN_SECRET, input.bearerToken.trim());
  writeConfig(tenantId, {
    ...current,
    enabled: input.enabled,
    lastTestOk: input.bearerToken || input.clearBearerToken ? null : current.lastTestOk,
    lastTestedAt: input.bearerToken || input.clearBearerToken ? null : current.lastTestedAt,
    lastTestMessage: input.bearerToken || input.clearBearerToken ? null : current.lastTestMessage,
  });
  return getXIntegrationSettings(tenantId);
}

export function getXBearerTokenForIngest(tenantId: string): string | null {
  if (!readConfig(tenantId).enabled) return null;
  return savedToken(tenantId) || environmentToken();
}

function updateTestResult(tenantId: string, ok: boolean, message: string): void {
  const current = readConfig(tenantId);
  writeConfig(tenantId, {
    ...current,
    lastTestedAt: new Date().toISOString(),
    lastTestOk: ok,
    lastTestMessage: message.slice(0, 240),
  });
}

export async function testXIntegration(tenantId: string): Promise<{ ok: true; accountName: string; username: string }> {
  const token = savedToken(tenantId) || environmentToken();
  if (!token) throw new Error("Save an X API bearer token before testing the integration.");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12_000);
  try {
    const response = await fetch(`https://api.x.com/2/users/by/username/${ACCOUNT_USERNAME}`, {
      signal: controller.signal,
      headers: { accept: "application/json", authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
      const message =
        response.status === 401 || response.status === 403
          ? "X rejected the bearer token or the project lacks user-lookup access."
          : response.status === 429
            ? "X API rate or credit limit reached."
            : `X account lookup failed with HTTP ${response.status}.`;
      updateTestResult(tenantId, false, message);
      throw new Error(message);
    }
    const payload = (await response.json()) as any;
    const username = String(payload?.data?.username || "");
    const accountName = String(payload?.data?.name || "FalconFeeds.io");
    if (!payload?.data?.id || username.toLowerCase() !== ACCOUNT_USERNAME.toLowerCase()) {
      const message = "X returned an unexpected account response.";
      updateTestResult(tenantId, false, message);
      throw new Error(message);
    }
    updateTestResult(tenantId, true, `Connected to @${username}.`);
    return { ok: true, accountName, username };
  } catch (error: any) {
    if (error?.name === "AbortError") {
      const message = "X connection test timed out.";
      updateTestResult(tenantId, false, message);
      throw new Error(message);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
