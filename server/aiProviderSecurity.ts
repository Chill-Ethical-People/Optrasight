import { X509Certificate } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { isIP } from "node:net";
import { isAbsolute } from "node:path";
import { isPrivateOrReservedAddress, isSafeSourceFetchUrl } from "./sourceFetch";
import type { AiProviderKind } from "@shared/schema";

const SAFE_AI_PORTS = new Set(["", "443"]);
const LOCAL_AI_CA_MAX_BYTES = 1024 * 1024;

export interface LocalAiTlsConfig {
  caCertPath?: string;
  error?: string;
}

function normalizeBaseUrl(baseUrl: string | null | undefined): string {
  return (baseUrl || "").trim().replace(/\/+$/, "");
}

function parsePemCertificates(pem: string): string[] | null {
  const beginMarker = "-----BEGIN CERTIFICATE-----";
  const endMarker = "-----END CERTIFICATE-----";
  let cursor = 0;
  const certificates: string[] = [];
  while (cursor < pem.length) {
    const begin = pem.indexOf(beginMarker, cursor);
    if (begin < 0) return certificates.length > 0 && pem.slice(cursor).trim().length === 0 ? certificates : null;
    if (pem.slice(cursor, begin).trim().length > 0) return null;
    const bodyStart = begin + beginMarker.length;
    const end = pem.indexOf(endMarker, bodyStart);
    if (end < 0) return null;
    const body = pem.slice(bodyStart, end).replace(/\s/g, "");
    if (!body || !/^[A-Za-z0-9+/=]+$/.test(body)) return null;
    certificates.push(pem.slice(begin, end + endMarker.length));
    cursor = end + endMarker.length;
  }
  return certificates.length > 0 ? certificates : null;
}

function isAllowedLocalAiAddress(host: string): boolean {
  const normalized = host.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(normalized)?.[1];
  const address = mapped ?? normalized;
  if (isIP(address) === 4) {
    const parts = address.split(".").map(Number);
    return (
      parts[0] === 10
      || parts[0] === 127
      || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
      || (parts[0] === 192 && parts[1] === 168)
    );
  }
  if (isIP(normalized) === 6) {
    return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd");
  }
  return (
    normalized === "localhost"
    || normalized === "localhost."
    || normalized.endsWith(".localhost")
    || normalized.endsWith(".local")
    || normalized.endsWith(".internal")
  );
}

export function isExplicitlyAllowedLocalAiUrl(
  kind: AiProviderKind | undefined,
  baseUrl: string | null | undefined,
): boolean {
  if (process.env.OPTRASIGHT_ALLOW_LOCAL_AI !== "1" || kind !== "ollama") return false;
  let parsed: URL;
  try {
    parsed = new URL(normalizeBaseUrl(baseUrl));
  } catch {
    return false;
  }
  if (parsed.username || parsed.password) return false;
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  return isAllowedLocalAiAddress(parsed.hostname);
}

export function resolveLocalAiTlsConfig(
  kind: AiProviderKind | undefined,
  baseUrl: string | null | undefined,
): LocalAiTlsConfig {
  if (!isExplicitlyAllowedLocalAiUrl(kind, baseUrl)) return {};
  let parsed: URL;
  try {
    parsed = new URL(normalizeBaseUrl(baseUrl));
  } catch {
    return {};
  }
  if (parsed.protocol !== "https:") return {};
  const configuredPath = (process.env.OPTRASIGHT_LOCAL_AI_CA_CERT || "").trim();
  if (!configuredPath) return {};
  if (!isAbsolute(configuredPath)) {
    return { error: "OPTRASIGHT_LOCAL_AI_CA_CERT must be an absolute path to a PEM certificate bundle." };
  }
  try {
    const metadata = statSync(configuredPath);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > LOCAL_AI_CA_MAX_BYTES) {
      return { error: "OPTRASIGHT_LOCAL_AI_CA_CERT must reference a PEM file no larger than 1 MB." };
    }
    const pem = readFileSync(configuredPath, "utf8");
    const certificates = parsePemCertificates(pem);
    if (!certificates) {
      return { error: "OPTRASIGHT_LOCAL_AI_CA_CERT must contain only PEM-encoded certificates." };
    }
    try {
      for (const certificate of certificates) new X509Certificate(certificate);
    } catch {
      return { error: "OPTRASIGHT_LOCAL_AI_CA_CERT contains an invalid X.509 certificate." };
    }
  } catch {
    return { error: "OPTRASIGHT_LOCAL_AI_CA_CERT could not be read by the OptraSight service." };
  }
  return { caCertPath: configuredPath };
}

export function aiProviderBaseUrlSyncFailure(
  baseUrl: string | null | undefined,
  kind?: AiProviderKind,
): string | null {
  const value = normalizeBaseUrl(baseUrl);
  if (!value) return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return "AI provider base URL must be a valid HTTPS URL.";
  }
  if (parsed.username || parsed.password) {
    return "AI provider base URL must not include embedded credentials.";
  }
  if (isExplicitlyAllowedLocalAiUrl(kind, value)) return null;
  if (parsed.protocol !== "https:") {
    return "AI provider base URL must use HTTPS.";
  }
  if (!SAFE_AI_PORTS.has(parsed.port)) {
    return "AI provider base URL must use the default HTTPS port.";
  }
  const host = parsed.hostname.toLowerCase();
  const addressHost = host.replace(/^\[/, "").replace(/\]$/, "");
  if (
    host === "localhost"
    || host === "localhost."
    || host.endsWith(".localhost")
    || host.endsWith(".local")
    || host.endsWith(".internal")
  ) {
    return "AI provider base URL cannot target local or internal hosts.";
  }
  if (isIP(addressHost) && isPrivateOrReservedAddress(addressHost)) {
    return "AI provider base URL cannot target private or reserved IP space.";
  }
  return null;
}

export async function validateAiProviderBaseUrl(kind: AiProviderKind, baseUrl: string | null | undefined): Promise<string | null> {
  const value = normalizeBaseUrl(baseUrl);
  if (!value) return null;
  const syncFailure = aiProviderBaseUrlSyncFailure(value, kind);
  if (syncFailure) return syncFailure;
  if (isExplicitlyAllowedLocalAiUrl(kind, value)) {
    const tlsConfig = resolveLocalAiTlsConfig(kind, value);
    if (tlsConfig.error) return tlsConfig.error;
    return null;
  }
  if (!(await isSafeSourceFetchUrl(value))) {
    return "AI provider base URL failed outbound safety checks.";
  }
  return null;
}
