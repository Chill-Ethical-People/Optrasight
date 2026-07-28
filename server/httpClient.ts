import { spawnSync } from "node:child_process";
import type { AiProviderKind } from "@shared/schema";
import { isExplicitlyAllowedLocalAiUrl, resolveLocalAiTlsConfig } from "./aiProviderSecurity";

export interface CurlHttpResult {
  ok: boolean;
  status: number;
  body: string;
  error?: string;
  latencyMs: number;
}

interface CurlRequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutSeconds: number;
  maxTimeoutSeconds?: number;
  accept?: string;
  contentType?: string;
  protocolArgs?: string[];
  noBuffer?: boolean;
  maxBuffer?: number;
  statusMarker?: string;
  httpVersion?: "1.1" | "auto";
  providerKind?: AiProviderKind;
}

const DEFAULT_STATUS_MARKER = "__OPTRASIGHT_HTTP_STATUS__";

export function aiProviderProtocolArgs(url: string, kind?: AiProviderKind): string[] {
  const allowLocalHttp = url.toLowerCase().startsWith("http:") && isExplicitlyAllowedLocalAiUrl(kind, url);
  return [
    "--proto", allowLocalHttp ? "=http,https" : "=https",
    "--proto-redir", "=https",
  ];
}

function withLocalAiCertificateGuidance(
  error: string,
  opts: CurlRequestOptions,
  hasConfiguredCa: boolean,
): string {
  if (
    opts.providerKind === "ollama"
    && isExplicitlyAllowedLocalAiUrl(opts.providerKind, opts.url)
    && /(?:certificate|self[- ]signed|unable to get local issuer|CERT_)/i.test(error)
  ) {
    const guidance = hasConfiguredCa
      ? "The configured local AI CA did not validate the server certificate or hostname."
      : "Set OPTRASIGHT_LOCAL_AI_CA_CERT to the absolute path of the issuing CA PEM and restart OptraSight.";
    return `${error.trim()} ${guidance}`;
  }
  return error;
}

export function curlRequestSync(opts: CurlRequestOptions): CurlHttpResult {
  const started = Date.now();
  const localTls = resolveLocalAiTlsConfig(opts.providerKind, opts.url);
  if (localTls.error) {
    return { ok: false, status: 0, body: "", error: localTls.error, latencyMs: Date.now() - started };
  }
  const maxTimeoutSeconds = opts.maxTimeoutSeconds ?? opts.timeoutSeconds;
  const t = Math.max(1, Math.min(maxTimeoutSeconds, opts.timeoutSeconds));
  const marker = opts.statusMarker ?? DEFAULT_STATUS_MARKER;
  const args: string[] = [
    "-sS",
    "-X", opts.method ?? (opts.body ? "POST" : "GET"),
    "--max-time", String(t),
    "-w", `\n${marker}:%{http_code}`,
  ];
  if (opts.httpVersion !== "auto") args.splice(1, 0, "--http1.1");

  if (opts.noBuffer) args.push("--no-buffer");
  if (localTls.caCertPath) args.push("--cacert", localTls.caCertPath);
  if (opts.accept) args.push("-H", `Accept: ${opts.accept}`);
  if (opts.contentType) args.push("-H", `Content-Type: ${opts.contentType}`);
  if (opts.protocolArgs?.length) args.push(...opts.protocolArgs);
  for (const [k, v] of Object.entries(opts.headers ?? {})) {
    args.push("-H", `${k}: ${v}`);
  }
  if (opts.body !== undefined) args.push("--data-binary", "@-");
  args.push(opts.url);

  const r = spawnSync("curl", args, {
    input: opts.body,
    encoding: "utf8",
    timeout: (t + 2) * 1000,
    ...(opts.maxBuffer ? { maxBuffer: opts.maxBuffer } : {}),
  });
  const latencyMs = Date.now() - started;
  if (r.error) return { ok: false, status: 0, body: "", error: r.error.message, latencyMs };
  if (r.status !== 0 && !r.stdout) {
    const error = withLocalAiCertificateGuidance(
      r.stderr || `curl exit ${r.status}`,
      opts,
      !!localTls.caCertPath,
    );
    return { ok: false, status: 0, body: "", error, latencyMs };
  }

  const out = r.stdout || "";
  const markerText = `\n${marker}:`;
  const markerIndex = out.lastIndexOf(markerText);
  const status = markerIndex >= 0 ? parseInt(out.slice(markerIndex + markerText.length), 10) || 0 : 0;
  const body = markerIndex >= 0 ? out.slice(0, markerIndex) : out;
  const ok = status >= 200 && status < 300;
  const error = ok
    ? undefined
    : withLocalAiCertificateGuidance(r.stderr || `HTTP ${status}`, opts, !!localTls.caCertPath);
  return { ok, status, body, error, latencyMs };
}
