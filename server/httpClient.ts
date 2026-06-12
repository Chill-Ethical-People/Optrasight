import { spawnSync } from "node:child_process";

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
}

const DEFAULT_STATUS_MARKER = "__OPTRASIGHT_HTTP_STATUS__";

export function aiProviderProtocolArgs(url: string): string[] {
  const allowLocalHttp = process.env.OPTRASIGHT_ALLOW_LOCAL_AI === "1"
    && /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(url);
  return [
    "--proto", allowLocalHttp ? "=http,https" : "=https",
    "--proto-redir", "=https",
  ];
}

export function curlRequestSync(opts: CurlRequestOptions): CurlHttpResult {
  const started = Date.now();
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
    return { ok: false, status: 0, body: "", error: r.stderr || `curl exit ${r.status}`, latencyMs };
  }

  const out = r.stdout || "";
  const markerText = `\n${marker}:`;
  const markerIndex = out.lastIndexOf(markerText);
  const status = markerIndex >= 0 ? parseInt(out.slice(markerIndex + markerText.length), 10) || 0 : 0;
  const body = markerIndex >= 0 ? out.slice(0, markerIndex) : out;
  const ok = status >= 200 && status < 300;
  return { ok, status, body, error: ok ? undefined : (r.stderr || `HTTP ${status}`), latencyMs };
}
