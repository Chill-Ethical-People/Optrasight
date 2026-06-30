/**
 * Live AI provider client — synchronous chat-completion + ping helpers.
 *
 * The existing aiClient.ts is wired into synchronous storage methods that use
 * better-sqlite3. Rather than refactor the entire AI dispatch chain to async,
 * this module uses `spawnSync('curl', ...)` to issue blocking HTTP requests
 * from inside the same call stack.
 *
 * Supported provider families:
 *   • OpenAI-compatible (chat completions): openai, deepseek, perplexity,
 *     azure-openai, ollama
 *   • Anthropic Messages API: anthropic
 *   • Google Gemini generateContent: gemini
 *
 * All helpers are total — they NEVER throw. liveChatJson returns null on any
 * error (missing key, HTTP failure, timeout, JSON parse failure). The caller
 * is expected to fall back to its deterministic mock so the demo never crashes.
 */
import { createDecipheriv, createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { AiProvider, AiProviderKind } from "@shared/schema";
import { aiProviderBaseUrlSyncFailure } from "./aiProviderSecurity";
import { aiProviderProtocolArgs, curlRequestSync, type CurlHttpResult } from "./httpClient";

const GEMINI_SAFE_FALLBACK_MODEL = "gemini-flash-latest";
const OPENAI_PORTRAIT_MODEL = "gpt-image-2";
const GEMINI_PORTRAIT_MODEL = "gemini-3.1-flash-image";
const GEMINI_PORTRAIT_FALLBACK_MODELS = ["gemini-3.1-flash-image", "gemini-3-pro-image"] as const;

function loadKekForDecrypt(): Buffer {
  const env = process.env.OPTRASIGHT_KEY_ENCRYPTION_KEY || process.env.OPTRASIGHT_KEK;
  if (env) {
    const raw = /^[A-Za-z0-9+/=]{43,}$/.test(env) ? Buffer.from(env, "base64") : Buffer.from(env, "utf8");
    return createHash("sha256").update(raw).digest();
  }
  const keyPath = join(resolve(process.cwd(), "data"), ".optrasight-kek");
  try {
    if (existsSync(keyPath)) {
      const v = readFileSync(keyPath, "utf8").trim();
      if (v) return Buffer.from(v, "base64");
    }
  } catch { /* fall through to deterministic legacy fallback */ }
  return createHash("sha256").update(`optrasight-local-${process.cwd()}`).digest();
}

const KEK = loadKekForDecrypt();

// Matches storage.ts encryption while retaining legacy base64-only support.
function dec(b64: string | null | undefined): string | null {
  if (!b64) return null;
  try {
    if (b64.startsWith("v1:")) {
      const [, ivB64, tagB64, bodyB64] = b64.split(":");
      const decipher = createDecipheriv("aes-256-gcm", KEK, Buffer.from(ivB64, "base64"));
      decipher.setAuthTag(Buffer.from(tagB64, "base64"));
      return Buffer.concat([decipher.update(Buffer.from(bodyB64, "base64")), decipher.final()]).toString("utf8");
    }
    return Buffer.from(b64, "base64").toString("utf8");
  } catch { return null; }
}

function normaliseProviderApiKey(kind: AiProviderKind, raw: string | null): string | null {
  if (!raw) return raw;
  let key = raw.trim();
  key = key.replace(/^["']|["']$/g, "").trim();
  key = key.replace(/^\{(.+)\}$/s, "$1").trim();
  key = key.replace(/^bearer\s+/i, "").trim();
  if (kind === "gemini") {
    key = key.replace(/^x-goog-api-key\s*:\s*/i, "").trim();
    const m = key.match(/\bAIza[0-9A-Za-z_-]{20,}\b/);
    if (m) return m[0];
  }
  return key;
}

// Default 12-second wall-clock timeout for most AI calls. The chat triage /
// deep-dive endpoints (v2.15) override this to 90s because they ship much
// larger payloads (full pre-fetched article bodies) and produce much longer
// reports than the per-row AI tasks.
const TIMEOUT_SECONDS = 12;
// v2.27 — ceiling raised to 10 min because the DeepSeek v4-pro reasoning
// model frequently spends 4-6 min streaming nothing but keepalive newlines
// before emitting the final chat.completion envelope. With the new async-
// job pattern the long wall-clock is fine — the HTTP request that the
// browser made already returned in milliseconds.
const MAX_TIMEOUT_SECONDS = 600;

type CurlResult = Omit<CurlHttpResult, "latencyMs">;

/** Run curl synchronously. Returns body and HTTP status. */
function curlPost(
  url: string,
  headers: Record<string, string>,
  body: string,
  timeoutSeconds?: number,
  opts?: { httpVersion?: "1.1" | "auto"; protocolGuard?: boolean },
): CurlResult {
  const t = Math.max(1, Math.min(MAX_TIMEOUT_SECONDS, timeoutSeconds ?? TIMEOUT_SECONDS));
  const { latencyMs: _latencyMs, ...result } = curlRequestSync({
    method: "POST",
    url,
    headers,
    body,
    timeoutSeconds: t,
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
    contentType: "application/json",
    protocolArgs: opts?.protocolGuard === false ? undefined : aiProviderProtocolArgs(url),
    statusMarker: "__BG_HTTP_STATUS__",
    httpVersion: opts?.httpVersion,
  });
  return result;
}

function isGemini3Model(model: string): boolean {
  return /^gemini-3(?:\.|$|-)/i.test(model);
}

function geminiApiModel(model: string): string {
  const m = (model || "").trim();
  if (
    !m
    || /^gemini-1(?:\.|$|-)/i.test(m)
    || /^gemini-2(?:\.|$|-)/i.test(m)
    || /^gemini-pro$/i.test(m)
  ) return "gemini-flash-latest";
  return m;
}

function supportsGeminiUrlContext(model: string): boolean {
  return /^gemini-(?:flash-latest|3\.5-flash|3\.1-pro|3\.1-flash-lite|3-flash)/i.test(geminiApiModel(model));
}

function geminiFallbackModel(model: string): string | null {
  const effective = geminiApiModel(model);
  if (effective === GEMINI_SAFE_FALLBACK_MODEL) return null;
  return GEMINI_SAFE_FALLBACK_MODEL;
}

function geminiConnectivityAttempts(model: string): string[] {
  const fallback = geminiFallbackModel(model);
  return Array.from(new Set([model, model, fallback].filter(Boolean) as string[]));
}

function isRetryableGeminiTransportFailure(r: CurlResult): boolean {
  return r.status === 0 || r.status === 503 || /timed out|timeout|empty reply|connection reset/i.test(r.error || "");
}

function providerApiModel(kind: AiProviderKind, model: string): string {
  const m = (model || "").trim();
  if (kind === "gemini") return geminiApiModel(m);
  const key = m.toLowerCase();
  if (kind === "openai" || kind === "azure-openai") {
    return m || "gpt-5.4-mini";
  }
  if (kind === "anthropic") {
    const aliases: Record<string, string> = {
      "claude-3-5-sonnet": "claude-sonnet-4-6",
      "claude-3-5-sonnet-latest": "claude-sonnet-4-6",
      "claude-3-5-haiku-latest": "claude-haiku-4-5",
      "claude-sonnet-latest": "claude-sonnet-4-6",
      "claude-opus-latest": "claude-opus-4-7",
      "claude-haiku-latest": "claude-haiku-4-5",
    };
    return aliases[key] || m || "claude-sonnet-4-6";
  }
  if (kind === "deepseek") {
    if (key === "deepseek-chat") return "deepseek-v4-flash";
    if (key === "deepseek-reasoner") return "deepseek-v4-pro";
    return m || "deepseek-v4-flash";
  }
  if (kind === "perplexity") {
    if (key === "sonar-large") return "sonar-pro";
    return m || "sonar-pro";
  }
  if (kind === "kimi") {
    if (key === "kimi-latest") return "kimi-k2.6";
    if (key === "kimi-k2-instruct") return "kimi-k2-0711-preview";
    return m || "kimi-k2.6";
  }
  return m;
}

function openAiUsesCompletionTokenParam(kind: AiProviderKind, model: string): boolean {
  return (kind === "openai" || kind === "azure-openai") && /^(?:gpt-5|o\d|o[134](?:-|$))/i.test(model);
}

function openAiSupportsTemperature(kind: AiProviderKind, model: string): boolean {
  return !(kind === "openai" || kind === "azure-openai") || !/^(?:o\d|o[134](?:-|$))/i.test(model);
}

function portraitModelForProvider(kind: AiProviderKind, model: string): string {
  const m = (model || "").trim();
  if (kind === "openai" || kind === "azure-openai") {
    return /^gpt-image-/i.test(m) ? m : OPENAI_PORTRAIT_MODEL;
  }
  if (kind === "gemini") {
    return /image/i.test(m) ? m : GEMINI_PORTRAIT_MODEL;
  }
  return m;
}

function portraitModelAttempts(kind: AiProviderKind, model: string): string[] {
  const primary = portraitModelForProvider(kind, model);
  if (kind === "gemini") return Array.from(new Set([primary, ...GEMINI_PORTRAIT_FALLBACK_MODELS]));
  return [primary];
}

function geminiThinkingLevel(model: string, images: LiveChatImage[], useUrlContext: boolean): "low" | "medium" | "high" {
  if (images.length > 0 || useUrlContext) return "high";
  return /flash/i.test(model) ? "medium" : "low";
}

function hasHttpUrl(text: string): boolean {
  return /\bhttps?:\/\/[^\s<>"'`]+/i.test(text);
}

function extractGeminiText(parsed: any): string | null {
  const candidates = Array.isArray(parsed?.candidates) ? parsed.candidates : [];
  const chunks: string[] = [];
  for (const candidate of candidates) {
    const parts = Array.isArray(candidate?.content?.parts) ? candidate.content.parts : [];
    for (const part of parts) {
      if (typeof part?.text === "string" && part.text.trim()) chunks.push(part.text);
    }
  }
  return chunks.length > 0 ? chunks.join("") : null;
}

/**
 * Streaming POST — issues an SSE-style chat-completions request with
 * `stream: true` set in the JSON body and concatenates every `data: { delta }`
 * chunk into the final aggregated content. This is the production path for
 * DeepSeek v4-pro and other reasoning models whose end-to-end latency exceeds
 * the 60s edge timeout that the non-streaming endpoint enforces.
 *
 * Returns the SAME shape as curlPost so the caller can reuse all existing
 * envelope-parsing helpers — the synthetic `body` is a single-line
 * `chat.completion` JSON envelope reconstructed from the assembled stream.
 *
 * On any parse error mid-stream we keep going and return whatever content we
 * managed to assemble; the caller's tryParseJsonObject will catch malformed
 * results just like the non-streaming path does.
 */
function curlPostStreaming(url: string, headers: Record<string, string>, body: string, timeoutSeconds?: number): CurlResult {
  const t = Math.max(1, Math.min(MAX_TIMEOUT_SECONDS, timeoutSeconds ?? TIMEOUT_SECONDS));
  const { latencyMs: _latencyMs, ...r } = curlRequestSync({
    method: "POST",
    url,
    headers,
    body,
    timeoutSeconds: t,
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
    contentType: "application/json",
    accept: "text/event-stream",
    protocolArgs: aiProviderProtocolArgs(url),
    noBuffer: true,
    maxBuffer: 64 * 1024 * 1024,
    statusMarker: "__BG_HTTP_STATUS__",
  });
  const status = r.status;
  const stream = r.body;
  const ok = status >= 200 && status < 300;

  // If the call failed the body is usually a plain JSON error envelope.
  if (!ok) return { ok, status, body: stream, error: r.error || `HTTP ${status}` };

  // Assemble content from every `data: { ... }` SSE chunk.
  const contentChunks: string[] = [];
  let usage: any = null;
  let model = "";
  let id = "";
  let finishReason: string | null = null;
  for (const rawLine of stream.split("\n")) {
    const line = rawLine.trim();
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]") continue;
    let parsed: any;
    try { parsed = JSON.parse(payload); } catch { continue; }
    if (!parsed || typeof parsed !== "object") continue;
    if (!id && typeof parsed.id === "string") id = parsed.id;
    if (!model && typeof parsed.model === "string") model = parsed.model;
    if (parsed.usage) usage = parsed.usage;
    const ch = Array.isArray(parsed.choices) ? parsed.choices[0] : null;
    if (!ch) continue;
    const delta = ch.delta || {};
    if (typeof delta.content === "string" && delta.content.length > 0) {
      contentChunks.push(delta.content);
    }
    if (typeof ch.finish_reason === "string") finishReason = ch.finish_reason;
  }

  // Reconstruct a non-streaming envelope so downstream parsers keep working.
  const content = contentChunks.join("");
  const envelope = {
    id: id || `synth-${Date.now()}`,
    object: "chat.completion",
    model,
    choices: [{
      index: 0,
      message: { role: "assistant", content },
      finish_reason: finishReason || "stop",
    }],
    ...(usage ? { usage } : {}),
  };
  return { ok: true, status, body: JSON.stringify(envelope) };
}

function curlGet(url: string, headers: Record<string, string>, opts?: { httpVersion?: "1.1" | "auto"; protocolGuard?: boolean }): CurlResult {
  const { latencyMs: _latencyMs, ...result } = curlRequestSync({
    method: "GET",
    url,
    headers,
    timeoutSeconds: TIMEOUT_SECONDS,
    protocolArgs: opts?.protocolGuard === false ? undefined : aiProviderProtocolArgs(url),
    statusMarker: "__BG_HTTP_STATUS__",
    httpVersion: opts?.httpVersion,
  });
  return result;
}

// ---------- per-provider base URL resolution ----------
function defaultBaseUrl(provider: string): string {
  switch (provider) {
    case "openai":       return "https://api.openai.com";
    case "deepseek":     return "https://api.deepseek.com";
    case "perplexity":   return "https://api.perplexity.ai";
    case "anthropic":    return "https://api.anthropic.com";
    case "gemini":       return "https://generativelanguage.googleapis.com";
    case "ollama":       return "http://localhost:11434";
    case "azure-openai": return "";  // user must provide base URL
    // Moonshot Kimi is OpenAI-compatible. International endpoint by default;
    // China-mainland users should override to https://api.moonshot.cn .
    case "kimi":         return "https://api.moonshot.ai";
    default:             return "";
  }
}

function stripTrailingSlash(s: string): string {
  return s.replace(/\/+$/, "");
}

function chatCompletionsUrl(kind: AiProviderKind, base: string) {
  const suffix = kind === "deepseek" || base.endsWith("/v1") ? "/chat/completions" : "/v1/chat/completions";
  return `${base}${suffix}`;
}

function modelsUrl(kind: AiProviderKind, base: string) {
  const suffix = kind === "deepseek" || base.endsWith("/v1") ? "/models" : "/v1/models";
  return `${base}${suffix}`;
}

// ---------- JSON extraction helpers ----------
/**
 * Some providers wrap JSON in ```json fenced blocks or prefix it with prose.
 * Try strict parse first; if that fails, extract the first {...} block.
 */
function tryParseJsonObject(s: string): Record<string, any> | null {
  if (!s) return null;
  const trimmed = s.trim();
  // Strict path
  try {
    const v = JSON.parse(trimmed);
    if (v && typeof v === "object" && !Array.isArray(v)) return v;
  } catch { /* fall through */ }
  // Fenced code block ```json ... ```
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) {
    try {
      const v = JSON.parse(fenced[1].trim());
      if (v && typeof v === "object" && !Array.isArray(v)) return v;
    } catch { /* continue */ }
  }
  // First {...} balanced run — naive but adequate for most provider quirks
  const first = trimmed.indexOf("{");
  const last = trimmed.lastIndexOf("}");
  if (first >= 0 && last > first) {
    const slice = trimmed.slice(first, last + 1);
    try {
      const v = JSON.parse(slice);
      if (v && typeof v === "object" && !Array.isArray(v)) return v;
    } catch { /* ignore */ }
  }
  return null;
}

/**
 * v2.26 — robust recovery of `choices[0].message.content` from an
 * OpenAI-compatible chat-completions envelope even when the envelope JSON is
 * truncated (e.g. server-side max-response-time on a very long DeepSeek
 * v4-pro reasoning run). We locate the `"content":"..."` field and decode
 * the embedded JSON string by hand, stopping at the first unescaped closing
 * quote OR end-of-buffer (treating a truncated trailing run as the
 * partially-streamed model output).
 *
 * Returns null when no plausible content field is present.
 */
function extractContentFromTruncatedEnvelope(raw: string): string | null {
  if (!raw) return null;
  // Find the FIRST occurrence of `"content":"` after a `"message":{` marker.
  const msgIdx = raw.indexOf("\"message\"");
  if (msgIdx < 0) return null;
  const contentKey = raw.indexOf("\"content\":\"", msgIdx);
  if (contentKey < 0) return null;
  let i = contentKey + "\"content\":\"".length;
  const out: string[] = [];
  while (i < raw.length) {
    const ch = raw.charCodeAt(i);
    if (ch === 0x5c /* \ */) {
      // JSON escape — consume next char or unicode quad.
      const nxt = raw[i + 1];
      if (nxt === undefined) break;
      if (nxt === "u" && i + 5 < raw.length) {
        const hex = raw.slice(i + 2, i + 6);
        const code = parseInt(hex, 16);
        if (!Number.isNaN(code)) out.push(String.fromCharCode(code));
        i += 6;
        continue;
      }
      switch (nxt) {
        case "n":  out.push("\n"); break;
        case "t":  out.push("\t"); break;
        case "r":  out.push("\r"); break;
        case "\"": out.push("\""); break;
        case "\\": out.push("\\"); break;
        case "/":  out.push("/"); break;
        case "b":  out.push("\b"); break;
        case "f":  out.push("\f"); break;
        default:   out.push(nxt); break;
      }
      i += 2;
      continue;
    }
    if (ch === 0x22 /* " */) {
      // Properly closed string.
      return out.join("");
    }
    out.push(raw[i]);
    i++;
  }
  // Stream ended mid-string — treat partial buffer as the truncated content.
  return out.length > 0 ? out.join("") : null;
}

// ---------- main entry: chat with JSON response ----------
/**
 * One image to attach to the user message. Used by vision-capable providers
 * (OpenAI vision-tier models, Anthropic Claude, Gemini, Kimi-Vision). Caller
 * is responsible for gating on provider.supportsVision before populating —
 * sending images to a text-only model burns input tokens and may error.
 */
export interface LiveChatImage {
  /** Logical role of this image (screenshot, logo, trademark, app_icon). */
  kind: string;
  /** Image mime type — must be one of image/png, image/jpeg, image/webp, image/gif. */
  mime: string;
  /** Raw base64-encoded bytes (no data: prefix). */
  dataBase64: string;
  /** Optional caption rendered next to the image in the text payload. */
  label?: string;
}

export interface LiveChatOptions {
  /** System prompt that establishes role + required JSON output schema. */
  system: string;
  /** User content — the task input, usually JSON.stringify of structured data. */
  user: string;
  /** Override default temperature (0.3). */
  temperature?: number;
  /** Override default 12s timeout (max 180s). Large reports need more. */
  timeoutSeconds?: number;
  /** Cap output tokens. Defaults to 2048; large CIRT reports want 4096+. */
  maxTokens?: number;
  /**
   * Optional image attachments. When non-empty and the provider supports
   * vision, each image is forwarded in the provider's native content-block
   * format (OpenAI-compatible: image_url; Anthropic: source/base64; Gemini:
   * inlineData). When the provider does NOT support vision, the images are
   * silently dropped — the user-text references them by metadata only.
   */
  images?: LiveChatImage[];
}

const ALLOWED_IMAGE_MIMES = new Set(["image/png", "image/jpeg", "image/jpg", "image/webp", "image/gif"]);

function filterImages(images?: LiveChatImage[]): LiveChatImage[] {
  if (!images || images.length === 0) return [];
  return images
    .filter((img) => img && typeof img.dataBase64 === "string" && img.dataBase64.length > 0
      && ALLOWED_IMAGE_MIMES.has((img.mime || "").toLowerCase()))
    .slice(0, 8); // hard cap so a misbehaving caller can't blow up the request
}

/** Anthropic only accepts media_type without the +xml/charset suffix. */
function normaliseAnthropicMime(mime: string): "image/jpeg" | "image/png" | "image/gif" | "image/webp" {
  const m = mime.toLowerCase();
  if (m === "image/jpg") return "image/jpeg";
  if (m === "image/jpeg" || m === "image/png" || m === "image/gif" || m === "image/webp") return m;
  return "image/png";
}

/** Diagnostic outcome from a live chat call — used by the chat triage / deep-dive
 *  endpoints (v2.15) so the UI can surface WHY a live call failed instead of
 *  silently falling back to a deterministic mock. */
export interface LiveChatDiagnostic {
  ok: boolean;
  result: Record<string, any> | null;
  /** Short human-readable reason when ok=false. */
  reason: string;
  /** HTTP status if a request was issued. 0 = no request reached the server. */
  httpStatus: number;
  /** Total round-trip latency in ms. */
  latencyMs: number;
  /** First ~400 chars of the raw provider response body, for debugging. */
  rawBodyPreview: string;
}

/**
 * Call the configured live provider with a JSON-mode chat completion request.
 * Returns the parsed JSON object on success, or null on any failure.
 *
 * The caller MUST validate the returned object's shape before using its fields.
 */
export function liveChatJson(provider: AiProvider, opts: LiveChatOptions): Record<string, any> | null {
  return liveChatJsonDiagnostic(provider, opts).result;
}

/** Same as liveChatJson but surfaces the failure reason for the v2.15 chat
 *  triage / deep-dive endpoints so the UI can show useful errors instead of
 *  silent mock fallback. */
export function liveChatJsonDiagnostic(provider: AiProvider, opts: LiveChatOptions): LiveChatDiagnostic {
  const start = Date.now();
  const kind = provider.provider as AiProviderKind;
  const apiKey = normaliseProviderApiKey(kind, dec(provider.apiKeyEnc));
  const base = stripTrailingSlash(provider.baseUrl || defaultBaseUrl(kind));
  const model = providerApiModel(kind, provider.model);
  const temperature = opts.temperature ?? 0.3;
  // v2.26 — unbounded token budget. When the caller passes maxTokens we honor
  // it verbatim (no upper cap); when omitted we don't send max_tokens at all
  // and let the provider use its model-level default (much larger than any
  // hard-coded cap we had previously). This eliminates silent truncation on
  // long DeepSeek v4-pro reasoning runs.
  const maxTokens = typeof opts.maxTokens === "number" && opts.maxTokens > 0 ? opts.maxTokens : null;
  const timeoutSeconds = opts.timeoutSeconds;

  const out = (reason: string, httpStatus = 0, rawBodyPreview = "", result: Record<string, any> | null = null): LiveChatDiagnostic =>
    ({ ok: result != null, result, reason, httpStatus, latencyMs: Date.now() - start, rawBodyPreview });

  // Ollama is the only family that can run keyless; everyone else needs a key.
  if (!apiKey && kind !== "ollama") return out("missing API key on configured provider");
  if (!base) return out("provider has no base URL");
  const baseUrlFailure = aiProviderBaseUrlSyncFailure(base);
  if (baseUrlFailure) return out(baseUrlFailure);
  if (!model) return out("provider has no model configured");

  try {
    if (kind === "openai" || kind === "deepseek" || kind === "perplexity" || kind === "azure-openai" || kind === "ollama" || kind === "kimi") {
      // OpenAI-compatible chat completions (Moonshot Kimi falls into this
      // branch; DeepSeek uses the same body shape but documents the path
      // without `/v1` under https://api.deepseek.com).
      const url = chatCompletionsUrl(kind, base);
      const headers: Record<string, string> = {};
      if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
      // Build the user message. When vision images are attached we switch
      // to the OpenAI content-array shape (text + image_url blocks); plain
      // text otherwise so we stay compatible with text-only models.
      const openAiImages = filterImages(opts.images);
      const jsonSystem = `${opts.system}\n\nReturn a valid JSON object only. Do not include markdown fences, prose outside the JSON object, or trailing commentary.`;
      const userContent: any = openAiImages.length > 0
        ? [
            { type: "text", text: `${opts.user}\n\nThe final answer must be valid JSON.` },
            ...openAiImages.map((img) => ({
              type: "image_url",
              image_url: {
                url: `data:${img.mime};base64,${img.dataBase64}`,
                detail: "low",
              },
            })),
          ]
        : `${opts.user}\n\nThe final answer must be valid JSON.`;
      // Perplexity ignores response_format; OpenAI/DeepSeek/Kimi honor it.
      const requestBody: Record<string, any> = {
        model,
        messages: [
          { role: "system", content: jsonSystem },
          { role: "user",   content: userContent },
        ],
      };
      if (openAiSupportsTemperature(kind, model)) requestBody.temperature = temperature;
      if (maxTokens !== null) {
        if (openAiUsesCompletionTokenParam(kind, model)) requestBody.max_completion_tokens = maxTokens;
        else requestBody.max_tokens = maxTokens;
      }
      // OpenAI + DeepSeek + Azure-OpenAI + Kimi accept response_format json_object.
      if (kind === "openai" || kind === "deepseek" || kind === "azure-openai" || kind === "kimi") {
        requestBody.response_format = { type: "json_object" };
      }
      // v2.28 — switch long-running calls (CIRT triage, deep-dive, TAP
      // enrichment; all pass timeoutSeconds > 60) to SERVER-SENT
      // EVENTS streaming. DeepSeek's non-streaming endpoint enforces a hard
      // ~60s edge timeout that closes the connection with HTTP 200 and a
      // single "\n" byte when the reasoning model is still thinking. With
      // `stream: true` the provider emits keep-alive SSE chunks the whole
      // time, so the connection never goes idle and we receive the full
      // assembled content even when the model takes 4-6 min to finish.
      const useStreaming = typeof timeoutSeconds === "number" && timeoutSeconds > 60
        && (kind === "openai" || kind === "deepseek" || kind === "azure-openai" || kind === "perplexity" || kind === "kimi");
      if (useStreaming) requestBody.stream = true;
      let r = useStreaming
        ? curlPostStreaming(url, headers, JSON.stringify(requestBody), timeoutSeconds)
        : curlPost(url, headers, JSON.stringify(requestBody), timeoutSeconds);
      if (kind === "deepseek" && !r.ok && r.status === 400 && requestBody.response_format) {
        // DeepSeek is strict about JSON mode. If the provider rejects
        // response_format for a model/region-specific reason, retry once with
        // explicit JSON instructions and parse the returned content ourselves.
        delete requestBody.response_format;
        r = useStreaming
          ? curlPostStreaming(url, headers, JSON.stringify(requestBody), timeoutSeconds)
          : curlPost(url, headers, JSON.stringify(requestBody), timeoutSeconds);
      }
      const preview = (r.body || "").slice(0, 400);
      if (!r.ok) return out(`HTTP ${r.status || "network"}${r.error ? " — " + r.error : ""}`, r.status, preview);

      // v2.28 — detect upstream-edge timeout: HTTP 200 with a body that is
      // empty or whitespace-only. This is what DeepSeek does at the 60s
      // mark on its non-streaming endpoint when the reasoning model is
      // still thinking. Surface an actionable message instead of the
      // generic "non-JSON envelope" so users can retry or narrow scope.
      if (!r.body || r.body.trim().length === 0) {
        return out(
          "upstream returned empty response after ~60s (DeepSeek edge timeout during model reasoning) — retry, or narrow scope (single tenant / shorter range) to reduce prompt size",
          r.status,
          preview,
        );
      }

      let choice: string | null = null;
      const parsed = tryParseJsonObject(r.body);
      if (parsed && typeof parsed.choices?.[0]?.message?.content === "string") {
        choice = parsed.choices[0].message.content;
      } else {
        // v2.26 — fall back to the truncation-tolerant extractor so long
        // DeepSeek v4-pro reasoning runs that exceed the upstream max
        // response time still surface the (partial) model output instead
        // of failing with a generic "non-JSON envelope" error.
        const recovered = extractContentFromTruncatedEnvelope(r.body);
        if (recovered && recovered.length > 0) choice = recovered;
      }
      if (typeof choice !== "string" || choice.trim().length === 0) {
        return out(
          "provider returned envelope with empty content (model reasoning may have consumed full token budget) — try raising maxTokens or narrowing scope",
          r.status,
          preview,
        );
      }
      const json = tryParseJsonObject(choice);
      if (!json) return out("model response was not valid JSON (consider raising maxTokens for long reports)", r.status, choice.slice(0, 400));
      return out("ok", r.status, choice.slice(0, 400), json);
    }

    if (kind === "anthropic") {
      // Anthropic Messages API: system is a top-level field, not a message.
      const url = `${base}/v1/messages`;
      const headers: Record<string, string> = {
        "x-api-key": apiKey || "",
        "anthropic-version": "2023-06-01",
      };
      // Anthropic Messages API REQUIRES max_tokens. Use a very large value
      // (200k tokens — well above any Claude model output limit) when caller
      // didn't specify, so the model decides where to stop.
      const anthropicMaxTokens = maxTokens ?? 200000;
      const anthropicImages = filterImages(opts.images);
      const anthropicUserContent: any = anthropicImages.length > 0
        ? [
            { type: "text", text: opts.user },
            ...anthropicImages.map((img) => ({
              type: "image",
              source: {
                type: "base64",
                media_type: normaliseAnthropicMime(img.mime),
                data: img.dataBase64,
              },
            })),
          ]
        : [{ type: "text", text: opts.user }];
      const requestBody = {
        model,
        max_tokens: anthropicMaxTokens,
        system: opts.system,
        messages: [{ role: "user", content: anthropicUserContent }],
        temperature,
      };
      const r = curlPost(url, headers, JSON.stringify(requestBody), timeoutSeconds);
      const preview = (r.body || "").slice(0, 400);
      if (!r.ok) return out(`HTTP ${r.status || "network"}${r.error ? " — " + r.error : ""}`, r.status, preview);
      const parsed = tryParseJsonObject(r.body);
      if (!parsed) return out("anthropic returned non-JSON envelope", r.status, preview);
      const blocks = parsed.content;
      if (!Array.isArray(blocks)) return out("anthropic response missing content blocks", r.status, preview);
      const text = blocks.map((b: any) => (b?.type === "text" ? b.text : "")).join("");
      const json = tryParseJsonObject(text);
      if (!json) return out("model response was not valid JSON", r.status, text.slice(0, 400));
      return out("ok", r.status, text.slice(0, 400), json);
    }

    if (kind === "gemini") {
      const effectiveModel = providerApiModel(kind, model);
      const url = `${base}/v1beta/models/${encodeURIComponent(effectiveModel)}:generateContent`;
      const headers: Record<string, string> = { "X-goog-api-key": apiKey || "" };
      const geminiImages = filterImages(opts.images);
      const canUseUrlContext = supportsGeminiUrlContext(effectiveModel) && hasHttpUrl(opts.user);
      const geminiParts: any[] = [{
        text: `${opts.user}\n\nThe final answer must be one valid JSON object only. Start with { and end with }. Do not include markdown, prose, or commentary outside the JSON object.`,
      }];
      for (const img of geminiImages) {
        geminiParts.push({ inlineData: { mimeType: img.mime, data: img.dataBase64 } });
      }
      const geminiMaxTokens = maxTokens !== null ? Math.min(maxTokens, 16000) : null;
      const generationConfig: Record<string, any> = {
        responseMimeType: "application/json",
        ...(geminiMaxTokens !== null ? { maxOutputTokens: geminiMaxTokens } : {}),
      };
      if (isGemini3Model(effectiveModel)) {
        generationConfig.thinkingConfig = {
          thinkingLevel: geminiThinkingLevel(effectiveModel, geminiImages, canUseUrlContext),
        };
      } else {
        generationConfig.temperature = temperature;
      }
      const requestBody: Record<string, any> = {
        systemInstruction: { role: "system", parts: [{ text: opts.system }] },
        contents: [{ role: "user", parts: geminiParts }],
        generationConfig,
      };
      if (canUseUrlContext) requestBody.tools = [{ url_context: {} }];
      let r = curlPost(url, headers, JSON.stringify(requestBody), timeoutSeconds, { httpVersion: "auto" });
      if (!r.ok && isRetryableGeminiTransportFailure(r)) {
        const retryModel = geminiFallbackModel(effectiveModel);
        if (!retryModel) {
          const preview = (r.body || "").slice(0, 400);
          return out(`HTTP ${r.status || "network"}${r.error ? " — " + r.error : ""}`, r.status, preview);
        }
        const retryUrl = `${base}/v1beta/models/${encodeURIComponent(retryModel)}:generateContent`;
        r = curlPost(retryUrl, headers, JSON.stringify(requestBody), timeoutSeconds, { httpVersion: "auto" });
      }
      const preview = (r.body || "").slice(0, 400);
      if (!r.ok) return out(`HTTP ${r.status || "network"}${r.error ? " — " + r.error : ""}`, r.status, preview);
      const parsed = tryParseJsonObject(r.body);
      if (!parsed) return out("gemini returned non-JSON envelope", r.status, preview);
      const text = extractGeminiText(parsed);
      if (typeof text !== "string") return out("gemini response missing candidate text", r.status, preview);
      const json = tryParseJsonObject(text);
      if (!json) return out("model response was not valid JSON", r.status, text.slice(0, 400));
      return out("ok", r.status, text.slice(0, 400), json);
    }
  } catch (e: any) {
    return out(`exception: ${e?.message || String(e)}`);
  }
  return out(`unsupported provider kind: ${kind}`);
}

// ---------- provider connectivity ping ----------
export interface LivePingResult {
  ok: boolean;
  latencyMs: number;
  message: string;
}

/**
 * Confirm the provider responds. Uses a lightweight endpoint that does not
 * consume meaningful credits:
 *   • OpenAI-compatible: GET /v1/models (lists configured models)
 *   • Anthropic: POST /v1/messages with max_tokens=1 (smallest possible completion)
 *   • Gemini: GET /v1beta/models?key=… (lists models)
 */
export function livePing(provider: AiProvider): LivePingResult {
  const kind = provider.provider as AiProviderKind;
  const apiKey = normaliseProviderApiKey(kind, dec(provider.apiKeyEnc));
  const base = stripTrailingSlash(provider.baseUrl || defaultBaseUrl(kind));

  if (!apiKey && kind !== "ollama") {
    return { ok: false, latencyMs: 0, message: `${provider.label}: missing API key` };
  }
  if (!base) {
    return { ok: false, latencyMs: 0, message: `${provider.label}: missing base URL` };
  }
  const baseUrlFailure = aiProviderBaseUrlSyncFailure(base);
  if (baseUrlFailure) {
    return { ok: false, latencyMs: 0, message: `${provider.label}: ${baseUrlFailure}` };
  }

  const t0 = Date.now();
  try {
    if (kind === "openai" || kind === "deepseek" || kind === "perplexity" || kind === "azure-openai" || kind === "ollama" || kind === "kimi") {
      const selectedModel = providerApiModel(kind, provider.model);
      const probeHeaders: Record<string, string> = {};
      if (apiKey) probeHeaders["Authorization"] = `Bearer ${apiKey}`;
      if (!/^gpt-image-/i.test(selectedModel)) {
        const probe = curlPost(chatCompletionsUrl(kind, base), probeHeaders, JSON.stringify({
          model: selectedModel,
          messages: [{ role: "user", content: "Reply with ok." }],
          ...(openAiUsesCompletionTokenParam(kind, selectedModel) ? { max_completion_tokens: 8 } : { max_tokens: 8 }),
        }));
        const latencyMs = Date.now() - t0;
        if (probe.ok) {
          return { ok: true, latencyMs, message: `${provider.label} (${selectedModel}) — connected via chat` };
        }
        // Some OpenAI accounts expose newest model ids in /models before they
        // are enabled for chat-completions. Treat that as a failed selected
        // model test so users do not route jobs to a model that cannot run.
        if (kind === "openai" || kind === "azure-openai" || kind === "deepseek" || kind === "kimi" || kind === "perplexity") {
          return { ok: false, latencyMs, message: `${provider.label}: ${probe.status ? `HTTP ${probe.status}` : "network"}${probe.error ? ` — ${probe.error}` : ""}` };
        }
      }

      // Image-only OpenAI models and local Ollama discovery can still be
      // validated by model listing when a chat probe is not meaningful.
      const url = modelsUrl(kind, base);
      const headers: Record<string, string> = {};
      if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
      const r = curlGet(url, headers);
      const latencyMs = Date.now() - t0;
      if (r.ok) {
        return { ok: true, latencyMs, message: `${provider.label} (${provider.model}) — connected` };
      }
      return { ok: false, latencyMs, message: `${provider.label}: ${r.status ? `HTTP ${r.status}` : "network"}${r.error ? ` — ${r.error}` : ""}` };
    }

    if (kind === "anthropic") {
      const url = `${base}/v1/messages`;
      const headers: Record<string, string> = {
        "x-api-key": apiKey || "",
        "anthropic-version": "2023-06-01",
      };
      const body = JSON.stringify({
        model: provider.model,
        max_tokens: 1,
        messages: [{ role: "user", content: "ping" }],
      });
      const r = curlPost(url, headers, body);
      const latencyMs = Date.now() - t0;
      if (r.ok) return { ok: true, latencyMs, message: `${provider.label} (${provider.model}) — connected` };
      return { ok: false, latencyMs, message: `${provider.label}: ${r.status ? `HTTP ${r.status}` : (r.error || "no response")}` };
    }

    if (kind === "gemini") {
      const effectiveModel = providerApiModel(kind, provider.model);
      const modelAttempts = geminiConnectivityAttempts(effectiveModel);
      // Keep this probe aligned with Google's REST quickstart shape. A
      // connection test should prove auth/model reachability; task-specific
      // JSON validation happens in liveChatJsonDiagnostic().
      const body = JSON.stringify({
        contents: [{ parts: [{ text: "Explain how AI works in a few words" }] }],
        generationConfig: {
          maxOutputTokens: 64,
          temperature: 0,
        },
      });
      let lastFailure: CurlResult | null = null;
      for (const attemptModel of modelAttempts) {
        const url = `${base}/v1beta/models/${encodeURIComponent(attemptModel)}:generateContent`;
        const r = curlPost(url, { "X-goog-api-key": apiKey || "" }, body, 18, { httpVersion: "auto" });
        const latencyMs = Date.now() - t0;
        if (r.ok) {
          const parsed = tryParseJsonObject(r.body);
          const text = parsed ? (extractGeminiText(parsed) ?? "") : "";
          if (text.trim().length > 0) {
            const modelLabel = attemptModel === provider.model
              ? provider.model
              : `${provider.model} -> ${attemptModel}`;
            return { ok: true, latencyMs, message: `${provider.label} (${modelLabel}) — connected via generateContent` };
          }
          const finishReason = String(parsed?.candidates?.[0]?.finishReason || "");
          if (finishReason === "MAX_TOKENS") {
            lastFailure = r;
            continue;
          }
          return { ok: false, latencyMs, message: `${provider.label}: HTTP ${r.status} but response had no candidate text` };
        }
        lastFailure = r;
        if (!isRetryableGeminiTransportFailure(r)) break;
      }
      const latencyMs = Date.now() - t0;
      const r = lastFailure;
      return { ok: false, latencyMs, message: `${provider.label}: ${r?.status ? `HTTP ${r.status}` : "network"}${r?.error ? ` — ${r.error}` : ""}` };
    }
  } catch (e: any) {
    return { ok: false, latencyMs: Date.now() - t0, message: `${provider.label}: ${e?.message ?? String(e)}` };
  }
  return { ok: false, latencyMs: Date.now() - t0, message: `${provider.label}: unsupported provider kind` };
}

// ---------- developer convenience: detect whether a provider has a usable key ----------
export function providerHasUsableKey(provider: AiProvider): boolean {
  if (provider.provider === "ollama") return true;
  return !!dec(provider.apiKeyEnc);
}

export interface LiveImageResult {
  ok: boolean;
  status?: number;
  mimeType?: string;
  data?: Buffer;
  message: string;
}

function firstImageFromGeminiEnvelope(parsed: any): { mimeType: string; dataBase64: string } | null {
  const candidates = Array.isArray(parsed?.candidates) ? parsed.candidates : [];
  for (const candidate of candidates) {
    const parts = Array.isArray(candidate?.content?.parts) ? candidate.content.parts : [];
    for (const part of parts) {
      const inline = part?.inlineData ?? part?.inline_data;
      const data = inline?.data;
      if (typeof data === "string" && data.trim()) {
        return {
          mimeType: String(inline?.mimeType ?? inline?.mime_type ?? "image/png"),
          dataBase64: data,
        };
      }
    }
  }
  return null;
}

/**
 * Generate one TAP portrait image through the encrypted AI Setup provider row.
 * Supported in BatchOne:
 *   - OpenAI Image API: gpt-image-2 / gpt-image-1.5 / gpt-image-1
 *   - Gemini native image models: gemini-3.1-flash-image / gemini-3-pro-image
 *
 * Text-only providers return a clear unsupported message so the UI can route
 * them to TAP enrichment without implying portrait capability.
 */
export function liveGenerateImage(provider: AiProvider, prompt: string, opts?: { timeoutSeconds?: number }): LiveImageResult {
  const kind = provider.provider as AiProviderKind;
  const apiKey = normaliseProviderApiKey(kind, dec(provider.apiKeyEnc));
  const base = stripTrailingSlash(provider.baseUrl || defaultBaseUrl(kind));
  const timeoutSeconds = opts?.timeoutSeconds ?? 300;

  if (!apiKey) return { ok: false, message: `${provider.label}: missing API key` };
  const baseUrlFailure = aiProviderBaseUrlSyncFailure(base);
  if (baseUrlFailure) return { ok: false, message: `${provider.label}: ${baseUrlFailure}` };

  if (kind === "openai" || kind === "azure-openai") {
    const model = portraitModelForProvider(kind, provider.model);
    const url = kind === "azure-openai" && base
      ? `${base}/images/generations`
      : "https://api.openai.com/v1/images/generations";
    const headers: Record<string, string> = { Authorization: `Bearer ${apiKey}` };
    const r = curlPost(url, headers, JSON.stringify({
      model,
      prompt,
      n: 1,
      size: "1024x1024",
      quality: "medium",
    }), timeoutSeconds);
    const preview = (r.body || "").slice(0, 400);
    if (!r.ok) return { ok: false, status: r.status, message: `${provider.label}: HTTP ${r.status || "network"}${r.error ? ` — ${r.error}` : ""}` };
    const parsed = tryParseJsonObject(r.body);
    const b64 = parsed?.data?.[0]?.b64_json;
    if (typeof b64 !== "string" || !b64.trim()) {
      return { ok: false, status: r.status, message: `${provider.label}: image response did not include base64 data: ${preview}` };
    }
    return { ok: true, status: r.status, mimeType: "image/png", data: Buffer.from(b64, "base64"), message: "ok" };
  }

  if (kind === "gemini") {
    let last: CurlResult | null = null;
    for (const model of portraitModelAttempts(kind, provider.model)) {
      const url = `${base}/v1/models/${encodeURIComponent(model)}:generateContent`;
      const r = curlPost(url, { "X-goog-api-key": apiKey }, JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: {
          responseFormat: {
            image: {
              aspectRatio: "1:1",
              imageSize: "1K",
            },
          },
        },
      }), timeoutSeconds, { httpVersion: "auto" });
      last = r;
      const parsed = tryParseJsonObject(r.body);
      if (r.ok && parsed) {
        const image = firstImageFromGeminiEnvelope(parsed);
        if (image) return { ok: true, status: r.status, mimeType: image.mimeType, data: Buffer.from(image.dataBase64, "base64"), message: `ok (${model})` };
      }
      if (!isRetryableGeminiTransportFailure(r) && r.status !== 404 && r.status !== 400) break;
    }
    const preview = (last?.body || "").slice(0, 400);
    if (!last?.ok) return { ok: false, status: last?.status, message: `${provider.label}: HTTP ${last?.status || "network"}${last?.error ? ` — ${last.error}` : ""}` };
    const parsed = tryParseJsonObject(last.body);
    if (!parsed) return { ok: false, status: last.status, message: `${provider.label}: image response was not valid JSON` };
    return { ok: false, status: last.status, message: `${provider.label}: image response did not include inline image data: ${preview}` };
  }

  return { ok: false, message: `${provider.label}: ${kind} is text-only for BatchOne TAP portrait generation` };
}
