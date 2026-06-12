/**
 * Source URL fetcher — v2.13.
 *
 * Lets AI tasks pull the *original* article text directly from the source URL
 * instead of relying only on the short summary we ingested from the feed.
 *
 * Design notes:
 *   • Uses Node's built-in fetch (no extra dependency) with a 10-second timeout.
 *   • Caps response at 200 KB to keep prompt sizes reasonable.
 *   • Strips HTML tags, script/style blocks, and excess whitespace.
 *   • In-memory LRU cache (TTL 24 h, max 200 entries) so repeated runs over
 *     the same finding don't re-hit the source server.
 *   • All errors are swallowed and surfaced as null — callers degrade
 *     gracefully to the stored summary / rawSnippet.
 */

import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

const TIMEOUT_MS = 10_000;
const MAX_BYTES = 200_000;
const MAX_CHARS = 18_000;     // post-strip cap fed to the LLM
const MAX_CONTEXT_CHARS = 30_000;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_MAX = 200;
const MAX_REDIRECTS = 5;
const SAFE_PORTS = new Set(["", "80", "443"]);
const SKIP_LINK_EXTENSIONS = /\.(?:7z|avi|bmp|css|csv|docx?|gif|gz|ico|jpe?g|js|mov|mp3|mp4|mpeg|png|pptx?|rar|svg|tar|tgz|wav|webm|webp|xlsx?|zip)(?:$|[?#])/i;
const LOW_VALUE_LINK_PATH = /\/(?:about|advertis(?:e|ing)|author|authors|careers|category|categories|contact|cookie|events?|feed|login|newsletter|partners?|podcast|privacy|register|rss|search|signin|signup|sponsored|subscribe|tag|tags|terms)(?:\/|$)/i;
const LOW_VALUE_LINK_HOST = /(?:facebook|instagram|linkedin|reddit|tiktok|x\.com|twitter|youtube|discord|slack)\.com$/i;
const HIGH_VALUE_LINK_HOST = /(?:attack\.mitre\.org|nvd\.nist\.gov|cve\.mitre\.org|cisa\.gov|github\.com|gitlab\.com|virustotal\.com|hybrid-analysis\.com|malwarebazaar\.abuse\.ch|urlhaus\.abuse\.ch|cert\.[^/]+|msrc\.microsoft\.com|learn\.microsoft\.com|cloud\.google\.com|mandiant\.com|crowdstrike\.com|unit42\.paloaltonetworks\.com|talosintelligence\.com|securelist\.com|welivesecurity\.com|fortinet\.com|sophos\.com|trendmicro\.com|proofpoint\.com|recordedfuture\.com|bleepingcomputer\.com|thehackernews\.com|securityweek\.com|darkreading\.com)$/i;

type CacheEntry = { value: string | null; expiresAt: number };
type SafeResolvedUrl = { parsed: URL; address: string; family: 4 | 6 };
type PinnedFetchResponse = { status: number; headers: Record<string, string | string[] | undefined>; body: Buffer };
type SourceArticle = { text: string; referencedUrls: string[] };
const CACHE = new Map<string, CacheEntry>();

function cacheGet(url: string): string | null | undefined {
  const e = CACHE.get(url);
  if (!e) return undefined;
  if (Date.now() > e.expiresAt) {
    CACHE.delete(url);
    return undefined;
  }
  // Refresh LRU position
  CACHE.delete(url);
  CACHE.set(url, e);
  return e.value;
}

function cacheSet(url: string, value: string | null) {
  if (CACHE.size >= CACHE_MAX) {
    const firstKey = CACHE.keys().next().value;
    if (firstKey) CACHE.delete(firstKey);
  }
  CACHE.set(url, { value, expiresAt: Date.now() + CACHE_TTL_MS });
}

function stripHtml(html: string): string {
  return html
    // Remove scripts, styles, head, nav-ish blocks
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, " ")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, " ")
    .replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, " ")
    .replace(/<header\b[^<]*(?:(?!<\/header>)<[^<]*)*<\/header>/gi, " ")
    .replace(/<footer\b[^<]*(?:(?!<\/footer>)<[^<]*)*<\/footer>/gi, " ")
    .replace(/<nav\b[^<]*(?:(?!<\/nav>)<[^<]*)*<\/nav>/gi, " ")
    .replace(/<aside\b[^<]*(?:(?!<\/aside>)<[^<]*)*<\/aside>/gi, " ")
    // Strip all remaining tags
    .replace(/<[^>]+>/g, " ")
    // HTML entities
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&hellip;/g, "…")
    // RSS feeds often entity-encode article HTML inside content:encoded.
    .replace(/<[^>]+>/g, " ")
    // Collapse whitespace
    .replace(/\s+/g, " ")
    .trim();
}

function decodeHtmlAttribute(value: string): string {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");
}

function normaliseSourceLink(raw: string, baseUrl: string): string | null {
  const cleaned = decodeHtmlAttribute(raw).trim();
  if (!cleaned || cleaned.startsWith("#")) return null;
  if (/^(?:mailto|tel|javascript|data):/i.test(cleaned)) return null;
  let parsed: URL;
  try {
    parsed = new URL(cleaned, baseUrl);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  parsed.hash = "";
  const href = parsed.toString();
  if (href === baseUrl || SKIP_LINK_EXTENSIONS.test(parsed.pathname)) return null;
  return href;
}

function extractReferencedUrls(html: string, baseUrl: string, maxLinks: number): string[] {
  const candidates: string[] = [];
  const seen = new Set<string>();
  const add = (candidate: string | null) => {
    if (!candidate || seen.has(candidate)) return;
    seen.add(candidate);
    candidates.push(candidate);
  };
  for (const m of html.matchAll(/\bhref\s*=\s*["']([^"']+)["']/gi)) {
    add(normaliseSourceLink(m[1], baseUrl));
  }
  for (const m of html.matchAll(/\bhttps?:\/\/[^\s<>"')]+/gi)) {
    add(normaliseSourceLink(m[0], baseUrl));
  }
  return candidates
    .map((url, ordinal) => ({ url, ordinal, score: scoreReferencedUrl(url, baseUrl) }))
    .filter((item) => item.score > -50)
    .sort((a, b) => b.score - a.score || a.ordinal - b.ordinal)
    .slice(0, maxLinks)
    .map((item) => item.url);
}

export function extractReferencedUrlsForTest(html: string, baseUrl: string, maxLinks: number): string[] {
  return extractReferencedUrls(html, baseUrl, maxLinks);
}

function scoreReferencedUrl(url: string, baseUrl: string): number {
  let parsed: URL;
  let base: URL;
  try {
    parsed = new URL(url);
    base = new URL(baseUrl);
  } catch {
    return -100;
  }
  const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const baseHost = base.hostname.toLowerCase().replace(/^www\./, "");
  if (LOW_VALUE_LINK_HOST.test(host)) return -100;
  if (LOW_VALUE_LINK_PATH.test(parsed.pathname)) return -80;

  let score = 0;
  if (host !== baseHost) score += 18;
  if (HIGH_VALUE_LINK_HOST.test(host)) score += 55;
  if (/(?:cve-\d{4}-\d+|\/cve\/|\/kev|\/advisor|\/security|\/vulnerab|\/malware|\/threat|\/ioc|\/indicator|\/attack|\/apt|\/ransom|\/research)/i.test(`${parsed.pathname} ${parsed.search}`)) score += 24;
  if (/\.(?:pdf|txt)$/i.test(parsed.pathname)) score += 10;
  if (parsed.searchParams.has("utm_source") || parsed.searchParams.has("utm_campaign")) score -= 6;
  return score;
}

function ipv4ToInt(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    out = (out << 8) + n;
  }
  return out >>> 0;
}

function ipv4InCidr(address: string, base: string, bits: number): boolean {
  const addr = ipv4ToInt(address);
  const root = ipv4ToInt(base);
  if (addr == null || root == null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (addr & mask) === (root & mask);
}

export function isPrivateOrReservedAddress(address: string): boolean {
  const lower = address.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower)?.[1];
  const ipv4 = mapped ?? address;
  if (ipv4ToInt(ipv4) != null) {
    return [
      ["0.0.0.0", 8],
      ["10.0.0.0", 8],
      ["100.64.0.0", 10],
      ["127.0.0.0", 8],
      ["169.254.0.0", 16],
      ["172.16.0.0", 12],
      ["192.0.0.0", 24],
      ["192.0.2.0", 24],
      ["192.168.0.0", 16],
      ["198.18.0.0", 15],
      ["198.51.100.0", 24],
      ["203.0.113.0", 24],
      ["224.0.0.0", 4],
      ["240.0.0.0", 4],
    ].some(([base, bits]) => ipv4InCidr(ipv4, base as string, bits as number));
  }
  return lower === "::"
    || lower === "::1"
    || lower.startsWith("fc")
    || lower.startsWith("fd")
    || lower.startsWith("fe80:")
    || lower.startsWith("ff")
    || lower.startsWith("2001:db8:");
}

export async function resolveSafeSourceFetchUrl(url: string | null | undefined): Promise<SafeResolvedUrl | null> {
  if (!url || typeof url !== "string") return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  if (!SAFE_PORTS.has(parsed.port)) return null;
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost"
    || host === "localhost."
    || host.endsWith(".localhost")
    || host.endsWith(".local")
    || host.endsWith(".internal")
  ) return null;
  if (isPrivateOrReservedAddress(host)) return null;
  try {
    const addresses = await lookup(host, { all: true, verbatim: false });
    const safe = addresses.filter((entry) => !isPrivateOrReservedAddress(entry.address));
    if (safe.length === 0 || safe.length !== addresses.length) return null;
    const chosen = safe[0];
    if (chosen.family !== 4 && chosen.family !== 6) return null;
    return { parsed, address: chosen.address, family: chosen.family };
  } catch {
    return null;
  }
}

export async function isSafeSourceFetchUrl(url: string | null | undefined): Promise<boolean> {
  return (await resolveSafeSourceFetchUrl(url)) !== null;
}

async function fetchValidatedUrl(url: string, controller: AbortController, redirects = 0): Promise<PinnedFetchResponse | null> {
  if (redirects > MAX_REDIRECTS) return null;
  const resolved = await resolveSafeSourceFetchUrl(url);
  if (!resolved) return null;
  const { parsed, address, family } = resolved;
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: PinnedFetchResponse | null) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    const client = parsed.protocol === "https:" ? httpsRequest : httpRequest;
    const req = client({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: `${parsed.pathname}${parsed.search}`,
      method: "GET",
      signal: controller.signal,
      lookup: (_hostname, opts, cb) => {
        if ((opts as { all?: boolean } | undefined)?.all) {
          cb(null, [{ address, family }] as any, undefined as any);
        } else {
          cb(null, address, family);
        }
      },
      headers: {
      // Pretend to be a real browser; many intel sites 403 default fetch UA.
        "User-Agent": "Mozilla/5.0 (compatible; OptraSightBot/2.28; +https://optrasight.local)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en;q=0.9,*;q=0.7",
      },
    }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode || 0)) {
        const location = res.headers.location;
        res.resume();
        if (!location || Array.isArray(location)) return done(null);
        const next = new URL(location, url).toString();
        fetchValidatedUrl(next, controller, redirects + 1).then(done, () => done(null));
        return;
      }
      let bytes = 0;
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => {
        if (settled) return;
        bytes += chunk.byteLength;
        chunks.push(chunk);
        if (bytes >= MAX_BYTES) {
          done({ status: res.statusCode || 0, headers: res.headers, body: Buffer.concat(chunks, Math.min(bytes, MAX_BYTES)) });
          res.destroy();
        }
      });
      res.on("end", () => {
        done({ status: res.statusCode || 0, headers: res.headers, body: Buffer.concat(chunks, bytes) });
      });
      res.on("error", () => done(null));
    });
    req.setTimeout(TIMEOUT_MS, () => {
      req.destroy();
      done(null);
    });
    req.on("error", () => done(null));
    req.end();
  });
}

function headerValue(headers: Record<string, string | string[] | undefined>, name: string): string {
  const raw = headers[name.toLowerCase()];
  return Array.isArray(raw) ? raw.join(", ") : raw || "";
}

async function fetchSourceArticle(url: string | null | undefined, linkBudget = 0): Promise<SourceArticle | null> {
  if (!url || typeof url !== "string") return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetchValidatedUrl(url, controller);
    if (!res) {
      return null;
    }
    if (res.status < 200 || res.status >= 300) {
      return null;
    }
    const ct = headerValue(res.headers, "content-type").toLowerCase();
    if (ct && !ct.includes("text") && !ct.includes("xml") && !ct.includes("json")) {
      return null;
    }
    const html = res.body.toString("utf8");
    let text = stripHtml(html);
    if (text.length > MAX_CHARS) text = text.slice(0, MAX_CHARS) + " …[truncated]";
    if (!text || text.length < 40) {
      return null;
    }
    return { text, referencedUrls: linkBudget > 0 ? extractReferencedUrls(html, url, linkBudget) : [] };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch a URL and return cleaned plain-text content suitable for AI prompts.
 * Returns null if the URL is invalid, the request fails, the response is
 * non-text, or the cleaned content is empty.
 */
export async function fetchSourceContent(url: string | null | undefined): Promise<string | null> {
  if (!url || typeof url !== "string") return null;
  const cached = cacheGet(url);
  if (cached !== undefined) return cached;
  const article = await fetchSourceArticle(url, 0);
  const text = article?.text ?? null;
  cacheSet(url, text);
  return text;
}

export async function fetchSourceContentWithReferences(
  url: string | null | undefined,
  opts?: { maxReferenceLinks?: number },
): Promise<string | null> {
  if (!url || typeof url !== "string") return null;
  const maxReferenceLinks = Math.max(0, Math.min(opts?.maxReferenceLinks ?? 3, 6));
  const article = await fetchSourceArticle(url, maxReferenceLinks);
  if (!article) return null;

  const sections = [
    [
      `Primary source (${url}):`,
      article.text,
      "",
      "Supplemental referenced sources below were discovered inside the primary source page and fetched server-side. Use them only as supporting evidence for context, CVE details, vendor advisories, linked research, or IoC confirmation.",
    ].join("\n"),
  ];
  let used = sections[0].length;
  for (const refUrl of article.referencedUrls.slice(0, maxReferenceLinks)) {
    const refText = await fetchSourceContent(refUrl);
    if (!refText) continue;
    const remaining = MAX_CONTEXT_CHARS - used;
    if (remaining < 800) break;
    const clipped = refText.length > Math.min(4_000, remaining)
      ? `${refText.slice(0, Math.min(4_000, remaining))} …[truncated]`
      : refText;
    const block = `Referenced source (${refUrl}):\n${clipped}`;
    sections.push(block);
    used += block.length + 2;
  }
  return sections.join("\n\n").slice(0, MAX_CONTEXT_CHARS);
}

/**
 * Fetch many URLs in parallel. Returns an array of [url, content|null] tuples
 * preserving input order. Safe to call with up to ~20 URLs; uses concurrency
 * limit of 5 to be polite to source servers.
 */
export async function fetchSourcesBatch(
  urls: Array<string | null | undefined>,
  opts?: { includeReferences?: boolean; maxReferenceLinks?: number },
): Promise<Array<{ url: string; content: string | null }>> {
  const valid: Array<{ idx: number; url: string }> = [];
  const out: Array<{ url: string; content: string | null }> = urls.map((u) => ({ url: u || "", content: null }));
  urls.forEach((u, i) => { if (u && typeof u === "string") valid.push({ idx: i, url: u }); });

  const CONC = 5;
  let cursor = 0;
  async function worker() {
    while (cursor < valid.length) {
      const my = cursor++;
      const v = valid[my];
      const content = opts?.includeReferences
        ? await fetchSourceContentWithReferences(v.url, { maxReferenceLinks: opts.maxReferenceLinks })
        : await fetchSourceContent(v.url);
      out[v.idx] = { url: v.url, content };
    }
  }
  const workers: Promise<void>[] = [];
  for (let k = 0; k < Math.min(CONC, valid.length); k++) workers.push(worker());
  await Promise.all(workers);
  return out;
}
