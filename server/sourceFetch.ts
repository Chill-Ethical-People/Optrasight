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
const MAX_CHARS = 24_000;     // post-strip cap fed to the LLM
const MAX_CONTEXT_CHARS = 96_000;
const MAX_REFERENCE_PAGES = 24;
const MAX_REFERENCE_DEPTH = 2;
const MAX_DISCOVERED_LINKS_PER_PAGE = 64;
const REFERENCE_FETCH_CONCURRENCY = 4;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_MAX = 200;
const MAX_REDIRECTS = 5;
const SAFE_PORTS = new Set(["", "80", "443"]);
const SKIP_LINK_EXTENSIONS = /\.(?:7z|avi|bmp|css|csv|docx?|gif|gz|ico|jpe?g|js|mov|mp3|mp4|mpeg|png|pptx?|rar|svg|tar|tgz|wav|webm|webp|xlsx?|zip)(?:$|[?#])/i;
const LOW_VALUE_LINK_PATH = /\/(?:about|advertis(?:e|ing)|author|authors|careers|category|categories|contact|cookie|events?|feed|login|newsletter|partners?|podcast|privacy|register|rss|search|signin|signup|sponsored|subscribe|tag|tags|terms)(?:\/|$)/i;
const LOW_VALUE_LINK_HOST = /^(?:x\.com|(?:facebook|instagram|linkedin|reddit|tiktok|twitter|youtube|discord|slack)\.com)$/i;

type CacheEntry = { value: string | null; expiresAt: number };
type SafeResolvedUrl = { parsed: URL; address: string; family: 4 | 6 };
type PinnedFetchResponse = { status: number; headers: Record<string, string | string[] | undefined>; body: Buffer };
type SourceArticle = { text: string; referencedUrls: string[] };
type SourceEvidencePage = SourceArticle & { url: string; parentUrl: string | null; depth: number };
type SourceEvidenceGraph = {
  pages: SourceEvidencePage[];
  unavailableUrls: string[];
  unfetchedUrls: string[];
};
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
  for (const key of Array.from(parsed.searchParams.keys())) {
    if (/^(?:utm_.+|fbclid|gclid|mc_cid|mc_eid)$/i.test(key)) parsed.searchParams.delete(key);
  }
  const href = parsed.toString();
  if (href === baseUrl || SKIP_LINK_EXTENSIONS.test(parsed.pathname)) return null;
  return href;
}

function likelyArticleHtml(html: string): string {
  const withoutEmbeddedChrome = (value: string) => value
    .replace(/<(?:header|footer|nav|aside|form)\b[^>]*>[\s\S]*?<\/(?:header|footer|nav|aside|form)>/gi, " ")
    .replace(/<(?:script|style|noscript)\b[^>]*>[\s\S]*?<\/(?:script|style|noscript)>/gi, " ");
  const articleBlocks = Array.from(html.matchAll(/<article\b[^>]*>([\s\S]*?)<\/article>/gi), (match) => match[1]);
  if (articleBlocks.length > 0) return withoutEmbeddedChrome(articleBlocks.sort((a, b) => stripHtml(b).length - stripHtml(a).length)[0]);
  const mainBlocks = Array.from(html.matchAll(/<main\b[^>]*>([\s\S]*?)<\/main>/gi), (match) => match[1]);
  if (mainBlocks.length > 0) return withoutEmbeddedChrome(mainBlocks.sort((a, b) => stripHtml(b).length - stripHtml(a).length)[0]);
  return withoutEmbeddedChrome(html)
    .replace(/<head\b[^>]*>[\s\S]*?<\/head>/gi, " ");
}

function extractReferencedUrls(html: string, baseUrl: string, maxLinks: number): string[] {
  const contentHtml = likelyArticleHtml(html);
  const candidates: string[] = [];
  const seen = new Set<string>();
  const add = (candidate: string | null) => {
    if (!candidate || seen.has(candidate)) return;
    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      return;
    }
    const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
    if (LOW_VALUE_LINK_HOST.test(host) || LOW_VALUE_LINK_PATH.test(parsed.pathname)) return;
    seen.add(candidate);
    candidates.push(candidate);
  };
  for (const m of contentHtml.matchAll(/<a\b([^>]*)\bhref\s*=\s*["']([^"']+)["']([^>]*)>([\s\S]*?)<\/a>/gi)) {
    add(normaliseSourceLink(m[2], baseUrl));
  }
  return candidates.slice(0, maxLinks);
}

export function extractReferencedUrlsForTest(html: string, baseUrl: string, maxLinks: number): string[] {
  return extractReferencedUrls(html, baseUrl, maxLinks);
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
    let text = stripHtml(likelyArticleHtml(html));
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
  opts?: { maxReferenceLinks?: number; maxReferenceDepth?: number },
): Promise<string | null> {
  if (!url || typeof url !== "string") return null;
  const maxReferenceLinks = Math.max(0, Math.min(opts?.maxReferenceLinks ?? 12, MAX_REFERENCE_PAGES));
  const maxReferenceDepth = Math.max(1, Math.min(opts?.maxReferenceDepth ?? MAX_REFERENCE_DEPTH, MAX_REFERENCE_DEPTH));
  const graph = await crawlSourceEvidence(url, { maxReferenceLinks, maxReferenceDepth });
  const primary = graph.pages[0];
  if (!primary) return null;

  const sections = [
    [
      `Primary source (${url}):`,
      primary.text,
      "",
      "Supplemental referenced sources below were discovered from main article content and fetched server-side. Each section records its parent link and traversal depth. Use them only as supporting evidence for context, CVE details, vendor advisories, linked research, IoCs, or detection behavior.",
    ].join("\n"),
  ];
  let used = sections[0].length;
  const referencedPages = graph.pages.slice(1);
  for (let index = 0; index < referencedPages.length; index += 1) {
    const page = referencedPages[index];
    const remaining = MAX_CONTEXT_CHARS - used;
    if (remaining < 800) break;
    const pagesLeft = Math.max(1, referencedPages.length - index);
    const pageBudget = Math.max(1_200, Math.min(6_000, Math.floor(remaining / pagesLeft)));
    const clipped = page.text.length > pageBudget
      ? `${page.text.slice(0, pageBudget)} …[truncated]`
      : page.text;
    const block = [
      `Referenced source (${page.url}):`,
      `Linked from: ${page.parentUrl || url} · depth ${page.depth}`,
      clipped,
    ].join("\n");
    sections.push(block);
    used += block.length + 2;
  }
  if (graph.unavailableUrls.length > 0) {
    sections.push([
      "Referenced URLs discovered in main content but unavailable to the server:",
      ...graph.unavailableUrls.map((item) => `- ${item}`),
    ].join("\n"));
  }
  if (graph.unfetchedUrls.length > 0) {
    sections.push([
      `Referenced URLs beyond the ${maxReferenceLinks}-page safety budget (preserved for analyst provenance, not read):`,
      ...graph.unfetchedUrls.map((item) => `- ${item}`),
    ].join("\n"));
  }
  return sections.join("\n\n").slice(0, MAX_CONTEXT_CHARS);
}

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  mapper: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await mapper(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => worker()));
  return results;
}

async function crawlSourceEvidence(
  rootUrl: string,
  opts: { maxReferenceLinks: number; maxReferenceDepth: number },
  loader: (url: string, linkBudget: number) => Promise<SourceArticle | null> = fetchSourceArticle,
): Promise<SourceEvidenceGraph> {
  const primary = await loader(rootUrl, MAX_DISCOVERED_LINKS_PER_PAGE);
  if (!primary) return { pages: [], unavailableUrls: [], unfetchedUrls: [] };

  const pages: SourceEvidencePage[] = [{ ...primary, url: rootUrl, parentUrl: null, depth: 0 }];
  const seen = new Set<string>([rootUrl]);
  const unavailableUrls: string[] = [];
  const queue: Array<{ url: string; parentUrl: string; depth: number }> = [];
  const enqueue = (candidate: { url: string; parentUrl: string; depth: number }) => {
    if (seen.has(candidate.url)) return;
    seen.add(candidate.url);
    queue.push(candidate);
  };
  primary.referencedUrls.forEach((candidate) => enqueue({ url: candidate, parentUrl: rootUrl, depth: 1 }));

  let attempted = 0;
  while (queue.length > 0 && attempted < opts.maxReferenceLinks) {
    const batchSize = Math.min(
      REFERENCE_FETCH_CONCURRENCY,
      queue.length,
      opts.maxReferenceLinks - attempted,
    );
    const batch = queue.splice(0, batchSize);
    attempted += batch.length;
    const loaded = await mapWithConcurrency(batch, REFERENCE_FETCH_CONCURRENCY, (item) =>
      loader(item.url, MAX_DISCOVERED_LINKS_PER_PAGE));
    loaded.forEach((article, index) => {
      const item = batch[index];
      if (!article) {
        unavailableUrls.push(item.url);
        return;
      }
      pages.push({ ...article, ...item });
      if (item.depth < opts.maxReferenceDepth) {
        article.referencedUrls.forEach((candidate) => enqueue({
          url: candidate,
          parentUrl: item.url,
          depth: item.depth + 1,
        }));
      }
    });
  }
  return {
    pages,
    unavailableUrls,
    unfetchedUrls: queue.map((item) => item.url),
  };
}

export async function crawlSourceEvidenceForTest(
  rootUrl: string,
  articles: Record<string, SourceArticle | null>,
  opts?: { maxReferenceLinks?: number; maxReferenceDepth?: number },
): Promise<SourceEvidenceGraph> {
  return crawlSourceEvidence(rootUrl, {
    maxReferenceLinks: opts?.maxReferenceLinks ?? MAX_REFERENCE_PAGES,
    maxReferenceDepth: opts?.maxReferenceDepth ?? MAX_REFERENCE_DEPTH,
  }, async (candidate) => articles[candidate] ?? null);
}

/**
 * Fetch many URLs in parallel. Returns an array of [url, content|null] tuples
 * preserving input order. Safe to call with up to ~20 URLs; uses concurrency
 * limit of 5 to be polite to source servers.
 */
export async function fetchSourcesBatch(
  urls: Array<string | null | undefined>,
  opts?: { includeReferences?: boolean; maxReferenceLinks?: number; maxReferenceDepth?: number },
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
        ? await fetchSourceContentWithReferences(v.url, {
            maxReferenceLinks: opts.maxReferenceLinks,
            maxReferenceDepth: opts.maxReferenceDepth,
          })
        : await fetchSourceContent(v.url);
      out[v.idx] = { url: v.url, content };
    }
  }
  const workers: Promise<void>[] = [];
  for (let k = 0; k < Math.min(CONC, valid.length); k++) workers.push(worker());
  await Promise.all(workers);
  return out;
}
