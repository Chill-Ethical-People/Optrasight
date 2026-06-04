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

const TIMEOUT_MS = 10_000;
const MAX_BYTES = 200_000;
const MAX_CHARS = 18_000;     // post-strip cap fed to the LLM
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_MAX = 200;

type CacheEntry = { value: string | null; expiresAt: number };
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
    .replace(/&hellip;/g, "…")
    // Collapse whitespace
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Fetch a URL and return cleaned plain-text content suitable for AI prompts.
 * Returns null if the URL is invalid, the request fails, the response is
 * non-text, or the cleaned content is empty.
 */
export async function fetchSourceContent(url: string | null | undefined): Promise<string | null> {
  if (!url || typeof url !== "string") return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;

  const cached = cacheGet(url);
  if (cached !== undefined) return cached;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        // Pretend to be a real browser; many intel sites 403 default fetch UA
        "User-Agent": "Mozilla/5.0 (compatible; OptraSightBot/2.28; +https://optrasight.local)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en;q=0.9,*;q=0.7",
      },
    });
    if (!res.ok) {
      cacheSet(url, null);
      return null;
    }
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    if (ct && !ct.includes("text") && !ct.includes("xml") && !ct.includes("json")) {
      cacheSet(url, null);
      return null;
    }
    // Read with byte cap
    const reader = (res.body as any)?.getReader?.();
    let bytes = 0;
    const chunks: Uint8Array[] = [];
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          bytes += value.byteLength;
          chunks.push(value);
          if (bytes >= MAX_BYTES) {
            try { await reader.cancel(); } catch {}
            break;
          }
        }
      }
    } else {
      const buf = Buffer.from(await res.arrayBuffer());
      chunks.push(buf.subarray(0, MAX_BYTES));
    }
    const merged = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    const html = merged.toString("utf8");
    let text = stripHtml(html);
    if (text.length > MAX_CHARS) text = text.slice(0, MAX_CHARS) + " …[truncated]";
    if (!text || text.length < 40) {
      cacheSet(url, null);
      return null;
    }
    cacheSet(url, text);
    return text;
  } catch {
    cacheSet(url, null);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch many URLs in parallel. Returns an array of [url, content|null] tuples
 * preserving input order. Safe to call with up to ~20 URLs; uses concurrency
 * limit of 5 to be polite to source servers.
 */
export async function fetchSourcesBatch(urls: Array<string | null | undefined>): Promise<Array<{ url: string; content: string | null }>> {
  const valid: Array<{ idx: number; url: string }> = [];
  const out: Array<{ url: string; content: string | null }> = urls.map((u) => ({ url: u || "", content: null }));
  urls.forEach((u, i) => { if (u && typeof u === "string") valid.push({ idx: i, url: u }); });

  const CONC = 5;
  let cursor = 0;
  async function worker() {
    while (cursor < valid.length) {
      const my = cursor++;
      const v = valid[my];
      const content = await fetchSourceContent(v.url);
      out[v.idx] = { url: v.url, content };
    }
  }
  const workers: Promise<void>[] = [];
  for (let k = 0; k < Math.min(CONC, valid.length); k++) workers.push(worker());
  await Promise.all(workers);
  return out;
}
