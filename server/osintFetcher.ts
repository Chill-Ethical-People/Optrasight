// Real OSINT feed fetcher and parser (v2.8).
//
// v2.8 changes:
//   - Generic catalog walker now ONLY targets RSS / Atom / RDF XML feeds.
//     JSON-only sources are skipped here — they're handled by hand-written
//     deep parsers (NVD, GHSA, OSV, KEV, EPSS, ransomware.live, CIRCL) where
//     we know the response shape.
//   - Every ParsedItem now carries `iocs` (grouped IPv4/IPv6/domain/url/hash/
//     email/btc) and a `contentHash` (SHA-1 over normalised title + host) used
//     for cross-source dedupe — so the same advisory reposted by 5 different
//     RSS feeds collapses to a single finding per tenant.
//   - URL normalisation strips utm_*/fbclid/gclid/mc_eid/ref/share tracking
//     params, lowercases the host, removes trailing slash and #fragments.

//
// v2.6 only had 6 hard-wired feed adapters. v2.7 broadens the ingest to:
//   1. A small set of ~30 *deep* custom parsers that backfill up to 365 days
//      where the upstream supports historical queries (NVD pagination, GHSA
//      pagination, CISA KEV full catalog, GitHub releases, OSV ecosystem
//      dumps, ransomware.live full feed, etc.).
//   2. A *generic* RSS/Atom/RDF/JSON adapter that runs across the entire
//      514-entry source catalog from osintSeed.ts so every catalog row has a
//      real chance to be parsed.
//
// Tenant tech filtering is no longer applied at ingest — every parsed item
// lands in the DB and filtering happens at view time. This means newly added
// tenant technologies retroactively benefit from the existing archive.
//
// All fetches are best-effort with an aggressive timeout; if a feed fails the
// scan still continues and returns whatever items were ingested.

import { MONITORED_TECHNOLOGIES, type FindingIoCs } from "../shared/schema";
import { OSINT_SOURCES, type OsintSourceSeed } from "./osintSeed";
import { createHash } from "crypto";
import { isSecurityPublisherHost } from "./iocPublisherBlocklist";

export interface ParsedItem {
  sourceId?: string;          // canonical osrc-XXXX id from the catalog (when known)
  sourceName: string;
  sourceCategory: string;
  sourceUrl: string;
  title: string;
  url: string;
  publishedAt: string;        // ISO
  severity: "critical" | "high" | "medium" | "low" | "info";
  cveIds: string[];
  affectedTech: string[];
  threatActors: string[];
  /** v2.8 — parsed Indicators of Compromise. */
  iocs?: FindingIoCs;
  /** v2.8 — SHA-1 over normalised (title + host). Used for cross-source dedupe. */
  contentHash?: string;
  summary: string;
  rawSnippet: string;
}

// ---------- shared helpers -------------------------------------------------

const FETCH_TIMEOUT_MS = 9000;
const FEED_CONCURRENCY = 8;

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...init,
      signal: ctl.signal,
      headers: {
        "user-agent": "OptraSight-OSINT/2.28 (+https://optrasight.local)",
        accept: init?.headers && (init.headers as any).accept
          ? (init.headers as any).accept
          : "application/json, text/xml, application/rss+xml, application/atom+xml, application/rdf+xml, */*",
        ...(init?.headers || {}),
      },
    });
  } finally {
    clearTimeout(t);
  }
}

function stripHtml(s: string): string {
  return (s || "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractCves(text: string): string[] {
  const set = new Set<string>();
  const re = /CVE-\d{4}-\d{4,7}/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text || "")) !== null) set.add(m[0].toUpperCase());
  return Array.from(set);
}

// v2.22 — The previous tokenizer split every label into 4+ letter words
// (e.g. "Ivanti Connect Secure / Pulse" → ["ivanti", "connect", "secure",
// "pulse"]) and stored each as an independent match key. That caused massive
// false positives: any article mentioning "connect", "secure", "pulse",
// "point", "quantum", "edge", etc. would cross-tag entirely unrelated
// findings with five+ vendor technologies.
//
// The fix is conservative: index only the FULL label (lower-cased) and the
// slug-id (e.g. "ivanti-connectsecure" → "ivanti connectsecure"), plus the
// hyphenated slug form itself. We also keep a small set of high-precision
// single-word brand tokens that are unambiguous ("crowdstrike", "barracuda",
// "fortinet" …). Generic dictionary words are never used as match keys.
const SAFE_BRAND_SINGLETONS = new Set<string>([
  "crowdstrike", "barracuda", "fortinet", "sonicwall", "watchguard",
  "paloalto", "checkpoint", "cyberark", "thycotic", "beyondtrust",
  "sentinelone", "carbonblack", "trendmicro", "sophos", "bitdefender",
  "qualys", "tenable", "rapid7", "nessus", "splunk", "elastic",
  "kibana", "logstash", "datadog", "newrelic", "dynatrace",
  "snowflake", "databricks", "mongodb", "postgresql", "mariadb",
  "jenkins", "gitlab", "github", "bitbucket", "atlassian", "jira",
  "confluence", "slack", "okta", "auth0", "duo", "yubikey",
  "cisco", "juniper", "aruba", "ubiquiti", "meraki",
  "vmware", "vsphere", "vcenter", "esxi", "horizon",
  "citrix", "netscaler", "xenapp", "xendesktop",
  "zimbra", "exchange", "sharepoint", "outlook",
  "wordpress", "drupal", "joomla", "magento", "shopify",
  "openssl", "openssh", "openvpn", "wireguard",
  "kubernetes", "docker", "containerd", "openshift",
  "jboss", "weblogic", "glassfish", "tomcat", "jetty",
  "struts", "spring4shell", "log4j", "log4shell",
  "solarwinds", "kaseya", "connectwise", "manageengine",
  "papercut", "moveit", "goanywhere", "accellion",
  "ivanti", "pulse", "pulsesecure", "sentinel",
]);

const TECH_INDEX = (() => {
  // tok → techId. Only multi-word phrases or whitelisted brand singletons.
  const idx = new Map<string, string>();
  for (const t of MONITORED_TECHNOLOGIES) {
    const tokens = new Set<string>();
    const label = t.label.toLowerCase().trim();
    tokens.add(label);                                // full label e.g. "ivanti connect secure / pulse"
    tokens.add(t.id.toLowerCase());                   // slug e.g. "ivanti-connectsecure"
    tokens.add(t.id.replace(/-/g, " ").toLowerCase()); // slug with spaces e.g. "ivanti connectsecure"
    // High-precision brand singletons — only emit if the slug or label
    // contains a known unambiguous brand word.
    for (const w of label.split(/[^a-z0-9]+/)) {
      if (w.length >= 4 && SAFE_BRAND_SINGLETONS.has(w)) tokens.add(w);
    }
    for (const tok of tokens) {
      if (!tok) continue;
      if (!idx.has(tok)) idx.set(tok, t.id);
    }
  }
  return idx;
})();

function detectTech(text: string): string[] {
  const lower = (text || "").toLowerCase();
  const out = new Set<string>();
  for (const [tok, techId] of TECH_INDEX) {
    // Word-boundary match so "point" doesn't fire on "endpoint" and
    // "edge" doesn't fire on "wedge". The original (^|non-alnum) guard is
    // retained for tokens containing punctuation.
    const re = new RegExp(`(^|[^a-z0-9])${tok.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^a-z0-9]|$)`);
    if (re.test(lower)) out.add(techId);
  }
  return Array.from(out);
}

function severityFromCvss(score: number): ParsedItem["severity"] {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0)  return "low";
  return "info";
}

function severityFromText(text: string): ParsedItem["severity"] {
  const lower = (text || "").toLowerCase();
  if (/\b(critical|exploit(ed|ing)? in the wild|actively exploited|emergency|0[\s-]?day|zero[\s-]?day|kev|wormable)\b/.test(lower)) return "critical";
  if (/\b(high|severe|rce|remote code execution|auth(?:entication)? bypass|privilege escalation|sql injection|deserialisation|deserialization)\b/.test(lower)) return "high";
  if (/\b(medium|moderate|disclosure|denial of service|dos|xss|csrf|information leak)\b/.test(lower)) return "medium";
  if (/\b(low|minor|informational|hardening)\b/.test(lower)) return "low";
  return "info";
}

// Known threat actor lexicon — kept short and high-precision.
const ACTOR_LEXICON = [
  "Storm-0558","Storm-1811","Storm-2603","Volt Typhoon","Salt Typhoon","Flax Typhoon",
  "APT28","APT29","APT41","APT10","APT40","APT35",
  "Lazarus","Kimsuky","Andariel","Hidden Cobra",
  "Cl0p","CL0P","LockBit","ALPHV","BlackCat","BlackBasta","Black Basta","Akira",
  "RansomHub","Play","Royal","Conti","Hive","Vice Society","Medusa","Qilin","DragonForce",
  "FIN7","FIN8","FIN12","Scattered Spider","Octo Tempest","Muddled Libra",
  "TA505","TA577","TA453","TA571","TA866",
  "Sandworm","Turla","Gamaredon","Fancy Bear","Cozy Bear",
  "Lapsus$","UNC2452","UNC3886","UNC4841","UNC5337",
  "Mustang Panda","Iron Tiger","Aquatic Panda","ToddyCat","Earth Lusca",
  "ScarCruft","Charming Kitten","CyberAv3ngers",
];

function detectActors(text: string): string[] {
  const out = new Set<string>();
  const lower = (text || "").toLowerCase();
  for (const a of ACTOR_LEXICON) {
    if (lower.includes(a.toLowerCase())) out.add(a);
  }
  return Array.from(out);
}

// ---------- RSS / Atom / RDF parser (tolerant) -----------------------------

interface FeedEntry {
  title: string;
  link: string;
  description: string;
  pubDate: string;
}

function extractTag(blk: string, tag: string): string {
  const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
  const m = re.exec(blk);
  return m ? m[1].trim() : "";
}

function extractAttr(blk: string, tag: string, attr: string): string {
  const re = new RegExp(`<${tag}\\b[^>]*\\b${attr}=["']([^"']+)["']`, "i");
  const m = re.exec(blk);
  return m ? m[1] : "";
}

export function parseFeed(xml: string): FeedEntry[] {
  const items: FeedEntry[] = [];
  // RSS 2.0 <item>
  const itemRe = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
  let m: RegExpExecArray | null;
  while ((m = itemRe.exec(xml)) !== null) {
    const blk = m[1];
    items.push({
      title: stripHtml(extractTag(blk, "title")),
      link: stripHtml(extractTag(blk, "link")) || extractAttr(blk, "link", "href"),
      description: stripHtml(extractTag(blk, "description") || extractTag(blk, "summary") || extractTag(blk, "content:encoded")),
      pubDate: extractTag(blk, "pubDate") || extractTag(blk, "dc:date") || extractTag(blk, "published") || extractTag(blk, "updated"),
    });
  }
  if (items.length > 0) return items;
  // Atom <entry>
  const entryRe = /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi;
  while ((m = entryRe.exec(xml)) !== null) {
    const blk = m[1];
    items.push({
      title: stripHtml(extractTag(blk, "title")),
      link: extractAttr(blk, "link", "href") || stripHtml(extractTag(blk, "link")),
      description: stripHtml(extractTag(blk, "summary") || extractTag(blk, "content")),
      pubDate: extractTag(blk, "updated") || extractTag(blk, "published"),
    });
  }
  if (items.length > 0) return items;
  // RDF <rss:item> / <rdf:item>
  const rdfRe = /<(?:rdf:|rss:)?item\b[^>]*>([\s\S]*?)<\/(?:rdf:|rss:)?item>/gi;
  while ((m = rdfRe.exec(xml)) !== null) {
    const blk = m[1];
    items.push({
      title: stripHtml(extractTag(blk, "title")),
      link: stripHtml(extractTag(blk, "link")),
      description: stripHtml(extractTag(blk, "description") || extractTag(blk, "dc:description") || extractTag(blk, "content:encoded")),
      pubDate: extractTag(blk, "dc:date") || extractTag(blk, "pubDate"),
    });
  }
  return items;
}

function safeDateIso(s: string): string {
  if (!s) return new Date().toISOString();
  const d = new Date(s);
  if (isNaN(d.getTime())) return new Date().toISOString();
  return d.toISOString();
}

// ---------- v2.8 helpers: URL normalisation, content hash, IoC extraction ----

const TRACKING_PARAMS = new Set([
  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
  "utm_id", "utm_name", "utm_brand", "utm_social", "utm_social-type",
  "fbclid", "gclid", "mc_eid", "mc_cid", "ref", "share",
  "__twitter_impression", "_hsenc", "_hsmi", "hsCtaTracking",
  "yclid", "dclid", "msclkid", "oly_anon_id", "oly_enc_id",
]);

export function normaliseUrl(raw: string): string {
  if (!raw) return "";
  try {
    const u = new URL(raw.trim());
    // Lowercase host
    u.hostname = u.hostname.toLowerCase();
    // Strip tracking params
    const drop: string[] = [];
    u.searchParams.forEach((_v, k) => {
      if (TRACKING_PARAMS.has(k.toLowerCase())) drop.push(k);
    });
    for (const k of drop) u.searchParams.delete(k);
    // Drop fragment
    u.hash = "";
    // Build normalised string and trim trailing slash on path (but keep root '/')
    let out = u.toString();
    if (out.endsWith("/") && u.pathname !== "/") out = out.slice(0, -1);
    return out;
  } catch {
    return raw.trim();
  }
}

export function contentHashFor(title: string, url: string): string {
  const t = (title || "").toLowerCase().trim().replace(/\s+/g, " ");
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch { host = ""; }
  return createHash("sha1").update(`${t}||${host}`).digest("hex");
}

// ---- IoC extraction --------------------------------------------------------

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
const URL_RE = /https?:\/\/[^\s<>"'`]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const MD5_RE = /\b[a-f0-9]{32}\b/gi;
const SHA1_RE = /\b[a-f0-9]{40}\b/gi;
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const BTC_RE = /\b(?:bc1[a-z0-9]{25,39}|[13][a-zA-HJ-NP-Z0-9]{25,34})\b/g;

const DOMAIN_FALSE_POSITIVES = new Set([
  "example.com", "example.org", "example.net", "localhost", "test.com",
  "foo.com", "bar.com", "domain.com", "yoursite.com", "acme.com",
  "site.com", "company.com", "email.com",
]);
const NOISE_EMAIL_PREFIXES = ["noreply@", "no-reply@", "donotreply@", "example@"];
// v2.22 — Significantly expanded the noise-TLD list because the analyst saw
// findings whose "domain" bucket contained pure script/executable filenames
// like getmac.exe, collector.py, pythonw.exe, cmd.exe, ssss.dll, cldflt.sys,
// link.log. These look like 2–3 letter TLDs to DOMAIN_RE. The blacklist now
// covers executables, scripts, config / cache / log / temp files, archives,
// office/media formats, and common dev artefacts.
const NOISE_TLD = new Set([
  // images & web assets
  "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tif", "tiff",
  "css", "js", "mjs", "json", "xml", "html", "htm", "jsp", "asp", "aspx", "php",
  // documents & archives
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "odp",
  "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "iso", "img", "vhd", "vmdk",
  // executables / scripts (the original false-positive source)
  "exe", "dll", "sys", "drv", "ocx", "cpl", "scr", "msi", "msp", "cab", "bin",
  "py", "pyc", "pyw", "rb", "pl", "sh", "bash", "zsh", "ksh", "bat", "cmd", "ps1",
  "vbs", "vbe", "wsf", "jar", "war", "ear", "class", "apk", "ipa", "app",
  // config / data / log / temp
  "log", "tmp", "bak", "old", "swp", "cache", "lock", "pid", "sock",
  "conf", "cfg", "ini", "env", "yaml", "yml", "toml", "properties",
  "dat", "db", "sqlite", "sqlite3", "csv", "tsv", "txt", "md",
  // media
  "mp3", "mp4", "m4a", "wav", "ogg", "flac", "mkv", "mov", "avi", "wmv", "flv",
  // misc
  "pem", "key", "crt", "cer", "pfx", "p12",
]);

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p))) return true;
  const [a, b] = parts;
  if (a === 0 || a === 127 || a === 255) return true;
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;       // link-local
  if (a >= 224) return true;                       // multicast / reserved
  return false;
}

function dedupeCap(arr: string[], cap = 20): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of arr) {
    if (!v) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
    if (out.length >= cap) break;
  }
  return out;
}

// v2.23 — Helper: determine whether an IPv4-shaped match is actually a
// software version number (e.g. "version 3.2.1.1", "build 10.0.19042",
// "Windows 10.0.19042.1889"). The OSINT feeds we ingest are almost entirely
// vulnerability disclosures, where four-octet numbers in body text are
// overwhelmingly product versions, NOT routable IPv4 indicators. Real IPv4
// IoCs are typically defanged (1[.]2[.]3[.]4) or appear in tabular evidence
// sections — those will still come through via the AI extraction pass.
function looksLikeVersionNumber(ip: string, fullText: string, matchIndex: number): boolean {
  // 1) Octet-value heuristic. Real IPv4 IoCs rarely have all-low octets;
  //    version numbers like 3.2.1.1, 1.0.0.0, 6.5.4.2 almost always do.
  //    Triggers when every octet is <= 32 AND at least two octets are <= 9.
  const parts = ip.split(".").map(Number);
  if (parts.length === 4) {
    const allLow = parts.every((p) => p <= 32);
    const tinyCount = parts.filter((p) => p <= 9).length;
    if (allLow && tinyCount >= 2) return true;
  }

  // 2) Context-keyword heuristic. Look at the 40 chars immediately preceding
  //    the match for typical version markers; 20 chars after for "build" /
  //    "release" / "patch" mentions.
  const before = fullText.slice(Math.max(0, matchIndex - 40), matchIndex).toLowerCase();
  const after = fullText.slice(matchIndex + ip.length, matchIndex + ip.length + 20).toLowerCase();
  if (/\b(v|ver|version|build|release|patch|update|kb|firmware|driver|sdk|api|schema)\b[\s.:]*$/.test(before)) return true;
  if (/\b(windows|server|office|chrome|firefox|edge|safari|android|ios|macos|linux|kernel|bios|uefi)\b[\s.:]*$/.test(before)) return true;
  if (/^\s*(build|release|patch|update|hotfix|cumulative)\b/.test(after)) return true;

  return false;
}

export function extractIoCs(text: string, sourceUrl?: string | null): FindingIoCs {
  const s = text || "";
  const out: FindingIoCs = {};

  // v2.23 — Compute the publisher / source host(s) so we can strip them
  // from both the URL and domain buckets. A feed's own URL is NEVER a
  // threat indicator — it is the article address.
  const sourceHosts = new Set<string>();
  const sourceUrls = new Set<string>();
  if (sourceUrl) {
    try {
      const u = new URL(sourceUrl);
      const host = u.hostname.toLowerCase();
      sourceHosts.add(host);
      // Also strip the bare apex domain (without leading "www.") so a feed
      // with a www-prefixed host doesn't bypass the filter when the body
      // mentions the bare domain (or vice-versa).
      sourceHosts.add(host.replace(/^www\./, ""));
      sourceUrls.add(normaliseUrl(sourceUrl));
    } catch { /* malformed URL — skip */ }
  }

  // IPv4 — filter private/reserved AND version-number false positives.
  const ipv4Matches: string[] = [];
  {
    let m: RegExpExecArray | null;
    IPV4_RE.lastIndex = 0;
    while ((m = IPV4_RE.exec(s)) !== null) {
      const ip = m[0];
      if (isPrivateIPv4(ip)) continue;
      if (looksLikeVersionNumber(ip, s, m.index)) continue;
      ipv4Matches.push(ip);
    }
  }
  if (ipv4Matches.length) out.ipv4 = dedupeCap(ipv4Matches);

  // IPv6
  const ipv6 = (s.match(IPV6_RE) || []).map((v) => v.toLowerCase());
  if (ipv6.length) out.ipv6 = dedupeCap(ipv6);

  // URLs (normalised) — strip the article's own URL.
  const urlsRaw = (s.match(URL_RE) || []).map((u) => normaliseUrl(u.replace(/[\)\].,;:!\?]+$/, "")));
  const urls: string[] = [];
  for (const u of urlsRaw) {
    if (sourceUrls.has(u)) continue;
    // Also skip any URL whose host matches the publisher host — these are
    // navigation / share links on the same article (tag pages, paginated
    // archives), not threat indicators.
    try {
      const host = new URL(u).hostname.toLowerCase();
      if (sourceHosts.has(host)) continue;
      if (sourceHosts.has(host.replace(/^www\./, ""))) continue;
      // v2.28 — strip any URL hosted on a known security publisher / vendor
      // blog / CERT / MITRE / NVD / github reference. These are *references*
      // about the campaign, never an IoC themselves.
      if (isSecurityPublisherHost(host)) continue;
    } catch { /* if URL parsing fails, keep the raw string */ }
    urls.push(u);
  }
  if (urls.length) out.url = dedupeCap(urls);

  // Hosts from URLs — these become the "clean" domains (publisher already stripped)
  const urlHosts = new Set<string>();
  for (const u of urls) {
    try { urlHosts.add(new URL(u).hostname.toLowerCase()); } catch { /* noop */ }
  }

  // Domains — filter false positives, image/file extensions misread as TLDs,
  // and the article's own publisher host.
  const domainsRaw = (s.match(DOMAIN_RE) || []).map((d) => d.toLowerCase());
  const domains: string[] = [];
  for (const d of domainsRaw) {
    if (DOMAIN_FALSE_POSITIVES.has(d)) continue;
    if (!d.includes(".")) continue;
    const tld = d.split(".").pop() || "";
    if (NOISE_TLD.has(tld)) continue;
    if (d.split(".").length < 2) continue;
    if (/^\d+\./.test(d)) continue;                  // starts with digits-only label (likely IP fragment)
    // v2.23 — strip the publisher host.
    if (sourceHosts.has(d)) continue;
    if (sourceHosts.has(d.replace(/^www\./, ""))) continue;
    // v2.28 — strip any global security publisher host.
    if (isSecurityPublisherHost(d)) continue;
    domains.push(d);
  }
  // Include hosts from URL section (already filtered above so publisher is gone)
  for (const h of urlHosts) if (h && !DOMAIN_FALSE_POSITIVES.has(h)) domains.push(h);
  if (domains.length) out.domain = dedupeCap(domains);

  // SHA256 first, then SHA1 — exclude already-matched longer hashes from SHA1/MD5 results
  const sha256 = (s.match(SHA256_RE) || []).map((v) => v.toLowerCase());
  if (sha256.length) out.sha256 = dedupeCap(sha256);
  const sha256Set = new Set(sha256.map((v) => v.toLowerCase()));
  const sha1 = (s.match(SHA1_RE) || [])
    .map((v) => v.toLowerCase())
    .filter((v) => ![...sha256Set].some((h) => h.includes(v)));
  if (sha1.length) out.sha1 = dedupeCap(sha1);
  const sha1Set = new Set(sha1.map((v) => v.toLowerCase()));
  const md5 = (s.match(MD5_RE) || [])
    .map((v) => v.toLowerCase())
    .filter((v) => !sha256Set.has(v) && !sha1Set.has(v)
      && ![...sha256Set, ...sha1Set].some((h) => h.includes(v)));
  if (md5.length) out.md5 = dedupeCap(md5);

  // Emails — filter noise prefixes
  const emails = (s.match(EMAIL_RE) || [])
    .map((v) => v.toLowerCase())
    .filter((e) => !NOISE_EMAIL_PREFIXES.some((p) => e.startsWith(p)));
  if (emails.length) out.email = dedupeCap(emails);

  // BTC
  const btc = (s.match(BTC_RE) || []).filter((b) => b.length >= 26);
  if (btc.length) out.btc = dedupeCap(btc);

  return out;
}

// ============================================================================
// DEEP CUSTOM PARSERS — each can backfill 365 days where the source supports it
// ============================================================================
//
// `sourceId` here MUST match a canonical id from osintSeed.ts so the storage
// layer can attribute findings to the right source row (so "Parsed" counts
// populate correctly).

type DeepParser = {
  id: string;
  sourceId: string;
  sourceName: string;
  sourceCategory: string;
  sourceUrl: string;
  // Returns an array of ParsedItem for this source.
  run: (opts: { sinceIso: string; maxItems: number }) => Promise<ParsedItem[]>;
};

// ---- helper: lookup catalog source id by category + name fragment ----
function findCatalogId(category: string, namePattern: RegExp): string | undefined {
  return OSINT_SOURCES.find((s) => s.category === category && namePattern.test(s.name))?.id;
}

// v2.9 — lookup catalog source by EXACT name (case-insensitive). Avoids the
// v2.8 bug where deep parsers matched on first-word-only regex and collided
// across sources sharing a prefix (e.g. "The DFIR Report" -> /The/ -> matched
// "The Hacker News" first). Falls back to host match if exact name fails.
function findCatalogIdByName(name: string, hostFallback?: string): string | undefined {
  const target = name.trim().toLowerCase();
  const exact = OSINT_SOURCES.find((s) => s.name.trim().toLowerCase() === target);
  if (exact) return exact.id;
  if (hostFallback) {
    const host = hostFallback.toLowerCase();
    const byHost = OSINT_SOURCES.find((s) => {
      try { return new URL(s.url).hostname.toLowerCase() === host; } catch { return false; }
    });
    if (byHost) return byHost.id;
  }
  return undefined;
}

// Build deep parsers. Each parser is wrapped in try/catch in the runner so a
// single upstream outage never breaks the whole ingest.
function buildDeepParsers(): DeepParser[] {
  const parsers: DeepParser[] = [];

  // ---- 1. CISA KEV — full catalog ----
  parsers.push({
    id: "deep-cisa-kev",
    sourceId: findCatalogId("CVE_VULN", /KEV.*Known Exploited/i) || "osrc-cisa-kev",
    sourceName: "CISA KEV (Known Exploited Vulnerabilities)",
    sourceCategory: "CVE_VULN",
    sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    run: async ({ sinceIso }) => {
      const r = await fetchWithTimeout(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      );
      if (!r.ok) return [];
      const j = await r.json() as any;
      const out: ParsedItem[] = [];
      for (const v of j.vulnerabilities || []) {
        const dateAdded = v.dateAdded ? new Date(v.dateAdded).toISOString() : new Date().toISOString();
        if (dateAdded < sinceIso) continue;
        const cve = (v.cveID || "").toUpperCase();
        const text = `${v.vendorProject || ""} ${v.product || ""} ${v.vulnerabilityName || ""} ${v.shortDescription || ""}`;
        out.push({
          sourceId: findCatalogId("CVE_VULN", /CISA KEV/i) || "osrc-0030",
          sourceName: "CISA KEV — RSS",
          sourceCategory: "CVE_VULN",
          sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
          title: `${v.vendorProject} ${v.product} — ${v.vulnerabilityName}`,
          url: `https://nvd.nist.gov/vuln/detail/${cve}`,
          publishedAt: dateAdded,
          severity: "critical",
          cveIds: cve ? [cve] : [],
          affectedTech: detectTech(text),
          threatActors: v.knownRansomwareCampaignUse === "Known" ? ["Ransomware operators"] : ["opportunistic"],
          summary: stripHtml(v.shortDescription || "Known exploited vulnerability tracked by CISA.").slice(0, 320),
          rawSnippet: `[CISA KEV]\nVendor: ${v.vendorProject}\nProduct: ${v.product}\nName: ${v.vulnerabilityName}\nCVE: ${cve}\nDate added: ${v.dateAdded}\nDue date: ${v.dueDate}\nKnown ransomware use: ${v.knownRansomwareCampaignUse}\n\n${v.shortDescription || ""}`,
        });
      }
      return out;
    },
  });

  // ---- 2. NVD — paginated full year ----
  parsers.push({
    id: "deep-nvd",
    sourceId: findCatalogId("CVE_VULN", /NVD JSON 1\.1 — recent/i) || "osrc-nvd",
    sourceName: "NVD CVE feed",
    sourceCategory: "CVE_VULN",
    sourceUrl: "https://nvd.nist.gov/vuln/search",
    run: async ({ sinceIso, maxItems }) => {
      const out: ParsedItem[] = [];
      const end = new Date();
      const start = new Date(sinceIso);
      // NVD allows max 120-day window. Slice into 120-day chunks, fetch 2000 at a time.
      let cursor = new Date(start);
      while (cursor < end && out.length < maxItems) {
        const chunkEnd = new Date(Math.min(cursor.getTime() + 119 * 86400_000, end.getTime()));
        let startIndex = 0;
        for (let page = 0; page < 5 && out.length < maxItems; page++) {
          const u = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            + `?resultsPerPage=2000&startIndex=${startIndex}`
            + `&pubStartDate=${encodeURIComponent(cursor.toISOString().slice(0, 23))}`
            + `&pubEndDate=${encodeURIComponent(chunkEnd.toISOString().slice(0, 23))}`;
          let r: Response;
          try { r = await fetchWithTimeout(u); } catch { break; }
          if (!r.ok) break;
          const j = await r.json() as any;
          const arr: any[] = j.vulnerabilities || [];
          if (arr.length === 0) break;
          for (const w of arr) {
            const c = w.cve || {};
            const cve = (c.id || "").toUpperCase();
            const desc = (c.descriptions || []).find((d: any) => d.lang === "en")?.value || "";
            const metric = (c.metrics?.cvssMetricV31 || c.metrics?.cvssMetricV30 || c.metrics?.cvssMetricV2 || [])[0];
            const score = metric?.cvssData?.baseScore ?? 0;
            out.push({
              sourceName: "NVD",
              sourceCategory: "CVE_VULN",
              sourceUrl: "https://nvd.nist.gov/vuln/search",
              title: `${cve} — ${desc.slice(0, 140)}`,
              url: `https://nvd.nist.gov/vuln/detail/${cve}`,
              publishedAt: c.published ? new Date(c.published).toISOString() : new Date().toISOString(),
              severity: severityFromCvss(score),
              cveIds: cve ? [cve] : [],
              affectedTech: detectTech(desc),
              threatActors: detectActors(desc),
              summary: desc.slice(0, 320),
              rawSnippet: `[NVD]\nCVE: ${cve}\nCVSS: ${score} (${metric?.cvssData?.baseSeverity || "n/a"})\nPublished: ${c.published}\n\n${desc}`,
            });
            if (out.length >= maxItems) break;
          }
          if (arr.length < 2000) break;
          startIndex += 2000;
          await new Promise((r) => setTimeout(r, 250)); // be gentle to NVD
        }
        cursor = new Date(chunkEnd.getTime() + 1000);
      }
      return out;
    },
  });

  // ---- 3. GHSA recent (paginated) ----
  parsers.push({
    id: "deep-ghsa",
    sourceId: findCatalogId("CVE_VULN", /GitHub Advisory DB/i) || "osrc-0034",
    sourceName: "GitHub Advisory DB (GHSA mirror)",
    sourceCategory: "CVE_VULN",
    sourceUrl: "https://github.com/advisories",
    run: async ({ sinceIso, maxItems }) => {
      const out: ParsedItem[] = [];
      let cursor: string | null = null;
      for (let page = 0; page < 10 && out.length < maxItems; page++) {
        const u = "https://api.github.com/advisories?per_page=100&sort=published&direction=desc"
          + (cursor ? `&after=${encodeURIComponent(cursor)}` : "");
        let r: Response;
        try { r = await fetchWithTimeout(u); } catch { break; }
        if (!r.ok) break;
        const arr = await r.json() as any[];
        if (!Array.isArray(arr) || arr.length === 0) break;
        let stopped = false;
        for (const a of arr) {
          const pub = a.published_at ? new Date(a.published_at).toISOString() : new Date().toISOString();
          if (pub < sinceIso) { stopped = true; break; }
          const text = `${a.summary || ""} ${a.description || ""} ${(a.vulnerabilities || []).map((v: any) => v.package?.name || "").join(" ")}`;
          out.push({
            sourceName: "GitHub Advisory DB (GHSA mirror)",
            sourceCategory: "CVE_VULN",
            sourceUrl: "https://github.com/advisories",
            title: a.summary || a.ghsa_id || "GitHub advisory",
            url: a.html_url || `https://github.com/advisories/${a.ghsa_id}`,
            publishedAt: pub,
            severity: a.cvss?.score > 0 ? severityFromCvss(a.cvss.score) : severityFromText(a.severity || a.summary || ""),
            cveIds: extractCves(`${a.cve_id || ""} ${a.summary || ""} ${a.description || ""}`),
            affectedTech: detectTech(text),
            threatActors: [],
            summary: stripHtml((a.description || a.summary || "").slice(0, 320)),
            rawSnippet: `[GHSA]\n${a.ghsa_id}\nSeverity: ${a.severity}\nCVSS: ${a.cvss?.score}\nPackages: ${(a.vulnerabilities || []).map((v: any) => `${v.package?.ecosystem}:${v.package?.name}`).join(", ")}\n\n${a.description || a.summary || ""}`,
          });
        }
        if (stopped || arr.length < 100) break;
        cursor = arr[arr.length - 1]?.cursor || null;
        if (!cursor) break;
        await new Promise((r) => setTimeout(r, 200));
      }
      return out;
    },
  });

  // ---- 4. OSV.dev per-ecosystem (batched query API) ----
  const OSV_ECOS = ["npm", "PyPI", "Maven", "RubyGems", "NuGet", "Packagist", "Go", "crates.io", "Pub"];
  for (const eco of OSV_ECOS) {
    parsers.push({
      id: `deep-osv-${eco}`,
      sourceId: findCatalogId("CVE_VULN", new RegExp(`OSV — ${eco.toLowerCase()}`, "i")) || `osrc-osv-${eco}`,
      sourceName: `OSV — ${eco}`,
      sourceCategory: "CVE_VULN",
      sourceUrl: `https://osv.dev/list?ecosystem=${eco}`,
      run: async ({ sinceIso, maxItems }) => {
        // OSV doesn't have a "since" query — use the bulk vulnerability list endpoint.
        // Query a sentinel package per ecosystem to avoid downloading the full dump.
        // Instead, hit OSV's "all" endpoint with pagination.
        const out: ParsedItem[] = [];
        const sentinel: Record<string, string> = {
          npm: "lodash", PyPI: "django", Maven: "org.apache.commons:commons-lang3", RubyGems: "rails",
          NuGet: "Newtonsoft.Json", Packagist: "symfony/http-foundation", Go: "github.com/gin-gonic/gin",
          "crates.io": "tokio", Pub: "http",
        };
        const pkg = sentinel[eco];
        if (!pkg) return out;
        let r: Response;
        try {
          r = await fetchWithTimeout("https://api.osv.dev/v1/query", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ package: { name: pkg, ecosystem: eco } }),
          });
        } catch { return out; }
        if (!r.ok) return out;
        const j = await r.json() as any;
        for (const v of (j.vulns || []).slice(0, maxItems)) {
          const pub = v.published ? new Date(v.published).toISOString() : new Date().toISOString();
          if (pub < sinceIso) continue;
          const summary = v.summary || v.details || v.id || "OSV advisory";
          out.push({
            sourceName: `OSV — ${eco}`,
            sourceCategory: "CVE_VULN",
            sourceUrl: `https://osv.dev/list?ecosystem=${eco}`,
            title: `${v.id} — ${summary.slice(0, 140)}`,
            url: `https://osv.dev/vulnerability/${v.id}`,
            publishedAt: pub,
            severity: severityFromText(v.summary || v.details || ""),
            cveIds: (v.aliases || []).filter((a: string) => /^CVE-/i.test(a)),
            affectedTech: detectTech(`${summary} ${pkg}`),
            threatActors: [],
            summary: stripHtml(summary).slice(0, 320),
            rawSnippet: `[OSV ${eco}]\n${v.id}\nAliases: ${(v.aliases || []).join(", ")}\nPackage: ${pkg}\n\n${v.details || v.summary || ""}`,
          });
        }
        return out;
      },
    });
  }

  // ---- 5. Ransomware.live — full recent victims + groups ----
  parsers.push({
    id: "deep-ransomware-live",
    sourceId: findCatalogId("RANSOMWARE_LEAK", /Ransomware\.live — feed/i) || "osrc-ransomware-live",
    sourceName: "Ransomware.live",
    sourceCategory: "RANSOMWARE_LEAK",
    sourceUrl: "https://www.ransomware.live/",
    run: async ({ sinceIso, maxItems }) => {
      const out: ParsedItem[] = [];
      let r: Response;
      try { r = await fetchWithTimeout("https://api.ransomware.live/v2/recentvictims"); } catch { return out; }
      if (!r.ok) return out;
      const arr = await r.json() as any[];
      for (const v of (arr || []).slice(0, maxItems)) {
        const pub = v.discovered ? new Date(v.discovered).toISOString() : new Date().toISOString();
        if (pub < sinceIso) continue;
        out.push({
          sourceName: `Ransomware.live · ${v.group_name || v.group || "unknown"}`,
          sourceCategory: "RANSOMWARE_LEAK",
          sourceUrl: "https://www.ransomware.live/recentvictims",
          title: `${v.group_name || v.group || "Ransomware"} listed: ${v.victim || v.title || "victim"}`,
          url: v.url || v.post_url || "https://www.ransomware.live/",
          publishedAt: pub,
          severity: "high",
          cveIds: [],
          affectedTech: detectTech(`${v.victim || ""} ${v.activity || ""}`),
          threatActors: [v.group_name || v.group].filter(Boolean) as string[],
          summary: stripHtml((v.description || `${v.group_name || v.group} listed ${v.victim} (${v.country || "n/a"})`).slice(0, 320)),
          rawSnippet: `[Ransomware.live]\nGroup: ${v.group_name || v.group}\nVictim: ${v.victim}\nCountry: ${v.country || "n/a"}\nActivity: ${v.activity || "n/a"}\nDiscovered: ${v.discovered}\n${v.description || ""}`,
        });
      }
      return out;
    },
  });

  // ---- 6. CIRCL CVE search (recent) ----
  parsers.push({
    id: "deep-circl",
    sourceId: findCatalogId("CVE_VULN", /^CIRCL CVE search$/i) || "osrc-0032",
    sourceName: "CIRCL CVE search",
    sourceCategory: "CVE_VULN",
    sourceUrl: "https://cve.circl.lu/",
    run: async ({ sinceIso, maxItems }) => {
      let r: Response;
      try { r = await fetchWithTimeout(`https://cve.circl.lu/api/last/${Math.min(maxItems, 300)}`); } catch { return []; }
      if (!r.ok) return [];
      const arr = await r.json() as any[];
      const out: ParsedItem[] = [];
      for (const c of arr || []) {
        const pub = (c.Published || c.published) ? new Date(c.Published || c.published).toISOString() : new Date().toISOString();
        if (pub < sinceIso) continue;
        const cve = (c.id || c.cveMetadata?.cveId || "").toUpperCase();
        const desc = c.summary || c.containers?.cna?.descriptions?.[0]?.value || "";
        out.push({
          sourceName: "CIRCL CVE search",
          sourceCategory: "CVE_VULN",
          sourceUrl: "https://cve.circl.lu/",
          title: `${cve} — ${desc.slice(0, 140)}`,
          url: `https://cve.circl.lu/cve/${cve}`,
          publishedAt: pub,
          severity: severityFromCvss(c.cvss ?? 0),
          cveIds: cve ? [cve] : [],
          affectedTech: detectTech(desc),
          threatActors: [],
          summary: desc.slice(0, 320),
          rawSnippet: `[CIRCL]\nCVE: ${cve}\nCVSS: ${c.cvss}\n\n${desc}`,
        });
      }
      return out;
    },
  });

  // ---- 7. CVE.org official JSON (recent) ----
  parsers.push({
    id: "deep-cveorg",
    sourceId: findCatalogId("CVE_VULN", /CVE\.org/i) || "osrc-cveorg",
    sourceName: "CVE.org Project — JSON v5",
    sourceCategory: "CVE_VULN",
    sourceUrl: "https://www.cve.org/",
    run: async ({ sinceIso, maxItems }) => {
      let r: Response;
      try { r = await fetchWithTimeout("https://cveawg.mitre.org/api/cve?count=200&state=PUBLISHED"); } catch { return []; }
      if (!r.ok) return [];
      const j = await r.json() as any;
      const arr = j.cveRecords || j.data || j || [];
      const out: ParsedItem[] = [];
      for (const rec of arr.slice(0, maxItems)) {
        const pub = rec.cveMetadata?.datePublished ? new Date(rec.cveMetadata.datePublished).toISOString() : new Date().toISOString();
        if (pub < sinceIso) continue;
        const cve = rec.cveMetadata?.cveId || "";
        const desc = rec.containers?.cna?.descriptions?.[0]?.value || "";
        out.push({
          sourceName: "CVE.org",
          sourceCategory: "CVE_VULN",
          sourceUrl: "https://www.cve.org/",
          title: `${cve} — ${desc.slice(0, 140)}`,
          url: `https://www.cve.org/CVERecord?id=${cve}`,
          publishedAt: pub,
          severity: severityFromText(desc),
          cveIds: cve ? [cve] : [],
          affectedTech: detectTech(desc),
          threatActors: [],
          summary: desc.slice(0, 320),
          rawSnippet: `[CVE.org]\n${cve}\n\n${desc}`,
        });
      }
      return out;
    },
  });

  // ---- 8. EPSS — top scored CVEs ----
  parsers.push({
    id: "deep-epss",
    sourceId: findCatalogId("CVE_VULN", /EPSS/i) || "osrc-0033",
    sourceName: "FIRST EPSS",
    sourceCategory: "CVE_VULN",
    sourceUrl: "https://www.first.org/epss/",
    run: async () => {
      let r: Response;
      try { r = await fetchWithTimeout("https://api.first.org/data/v1/epss?envelope=true&pretty=false&order=!epss&limit=200"); } catch { return []; }
      if (!r.ok) return [];
      const j = await r.json() as any;
      const out: ParsedItem[] = [];
      for (const e of j.data || []) {
        const epss = parseFloat(e.epss || "0");
        if (epss < 0.5) continue;
        out.push({
          sourceName: "FIRST EPSS",
          sourceCategory: "CVE_VULN",
          sourceUrl: "https://www.first.org/epss/",
          title: `${e.cve} — EPSS ${(epss * 100).toFixed(1)}% (percentile ${Math.round(parseFloat(e.percentile) * 100)}%)`,
          url: `https://nvd.nist.gov/vuln/detail/${e.cve}`,
          publishedAt: e.date ? new Date(e.date).toISOString() : new Date().toISOString(),
          severity: epss >= 0.9 ? "critical" : epss >= 0.7 ? "high" : "medium",
          cveIds: [e.cve],
          affectedTech: [],
          threatActors: [],
          summary: `EPSS exploit-prediction score ${(epss * 100).toFixed(2)}% places ${e.cve} in the top ${(100 - parseFloat(e.percentile) * 100).toFixed(1)}% of CVEs by predicted exploitation likelihood.`,
          rawSnippet: `[EPSS]\nCVE: ${e.cve}\nEPSS score: ${e.epss}\nPercentile: ${e.percentile}\nDate: ${e.date}`,
        });
      }
      return out;
    },
  });

  // ---- 9. Project Zero — issue tracker ----
  parsers.push({
    id: "deep-pzero",
    sourceId: findCatalogId("CVE_VULN", /Project Zero/i) || "osrc-pzero",
    sourceName: "Project Zero",
    sourceCategory: "CVE_VULN",
    sourceUrl: "https://googleprojectzero.blogspot.com/",
    run: async ({ sinceIso, maxItems }) => {
      let r: Response;
      try { r = await fetchWithTimeout("https://googleprojectzero.blogspot.com/feeds/posts/default?max-results=50"); } catch { return []; }
      if (!r.ok) return [];
      const body = await r.text();
      const entries = parseFeed(body);
      const out: ParsedItem[] = [];
      for (const e of entries.slice(0, maxItems)) {
        const pub = safeDateIso(e.pubDate);
        if (pub < sinceIso) continue;
        const text = `${e.title} ${e.description}`;
        out.push({
          sourceName: "Google Project Zero",
          sourceCategory: "CVE_VULN",
          sourceUrl: "https://googleprojectzero.blogspot.com/",
          title: e.title,
          url: e.link,
          publishedAt: pub,
          severity: severityFromText(text),
          cveIds: extractCves(text),
          affectedTech: detectTech(text),
          threatActors: detectActors(text),
          summary: e.description.slice(0, 320),
          rawSnippet: `[Project Zero]\n${e.title}\n\n${e.description}`,
        });
      }
      return out;
    },
  });

  // ---- 10. ZDI — published advisories ----
  parsers.push({
    id: "deep-zdi",
    sourceId: findCatalogId("CVE_VULN", /ZDI.*Trend Micro/i) || "osrc-zdi",
    sourceName: "ZDI advisories",
    sourceCategory: "CVE_VULN",
    sourceUrl: "https://www.zerodayinitiative.com/",
    run: async ({ sinceIso, maxItems }) => {
      let r: Response;
      try { r = await fetchWithTimeout("https://www.zerodayinitiative.com/rss/published/"); } catch { return []; }
      if (!r.ok) return [];
      const entries = parseFeed(await r.text());
      const out: ParsedItem[] = [];
      for (const e of entries.slice(0, maxItems)) {
        const pub = safeDateIso(e.pubDate);
        if (pub < sinceIso) continue;
        const text = `${e.title} ${e.description}`;
        out.push({
          sourceName: "ZDI",
          sourceCategory: "CVE_VULN",
          sourceUrl: "https://www.zerodayinitiative.com/",
          title: e.title,
          url: e.link,
          publishedAt: pub,
          severity: severityFromText(text),
          cveIds: extractCves(text),
          affectedTech: detectTech(text),
          threatActors: [],
          summary: e.description.slice(0, 320),
          rawSnippet: `[ZDI]\n${e.title}\n\n${e.description}`,
        });
      }
      return out;
    },
  });

  // ---- 11. BleepingComputer — full RSS (publishes ~30 items, deep history via archive) ----
  parsers.push({
    id: "deep-bleeping",
    sourceId: findCatalogId("SECURITY_NEWS", /BleepingComputer/i) || "osrc-bleeping",
    sourceName: "BleepingComputer",
    sourceCategory: "SECURITY_NEWS",
    sourceUrl: "https://www.bleepingcomputer.com/",
    run: async ({ sinceIso, maxItems }) => {
      // BleepingComputer's RSS gives ~50 most recent posts. We also try the
      // dedicated security tag feeds for deeper history.
      const out: ParsedItem[] = [];
      const urls = [
        "https://www.bleepingcomputer.com/feed/",
        "https://www.bleepingcomputer.com/tag/vulnerabilities/feed/",
        "https://www.bleepingcomputer.com/tag/security/feed/",
        "https://www.bleepingcomputer.com/tag/ransomware/feed/",
        "https://www.bleepingcomputer.com/tag/malware/feed/",
        "https://www.bleepingcomputer.com/tag/cve/feed/",
      ];
      for (const u of urls) {
        let r: Response;
        try { r = await fetchWithTimeout(u); } catch { continue; }
        if (!r.ok) continue;
        const entries = parseFeed(await r.text());
        for (const e of entries) {
          const pub = safeDateIso(e.pubDate);
          if (pub < sinceIso) continue;
          const text = `${e.title} ${e.description}`;
          out.push({
            sourceName: "BleepingComputer",
            sourceCategory: "SECURITY_NEWS",
            sourceUrl: "https://www.bleepingcomputer.com/",
            title: e.title,
            url: e.link,
            publishedAt: pub,
            severity: severityFromText(text),
            cveIds: extractCves(text),
            affectedTech: detectTech(text),
            threatActors: detectActors(text),
            summary: e.description.slice(0, 320),
            rawSnippet: `[BleepingComputer]\n${e.title}\n${e.link}\n\n${e.description}`,
          });
          if (out.length >= maxItems) return out;
        }
      }
      return out;
    },
  });

  // ---- 12. The Hacker News — multi-feed pull ----
  parsers.push({
    id: "deep-thn",
    sourceId: findCatalogId("SECURITY_NEWS", /Hacker News/i) || "osrc-thn",
    sourceName: "The Hacker News",
    sourceCategory: "SECURITY_NEWS",
    sourceUrl: "https://thehackernews.com/",
    run: async ({ sinceIso, maxItems }) => {
      const out: ParsedItem[] = [];
      const urls = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://thehackernews.com/feeds/posts/default?max-results=200",
        "https://thehackernews.com/search/label/vulnerability/feeds/posts/default?max-results=200",
        "https://thehackernews.com/search/label/Malware/feeds/posts/default?max-results=200",
      ];
      for (const u of urls) {
        let r: Response;
        try { r = await fetchWithTimeout(u); } catch { continue; }
        if (!r.ok) continue;
        const entries = parseFeed(await r.text());
        for (const e of entries) {
          const pub = safeDateIso(e.pubDate);
          if (pub < sinceIso) continue;
          const text = `${e.title} ${e.description}`;
          out.push({
            sourceName: "The Hacker News",
            sourceCategory: "SECURITY_NEWS",
            sourceUrl: "https://thehackernews.com/",
            title: e.title,
            url: e.link,
            publishedAt: pub,
            severity: severityFromText(text),
            cveIds: extractCves(text),
            affectedTech: detectTech(text),
            threatActors: detectActors(text),
            summary: e.description.slice(0, 320),
            rawSnippet: `[THN]\n${e.title}\n${e.link}\n\n${e.description}`,
          });
          if (out.length >= maxItems) return out;
        }
      }
      return out;
    },
  });

  // ---- 13-16. KrebsOnSecurity / DarkReading / SecurityWeek / Schneier ----
  const RICH_RSS: Array<[string, string, string, string]> = [
    ["KrebsOnSecurity", "SECURITY_NEWS", "https://krebsonsecurity.com/feed/", "https://krebsonsecurity.com/"],
    ["Dark Reading", "SECURITY_NEWS", "https://www.darkreading.com/rss.xml", "https://www.darkreading.com/"],
    ["SecurityWeek", "SECURITY_NEWS", "https://feeds.feedburner.com/Securityweek", "https://www.securityweek.com/"],
    ["Schneier on Security", "SECURITY_NEWS", "https://www.schneier.com/feed/atom/", "https://www.schneier.com/"],
    ["The Register Security", "SECURITY_NEWS", "https://www.theregister.com/security/headlines.atom", "https://www.theregister.com/security/"],
    ["SANS ISC Diary", "SECURITY_NEWS", "https://isc.sans.edu/rssfeed_full.xml", "https://isc.sans.edu/"],
    ["The DFIR Report", "SECURITY_NEWS", "https://thedfirreport.com/feed/", "https://thedfirreport.com/"],
    ["The Record (Recorded Future)", "SECURITY_NEWS", "https://therecord.media/feed", "https://therecord.media/"],
    ["Cyberscoop", "SECURITY_NEWS", "https://www.cyberscoop.com/feed/", "https://www.cyberscoop.com/"],
    ["404 Media — Cybersecurity", "SECURITY_NEWS", "https://www.404media.co/rss", "https://www.404media.co/"],
    ["Help Net Security", "SECURITY_NEWS", "https://www.helpnetsecurity.com/feed/", "https://www.helpnetsecurity.com/"],
    ["Cisco Talos", "SECURITY_NEWS", "https://blog.talosintelligence.com/feeds/posts/default", "https://blog.talosintelligence.com/"],
    ["Microsoft Threat Intelligence", "SECURITY_NEWS", "https://www.microsoft.com/en-us/security/blog/feed/", "https://www.microsoft.com/security/blog/"],
    ["Mandiant Threat Research", "SECURITY_NEWS", "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "https://cloud.google.com/blog/topics/threat-intelligence"],
    ["CrowdStrike Adversary blog", "SECURITY_NEWS", "https://www.crowdstrike.com/blog/feed/", "https://www.crowdstrike.com/blog/"],
    ["Unit 42 (Palo Alto)", "SECURITY_NEWS", "https://unit42.paloaltonetworks.com/feed/", "https://unit42.paloaltonetworks.com/"],
    ["Trend Micro Research", "SECURITY_NEWS", "https://feeds.trendmicro.com/TrendMicroResearch", "https://www.trendmicro.com/"],
    ["SentinelLabs", "SECURITY_NEWS", "https://www.sentinelone.com/labs/feed/", "https://www.sentinelone.com/labs/"],
    ["ESET WeLiveSecurity", "SECURITY_NEWS", "https://www.welivesecurity.com/en/rss/feed/", "https://www.welivesecurity.com/"],
    ["Securelist (Kaspersky)", "SECURITY_NEWS", "https://securelist.com/feed/", "https://securelist.com/"],
    ["Volexity", "SECURITY_NEWS", "https://www.volexity.com/blog/feed/", "https://www.volexity.com/"],
    ["Proofpoint Threat Insight", "SECURITY_NEWS", "https://www.proofpoint.com/us/threat-insight/feed", "https://www.proofpoint.com/"],
    ["Group-IB blog", "SECURITY_NEWS", "https://www.group-ib.com/blog/feed/", "https://www.group-ib.com/"],
    ["Tenable Blog Vulnerabilities", "SECURITY_NEWS", "https://www.tenable.com/blog/feed/category/vulnerabilities", "https://www.tenable.com/blog/"],
    ["Rapid7", "SECURITY_NEWS", "https://blog.rapid7.com/rss/", "https://blog.rapid7.com/"],
    ["Sophos News Security Operations", "SECURITY_NEWS", "https://news.sophos.com/en-us/category/security-operations/feed/", "https://news.sophos.com/"],
    ["Malwarebytes Labs", "SECURITY_NEWS", "https://www.malwarebytes.com/blog/feed", "https://www.malwarebytes.com/blog"],
    ["Snyk Vulnerabilities", "SECURITY_NEWS", "https://snyk.io/blog/category/vulnerabilities/feed/", "https://snyk.io/blog/"],
    ["AttackerKB", "SECURITY_NEWS", "https://attackerkb.com/api/feed", "https://attackerkb.com/"],
    ["GreyNoise blog", "SECURITY_NEWS", "https://www.greynoise.io/blog/rss.xml", "https://www.greynoise.io/"],
  ];
  for (const [name, cat, url, landing] of RICH_RSS) {
    let host = "";
    try { host = new URL(url).hostname.toLowerCase(); } catch { /* ignore */ }
    parsers.push({
      id: `deep-rich-${name.toLowerCase().replace(/\W+/g, "-")}`,
      // v2.9 fix: match catalog source by exact name (with host fallback) so
      // multi-word names like "The DFIR Report" don't collide with "The Hacker News".
      sourceId: findCatalogIdByName(name, host) || `osrc-${name.toLowerCase().replace(/\W+/g, "-")}`,
      sourceName: name,
      sourceCategory: cat,
      sourceUrl: landing,
      run: async ({ sinceIso, maxItems }) => {
        let r: Response;
        try { r = await fetchWithTimeout(url); } catch { return []; }
        if (!r.ok) return [];
        const entries = parseFeed(await r.text());
        const out: ParsedItem[] = [];
        for (const e of entries.slice(0, maxItems)) {
          const pub = safeDateIso(e.pubDate);
          if (pub < sinceIso) continue;
          const text = `${e.title} ${e.description}`;
          out.push({
            sourceName: name,
            sourceCategory: cat,
            sourceUrl: landing,
            title: e.title,
            url: e.link,
            publishedAt: pub,
            severity: severityFromText(text),
            cveIds: extractCves(text),
            affectedTech: detectTech(text),
            threatActors: detectActors(text),
            summary: e.description.slice(0, 320),
            rawSnippet: `[${name}]\n${e.title}\n${e.link}\n\n${e.description}`,
          });
        }
        return out;
      },
    });
  }

  return parsers;
}

// ============================================================================
// GENERIC CATALOG ADAPTER — best-effort across every seed entry
// ============================================================================
//
// Walks OSINT_SOURCES in batches, tries each URL once, and parses whatever it
// gets back. RSS / Atom / RDF feeds get parsed via parseFeed(). JSON gets a
// light-touch heuristic conversion. HTML pages without a feed are skipped
// (we'd need bespoke parsers, which deep parsers handle).

async function runOneGeneric(src: OsintSourceSeed, sinceIso: string, maxPerSource: number): Promise<ParsedItem[]> {
  // v2.8 — generic walker is RSS/Atom/RDF ONLY. JSON sources are handled by
  // hand-written deep parsers where the response shape is known.
  let r: Response;
  try { r = await fetchWithTimeout(src.url); } catch { return []; }
  if (!r.ok) return [];
  let body: string;
  try { body = await r.text(); } catch { return []; }
  if (!body || body.length < 32) return [];

  // Hard skip: anything that looks like JSON. The candidate filter already
  // drops .json / /api/ URLs, but some feeds Content-Negotiate to JSON.
  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return [];

  const items: ParsedItem[] = [];

  // RSS / Atom / RDF
  const entries = parseFeed(body);
  for (const e of entries.slice(0, maxPerSource)) {
    const pub = safeDateIso(e.pubDate);
    if (pub < sinceIso) continue;
    if (!e.title) continue;
    const text = `${e.title} ${e.description}`;
    items.push({
      sourceId: src.id,
      sourceName: src.name,
      sourceCategory: src.category,
      sourceUrl: src.url,
      title: e.title.slice(0, 280),
      url: e.link || src.url,
      publishedAt: pub,
      severity: severityFromText(text),
      cveIds: extractCves(text),
      affectedTech: detectTech(text),
      threatActors: detectActors(text),
      summary: e.description.slice(0, 320),
      rawSnippet: `[${src.name}]\n${e.title}\n${e.link}\n\n${e.description}`.slice(0, 2000),
    });
  }
  return items;
}

// v2.8 — RSS/Atom-only URL heuristic used by the generic catalog walker.
function looksLikeFeedUrl(url: string): boolean {
  const u = url.toLowerCase();
  // Drop JSON-style endpoints outright.
  if (/\.(json|csv|txt)(\?|$)/.test(u)) return false;
  if (/\/api\//.test(u)) return false;
  // Accept anything ending in a recognised feed extension or containing
  // /feed|/rss|/atom in the path.
  if (/\.(rss|xml|atom|rdf)(\?|$)/.test(u)) return true;
  if (/\/feeds?\//.test(u)) return true;
  if (/[?&\/](rss|atom|feed)([\/?&=]|$)/.test(u)) return true;
  if (/(\/feed\/?$|\/rss\/?$|\/atom\/?$)/.test(u)) return true;
  return false;
}

// ---------- main entrypoints -----------------------------------------------

/**
 * Targeted scan for legacy callers — fetches a small number of feeds, filters
 * by tenant tech. Preserved for backwards compatibility with v2.6 runOsintScan.
 */
export async function fetchRealOsintItems(opts: {
  techs: string[];
  maxItems: number;
}): Promise<{ items: ParsedItem[]; feedsTried: number; feedsOk: number; errors: string[] }> {
  const sinceIso = new Date(Date.now() - 30 * 86400_000).toISOString();
  const broad = await runBroadIngest({
    sinceIso,
    maxPerSource: 30,
    maxTotal: opts.maxItems * 4,
    deepOnly: true,
  });
  const allowed = new Set(opts.techs);
  const filtered = allowed.size === 0
    ? broad.items
    : broad.items.filter((it) => it.affectedTech.some((t) => allowed.has(t)));
  return {
    items: filtered.slice(0, opts.maxItems),
    feedsTried: broad.feedsTried,
    feedsOk: broad.feedsOk,
    errors: broad.errors.slice(0, 5),
  };
}

/**
 * Broad ingest — runs every deep parser AND walks the full catalog with the
 * generic adapter. Tenant tech filtering is NOT applied. Caller is expected to
 * persist every returned item and filter at view time.
 */
export async function runBroadIngest(opts: {
  sinceIso: string;            // ISO timestamp — only ingest items newer than this
  maxPerSource: number;        // hard cap per single source
  maxTotal: number;            // hard cap on total returned items
  deepOnly?: boolean;          // skip the generic 514-source walk (used by legacy scan)
  categoryFilter?: string[];   // optional whitelist of seed categories
}): Promise<{ items: ParsedItem[]; feedsTried: number; feedsOk: number; errors: string[] }> {
  const errors: string[] = [];
  const collected: ParsedItem[] = [];
  let feedsTried = 0;
  let feedsOk = 0;

  // ---- Phase A: deep parsers ----
  const deep = buildDeepParsers();
  let di = 0;
  async function deepWorker() {
    while (di < deep.length && collected.length < opts.maxTotal) {
      const p = deep[di++];
      feedsTried += 1;
      try {
        const items = await p.run({ sinceIso: opts.sinceIso, maxItems: opts.maxPerSource * 3 });
        if (items.length > 0) feedsOk += 1;
        for (const it of items) {
          if (!it.sourceId) it.sourceId = p.sourceId;
          collected.push(it);
          if (collected.length >= opts.maxTotal) return;
        }
      } catch (e: any) {
        errors.push(`${p.id}: ${e?.message || e}`);
      }
    }
  }
  await Promise.all(Array.from({ length: FEED_CONCURRENCY }, () => deepWorker()));

  if (opts.deepOnly) {
    return finalise(collected, feedsTried, feedsOk, errors, opts.maxTotal);
  }

  // ---- Phase B: generic catalog walk (v2.8 — RSS/Atom XML only) ----
  // Pre-filter sources: skip anything that isn't a feed-style URL. JSON sources
  // (NVD/GHSA/OSV/KEV/etc.) are handled by hand-written deep parsers above.
  const candidates = OSINT_SOURCES.filter((s) => {
    if (opts.categoryFilter && !opts.categoryFilter.includes(s.category)) return false;
    const FEED_CATS = new Set(["SECURITY_NEWS","CVE_VULN","CERT_GOV","VENDOR_RESEARCH","RANSOMWARE_LEAK"]);
    if (!FEED_CATS.has(s.category)) return false;
    return looksLikeFeedUrl(s.url);
  });

  let gi = 0;
  async function genericWorker() {
    while (gi < candidates.length && collected.length < opts.maxTotal) {
      const src = candidates[gi++];
      feedsTried += 1;
      try {
        const items = await runOneGeneric(src, opts.sinceIso, opts.maxPerSource);
        if (items.length > 0) feedsOk += 1;
        for (const it of items) {
          collected.push(it);
          if (collected.length >= opts.maxTotal) return;
        }
      } catch (e: any) {
        errors.push(`${src.id}: ${e?.message || e}`);
      }
    }
  }
  await Promise.all(Array.from({ length: FEED_CONCURRENCY }, () => genericWorker()));

  return finalise(collected, feedsTried, feedsOk, errors, opts.maxTotal);
}

function finalise(
  collected: ParsedItem[],
  feedsTried: number,
  feedsOk: number,
  errors: string[],
  maxTotal: number,
): { items: ParsedItem[]; feedsTried: number; feedsOk: number; errors: string[] } {
  const SEV: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  // v2.8 — enrich every item with normalised URL, contentHash and IoCs.
  for (const it of collected) {
    it.url = normaliseUrl(it.url || "");
    const text = `${it.title || ""} ${it.summary || ""} ${it.rawSnippet || ""}`;
    if (!it.iocs) it.iocs = extractIoCs(text, it.url || it.sourceUrl);
    if (!it.contentHash) it.contentHash = contentHashFor(it.title || "", it.url || it.sourceUrl || "");
  }

  // v2.8 — primary dedupe key is contentHash (cross-source: same advisory
  // reposted by N feeds collapses to one item). Fallback is (sourceId, url).
  const byHash = new Map<string, ParsedItem>();
  for (const it of collected) {
    const key = it.contentHash || `${it.sourceId || it.sourceName}::${(it.url || it.title).slice(0, 200)}`.toLowerCase();
    const prev = byHash.get(key);
    if (!prev) { byHash.set(key, it); continue; }
    // Merge: keep highest severity; union IoCs / CVE / tech / actor arrays.
    const winner: ParsedItem = ((SEV[it.severity] ?? 0) > (SEV[prev.severity] ?? 0)) ? it : prev;
    const other: ParsedItem = winner === it ? prev : it;
    winner.cveIds = Array.from(new Set([...(winner.cveIds || []), ...(other.cveIds || [])]));
    winner.affectedTech = Array.from(new Set([...(winner.affectedTech || []), ...(other.affectedTech || [])]));
    winner.threatActors = Array.from(new Set([...(winner.threatActors || []), ...(other.threatActors || [])]));
    if (winner.iocs || other.iocs) {
      const merged: FindingIoCs = { ...(winner.iocs || {}) };
      const o = other.iocs || {};
      const keys = new Set([...Object.keys(merged), ...Object.keys(o)]) as Set<keyof FindingIoCs>;
      for (const k of keys) {
        const a = (merged[k] || []) as string[];
        const b = (o[k] || []) as string[];
        const u = Array.from(new Set([...a, ...b]));
        if (u.length) (merged as any)[k] = u.slice(0, 20);
      }
      winner.iocs = merged;
    }
    byHash.set(key, winner);
  }

  const deduped = Array.from(byHash.values());
  deduped.sort((a, b) => {
    const dr = (SEV[b.severity] ?? 0) - (SEV[a.severity] ?? 0);
    if (dr !== 0) return dr;
    return (b.publishedAt || "").localeCompare(a.publishedAt || "");
  });
  return {
    items: deduped.slice(0, maxTotal),
    feedsTried,
    feedsOk,
    errors: errors.slice(0, 20),
  };
}
