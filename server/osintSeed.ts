// OSINT source catalog — v2.10 pruned + re-categorised.
//
// v2.9 carried 521 sources across legacy CVE/CERT/GOV/RSS/VENDOR/RANSOMWARE/
// GHSA/SOCIAL/TELEGRAM/PASTE/DARKWEB categories. 452 of those never returned
// findings in production ingest runs (many require credentials, were 404, or
// were placeholders padded out to a round 500). v2.10 ships only the 69 feeds
// that actually parse on the live network, organised into a 5-bucket taxonomy:
//
//   1. CVE_VULN          — NVD, KEV, ZDI, Exploit-DB, JVN, GHSA mirrors
//   2. CERT_GOV          — Regional CERTs (CERT-FR, JPCERT, NCSC-NL, CIRCL,
//                          NIST, Taiwan NICST, etc.)
//   3. VENDOR_RESEARCH   — Threat-research blogs from named vendors
//                          (Unit 42, Mandiant, Microsoft Threat Intelligence,
//                          CrowdStrike, SentinelLabs, ESET, Securelist, ZDI,
//                          DFIR Report, Check Point, etc.) and vendor PSIRT
//                          advisories (Fortinet, Palo Alto, GitLab, Apple,
//                          AWS, Cloudflare, Chrome, Ubuntu, Amazon Linux, …)
//   4. SECURITY_NEWS     — Independent / press / community news outlets
//                          (Hacker News, BleepingComputer, Dark Reading,
//                          SecurityWeek, Krebs, Wired, The Register, etc.)
//   5. RANSOMWARE_LEAK   — Ransomware victim trackers + data-breach feeds
//
// Reliability uses NATO admiralty grades (A=verified primary source,
// B=usually reliable, C=community/unverified).

export type OsintCategory =
  | "CVE_VULN"
  | "CERT_GOV"
  | "VENDOR_RESEARCH"
  | "SECURITY_NEWS"
  | "RANSOMWARE_LEAK";

export const CATEGORY_LABELS: Record<OsintCategory, string> = {
  CVE_VULN: "CVE & Vulnerability DBs",
  CERT_GOV: "CERT / Government Advisories",
  VENDOR_RESEARCH: "Vendor Threat Research",
  SECURITY_NEWS: "Security News & Press",
  RANSOMWARE_LEAK: "Ransomware & Data-Leak Feeds",
};

export interface OsintSourceSeed {
  id: string;
  category: OsintCategory;
  name: string;
  url: string;
  language?: string;
  region?: string | null;
  reliability?: "A" | "B" | "C";
}

// Stable IDs are preserved across v2.9 → v2.10 so existing findings keep
// resolving even if we re-ingest (defence-in-depth — we wipe + re-ingest as
// part of v2.10 anyway, but keeping the IDs makes diffing easier).
export const OSINT_SOURCES: OsintSourceSeed[] = [
  // ============== 1. CVE & Vulnerability DBs (9) ==============
  { id: "osrc-0001", category: "CVE_VULN", name: "NVD JSON 1.1 — recent", url: "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz", reliability: "A" },
  { id: "osrc-0030", category: "CVE_VULN", name: "CISA KEV — RSS", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", reliability: "A" },
  { id: "osrc-0034", category: "CVE_VULN", name: "GitHub Advisory DB (GHSA mirror)", url: "https://github.com/github/advisory-database", reliability: "A" },
  { id: "osrc-0035", category: "CVE_VULN", name: "Exploit-DB — RSS", url: "https://www.exploit-db.com/rss.xml", reliability: "B" },
  { id: "osrc-0038", category: "CVE_VULN", name: "JVN iPedia — Japan Vulnerability Notes", url: "https://jvndb.jvn.jp/en/rss/jvndb.rdf", region: "JP", reliability: "A" },
  { id: "osrc-0039", category: "CVE_VULN", name: "JVN — JPCERT/CC Advisories", url: "https://jvn.jp/en/rss/jvn.rdf", region: "JP", reliability: "A" },
  { id: "osrc-0043", category: "CVE_VULN", name: "ZDI — Trend Micro Zero Day Initiative", url: "https://www.zerodayinitiative.com/rss/published/", reliability: "A" },
  { id: "osrc-0044", category: "CVE_VULN", name: "ZDI — Upcoming advisories", url: "https://www.zerodayinitiative.com/rss/upcoming/", reliability: "A" },
  { id: "osrc-0046", category: "CVE_VULN", name: "Tenable Research advisories", url: "https://www.tenable.com/security/research/feed", reliability: "A" },
  { id: "osrc-0508a", category: "CVE_VULN", name: "OSV — PyPI", url: "https://osv.dev/list?ecosystem=PyPI", reliability: "B" },
  { id: "osrc-0032", category: "CVE_VULN", name: "CIRCL CVE search", url: "https://cve.circl.lu/", reliability: "A" },
  { id: "osrc-0033", category: "CVE_VULN", name: "FIRST EPSS", url: "https://www.first.org/epss/", reliability: "A" },

  // ============== 2. CERT / Government Advisories (6) ==============
  { id: "osrc-0151", category: "CERT_GOV", name: "NCSC-NL — Netherlands advisories", url: "https://advisories.ncsc.nl/rss/advisories", region: "NL", reliability: "A" },
  { id: "osrc-0154", category: "CERT_GOV", name: "CERT-FR — avis", url: "https://www.cert.ssi.gouv.fr/avis/feed/", region: "FR", reliability: "A" },
  { id: "osrc-0159", category: "CERT_GOV", name: "JPCERT/CC — alerts", url: "https://www.jpcert.or.jp/rss/jpcert.rdf", region: "JP", reliability: "A" },
  { id: "osrc-0179", category: "CERT_GOV", name: "CIRCL — Luxembourg", url: "https://circl.lu/rss.xml", region: "LU", reliability: "A" },
  { id: "osrc-0187", category: "CERT_GOV", name: "NIST — Cybersecurity blog", url: "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml", region: "US", reliability: "A" },
  { id: "osrc-0508", category: "CERT_GOV", name: "Taiwan iThome — Security Weekly", url: "https://www.ithome.com.tw/rss", region: "TW", reliability: "A" },

  // ============== 3. Vendor Threat Research & PSIRT (24) ==============
  { id: "osrc-0061", category: "VENDOR_RESEARCH", name: "Palo Alto — Unit 42 threat research", url: "https://unit42.paloaltonetworks.com/feed/", reliability: "A" },
  { id: "osrc-0280", category: "VENDOR_RESEARCH", name: "Mandiant — Threat Intelligence", url: "https://cloud.google.com/blog/topics/threat-intelligence/rss/", reliability: "A" },
  { id: "osrc-0279", category: "VENDOR_RESEARCH", name: "Microsoft Threat Intelligence", url: "https://www.microsoft.com/en-us/security/blog/feed/", reliability: "A" },
  { id: "osrc-0277", category: "VENDOR_RESEARCH", name: "CrowdStrike — Adversary blog", url: "https://www.crowdstrike.com/blog/feed/", reliability: "A" },
  { id: "osrc-0281", category: "VENDOR_RESEARCH", name: "SentinelLabs", url: "https://www.sentinelone.com/labs/feed/", reliability: "A" },
  { id: "osrc-0282", category: "VENDOR_RESEARCH", name: "ESET WeLiveSecurity", url: "https://www.welivesecurity.com/en/rss/feed/", reliability: "A" },
  { id: "osrc-0283", category: "VENDOR_RESEARCH", name: "Securelist (Kaspersky)", url: "https://securelist.com/feed/", reliability: "A" },
  { id: "osrc-0289", category: "VENDOR_RESEARCH", name: "The DFIR Report", url: "https://thedfirreport.com/feed/", reliability: "A" },
  { id: "osrc-0072", category: "VENDOR_RESEARCH", name: "Check Point Research", url: "https://research.checkpoint.com/feed/", reliability: "A" },
  { id: "osrc-0297", category: "VENDOR_RESEARCH", name: "Rapid7 blog", url: "https://blog.rapid7.com/rss/", reliability: "A" },
  { id: "osrc-0304", category: "VENDOR_RESEARCH", name: "Malwarebytes Labs", url: "https://www.malwarebytes.com/blog/feed", reliability: "B" },
  { id: "osrc-0307", category: "VENDOR_RESEARCH", name: "Imperva blog", url: "https://www.imperva.com/blog/feed/", reliability: "B" },
  { id: "osrc-0314", category: "VENDOR_RESEARCH", name: "Bishop Fox", url: "https://bishopfox.com/blog/rss.xml", reliability: "B" },
  // Vendor PSIRT / security advisories
  { id: "osrc-0058", category: "VENDOR_RESEARCH", name: "Fortinet — PSIRT RSS", url: "https://filestore.fortinet.com/fortiguard/rss/ir.xml", reliability: "A" },
  { id: "osrc-0060", category: "VENDOR_RESEARCH", name: "Palo Alto — PSIRT advisories", url: "https://security.paloaltonetworks.com/rss.xml", reliability: "A" },
  { id: "osrc-0086", category: "VENDOR_RESEARCH", name: "Apple — Security RSS", url: "https://developer.apple.com/news/releases/rss/releases.rss", reliability: "A" },
  { id: "osrc-0087", category: "VENDOR_RESEARCH", name: "Google — Chrome Releases blog", url: "https://chromereleases.googleblog.com/feeds/posts/default", reliability: "A" },
  { id: "osrc-0094", category: "VENDOR_RESEARCH", name: "Ubuntu — Security Notices", url: "https://ubuntu.com/security/notices/rss.xml", reliability: "A" },
  { id: "osrc-0097", category: "VENDOR_RESEARCH", name: "Amazon Linux — Security Advisories", url: "https://alas.aws.amazon.com/AL2/alas.rss", reliability: "A" },
  { id: "osrc-0099", category: "VENDOR_RESEARCH", name: "AWS — Security Bulletins", url: "https://aws.amazon.com/security/security-bulletins/rss/feed/", reliability: "A" },
  { id: "osrc-0100", category: "VENDOR_RESEARCH", name: "AWS — Security Blog", url: "https://aws.amazon.com/blogs/security/feed/", reliability: "A" },
  { id: "osrc-0102", category: "VENDOR_RESEARCH", name: "GCP — Cloud security bulletins", url: "https://cloud.google.com/feeds/gcp-release-notes.xml", reliability: "A" },
  { id: "osrc-0108", category: "VENDOR_RESEARCH", name: "GitLab — Security blog", url: "https://about.gitlab.com/atom.xml", reliability: "A" },
  { id: "osrc-0113", category: "VENDOR_RESEARCH", name: "Fortra — Security Advisories", url: "https://www.fortra.com/security/advisory", reliability: "A" },
  { id: "osrc-0135", category: "VENDOR_RESEARCH", name: "Cloudflare — Security blog", url: "https://blog.cloudflare.com/tag/security/rss", reliability: "A" },
  { id: "osrc-0051", category: "VENDOR_RESEARCH", name: "Microsoft — Azure Security blog", url: "https://azure.microsoft.com/en-us/blog/topics/security/feed/", reliability: "A" },
  { id: "osrc-0339", category: "VENDOR_RESEARCH", name: "CIS — Center for Internet Security", url: "https://www.cisecurity.org/feed/", reliability: "A" },

  // ============== 4. Security News & Press (24) ==============
  { id: "osrc-0263", category: "SECURITY_NEWS", name: "KrebsOnSecurity", url: "https://krebsonsecurity.com/feed/", reliability: "B" },
  { id: "osrc-0264", category: "SECURITY_NEWS", name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/", reliability: "B" },
  { id: "osrc-0265", category: "SECURITY_NEWS", name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews", reliability: "B" },
  { id: "osrc-0266", category: "SECURITY_NEWS", name: "Dark Reading", url: "https://www.darkreading.com/rss.xml", reliability: "B" },
  { id: "osrc-0269", category: "SECURITY_NEWS", name: "SecurityWeek", url: "https://feeds.feedburner.com/Securityweek", reliability: "B" },
  { id: "osrc-0270", category: "SECURITY_NEWS", name: "The Register — Security", url: "https://www.theregister.com/security/headlines.atom", reliability: "B" },
  { id: "osrc-0318", category: "SECURITY_NEWS", name: "Help Net Security", url: "https://www.helpnetsecurity.com/feed/", reliability: "B" },
  { id: "osrc-0319", category: "SECURITY_NEWS", name: "TechCrunch Security", url: "https://techcrunch.com/category/security/feed/", reliability: "B" },
  { id: "osrc-0320", category: "SECURITY_NEWS", name: "Wired — Threat Level", url: "https://www.wired.com/feed/category/security/latest/rss", reliability: "B" },
  { id: "osrc-0321", category: "SECURITY_NEWS", name: "Infosecurity Magazine UK", url: "https://www.infosecurity-magazine.com/rss/news/", reliability: "B" },
  { id: "osrc-0323", category: "SECURITY_NEWS", name: "CSO Online", url: "https://www.csoonline.com/feed/", reliability: "B" },
  { id: "osrc-0324", category: "SECURITY_NEWS", name: "The Record (Recorded Future)", url: "https://therecord.media/feed", reliability: "B" },
  { id: "osrc-0330", category: "SECURITY_NEWS", name: "NextGov — Cybersecurity", url: "https://www.nextgov.com/rss/cybersecurity/", reliability: "B" },
  { id: "osrc-0331", category: "SECURITY_NEWS", name: "Cyberscoop", url: "https://www.cyberscoop.com/feed/", reliability: "B" },
  { id: "osrc-0333", category: "SECURITY_NEWS", name: "Schneier on Security", url: "https://www.schneier.com/feed/atom/", reliability: "B" },
  { id: "osrc-0334", category: "SECURITY_NEWS", name: "Graham Cluley", url: "https://grahamcluley.com/feed/", reliability: "B" },
  { id: "osrc-0335", category: "SECURITY_NEWS", name: "Daniel Miessler", url: "https://danielmiessler.com/feed/", reliability: "B" },
  { id: "osrc-0337", category: "SECURITY_NEWS", name: "SANS ISC Diary", url: "https://isc.sans.edu/rssfeed_full.xml", reliability: "B" },
  { id: "osrc-0341", category: "SECURITY_NEWS", name: "Bellingcat", url: "https://www.bellingcat.com/feed/", reliability: "B" },
  { id: "osrc-0342", category: "SECURITY_NEWS", name: "404 Media — Cybersecurity", url: "https://www.404media.co/rss", reliability: "B" },
  { id: "osrc-0344", category: "SECURITY_NEWS", name: "Just Security — Cyber", url: "https://www.justsecurity.org/feed/", reliability: "B" },
  { id: "osrc-0345", category: "SECURITY_NEWS", name: "The Citizen Lab", url: "https://citizenlab.ca/feed/", reliability: "B" },
  { id: "osrc-0347", category: "SECURITY_NEWS", name: "EFF Deeplinks", url: "https://www.eff.org/rss/updates.xml", reliability: "B" },

  // ============== 5. Ransomware & Data-Leak Feeds (3) ==============
  { id: "osrc-0258", category: "RANSOMWARE_LEAK", name: "Ransomware.live — feed", url: "https://www.ransomware.live/api/recentvictims", reliability: "B" },
  { id: "osrc-0260", category: "RANSOMWARE_LEAK", name: "DarkFeed — aggregated CTI", url: "https://darkfeed.io/feed/", reliability: "B" },
  { id: "osrc-0261", category: "RANSOMWARE_LEAK", name: "DataBreach.today — RSS", url: "https://www.databreaches.net/feed/", reliability: "B" },
];
