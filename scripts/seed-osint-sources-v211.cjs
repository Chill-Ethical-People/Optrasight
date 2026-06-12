#!/usr/bin/env node
// Seed v2.11 OSINT sources into an existing database.
// Upserts new sources without touching existing ones.
// Usage: node scripts/seed-osint-sources-v211.cjs [path/to/data.db]

const Database = require("better-sqlite3");
const path = require("path");

const dbPath = process.argv[2] || path.join(__dirname, "..", "data", "data.db");
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");

const PRUNED_SOURCE_IDS = new Set([
  "osrc-1001", "osrc-1002", "osrc-1003", "osrc-1004", "osrc-1005", "osrc-1006",
  "osrc-1007", "osrc-1008", "osrc-1009", "osrc-1010", "osrc-1011", "osrc-1012",
  "osrc-1020", "osrc-1021", "osrc-1022", "osrc-1023", "osrc-1024", "osrc-1025",
  "osrc-1026", "osrc-1027", "osrc-1028", "osrc-1029", "osrc-1030", "osrc-1031",
  "osrc-1040", "osrc-1041", "osrc-1042", "osrc-1043", "osrc-1044", "osrc-1045",
  "osrc-1046", "osrc-1047", "osrc-1048", "osrc-1049", "osrc-1050", "osrc-1051", "osrc-1052",
  "osrc-1053", "osrc-1054", "osrc-1055", "osrc-1056", "osrc-1057", "osrc-1058",
  "osrc-1059",
]);

const NEW_SOURCES = [
  // CERT_GOV additions
  { id: "osrc-1001", category: "CERT_GOV", name: "CISA — Cybersecurity Alerts & Advisories", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", region: "US", reliability: "A" },
  { id: "osrc-1002", category: "CERT_GOV", name: "UK NCSC — Advisories", url: "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", region: "GB", reliability: "A" },
  { id: "osrc-1003", category: "CERT_GOV", name: "Australian ACSC — Alerts", url: "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/rss.xml", region: "AU", reliability: "A" },
  { id: "osrc-1004", category: "CERT_GOV", name: "Canadian CCCS — Advisories", url: "https://www.cyber.gc.ca/api/v1/rss/en", region: "CA", reliability: "A" },
  { id: "osrc-1005", category: "CERT_GOV", name: "ENISA — Threat Landscape", url: "https://www.enisa.europa.eu/publications/rss", region: "EU", reliability: "A" },
  { id: "osrc-1006", category: "CERT_GOV", name: "BSI — German Federal Cyber Agency", url: "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_en.xml", region: "DE", reliability: "A" },
  { id: "osrc-1007", category: "CERT_GOV", name: "CERT-In — India Advisories", url: "https://www.cert-in.org.in/Rss.jsp", region: "IN", reliability: "A" },
  { id: "osrc-1008", category: "CERT_GOV", name: "SingCERT — Singapore", url: "https://www.csa.gov.sg/api/RSS/getsecurityalerts", region: "SG", reliability: "A" },
  { id: "osrc-1009", category: "CERT_GOV", name: "HKCERT — Hong Kong", url: "https://www.hkcert.org/feed/rss", region: "HK", reliability: "A" },
  { id: "osrc-1010", category: "CERT_GOV", name: "KrCERT — South Korea (KISA)", url: "https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000133&menuNo=205020&pageIndex=1", region: "KR", reliability: "A" },
  { id: "osrc-1011", category: "CERT_GOV", name: "CERT-EU — EU Institutions", url: "https://cert.europa.eu/publications/security-advisories/rss", region: "EU", reliability: "A" },
  { id: "osrc-1012", category: "CERT_GOV", name: "CERT-PL — Poland", url: "https://cert.pl/en/rss.xml", region: "PL", reliability: "A" },

  // VENDOR_RESEARCH additions
  { id: "osrc-1020", category: "VENDOR_RESEARCH", name: "Cisco Talos Intelligence", url: "https://blog.talosintelligence.com/feeds/posts/default", reliability: "A" },
  { id: "osrc-1021", category: "VENDOR_RESEARCH", name: "Volexity Threat Research", url: "https://www.volexity.com/blog/feed/", reliability: "A" },
  { id: "osrc-1022", category: "VENDOR_RESEARCH", name: "Proofpoint Threat Insight", url: "https://www.proofpoint.com/us/threat-insight/feed", reliability: "A" },
  { id: "osrc-1023", category: "VENDOR_RESEARCH", name: "Sophos News — Security Operations", url: "https://news.sophos.com/en-us/category/security-operations/feed/", reliability: "A" },
  { id: "osrc-1024", category: "VENDOR_RESEARCH", name: "Trend Micro Research", url: "https://feeds.trendmicro.com/TrendMicroResearch", reliability: "A" },
  { id: "osrc-1025", category: "VENDOR_RESEARCH", name: "Google TAG — Threat Analysis Group", url: "https://blog.google/threat-analysis-group/rss/", reliability: "A" },
  { id: "osrc-1026", category: "VENDOR_RESEARCH", name: "Group-IB Research", url: "https://www.group-ib.com/blog/feed/", reliability: "A" },
  { id: "osrc-1027", category: "VENDOR_RESEARCH", name: "Dragos — ICS/OT Threat Research", url: "https://www.dragos.com/feed/", reliability: "A" },
  { id: "osrc-1028", category: "VENDOR_RESEARCH", name: "Huntress — SMB Threat Research", url: "https://www.huntress.com/blog/rss.xml", reliability: "B" },
  { id: "osrc-1029", category: "VENDOR_RESEARCH", name: "Zscaler ThreatLabz", url: "https://www.zscaler.com/blogs/security-research/feed", reliability: "A" },
  { id: "osrc-1030", category: "VENDOR_RESEARCH", name: "Secureworks — Counter Threat Unit", url: "https://www.secureworks.com/blog/rss", reliability: "A" },
  { id: "osrc-1031", category: "VENDOR_RESEARCH", name: "Google Project Zero", url: "https://googleprojectzero.blogspot.com/feeds/posts/default", reliability: "A" },
  { id: "osrc-1032", category: "VENDOR_RESEARCH", name: "InfoGuard Labs", url: "https://labs.infoguard.ch/rss.xml", region: "CH", reliability: "B" },

  // THREAT_INTEL — IOC feeds
  { id: "osrc-1040", category: "THREAT_INTEL", name: "abuse.ch — MalwareBazaar Recent", url: "https://mb-api.abuse.ch/api/v1/", reliability: "A" },
  { id: "osrc-1041", category: "THREAT_INTEL", name: "abuse.ch — ThreatFox IOCs", url: "https://threatfox-api.abuse.ch/api/v1/", reliability: "A" },
  { id: "osrc-1042", category: "THREAT_INTEL", name: "abuse.ch — URLhaus Recent URLs", url: "https://urlhaus-api.abuse.ch/v1/urls/recent/", reliability: "A" },
  { id: "osrc-1043", category: "THREAT_INTEL", name: "abuse.ch — Feodo Tracker C2 IPs", url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", reliability: "A" },
  { id: "osrc-1044", category: "THREAT_INTEL", name: "abuse.ch — SSL Blocklist", url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", reliability: "A" },
  { id: "osrc-1045", category: "THREAT_INTEL", name: "AlienVault OTX — Pulse Feed", url: "https://otx.alienvault.com/api/v1/pulses/subscribed", reliability: "A" },
  { id: "osrc-1046", category: "THREAT_INTEL", name: "OpenPhish — Community Phishing Feed", url: "https://openphish.com/feed.txt", reliability: "B" },
  { id: "osrc-1047", category: "THREAT_INTEL", name: "PhishTank — Verified Phishing", url: "https://data.phishtank.com/data/online-valid.json.gz", reliability: "B" },
  { id: "osrc-1048", category: "THREAT_INTEL", name: "DShield — SANS Top Attackers", url: "https://isc.sans.edu/api/topips/records/100?json", reliability: "A" },
  { id: "osrc-1049", category: "THREAT_INTEL", name: "Spamhaus DROP — Do Not Route", url: "https://www.spamhaus.org/drop/drop.txt", reliability: "A" },
  { id: "osrc-1050", category: "THREAT_INTEL", name: "Spamhaus EDROP — Extended", url: "https://www.spamhaus.org/drop/edrop.txt", reliability: "A" },
  { id: "osrc-1051", category: "THREAT_INTEL", name: "Blocklist.de — All Attack IPs", url: "https://lists.blocklist.de/lists/all.txt", reliability: "B" },
  { id: "osrc-1052", category: "THREAT_INTEL", name: "Tor Exit Nodes — Bulk Exit List", url: "https://check.torproject.org/torbulkexitlist", reliability: "A" },
  { id: "osrc-1053", category: "THREAT_INTEL", name: "TweetFeed — Security Researcher IOCs", url: "https://api.tweetfeed.live/v1/month/", reliability: "B" },
  { id: "osrc-1054", category: "THREAT_INTEL", name: "Botvrij.eu — CSIRT IOCs", url: "https://www.botvrij.eu/data/feed-osint", reliability: "B" },
  { id: "osrc-1055", category: "THREAT_INTEL", name: "CyberCure — Free Threat Intel", url: "https://api.cybercure.ai/feed/get_hash?type=csv", reliability: "C" },
  { id: "osrc-1056", category: "THREAT_INTEL", name: "MITRE ATT&CK — Updates Blog", url: "https://medium.com/feed/mitre-attack", reliability: "A" },
  { id: "osrc-1057", category: "THREAT_INTEL", name: "C2IntelFeeds — Active C2 Servers", url: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv", reliability: "B" },
  { id: "osrc-1058", category: "THREAT_INTEL", name: "GreyNoise — Mass Scanner Trends", url: "https://www.greynoise.io/blog/rss.xml", reliability: "B" },
  { id: "osrc-1059", category: "THREAT_INTEL", name: "InQuest Labs — IOC Feed", url: "https://labs.inquest.net/api/iocdb/list?type=ip&last_seen_after=30d", reliability: "B" },
].filter((source) => !PRUNED_SOURCE_IDS.has(source.id));

const ins = db.prepare(
  "INSERT OR IGNORE INTO osint_sources (id, category, name, url, language, region, reliability, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, 1)"
);

const tx = db.transaction((rows) => {
  let added = 0;
  for (const s of rows) {
    const r = ins.run(s.id, s.category, s.name, s.url, "en", s.region || null, s.reliability || "B");
    if (r.changes > 0) added++;
  }
  return added;
});

const added = tx(NEW_SOURCES);
const total = db.prepare("SELECT COUNT(*) AS c FROM osint_sources").get().c;

console.log(`Seeded ${added} new OSINT sources (${total} total). DB=${dbPath}`);
db.close();
