// ---------------------------------------------------------------------------
// v2.28 — Security-publisher block-list
// ---------------------------------------------------------------------------
// Hostnames belonging to security vendors, research blogs, news outlets, and
// public CVE/MITRE databases. URLs and domains whose host (or apex domain)
// matches this set are *reference links*, not threat indicators — they're
// stripped from the IoC `url` and `domain` buckets regardless of where they
// appear (regex pre-parse on ingest AND AI post-cleanup).
//
// Kept in a standalone module so both osintFetcher.ts (ingest-time regex
// extractor) and aiClient.ts (AI cleanup pass) can import it without creating
// a circular import.
// ---------------------------------------------------------------------------

export const SECURITY_PUBLISHER_HOSTS: ReadonlySet<string> = new Set([
  // Vendor research blogs
  "www.rapid7.com", "rapid7.com",
  "www.mandiant.com", "mandiant.com", "cloud.google.com",
  "www.crowdstrike.com", "crowdstrike.com",
  "www.microsoft.com", "learn.microsoft.com", "techcommunity.microsoft.com", "msrc.microsoft.com",
  "blog.talosintelligence.com", "talosintelligence.com", "blogs.cisco.com",
  "unit42.paloaltonetworks.com", "www.paloaltonetworks.com", "paloaltonetworks.com",
  "www.kaspersky.com", "kaspersky.com", "securelist.com",
  "www.welivesecurity.com", "welivesecurity.com",
  "www.eset.com", "eset.com",
  "www.fortinet.com", "fortinet.com", "www.fortiguard.com", "fortiguard.com",
  "www.sentinelone.com", "sentinelone.com", "www.sentinellabs.com", "sentinellabs.com",
  "www.sophos.com", "sophos.com", "news.sophos.com",
  "www.symantec.com", "symantec-enterprise-blogs.security.com",
  "www.trendmicro.com", "trendmicro.com",
  "www.checkpoint.com", "checkpoint.com", "research.checkpoint.com",
  "www.recordedfuture.com", "recordedfuture.com",
  "www.proofpoint.com", "proofpoint.com",
  "blog.virustotal.com", "www.virustotal.com", "virustotal.com",
  "www.akamai.com", "akamai.com",
  "www.huntress.com", "huntress.com",
  "www.zscaler.com", "zscaler.com",
  "www.tenable.com", "tenable.com",
  "www.qualys.com", "qualys.com",
  "www.tanium.com", "tanium.com",
  "www.cybereason.com", "cybereason.com",
  "redcanary.com", "www.redcanary.com",
  "www.intel471.com", "intel471.com",
  "www.group-ib.com", "group-ib.com",
  "www.flashpoint-intel.com", "flashpoint-intel.com",
  "www.greynoise.io", "greynoise.io",
  "www.shadowserver.org", "shadowserver.org",
  // Security news
  "www.bleepingcomputer.com", "bleepingcomputer.com",
  "thehackernews.com", "www.thehackernews.com",
  "www.infosecurity-magazine.com", "infosecurity-magazine.com",
  "www.securityweek.com", "securityweek.com",
  "www.darkreading.com", "darkreading.com",
  "www.theregister.com", "theregister.com",
  "www.zdnet.com", "zdnet.com",
  "krebsonsecurity.com", "www.krebsonsecurity.com",
  "www.scmagazine.com", "scmagazine.com",
  "www.helpnetsecurity.com", "helpnetsecurity.com",
  "www.cyberscoop.com", "cyberscoop.com",
  "therecord.media", "www.therecord.media",
  // CERTs / Government
  "www.cisa.gov", "cisa.gov",
  "www.cert.gov", "cert.gov",
  "www.us-cert.gov", "us-cert.gov",
  "www.ncsc.gov.uk", "ncsc.gov.uk",
  "www.cyber.gov.au", "cyber.gov.au",
  "www.hkcert.org", "hkcert.org",
  // Public databases / standards
  "attack.mitre.org", "www.mitre.org", "cwe.mitre.org",
  "nvd.nist.gov", "www.nist.gov",
  "cve.mitre.org", "www.cve.org",
  "exploit-db.com", "www.exploit-db.com",
  "www.first.org", "first.org",
  // Code hosts (when used as references, not C2 — real C2 on github is rare)
  "github.com", "raw.githubusercontent.com", "gist.github.com",
  "gitlab.com",
]);

export function isSecurityPublisherHost(hostname: string): boolean {
  const h = String(hostname || "").toLowerCase().replace(/^www\./, "");
  if (SECURITY_PUBLISHER_HOSTS.has(hostname)) return true;
  if (SECURITY_PUBLISHER_HOSTS.has("www." + h)) return true;
  if (SECURITY_PUBLISHER_HOSTS.has(h)) return true;
  return false;
}
