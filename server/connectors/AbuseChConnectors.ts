import type { CommunityIngestConfig } from "../communityIntegrations";
import { ThreatIntelConnector } from "./ThreatIntelConnector";
import type { ConnectorIntelItem, ConnectorParsingServices, ConnectorRunOptions } from "./types";

abstract class AbuseChConnector extends ThreatIntelConnector<CommunityIngestConfig> {
  constructor(config: CommunityIngestConfig, parsing: ConnectorParsingServices) {
    super(config, parsing);
  }
  protected headers(): Record<string, string> {
    return { "Auth-Key": this.config.credential };
  }
  protected item(
    sourceId: string,
    sourceName: string,
    title: string,
    url: string,
    publishedAt: string,
    text: string,
    severity: ConnectorIntelItem["severity"],
  ): ConnectorIntelItem {
    return {
      sourceId,
      sourceName,
      sourceCategory: "THREAT_INTEL",
      sourceUrl: url,
      title: title.slice(0, 280),
      url,
      publishedAt,
      severity,
      cveIds: this.parsing.extractCves(text),
      affectedTech: this.parsing.detectTech(text),
      threatActors: this.parsing.detectActors(text),
      summary: text.slice(0, 320),
      rawSnippet: `[${sourceName}]\n${text}`.slice(0, 2000),
    };
  }
}

export class ThreatFoxConnector extends AbuseChConnector {
  readonly metadata = {
    id: "community-threatfox",
    sourceId: "osrc-1041",
    sourceName: "abuse.ch — ThreatFox",
    sourceCategory: "THREAT_INTEL",
    sourceUrl: "https://threatfox.abuse.ch/",
  } as const;
  async fetch({ sinceIso, maxItems }: ConnectorRunOptions): Promise<ConnectorIntelItem[]> {
    const payload = await this.fetchJson("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { ...this.headers(), "content-type": "application/json" },
      body: JSON.stringify({ query: "get_iocs", days: 7 }),
    });
    const rows = Array.isArray(payload?.data) ? payload.data : [];
    return rows.slice(0, maxItems).flatMap((row: any) => {
      const publishedAt = this.parsing.safeDateIso(row?.first_seen_utc || row?.first_seen);
      if (publishedAt < sinceIso) return [];
      const text = `${row?.malware_printable || row?.malware || "ThreatFox IOC"} ${row?.ioc_type || ""} ${row?.ioc || ""} ${(row?.tags || []).join(" ")}`;
      return [
        this.item(
          this.metadata.sourceId,
          this.metadata.sourceName,
          `ThreatFox: ${row?.malware_printable || row?.malware || row?.ioc_type || "IOC"}`,
          row?.reference || this.metadata.sourceUrl,
          publishedAt,
          text,
          "high",
        ),
      ];
    });
  }
}

export class MalwareBazaarConnector extends AbuseChConnector {
  readonly metadata = {
    id: "community-malwarebazaar",
    sourceId: "osrc-1040",
    sourceName: "abuse.ch — MalwareBazaar",
    sourceCategory: "THREAT_INTEL",
    sourceUrl: "https://bazaar.abuse.ch/",
  } as const;
  async fetch({ sinceIso, maxItems }: ConnectorRunOptions): Promise<ConnectorIntelItem[]> {
    const response = await this.request("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { ...this.headers(), "content-type": "application/x-www-form-urlencoded" },
      body: "query=get_recent&selector=time",
    });
    if (!response.ok) throw new Error(`MalwareBazaar failed (HTTP ${response.status})`);
    const payload = (await response.json()) as any;
    const rows = Array.isArray(payload?.data) ? payload.data : [];
    return rows.slice(0, maxItems).flatMap((row: any) => {
      const publishedAt = this.parsing.safeDateIso(row?.first_seen);
      if (publishedAt < sinceIso) return [];
      const text = `${row?.signature || row?.file_type || "Malware sample"} SHA256 ${row?.sha256_hash || ""} ${(row?.tags || []).join(" ")}`;
      return [
        this.item(
          this.metadata.sourceId,
          this.metadata.sourceName,
          `MalwareBazaar: ${row?.signature || row?.file_name || "sample"}`,
          `${this.metadata.sourceUrl}sample/${row?.sha256_hash || ""}/`,
          publishedAt,
          text,
          "high",
        ),
      ];
    });
  }
}

export class UrlHausConnector extends AbuseChConnector {
  readonly metadata = {
    id: "community-urlhaus",
    sourceId: "osrc-1042",
    sourceName: "abuse.ch — URLhaus",
    sourceCategory: "THREAT_INTEL",
    sourceUrl: "https://urlhaus.abuse.ch/",
  } as const;
  async fetch({ sinceIso, maxItems }: ConnectorRunOptions): Promise<ConnectorIntelItem[]> {
    const payload = await this.fetchJson(
      `https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(this.config.credential)}/recent.json`,
    );
    const rows = Array.isArray(payload?.urls) ? payload.urls : Array.isArray(payload) ? payload : [];
    return rows.slice(0, maxItems).flatMap((row: any) => {
      const publishedAt = this.parsing.safeDateIso(row?.date_added || row?.firstseen);
      if (publishedAt < sinceIso) return [];
      const text = `${row?.threat || "Malware URL"} ${row?.url || ""} ${(row?.tags || []).join(" ")}`;
      return [
        this.item(
          this.metadata.sourceId,
          this.metadata.sourceName,
          `URLhaus: ${row?.threat || row?.url_status || "malware URL"}`,
          row?.urlhaus_reference || this.metadata.sourceUrl,
          publishedAt,
          text,
          "high",
        ),
      ];
    });
  }
}
