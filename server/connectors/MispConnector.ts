import type { CommunityIngestConfig } from "../communityIntegrations";
import { communityConnectorHeaders } from "../communityIntegrations";
import { ThreatIntelConnector } from "./ThreatIntelConnector";
import type { ConnectorIntelItem, ConnectorParsingServices, ConnectorRunOptions } from "./types";

export class MispConnector extends ThreatIntelConnector<CommunityIngestConfig> {
  readonly metadata = {
    id: "community-misp",
    sourceId: "osrc-1063",
    sourceName: "MISP — configured community",
    sourceCategory: "THREAT_INTEL",
    sourceUrl: "https://www.misp-project.org/",
  } as const;
  constructor(config: CommunityIngestConfig, parsing: ConnectorParsingServices) {
    super(config, parsing);
  }

  async fetch({ sinceIso, maxItems }: ConnectorRunOptions): Promise<ConnectorIntelItem[]> {
    const payload = await this.fetchJson(
      `${this.config.endpoint}/attributes/restSearch`,
      {
        method: "POST",
        headers: {
          ...communityConnectorHeaders(this.config),
          accept: "application/json",
          "content-type": "application/json",
        },
        body: JSON.stringify({ returnFormat: "json", timestamp: sinceIso, limit: maxItems, includeContext: true }),
      },
      15_000,
    );
    const attributes = Array.isArray(payload?.response?.Attribute)
      ? payload.response.Attribute
      : Array.isArray(payload?.Attribute)
        ? payload.Attribute
        : Array.isArray(payload)
          ? payload
          : [];
    return attributes.slice(0, maxItems).map((attribute: any) => {
      const event = attribute?.Event || {};
      const title = this.parsing.stripHtml(
        String(event?.info || attribute?.comment || `MISP ${attribute?.type || "attribute"}`),
      );
      const value = String(attribute?.value || "");
      const text = `${title} ${attribute?.category || ""} ${value}`;
      const publishedAt = this.parsing.safeDateIso(
        attribute?.timestamp
          ? Number(attribute.timestamp) * 1000
          : event?.publish_timestamp
            ? Number(event.publish_timestamp) * 1000
            : sinceIso,
      );
      return {
        sourceId: this.metadata.sourceId,
        sourceName: this.metadata.sourceName,
        sourceCategory: this.metadata.sourceCategory,
        sourceUrl: this.metadata.sourceUrl,
        title: title.slice(0, 280),
        url: `${this.config.endpoint}/events/view/${event?.id || attribute?.event_id || ""}`,
        publishedAt,
        severity: event?.threat_level_id === "1" ? "high" : event?.threat_level_id === "2" ? "medium" : "low",
        cveIds: this.parsing.extractCves(text),
        affectedTech: this.parsing.detectTech(text),
        threatActors: this.parsing.detectActors(text),
        summary: `${attribute?.category || "MISP attribute"}: ${value}`.slice(0, 320),
        rawSnippet:
          `[MISP]\nEvent: ${title}\nType: ${attribute?.type || "unknown"}\nValue: ${value}\nComment: ${attribute?.comment || ""}`.slice(
            0,
            2000,
          ),
      } as ConnectorIntelItem;
    });
  }
}
