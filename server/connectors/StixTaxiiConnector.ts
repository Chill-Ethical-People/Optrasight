import type { CommunityIngestConfig } from "../communityIntegrations";
import { communityConnectorHeaders } from "../communityIntegrations";
import { ThreatIntelConnector } from "./ThreatIntelConnector";
import type { ConnectorIntelItem, ConnectorParsingServices, ConnectorRunOptions } from "./types";

export class StixTaxiiConnector extends ThreatIntelConnector<CommunityIngestConfig> {
  readonly metadata = {
    id: "community-taxii",
    sourceId: "osrc-1062",
    sourceName: "TAXII 2.1 — configured collection",
    sourceCategory: "THREAT_INTEL",
    sourceUrl: "https://www.oasis-open.org/standard/taxii2-1/",
  } as const;

  constructor(config: CommunityIngestConfig, parsing: ConnectorParsingServices) {
    super(config, parsing);
  }

  async fetch({ sinceIso, maxItems }: ConnectorRunOptions): Promise<ConnectorIntelItem[]> {
    const url = `${this.config.endpoint}/collections/${encodeURIComponent(this.config.collectionId)}/objects/?limit=${Math.min(maxItems, 100)}&added_after=${encodeURIComponent(sinceIso)}`;
    const payload = await this.fetchJson(
      url,
      {
        headers: {
          ...communityConnectorHeaders(this.config),
          accept: "application/taxii+json;version=2.1, application/stix+json;version=2.1",
        },
      },
      15_000,
    );
    const objects = Array.isArray(payload?.objects) ? payload.objects : [];
    return objects.slice(0, maxItems).flatMap((object: any) => this.mapObject(object, sinceIso));
  }

  private mapObject(object: any, sinceIso: string): ConnectorIntelItem[] {
    const publishedAt = this.parsing.safeDateIso(
      object?.published || object?.created || object?.modified || object?.first_seen,
    );
    if (publishedAt < sinceIso) return [];
    const type = String(object?.type || "stix-object");
    const name = this.parsing.stripHtml(String(object?.name || object?.labels?.[0] || ""));
    const description = this.parsing.stripHtml(String(object?.description || ""));
    const pattern = String(object?.pattern || "");
    const text = `${name} ${description} ${pattern}`.trim();
    if (!text) return [];
    const reference = Array.isArray(object?.external_references)
      ? object.external_references.find((entry: any) => entry?.url)?.url
      : null;
    return [
      {
        sourceId: this.metadata.sourceId,
        sourceName: this.metadata.sourceName,
        sourceCategory: this.metadata.sourceCategory,
        sourceUrl: this.metadata.sourceUrl,
        title: (name || `TAXII ${type}`).slice(0, 280),
        url: typeof reference === "string" ? reference : this.config.endpoint,
        publishedAt,
        severity: this.parsing.severityFromText(text),
        cveIds: this.parsing.extractCves(text),
        affectedTech: this.parsing.detectTech(text),
        threatActors: this.parsing.detectActors(text),
        summary: (description || pattern || name).slice(0, 320),
        rawSnippet: `[TAXII 2.1]\nType: ${type}\nCollection: ${this.config.collectionId}\n\n${text}`.slice(0, 2000),
      },
    ];
  }
}
