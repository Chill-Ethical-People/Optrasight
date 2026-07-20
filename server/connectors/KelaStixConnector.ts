import { kelaRequestHeaders, type KelaIngestConfig } from "../kelaIntegration";
import { ThreatIntelConnector } from "./ThreatIntelConnector";
import type { ConnectorIntelItem, ConnectorParsingServices, ConnectorRunOptions } from "./types";

export class KelaStixConnector extends ThreatIntelConnector<KelaIngestConfig> {
  readonly metadata = {
    id: "deep-kela-stix",
    sourceId: "osrc-1058",
    sourceName: "KELA — Technical Intelligence STIX",
    sourceCategory: "THREAT_INTEL",
    sourceUrl: "https://www.kelacyber.com/technical-intelligence/",
  } as const;

  constructor(config: KelaIngestConfig, parsing: ConnectorParsingServices) {
    super(config, parsing);
  }

  async fetch({ sinceIso, maxItems }: ConnectorRunOptions): Promise<ConnectorIntelItem[]> {
    const payload = await this.fetchJson(this.config.feedUrl, { headers: kelaRequestHeaders(this.config) });
    const objects = Array.isArray(payload?.objects)
      ? payload.objects
      : Array.isArray(payload?.data)
        ? payload.data
        : Array.isArray(payload?.items)
          ? payload.items
          : Array.isArray(payload?.results)
            ? payload.results
            : [];
    const out: ConnectorIntelItem[] = [];

    for (const object of objects) {
      if (out.length >= maxItems) break;
      const type = String(object?.type || object?.object_type || "intelligence");
      const publishedAt = this.parsing.safeDateIso(
        object?.published || object?.created || object?.modified || object?.first_seen || object?.timestamp,
      );
      if (publishedAt < sinceIso) continue;
      const description = this.parsing.stripHtml(
        String(object?.description || object?.summary || object?.context || ""),
      );
      const pattern = String(object?.pattern || object?.indicator || object?.value || "");
      const name = this.parsing.stripHtml(String(object?.name || object?.title || object?.label || ""));
      const text = `${name} ${description} ${pattern}`.trim();
      if (!text) continue;
      const rawReference = Array.isArray(object?.external_references)
        ? object.external_references.find((item: any) => typeof item?.url === "string")?.url
        : null;
      let reference: string | null = null;
      try {
        const candidate = rawReference ? new URL(rawReference) : null;
        if (candidate && (candidate.protocol === "https:" || candidate.protocol === "http:"))
          reference = candidate.toString();
      } catch {
        /* Ignore malformed vendor references. */
      }
      const title = name || `KELA ${type.replace(/-/g, " ")} intelligence`;
      out.push({
        sourceId: this.metadata.sourceId,
        sourceName: this.metadata.sourceName,
        sourceCategory: this.metadata.sourceCategory,
        sourceUrl: this.metadata.sourceUrl,
        title: title.slice(0, 280),
        url: reference || this.config.feedUrl,
        publishedAt,
        severity: this.parsing.severityFromText(`${object?.severity || ""} ${text}`),
        cveIds: this.parsing.extractCves(text),
        affectedTech: this.parsing.detectTech(text),
        threatActors: this.parsing.detectActors(text),
        summary: (description || pattern || title).slice(0, 320),
        rawSnippet:
          `[KELA Technical Intelligence — licensed STIX]\nType: ${type}\nPublished: ${publishedAt}\nReference: ${reference || "KELA API"}\n\n${text}`.slice(
            0,
            2000,
          ),
      });
    }
    return out;
  }
}
