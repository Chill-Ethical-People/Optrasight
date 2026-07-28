import type { FindingIoCs } from "../../shared/schema";

export interface ConnectorIntelItem {
  sourceId?: string;
  sourceName: string;
  sourceCategory: string;
  sourceUrl: string;
  title: string;
  url: string;
  publishedAt: string;
  /** True when the source omitted or supplied an invalid publication date. */
  publishedAtInferred?: boolean;
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** Severity asserted or heuristically derived directly from the publisher. */
  publisherSeverity?: "critical" | "high" | "medium" | "low" | "info";
  /** Client-neutral technical severity before analyst or client-impact overrides. */
  technicalSeverity?: "critical" | "high" | "medium" | "low" | "info";
  cveIds: string[];
  affectedTech: string[];
  threatActors: string[];
  iocs?: FindingIoCs;
  contentHash?: string;
  summary: string;
  rawSnippet: string;
}

export interface ConnectorRunOptions {
  sinceIso: string;
  maxItems: number;
}

export interface ConnectorParsingServices {
  stripHtml(value: string): string;
  safeDateIso(value: unknown): string;
  severityFromText(value: string): ConnectorIntelItem["severity"];
  extractCves(value: string): string[];
  detectTech(value: string): string[];
  detectActors(value: string): string[];
}
