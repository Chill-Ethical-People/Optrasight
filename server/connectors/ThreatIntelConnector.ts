import { isSafeSourceFetchUrl } from "../sourceFetch";
import type { ConnectorIntelItem, ConnectorParsingServices, ConnectorRunOptions } from "./types";

export interface ThreatIntelConnectorMetadata {
  id: string;
  sourceId: string;
  sourceName: string;
  sourceCategory: string;
  sourceUrl: string;
}

export abstract class ThreatIntelConnector<TConfig> {
  abstract readonly metadata: ThreatIntelConnectorMetadata;

  protected constructor(
    protected readonly config: TConfig,
    protected readonly parsing: ConnectorParsingServices,
  ) {}

  abstract fetch(options: ConnectorRunOptions): Promise<ConnectorIntelItem[]>;

  protected async request(url: string, init: RequestInit = {}, timeoutMs = 9_000): Promise<Response> {
    if (!(await isSafeSourceFetchUrl(url))) throw new Error("unsafe connector URL");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, {
        ...init,
        signal: controller.signal,
        headers: {
          accept: "application/json",
          "user-agent": "OptraSight-Connector/1.0 (+https://optrasight.local)",
          ...(init.headers || {}),
        },
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  protected async fetchJson(url: string, init: RequestInit = {}, timeoutMs = 9_000): Promise<any> {
    const response = await this.request(url, init, timeoutMs);
    if (!response.ok) throw new Error(`connector request failed (HTTP ${response.status})`);
    return response.json();
  }
}
