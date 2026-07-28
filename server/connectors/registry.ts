import type { KelaIngestConfig } from "../kelaIntegration";
import { FalconFeedsXConnector } from "./FalconFeedsXConnector";
import { KelaStixConnector } from "./KelaStixConnector";
import type { ThreatIntelConnector } from "./ThreatIntelConnector";
import type { ConnectorParsingServices } from "./types";
import type { CommunityIngestConfig } from "../communityIntegrations";
import { MalwareBazaarConnector, ThreatFoxConnector, UrlHausConnector } from "./AbuseChConnectors";
import { StixTaxiiConnector } from "./StixTaxiiConnector";
import { MispConnector } from "./MispConnector";

export interface ConnectorRegistryOptions {
  xBearerToken?: string | null;
  kelaConfig?: KelaIngestConfig | null;
  communityConfigs?: CommunityIngestConfig[];
}

export function createThreatIntelConnectors(
  options: ConnectorRegistryOptions,
  parsing: ConnectorParsingServices,
): ThreatIntelConnector<any>[] {
  const connectors: ThreatIntelConnector<any>[] = [];
  const xToken =
    options.xBearerToken === undefined
      ? process.env.X_BEARER_TOKEN || process.env.TWITTER_BEARER_TOKEN || ""
      : options.xBearerToken || "";
  if (options.xBearerToken !== null && xToken.trim()) {
    connectors.push(new FalconFeedsXConnector({ bearerToken: xToken }, parsing));
  }
  if (options.kelaConfig) connectors.push(new KelaStixConnector(options.kelaConfig, parsing));
  for (const config of options.communityConfigs || []) {
    if (config.kind === "abusech")
      connectors.push(
        new ThreatFoxConnector(config, parsing),
        new MalwareBazaarConnector(config, parsing),
        new UrlHausConnector(config, parsing),
      );
    if (config.kind === "taxii") connectors.push(new StixTaxiiConnector(config, parsing));
    if (config.kind === "misp") connectors.push(new MispConnector(config, parsing));
  }
  return connectors;
}
