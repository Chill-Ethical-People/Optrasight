# Threat-intelligence connectors

Authenticated and vendor-specific collection adapters live here. Built-in RSS
and public catalog parsers remain in `osintFetcher.ts` until they need their own
configuration or lifecycle.

To add a connector:

1. Extend `ThreatIntelConnector<TConfig>`.
2. Return normalized `ConnectorIntelItem` records from `fetch()`.
3. Register the connector in `registry.ts` only when its workspace configuration
   is enabled and complete.
4. Add its source metadata to `osintSeed.ts`, disabled by default.
5. Keep credentials in the server-side secret store; never return them to the
   client or place them in source metadata.

The base class enforces safe outbound URL validation, timeout handling, a stable
user agent, and JSON response handling. Source classes should contain only
authentication details, upstream response mapping, and source-specific quality
controls.
