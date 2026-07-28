import type { AiProvider } from "@shared/schema";
import type { ClientDigestInput, ClientDigestOutput, OsintAnalysisInput, OsintAnalysisOutput } from "./aiClient";

type ProviderIdentity = Pick<AiProvider, "provider">;

export interface ClientIdentity {
  id?: string | null;
  name: string;
}

interface IdentityRule {
  alias: string;
  id: string | null;
  name: string;
}

export interface ClientIdentityBoundary {
  external: boolean;
  aliasForId(id: string | null | undefined): string | undefined;
  realIdForAlias(alias: string | null | undefined): string | undefined;
  restoreNames(value: string): string;
  sanitiseContextValues(values: readonly string[]): string[];
  sanitisePayload<T>(value: T): T;
  sanitiseText(value: string): string;
}

const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const DOMAIN_PATTERN = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;

/** Ollama is the only connector whose traffic is permitted to remain on-premises. */
export function isExternalAiProvider(provider: ProviderIdentity): boolean {
  return provider.provider !== "ollama";
}

function escaped(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function replaceIdentity(value: string, identity: string, replacement: string): string {
  if (!identity) return value;
  const expression =
    /^[\p{L}\p{N}_]/u.test(identity) && /[\p{L}\p{N}_]$/u.test(identity)
      ? new RegExp(`(?<![\\p{L}\\p{N}_])${escaped(identity)}(?![\\p{L}\\p{N}_])`, "giu")
      : new RegExp(escaped(identity), "gi");
  return value.replace(expression, () => replacement);
}

function mapPayload<T>(value: T, mapText: (input: string) => string, seen = new WeakMap<object, unknown>()): T {
  if (typeof value === "string") return mapText(value) as T;
  if (value == null || typeof value !== "object") return value;
  if (seen.has(value)) return seen.get(value) as T;
  if (Array.isArray(value)) {
    const output: unknown[] = [];
    seen.set(value, output);
    value.forEach((item) => output.push(mapPayload(item, mapText, seen)));
    return output as T;
  }
  const output: Record<string, unknown> = {};
  seen.set(value, output);
  Object.entries(value as Record<string, unknown>).forEach(([key, item]) => {
    output[key] = mapPayload(item, mapText, seen);
  });
  return output as T;
}

export function createClientIdentityBoundary(
  provider: ProviderIdentity,
  identities: readonly ClientIdentity[],
): ClientIdentityBoundary {
  const external = isExternalAiProvider(provider);
  const rules: IdentityRule[] = identities
    .map((identity, index) => ({
      alias: `CLIENT-${String(index + 1).padStart(2, "0")}`,
      id: String(identity.id || "").trim() || null,
      name: String(identity.name || "").trim(),
    }))
    .filter((identity) => identity.name.length > 0);
  const replacements = rules
    .flatMap((rule) => [
      ...(rule.id ? [{ sensitive: rule.id, alias: rule.alias }] : []),
      { sensitive: rule.name, alias: rule.alias },
    ])
    .sort((left, right) => right.sensitive.length - left.sensitive.length);

  const sanitiseText = (value: string): string => {
    if (!external) return value;
    return replacements.reduce(
      (output, replacement) => replaceIdentity(output, replacement.sensitive, replacement.alias),
      value,
    );
  };
  const restoreNames = (value: string): string =>
    rules.reduce((output, rule) => replaceIdentity(output, rule.alias, rule.name), value);

  return {
    external,
    aliasForId: (id) => rules.find((rule) => rule.id === id)?.alias,
    realIdForAlias: (alias) => rules.find((rule) => rule.alias === alias)?.id ?? undefined,
    restoreNames,
    sanitiseContextValues: (values) => {
      if (!external) return [...values];
      return Array.from(
        new Set(
          values.map((value) =>
            sanitiseText(String(value || ""))
              .replace(EMAIL_PATTERN, "[EMAIL]")
              .replace(DOMAIN_PATTERN, "[DOMAIN]")
              .trim(),
          ),
        ),
      ).filter((value) => value.length > 0 && !/^(?:CLIENT-\d{2}|\[EMAIL\]|\[DOMAIN\])$/i.test(value));
    },
    sanitisePayload: <T>(value: T) => (external ? mapPayload(value, sanitiseText) : value),
    sanitiseText,
  };
}

export function prepareOsintAnalysisForProvider(
  input: OsintAnalysisInput,
  provider: ProviderIdentity,
): {
  input: OsintAnalysisInput;
  restoreOutput: (output: OsintAnalysisOutput) => OsintAnalysisOutput;
  external: boolean;
} {
  const clients = input.clientProfile?.clients ?? [];
  const boundary = createClientIdentityBoundary(provider, clients);
  if (!boundary.external) return { input, restoreOutput: (output) => output, external: false };

  const safeInput = boundary.sanitisePayload(input);
  safeInput.clientProfile.clients = safeInput.clientProfile.clients.map((client, index) => ({
    ...client,
    id: boundary.aliasForId(clients[index]?.id) ?? `CLIENT-${String(index + 1).padStart(2, "0")}`,
    name: boundary.aliasForId(clients[index]?.id) ?? `CLIENT-${String(index + 1).padStart(2, "0")}`,
    mappingTerms: boundary.sanitiseContextValues(clients[index]?.mappingTerms ?? []),
  }));

  return {
    input: safeInput,
    external: true,
    restoreOutput: (output) => ({
      ...output,
      ...(output.clientIds
        ? {
            clientIds: output.clientIds.flatMap((clientId) => boundary.realIdForAlias(clientId) ?? []),
          }
        : {}),
      ...(output.clientMatches
        ? {
            clientMatches: output.clientMatches.flatMap((match) => {
              const clientId = boundary.realIdForAlias(match.clientId);
              return clientId
                ? [
                    {
                      ...match,
                      clientId,
                      reason: boundary.restoreNames(match.reason),
                    },
                  ]
                : [];
            }),
          }
        : {}),
    }),
  };
}

export function prepareClientDigestForProvider(
  input: ClientDigestInput,
  provider: ProviderIdentity,
): { input: ClientDigestInput; restoreOutput: (output: ClientDigestOutput) => ClientDigestOutput; external: boolean } {
  const boundary = createClientIdentityBoundary(provider, [{ name: input.client.name }]);
  if (!boundary.external) return { input, restoreOutput: (output) => output, external: false };

  const safeInput = boundary.sanitisePayload(input);
  safeInput.client.name = "CLIENT-01";
  safeInput.client.mappingTerms = boundary.sanitiseContextValues(input.client.mappingTerms);
  return {
    input: safeInput,
    external: true,
    restoreOutput: (output) => ({
      ...output,
      subject: boundary.restoreNames(output.subject),
      bodyMd: boundary.restoreNames(output.bodyMd),
    }),
  };
}
