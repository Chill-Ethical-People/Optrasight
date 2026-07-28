export const CLIENT_MATCHING_SCOPES = ["cti_subscription", "managed_security", "hybrid", "advisory"] as const;
export type ClientMatchingScope = (typeof CLIENT_MATCHING_SCOPES)[number];

export const MANAGED_SECURITY_TECHNOLOGY_LIMIT = 5;
export const MANAGED_SECURITY_MAPPING_TERM_LIMIT = 2;

const TYPE_ALIASES: Record<string, string> = {
  CTI: "TI",
  "THREAT INTELLIGENCE": "TI",
  "CYBER THREAT INTELLIGENCE": "TI",
  MDD: "MDR",
  "MANAGED DETECTION AND DEFENCE": "MDR",
  "MANAGED DETECTION AND RESPONSE": "MDR",
  "MANAGED SECURITY SERVICE": "MSS",
  IR: "CIR",
  "INCIDENT RESPONSE": "CIR",
  "CYBER INCIDENT RESPONSE": "CIR",
  "RED TEAM": "RED_TEAM",
  "RED TEAM / OFFENSIVE": "RED_TEAM",
  "VCISO / ADVISORY": "VCISO",
};

function cleanClientType(value: string): string {
  return value
    .normalize("NFKC")
    .trim()
    .toUpperCase()
    .split(/\s+[—–-]\s+/)[0]
    .replace(/\s+/g, " ");
}

export function normalizeClientTypeIds(values: string[]): string[] {
  const supported = new Set(["MSS", "MDR", "CIR", "TI", "RED_TEAM", "VCISO"]);
  return Array.from(
    new Set(
      values.flatMap((value) => {
        const cleaned = cleanClientType(value);
        const normalized = TYPE_ALIASES[cleaned] ?? cleaned.replace(/[\s-]+/g, "_");
        return supported.has(normalized) ? [normalized] : [];
      }),
    ),
  );
}

export function isManagedSecurityClient(clientTypes: string[]): boolean {
  const types = new Set(normalizeClientTypeIds(clientTypes));
  return types.has("MSS") || types.has("MDR") || types.has("CIR");
}

export function clientProfileScopeLimitErrors(input: {
  clientTypes: string[];
  monitoredTechnologies: string[];
  mappingTerms: string[];
}): string[] {
  if (!isManagedSecurityClient(input.clientTypes)) return [];
  const errors: string[] = [];
  if (new Set(input.monitoredTechnologies).size > MANAGED_SECURITY_TECHNOLOGY_LIMIT) {
    errors.push(`MSS, MDR, and IR clients can monitor at most ${MANAGED_SECURITY_TECHNOLOGY_LIMIT} technologies.`);
  }
  const mappingTerms = new Set(input.mappingTerms.map((term) => term.normalize("NFKC").trim()).filter(Boolean));
  if (mappingTerms.size > MANAGED_SECURITY_MAPPING_TERM_LIMIT) {
    errors.push(`MSS, MDR, and IR clients can use at most ${MANAGED_SECURITY_MAPPING_TERM_LIMIT} mapping keywords.`);
  }
  return errors;
}

export function clientMatchingScopeForTypes(clientTypes: string[]): ClientMatchingScope {
  const types = new Set(normalizeClientTypeIds(clientTypes));
  const hasCti = types.has("TI");
  const hasManaged = types.has("MSS") || types.has("MDR") || types.has("CIR");
  if (hasCti && hasManaged) return "hybrid";
  if (hasCti) return "cti_subscription";
  if (hasManaged) return "managed_security";
  return "advisory";
}

export const CLIENT_MATCHING_SCOPE_META: Record<ClientMatchingScope, { label: string; description: string }> = {
  cti_subscription: {
    label: "CTI subscription",
    description:
      "Broader strategic and tactical intelligence: campaigns, actors, victimology, sector and geography, source confidence, indicators, and outlook. A direct technology match is not mandatory, but exposure must not be implied.",
  },
  managed_security: {
    label: "MSS/MDR operational",
    description:
      "Prioritizes confirmed or plausible technology exposure, telemetry correlation, detection coverage, hunting, patching, containment, and indicator fitness.",
  },
  hybrid: {
    label: "Hybrid CTI + managed security",
    description:
      "Applies both strategic CTI context and operational MSS/MDR relevance, while keeping intelligence outlook separate from environment-specific action.",
  },
  advisory: {
    label: "Advisory",
    description:
      "Uses business, sector, geography, and technology context for proportionate awareness without implying continuous monitoring or confirmed exposure.",
  },
};
