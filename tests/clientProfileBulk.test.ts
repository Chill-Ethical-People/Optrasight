import { describe, expect, it } from "vitest";

import {
  clientMatchingScopeForTypes,
  clientProfileScopeLimitErrors,
  normalizeClientTypeIds,
} from "../shared/clientMatchingScope";
import { parseClientProfileBulkCsv } from "../shared/clientProfileBulk";
import { clientProfileBulkCreateSchema } from "../shared/schema";

describe("Client Profile bulk CSV", () => {
  it("parses multi-value fields and quoted client names", () => {
    const profiles =
      parseClientProfileBulkCsv(`name,client_types,geographies,industries,technologies,mapping_terms,notification_emails,digest_enabled,digest_cadence
"Example, Limited",TI,Hong Kong|Singapore,Financial Services,,APT campaigns|regional outlook,cti@example.com,true,weekly`);

    expect(profiles).toEqual([
      expect.objectContaining({
        name: "Example, Limited",
        clientTypes: ["TI"],
        geographies: ["Hong Kong", "Singapore"],
        mappingTerms: ["APT campaigns", "regional outlook"],
        digestEnabled: true,
        digestCadence: "weekly",
      }),
    ]);
    expect(clientProfileBulkCreateSchema.safeParse({ profiles }).success).toBe(true);
  });

  it("rejects invalid cadence before submission", () => {
    expect(() => parseClientProfileBulkCsv(`name,digest_cadence\nExample,quarterly`)).toThrow(/digest_cadence/);
  });

  it("enforces the managed-security monitoring limits for bulk rows", () => {
    const overLimit = {
      name: "Managed Client",
      clientTypes: ["MSS"],
      geographies: [],
      industries: [],
      monitoredTechnologies: ["one", "two", "three", "four", "five", "six"],
      mappingTerms: ["brand", "domain", "business unit"],
      notificationEmails: [],
      digestEnabled: false,
      digestCadence: "weekly" as const,
    };
    const parsed = clientProfileBulkCreateSchema.safeParse({ profiles: [overLimit] });
    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    const messages = parsed.error.issues.map((issue) => issue.message).join(" ");
    expect(messages).toMatch(/at most 5 technologies/);
    expect(messages).toMatch(/at most 2 mapping keywords/);
  });
});

describe("client-type matching scope", () => {
  it.each([
    [["TI"], "cti_subscription"],
    [["CTI"], "cti_subscription"],
    [["MSS", "MDR"], "managed_security"],
    [["CIR"], "managed_security"],
    [["TI", "MDR"], "hybrid"],
    [["VCISO"], "advisory"],
  ] as const)("maps %j to %s", (types, expected) => {
    expect(clientMatchingScopeForTypes([...types])).toBe(expected);
  });

  it("normalizes common service aliases", () => {
    expect(normalizeClientTypeIds(["Cyber Threat Intelligence", "MDD", "Incident Response"])).toEqual([
      "TI",
      "MDR",
      "CIR",
    ]);
  });

  it("applies managed limits to IR aliases but not TI-only clients", () => {
    const values = {
      monitoredTechnologies: ["one", "two", "three", "four", "five", "six"],
      mappingTerms: ["one", "two", "three"],
    };
    expect(clientProfileScopeLimitErrors({ clientTypes: ["IR"], ...values })).toHaveLength(2);
    expect(clientProfileScopeLimitErrors({ clientTypes: ["TI"], ...values })).toEqual([]);
  });
});
