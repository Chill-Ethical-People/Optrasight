import { describe, expect, it } from "vitest";

import {
  createClientIdentityBoundary,
  isExternalAiProvider,
  prepareClientDigestForProvider,
  prepareOsintAnalysisForProvider,
} from "../server/aiDataPrivacy";
import type { ClientDigestInput, OsintAnalysisInput } from "../server/aiClient";

const externalProvider = { provider: "openai" } as const;
const localProvider = { provider: "ollama" } as const;

describe("external AI client identity boundary", () => {
  it("classifies Ollama as local and hosted providers as external", () => {
    expect(isExternalAiProvider(localProvider)).toBe(false);
    expect(isExternalAiProvider(externalProvider)).toBe(true);
    expect(isExternalAiProvider({ provider: "deepseek" })).toBe(true);
  });

  it("pseudonymises OSINT client ids and names while retaining approved context", () => {
    const input: OsintAnalysisInput = {
      finding: {
        title: "Campaign affecting Acme Rail Holdings",
        summary: "Acme Rail Holdings may be affected; evil.example is a reported indicator.",
        severity: "high",
        affectedTech: ["Microsoft Exchange"],
        cveIds: ["CVE-2026-1000"],
        threatActors: ["Example actor"],
        url: "https://research.example/advisory",
        sourceContent: "Acme Rail Holdings should validate Microsoft Exchange exposure.",
      },
      clientProfile: {
        clients: [
          {
            id: "11111111-2222-4333-8444-555555555555",
            name: "Acme Rail Holdings",
            mappingTerms: [
              "Acme Rail Holdings",
              "soc@acmerail.example",
              "portal.acmerail.example",
              "Northern Freight Subsidiary",
            ],
            geographies: [{ id: "geo-hk", label: "Hong Kong", aliases: ["HK"] }],
            industries: [{ id: "industry-transport", label: "Transportation" }],
            technologies: [{ id: "tech-exchange", label: "Microsoft Exchange" }],
          },
        ],
      },
    };

    const privacy = prepareOsintAnalysisForProvider(input, externalProvider);
    const serialised = JSON.stringify(privacy.input);
    expect(privacy.external).toBe(true);
    expect(serialised).not.toContain("Acme Rail Holdings");
    expect(serialised).not.toContain("11111111-2222-4333-8444-555555555555");
    expect(serialised).not.toContain("soc@acmerail.example");
    expect(serialised).not.toContain("portal.acmerail.example");
    expect(privacy.input.clientProfile.clients[0]).toMatchObject({
      id: "CLIENT-01",
      name: "CLIENT-01",
      mappingTerms: ["Northern Freight Subsidiary"],
    });
    expect(serialised).toContain("Hong Kong");
    expect(serialised).toContain("Transportation");
    expect(serialised).toContain("Microsoft Exchange");
    expect(serialised).toContain("evil.example");

    const restored = privacy.restoreOutput({
      summary: "CLIENT-01 should validate exposure.",
      relevanceScore: 0.8,
      recommendation: "Review telemetry.",
      clientIds: ["CLIENT-01"],
      clientMatches: [
        {
          clientId: "CLIENT-01",
          relevanceScore: 0.9,
          reason: "CLIENT-01 operates in the affected sector.",
        },
      ],
    });
    expect(restored.clientIds).toEqual(["11111111-2222-4333-8444-555555555555"]);
    expect(restored.clientMatches).toEqual([
      {
        clientId: "11111111-2222-4333-8444-555555555555",
        relevanceScore: 0.9,
        reason: "Acme Rail Holdings operates in the affected sector.",
      },
    ]);
  });

  it("keeps the original payload for an on-premises Ollama provider", () => {
    const input: OsintAnalysisInput = {
      finding: {
        title: "Acme Rail Holdings advisory",
        summary: null,
        severity: "medium",
        affectedTech: [],
        cveIds: [],
        threatActors: [],
      },
      clientProfile: {
        clients: [
          {
            id: "client-id",
            name: "Acme Rail Holdings",
            mappingTerms: ["portal.acmerail.example"],
            geographies: [],
            industries: [],
            technologies: [],
          },
        ],
      },
    };
    const privacy = prepareOsintAnalysisForProvider(input, localProvider);
    expect(privacy.external).toBe(false);
    expect(privacy.input).toBe(input);
  });

  it("pseudonymises client-email inputs and restores the real name after generation", () => {
    const input: ClientDigestInput = {
      client: {
        name: "Acme Rail Holdings",
        cadence: "weekly",
        clientTypes: ["MSS"],
        matchingScope: "managed_security",
        mappingTerms: ["Northern Freight Subsidiary", "soc@acmerail.example"],
        industries: ["Transportation"],
        geographies: ["Hong Kong"],
        technologies: ["Microsoft Exchange"],
      },
      periodStart: "2026-07-01T00:00:00.000Z",
      periodEnd: "2026-07-07T00:00:00.000Z",
      template: {
        subjectTemplate: "{{client_name}} weekly brief for Acme Rail Holdings",
        bodyTemplate: "Hello {{client_name}} Security Team,\n\n{{executive_summary}}\n\n{{sources}}",
        supportedPlaceholders: ["{{client_name}}", "{{executive_summary}}", "{{sources}}"],
      },
      findings: [
        {
          id: "finding-1",
          title: "Acme Rail Holdings exposure review",
          source: "Example source",
          url: "https://research.example/advisory",
          publishedAt: "2026-07-06T00:00:00.000Z",
          severity: "high",
          status: "triaged",
          aiSummary: "Relevant to Acme Rail Holdings.",
          analystAssessment: null,
          analystDisposition: null,
          analystImpact: null,
          analystNextAction: null,
          cveIds: [],
          threatActors: [],
          affectedTech: ["Microsoft Exchange"],
          iocCount: 0,
        },
      ],
    };

    const privacy = prepareClientDigestForProvider(input, externalProvider);
    const serialised = JSON.stringify(privacy.input);
    expect(serialised).not.toContain("Acme Rail Holdings");
    expect(serialised).not.toContain("soc@acmerail.example");
    expect(privacy.input.client.name).toBe("CLIENT-01");
    expect(privacy.input.client.mappingTerms).toEqual(["Northern Freight Subsidiary"]);
    expect(privacy.input.template.subjectTemplate).toContain("{{client_name}}");

    expect(
      privacy.restoreOutput({
        subject: "CLIENT-01 weekly threat brief",
        bodyMd: "Hello CLIENT-01 Security Team.",
        includedFindingIds: ["finding-1"],
      }),
    ).toEqual({
      subject: "Acme Rail Holdings weekly threat brief",
      bodyMd: "Hello Acme Rail Holdings Security Team.",
      includedFindingIds: ["finding-1"],
    });
  });

  it("does not corrupt the client_name placeholder when the client is literally named Client", () => {
    const boundary = createClientIdentityBoundary(externalProvider, [{ name: "Client" }]);
    expect(boundary.sanitiseText("Hello Client. Keep {{client_name}}.")).toBe("Hello CLIENT-01. Keep {{client_name}}.");
  });
});
