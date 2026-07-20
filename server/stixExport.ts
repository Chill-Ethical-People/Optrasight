import { randomUUID } from "crypto";
import type { FindingIoCs, OsintFindingDTO } from "../shared/schema";

const TLP_CLEAR_ID = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487";

type StixObject = Record<string, unknown> & { type: string; id: string };

export interface StixExportResult {
  bundle: { type: "bundle"; id: string; objects: StixObject[] };
  findingCount: number;
  indicatorCount: number;
  attackPatternCount: number;
  objectCounts: Record<string, number>;
  warnings: string[];
  errors: string[];
  valid: boolean;
}

function stixId(type: string): string {
  return `${type}--${randomUUID()}`;
}

function iso(value: string | null | undefined): string {
  const parsed = value ? new Date(value) : new Date();
  return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

function escapePatternValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function indicatorPattern(kind: keyof FindingIoCs, value: string): string | null {
  const escaped = escapePatternValue(value);
  const patterns: Partial<Record<keyof FindingIoCs, string>> = {
    ipv4: `[ipv4-addr:value = '${escaped}']`,
    ipv6: `[ipv6-addr:value = '${escaped}']`,
    domain: `[domain-name:value = '${escaped}']`,
    url: `[url:value = '${escaped}']`,
    email: `[email-addr:value = '${escaped}']`,
    md5: `[file:hashes.MD5 = '${escaped}']`,
    sha1: `[file:hashes.'SHA-1' = '${escaped}']`,
    sha256: `[file:hashes.'SHA-256' = '${escaped}']`,
    btc: `[x-optrasight-crypto-address:value = '${escaped}']`,
  };
  return patterns[kind] ?? null;
}

function marked(object: StixObject): StixObject {
  return { ...object, object_marking_refs: [TLP_CLEAR_ID] };
}

export function buildOsintStixBundle(findings: OsintFindingDTO[], producerName = "OptraSight"): StixExportResult {
  const generatedAt = new Date().toISOString();
  const producerId = stixId("identity");
  const objects: StixObject[] = [
    marked({
      type: "identity",
      spec_version: "2.1",
      id: producerId,
      created: generatedAt,
      modified: generatedAt,
      name: producerName,
      identity_class: "organization",
    }),
  ];
  let indicatorCount = 0;
  let attackPatternCount = 0;
  const warnings: string[] = [];

  for (const finding of findings) {
    const created = iso(finding.createdAt);
    const published = iso(finding.publishedAt);
    const reportRefs: string[] = [producerId];

    for (const [kind, values] of Object.entries(finding.iocs || {}) as Array<[keyof FindingIoCs, string[]]>) {
      for (const value of Array.isArray(values) ? values : []) {
        const pattern = indicatorPattern(kind, String(value));
        if (!pattern) continue;
        const indicator = marked({
          type: "indicator",
          spec_version: "2.1",
          id: stixId("indicator"),
          created_by_ref: producerId,
          created,
          modified: generatedAt,
          name: `${kind.toUpperCase()} indicator from ${finding.sourceName}`,
          description: `Extracted from ${finding.title}`,
          indicator_types: ["malicious-activity"],
          pattern,
          pattern_type: "stix",
          pattern_version: "2.1",
          valid_from: published,
          confidence: Math.max(0, Math.min(100, Number(finding.aiRelevanceScore ?? 50))),
          external_references: finding.url ? [{ source_name: finding.sourceName, url: finding.url }] : [],
        });
        objects.push(indicator);
        reportRefs.push(indicator.id);
        indicatorCount += 1;
      }
    }

    for (const technique of finding.attackTechniques || []) {
      const attackPattern = marked({
        type: "attack-pattern",
        spec_version: "2.1",
        id: stixId("attack-pattern"),
        created_by_ref: producerId,
        created,
        modified: generatedAt,
        name: technique.name || technique.id,
        external_references: [{ source_name: "mitre-attack", external_id: technique.id }],
      });
      objects.push(attackPattern);
      reportRefs.push(attackPattern.id);
      attackPatternCount += 1;
    }

    for (const cve of finding.cveIds || []) {
      const vulnerability = marked({
        type: "vulnerability",
        spec_version: "2.1",
        id: stixId("vulnerability"),
        created_by_ref: producerId,
        created,
        modified: generatedAt,
        name: cve,
        external_references: [
          { source_name: "cve", external_id: cve, url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}` },
        ],
      });
      objects.push(vulnerability);
      reportRefs.push(vulnerability.id);
    }

    const report = marked({
      type: "report",
      spec_version: "2.1",
      id: stixId("report"),
      created_by_ref: producerId,
      created,
      modified: generatedAt,
      name: finding.title,
      description: finding.analystAssessment || finding.aiSummary || finding.summary || undefined,
      report_types: ["threat-report"],
      published,
      object_refs: reportRefs,
      labels: [finding.status, finding.severity, finding.intelCategory || "unclassified"],
      confidence: Math.max(0, Math.min(100, Number(finding.aiRelevanceScore ?? 50))),
      external_references: finding.url ? [{ source_name: finding.sourceName, url: finding.url }] : [],
      x_optrasight_finding_id: finding.id,
      x_optrasight_publication_date_inferred: finding.publishedAtInferred === true,
      x_optrasight_severity: {
        publisher: finding.publisherSeverity ?? null,
        technical: finding.technicalSeverity ?? null,
        client_impact: finding.clientImpactSeverity ?? null,
        analyst_final: finding.analystFinalSeverity ?? null,
      },
    });
    objects.push(report);
    if (finding.publishedAtInferred) warnings.push(`${finding.id}: publication time was inferred from ingestion time.`);
  }

  if (findings.length > 0)
    warnings.push(
      "Public-source findings are exported with the standard TLP:CLEAR marking until finding-level handling markings are implemented.",
    );
  const errors = validateStixObjects(objects);
  const objectCounts = objects.reduce<Record<string, number>>((counts, object) => {
    counts[object.type] = (counts[object.type] || 0) + 1;
    return counts;
  }, {});
  return {
    bundle: { type: "bundle", id: stixId("bundle"), objects },
    findingCount: findings.length,
    indicatorCount,
    attackPatternCount,
    objectCounts,
    warnings,
    errors,
    valid: errors.length === 0,
  };
}

function validateStixObjects(objects: StixObject[]): string[] {
  const errors: string[] = [];
  const ids = new Set<string>();
  for (const object of objects) {
    if (!/^[a-z][a-z0-9-]*--[0-9a-f-]{36}$/i.test(object.id))
      errors.push(`${object.type}: invalid STIX id ${object.id}.`);
    if (ids.has(object.id)) errors.push(`${object.id}: duplicate object id.`);
    ids.add(object.id);
    if (object.type === "indicator" && (typeof object.pattern !== "string" || !object.pattern))
      errors.push(`${object.id}: indicator pattern is required.`);
    if (object.type === "report" && (!Array.isArray(object.object_refs) || object.object_refs.length === 0))
      errors.push(`${object.id}: report object_refs must contain at least one object.`);
  }
  for (const object of objects) {
    if (object.type !== "report") continue;
    for (const ref of object.object_refs as string[])
      if (!ids.has(ref)) errors.push(`${object.id}: unresolved object reference ${ref}.`);
  }
  return errors;
}
