// v2.30.3 — Threat Actor Profile DOCX exporter.
//
// Builds a Word document matching the structure of the user's canonical
// Threat_Actor_Profile_Template.docx and the TAP-001/002/003 reference files:
//   - Header table (Profile ID, Version, TLP, Threat level, Cut-off, Prepared by, Date)
//   - 13 numbered sections + 4 appendices (IOCs, STIX 2.1, References, Version log)
//
// Pure server-side generation with the `docx` library. The route returns the
// .docx as `Content-Disposition: attachment` with a filename derived from
// profileId + primary name.

import {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, ShadingType,
} from "docx";
import type { ThreatActorFullDTO } from "@shared/schema";

// ----- helpers --------------------------------------------------------------

const COLOR_HEADING = "1F2A44"; // dark slate
const COLOR_LABEL = "5B6478";   // muted slate
const COLOR_DANGER = "B91C1C";  // crimson
const COLOR_TABLE_HEADER = "F1F5F9"; // light slate fill

function h1(text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 160 },
    children: [new TextRun({ text, bold: true, size: 32, color: COLOR_HEADING })],
  });
}

function h3(text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 160, after: 80 },
    children: [new TextRun({ text, bold: true, size: 22, color: COLOR_HEADING })],
  });
}

function p(text: string, opts: { bold?: boolean; italic?: boolean; color?: string } = {}): Paragraph {
  return new Paragraph({
    spacing: { after: 80 },
    children: [new TextRun({ text, bold: opts.bold, italics: opts.italic, color: opts.color, size: 20 })],
  });
}

function bullets(items: string[]): Paragraph[] {
  if (!items.length) return [p("—", { italic: true, color: COLOR_LABEL })];
  return items.map((t) =>
    new Paragraph({
      bullet: { level: 0 },
      spacing: { after: 40 },
      children: [new TextRun({ text: t, size: 20 })],
    }),
  );
}

function emptyOrItalic(text: string | null | undefined, fallback = "Not yet populated."): Paragraph {
  if (text && text.trim()) return p(text);
  return p(fallback, { italic: true, color: COLOR_LABEL });
}

function safeArr<T>(x: T[] | undefined | null): T[] { return Array.isArray(x) ? x : []; }
function safeObj(x: any): Record<string, any> { return (x && typeof x === "object") ? x : {}; }
function safeStr(x: any): string { return typeof x === "string" ? x : (x == null ? "" : String(x)); }

function joinOrDash(arr: string[]): string {
  return arr.length ? arr.join(", ") : "—";
}

// 2-column key/value table for "labelled facts" blocks.
function kvTable(rows: Array<[string, string]>): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: rows.map(([k, v]) => new TableRow({
      children: [
        new TableCell({
          width: { size: 30, type: WidthType.PERCENTAGE },
          shading: { type: ShadingType.CLEAR, color: "auto", fill: COLOR_TABLE_HEADER },
          children: [new Paragraph({ children: [new TextRun({ text: k.toUpperCase(), bold: true, size: 16, color: COLOR_LABEL })] })],
        }),
        new TableCell({
          width: { size: 70, type: WidthType.PERCENTAGE },
          children: [new Paragraph({ children: [new TextRun({ text: v || "—", size: 20 })] })],
        }),
      ],
    })),
  });
}

// ----- document assembly ----------------------------------------------------

export async function buildThreatActorDocx(full: ThreatActorFullDTO): Promise<Buffer> {
  const today = new Date().toISOString().slice(0, 10);
  const titleLine = `${full.profileId} — ${full.primaryName}`;

  const headerTable = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      ["Profile ID", full.profileId, "Version", `v${full.version}`],
      ["TLP", full.tlp, "Threat level", full.threatLevel],
      ["Admiralty", `${full.admiraltySource} / ${full.admiraltyInfo}`, "WEP", full.wepConfidence],
      ["Cut-off", full.cutoffDate ?? "—", "Prepared by", full.preparedBy ?? full.createdBy],
      ["Status", full.status, "Generated", today],
    ].map((r) => new TableRow({
      children: r.map((cell, i) => new TableCell({
        width: { size: 25, type: WidthType.PERCENTAGE },
        shading: i % 2 === 0 ? { type: ShadingType.CLEAR, color: "auto", fill: COLOR_TABLE_HEADER } : undefined,
        children: [new Paragraph({ children: [new TextRun({ text: safeStr(cell), bold: i % 2 === 0, size: i % 2 === 0 ? 16 : 20, color: i % 2 === 0 ? COLOR_LABEL : undefined })] })],
      })),
    })),
  });

  const children: (Paragraph | Table)[] = [];

  // Title block
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 80 },
    children: [new TextRun({ text: "THREAT ACTOR PROFILE", bold: true, size: 22, color: COLOR_LABEL })],
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 120 },
    children: [new TextRun({ text: titleLine, bold: true, size: 40, color: COLOR_HEADING })],
  }));
  if (full.aliases.length) {
    children.push(new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 240 },
      children: [new TextRun({ text: `Also known as: ${full.aliases.join(", ")}`, italics: true, size: 20, color: COLOR_LABEL })],
    }));
  }

  children.push(headerTable);
  children.push(p(" "));

  // ----- 1. Executive Summary ----------------------------------------------
  children.push(h1("1. Executive Summary"));
  children.push(h3("What"));
  children.push(emptyOrItalic(full.execWhat));
  children.push(h3("So what"));
  children.push(emptyOrItalic(full.execSoWhat));
  children.push(h3("What now"));
  children.push(emptyOrItalic(full.execWhatNow));
  children.push(h3("Threat level rationale"));
  children.push(emptyOrItalic(full.threatLevelRationale));
  children.push(kvTable([
    ["Threat level", full.threatLevel],
    ["Sector actively targeted", full.sectorActivelyTargeted ? "Yes" : "No"],
    ["Intent proximity", full.intentProximity],
    ["Relevance rating", full.relevanceRating ?? "—"],
  ]));

  // ----- 2. Identity --------------------------------------------------------
  children.push(h1("2. Identity"));
  children.push(kvTable([
    ["Primary name", full.primaryName],
    ["MITRE Group", full.mitreGroupId ?? "—"],
    ["Active since", full.activeSince ? String(full.activeSince) : "—"],
    ["Actor type", full.actorType],
    ["Sponsorship", full.sponsorship],
    ["Sophistication", full.sophistication],
    ["Assessed origin", full.assessedOrigin ?? "—"],
    ["Origin confidence", full.originConfidence ?? "—"],
    ["Sponsoring entity", full.sponsoringEntity ?? "—"],
  ]));
  children.push(h3("Aliases"));
  children.push(...bullets(full.aliases));
  const vendorRows = Object.entries(safeObj(full.vendorNames));
  if (vendorRows.length) {
    children.push(h3("Vendor naming"));
    for (const [vendor, names] of vendorRows) {
      children.push(p(`${vendor}: ${safeArr<string>(names as any).join(", ")}`));
    }
  }
  children.push(h3("Motivation"));
  children.push(p(joinOrDash(full.motivation)));

  // ----- 3. Victimology -----------------------------------------------------
  children.push(h1("3. Victimology"));
  children.push(kvTable([
    ["Target sectors", joinOrDash(full.targetSectors)],
    ["Target regions", joinOrDash(full.targetRegions)],
    ["Target tech stack", joinOrDash(full.targetTechStack)],
    ["Org-size preference", full.orgSizePreference ?? "—"],
  ]));

  // ----- 4. Capability ------------------------------------------------------
  children.push(h1("4. Capability"));
  const cap = safeObj(full.capabilityProfile);
  const capSummary = safeStr(cap.summary || cap.overview || cap.assessment);
  children.push(emptyOrItalic(capSummary));
  const capLanes = ["initialAccess", "execution", "persistence", "lateralMovement", "exfiltration", "impact"];
  const capLanesPresent = capLanes.filter((k) => cap[k]);
  if (capLanesPresent.length) {
    children.push(kvTable(capLanesPresent.map((k) => [k.replace(/([A-Z])/g, " $1").trim(), safeStr(cap[k])])));
  }
  children.push(h3("Tools / malware"));
  if (full.tools.length) {
    children.push(...full.tools.map((t) => {
      const meta = [t.category, t.purpose].filter(Boolean).join(" · ");
      const variants = t.variants && t.variants.length ? ` (variants: ${t.variants.join(", ")})` : "";
      return new Paragraph({
        bullet: { level: 0 },
        spacing: { after: 40 },
        children: [
          new TextRun({ text: t.name, bold: true, size: 20 }),
          ...(meta ? [new TextRun({ text: ` — ${meta}`, size: 20, color: COLOR_LABEL })] : []),
          ...(variants ? [new TextRun({ text: variants, size: 18, color: COLOR_LABEL })] : []),
        ],
      });
    }));
  } else {
    children.push(p("No tools listed.", { italic: true, color: COLOR_LABEL }));
  }

  // ----- 5. TTPs ------------------------------------------------------------
  children.push(h1("5. TTPs (MITRE ATT&CK)"));
  if (full.ttps.length) {
    const ttpRows: TableRow[] = [
      new TableRow({
        children: ["Tactic", "Technique ID", "Technique", "Status", "Notes"].map((h) =>
          new TableCell({
            shading: { type: ShadingType.CLEAR, color: "auto", fill: COLOR_TABLE_HEADER },
            children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, size: 16, color: COLOR_LABEL })] })],
          })),
      }),
      ...full.ttps.map((t) => new TableRow({
        children: [t.tactic ?? "—", t.techniqueId, t.techniqueName ?? "—", t.status, t.evidence ?? ""].map((c) =>
          new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: safeStr(c), size: 18 })] })] }),
        ),
      })),
    ];
    children.push(new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: ttpRows }));
  } else {
    children.push(p("No TTPs catalogued yet.", { italic: true, color: COLOR_LABEL }));
  }

  // ----- 6. Diamond Model ---------------------------------------------------
  children.push(h1("6. Diamond Model"));
  const diamondCorners: Array<[string, Record<string, any>]> = [
    ["Adversary", safeObj(full.diamondAdversary)],
    ["Capability", safeObj(full.diamondCapability)],
    ["Infrastructure", safeObj(full.diamondInfrastructure)],
    ["Victim", safeObj(full.diamondVictim)],
  ];
  for (const [name, val] of diamondCorners) {
    children.push(h3(name));
    const entries = Object.entries(val);
    if (entries.length === 0) {
      children.push(p("Not populated.", { italic: true, color: COLOR_LABEL }));
    } else {
      children.push(kvTable(entries.map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : safeStr(v)])));
    }
  }

  // ----- 7. Campaigns -------------------------------------------------------
  children.push(h1("7. Campaigns"));
  if (full.campaigns.length) {
    for (const c of full.campaigns) {
      children.push(h3(c.name));
      children.push(kvTable([
        ["Period", c.period ?? "—"],
        ["Target sector", c.targetSector ?? "—"],
        ["Target geography", c.targetGeography ?? "—"],
        ["Initial access", c.initialAccess ?? "—"],
        ["Outcome", c.outcome ?? "—"],
      ]));
      if (c.sourceUrl) children.push(p(`Source: ${c.sourceUrl}`, { italic: true, color: COLOR_LABEL }));
    }
  } else {
    children.push(p("No campaigns logged.", { italic: true, color: COLOR_LABEL }));
  }

  // ----- 8. Infrastructure --------------------------------------------------
  children.push(h1("8. Infrastructure"));
  const infra = safeObj(full.infrastructureProfile);
  const infraSummary = safeStr(infra.summary || infra.overview);
  children.push(emptyOrItalic(infraSummary, "Infrastructure profile not populated."));
  const infraLanes = ["c2", "domains", "asn", "hosting", "lolbins", "operationalTradecraft"];
  const infraPresent = infraLanes.filter((k) => infra[k]);
  if (infraPresent.length) {
    children.push(kvTable(infraPresent.map((k) => {
      const v = infra[k];
      return [k.toUpperCase(), Array.isArray(v) ? v.join(", ") : safeStr(v)];
    })));
  }

  // ----- 9. Detection -------------------------------------------------------
  children.push(h1("9. Detection (linked rules)"));
  if (full.ruleLinks.length) {
    for (const rl of full.ruleLinks) {
      children.push(new Paragraph({
        bullet: { level: 0 },
        spacing: { after: 40 },
        children: [
          new TextRun({ text: `[${rl.priority}] `, bold: true, size: 20, color: COLOR_DANGER }),
          new TextRun({ text: safeStr(rl.ruleTitle || rl.ruleId), size: 20 }),
          ...(rl.notes ? [new TextRun({ text: ` — ${rl.notes}`, size: 20, color: COLOR_LABEL })] : []),
        ],
      }));
    }
  } else {
    children.push(p("No detection rules linked.", { italic: true, color: COLOR_LABEL }));
  }

  // ----- 10. IR Actions -----------------------------------------------------
  children.push(h1("10. Incident-Response Actions"));
  const ir = safeObj(full.irActions);
  const irGroups = ["immediate", "shortTerm", "longTerm", "containment", "eradication", "recovery"];
  const irPresent = irGroups.filter((k) => Array.isArray(ir[k]) ? ir[k].length : ir[k]);
  if (irPresent.length === 0) {
    children.push(p("Not populated.", { italic: true, color: COLOR_LABEL }));
  } else {
    for (const g of irPresent) {
      children.push(h3(g.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase())));
      const v = ir[g];
      if (Array.isArray(v)) children.push(...bullets(v.map(safeStr)));
      else children.push(p(safeStr(v)));
    }
  }

  // ----- 11. Countermeasures ------------------------------------------------
  children.push(h1("11. Countermeasures"));
  const cm = safeObj(full.countermeasures);
  const cmGroups = ["preventive", "detective", "corrective", "hardening", "controls"];
  const cmPresent = cmGroups.filter((k) => Array.isArray(cm[k]) ? cm[k].length : cm[k]);
  if (cmPresent.length === 0) {
    children.push(p("Not populated.", { italic: true, color: COLOR_LABEL }));
  } else {
    for (const g of cmPresent) {
      children.push(h3(g.replace(/^./, (c) => c.toUpperCase())));
      const v = cm[g];
      if (Array.isArray(v)) children.push(...bullets(v.map(safeStr)));
      else children.push(p(safeStr(v)));
    }
  }

  // ----- 12. Forecast -------------------------------------------------------
  children.push(h1("12. Forecast"));
  children.push(emptyOrItalic(full.forecast));
  const ext = safeObj(full.extortionTactics);
  if (Object.keys(ext).length) {
    children.push(h3("Extortion tactics"));
    children.push(kvTable(Object.entries(ext).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : safeStr(v)])));
  }
  const bi = safeObj(full.businessImpact);
  if (Object.keys(bi).length) {
    children.push(h3("Business impact"));
    children.push(kvTable(Object.entries(bi).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : safeStr(v)])));
  }

  // ----- 13. Confidence / Sources ------------------------------------------
  children.push(h1("13. Confidence & Sources"));
  children.push(kvTable([
    ["TLP", full.tlp],
    ["Admiralty (source / info)", `${full.admiraltySource} / ${full.admiraltyInfo}`],
    ["WEP confidence", full.wepConfidence],
    ["Origin confidence", full.originConfidence ?? "—"],
    ["Sophistication", full.sophistication],
    ["Sponsorship", full.sponsorship],
    ["AI provider", full.aiProviderLabel ?? "—"],
  ]));

  // ----- Appendix A — IOCs --------------------------------------------------
  children.push(h1("Appendix A — IOCs"));
  if (full.iocs.length) {
    const iocRows: TableRow[] = [
      new TableRow({
        children: ["Type", "Value", "First seen", "Last seen", "Confidence", "TLP"].map((h) =>
          new TableCell({
            shading: { type: ShadingType.CLEAR, color: "auto", fill: COLOR_TABLE_HEADER },
            children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, size: 16, color: COLOR_LABEL })] })],
          })),
      }),
      ...full.iocs.map((i) => new TableRow({
        children: [i.iocType, i.value, i.firstSeen ?? "—", i.lastConfirmed ?? "—", safeStr(i.confidence ?? "—"), i.tlp].map((c) =>
          new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: safeStr(c), size: 16 })] })] }),
        ),
      })),
    ];
    children.push(new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: iocRows }));
  } else {
    children.push(p("No IOCs catalogued.", { italic: true, color: COLOR_LABEL }));
  }

  // ----- Appendix B — STIX 2.1 reference -----------------------------------
  children.push(h1("Appendix B — STIX 2.1"));
  children.push(p("A live STIX 2.1 bundle for this profile is downloadable from the OptraSight console (Threat Actors → STIX tab). The bundle includes the threat-actor SDO, related malware/tools, indicators, intrusion-sets and attack-pattern references where catalogued.", { italic: true, color: COLOR_LABEL }));

  // ----- Appendix C — References -------------------------------------------
  children.push(h1("Appendix C — References"));
  if (full.references.length) {
    for (const r of full.references) {
      children.push(new Paragraph({
        spacing: { after: 60 },
        children: [
          new TextRun({ text: `[${r.refNum}] `, bold: true, size: 20 }),
          new TextRun({ text: r.title, size: 20 }),
          ...(r.sourceType ? [new TextRun({ text: ` (${r.sourceType})`, size: 20, color: COLOR_LABEL })] : []),
          ...(r.date ? [new TextRun({ text: ` — ${r.date}`, size: 20, color: COLOR_LABEL })] : []),
          ...(r.url ? [new TextRun({ text: ` — ${r.url}`, size: 18, color: COLOR_LABEL })] : []),
        ],
      }));
    }
  } else {
    children.push(p("No references catalogued.", { italic: true, color: COLOR_LABEL }));
  }

  // ----- Appendix D — Version log ------------------------------------------
  children.push(h1("Appendix D — Version log"));
  children.push(kvTable([
    ["Profile ID", full.profileId],
    ["Version", `v${full.version}`],
    ["Status", full.status],
    ["Created", full.createdAt],
    ["Updated", full.updatedAt],
    ["Created by", full.createdBy],
    ["Prepared by", full.preparedBy ?? "—"],
    ["AI provider", full.aiProviderLabel ?? "—"],
  ]));

  const doc = new Document({
    creator: "OptraSight",
    title: titleLine,
    description: "Threat Actor Profile (TAP) export",
    styles: {
      default: {
        document: {
          run: { font: "Calibri" },
        },
      },
    },
    sections: [{
      properties: {
        page: {
          margin: { top: 720, bottom: 720, left: 720, right: 720 }, // 0.5" margins
        },
      },
      children,
    }],
  });

  return Packer.toBuffer(doc);
}
