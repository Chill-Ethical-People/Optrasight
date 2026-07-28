// Threat Actor Profile DOCX exporter.
//
// The document has two reading layers:
//   1. a concise decision briefing for executives and CIRT leads; and
//   2. the complete analyst dossier, including ATT&CK coverage, Diamond Model,
//      campaigns, indicators, references, and version metadata.

// Keep the exporter derived from structured profile fields. bodyMd is retained
// as the canonical narrative but is not parsed here because doing so would make
// the Word output depend on fragile Markdown layout conventions.

import {
  AlignmentType,
  BorderStyle,
  Document,
  ExternalHyperlink,
  Footer,
  Header,
  HeightRule,
  HeadingLevel,
  HorizontalPositionRelativeFrom,
  ImageRun,
  PageBreak,
  PageNumber,
  Packer,
  Paragraph,
  SectionType,
  ShadingType,
  Table,
  TableCell,
  TableOfContents,
  TableRow,
  TextWrappingType,
  TextRun,
  VerticalAlign,
  VerticalPositionRelativeFrom,
  WidthType,
} from "docx";
import sharp from "sharp";
import type {
  ThreatActorFullDTO,
  ThreatActorRuleLinkDTO,
  ThreatActorTtpDTO,
} from "@shared/schema";

// Chill Ethical People dossier system. Source:
// /Users/f1h3/Documents/cep_site/Chill Ethical People/dossier.css
const NIGHT = "0E1626";
const DEPTH = "16213A";
const FOG = "EDEFE9";
const MOSS = "9DBE8D";
const MOSS_DEEP = "5C7C4C";
const SLATE = "7C8696";
const PAPER = "FCFBF7";
const PAPER_TINT = "F2F0E8";
const PAPER_CARD = "F7F5EE";
const INK = "19223A";
const MUTED = "4B5570";
const FAINT = "8A91A3";
const LINE = "D9D9D2";
const AMBER = "B07914";
const RISK = "B14635";
const SUCCESS = MOSS_DEEP;
const WHITE = "FFFFFF";
const BRAND = MOSS_DEEP;
const SIGNAL = MOSS;
const BRAND_SOFT = "EDF2E8";
const PANEL = PAPER_CARD;

// Office-safe equivalents preserve the CEP display/body/mono hierarchy even
// when the Google brand fonts are not installed on an analyst workstation.
const DISPLAY_FONT = "Arial";
const BODY_FONT = "Calibri";
const COVER_BODY_FONT = "Arial";
const MONO_FONT = "Courier New";

// Reproduces the supplied CEP capybara mark exactly: one calm line and one
// moss accent dot. It is rendered to PNG at export time for broad Word support.
function cepMarkSvg(ink: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none">
    <path d="M 26 34 C 21 36, 18 41, 18 47 C 18 53, 21 58, 27 60 C 36 63, 52 64.5, 64 63 C 74 62, 80 56, 81 47 C 81.5 41, 80 36, 76 33 C 78 27, 73 23, 68 26 C 66 27.2, 65 29, 64.5 30 C 56 27.5, 44 29, 34 32 C 31 33, 28 33.5, 26 34 Z" stroke="#${ink}" stroke-width="5.5" stroke-linejoin="round" stroke-linecap="round"/>
    <path d="M 41 39.5 Q 45.5 44 50 40" stroke="#${ink}" stroke-width="4" stroke-linecap="round"/>
    <circle cx="25" cy="44" r="2.4" fill="#${MOSS}"/>
  </svg>`;
}

async function renderCepMark(ink: string): Promise<Buffer> {
  return sharp(Buffer.from(cepMarkSvg(ink))).resize(180, 180).png().toBuffer();
}

function coverLockupSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 650 100" fill="none">
    <g transform="translate(0 5)">
      <path d="M 26 34 C 21 36, 18 41, 18 47 C 18 53, 21 58, 27 60 C 36 63, 52 64.5, 64 63 C 74 62, 80 56, 81 47 C 81.5 41, 80 36, 76 33 C 78 27, 73 23, 68 26 C 66 27.2, 65 29, 64.5 30 C 56 27.5, 44 29, 34 32 C 31 33, 28 33.5, 26 34 Z" stroke="#${FOG}" stroke-width="5.5" stroke-linejoin="round" stroke-linecap="round"/>
      <path d="M 41 39.5 Q 45.5 44 50 40" stroke="#${FOG}" stroke-width="4" stroke-linecap="round"/>
      <circle cx="25" cy="44" r="2.4" fill="#${MOSS}"/>
    </g>
    <text x="104" y="50" dominant-baseline="middle" font-family="Arial, sans-serif" font-size="26" font-weight="700" fill="#${FOG}">Chill Ethical People</text>
    <text x="410" y="50" dominant-baseline="middle" font-family="Courier New, monospace" font-size="13" letter-spacing="1.2" fill="#${SLATE}">Threat Intelligence Unit</text>
  </svg>`;
}

async function renderCoverLockup(): Promise<Buffer> {
  return sharp(Buffer.from(coverLockupSvg())).resize(1300, 200).png().toBuffer();
}

function capyMascotSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 144" fill="none">
    <g opacity="0.10">
      <path d="M 34 40 C 27.55 42.84, 23.09 44.51, 22.5 50 C 22.07 54.01, 22.05 56.99, 22.5 59 C 23.28 62.48, 26.01 64.97, 31 66 C 38.01 67.45, 45.95 69.11, 53 72.5 C 59.45 75.6, 62.72 80.97, 63.5 88 C 64.61 97.97, 64.5 108, 64.5 115 C 64.5 119.67, 66.33 122, 70 122 L 73.5 122 C 76.83 122, 78.63 120, 78.8 116 C 79.05 110, 79.2 103, 80.5 97.5 C 90 101, 120 102, 134.5 99 C 135.5 104, 135.8 110, 135.8 116 C 135.8 120, 137.7 122, 141.5 122 L 150.5 122 C 154.5 122, 156.65 120, 156.8 116 C 157.1 108, 157.2 100, 157.8 93.5 C 170 91.5, 179.83 81.99, 181 66 C 181.88 53.99, 176.07 43.79, 164 40 C 142.12 33.12, 111.99 30.4, 92 33.5 C 89.5 33.89, 87.5 34.4, 86 35 C 88.5 26.5, 81.05 21.07, 75.5 24.8 C 73.22 26.33, 71.8 28.6, 71.4 30.6 C 60 28.8, 45.78 31.43, 39 35.6 C 36.31 37.26, 35.57 39.31, 34 40 Z" stroke="#${FOG}" stroke-width="7" stroke-linejoin="round" stroke-linecap="round"/>
      <path d="M 46 44.5 C 49.33 47.5, 52.67 47.67, 56 45" stroke="#${FOG}" stroke-width="5" stroke-linecap="round"/>
      <circle cx="29.5" cy="48.5" r="3" fill="#${MOSS}"/>
    </g>
  </svg>`;
}

async function renderCapyMascot(): Promise<Buffer> {
  return sharp(Buffer.from(capyMascotSvg())).resize(800, 576).png().toBuffer();
}

function diamondDiagramSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 420 320" fill="none">
    <path d="M210 24 L382 160 L210 296 L38 160 Z" fill="#${PAPER_TINT}" stroke="#${MOSS_DEEP}" stroke-width="5"/>
    <path d="M210 24 L210 160 L38 160 Z" fill="#EBF2E7"/>
    <path d="M210 24 L382 160 L210 160 Z" fill="#FBF1DE"/>
    <path d="M38 160 L210 160 L210 296 Z" fill="#EEF0F3"/>
    <path d="M382 160 L210 160 L210 296 Z" fill="#F8EAE7"/>
    <path d="M210 24 L382 160 L210 296 L38 160 Z M210 24 V296 M38 160 H382" stroke="#${MOSS_DEEP}" stroke-width="4"/>
    <circle cx="210" cy="160" r="28" fill="#${NIGHT}" stroke="#${MOSS}" stroke-width="5"/>
    <circle cx="210" cy="24" r="11" fill="#${MOSS_DEEP}"/>
    <circle cx="382" cy="160" r="11" fill="#${AMBER}"/>
    <circle cx="210" cy="296" r="11" fill="#${MOSS}"/>
    <circle cx="38" cy="160" r="11" fill="#${SLATE}"/>
    <text x="210" y="166" text-anchor="middle" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="#${FOG}">Event</text>
  </svg>`;
}

async function renderDiamondDiagram(): Promise<Buffer> {
  return sharp(Buffer.from(diamondDiagramSvg())).resize(630, 480).png().toBuffer();
}

function markRun(data: Buffer, size: number, description: string): ImageRun {
  return new ImageRun({
    type: "png",
    data,
    transformation: { width: size, height: size },
    altText: { title: "Chill Ethical People", description, name: "CEP capybara mark" },
  });
}

type Block = Paragraph | Table | TableOfContents;

function safeArr<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function safeObj(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function safeStr(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(safeStr).filter(Boolean).join(", ");
  return Object.entries(safeObj(value))
    .map(([key, item]) => `${prettyKey(key)}: ${safeStr(item)}`)
    .filter((item) => !item.endsWith(": "))
    .join("; ");
}

function prettyKey(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/^./, (char) => char.toUpperCase());
}

function display(value: unknown, fallback = "Not assessed"): string {
  const text = safeStr(value).trim();
  return text || fallback;
}

function displayCategory(value: unknown, fallback = "Not assessed"): string {
  const text = display(value, fallback);
  if (!/^[A-Z][A-Z0-9 _-]+$/.test(text)) return text;
  const normalized = text.toLowerCase().replace(/[_-]+/g, " ");
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function para(
  text: string,
  options: { bold?: boolean; italic?: boolean; color?: string; size?: number; before?: number; after?: number } = {},
): Paragraph {
  return new Paragraph({
    spacing: { before: options.before ?? 0, after: options.after ?? 100, line: 280 },
    children: [new TextRun({
      text,
      font: BODY_FONT,
      bold: options.bold,
      italics: options.italic,
      color: options.color ?? INK,
      size: options.size ?? 19,
    })],
  });
}

function heading(text: string, level: 1 | 2 | 3 = 1, pageBreakBefore = false): Paragraph {
  const size = level === 1 ? 29 : level === 2 ? 23 : 20;
  return new Paragraph({
    heading: level === 1 ? HeadingLevel.HEADING_1 : level === 2 ? HeadingLevel.HEADING_2 : HeadingLevel.HEADING_3,
    pageBreakBefore,
    spacing: { before: level === 1 ? 320 : 210, after: 110 },
    border: level === 1 ? {
      bottom: { color: SIGNAL, size: 8, style: BorderStyle.SINGLE, space: 5 },
    } : undefined,
    children: [new TextRun({ text, font: DISPLAY_FONT, bold: true, color: level === 1 ? BRAND : INK, size })],
  });
}

function eyebrow(text: string, pageBreakBefore = false): Paragraph {
  return new Paragraph({
    pageBreakBefore,
    spacing: { before: 80, after: 60 },
    children: [new TextRun({ text, font: MONO_FONT, bold: true, color: BRAND, size: 15 })],
  });
}

function emptyParagraph(fallback = "Not yet populated."): Paragraph {
  return para(fallback, { italic: true, color: MUTED });
}

function bulletList(items: unknown[], color = INK): Paragraph[] {
  const values = items.map(safeStr).map((item) => item.trim()).filter(Boolean);
  if (!values.length) return [emptyParagraph()];
  return values.map((text) => new Paragraph({
    bullet: { level: 0 },
    spacing: { after: 55, line: 270 },
    children: [new TextRun({ text, font: BODY_FONT, color, size: 18 })],
  }));
}

function cell(
  text: string,
  options: { fill?: string; color?: string; bold?: boolean; width?: number; align?: AlignmentType } = {},
): TableCell {
  return new TableCell({
    width: options.width ? { size: options.width, type: WidthType.PERCENTAGE } : undefined,
    shading: options.fill ? { type: ShadingType.CLEAR, color: "auto", fill: options.fill } : undefined,
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 90, bottom: 90, left: 110, right: 110 },
    children: [new Paragraph({
      alignment: options.align,
      spacing: { after: 0, line: 250 },
      children: [new TextRun({
        text: text || "—",
        font: options.bold ? MONO_FONT : BODY_FONT,
        bold: options.bold,
        color: options.color ?? INK,
        size: options.bold ? 16 : 18,
      })],
    })],
  });
}

function table(rows: TableRow[], widths?: number[]): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: widths?.map((width) => width * 100),
    rows,
  });
}

function kvTable(rows: Array<[string, unknown]>): Table {
  return table(rows.map(([label, value]) => new TableRow({
    children: [
      cell(label, { fill: PANEL, color: MUTED, bold: true, width: 29 }),
      cell(display(value, "—"), { width: 71 }),
    ],
  })));
}

function headerRow(labels: string[], fills = BRAND): TableRow {
  return new TableRow({
    tableHeader: true,
    children: labels.map((label) => cell(label, { fill: fills, color: WHITE, bold: true })),
  });
}

function statusColor(value: string): string {
  const normalized = value.toLowerCase();
  if (/critical|high|p1|confirmed|targeted/.test(normalized)) return RISK;
  if (/moderate|medium|p2|suspected|sector/.test(normalized)) return AMBER;
  if (/low|p4|deployed|approved/.test(normalized)) return SUCCESS;
  return BRAND;
}

function techniqueId(ttp: ThreatActorTtpDTO): string {
  return (ttp.subTechniqueId || ttp.techniqueId).trim().toUpperCase();
}

function linkedTechniqueIds(link: ThreatActorRuleLinkDTO): string[] {
  return safeArr(link.ruleMitreTechniques)
    .map((item) => String(item.id || "").trim().toUpperCase())
    .filter(Boolean);
}

function ruleCoversTtp(link: ThreatActorRuleLinkDTO, ttp: ThreatActorTtpDTO): boolean {
  const primary = ttp.techniqueId.trim().toUpperCase();
  const sub = (ttp.subTechniqueId || "").trim().toUpperCase();
  return linkedTechniqueIds(link).some((id) => id === primary || (!!sub && id === sub));
}

function coverageForTtp(full: ThreatActorFullDTO, ttp: ThreatActorTtpDTO): { label: string; rules: ThreatActorRuleLinkDTO[] } {
  const rules = full.ruleLinks.filter((link) => ruleCoversTtp(link, ttp));
  if (!rules.length) return { label: "Gap — no linked rule", rules };
  const statuses = rules.map((rule) => String(rule.ruleStatus || "").toLowerCase());
  if (statuses.some((status) => /deploy|validat/.test(status))) return { label: "Operational", rules };
  if (statuses.some((status) => /review|approved/.test(status))) return { label: "Reviewed", rules };
  return { label: "Draft coverage", rules };
}

function priorityRank(priority: string): number {
  return ({ P1: 1, P2: 2, P3: 3, P4: 4 } as Record<string, number>)[priority] ?? 9;
}

function renderObject(value: unknown): Block[] {
  const entries = Object.entries(safeObj(value)).filter(([, item]) => safeStr(item).trim());
  if (!entries.length) return [emptyParagraph()];
  return [kvTable(entries.map(([key, item]) => [prettyKey(key), item]))];
}

function diamondTextBox(title: string, value: unknown, fill: string, columnSpan: number): TableCell {
  const summary = display(value);
  return new TableCell({
    columnSpan,
    shading: { type: ShadingType.CLEAR, color: "auto", fill },
    verticalAlign: VerticalAlign.CENTER,
    borders: {
      top: { color: LINE, size: 8, style: BorderStyle.SINGLE },
      bottom: { color: LINE, size: 8, style: BorderStyle.SINGLE },
      left: { color: LINE, size: 8, style: BorderStyle.SINGLE },
      right: { color: LINE, size: 8, style: BorderStyle.SINGLE },
    },
    margins: { top: 130, bottom: 130, left: 130, right: 130 },
    children: [
      new Paragraph({
        alignment: AlignmentType.LEFT,
        spacing: { after: 70 },
        children: [new TextRun({ text: title, font: MONO_FONT, bold: true, color: BRAND, size: 16 })],
      }),
      new Paragraph({
        alignment: AlignmentType.LEFT,
        spacing: { after: 0, line: 245 },
        children: [new TextRun({ text: summary, font: BODY_FONT, color: INK, size: 16 })],
      }),
    ],
  });
}

function diamondBlankCell(columnSpan = 1): TableCell {
  return new TableCell({
    columnSpan,
    children: [new Paragraph("")],
    shading: { type: ShadingType.CLEAR, color: "auto", fill: PAPER },
    borders: {
      top: { style: BorderStyle.NONE },
      bottom: { style: BorderStyle.NONE },
      left: { style: BorderStyle.NONE },
      right: { style: BorderStyle.NONE },
    },
  });
}

function diamondDiagramCell(diagram: Buffer): TableCell {
  return new TableCell({
    columnSpan: 2,
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 90, bottom: 90, left: 90, right: 90 },
    borders: {
      top: { style: BorderStyle.NONE },
      bottom: { style: BorderStyle.NONE },
      left: { style: BorderStyle.NONE },
      right: { style: BorderStyle.NONE },
    },
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 0 },
      children: [new ImageRun({
        type: "png",
        data: diagram,
        transformation: { width: 175, height: 133 },
        altText: {
          title: "Diamond Model",
          description: "Four-vertex analytical relationship between adversary, capability, infrastructure, and victim",
          name: "Diamond Model diagram",
        },
      })],
    })],
  });
}

function diamondModel(full: ThreatActorFullDTO, diagram: Buffer): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: [1000, 1000, 1000, 1000, 1000, 1000],
    borders: {
      top: { style: BorderStyle.NONE },
      bottom: { style: BorderStyle.NONE },
      left: { style: BorderStyle.NONE },
      right: { style: BorderStyle.NONE },
      insideHorizontal: { style: BorderStyle.NONE },
      insideVertical: { style: BorderStyle.NONE },
    },
    rows: [
      new TableRow({ children: [
        diamondBlankCell(),
        diamondTextBox("Adversary", full.diamondAdversary, "F8EAE7", 4),
        diamondBlankCell(),
      ] }),
      new TableRow({
        children: [
          diamondTextBox("Infrastructure", full.diamondInfrastructure, "EEF0F3", 2),
          diamondDiagramCell(diagram),
          diamondTextBox("Capability", full.diamondCapability, "FBF1DE", 2),
        ],
      }),
      new TableRow({ children: [
        diamondBlankCell(),
        diamondTextBox("Victim", full.diamondVictim, "EBF2E7", 4),
        diamondBlankCell(),
      ] }),
      new TableRow({ children: [diamondTextBox("Meta-features", full.diamondMeta, PAPER_TINT, 6)] }),
    ],
  });
}

function campaignTimeline(full: ThreatActorFullDTO): Table {
  const noBorder = { style: BorderStyle.NONE } as const;
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: [2200, 7800],
    borders: {
      top: noBorder,
      bottom: noBorder,
      left: noBorder,
      right: noBorder,
      insideHorizontal: noBorder,
      insideVertical: noBorder,
    },
    rows: full.campaigns.map((campaign, index) => new TableRow({
      cantSplit: true,
      children: [
        new TableCell({
          width: { size: 22, type: WidthType.PERCENTAGE },
          verticalAlign: VerticalAlign.TOP,
          margins: { top: 130, bottom: 160, left: 0, right: 160 },
          borders: { top: noBorder, bottom: noBorder, left: noBorder, right: noBorder },
          children: [
            new Paragraph({
              alignment: AlignmentType.RIGHT,
              spacing: { after: 35 },
              children: [new TextRun({
                text: display(campaign.period, "Date not recorded"),
                font: MONO_FONT,
                color: index === 0 ? AMBER : MOSS_DEEP,
                size: 16,
              })],
            }),
            new Paragraph({
              alignment: AlignmentType.RIGHT,
              spacing: { after: 0 },
              children: [new TextRun({ text: String(index + 1).padStart(2, "0"), font: MONO_FONT, color: FAINT, size: 13 })],
            }),
          ],
        }),
        new TableCell({
          width: { size: 78, type: WidthType.PERCENTAGE },
          verticalAlign: VerticalAlign.TOP,
          margins: { top: 120, bottom: 160, left: 220, right: 80 },
          borders: {
            top: noBorder,
            bottom: noBorder,
            right: noBorder,
            left: { color: index === 0 ? AMBER : LINE, size: index === 0 ? 14 : 7, style: BorderStyle.SINGLE },
          },
          children: [
            new Paragraph({
              spacing: { after: 60 },
              children: [new TextRun({ text: campaign.name, font: DISPLAY_FONT, bold: true, color: INK, size: 21 })],
            }),
            new Paragraph({
              spacing: { after: campaign.sourceUrl ? 60 : 0, line: 260 },
              children: [new TextRun({
                text: [
                  campaign.initialAccess && `Initial access: ${campaign.initialAccess}`,
                  campaign.outcome && `Outcome: ${campaign.outcome}`,
                  campaign.targetSector && `Sector: ${campaign.targetSector}`,
                  campaign.targetGeography && `Geography: ${campaign.targetGeography}`,
                  campaign.findingIds.length && `Findings: ${campaign.findingIds.join(", ")}`,
                  campaign.ruleIds.length && `Rules: ${campaign.ruleIds.join(", ")}`,
                ].filter(Boolean).join(" · ") || "Campaign details have not been recorded.",
                font: BODY_FONT,
                color: MUTED,
                size: 17,
              })],
            }),
            ...(campaign.sourceUrl ? [new Paragraph({
              spacing: { after: 0 },
              children: [new ExternalHyperlink({
                link: campaign.sourceUrl,
                children: [new TextRun({ text: "Open source reference", font: MONO_FONT, color: MOSS_DEEP, underline: {}, size: 14 })],
              })],
            })] : []),
          ],
        }),
      ],
    })),
  });
}

function defenderActionPlan(value: unknown): Table {
  const actionObject = safeObj(value);
  const preferredOrder = ["immediate", "shortTerm", "mediumTerm", "strategic"];
  const phaseKeys = [
    ...preferredOrder.filter((key) => key in actionObject),
    ...Object.keys(actionObject).filter((key) => !preferredOrder.includes(key)),
  ];
  const phases = phaseKeys.map((key) => [key, actionObject[key]] as const).filter(([, actions]) => safeStr(actions).trim());
  const noBorder = { style: BorderStyle.NONE } as const;
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: [2200, 7800],
    borders: {
      top: noBorder,
      bottom: noBorder,
      left: noBorder,
      right: noBorder,
      insideHorizontal: noBorder,
      insideVertical: noBorder,
    },
    rows: phases.map(([phase, rawActions], index) => {
      const actions = Array.isArray(rawActions) ? rawActions.map(safeStr).filter(Boolean) : [safeStr(rawActions)];
      return new TableRow({
        cantSplit: true,
        children: [
          new TableCell({
            width: { size: 22, type: WidthType.PERCENTAGE },
            shading: { type: ShadingType.CLEAR, color: "auto", fill: index === 0 ? BRAND_SOFT : PAPER_CARD },
            verticalAlign: VerticalAlign.CENTER,
            margins: { top: 130, bottom: 130, left: 130, right: 130 },
            children: [
              new Paragraph({ spacing: { after: 45 }, children: [new TextRun({ text: String(index + 1).padStart(2, "0"), font: MONO_FONT, color: MOSS_DEEP, size: 15 })] }),
              new Paragraph({ spacing: { after: 0 }, children: [new TextRun({ text: prettyKey(phase), font: DISPLAY_FONT, bold: true, color: INK, size: 18 })] }),
            ],
          }),
          new TableCell({
            width: { size: 78, type: WidthType.PERCENTAGE },
            verticalAlign: VerticalAlign.CENTER,
            margins: { top: 110, bottom: 110, left: 180, right: 120 },
            children: actions.map((action) => new Paragraph({
              bullet: { level: 0 },
              spacing: { after: 45, line: 255 },
              children: [new TextRun({ text: action, font: BODY_FONT, color: MUTED, size: 17 })],
            })),
          }),
        ],
      });
    }),
  });
}

function briefingMetric(label: string, value: string, color = INK): TableCell {
  return new TableCell({
    shading: { type: ShadingType.CLEAR, color: "auto", fill: PANEL },
    margins: { top: 110, bottom: 110, left: 110, right: 110 },
    children: [
      new Paragraph({ spacing: { after: 45 }, children: [new TextRun({ text: label, font: MONO_FONT, bold: true, color: FAINT, size: 14 })] }),
      new Paragraph({ spacing: { after: 0 }, children: [new TextRun({ text: value, font: DISPLAY_FONT, bold: true, color, size: 22 })] }),
    ],
  });
}

function briefingBlocks(full: ThreatActorFullDTO): Block[] {
  const ttps = [...full.ttps].sort((a, b) => priorityRank(a.detectionPriority) - priorityRank(b.detectionPriority));
  const covered = ttps.filter((ttp) => coverageForTtp(full, ttp).rules.length > 0).length;
  const coverage = ttps.length ? `${covered}/${ttps.length}` : "0/0";
  const topTtps = ttps.slice(0, 8);
  const blocks: Block[] = [
    eyebrow("Decision briefing"),
    heading(`${full.primaryName} threat actor briefing`, 1),
    para("A calm, evidence-led judgement for leadership, CIRT, SOC, and detection engineering. Detailed claims and sources follow in the analyst dossier.", { color: MUTED, italic: true }),
    table([new TableRow({ children: [
      cell("Handling note", { fill: BRAND_SOFT, color: MOSS_DEEP, bold: true, width: 20 }),
      cell(`Defensive use under TLP:${full.tlp}. Validate time-sensitive indicators and analyst judgements before operational action or external distribution.`, { fill: BRAND_SOFT, width: 80 }),
    ] })], [20, 80]),
    table([new TableRow({ children: [
      briefingMetric("Threat", displayCategory(full.threatLevel), statusColor(full.threatLevel)),
      briefingMetric("Confidence", displayCategory(full.wepConfidence), BRAND),
      briefingMetric("Priority TTP coverage", coverage, covered === ttps.length && ttps.length ? SUCCESS : AMBER),
      briefingMetric("Cut-off", full.cutoffDate ?? "Not set", MUTED),
    ] })], [25, 25, 25, 25]),
    heading("Key judgements", 2),
    table([
      new TableRow({ children: [cell("What", { fill: MOSS_DEEP, color: WHITE, bold: true, width: 18 }), cell(display(full.execWhat), { width: 82 })] }),
      new TableRow({ children: [cell("So what", { fill: AMBER, color: WHITE, bold: true, width: 18 }), cell(display(full.execSoWhat), { width: 82 })] }),
      new TableRow({ children: [cell("What now", { fill: MOSS, color: NIGHT, bold: true, width: 18 }), cell(display(full.execWhatNow), { width: 82 })] }),
    ]),
    heading("Profile snapshot", 2),
    kvTable([
      ["Identity", [full.primaryName, full.mitreGroupId].filter(Boolean).join(" · ")],
      ["Aliases", safeArr(full.aliases).join(", ")],
      ["Actor model", `${full.actorType} · ${full.sponsorship} · ${full.sophistication}`],
      ["Motivation", safeArr(full.motivation).join(", ")],
      ["Primary targeting", [...safeArr(full.targetSectors), ...safeArr(full.targetRegions)].join(" · ")],
      ["Technology exposure", safeArr(full.targetTechStack).join(", ")],
    ]),
    heading("Priority ATT&CK behaviours", 2),
  ];

  if (topTtps.length) {
    blocks.push(table([
      headerRow(["Priority", "Technique", "Observed behaviour", "Detection coverage"]),
      ...topTtps.map((ttp) => {
        const coverageState = coverageForTtp(full, ttp);
        return new TableRow({ children: [
          cell(ttp.detectionPriority, { color: statusColor(ttp.detectionPriority), bold: true }),
          cell(`${techniqueId(ttp)} · ${ttp.techniqueName}`),
          cell(display(ttp.evidence, ttp.status)),
          cell(coverageState.label, { color: coverageState.rules.length ? SUCCESS : RISK }),
        ] });
      }),
    ]));
  } else {
    blocks.push(emptyParagraph("No ATT&CK behaviours have been mapped."));
  }

  if (full.relevantTenants.length) {
    blocks.push(heading("Client relevance", 2));
    blocks.push(table([
      headerRow(["Client", "Relevance", "Analytical rationale"]),
      ...full.relevantTenants.map((tenant) => new TableRow({ children: [
        cell(tenant.tenantName || tenant.tenantId),
        cell(prettyKey(tenant.relevance), { color: statusColor(tenant.relevance), bold: true }),
        cell(display(tenant.rationale)),
      ] })),
    ]));
  }

  blocks.push(heading("Confidence statement", 2));
  blocks.push(para(
    `${full.wepConfidence} overall confidence using Admiralty ${full.admiraltySource}/${full.admiraltyInfo}. `
      + `Origin confidence: ${full.originConfidence ?? "not assessed"}. Intelligence cut-off: ${full.cutoffDate ?? "not recorded"}.`,
  ));
  return blocks;
}

function fullProfileBlocks(full: ThreatActorFullDTO, diamondDiagram: Buffer): Block[] {
  const blocks: Block[] = [
    eyebrow("Analyst dossier", true),
    heading("Contents", 1),
    new TableOfContents("Threat actor profile contents", { hyperlink: true, headingStyleRange: "1-3" }),

    heading("1. Executive Summary", 1),
    heading("What", 2),
    para(display(full.execWhat)),
    heading("So what", 2),
    para(display(full.execSoWhat)),
    heading("What now", 2),
    para(display(full.execWhatNow)),
    heading("Threat assessment", 2),
    kvTable([
      ["Threat level", full.threatLevel],
      ["Rationale", full.threatLevelRationale],
      ["Sector actively targeted", full.sectorActivelyTargeted ? "Yes" : "No"],
      ["Intent proximity", full.intentProximity],
      ["Relevance", full.relevanceRating],
    ]),

    heading("2. Identity & Attribution", 1),
    kvTable([
      ["Primary name", full.primaryName],
      ["MITRE group", full.mitreGroupId],
      ["Actor type", full.actorType],
      ["Sponsorship", full.sponsorship],
      ["Assessed origin", full.assessedOrigin],
      ["Origin confidence", full.originConfidence],
      ["Sponsoring entity", full.sponsoringEntity],
      ["Active since", full.activeSince],
      ["Sophistication", full.sophistication],
      ["Motivation", full.motivation],
    ]),
    heading("Aliases", 2),
    ...bulletList(full.aliases),
    heading("Vendor naming", 2),
    ...renderObject(full.vendorNames),

    heading("3. Victimology & Targeting", 1),
    kvTable([
      ["Target sectors", full.targetSectors],
      ["Target regions", full.targetRegions],
      ["Target technologies", full.targetTechStack],
      ["Organisation size", full.orgSizePreference],
      ["Intent proximity", full.intentProximity],
    ]),
    heading("Business impact", 2),
    ...renderObject(full.businessImpact),
  ];

  blocks.push(heading("4. Capability & Resources", 1));
  blocks.push(...renderObject(full.capabilityProfile));
  blocks.push(heading("Tools and malware", 2));
  if (full.tools.length) {
    blocks.push(table([
      headerRow(["Tool / malware", "Category", "Operational purpose", "Confidence"]),
      ...full.tools.map((tool) => new TableRow({ children: [
        cell([tool.name, safeArr(tool.variants).join(", ")].filter(Boolean).join(" · ")),
        cell(display(tool.category, "—")),
        cell(display(tool.purpose, "—")),
        cell(tool.confidence, { color: statusColor(tool.confidence) }),
      ] })),
    ]));
  } else {
    blocks.push(emptyParagraph("No tools or malware have been catalogued."));
  }

  blocks.push(heading("5. Modus Operandi & ATT&CK Mapping", 1));
  if (full.ttps.length) {
    blocks.push(table([
      headerRow(["Priority", "Tactic", "Technique", "Status", "Evidence", "Coverage"]),
      ...[...full.ttps]
        .sort((a, b) => priorityRank(a.detectionPriority) - priorityRank(b.detectionPriority) || a.tactic.localeCompare(b.tactic))
        .map((ttp) => {
          const coverageState = coverageForTtp(full, ttp);
          return new TableRow({ children: [
            cell(ttp.detectionPriority, { color: statusColor(ttp.detectionPriority), bold: true }),
            cell(ttp.tactic),
            cell(`${techniqueId(ttp)} · ${ttp.techniqueName}`),
            cell(prettyKey(ttp.status), { color: statusColor(ttp.status) }),
            cell(display(ttp.evidence, "Evidence not recorded")),
            cell(coverageState.label, { color: coverageState.rules.length ? SUCCESS : RISK }),
          ] });
        }),
    ]));
  } else {
    blocks.push(emptyParagraph("No ATT&CK behaviours have been catalogued."));
  }

  blocks.push(heading("6. Diamond Model", 1, true));
  blocks.push(para(
    "Read the model as an analytical relationship: the adversary applies capability through infrastructure against a victim. Meta-features record timing, directionality, phase, result, methodology, and confidence.",
    { color: MUTED, italic: true },
  ));
  blocks.push(diamondModel(full, diamondDiagram));
  blocks.push(heading("Diamond evidence detail", 2));
  for (const [label, value] of [
    ["Adversary", full.diamondAdversary],
    ["Capability", full.diamondCapability],
    ["Infrastructure", full.diamondInfrastructure],
    ["Victim", full.diamondVictim],
    ["Meta-features", full.diamondMeta],
  ] as Array<[string, unknown]>) {
    blocks.push(heading(label, 3), ...renderObject(value));
  }

  blocks.push(heading("7. Campaign & Activity Timeline", 1));
  if (full.campaigns.length) {
    blocks.push(para(
      "Campaigns are arranged as an evidence timeline. The highlighted first row is the most prominent activity in the current profile, not necessarily the newest event.",
      { color: MUTED, italic: true },
    ));
    blocks.push(campaignTimeline(full));
  } else {
    blocks.push(emptyParagraph("No campaigns have been catalogued."));
  }

  blocks.push(heading("8. Infrastructure Profile", 1));
  blocks.push(...renderObject(full.infrastructureProfile));

  blocks.push(heading("9. Detection & Threat Hunting", 1));
  const covered = full.ttps.filter((ttp) => coverageForTtp(full, ttp).rules.length > 0);
  const gaps = full.ttps.filter((ttp) => coverageForTtp(full, ttp).rules.length === 0);
  blocks.push(kvTable([
    ["Mapped ATT&CK behaviours", full.ttps.length],
    ["Behaviours with linked rules", covered.length],
    ["Coverage gaps", gaps.length],
    ["Linked detection rules", full.ruleLinks.length],
  ]));
  if (gaps.length) {
    blocks.push(heading("Priority coverage gaps", 2));
    blocks.push(...bulletList(
      gaps
        .sort((a, b) => priorityRank(a.detectionPriority) - priorityRank(b.detectionPriority))
        .map((ttp) => `${ttp.detectionPriority} · ${techniqueId(ttp)} · ${ttp.techniqueName}`),
      RISK,
    ));
  }
  blocks.push(heading("Linked detection rules", 2));
  if (full.ruleLinks.length) {
    blocks.push(table([
      headerRow(["Priority", "Rule", "Lifecycle", "ATT&CK coverage", "Notes"]),
      ...full.ruleLinks.map((link) => new TableRow({ children: [
        cell(link.priority, { color: statusColor(link.priority), bold: true }),
        cell(link.ruleTitle || link.ruleId),
        cell(display(link.ruleStatus, "Unknown")),
        cell(linkedTechniqueIds(link).join(", ") || "Not mapped"),
        cell(display(link.notes, "—")),
      ] })),
    ]));
  } else {
    blocks.push(emptyParagraph("No detection rules are linked to this actor."));
  }

  blocks.push(new Paragraph({ children: [new PageBreak()] }));
  blocks.push(heading("10. Incident Response Actions", 1));
  if (!Object.keys(safeObj(full.irActions)).length) blocks.push(emptyParagraph());
  else {
    blocks.push(para(
      "Work from immediate containment toward durable risk reduction. Adjust timing and ownership to the affected environment.",
      { color: MUTED, italic: true },
    ));
    blocks.push(defenderActionPlan(full.irActions));
  }

  blocks.push(heading("11. Defensive Countermeasures", 1));
  const countermeasures = safeObj(full.countermeasures);
  if (!Object.keys(countermeasures).length) blocks.push(emptyParagraph());
  for (const [key, value] of Object.entries(countermeasures)) {
    blocks.push(heading(prettyKey(key), 2));
    blocks.push(...(Array.isArray(value) ? bulletList(value) : [para(display(value))]));
  }

  blocks.push(heading("12. Forecast, Implications & Recommendations", 1));
  blocks.push(para(display(full.forecast)));
  if (Object.keys(safeObj(full.extortionTactics)).length) {
    blocks.push(heading("Extortion assessment", 2), ...renderObject(full.extortionTactics));
  }

  blocks.push(heading("13. Intelligence Confidence Assessment", 1));
  blocks.push(kvTable([
    ["TLP", full.tlp],
    ["Admiralty source reliability", full.admiraltySource],
    ["Admiralty information credibility", full.admiraltyInfo],
    ["Overall WEP confidence", full.wepConfidence],
    ["Origin confidence", full.originConfidence],
    ["Intelligence cut-off", full.cutoffDate],
    ["Prepared by", full.preparedBy || full.createdBy],
    ["AI provider", full.aiProviderLabel],
  ]));

  blocks.push(heading("Appendix A — IOC Register", 1));
  if (full.iocs.length) {
    blocks.push(table([
      headerRow(["Type", "Indicator", "First seen", "Last confirmed", "Confidence", "ATT&CK", "Action"]),
      ...full.iocs.map((ioc) => new TableRow({ children: [
        cell(ioc.iocType),
        cell(ioc.value),
        cell(display(ioc.firstSeen, "—")),
        cell(display(ioc.lastConfirmed, "—")),
        cell(ioc.confidence),
        cell(ioc.mitreTtps.join(", ") || "—"),
        cell(display(ioc.recommendedAction, "Validate before blocking")),
      ] })),
    ]));
  } else {
    blocks.push(emptyParagraph("No indicators have been catalogued."));
  }

  blocks.push(heading("Appendix B — STIX 2.1", 1));
  blocks.push(para(
    "The live STIX 2.1 bundle is available from the Threat Actor profile in OptraSight. It includes the actor, tools, indicators, ATT&CK relationships, and other catalogued objects.",
    { color: MUTED, italic: true },
  ));

  blocks.push(heading("Appendix C — References", 1));
  if (full.references.length) {
    for (const reference of full.references) {
      const children: Array<TextRun | ExternalHyperlink> = [
        new TextRun({ text: `[R${reference.refNum}] `, bold: true, color: BRAND, size: 18 }),
        new TextRun({ text: reference.title, size: 18 }),
        new TextRun({
          text: [reference.sourceType, reference.date].filter(Boolean).length
            ? ` · ${[reference.sourceType, reference.date].filter(Boolean).join(" · ")}`
            : "",
          color: MUTED,
          size: 17,
        }),
      ];
      if (reference.url) {
        children.push(new ExternalHyperlink({
          link: reference.url,
          children: [new TextRun({ text: " · Open source", color: BRAND, underline: {}, size: 17 })],
        }));
      }
      if (reference.archiveUrl) {
        children.push(new ExternalHyperlink({
          link: reference.archiveUrl,
          children: [new TextRun({ text: " · Archive", color: MUTED, underline: {}, size: 17 })],
        }));
      }
      blocks.push(new Paragraph({ spacing: { after: 90, line: 270 }, children }));
    }
  } else {
    blocks.push(emptyParagraph("No references have been catalogued."));
  }

  blocks.push(heading("Appendix D — Version & Audit Metadata", 1));
  blocks.push(kvTable([
    ["Profile ID", full.profileId],
    ["Version", `v${full.version}`],
    ["Status", full.status],
    ["Created", full.createdAt],
    ["Updated", full.updatedAt],
    ["Created by", full.createdBy],
    ["Prepared by", full.preparedBy],
    ["AI provider", full.aiProviderLabel],
  ]));

  return blocks;
}

function documentHeader(full: ThreatActorFullDTO, mark: Buffer): Header {
  return new Header({ children: [new Paragraph({
    border: { bottom: { color: LINE, size: 4, style: BorderStyle.SINGLE, space: 5 } },
    spacing: { after: 70 },
    children: [
      markRun(mark, 17, "CEP document header mark"),
      new TextRun({ text: "  Chill Ethical People", font: DISPLAY_FONT, bold: true, color: INK, size: 17 }),
      new TextRun({ text: `   /   ${full.profileId} · ${full.primaryName}`, font: MONO_FONT, color: FAINT, size: 14 }),
    ],
  })] });
}

function documentFooter(full: ThreatActorFullDTO): Footer {
  return new Footer({ children: [new Paragraph({
    alignment: AlignmentType.RIGHT,
    border: { top: { color: LINE, size: 4, style: BorderStyle.SINGLE, space: 4 } },
    children: [new TextRun({
      children: [`TLP:${full.tlp} · Defensive use   ·   Chill Ethical People   ·   Prepared in OptraSight   ·   `, PageNumber.CURRENT],
      font: MONO_FONT,
      color: FAINT,
      size: 12,
    })],
  })] });
}

function coverMetaCell(label: string, value: unknown): TableCell {
  return new TableCell({
    shading: { type: ShadingType.CLEAR, color: "auto", fill: DEPTH },
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 130, bottom: 130, left: 130, right: 130 },
    children: [
      new Paragraph({
        spacing: { after: 55 },
        children: [new TextRun({ text: label, font: MONO_FONT, bold: true, color: SLATE, size: 13 })],
      }),
      new Paragraph({
        spacing: { after: 0 },
        children: [new TextRun({ text: display(value, "—"), font: MONO_FONT, color: FOG, size: 17 })],
      }),
    ],
  });
}

function coverPanel(full: ThreatActorFullDTO, lockup: Buffer, mascot: Buffer, exportedAt: string): Table {
  const severityFill = statusColor(full.threatLevel);
  const children: Array<Paragraph | Table> = [
    new Paragraph({
      spacing: { after: 500 },
      children: [
        new ImageRun({
          type: "png",
          data: lockup,
          transformation: { width: 390, height: 60 },
          altText: {
            title: "Chill Ethical People",
            description: "Chill Ethical People Threat Intelligence Unit lockup",
            name: "CEP Threat Intelligence Unit lockup",
          },
        }),
        new ImageRun({
          type: "png",
          data: mascot,
          transformation: { width: 260, height: 187 },
          floating: {
            horizontalPosition: { relative: HorizontalPositionRelativeFrom.PAGE, offset: 4_900_000 },
            verticalPosition: { relative: VerticalPositionRelativeFrom.PAGE, offset: 3_380_000 },
            allowOverlap: true,
            behindDocument: false,
            lockAnchor: true,
            wrap: { type: TextWrappingType.NONE },
          },
          altText: {
            title: "Chill Ethical People capybara",
            description: "Subtle CEP capybara cover watermark",
            name: "CEP capybara watermark",
          },
        }),
      ],
    }),
    new Paragraph({
      spacing: { after: 170 },
      children: [new TextRun({
        text: `${displayCategory(full.threatLevel)} · TLP:${full.tlp}`,
        font: MONO_FONT,
        bold: true,
        color: severityFill === AMBER ? NIGHT : FOG,
        shading: { type: ShadingType.CLEAR, color: "auto", fill: severityFill },
        size: 16,
      })],
    }),
    new Paragraph({
      spacing: { after: 90 },
      children: [new TextRun({ text: full.primaryName, font: DISPLAY_FONT, bold: true, color: FOG, size: 55 })],
    }),
    new Paragraph({
      spacing: { after: 240 },
      children: [new TextRun({ text: "Threat actor briefing & profile", font: DISPLAY_FONT, bold: true, color: MOSS, size: 27 })],
    }),
    new Paragraph({
      spacing: { after: 230, line: 330 },
      children: [new TextRun({ text: display(full.execWhat), font: COVER_BODY_FONT, color: "B9C0CC", size: 22 })],
    }),
  ];

  if (full.aliases.length) {
    children.push(new Paragraph({
      spacing: { after: 260 },
      children: [
        new TextRun({ text: "Aliases  ", font: MONO_FONT, bold: true, color: SLATE, size: 13 }),
        new TextRun({ text: full.aliases.join(" · "), font: COVER_BODY_FONT, italics: true, color: FOG, size: 17 }),
      ],
    }));
  }

  children.push(table([new TableRow({ children: [
    coverMetaCell("Cut-off", full.cutoffDate),
    coverMetaCell("Reference", full.profileId),
    coverMetaCell("Version", `v${full.version}`),
    coverMetaCell("Exported", exportedAt),
  ] })], [25, 25, 25, 25]));
  children.push(new Paragraph({
    spacing: { before: 380, after: 0 },
    children: [
      new TextRun({ text: "stay calm · dig deep · share everything", font: MONO_FONT, color: MOSS, size: 14 }),
      new TextRun({ text: "     Analyst review required before external distribution", font: MONO_FONT, color: SLATE, size: 12 }),
    ],
  }));

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [new TableRow({
      height: { value: 14800, rule: HeightRule.EXACT },
      children: [new TableCell({
        shading: { type: ShadingType.CLEAR, color: "auto", fill: NIGHT },
        verticalAlign: VerticalAlign.CENTER,
        margins: { top: 650, bottom: 650, left: 650, right: 650 },
        children,
      })],
    })],
  });
}

export async function buildThreatActorDocx(full: ThreatActorFullDTO): Promise<Buffer> {
  const exportedAt = new Date().toISOString().slice(0, 10);
  const title = `${full.profileId} — ${full.primaryName}`;
  const [coverLockup, bodyMark, coverMascot, diamondDiagram] = await Promise.all([
    renderCoverLockup(),
    renderCepMark("1B2430"),
    renderCapyMascot(),
    renderDiamondDiagram(),
  ]);
  const cover: Block[] = [coverPanel(full, coverLockup, coverMascot, exportedAt)];

  const header = documentHeader(full, bodyMark);
  const footer = documentFooter(full);
  const doc = new Document({
    creator: "Chill Ethical People · OptraSight",
    title,
    subject: "Threat actor intelligence briefing and analyst profile",
    description: "Chill Ethical People threat actor intelligence dossier prepared in OptraSight",
    keywords: `threat intelligence, threat actor, MITRE ATT&CK, Diamond Model, ${full.primaryName}`,
    settings: { updateFields: true },
    styles: {
      default: { document: { run: { font: BODY_FONT, size: 19, color: INK } } },
      paragraphStyles: [
        { id: "Title", name: "Title", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: DISPLAY_FONT, color: INK, bold: true, size: 46 } },
      ],
    },
    sections: [
      {
        properties: {
          type: SectionType.NEXT_PAGE,
          verticalAlign: VerticalAlign.TOP,
          page: { margin: { top: 420, bottom: 420, left: 420, right: 420 } },
        },
        children: cover,
      },
      {
        headers: { default: header },
        footers: { default: footer },
        properties: {
          page: { margin: { top: 850, bottom: 850, left: 850, right: 850 } },
        },
        children: [...briefingBlocks(full), ...fullProfileBlocks(full, diamondDiagram)],
      },
    ],
  });

  return Packer.toBuffer(doc);
}
