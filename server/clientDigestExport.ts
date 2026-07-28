import {
  AlignmentType,
  Document,
  HeadingLevel,
  ImageRun,
  Packer,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from "docx";
import type { ClientDigestDTO, ClientProfileDTO } from "@shared/schema";
import { CLIENT_DIGEST_TEMPLATE_PLACEHOLDERS } from "@shared/clientDigestTemplate";

const BRAND = "166534";
const INK = "13251A";
const MUTED = "3F5B49";
const SOFT = "F0FDF4";

export interface ClientEmailLogo {
  data: Buffer;
  mimeType: "image/png" | "image/jpeg";
}

function inlineRuns(text: string): TextRun[] {
  const runs: TextRun[] = [];
  const pattern = /(\*\*[^*]+\*\*|\[[^\]]+\]\(https?:\/\/[^)]+\)|{{[a-zA-Z0-9_]+}})/g;
  let cursor = 0;
  for (const match of text.matchAll(pattern)) {
    if (match.index! > cursor) runs.push(new TextRun({ text: text.slice(cursor, match.index), size: 20, color: INK }));
    const value = match[0];
    if (value.startsWith("**")) {
      runs.push(new TextRun({ text: value.slice(2, -2), bold: true, size: 20, color: INK }));
    } else if (value.startsWith("[")) {
      const link = value.match(/^\[([^\]]+)\]\((https?:\/\/[^)]+)\)$/);
      runs.push(new TextRun({ text: link ? `${link[1]} (${link[2]})` : value, size: 20, color: BRAND }));
    } else {
      runs.push(new TextRun({ text: value, bold: true, size: 20, color: BRAND }));
    }
    cursor = match.index! + value.length;
  }
  if (cursor < text.length) runs.push(new TextRun({ text: text.slice(cursor), size: 20, color: INK }));
  return runs.length ? runs : [new TextRun({ text, size: 20, color: INK })];
}

function markdownToDocx(body: string): Paragraph[] {
  return body.split(/\r?\n/).map((line) => {
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      const level =
        heading[1].length === 1
          ? HeadingLevel.HEADING_1
          : heading[1].length === 2
            ? HeadingLevel.HEADING_2
            : HeadingLevel.HEADING_3;
      return new Paragraph({
        heading: level,
        spacing: { before: 220, after: 90 },
        children: [new TextRun({ text: heading[2], bold: true, color: heading[1].length === 2 ? BRAND : INK })],
      });
    }
    const bullet = line.match(/^[-*]\s+(.+)$/);
    if (bullet) return new Paragraph({ bullet: { level: 0 }, spacing: { after: 70 }, children: inlineRuns(bullet[1]) });
    const numbered = line.match(/^(\d+)\.\s+(.+)$/);
    if (numbered)
      return new Paragraph({
        numbering: { reference: "actions", level: 0 },
        spacing: { after: 70 },
        children: inlineRuns(numbered[2]),
      });
    return new Paragraph({ spacing: { after: line ? 90 : 30 }, children: inlineRuns(line) });
  });
}

export async function buildClientTemplateDocx(profile: ClientProfileDTO, logo?: ClientEmailLogo): Promise<Buffer> {
  const headerChildren: Array<Paragraph | Table> = [];
  if (logo) {
    headerChildren.push(
      new Paragraph({
        spacing: { after: 80 },
        children: [
          new ImageRun({
            data: logo.data,
            type: logo.mimeType === "image/png" ? "png" : "jpg",
            transformation: { width: 180, height: 60 },
            altText: { title: `${profile.name} logo`, description: `${profile.name} email logo`, name: "Client logo" },
          }),
        ],
      }),
    );
  }
  headerChildren.push(
    new Paragraph({
      spacing: { after: 40 },
      children: [new TextRun({ text: profile.name, bold: true, size: 32, color: INK })],
    }),
  );
  headerChildren.push(
    new Paragraph({
      spacing: { after: 200 },
      children: [
        new TextRun({ text: "CLIENT THREAT INTELLIGENCE EMAIL TEMPLATE", bold: true, size: 16, color: BRAND }),
      ],
    }),
  );

  const subject = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({
        children: [
          new TableCell({
            shading: { type: ShadingType.CLEAR, fill: SOFT, color: "auto" },
            margins: { top: 140, bottom: 140, left: 180, right: 180 },
            children: [
              new Paragraph({ children: [new TextRun({ text: "EMAIL SUBJECT", bold: true, size: 15, color: MUTED })] }),
              new Paragraph({ spacing: { before: 50 }, children: inlineRuns(profile.digestSubjectTemplate) }),
            ],
          }),
        ],
      }),
    ],
  });

  const guide = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({
        tableHeader: true,
        children: ["Placeholder", "Required", "Placement", "Generated content"].map(
          (value) =>
            new TableCell({
              shading: { type: ShadingType.CLEAR, fill: BRAND, color: "auto" },
              children: [
                new Paragraph({ children: [new TextRun({ text: value, bold: true, size: 16, color: "FFFFFF" })] }),
              ],
            }),
        ),
      }),
      ...CLIENT_DIGEST_TEMPLATE_PLACEHOLDERS.map(
        (item) =>
          new TableRow({
            children: [
              new TableCell({
                children: [
                  new Paragraph({ children: [new TextRun({ text: item.token, bold: true, size: 16, color: BRAND })] }),
                ],
              }),
              new TableCell({
                children: [
                  new Paragraph({ children: [new TextRun({ text: item.required ? "Yes" : "Optional", bold: item.required, size: 16, color: INK })] }),
                ],
              }),
              new TableCell({
                children: [
                  new Paragraph({ children: [new TextRun({ text: item.placement, size: 16, color: MUTED })] }),
                ],
              }),
              new TableCell({
                children: [
                  new Paragraph({ children: [new TextRun({ text: item.description, size: 16, color: INK })] }),
                ],
              }),
            ],
          }),
      ),
    ],
  });

  const document = new Document({
    numbering: {
      config: [
        {
          reference: "actions",
          levels: [{ level: 0, format: "decimal", text: "%1.", alignment: AlignmentType.START }],
        },
      ],
    },
    styles: { default: { document: { run: { font: "Aptos", size: 20, color: INK } } } },
    sections: [
      {
        properties: { page: { margin: { top: 720, right: 720, bottom: 720, left: 720 } } },
        children: [
          ...headerChildren,
          subject,
          new Paragraph({ spacing: { after: 120 }, children: [] }),
          ...markdownToDocx(profile.digestBodyTemplate),
          new Paragraph({
            pageBreakBefore: true,
            children: [new TextRun({ text: "Supported placeholders", bold: true, size: 28, color: INK })],
          }),
          new Paragraph({
            spacing: { after: 160 },
            children: [
              new TextRun({
                text: "Required: {{client_name}} in the subject; {{executive_summary}} and {{sources}} in the body. Place generated section blocks on their own line.",
                size: 18,
                color: MUTED,
              }),
            ],
          }),
          guide,
          new Paragraph({
            spacing: { before: 200 },
            children: [
              new TextRun({
                text: "DRAFT - Analyst approval is required before client distribution.",
                bold: true,
                size: 16,
                color: INK,
              }),
            ],
          }),
        ],
      },
    ],
  });
  return Packer.toBuffer(document);
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function inlineHtml(value: string): string {
  let escaped = escapeHtml(value);
  escaped = escaped.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  escaped = escaped.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2" style="color:#166534;text-decoration:underline">$1</a>');
  escaped = escaped.replace(/({{[a-zA-Z0-9_]+}})/g, '<strong style="color:#166534">$1</strong>');
  return escaped;
}

export function markdownToEmailHtml(body: string): string {
  const output: string[] = [];
  let list: "ul" | "ol" | null = null;
  const closeList = () => {
    if (list) output.push(`</${list}>`);
    list = null;
  };
  for (const raw of body.split(/\r?\n/)) {
    const line = raw.trim();
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    const bullet = line.match(/^[-*]\s+(.+)$/);
    const numbered = line.match(/^\d+\.\s+(.+)$/);
    if (heading) {
      closeList();
      const level = heading[1].length <= 2 ? 2 : 3;
      const section = level === 2;
      const style = section
        ? "margin:26px 0 10px;padding:9px 12px;border-left:4px solid #166534;background:#F0FDF4;color:#14532D;font-size:15px"
        : "margin:20px 0 7px;color:#166534;font-size:14px";
      output.push(`<h${level} style="${style}">${inlineHtml(heading[2])}</h${level}>`);
    } else if (bullet || numbered) {
      const nextList = bullet ? "ul" : "ol";
      if (list !== nextList) {
        closeList();
        list = nextList;
        output.push(`<${list} style="margin:8px 0;padding-left:22px">`);
      }
      output.push(`<li style="margin:6px 0">${inlineHtml((bullet || numbered)![1])}</li>`);
    } else if (line) {
      closeList();
      output.push(`<p style="margin:8px 0;line-height:1.65">${inlineHtml(line)}</p>`);
    } else {
      closeList();
    }
  }
  closeList();
  return output.join("\n");
}

function foldBase64(data: Buffer): string {
  return (
    data
      .toString("base64")
      .match(/.{1,76}/g)
      ?.join("\r\n") ?? ""
  );
}

function encodedPart(value: string): string {
  return foldBase64(Buffer.from(value, "utf8"));
}

function buildClientEmailContent(
  profile: ClientProfileDTO,
  content: { subject: string; bodyMd: string; recipients: string[] },
  logo?: ClientEmailLogo,
) {
  const logoHtml = logo
    ? '<img src="cid:client-logo" alt="Client logo" style="display:block;max-width:180px;max-height:64px;margin:0 0 14px;filter:grayscale(1)">'
    : "";
  const html = `<!doctype html><html><body style="margin:0;background:#F3F7F4;font-family:Arial,Helvetica,sans-serif;color:#13251A"><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center" style="padding:28px 12px"><table role="presentation" width="700" style="width:100%;max-width:700px;background:#FFFFFF;border:1px solid #A7C7B0"><tr><td height="6" bgcolor="#166534" style="font-size:0;line-height:0">&nbsp;</td></tr><tr><td style="padding:24px 28px;border-bottom:1px solid #A7C7B0">${logoHtml}<div style="font-size:22px;font-weight:700">${escapeHtml(profile.name)}</div><div style="margin-top:4px;color:#166534;font-size:11px;font-weight:700;letter-spacing:1px">THREAT INTELLIGENCE BRIEF</div></td></tr><tr><td style="padding:18px 28px;background:#F0FDF4;border-bottom:1px solid #A7C7B0"><div style="font-size:10px;font-weight:700;color:#166534">SUBJECT</div><div style="margin-top:5px;font-size:14px;font-weight:700">${inlineHtml(content.subject)}</div></td></tr><tr><td style="padding:28px;font-size:14px">${markdownToEmailHtml(content.bodyMd)}</td></tr><tr><td style="padding:16px 28px;background:#14532D;color:#FFFFFF;font-size:11px">Sent after analyst approval through OptraSight.</td></tr></table></td></tr></table></body></html>`;
  const text = `${content.bodyMd}\n\nSent after analyst approval through OptraSight.`;
  return { subject: content.subject, recipients: content.recipients, html, text, logo };
}

export function buildClientDigestEmailContent(
  profile: ClientProfileDTO,
  digest: ClientDigestDTO,
  logo?: ClientEmailLogo,
) {
  return buildClientEmailContent(
    profile,
    {
      subject: digest.subject,
      bodyMd: digest.bodyMd,
      recipients: digest.recipients,
    },
    logo,
  );
}

function buildClientEml(
  profile: ClientProfileDTO,
  content: { subject: string; bodyMd: string; recipients: string[] },
  logo?: ClientEmailLogo,
): Buffer {
  const boundary = `optrasight-related-${Date.now().toString(36)}`;
  const altBoundary = `optrasight-alt-${Date.now().toString(36)}`;
  const rendered = buildClientEmailContent(profile, content, logo);
  const plain = `Subject: ${content.subject}\n\n${content.bodyMd}\n\nDRAFT - Analyst approval required before client distribution.`;
  const lines = [
    `Subject: ${content.subject.replace(/[\r\n]+/g, " ")}`,
    "From: OptraSight Threat Intelligence <threat-intel@example.com>",
    `To: ${content.recipients.length ? content.recipients.join(", ") : "[Client security distribution list]"}`,
    "MIME-Version: 1.0",
    "X-Unsent: 1",
    `Content-Type: multipart/related; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
    "",
    `--${altBoundary}`,
    'Content-Type: text/plain; charset="utf-8"',
    "Content-Transfer-Encoding: base64",
    "",
    encodedPart(plain),
    `--${altBoundary}`,
    'Content-Type: text/html; charset="utf-8"',
    "Content-Transfer-Encoding: base64",
    "",
    encodedPart(
      rendered.html.replace(
        "Sent after analyst approval through OptraSight.",
        "DRAFT - Analyst approval required before client distribution.",
      ),
    ),
    `--${altBoundary}--`,
  ];
  if (logo) {
    lines.push(
      `--${boundary}`,
      `Content-Type: ${logo.mimeType}; name="client-logo.${logo.mimeType === "image/png" ? "png" : "jpg"}"`,
      "Content-Transfer-Encoding: base64",
      'Content-Disposition: inline; filename="client-logo"',
      "Content-ID: <client-logo>",
      "",
      foldBase64(logo.data),
    );
  }
  lines.push(`--${boundary}--`, "");
  return Buffer.from(lines.join("\r\n"), "utf8");
}

export function buildClientTemplateEml(profile: ClientProfileDTO, logo?: ClientEmailLogo): Buffer {
  return buildClientEml(
    profile,
    {
      subject: profile.digestSubjectTemplate,
      bodyMd: profile.digestBodyTemplate,
      recipients: [],
    },
    logo,
  );
}

export function buildClientDigestEml(
  profile: ClientProfileDTO,
  digest: ClientDigestDTO,
  logo?: ClientEmailLogo,
): Buffer {
  return buildClientEml(
    profile,
    {
      subject: digest.subject,
      bodyMd: digest.bodyMd,
      recipients: digest.recipients,
    },
    logo,
  );
}
