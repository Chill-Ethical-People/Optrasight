import JSZip from "jszip";

import {
  CLIENT_DIGEST_TEMPLATE_TOKENS,
  DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE,
  missingRequiredClientDigestPlaceholders,
  unsupportedClientDigestPlaceholders,
} from "@shared/clientDigestTemplate";

const MAX_DOCX_BYTES = 5 * 1024 * 1024;
const MAX_DOCUMENT_XML_BYTES = 3 * 1024 * 1024;

export class ClientDigestTemplateUploadError extends Error {
  statusCode: number;

  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = "ClientDigestTemplateUploadError";
    this.statusCode = statusCode;
  }
}

export type ParsedClientDigestTemplate = {
  subjectTemplate: string;
  bodyTemplate: string;
  placeholders: string[];
  warnings: string[];
};

function decodeXml(value: string): string {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_match, code) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_match, code) => String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/&amp;/g, "&");
}

function paragraphText(xml: string): string {
  const expanded = xml.replace(/<w:tab\b[^>]*\/>/g, "\t").replace(/<w:(?:br|cr)\b[^>]*\/>/g, "\n");
  return Array.from(expanded.matchAll(/<w:t\b[^>]*>([\s\S]*?)<\/w:t>/g))
    .map((match) => decodeXml(match[1]))
    .join("")
    .replace(/\u00a0/g, " ")
    .trim();
}

function paragraphMarkdown(xml: string, text: string): string {
  if (!text) return "";
  const style = /<w:pStyle\b[^>]*w:val="([^"]+)"/.exec(xml)?.[1]?.toLowerCase() ?? "";
  const heading = /heading\s*([123])/.exec(style)?.[1];
  if (heading) return `${"#".repeat(Number(heading))} ${text}`;
  if (/<w:numPr\b/.test(xml)) return `- ${text}`;
  return text;
}

function validateTemplate(subjectTemplate: string, bodyTemplate: string): ParsedClientDigestTemplate {
  const subject = subjectTemplate.replace(/[\r\n]+/g, " ").trim();
  const body = bodyTemplate.trim();
  if (subject.length < 3 || subject.length > 500) {
    throw new ClientDigestTemplateUploadError("The Word template subject must contain 3 to 500 characters.");
  }
  if (body.length < 20 || body.length > 50_000) {
    throw new ClientDigestTemplateUploadError("The Word template body must contain 20 to 50,000 characters.");
  }
  const unsupported = Array.from(
    new Set([...unsupportedClientDigestPlaceholders(subject), ...unsupportedClientDigestPlaceholders(body)]),
  );
  if (unsupported.length) {
    throw new ClientDigestTemplateUploadError(`Unsupported placeholders: ${unsupported.join(", ")}`);
  }
  const missing = missingRequiredClientDigestPlaceholders(subject, body);
  if (missing.length) {
    throw new ClientDigestTemplateUploadError(
      `Missing required placeholders: ${missing.join(", ")}. Keep {{client_name}} in the subject and {{executive_summary}} plus {{sources}} in the body.`,
    );
  }
  const allowed = new Set<string>(CLIENT_DIGEST_TEMPLATE_TOKENS);
  const placeholders = Array.from(new Set(`${subject}\n${body}`.match(/{{[a-zA-Z0-9_]+}}/g) ?? [])).filter((token) =>
    allowed.has(token),
  );
  if (!placeholders.length) {
    throw new ClientDigestTemplateUploadError(
      "The Word template must contain at least one supported placeholder such as {{client_name}} or {{executive_summary}}.",
    );
  }
  return { subjectTemplate: subject, bodyTemplate: body, placeholders, warnings: [] };
}

export async function parseClientDigestTemplateDocx(input: {
  fileName: string;
  contentBase64: string;
}): Promise<ParsedClientDigestTemplate> {
  if (!/\.docx$/i.test(input.fileName.trim())) {
    throw new ClientDigestTemplateUploadError(
      "Upload a .docx Word document. Macro-enabled .docm files are not accepted.",
    );
  }
  const encoded = input.contentBase64.replace(/\s+/g, "");
  if (!encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new ClientDigestTemplateUploadError("The uploaded Word document is not valid base64 data.");
  }
  const buffer = Buffer.from(encoded, "base64");
  if (!buffer.length || buffer.length > MAX_DOCX_BYTES) {
    throw new ClientDigestTemplateUploadError("The Word template must be smaller than 5MB.", 413);
  }
  if (buffer[0] !== 0x50 || buffer[1] !== 0x4b) {
    throw new ClientDigestTemplateUploadError("The uploaded file is not a valid DOCX package.");
  }

  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(buffer, { checkCRC32: true });
  } catch {
    throw new ClientDigestTemplateUploadError("The Word template could not be opened as a valid DOCX package.");
  }
  const documentEntry = zip.file("word/document.xml");
  if (!documentEntry)
    throw new ClientDigestTemplateUploadError("The DOCX package does not contain a Word document body.");
  const declaredSize = Number((documentEntry as any)?._data?.uncompressedSize ?? 0);
  if (declaredSize > MAX_DOCUMENT_XML_BYTES) {
    throw new ClientDigestTemplateUploadError("The Word template document body is too large.", 413);
  }
  const documentXml = await documentEntry.async("string");
  if (documentXml.length > MAX_DOCUMENT_XML_BYTES) {
    throw new ClientDigestTemplateUploadError("The Word template document body is too large.", 413);
  }

  const paragraphs = Array.from(documentXml.matchAll(/<w:p\b[\s\S]*?<\/w:p>/g))
    .map((match) => ({ xml: match[0], text: paragraphText(match[0]) }))
    .filter((paragraph) => paragraph.text.length > 0);
  if (!paragraphs.length) throw new ClientDigestTemplateUploadError("The Word template contains no readable text.");

  let subjectTemplate = DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE;
  let bodyStart = 0;
  const subjectLabelIndex = paragraphs.findIndex((paragraph) => /^email\s+subject\s*:?$/i.test(paragraph.text));
  const inlineSubjectIndex = paragraphs.findIndex((paragraph) => /^subject\s*:/i.test(paragraph.text));
  if (subjectLabelIndex >= 0 && paragraphs[subjectLabelIndex + 1]) {
    subjectTemplate = paragraphs[subjectLabelIndex + 1].text;
    bodyStart = subjectLabelIndex + 2;
  } else if (inlineSubjectIndex >= 0) {
    subjectTemplate = paragraphs[inlineSubjectIndex].text.replace(/^subject\s*:\s*/i, "");
    bodyStart = inlineSubjectIndex + 1;
  }

  const bodyLines: string[] = [];
  for (let index = bodyStart; index < paragraphs.length; index += 1) {
    const paragraph = paragraphs[index];
    if (/^supported placeholders$/i.test(paragraph.text)) break;
    if (/^draft\s*[-–—]/i.test(paragraph.text)) continue;
    if (index < bodyStart + 3 && /^(client threat intelligence email template|optrasight)$/i.test(paragraph.text))
      continue;
    bodyLines.push(paragraphMarkdown(paragraph.xml, paragraph.text));
  }

  const parsed = validateTemplate(subjectTemplate, bodyLines.join("\n\n"));
  if (subjectLabelIndex < 0 && inlineSubjectIndex < 0) {
    parsed.warnings.push(
      "No 'EMAIL SUBJECT' or 'Subject:' marker was found; the existing default subject template was retained.",
    );
  }
  return parsed;
}
