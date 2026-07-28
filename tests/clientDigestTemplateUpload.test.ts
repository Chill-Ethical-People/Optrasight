import JSZip from "jszip";
import { describe, expect, it } from "vitest";

import { buildClientDigestEmailContent } from "../server/clientDigestExport";
import { ClientDigestTemplateUploadError, parseClientDigestTemplateDocx } from "../server/clientDigestTemplateUpload";

async function templateDocx(paragraphs: string[]): Promise<string> {
  const zip = new JSZip();
  zip.file("[Content_Types].xml", "<Types/>");
  zip.file(
    "word/document.xml",
    `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${paragraphs.join("")}<w:sectPr/></w:body></w:document>`,
  );
  const buffer = await zip.generateAsync({ type: "nodebuffer" });
  return buffer.toString("base64");
}

describe("Word client-digest template upload", () => {
  it("extracts subject, headings, and placeholders split across Word runs", async () => {
    const contentBase64 = await templateDocx([
      "<w:p><w:r><w:t>EMAIL SUBJECT</w:t></w:r></w:p>",
      "<w:p><w:r><w:t>Security brief for </w:t></w:r><w:r><w:t>{{client_</w:t></w:r><w:r><w:t>name}}</w:t></w:r></w:p>",
      '<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t>Executive Summary</w:t></w:r></w:p>',
      "<w:p><w:r><w:t>Hello </w:t></w:r><w:r><w:t>{{client_name}}</w:t></w:r><w:r><w:t> security team.</w:t></w:r></w:p>",
      "<w:p><w:r><w:t>{{executive_summary}}</w:t></w:r></w:p>",
      '<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t>Sources</w:t></w:r></w:p>',
      "<w:p><w:r><w:t>{{sources}}</w:t></w:r></w:p>",
    ]);

    const parsed = await parseClientDigestTemplateDocx({ fileName: "client-template.docx", contentBase64 });
    expect(parsed.subjectTemplate).toBe("Security brief for {{client_name}}");
    expect(parsed.bodyTemplate).toContain("## Executive Summary");
    expect(parsed.bodyTemplate).toContain("{{executive_summary}}");
    expect(parsed.placeholders).toEqual(["{{client_name}}", "{{executive_summary}}", "{{sources}}"]);
  });

  it("rejects unsupported placeholders", async () => {
    const contentBase64 = await templateDocx([
      "<w:p><w:r><w:t>Subject: {{client_name}} brief</w:t></w:r></w:p>",
      "<w:p><w:r><w:t>Hello {{client_name}}, this is {{unknown_value}}.</w:t></w:r></w:p>",
    ]);

    await expect(
      parseClientDigestTemplateDocx({ fileName: "client-template.docx", contentBase64 }),
    ).rejects.toBeInstanceOf(ClientDigestTemplateUploadError);
  });

  it("rejects a DOCX that omits required evidence placeholders", async () => {
    const contentBase64 = await templateDocx([
      "<w:p><w:r><w:t>Subject: {{client_name}} brief</w:t></w:r></w:p>",
      "<w:p><w:r><w:t>Hello {{client_name}}, this body has enough static content but no required evidence blocks.</w:t></w:r></w:p>",
    ]);

    await expect(parseClientDigestTemplateDocx({ fileName: "client-template.docx", contentBase64 })).rejects.toThrow(
      /Missing required placeholders/,
    );
  });
});

describe("client brief email theme", () => {
  it("uses the green client-brief palette", () => {
    const content = buildClientDigestEmailContent(
      { name: "Example Client" } as any,
      {
        subject: "Weekly security brief",
        bodyMd: "## Critical\n\nRead the [source](https://example.com).",
        recipients: ["soc@example.com"],
      } as any,
    );
    const colors = Array.from(content.html.matchAll(/#[0-9A-Fa-f]{6}/g), (match) => match[0].toUpperCase());
    expect(new Set(colors)).toEqual(
      new Set(["#F3F7F4", "#13251A", "#FFFFFF", "#A7C7B0", "#166534", "#F0FDF4", "#14532D"]),
    );
    expect(content.html).not.toContain("#000000");
  });
});
