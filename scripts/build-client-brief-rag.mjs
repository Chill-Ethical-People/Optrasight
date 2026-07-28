#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourcePath = "docs/WEEKLY_THREAT_INTELLIGENCE_DIGEST_GUIDE.md";
const outputDirectory = resolve(root, "ai-assets/client-brief/rag");
const maxChars = 3_500;

function slug(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 120);
}

function splitMarkdown(source) {
  const sections = [];
  let path = [];
  let heading = "Document overview";
  let level = 1;
  let lines = [];

  const flush = () => {
    const body = lines.join("\n").trim();
    if (body) sections.push({ heading, level, sectionPath: [...path], body });
    lines = [];
  };

  for (const line of source.split(/\r?\n/u)) {
    const match = /^(#{1,3})\s+(.+)$/u.exec(line);
    if (!match) {
      lines.push(line);
      continue;
    }
    flush();
    level = match[1].length;
    heading = match[2].trim();
    path = [...path.slice(0, level - 1), heading];
  }
  flush();
  return sections;
}

function splitLongSection(section) {
  const prefix = `${"#".repeat(section.level)} ${section.heading}`;
  const paragraphs = section.body.split(/\n{2,}/u).filter(Boolean);
  const parts = [];
  let current = prefix;
  for (const paragraph of paragraphs) {
    if (current.length + paragraph.length + 2 <= maxChars) {
      current += `\n\n${paragraph}`;
      continue;
    }
    if (current !== prefix) parts.push(current);
    if (paragraph.length <= maxChars - prefix.length - 2) {
      current = `${prefix}\n\n${paragraph}`;
      continue;
    }
    const lines = paragraph.split("\n");
    current = prefix;
    for (const line of lines) {
      if (current.length + line.length + 1 > maxChars && current !== prefix) {
        parts.push(current);
        current = prefix;
      }
      current += `\n${line}`;
    }
  }
  if (current !== prefix) parts.push(current);
  return parts;
}

function classify(sectionPath, content) {
  const value = `${sectionPath.join(" ")} ${content}`.toLowerCase();
  const audienceTags = [];
  const matchingScopes = [];
  if (/cti service subscriber|cti subscriber/u.test(value)) {
    audienceTags.push("cti_subscriber");
    matchingScopes.push("cti_subscription");
  }
  if (/mdr|mdd|incident response|managed_security|managed security/u.test(value)) {
    audienceTags.push("managed_security_client");
    matchingScopes.push("managed_security");
  }
  if (/general cybersecurity|prospect|advisory/u.test(value)) {
    audienceTags.push("advisory_or_prospect");
    matchingScopes.push("advisory");
  }
  if (/hybrid/u.test(value)) matchingScopes.push("hybrid");
  if (!audienceTags.length) audienceTags.push("all");
  if (!matchingScopes.length) matchingScopes.push("all");

  const contentTypes = [];
  if (/template/u.test(value)) contentTypes.push("template");
  if (/placeholder/u.test(value)) contentTypes.push("placeholder_contract");
  if (/word bank/u.test(value)) contentTypes.push("word_bank");
  if (/phrase/u.test(value)) contentTypes.push("phrase_bank");
  if (/guardrail|avoid\s+prefer/u.test(value)) contentTypes.push("claims_guardrail");
  if (/quality check/u.test(value)) contentTypes.push("quality_check");
  if (!contentTypes.length) contentTypes.push("guidance");

  return {
    audienceTags: [...new Set(audienceTags)],
    matchingScopes: [...new Set(matchingScopes)],
    contentTypes: [...new Set(contentTypes)],
  };
}

const source = await readFile(resolve(root, sourcePath), "utf8");
const sourceSha256 = createHash("sha256").update(source).digest("hex");
const chunks = [];

for (const section of splitMarkdown(source)) {
  const parts = splitLongSection(section);
  parts.forEach((content, partIndex) => {
    const classification = classify(section.sectionPath, content);
    const index = chunks.length + 1;
    chunks.push({
      id: `client-brief-guide-${String(index).padStart(3, "0")}`,
      document_id: "optrasight-client-brief-guide",
      title: section.heading,
      section_path: section.sectionPath,
      source_path: sourcePath,
      source_anchor: slug(section.sectionPath.join(" ")),
      part: partIndex + 1,
      audience_tags: classification.audienceTags,
      matching_scopes: classification.matchingScopes,
      content_types: classification.contentTypes,
      language: "en",
      tlp: "inherit_from_request",
      token_estimate: Math.ceil(content.length / 4),
      content,
    });
  });
}

const manifest = {
  schema_version: 1,
  document_id: "optrasight-client-brief-guide",
  title: "Weekly Threat Intelligence Digest Drafting Guide",
  source_path: sourcePath,
  source_sha256: sourceSha256,
  chunk_count: chunks.length,
  chunking: {
    strategy: "markdown_heading_then_paragraph",
    maximum_characters: maxChars,
    overlap: "heading repeated for split sections",
  },
  retrieval_defaults: {
    mode: "hybrid_semantic_keyword",
    candidate_count: 18,
    final_context_chunks: 6,
    diversity: "maximal_marginal_relevance",
    audience_filter: "boost",
  },
  citation_format: "[Client Brief Guide > {section_path}]",
};

await mkdir(outputDirectory, { recursive: true });
await writeFile(
  resolve(outputDirectory, "client-brief-guide.jsonl"),
  `${chunks.map((chunk) => JSON.stringify(chunk)).join("\n")}\n`,
);
await writeFile(resolve(outputDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Built ${chunks.length} Client Brief RAG chunks (${sourceSha256.slice(0, 12)}).`);
