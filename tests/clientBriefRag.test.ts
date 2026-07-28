import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const source = readFileSync(resolve(root, "docs/WEEKLY_THREAT_INTELLIGENCE_DIGEST_GUIDE.md"), "utf8");
const manifest = JSON.parse(readFileSync(resolve(root, "ai-assets/client-brief/rag/manifest.json"), "utf8"));
const chunks = readFileSync(resolve(root, "ai-assets/client-brief/rag/client-brief-guide.jsonl"), "utf8")
  .trim()
  .split("\n")
  .map((line) => JSON.parse(line));

describe("Client Brief RAG pack", () => {
  it("matches the canonical guide and has unique traceable chunks", () => {
    expect(manifest.source_sha256).toBe(createHash("sha256").update(source).digest("hex"));
    expect(manifest.chunk_count).toBe(chunks.length);
    expect(chunks.length).toBeGreaterThan(20);
    expect(new Set(chunks.map((chunk) => chunk.id)).size).toBe(chunks.length);
    expect(chunks.every((chunk) => chunk.source_path === manifest.source_path)).toBe(true);
    expect(chunks.every((chunk) => chunk.content.length <= 3_500)).toBe(true);
  });

  it("retains required contracts, audiences, and quality guardrails", () => {
    const corpus = chunks.map((chunk) => chunk.content).join("\n");
    expect(corpus).toContain("{{client_name}}");
    expect(corpus).toContain("{{executive_summary}}");
    expect(corpus).toContain("{{sources}}");
    expect(corpus).toContain("CTI service subscriber");
    expect(corpus).toContain("MDR, MDD, or IR client");
    expect(corpus).toContain("Claims and wording guardrails");
    expect(corpus).toContain("Pre-distribution quality check");
  });
});
