/**
 * Preserve the evidence graph inside generated Sigma rules. Source bodies use
 * stable section headers emitted by sourceFetch.ts, so this remains provider-
 * independent and does not rely on a model remembering every reference URL.
 */
export function extractFetchedEvidenceUrls(sourceContent: string | null | undefined): string[] {
  if (!sourceContent) return [];
  const urls: string[] = [];
  const seen = new Set<string>();
  for (const match of sourceContent.matchAll(/^(?:Primary source|Referenced source) \((https?:\/\/[^)\n]+)\):/gm)) {
    const url = match[1].trim();
    if (!seen.has(url)) {
      seen.add(url);
      urls.push(url);
    }
  }
  return urls;
}

export function ensureSigmaEvidenceReferences(
  sigmaYaml: string | null | undefined,
  evidenceUrls: string[],
): string | null {
  if (!sigmaYaml) return null;
  const lines = sigmaYaml.replace(/\r\n/g, "\n").split("\n");
  const referenceIndex = lines.findIndex((line) => /^references\s*:/i.test(line));
  let blockEnd = referenceIndex + 1;
  if (referenceIndex >= 0) {
    while (blockEnd < lines.length && !/^[A-Za-z_][\w-]*\s*:/.test(lines[blockEnd])) blockEnd += 1;
  }
  const existingBlock = referenceIndex >= 0 ? lines.slice(referenceIndex, blockEnd).join("\n") : "";
  const existingUrls = Array.from(existingBlock.matchAll(/https?:\/\/[^\s"'\],]+/g), (match) => match[0]);
  const references = Array.from(new Set([...existingUrls, ...evidenceUrls].filter(Boolean)));
  if (references.length === 0) return sigmaYaml;
  const replacement = ["references:", ...references.map((url) => `  - ${JSON.stringify(url)}`)];
  if (referenceIndex >= 0) {
    lines.splice(referenceIndex, blockEnd - referenceIndex, ...replacement);
  } else {
    const insertAt = lines.findIndex((line) => /^(?:author|date)\s*:/i.test(line));
    lines.splice(insertAt >= 0 ? insertAt : lines.length, 0, ...replacement);
  }
  return lines.join("\n");
}
