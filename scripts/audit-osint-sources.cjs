#!/usr/bin/env node
// Audit every OSINT source: hit the URL, report status, content type, size.
// Usage: node scripts/audit-osint-sources.cjs [path/to/data.db]

const Database = require("better-sqlite3");
const path = require("path");

const dbPath = process.argv[2]
  ? path.resolve(process.cwd(), process.argv[2])
  : path.join(__dirname, "..", "data.db");
const db = new Database(dbPath, { readonly: true });

const sources = db.prepare("SELECT id, category, name, url FROM osint_sources ORDER BY category, name").all();
db.close();

const TIMEOUT = 12000;

async function probe(src) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT);
  try {
    const r = await fetch(src.url, {
      signal: ctl.signal,
      method: src.url.includes("abuse.ch/api") ? "POST" : "GET",
      headers: {
        "user-agent": "OptraSight-OSINT/2.11 (+https://optrasight.local)",
        accept: "application/json, text/xml, application/rss+xml, application/atom+xml, */*",
        ...(src.url.includes("mb-api.abuse.ch") ? { "content-type": "application/x-www-form-urlencoded" } : {}),
        ...(src.url.includes("threatfox-api.abuse.ch") ? { "content-type": "application/json" } : {}),
      },
      body: src.url.includes("mb-api.abuse.ch")
        ? "query=get_recent&selector=10"
        : src.url.includes("threatfox-api.abuse.ch")
        ? JSON.stringify({ query: "get_iocs", days: 1 })
        : undefined,
    });
    clearTimeout(timer);
    const ct = r.headers.get("content-type") || "unknown";
    let bodyLen = 0;
    let snippet = "";
    let format = "unknown";
    try {
      const text = await r.text();
      bodyLen = text.length;
      snippet = text.slice(0, 200).replace(/\n/g, " ").trim();
      if (text.trimStart().startsWith("<?xml") || text.trimStart().startsWith("<rss") || text.trimStart().startsWith("<feed") || text.trimStart().startsWith("<rdf")) format = "XML/RSS";
      else if (text.trimStart().startsWith("{") || text.trimStart().startsWith("[")) format = "JSON";
      else if (text.trimStart().startsWith("<!DOCTYPE") || text.trimStart().startsWith("<html")) format = "HTML";
      else if (/^\d+\.\d+\.\d+\.\d+/.test(text.trimStart()) || /^#/.test(text.trimStart())) format = "TEXT/CSV";
      else if (text.includes("<item") || text.includes("<entry")) format = "XML/RSS";
      else format = "TEXT";
    } catch {}
    return { id: src.id, category: src.category, name: src.name, status: r.status, ct, bodyLen, format, snippet, ok: r.ok };
  } catch (e) {
    clearTimeout(timer);
    return { id: src.id, category: src.category, name: src.name, status: 0, ct: "", bodyLen: 0, format: "ERROR", snippet: e.message || String(e), ok: false };
  }
}

(async () => {
  console.log(`Probing ${sources.length} OSINT sources...\n`);
  const results = [];
  // batch 8 at a time
  for (let i = 0; i < sources.length; i += 8) {
    const batch = sources.slice(i, i + 8);
    const batchResults = await Promise.all(batch.map(probe));
    results.push(...batchResults);
    process.stdout.write(`  ${results.length}/${sources.length}\r`);
  }
  console.log("\n");

  // group by status
  const ok = results.filter(r => r.ok);
  const fail = results.filter(r => !r.ok);

  console.log(`=== ACCESSIBLE: ${ok.length}/${results.length} ===\n`);
  for (const r of ok) {
    console.log(`  ✓ [${r.category}] ${r.name}`);
    console.log(`    ${r.id} | HTTP ${r.status} | ${r.format} | ${r.bodyLen} bytes`);
  }

  console.log(`\n=== FAILED: ${fail.length}/${results.length} ===\n`);
  for (const r of fail) {
    console.log(`  ✗ [${r.category}] ${r.name}`);
    console.log(`    ${r.id} | HTTP ${r.status} | ${r.snippet.slice(0, 120)}`);
  }

  // format breakdown
  console.log(`\n=== FORMAT BREAKDOWN ===`);
  const fmtCount = {};
  for (const r of ok) fmtCount[r.format] = (fmtCount[r.format] || 0) + 1;
  for (const [fmt, count] of Object.entries(fmtCount)) console.log(`  ${fmt}: ${count}`);

  // parser coverage check
  console.log(`\n=== PARSER COVERAGE ===`);
  const needsParser = ok.filter(r => {
    // XML/RSS feeds are handled by generic walker
    if (r.format === "XML/RSS") return false;
    // JSON and TEXT need deep parsers — check if they have one
    return true;
  });
  console.log(`  XML/RSS (generic walker handles): ${ok.filter(r => r.format === "XML/RSS").length}`);
  console.log(`  JSON/TEXT/CSV (need deep parser): ${needsParser.length}`);
  for (const r of needsParser) {
    console.log(`    → ${r.id} ${r.name} [${r.format}]`);
  }
})();
