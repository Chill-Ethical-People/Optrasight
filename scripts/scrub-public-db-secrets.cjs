#!/usr/bin/env node

const Database = require("better-sqlite3");

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("Usage: node scripts/scrub-public-db-secrets.cjs <public-db> [public-db...]");
  process.exit(2);
}

const patterns = [
  [/AKIA[0-9A-Z-]{10,}/g, "[REDACTED_AWS_ACCESS_KEY]"],
  [/(?<![A-Za-z0-9])sk-(?:prod|live|test|FAKE|[A-Za-z0-9])[A-Za-z0-9_-]{20,}/gi, "[REDACTED_API_KEY]"],
  [/(secret_key["']?\s*[:=]\s*["']?)[^"',\s}]+/gi, "$1[REDACTED_SECRET]"],
  [/(api[_-]?key["']?\s*[:=]\s*["']?)[^"',\s}]+/gi, "$1[REDACTED_API_KEY]"],
  [/(token["']?\s*[:=]\s*["']?)[A-Za-z0-9._~+/-]{12,}/gi, "$1[REDACTED_TOKEN]"],
  [/(password["']?\s*[:=]\s*["']?)[^"',\s}]+/gi, "$1[REDACTED_PASSWORD]"],
  [/hunter2/g, "[REDACTED_PASSWORD]"],
  [/password123/g, "[REDACTED_PASSWORD]"],
];

function scrub(value) {
  let next = value;
  for (const [pattern, replacement] of patterns) {
    next = next.replace(pattern, replacement);
  }
  return next;
}

for (const file of files) {
  const db = new Database(file);
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all().map((r) => r.name);
  let changed = 0;
  const tx = db.transaction(() => {
    for (const table of tables) {
      const cols = db.prepare(`PRAGMA table_info(${JSON.stringify(table)})`).all();
      const pk = cols.find((c) => c.pk === 1)?.name;
      if (!pk) continue;
      const textCols = cols.filter((c) => /TEXT/i.test(String(c.type))).map((c) => c.name);
      if (!textCols.length) continue;
      const selectCols = [pk, ...textCols].map((c) => JSON.stringify(c)).join(", ");
      const rows = db.prepare(`SELECT ${selectCols} FROM ${JSON.stringify(table)}`).all();
      for (const row of rows) {
        const updates = {};
        for (const col of textCols) {
          const value = row[col];
          if (typeof value !== "string") continue;
          const next = scrub(value);
          if (next !== value) updates[col] = next;
        }
        const updateCols = Object.keys(updates);
        if (updateCols.length === 0) continue;
        const setSql = updateCols.map((c) => `${JSON.stringify(c)} = ?`).join(", ");
        db.prepare(`UPDATE ${JSON.stringify(table)} SET ${setSql} WHERE ${JSON.stringify(pk)} = ?`).run(
          ...updateCols.map((c) => updates[c]),
          row[pk],
        );
        changed += 1;
      }
    }
  });
  tx();
  db.pragma("wal_checkpoint(TRUNCATE)");
  db.close();
  console.log(`${file}: scrubbed_rows=${changed}`);
}
