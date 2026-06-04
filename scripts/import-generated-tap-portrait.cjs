#!/usr/bin/env node

const Database = require("better-sqlite3");
const { copyFileSync, existsSync, mkdirSync } = require("node:fs");
const { resolve, join } = require("node:path");

const [, , actorName, imagePath] = process.argv;
if (!actorName || !imagePath) {
  console.error("Usage: node scripts/import-generated-tap-portrait.cjs <actor-name> <image-path>");
  process.exit(2);
}

const source = resolve(imagePath);
if (!existsSync(source)) {
  console.error(`Image not found: ${source}`);
  process.exit(2);
}

const portraitsDir = resolve(process.cwd(), "data", "portraits");
mkdirSync(portraitsDir, { recursive: true });

const dbPaths = ["data.db", "data/data.db"].filter((p, ix, arr) => arr.indexOf(p) === ix && existsSync(p));

function norm(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function aliasesFor(value) {
  const n = norm(value);
  const aliases = new Set([n]);
  if (n === "lazarusgroup") aliases.add("lazarus");
  if (n === "sandwormteam") aliases.add("sandworm");
  if (n === "incransom") aliases.add("inc");
  if (n === "blackcat") aliases.add("alphv");
  return Array.from(aliases);
}

const ts = new Date().toISOString();
const cacheBust = Date.now();
const wanted = new Set(aliasesFor(actorName));
let imported = 0;

for (const dbPath of dbPaths) {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  const rows = db.prepare("SELECT id, tenant_id, primary_name FROM threat_actors").all()
    .filter((row) => wanted.has(norm(row.primary_name)));
  if (!rows.length) {
    db.close();
    continue;
  }
  const tx = db.transaction(() => {
    for (const row of rows) {
      const target = join(portraitsDir, `${row.id}.png`);
      copyFileSync(source, target);
      db.prepare(`
        UPDATE threat_actors
           SET portrait_url = ?, portrait_generated_at = ?, portrait_status = 'ready'
         WHERE id = ? AND tenant_id = ?
      `).run(`/portraits/${row.id}.png?v=${cacheBust}`, ts, row.id, row.tenant_id);
    }
  });
  tx();
  db.close();
  imported += rows.length;
  console.log(`Imported ${source} for ${rows.length} "${actorName}" profile row(s) in ${dbPath}.`);
}

if (!imported) {
  console.error(`No threat actor rows found for: ${actorName}`);
  process.exit(2);
}
