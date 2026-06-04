#!/usr/bin/env node

const Database = require("better-sqlite3");
const { copyFileSync, existsSync } = require("node:fs");
const { resolve, join } = require("node:path");

const SOURCE_DB = "data.db";
const TARGET_DBS = ["data.db", "data/data.db"].filter((p, ix, arr) => arr.indexOf(p) === ix && existsSync(p));
const PORTRAITS_DIR = resolve(process.cwd(), "data", "portraits");
const ts = new Date().toISOString();
const cacheBust = Date.now();

const aliasPairs = [
  ["lazarus", "lazarusgroup"],
  ["sandworm", "sandwormteam"],
  ["akira", "akira"],
  ["dragonforce", "dragonforce"],
  ["incransom", "incransom"],
  ["rhysida", "rhysida"],
  ["lockbit5", "lockbit"],
  ["blackcat", "blackcat"],
  ["alphv", "blackcat"],
  ["safepay", "safepay"],
];

function norm(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function parseJson(value, fallback) {
  try { return JSON.parse(value || ""); } catch { return fallback; }
}

function sourcePathFor(row) {
  const urlPath = String(row.portrait_url || "").split("?")[0];
  const file = urlPath.startsWith("/portraits/") ? urlPath.slice("/portraits/".length) : `${row.id}.png`;
  return join(PORTRAITS_DIR, file);
}

const source = new Database(SOURCE_DB, { readonly: true });
source.pragma("busy_timeout = 10000");
const sourceRows = source.prepare(`
  SELECT id, primary_name, aliases, portrait_url, portrait_generated_at
    FROM threat_actors
   WHERE portrait_url IS NOT NULL AND portrait_url != ''
   ORDER BY portrait_generated_at DESC
`).all();

const portraitByKey = new Map();
for (const row of sourceRows) {
  const src = sourcePathFor(row);
  if (!existsSync(src)) continue;
  const keys = new Set([norm(row.primary_name)]);
  for (const alias of parseJson(row.aliases, [])) keys.add(norm(alias));
  for (const [alias, canonical] of aliasPairs) {
    if (keys.has(canonical)) keys.add(alias);
    if (keys.has(alias)) keys.add(canonical);
  }
  for (const key of keys) {
    if (key && !portraitByKey.has(key)) portraitByKey.set(key, { src, sourceName: row.primary_name });
  }
}

let totalUpdated = 0;
for (const dbPath of TARGET_DBS) {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  const rows = db.prepare("SELECT id, tenant_id, primary_name, aliases, portrait_url FROM threat_actors").all();
  const update = db.prepare(`
    UPDATE threat_actors
       SET portrait_url = ?,
           portrait_generated_at = ?,
           portrait_status = 'ready'
     WHERE id = ? AND tenant_id = ?
  `);
  let updated = 0;
  const tx = db.transaction(() => {
    for (const row of rows) {
      const keys = new Set([norm(row.primary_name)]);
      for (const alias of parseJson(row.aliases, [])) keys.add(norm(alias));
      for (const [alias, canonical] of aliasPairs) {
        if (keys.has(canonical)) keys.add(alias);
        if (keys.has(alias)) keys.add(canonical);
      }
      let match = null;
      for (const key of keys) {
        match = portraitByKey.get(key);
        if (match) break;
      }
      if (!match) continue;
      const target = join(PORTRAITS_DIR, `${row.id}.png`);
      copyFileSync(match.src, target);
      update.run(`/portraits/${row.id}.png?v=${cacheBust}`, ts, row.id, row.tenant_id);
      updated++;
    }
  });
  tx();
  db.close();
  totalUpdated += updated;
  console.log(`${dbPath}: linked ${updated}/${rows.length} threat actor rows`);
}

source.close();
console.log(`Total portrait links repaired: ${totalUpdated}`);
