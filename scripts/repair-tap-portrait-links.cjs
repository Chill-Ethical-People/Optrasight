#!/usr/bin/env node

const Database = require("better-sqlite3");
const { copyFileSync, existsSync, mkdirSync, readdirSync } = require("node:fs");
const { basename, extname, resolve, join } = require("node:path");

const SOURCE_DB = "data.db";
const ROOT_STYLE_SOURCE_DBS = [
  process.env.OPTRASIGHT_PORTRAIT_SOURCE_DB,
  resolve(process.cwd(), "..", "optrasight-full-platform", "data.db"),
  resolve(process.cwd(), "..", "optrasight-full-platform", "data", "data.db"),
  "data.db",
  "data/data.db",
].filter(Boolean);
const TARGET_DBS = ["data.db", "data/data.db"].filter((p, ix, arr) => arr.indexOf(p) === ix && existsSync(p));
const PORTRAITS_DIR = resolve(process.cwd(), "data", "portraits");
const PUBLIC_CURATED_DIR = resolve(process.cwd(), "data", "public", "portraits", "curated-source");
const RUNTIME_CURATED_DIR = join(PORTRAITS_DIR, "curated-source");
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
  return String(value || "").toLowerCase().replace(/&/g, "and").replace(/[^a-z0-9]+/g, "");
}

function parseJson(value, fallback) {
  try { return JSON.parse(value || ""); } catch { return fallback; }
}

function sourcePathFor(row) {
  const urlPath = String(row.portrait_url || "").split("?")[0];
  const file = urlPath.startsWith("/portraits/") ? urlPath.slice("/portraits/".length) : `${row.id}.png`;
  return join(PORTRAITS_DIR, file);
}

function sourcePathFromDb(dbPath, row) {
  const urlPath = String(row.portrait_url || "").split("?")[0];
  const file = urlPath.startsWith("/portraits/") ? urlPath.slice("/portraits/".length) : `${row.id}.png`;
  const base = resolve(dbPath, "..");
  const candidates = [
    join(base, "data", "portraits", file),
    join(base, "portraits", file),
  ];
  return candidates.find((candidate) => existsSync(candidate)) || candidates[0];
}

const portraitByKey = new Map();

function rememberPortrait(keys, match) {
  for (const key of keys) {
    if (key && !portraitByKey.has(key)) portraitByKey.set(key, match);
  }
}

function keysForRow(row, opts = {}) {
  const keys = new Set([norm(row.primary_name)]);
  if (opts.includeAliases === true) {
    for (const alias of parseJson(row.aliases, [])) keys.add(norm(alias));
  }
  for (const [alias, canonical] of aliasPairs) {
    if (keys.has(canonical)) keys.add(alias);
    if (keys.has(alias)) keys.add(canonical);
  }
  return keys;
}

function loadRootStyleSources() {
  for (const dbPath of ROOT_STYLE_SOURCE_DBS) {
    if (!existsSync(dbPath)) continue;
    const sourceDb = new Database(dbPath, { readonly: true });
    sourceDb.pragma("busy_timeout = 10000");
    const hasThreatActors = sourceDb.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'threat_actors'").get();
    if (!hasThreatActors) {
      sourceDb.close();
      continue;
    }
    const rows = sourceDb.prepare(`
      SELECT id, profile_id, primary_name, aliases, portrait_url, portrait_generated_at
        FROM threat_actors
       WHERE portrait_url IS NOT NULL AND portrait_url != ''
         AND portrait_url LIKE '/portraits/%.png%'
         AND portrait_url NOT LIKE '/portraits/curated-source/%'
       ORDER BY portrait_generated_at DESC
    `).all();
    for (const row of rows) {
      const src = dbPath === SOURCE_DB ? sourcePathFor(row) : sourcePathFromDb(dbPath, row);
      if (!existsSync(src)) continue;
      const match = {
        source: "root-style",
        src,
        sourceName: row.primary_name,
      };
      // Root-style portraits are copied from live DB rows. They are safe only
      // for the source row's primary actor name plus explicit aliasPairs above;
      // broad alias matching can map unrelated synthetic profiles such as
      // "titan" to another actor's portrait.
      rememberPortrait(keysForRow(row, { includeAliases: false }), match);
    }
    sourceDb.close();
  }
}

function loadCuratedFallbacks() {
  if (!existsSync(PUBLIC_CURATED_DIR)) return;
  mkdirSync(RUNTIME_CURATED_DIR, { recursive: true });
  for (const file of readdirSync(PUBLIC_CURATED_DIR).filter((entry) => entry.toLowerCase().endsWith(".png"))) {
    const src = join(PUBLIC_CURATED_DIR, file);
    const dest = join(RUNTIME_CURATED_DIR, file);
    copyFileSync(src, dest);
    const key = norm(basename(file, ".png"));
    if (portraitByKey.has(key)) continue;
    portraitByKey.set(key, {
      source: "curated-source",
      src,
      publicUrl: `/portraits/curated-source/${file}?v=${cacheBust}`,
    });
  }
}

loadRootStyleSources();
// Do not map root-style UUID portraits from the public manifest alone. That
// manifest is a file pack inventory, not visual truth; several generated images
// have title plates for different actors. Root-style portraits are trusted only
// when copied from a real DB row with the same primary actor name. Otherwise the
// named curated-source portrait is safer than displaying another actor's art.
loadCuratedFallbacks();

let totalUpdated = 0;
for (const dbPath of TARGET_DBS) {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  const rows = db.prepare("SELECT id, tenant_id, profile_id, primary_name, aliases, portrait_url FROM threat_actors ORDER BY profile_id, tenant_id, id").all();
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
      let match = null;
      for (const key of keysForRow(row, { includeAliases: false })) {
        match = portraitByKey.get(key);
        if (match) break;
      }
      if (!match) continue;
      let publicUrl;
      if (match.source === "root-style") {
        const extension = extname(match.src) || ".png";
        const target = join(PORTRAITS_DIR, `${row.id}${extension}`);
        copyFileSync(match.src, target);
        publicUrl = `/portraits/${row.id}${extension}?v=${cacheBust}`;
      } else {
        publicUrl = match.publicUrl;
      }
      update.run(publicUrl, ts, row.id, row.tenant_id);
      updated++;
    }
  });
  tx();
  db.close();
  totalUpdated += updated;
  console.log(`${dbPath}: linked ${updated}/${rows.length} threat actor rows`);
}

console.log(`Total portrait links repaired: ${totalUpdated}`);
