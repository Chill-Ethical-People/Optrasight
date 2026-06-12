#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const sharp = require("sharp");
const Database = require("better-sqlite3");

const ROOT = path.resolve(__dirname, "..");
const DB_PATH = path.join(ROOT, "data.db");
const RUNTIME_PORTRAITS = path.join(ROOT, "data", "portraits");
const OUT_DIR = path.join(ROOT, "data", "public", "portraits", "root-style");
const MANIFEST_PATH = path.join(OUT_DIR, "manifest.json");
const CEP_MARK = path.resolve(process.env.HOME || "", "Downloads", "Chill Ethical People", "brand", "cep-mark-on-light.svg");
const OUTPUT_EXT = "webp";
const OUTPUT_SIZE = 900;

function rootPortraitPathFor(row) {
  const urlPath = String(row.portrait_url || "").split("?")[0];
  const file = urlPath.startsWith("/portraits/")
    ? urlPath.slice("/portraits/".length)
    : `${row.id}.png`;
  if (file.includes("/")) return null;
  return path.join(RUNTIME_PORTRAITS, file);
}

async function watermark(input, output) {
  const width = OUTPUT_SIZE;
  const height = OUTPUT_SIZE;
  const side = OUTPUT_SIZE;
  const markSize = Math.max(72, Math.round(side * 0.085));
  const margin = Math.max(22, Math.round(side * 0.025));
  const mark = await sharp(CEP_MARK)
    .resize(markSize, markSize, { fit: "contain" })
    .png()
    .toBuffer();
  await sharp(input)
    .resize(OUTPUT_SIZE, OUTPUT_SIZE, { fit: "cover", position: "attention" })
    .composite([{ input: mark, left: width - markSize - margin, top: height - markSize - margin }])
    .webp({ quality: 84, effort: 5 })
    .toFile(output);
}

async function main() {
  if (!fs.existsSync(DB_PATH)) throw new Error(`Runtime DB not found: ${DB_PATH}`);
  if (!fs.existsSync(CEP_MARK)) throw new Error(`CEP watermark not found: ${CEP_MARK}`);
  fs.mkdirSync(OUT_DIR, { recursive: true });
  for (const file of fs.readdirSync(OUT_DIR)) {
    if (file.toLowerCase().endsWith(".png") || file.toLowerCase().endsWith(".webp")) {
      fs.rmSync(path.join(OUT_DIR, file));
    }
  }

  const db = new Database(DB_PATH, { readonly: true });
  const rows = db.prepare(`
    SELECT id, profile_id, primary_name, portrait_url
      FROM threat_actors
     WHERE portrait_url IS NOT NULL
       AND portrait_url != ''
       AND portrait_url LIKE '/portraits/%.png%'
       AND portrait_url NOT LIKE '/portraits/curated-source/%'
     ORDER BY profile_id, primary_name, id
  `).all();
  db.close();

  const byId = new Map(rows.map((row) => [row.id, row]));
  const written = [];
  const missing = [];
  for (const row of byId.values()) {
    const source = rootPortraitPathFor(row);
    if (!source || !fs.existsSync(source)) {
      missing.push({ id: row.id, profileId: row.profile_id, name: row.primary_name });
      continue;
    }
    const file = `${row.id}.${OUTPUT_EXT}`;
    await watermark(source, path.join(OUT_DIR, file));
    written.push({ file, profileId: row.profile_id, name: row.primary_name });
  }

  const manifest = {
    generatedAt: new Date().toISOString(),
    count: written.length,
    format: OUTPUT_EXT,
    pixelSize: `${OUTPUT_SIZE}x${OUTPUT_SIZE}`,
    watermark: "CEP mark, lower-right, baked into image at approximately 8.5% of portrait size",
    source: "Runtime root-style TAP portraits from data/portraits, exported for public BatchOne setup",
    files: written,
    missing,
  };
  fs.writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);

  console.log(`[public-root-portraits] watermarked=${written.length} missing=${missing.length}`);
  if (missing.length) {
    console.log(`[public-root-portraits] missing=${missing.slice(0, 12).map((row) => `${row.profileId}:${row.name}`).join(", ")}${missing.length > 12 ? ", ..." : ""}`);
  }
}

main().catch((err) => {
  console.error(`[public-root-portraits] ${err?.message || err}`);
  process.exit(1);
});
