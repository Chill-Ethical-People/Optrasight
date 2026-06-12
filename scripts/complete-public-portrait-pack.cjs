#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const sharp = require("sharp");
const { createHash } = require("crypto");

const ROOT = path.resolve(__dirname, "..");
const GENERATED_ROOT = path.resolve(process.env.HOME || "", ".codex", "generated_images");
const CEP_MARK = path.resolve(process.env.HOME || "", "Downloads", "Chill Ethical People", "brand", "cep-mark-on-light.svg");
const OUT_DIR = path.join(ROOT, "data", "public", "portraits", "curated-source");
const ROOT_STYLE_DIR = path.join(ROOT, "data", "public", "portraits", "root-style");
const MANIFEST_PATH = path.join(OUT_DIR, "manifest.json");

const ACCEPTED_SOURCES = new Map([
  ["Evil Corp", "019e827a-2639-7bd0-bd5f-6bee01543cca/ig_055afb3885fb19b8016a1d4efbfac88191b71ee6b78c0b2d27.png"],
  ["Lazarus Group", "019e827a-2639-7bd0-bd5f-6bee01543cca/ig_055afb3885fb19b8016a1d4fb247488191b6e7587487e643ab.png"],
  ["APT43", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a108f5f782481919502b31344222b79.png"],
  ["Andariel", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1c433c43f88191b5f3235c93f7df05.png"],
  ["UNC3886", "019e827a-2639-7bd0-bd5f-6bee01543cca/ig_055afb3885fb19b8016a1d53627e0081919eb7611233e162ca.png"],
  ["Sandworm Team", "019e827a-2639-7bd0-bd5f-6bee01543cca/ig_055afb3885fb19b8016a1d547677bc8191b5e7dadfe88999ae.png"],
  ["FIN6", "019e827a-2639-7bd0-bd5f-6bee01543cca/ig_055afb3885fb19b8016a1d561da0088191b58fdf23b595a6ad.png"],
  ["Agrius", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1090ef80348191a4a3c8508c3324e6.png"],
  ["BlackByte", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1cd19f5b648191aded71e2a87b80d3.png"],
  ["Cactus", "019e827a-2639-7bd0-bd5f-6bee01543cca/ig_055afb3885fb19b8016a1d5c240e688191aa3bee1963bef759.png"],
  ["TA577", "019e827a-2639-7bd0-bd5f-6bee01543cca/ig_055afb3885fb19b8016a1d5cd9b3088191853252d9670d036b.png"],
  ["Storm-0501", "019e827a-2639-7bd0-bd5f-6bee01543cca/ig_055afb3885fb19b8016a1d5de159c48191b808671485c2f561.png"],
]);

const ROOT_STYLE_BACKDROP_SOURCES = new Map([
  ["nightspire", "c8237cf7-1709-4005-b64e-37a47efe56e3.webp"],
  ["titan", "b776028e-4222-4c1c-8788-18da211f368a.webp"],
  ["apt73", "d11d63e7-e635-4d4d-856c-abcb898a6dda.webp"],
  ["pear", "e60323d1-302e-4f30-970e-be0d2fae6f32.webp"],
  ["termite", "a2f17aae-f9c7-4058-a650-939fc1009d62.webp"],
  ["gunra", "26279756-ca54-4940-916e-d5adddf51d42.webp"],
]);

const TARGETS = [
  "Evil Corp",
  "Lazarus Group",
  "APT43",
  "Andariel",
  "UNC3886",
  "Sandworm Team",
  "FIN6",
  "Agrius",
  "BlackByte",
  "Cactus",
  "TA577",
  "Storm-0501",
  "nightspire",
  "titan",
  "apt73",
  "pear",
  "termite",
  "gunra",
  "0day Syndicate",
];

const ACTOR_KIND = new Map([
  ["Evil Corp", "Organized Cybercrime"],
  ["Lazarus Group", "Nation-State"],
  ["APT43", "Nation-State"],
  ["Andariel", "Nation-State"],
  ["UNC3886", "Nation-State"],
  ["Sandworm Team", "Nation-State"],
  ["FIN6", "Organized Cybercrime"],
  ["Agrius", "Nation-State"],
  ["BlackByte", "Ransomware-as-a-Service"],
  ["Cactus", "Ransomware-as-a-Service"],
  ["TA577", "Organized Cybercrime"],
  ["Storm-0501", "Ransomware Affiliate"],
  ["nightspire", "Ransomware"],
  ["titan", "Ransomware"],
  ["apt73", "Threat Cluster"],
  ["pear", "Ransomware"],
  ["termite", "Ransomware"],
  ["gunra", "Ransomware"],
  ["0day Syndicate", "Threat Cluster"],
]);

function fileNameFor(actor) {
  return `${actor.replace(/&/g, "and").replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "")}.png`;
}

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fallbackSvg(actor) {
  const hash = createHash("sha256").update(actor).digest();
  const hue1 = hash[0] % 360;
  const hue2 = (hue1 + 86 + (hash[1] % 92)) % 360;
  const kind = ACTOR_KIND.get(actor) || "Threat Actor";
  const initials = actor
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "?";
  const nodes = Array.from({ length: 14 }, (_, i) => {
    const x = 96 + ((hash[i] / 255) * 832);
    const y = 120 + ((hash[i + 14] / 255) * 560);
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${4 + (hash[i + 2] % 8)}" fill="#22D3EE" opacity="0.45"/>`;
  }).join("");
  const lines = Array.from({ length: 11 }, (_, i) => {
    const x1 = 96 + ((hash[i] / 255) * 832);
    const y1 = 120 + ((hash[i + 4] / 255) * 560);
    const x2 = 96 + ((hash[i + 8] / 255) * 832);
    const y2 = 120 + ((hash[i + 12] / 255) * 560);
    return `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"/>`;
  }).join("");

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="hsl(${hue1},58%,11%)"/>
      <stop offset="1" stop-color="hsl(${hue2},72%,17%)"/>
    </linearGradient>
    <radialGradient id="signal" cx="50%" cy="35%" r="48%">
      <stop offset="0" stop-color="rgba(34,211,238,0.5)"/>
      <stop offset="1" stop-color="rgba(34,211,238,0)"/>
    </radialGradient>
  </defs>
  <rect width="1024" height="1024" fill="url(#bg)"/>
  <rect width="1024" height="1024" fill="url(#signal)"/>
  <g stroke="#EEF0FE" stroke-width="2" opacity="0.18">${lines}</g>
  <g>${nodes}</g>
  <g transform="translate(512 408)">
    <circle r="226" fill="rgba(15,23,42,0.72)" stroke="#4F46E5" stroke-width="14"/>
    <circle r="174" fill="rgba(3,7,18,0.78)" stroke="#22D3EE" stroke-width="6"/>
    <path d="M-92 -44 C-38 -132 38 -132 92 -44 L56 104 C22 154 -22 154 -56 104 Z" fill="rgba(79,70,229,0.68)" stroke="#EEF0FE" stroke-width="6"/>
    <text x="0" y="34" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-weight="900" font-size="88" fill="#EEF0FE">${esc(initials)}</text>
  </g>
  <rect x="82" y="774" width="860" height="144" fill="rgba(3,7,18,0.84)" stroke="#22D3EE" stroke-width="3"/>
  <text x="512" y="838" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-weight="900" font-size="52" fill="#EEF0FE">${esc(actor)}</text>
  <text x="512" y="884" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-weight="700" font-size="25" fill="#22D3EE">${esc(kind)}</text>
</svg>`;
}

async function watermark(input, output) {
  const meta = await sharp(input).metadata();
  const side = Math.min(meta.width || 1024, meta.height || 1024);
  const markSize = Math.max(72, Math.round(side * 0.085));
  const margin = Math.max(22, Math.round(side * 0.025));
  const mark = await sharp(CEP_MARK)
    .resize(markSize, markSize, { fit: "contain" })
    .png()
    .toBuffer();
  await sharp(input)
    .png()
    .composite([{ input: mark, gravity: "southeast", left: (meta.width || side) - markSize - margin, top: (meta.height || side) - markSize - margin }])
    .toFile(output);
}

async function renderRootStylePortrait(actor, source, output) {
  const kind = ACTOR_KIND.get(actor) || "Threat Actor";
  const title = esc(actor);
  const subtitle = esc(kind);
  const plate = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
    <defs>
      <linearGradient id="plate" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0" stop-color="#020617" stop-opacity="1"/>
        <stop offset="0.55" stop-color="#020617" stop-opacity="1"/>
        <stop offset="1" stop-color="#111827" stop-opacity="1"/>
      </linearGradient>
      <linearGradient id="edge" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0" stop-color="#22D3EE"/>
        <stop offset="1" stop-color="#EF4444"/>
      </linearGradient>
    </defs>
    <rect x="0" y="724" width="1024" height="300" fill="url(#plate)"/>
    <rect x="0" y="724" width="1024" height="4" fill="url(#edge)" opacity="0.72"/>
    <rect x="34" y="774" width="956" height="190" fill="none" stroke="url(#edge)" stroke-width="3" opacity="0.32"/>
    <text x="512" y="866" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-weight="900" font-size="${actor.length > 12 ? 78 : 92}" fill="#F8FAFC">${title}</text>
    <text x="512" y="920" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-weight="800" font-size="25" letter-spacing="4" fill="#22D3EE">${subtitle}</text>
  </svg>`);
  const base = await sharp(source)
    .resize(1024, 1024, { fit: "cover", position: "attention" })
    .composite([{ input: plate, left: 0, top: 0 }])
    .png()
    .toBuffer();
  await watermark(base, output);
}

function loadManifest() {
  try {
    return JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  } catch {
    return {};
  }
}

async function main() {
  if (!fs.existsSync(CEP_MARK)) throw new Error(`CEP watermark not found: ${CEP_MARK}`);
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const added = [];
  const generated = [];
  const missing = [];
  for (const actor of TARGETS) {
    const out = path.join(OUT_DIR, fileNameFor(actor));
    const rel = ACCEPTED_SOURCES.get(actor);
    if (rel) {
      const source = path.join(GENERATED_ROOT, rel);
      if (!fs.existsSync(source)) {
        missing.push(actor);
        continue;
      }
      await watermark(source, out);
      added.push(actor);
      continue;
    }
    const backdrop = ROOT_STYLE_BACKDROP_SOURCES.get(actor);
    if (backdrop) {
      const source = path.join(ROOT_STYLE_DIR, backdrop);
      if (!fs.existsSync(source)) {
        missing.push(actor);
        continue;
      }
      await renderRootStylePortrait(actor, source, out);
      added.push(actor);
      continue;
    }
    const svg = Buffer.from(fallbackSvg(actor));
    await watermark(svg, out);
    generated.push(actor);
  }

  const files = fs.readdirSync(OUT_DIR)
    .filter((file) => file.toLowerCase().endsWith(".png"))
    .sort();
  const manifest = {
    ...loadManifest(),
    generatedAt: new Date().toISOString(),
    files,
    count: files.length,
    watermark: "CEP avatar mark, lower-right, baked into image at approximately 8.5% of portrait size",
    recoveredPortraits: added,
    deterministicFallbackPortraits: generated,
    missingSourcePortraits: missing,
  };
  fs.writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);

  console.log(`[public-portraits] watermarked accepted=${added.length} fallback=${generated.length} missing=${missing.length}`);
  if (missing.length) console.log(`[public-portraits] missing sources: ${missing.join(", ")}`);
  console.log(`[public-portraits] pack files=${files.length}`);
}

main().catch((err) => {
  console.error(`[public-portraits] ${err?.message || err}`);
  process.exit(1);
});
