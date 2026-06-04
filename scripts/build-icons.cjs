#!/usr/bin/env node
/**
 * Regenerate raster brand assets from the SVG sources in client/public/.
 *
 * Outputs:
 *   client/public/pwa-192.png          (PWA icon)
 *   client/public/pwa-512.png          (PWA icon)
 *   client/public/apple-touch-icon.png (180x180)
 *   client/public/favicon-32.png       (32x32)
 *   client/public/favicon-16.png       (16x16)
 *   client/public/og-image.png         (1200x630 link preview)
 *
 * Usage:
 *   node scripts/build-icons.cjs
 *
 * Requires:
 *   - playwright (already a dev dep)
 *   - SVG sources at client/public/{logo,favicon,wordmark}.svg
 */
const { chromium } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");

const PUBDIR = path.resolve(__dirname, "..", "client", "public");

async function rasterise(page, svgRelPath, outRelPath, size) {
  const svg = fs.readFileSync(path.join(PUBDIR, svgRelPath), "utf8");
  const html = `<!doctype html><html><head><style>
    html, body { margin: 0; padding: 0; background: transparent; }
    #wrap { width: ${size}px; height: ${size}px; }
    #wrap svg { width: 100%; height: 100%; display: block; }
  </style></head><body><div id="wrap">${svg}</div></body></html>`;
  await page.setContent(html, { waitUntil: "load" });
  await page.setViewportSize({ width: size, height: size });
  const el = await page.$("#wrap");
  await el.screenshot({
    path: path.join(PUBDIR, outRelPath),
    omitBackground: true,
  });
  console.log(`  ✓ ${outRelPath} (${size}x${size})`);
}

async function buildOgImage(page) {
  const wm = fs.readFileSync(path.join(PUBDIR, "wordmark.svg"), "utf8");
  const html = `<!doctype html><html><head><style>
    html, body { margin: 0; padding: 0; background: #0F172A; font-family: system-ui; }
    .card {
      width: 1200px; height: 630px;
      background: linear-gradient(135deg, #0F172A 0%, #1E1B4B 100%);
      display: flex; flex-direction: column; justify-content: center;
      padding: 80px; color: #fff;
    }
    .mark { width: 640px; }
    .tag {
      margin-top: 40px; font-size: 32px;
      color: #A5B4FC; font-weight: 500; letter-spacing: -0.5px;
    }
    .tag b { color: #22D3EE; font-weight: 600; }
  </style></head><body><div class="card">
    <div class="mark">${wm.replace(/fill="#0F172A"/g, 'fill="#FFFFFF"')}</div>
    <div class="tag">Omnidirectional ASM &middot; Brand monitoring &middot; <b>Threat intelligence</b></div>
  </div></body></html>`;
  await page.setContent(html, { waitUntil: "load" });
  await page.setViewportSize({ width: 1200, height: 630 });
  await (await page.$(".card")).screenshot({
    path: path.join(PUBDIR, "og-image.png"),
  });
  console.log("  ✓ og-image.png (1200x630)");
}

(async () => {
  console.log("Rasterising OptraSight brand assets…");
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ deviceScaleFactor: 1 });
  const page = await ctx.newPage();

  await rasterise(page, "logo.svg", "pwa-192.png", 192);
  await rasterise(page, "logo.svg", "pwa-512.png", 512);
  await rasterise(page, "logo.svg", "apple-touch-icon.png", 180);
  await rasterise(page, "favicon.svg", "favicon-32.png", 32);
  await rasterise(page, "favicon.svg", "favicon-16.png", 16);
  await buildOgImage(page);

  await browser.close();
  console.log("Done.");
})();
