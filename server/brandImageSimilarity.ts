import sharp from "sharp";

export interface ImageFingerprint {
  width: number;
  height: number;
  aspectRatio: number;
  dhash: string;
  histogram: number[];
  dominantRgb: [number, number, number];
}

export interface ImageSimilarityResult {
  score: number;
  dhashSimilarity: number;
  histogramSimilarity: number;
  colorSimilarity: number;
  aspectSimilarity: number;
  templateSimilarity?: number;
  templateBox?: { x: number; y: number; width: number; height: number; scale: number };
}

function bitStringToHex(bits: string): string {
  let out = "";
  for (let i = 0; i < bits.length; i += 4) {
    out += parseInt(bits.slice(i, i + 4).padEnd(4, "0"), 2).toString(16);
  }
  return out;
}

function hexToBits(hex: string): string {
  return hex.split("").map((ch) => parseInt(ch, 16).toString(2).padStart(4, "0")).join("");
}

function histogramIndex(r: number, g: number, b: number): number {
  const rb = Math.min(3, Math.floor(r / 64));
  const gb = Math.min(3, Math.floor(g / 64));
  const bb = Math.min(3, Math.floor(b / 64));
  return (rb * 16) + (gb * 4) + bb;
}

export async function fingerprintImage(buffer: Buffer): Promise<ImageFingerprint> {
  const image = sharp(buffer, { limitInputPixels: 24_000_000 }).rotate();
  const meta = await image.metadata();
  const width = meta.width || 1;
  const height = meta.height || 1;

  const gray = await image
    .clone()
    .resize(9, 8, { fit: "fill" })
    .greyscale()
    .raw()
    .toBuffer();
  let bits = "";
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      const i = y * 9 + x;
      bits += gray[i] > gray[i + 1] ? "1" : "0";
    }
  }

  const rgb = await image
    .clone()
    .resize(64, 64, { fit: "inside", withoutEnlargement: true })
    .removeAlpha()
    .raw()
    .toBuffer();
  const histogram = Array.from({ length: 64 }, () => 0);
  let total = 0;
  let rSum = 0;
  let gSum = 0;
  let bSum = 0;
  for (let i = 0; i + 2 < rgb.length; i += 3) {
    const r = rgb[i];
    const g = rgb[i + 1];
    const b = rgb[i + 2];
    histogram[histogramIndex(r, g, b)] += 1;
    rSum += r;
    gSum += g;
    bSum += b;
    total += 1;
  }
  if (total > 0) {
    for (let i = 0; i < histogram.length; i++) histogram[i] = histogram[i] / total;
  }

  return {
    width,
    height,
    aspectRatio: width / Math.max(1, height),
    dhash: bitStringToHex(bits),
    histogram,
    dominantRgb: total > 0
      ? [Math.round(rSum / total), Math.round(gSum / total), Math.round(bSum / total)]
      : [0, 0, 0],
  };
}

function hammingSimilarity(aHex: string, bHex: string): number {
  const a = hexToBits(aHex);
  const b = hexToBits(bHex);
  const n = Math.min(a.length, b.length);
  if (!n) return 0;
  let diff = 0;
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) diff += 1;
  return 1 - (diff / n);
}

function histogramIntersection(a: number[], b: number[]): number {
  const n = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < n; i++) sum += Math.min(a[i] || 0, b[i] || 0);
  return Math.max(0, Math.min(1, sum));
}

function colorSimilarity(a: [number, number, number], b: [number, number, number]): number {
  const dr = a[0] - b[0];
  const dg = a[1] - b[1];
  const db = a[2] - b[2];
  const dist = Math.sqrt(dr * dr + dg * dg + db * db);
  return Math.max(0, 1 - dist / 441.68);
}

function aspectSimilarity(a: number, b: number): number {
  const ratio = Math.min(a, b) / Math.max(a, b, 0.0001);
  return Math.max(0, Math.min(1, ratio));
}

export function compareFingerprints(a: ImageFingerprint, b: ImageFingerprint): ImageSimilarityResult {
  const dhashSimilarity = hammingSimilarity(a.dhash, b.dhash);
  const histogramSimilarity = histogramIntersection(a.histogram, b.histogram);
  const color = colorSimilarity(a.dominantRgb, b.dominantRgb);
  const aspect = aspectSimilarity(a.aspectRatio, b.aspectRatio);
  const score = (dhashSimilarity * 0.35) + (histogramSimilarity * 0.35) + (color * 0.2) + (aspect * 0.1);
  return {
    score: Math.round(score * 1000) / 1000,
    dhashSimilarity: Math.round(dhashSimilarity * 1000) / 1000,
    histogramSimilarity: Math.round(histogramSimilarity * 1000) / 1000,
    colorSimilarity: Math.round(color * 1000) / 1000,
    aspectSimilarity: Math.round(aspect * 1000) / 1000,
  };
}

interface GrayImage {
  width: number;
  height: number;
  data: Buffer;
  scale: number;
}

async function screenshotGray(buffer: Buffer): Promise<GrayImage> {
  const meta = await sharp(buffer, { limitInputPixels: 24_000_000 }).metadata();
  const width = meta.width || 1;
  const resizeWidth = Math.min(900, width);
  const scale = resizeWidth / width;
  const { data, info } = await sharp(buffer, { limitInputPixels: 24_000_000 })
    .rotate()
    .resize({ width: resizeWidth, withoutEnlargement: true })
    .greyscale()
    .raw()
    .toBuffer({ resolveWithObject: true });
  return { width: info.width, height: info.height, data, scale };
}

async function templateGray(buffer: Buffer, width: number): Promise<GrayImage | null> {
  try {
    const trimmed = await sharp(buffer, { limitInputPixels: 8_000_000 })
      .rotate()
      .flatten({ background: "#ffffff" })
      .trim({ background: "#ffffff", threshold: 24 })
      .png()
      .toBuffer();
    const meta = await sharp(trimmed).metadata();
    const naturalWidth = meta.width || 1;
    const scale = width / naturalWidth;
    const { data, info } = await sharp(trimmed)
      .resize({ width, withoutEnlargement: false })
      .greyscale()
      .raw()
      .toBuffer({ resolveWithObject: true });
    if (info.width < 12 || info.height < 8 || info.width > 360 || info.height > 260) return null;
    return { width: info.width, height: info.height, data, scale };
  } catch {
    return null;
  }
}

function nccAt(screen: GrayImage, tmpl: GrayImage, x: number, y: number): number {
  const n = tmpl.width * tmpl.height;
  let sumA = 0;
  let sumB = 0;
  let sumAA = 0;
  let sumBB = 0;
  let sumAB = 0;
  for (let ty = 0; ty < tmpl.height; ty++) {
    const sRow = (y + ty) * screen.width + x;
    const tRow = ty * tmpl.width;
    for (let tx = 0; tx < tmpl.width; tx++) {
      const a = screen.data[sRow + tx];
      const b = tmpl.data[tRow + tx];
      sumA += a;
      sumB += b;
      sumAA += a * a;
      sumBB += b * b;
      sumAB += a * b;
    }
  }
  const numerator = sumAB - (sumA * sumB / n);
  const denomA = sumAA - (sumA * sumA / n);
  const denomB = sumBB - (sumB * sumB / n);
  const denom = Math.sqrt(Math.max(0, denomA) * Math.max(0, denomB));
  if (!denom) return 0;
  return Math.max(0, numerator / denom);
}

export async function templateMatchImage(
  screenshotBuffer: Buffer,
  assetBuffer: Buffer,
): Promise<{ score: number; box: { x: number; y: number; width: number; height: number; scale: number } | null }> {
  const screen = await screenshotGray(screenshotBuffer);
  const widths = [32, 48, 64, 88, 112, 144, 184, 232];
  let best = 0;
  let bestBox: { x: number; y: number; width: number; height: number; scale: number } | null = null;
  for (const w of widths) {
    const tmpl = await templateGray(assetBuffer, w);
    if (!tmpl) continue;
    if (tmpl.width >= screen.width || tmpl.height >= screen.height) continue;
    const stride = Math.max(6, Math.floor(Math.min(tmpl.width, tmpl.height) / 5));
    for (let y = 0; y <= screen.height - tmpl.height; y += stride) {
      for (let x = 0; x <= screen.width - tmpl.width; x += stride) {
        const score = nccAt(screen, tmpl, x, y);
        if (score > best) {
          best = score;
          bestBox = {
            x: Math.round(x / screen.scale),
            y: Math.round(y / screen.scale),
            width: Math.round(tmpl.width / screen.scale),
            height: Math.round(tmpl.height / screen.scale),
            scale: Math.round(tmpl.scale * 1000) / 1000,
          };
        }
      }
    }
  }
  return { score: Math.round(best * 1000) / 1000, box: bestBox };
}
