/**
 * Keyword expansion engine — implements all 14 techniques from
 * SOP Phase 1-2 TI Service Onboarding §6 (Keyword Expansion Methodology).
 *
 * Output is deterministic (no random), idempotent, and bounded.
 * The engine is pure — no I/O. Routes call this and persist results.
 */
import type { KeywordVariant, KeywordExpansionDTO } from "@shared/schema";

// SOP §6.3 — top combosquatting keywords (financial sector additions included)
export const DEFAULT_COMBOSQUAT = [
  "support", "login", "signin", "secure", "security", "my", "account",
  "online", "help", "service", "official", "verify", "verification",
  "banking", "bank", "transfer", "pay", "payment", "rewards", "points",
  "alert", "notice", "notification", "trade", "invest", "funds",
];

// APAC + brand TLDs commonly abused for phishing
export const DEFAULT_TLDS = [
  ".com", ".net", ".io", ".co", ".hk", ".cn", ".sg", ".my", ".tw",
  ".app", ".bank", ".finance", ".ai", ".xyz", ".shop", ".online", ".tech",
];

// QWERTY adjacency map for Technique 4
const QWERTY: Record<string, string> = {
  q: "wa", w: "qeas", e: "wrds", r: "etdf", t: "ryfg", y: "tugh", u: "yihj",
  i: "uojk", o: "ipkl", p: "ol", a: "qwsz", s: "awedxz", d: "serfcx",
  f: "drtgvc", g: "ftyhbv", h: "gyujnb", j: "huiknm", k: "jiolm", l: "kop",
  z: "asx", x: "zsdc", c: "xdfv", v: "cfgb", b: "vghn", n: "bhjm", m: "njk",
};

// Homoglyph/IDN substitutions (Technique 6)
const HOMOGLYPH: Record<string, string[]> = {
  a: ["а", "ɑ"],          // Cyrillic a, Latin alpha
  o: ["о", "ο", "0"],     // Cyrillic, Greek omicron, zero
  e: ["е", "ё"],          // Cyrillic e
  i: ["і", "1", "l"],     // Ukrainian i, one, l
  c: ["с", "ϲ"],          // Cyrillic c, Greek lunate sigma
  p: ["р"],               // Cyrillic p
  x: ["х"],               // Cyrillic x
  l: ["1", "ӏ", "i"],
  s: ["ѕ"],               // Cyrillic s
  k: ["к"],
  m: ["м"],
  n: ["п"],
  g: ["ɡ"],
};

// Soundsquatting pairs (Technique 13) — phonetically equivalent transforms
const SOUND_PAIRS: Array<[RegExp, string]> = [
  [/safe/g, "save"],
  [/save/g, "safe"],
  [/pay/g, "pai"],
  [/pai/g, "pay"],
  [/bank/g, "banque"],
  [/check/g, "cheque"],
  [/credit/g, "kredit"],
  [/secure/g, "sekure"],
  [/account/g, "akount"],
  [/online/g, "onlne"],
  [/buy/g, "by"],
  [/site/g, "sight"],
  [/four/g, "for"],
  [/two/g, "to"],
  [/c/g, "k"],
  [/k/g, "c"],
  [/ph/g, "f"],
  [/f/g, "ph"],
];

// Numbers/ordinals (Technique 14)
const ORDINALS = ["1", "2", "3", "0", "01", "1st", "online1", "247"];

// ---------- Levenshtein distance (iterative DP) ----------
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const m = a.length, n = b.length;
  const dp = new Array(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a[i - 1] === b[j - 1]
        ? prev
        : 1 + Math.min(prev, dp[j - 1], dp[j]);
      prev = tmp;
    }
  }
  return dp[n];
}

function similarity(base: string, variant: string): number {
  const a = base.toLowerCase(), b = variant.toLowerCase();
  if (!a.length || !b.length) return 0;
  const dist = levenshtein(a, b);
  return Math.max(0, 1 - dist / Math.max(a.length, b.length));
}

// Strip TLD when comparing similarity so TLD-swap variants score high
function stripTld(s: string): string {
  const i = s.lastIndexOf(".");
  return i > 0 ? s.slice(0, i) : s;
}

// ---------- 14 techniques ----------
export const TECHNIQUES = [
  { id: "T01-omission",         label: "Character Omission" },
  { id: "T02-insertion",        label: "Character Insertion" },
  { id: "T03-transposition",    label: "Character Transposition" },
  { id: "T04-substitution",     label: "QWERTY Substitution" },
  { id: "T05-vowel-swap",       label: "Vowel Swap" },
  { id: "T06-homoglyph",        label: "Homoglyph / IDN" },
  { id: "T07-bitsquat",         label: "Bitsquatting" },
  { id: "T08-tld-swap",         label: "TLD Swap" },
  { id: "T09-hyphenation",      label: "Hyphenation" },
  { id: "T10-subdomain",        label: "Subdomain Squatting" },
  { id: "T11-combo-prefix",     label: "Combosquat Prefix" },
  { id: "T12-combo-suffix",     label: "Combosquat Suffix" },
  { id: "T13-soundsquat",       label: "Soundsquatting" },
  { id: "T14-ordinal",          label: "Ordinal / Number Swap" },
] as const;
export type TechniqueId = typeof TECHNIQUES[number]["id"];

function technique1Omission(base: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < base.length; i++) {
    out.push(base.slice(0, i) + base.slice(i + 1));
  }
  return out;
}

function technique2Insertion(base: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < base.length; i++) {
    // duplicate adjacent character
    out.push(base.slice(0, i) + base[i] + base[i] + base.slice(i + 1));
  }
  return out;
}

function technique3Transposition(base: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < base.length - 1; i++) {
    const arr = base.split("");
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    out.push(arr.join(""));
  }
  return out;
}

function technique4QwertySub(base: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < base.length; i++) {
    const c = base[i].toLowerCase();
    const neighbors = QWERTY[c];
    if (!neighbors) continue;
    for (const r of neighbors) {
      out.push(base.slice(0, i) + r + base.slice(i + 1));
    }
  }
  return out;
}

function technique5VowelSwap(base: string): string[] {
  const out: string[] = [];
  const vowels = ["a", "e", "i", "o", "u"];
  for (let i = 0; i < base.length; i++) {
    const c = base[i].toLowerCase();
    if (!vowels.includes(c)) continue;
    for (const v of vowels) {
      if (v === c) continue;
      out.push(base.slice(0, i) + v + base.slice(i + 1));
    }
  }
  return out;
}

function technique6Homoglyph(base: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < base.length; i++) {
    const c = base[i].toLowerCase();
    const alts = HOMOGLYPH[c];
    if (!alts) continue;
    for (const a of alts) {
      out.push(base.slice(0, i) + a + base.slice(i + 1));
    }
  }
  return out;
}

function technique7Bitsquat(base: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < base.length; i++) {
    const code = base.charCodeAt(i);
    for (let bit = 0; bit < 7; bit++) {
      const flipped = code ^ (1 << bit);
      // only keep letters/digits
      if ((flipped >= 97 && flipped <= 122) || (flipped >= 48 && flipped <= 57)) {
        out.push(base.slice(0, i) + String.fromCharCode(flipped) + base.slice(i + 1));
      }
    }
  }
  return out;
}

function technique8TldSwap(base: string, tlds: string[]): string[] {
  // base may include TLD or not — strip and re-apply
  const stem = stripTld(base);
  return tlds.map((t) => `${stem}${t}`);
}

function technique9Hyphenation(base: string): string[] {
  const out: string[] = [];
  for (let i = 1; i < base.length; i++) {
    out.push(base.slice(0, i) + "-" + base.slice(i));
  }
  return out;
}

function technique10Subdomain(base: string, suspiciousHosts: string[] = ["secure-update.com", "login-portal.net", "verify-now.co"]): string[] {
  return suspiciousHosts.map((h) => `${base}.${h}`);
}

function technique11ComboPrefix(base: string, combo: string[]): string[] {
  return combo.map((c) => `${c}-${base}`);
}

function technique12ComboSuffix(base: string, combo: string[]): string[] {
  return combo.map((c) => `${base}-${c}`);
}

function technique13Soundsquat(base: string): string[] {
  const out = new Set<string>();
  for (const [rx, repl] of SOUND_PAIRS) {
    const v = base.replace(rx, repl);
    if (v !== base) out.add(v);
  }
  return Array.from(out);
}

function technique14Ordinal(base: string): string[] {
  return ORDINALS.flatMap((o) => [`${base}${o}`, `${o}${base}`]);
}

// ---------- Orchestrator ----------
export interface ExpandOptions {
  base: string[];
  domains?: string[];
  techniques?: string[];
  tldList?: string[];
  combosquatList?: string[];
  sectorModifiers?: string[];
  maxPerTechnique?: number;
}

export function expandKeywords(opts: ExpandOptions): KeywordExpansionDTO {
  const tlds = opts.tldList?.length ? opts.tldList : DEFAULT_TLDS;
  const combo = [...new Set([
    ...(opts.combosquatList?.length ? opts.combosquatList : DEFAULT_COMBOSQUAT),
    ...(opts.sectorModifiers || []),
  ])];
  const cap = opts.maxPerTechnique || 50;
  const enabled = new Set((opts.techniques && opts.techniques.length) ? opts.techniques : TECHNIQUES.map((t) => t.id));

  const inputs = opts.base.map((s) => s.trim().toLowerCase()).filter(Boolean);
  const variantMap = new Map<string, KeywordVariant>(); // variant string -> first occurrence
  const techCount: Record<string, number> = {};

  function add(variant: string, base: string, technique: TechniqueId) {
    const v = variant.trim().toLowerCase();
    if (!v || v === base) return;
    if (variantMap.has(v)) return;
    const sim = similarity(stripTld(base), stripTld(v));
    const techLabel = TECHNIQUES.find((t) => t.id === technique)?.label || technique;
    // riskScore: combine similarity + technique weight
    const techWeight: Record<string, number> = {
      "T01-omission": 0.85, "T02-insertion": 0.85, "T03-transposition": 0.9,
      "T04-substitution": 0.85, "T05-vowel-swap": 0.8, "T06-homoglyph": 0.95,
      "T07-bitsquat": 0.7, "T08-tld-swap": 0.85, "T09-hyphenation": 0.75,
      "T10-subdomain": 0.6, "T11-combo-prefix": 0.8, "T12-combo-suffix": 0.8,
      "T13-soundsquat": 0.75, "T14-ordinal": 0.65,
    };
    const w = techWeight[technique] ?? 0.7;
    const riskScore = Math.round((sim * 0.6 + w * 0.4) * 100);
    variantMap.set(v, {
      variant: v, base, technique, techniqueLabel: techLabel,
      similarity: Math.round(sim * 1000) / 1000,
      riskScore,
    });
    techCount[technique] = (techCount[technique] || 0) + 1;
  }

  // For each input keyword/domain, run each enabled technique
  for (const baseRaw of inputs) {
    const base = baseRaw;
    const stem = stripTld(base);

    if (enabled.has("T01-omission"))      technique1Omission(stem).slice(0, cap).forEach((v) => add(v, base, "T01-omission"));
    if (enabled.has("T02-insertion"))     technique2Insertion(stem).slice(0, cap).forEach((v) => add(v, base, "T02-insertion"));
    if (enabled.has("T03-transposition")) technique3Transposition(stem).slice(0, cap).forEach((v) => add(v, base, "T03-transposition"));
    if (enabled.has("T04-substitution"))  technique4QwertySub(stem).slice(0, cap).forEach((v) => add(v, base, "T04-substitution"));
    if (enabled.has("T05-vowel-swap"))    technique5VowelSwap(stem).slice(0, cap).forEach((v) => add(v, base, "T05-vowel-swap"));
    if (enabled.has("T06-homoglyph"))     technique6Homoglyph(stem).slice(0, cap).forEach((v) => add(v, base, "T06-homoglyph"));
    if (enabled.has("T07-bitsquat"))      technique7Bitsquat(stem).slice(0, cap).forEach((v) => add(v, base, "T07-bitsquat"));
    if (enabled.has("T08-tld-swap"))      technique8TldSwap(stem, tlds).slice(0, cap).forEach((v) => add(v, base, "T08-tld-swap"));
    if (enabled.has("T09-hyphenation"))   technique9Hyphenation(stem).slice(0, cap).forEach((v) => add(v, base, "T09-hyphenation"));
    if (enabled.has("T10-subdomain"))     technique10Subdomain(stem).slice(0, cap).forEach((v) => add(v, base, "T10-subdomain"));
    if (enabled.has("T11-combo-prefix"))  technique11ComboPrefix(stem, combo).slice(0, cap).forEach((v) => add(v, base, "T11-combo-prefix"));
    if (enabled.has("T12-combo-suffix"))  technique12ComboSuffix(stem, combo).slice(0, cap).forEach((v) => add(v, base, "T12-combo-suffix"));
    if (enabled.has("T13-soundsquat"))    technique13Soundsquat(stem).slice(0, cap).forEach((v) => add(v, base, "T13-soundsquat"));
    if (enabled.has("T14-ordinal"))       technique14Ordinal(stem).slice(0, cap).forEach((v) => add(v, base, "T14-ordinal"));
  }

  // Process domains as additional bases — they get all techniques applied to the stem
  for (const dRaw of (opts.domains || [])) {
    const d = dRaw.trim().toLowerCase();
    if (!d) continue;
    const stem = stripTld(d);
    if (enabled.has("T08-tld-swap")) technique8TldSwap(stem, tlds).slice(0, cap).forEach((v) => add(v, d, "T08-tld-swap"));
    if (enabled.has("T11-combo-prefix")) technique11ComboPrefix(stem, combo).slice(0, cap).forEach((v) => add(v, d, "T11-combo-prefix"));
    if (enabled.has("T12-combo-suffix")) technique12ComboSuffix(stem, combo).slice(0, cap).forEach((v) => add(v, d, "T12-combo-suffix"));
  }

  const variants = Array.from(variantMap.values()).sort((a, b) => b.riskScore - a.riskScore);
  const techniques = TECHNIQUES.map((t) => ({
    id: t.id, label: t.label, count: techCount[t.id] || 0,
  }));
  return {
    inputs,
    totalGenerated: variants.length,
    uniqueCount: variants.length,
    variants,
    techniques,
  };
}
