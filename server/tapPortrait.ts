// v2.32 — AI-generated portraits per threat actor.
//
// Generates a stylized, editorial portrait for each Threat Actor Profile using
// `asi-generate-image` (gpt_image_2). Each portrait is seeded from the actor's
// canonical attributes (name, threat level, actor type, sponsorship, origin)
// so the visual language is consistent across actors but uniquely composed
// per profile.
//
// The CLI runs out-of-process via execFile to keep the dashboard event-loop
// free during the 15–40s generation window. Concurrent calls for the SAME
// actor id are coalesced through an in-process Promise cache.
//
// Output is saved to `data/portraits/<actor-id>.png` and the relative URL
// `/portraits/<actor-id>.png` is persisted on the row. The Express server
// serves the `/portraits/*` prefix as static files.

import { execFile } from "node:child_process";
import { mkdirSync, existsSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import type { ThreatActorDTO } from "@shared/schema";
import { storage } from "./storage";
import { liveGenerateImage } from "./aiLive";

const execFileP = promisify(execFile);

// data/portraits lives next to the SQLite DB so a single backup snapshot
// captures both the DB and the rendered images.
const PORTRAITS_DIR = resolve(process.cwd(), "data", "portraits");
function ensureDir() {
  if (!existsSync(PORTRAITS_DIR)) {
    mkdirSync(PORTRAITS_DIR, { recursive: true });
  }
}

export class PortraitGeneratorUnavailableError extends Error {
  name = "PortraitGeneratorUnavailableError";
  tool = "asi-generate-image";
  installHint = "Install or expose the asi-generate-image command on PATH, or upload/import generated portrait PNGs manually.";
  constructor(message = "AI portrait generator is unavailable: asi-generate-image is not installed or not on PATH.") {
    super(message);
  }
}

/** Coalesce duplicate concurrent requests for the same actor. */
const inFlight = new Map<string, Promise<string>>();

function isTapPortraitProvider(provider: { provider: string }): boolean {
  return provider.provider === "openai" || provider.provider === "azure-openai" || provider.provider === "gemini";
}

/** Build the prompt from the actor profile.
 * Produces the approved OptraSight TAP poster language: fictional avatar,
 * dark cyber-dossier environment, graphic-novel detail, and a lower-third title.
 */
export function buildPortraitPrompt(a: ThreatActorDTO): string {
  const level = (a.threatLevel || "MODERATE").toUpperCase();
  const palette = (() => {
    if (level === "CRITICAL" || level === "SEVERE")
      return "obsidian black, crimson warning accents, cold cyan rim light, bone-white dossier glow";
    if (level === "HIGH")
      return "obsidian black, steel blue, glacier cyan, sharp red signal accents, pale document light";
    if (level === "MODERATE" || level === "MEDIUM")
      return "charcoal black, steel blue, cyan telemetry light, muted amber threat highlights";
    if (level === "LOW")
      return "graphite black, teal-cyan signal light, desaturated steel, restrained red accents";
    return "deep indigo and cyan with charcoal shadows";
  })();

  const archetype = (() => {
    const t = (a.actorType || "Unknown").toLowerCase();
    if (t.includes("nation")) return "a fictional nonhuman espionage construct built from diplomatic folders, satellite arcs, access tokens, and dark infrastructure panels";
    if (t.includes("ransom") || t.includes("affiliate") || t.includes("crime"))
      return "a fictional extortion avatar formed from encrypted archive blocks, vault doors, ransom-note paper shards, and leak-site infrastructure";
    if (t.includes("hacktivist")) return "a fictional disruption avatar made of torn manifesto paper, network shards, and masked civic-broadcast geometry";
    if (t.includes("insider")) return "a fictional corporate access phantom assembled from badge fragments, file cabinets, and shadowed workstation glass";
    if (t.includes("script") || t.includes("kid")) return "a fictional chaotic toolsmith avatar built from cracked terminals, disposable scripts, and glitching test rigs";
    return "a fictional cyber adversary avatar assembled from dossier shelves, network routes, and abstract command infrastructure";
  })();

  const motif = (() => {
    const m = (a.motivation || []).map((s) => s.toLowerCase()).join(" ");
    if (m.includes("espionage")) return "background of blank diplomatic folders, satellite dish silhouettes, cyber map rings, and dark telecom vaults";
    if (m.includes("financ")) return "background of blank ledger blocks, payment-terminal fragments, vault geometry, and abstract transaction arcs";
    if (m.includes("destruction") || m.includes("disrupt")) return "background of broken infrastructure panels, power-grid shards, and warning-line telemetry";
    if (m.includes("ideolog") || m.includes("political")) return "background of torn blank posters, broadcast-grid panels, and protest-banner fragments without readable slogans";
    return "background of blank dossier shelves, circuit-board panels, abstract data rings, and dark-web archive blocks";
  })();

  const composition = "square 1:1 OptraSight TAP card poster, centered actor portrait with enough safe margin for circular and rounded-rectangle crops, low-angle or three-quarter view, varied full-figure or half-figure pose, strong hand or object gesture, jagged asymmetrical silhouette, diagonal foreground archive blocks, dramatic cyan rim light, crisp ink outlines, painterly digital illustration, bold graphic novel cyber poster, textured print grain, premium threat-intel dossier aesthetic";

  return [
    "Use case: stylized-concept.",
    "Asset type: square 1:1 threat actor portrait for OptraSight TAP card.",
    `Primary request: Create a fictional editorial cyber-threat-actor portrait for "${a.primaryName}".`,
    `Subject: ${archetype}; no real person, no celebrity likeness, no cultural caricature.`,
    `Scene/backdrop: ${motif}.`,
    "Style/medium: bold graphic novel cyber poster, painterly digital illustration, crisp ink outlines, high contrast, dramatic cyan rim light, textured print grain, premium threat-intel dossier aesthetic.",
    `Composition/framing: ${composition}.`,
    "Match the current TAP portrait style: dark illustrated dossier-poster, readable lower title band, high-detail fictional avatar, no flat monogram, no generic logo badge, no simple gradient placeholder.",
    `Color palette: ${palette}.`,
    `Text (verbatim): "${a.primaryName}" only, clean readable lower-third title band.`,
    `Hard text rule: only the title ${a.primaryName} may be readable; no console text, file names, numbers, map labels, logos, flags, or extra typography.`,
    "Constraints: fictional avatar only, no real person, no flags, no official seals, no realistic gore, no weapons, no logos, no watermark, no extra words.",
  ].join(" ");
}

/** Run `asi-generate-image` and return the absolute path to the rendered PNG.
 *  The CLI accepts `{prompt, filename, aspect_ratio, model}` as a JSON string
 *  argument and writes the PNG to the current working directory under
 *  `generated_assets/<filename>.png` (or returns the absolute path in stdout).
 *  We work around that by writing into a temp filename inside PORTRAITS_DIR
 *  via `cwd` so the output lands where we want it. */
async function runImageGen(prompt: string, baseName: string): Promise<string> {
  ensureDir();
  const filename = baseName;
  const payload = JSON.stringify({
    prompt,
    filename,
    aspect_ratio: "1:1",
    model: "gpt_image_2",
  });
  // The CLI is `asi-generate-image '<json>'` — we use execFile with a single
  // positional arg so we don't have to worry about shell quoting.
  let stdout = "";
  try {
    const out = await execFileP(
      "asi-generate-image",
      [payload],
      {
        cwd: PORTRAITS_DIR,
        timeout: 300_000, // 5 min hard cap — gpt_image_2 typically finishes in 60-150s
        maxBuffer: 4 * 1024 * 1024,
        env: { ...process.env },
      }
    );
    stdout = out.stdout;
  } catch (e: any) {
    if (e?.code === "ENOENT" || /spawn asi-generate-image ENOENT/i.test(String(e?.message ?? ""))) {
      throw new PortraitGeneratorUnavailableError();
    }
    throw e;
  }
  // The CLI may print either an absolute path or a relative one rooted at cwd.
  // Try to find the file deterministically — first by expected filename, then
  // by parsing stdout for a *.png reference.
  const expected = join(PORTRAITS_DIR, `${filename}.png`);
  if (existsSync(expected)) return expected;
  // Try generated_assets/<filename>.png in cwd (CLI default convention).
  const fallback = join(PORTRAITS_DIR, "generated_assets", `${filename}.png`);
  if (existsSync(fallback)) return fallback;
  // Last resort — parse stdout for the absolute PNG path the CLI prints.
  // The CLI line looks like:  "Image saved to /home/user/workspace/<file>.png (N bytes)"
  const m = stdout.match(/(\/[^\s'"]+\.png)/);
  if (m && existsSync(m[1])) return m[1];
  throw new Error(`asi-generate-image succeeded but no PNG found. stdout: ${stdout.slice(0, 200)}`);
}

export async function getPortraitGeneratorAvailability(tenantId?: string): Promise<{
  available: boolean;
  tool: string;
  installHint: string;
  message?: string;
}> {
  if (tenantId) {
    const provider = storage.resolveAiPortraitProvider(tenantId);
    if (provider && isTapPortraitProvider(provider)) {
      return {
        available: true,
        tool: `${provider.provider}:auto-image-model`,
        installHint: "",
        message: `Using ${provider.label} from AI Setup with an image-capable model selected automatically.`,
      };
    }
  }
  try {
    await execFileP("asi-generate-image", ["--help"], {
      timeout: 10_000,
      maxBuffer: 512 * 1024,
      env: { ...process.env },
    });
    return {
      available: true,
      tool: "asi-generate-image",
      installHint: "",
    };
  } catch (e: any) {
    if (e?.code === "ENOENT" || /spawn asi-generate-image ENOENT/i.test(String(e?.message ?? ""))) {
      const err = new PortraitGeneratorUnavailableError();
      return {
        available: false,
        tool: err.tool,
        installHint: err.installHint,
        message: err.message,
      };
    }
    return {
      available: false,
      tool: "asi-generate-image",
      installHint: "Check the asi-generate-image command and image provider credentials.",
      message: String(e?.message ?? e),
    };
  }
}

/** Generate a portrait for the given actor. Returns the public URL.
 *  Concurrent calls for the same actor id share a single in-flight Promise. */
export async function generateActorPortrait(
  tenantId: string,
  actorId: string,
): Promise<string> {
  const key = `${tenantId}/${actorId}`;
  const existing = inFlight.get(key);
  if (existing) return existing;

  const p = (async () => {
    const actor = storage.getThreatActor(tenantId, actorId);
    if (!actor) throw new Error(`actor ${actorId} not found in tenant ${tenantId}`);

    storage.setThreatActorPortraitStatus(tenantId, actorId, "generating");
    try {
      const prompt = buildPortraitPrompt(actor);
      let absPath: string;
      const provider = storage.resolveAiPortraitProvider(tenantId);
      if (provider && isTapPortraitProvider(provider)) {
        const generated = liveGenerateImage(provider, prompt, { timeoutSeconds: 300 });
        if (!generated.ok || !generated.data) {
          throw new Error(generated.message || "AI provider did not return portrait image data");
        }
        ensureDir();
        absPath = join(PORTRAITS_DIR, `${actorId}.png`);
        writeFileSync(absPath, generated.data);
      } else {
        absPath = await runImageGen(prompt, actorId);
      }

      // Normalize: ensure the file is at PORTRAITS_DIR/<actorId>.png so the
      // public URL is stable and predictable.
      const canonical = join(PORTRAITS_DIR, `${actorId}.png`);
      if (absPath !== canonical) {
        try {
          // Copy bytes (handles cross-dir moves where rename would EXDEV).
          const fs = await import("node:fs");
          fs.copyFileSync(absPath, canonical);
        } catch (e) {
          // If copy fails, fall back to using whatever path the CLI produced.
          console.warn("[tap-portrait] copy fallback", e);
        }
      }

      const publicUrl = `/portraits/${actorId}.png`;
      storage.setThreatActorPortrait(tenantId, actorId, publicUrl);
      return publicUrl;
    } catch (e) {
      storage.setThreatActorPortraitStatus(tenantId, actorId, "failed");
      throw e;
    } finally {
      inFlight.delete(key);
    }
  })();
  inFlight.set(key, p);
  return p;
}

export { PORTRAITS_DIR };
