#!/usr/bin/env node

const Database = require("better-sqlite3");
const { execFileSync } = require("node:child_process");
const { copyFileSync, existsSync, mkdirSync, writeFileSync } = require("node:fs");
const { join, resolve } = require("node:path");

process.on("uncaughtException", (err) => {
  console.error(`Portrait generation failed: ${err.message}`);
  process.exit(2);
});

const args = new Set(process.argv.slice(2));
const dryRun = args.has("--dry-run") || !args.has("--generate");
const force = args.has("--force");
const replacePlaceholders = args.has("--replace-placeholders");
const allTenants = args.has("--all-tenants");
const limitArg = process.argv.find((a) => a.startsWith("--limit="));
const limit = limitArg ? Math.max(1, Number(limitArg.split("=")[1]) || 0) : Infinity;
const tenantArg = process.argv.find((a) => a.startsWith("--tenant="));
const tenantSlug = tenantArg ? tenantArg.split("=")[1] : "acme-bank";

const db = new Database("data.db");
const PORTRAITS_DIR = resolve(process.cwd(), "data", "portraits");
const PROMPT_EXPORT = resolve(process.cwd(), "output", "tap-portrait-prompts.jsonl");
const PLACEHOLDER_MAX_BYTES = 800 * 1024;

function j(v) {
  try { return JSON.parse(v || "[]"); } catch { return []; }
}

function palette(level) {
  const v = String(level || "MODERATE").toUpperCase();
  if (v === "CRITICAL" || v === "SEVERE") return "obsidian black, crimson warning accents, cold cyan rim light, bone-white dossier glow";
  if (v === "HIGH") return "obsidian black, steel blue, glacier cyan, sharp red signal accents, pale document light";
  if (v === "LOW") return "graphite black, teal-cyan signal light, desaturated steel, restrained red accents";
  return "charcoal black, steel blue, cyan telemetry light, muted amber threat highlights";
}

const PALETTE_VARIANTS = [
  "jade cyan, oxidized copper, matte black, pale signal white",
  "crimson lacquer, graphite, ember orange, dim monitor green",
  "arctic blue, steel gray, ultraviolet rim light, snowfield white",
  "desert amber, petroleum green, dark umber, hot terminal gold",
  "cold violet, electric teal, charcoal, silver telemetry lines",
  "sodium yellow, deep navy, rust red, bone-white document light",
  "moss green, brass, black glass, pale blue packet trails",
  "magenta alarm glow, carbon black, cyan scanlines, warm paper beige",
  "sea-glass cyan, storm gray, deep indigo, fiber-optic white",
  "maroon, smoked bronze, ash gray, low amber backlight",
];

function stableIndex(value, modulo) {
  let n = 0;
  for (const ch of String(value || "")) n = (n * 31 + ch.charCodeAt(0)) >>> 0;
  return n % modulo;
}

function actorPalette(a) {
  const origin = String(a.assessed_origin || "");
  if (origin === "China") return "jade cyan, ink black, porcelain white highlights, copper packet traces";
  if (origin === "Russia") return "arctic blue, graphite black, deep red accent light, frosted signal white";
  if (origin === "North Korea") return "stark crimson, bunker gray, cold wallet gold, isolated black negative space";
  if (origin === "Iran") return "desert amber, petroleum green, dark umber, warm copper terminal glow";
  return PALETTE_VARIANTS[stableIndex(a.primary_name, PALETTE_VARIANTS.length)] || palette(a.threat_level);
}

function motif(motivation) {
  const m = motivation.map((s) => String(s).toLowerCase()).join(" ");
  if (m.includes("espionage")) return "subtle geopolitical map contours, document fragments, quiet surveillance geometry";
  if (m.includes("financial") || m.includes("extortion")) return "broken currency glyphs, vault-like geometry, cloud exfiltration trails";
  if (m.includes("disrupt") || m.includes("destruct")) return "fragmented infrastructure shards, broken circuitry, blackout textures";
  if (m.includes("ideolog") || m.includes("hacktiv")) return "torn-poster texture, protest-banner fragments, raw urban signal noise";
  return "fragmented circuit-board patterns and glitch artifacts dissolving into haze";
}

const ACTOR_VISUALS = {
  "Qilin": "mythic angular data-beast avatar with horn-like mask plates, rust-orange ESXi server racks, split Windows/Linux terminal panes, and a fractured affiliate network map",
  "Akira": "retro armored cyber-rider avatar with neon panel mask, dual Windows and Linux consoles, dark ESXi hypervisor blocks, and a fast-moving leak-site dossier wall",
  "Cl0p": "file-transfer vault golem avatar, managed file-transfer portals, MOVEit-style file vault corridors, cascading document exfiltration streams, and a precision mass-exploitation targeting grid",
  "Play": "theatrical trickster-mask avatar under a triangular play-button spotlight, Fortinet/RDP access-door abstractions, and dark red stage-curtain shadows",
  "SafePay": "sealed payment-vault guardian avatar with circular safe-door chest plate, clean escrow-ledger panels, sealed safe rings, and controlled double-extortion document stacks",
  "INC Ransom": "industrial incident-response automaton avatar, control-room panels, hospital chart shards, public-sector document stamps rendered as unreadable blocks, and heavy response binders",
  "DragonForce": "armored force-line commander avatar without literal dragon anatomy, cartel-style affiliate command table, pressure-campaign megaphone shapes, and branching partner nodes",
  "RansomHub": "marketplace hub construct avatar with spoke-like shoulders, abandoned portal fragments, transfer arrows feeding into rival infrastructure, and dark kiosk silhouettes",
  "LockBit": "broken-padlock mask avatar, countdown-timer shapes with no readable numbers, seized server cabinet shadows, and layered ransomware builder panels",
  "Black Basta": "black-and-cream paper wraith avatar, Qakbot loader traces, ransom-note paper armor without text, and disciplined enterprise intrusion maps",
  "Scattered Spider": "social-engineering trickster avatar with headset mask and many phone-shard eyes, SIM-swap fragments, SaaS login tiles without logos, and identity maze geometry",
  "FIN7": "payment-card phantom avatar with POS-terminal armor, card-track line halo, Carbanak-style bank-floor geometry, and restaurant/retail receipt shapes without readable text",
  "TA505": "botnet swarm avatar with email-wave cloak, Dridex mesh nodes, file-transfer zero-day blast radius rings, and Cl0p-linked archive vaults",
  "Evil Corp": "luxury-crime ledger phantom avatar, banking trojan control panels, Dridex web inject abstractions, sanctioned finance ledgers, and noir lighting",
  "Lazarus Group": "cold-wallet vault guardian avatar, cryptocurrency exchange vaults, supply-chain package limbs, destructive disk-wipe shards, and austere DPRK-linked intelligence-office geometry without flags",
  "Kimsuky": "policy-folder paper mask avatar, think-tank document wings, spear-phishing envelope shapes, and quiet analyst-desk surveillance geometry",
  "APT43": "nuclear-policy dossier sentinel avatar, research-board halo, credential-harvest lure fragments, diplomatic cables as unreadable strips, and restrained intelligence-collection lighting",
  "Andariel": "defense-lab cybernetic sentinel avatar, healthcare network diagrams, ransomware-and-espionage split plating, and austere bureau-style geometry without insignia",
  "Volt Typhoon": "panda-mask infrastructure phantom avatar, water-energy-transport-communications grid schematics, living-off-the-land admin consoles, and hidden foothold shadows",
  "Salt Typhoon": "deep-sea telecom cable serpent avatar, submarine fiber-optic cable lines, telecom switch rooms, lawful-intercept archive shapes with no text, and carrier routing paths",
  "Flax Typhoon": "edge-device swarm avatar built from appliance shells, long-running botnet nodes, camera/NVR silhouettes, and stealthy access paths across small-office networks",
  "Mustang Panda": "panda-mask diplomatic infiltrator avatar, briefing folders, USB lure shapes, Southeast Asia regional map contours without borders or flags, and compact implant panels",
  "APT41": "dual-faced arcade oni-mask avatar, split espionage/e-crime composition, software supply-chain package boxes, gaming-industry server rooms, and cloud control-plane glyphs",
  "APT40": "maritime chart leviathan-mask avatar, shipyard engineering drawings, university research folders, and coastal intelligence collection atmosphere without flags",
  "APT31": "briefcase-headed long-game espionage avatar, legal/policy target folders, router exploitation diagrams, and patient campaign-board lighting",
  "UNC3886": "hypervisor rootkit construct avatar, VMware virtualization stacks, Fortinet edge appliance armor, kernel rings, and stealth implants buried under hypervisor layers",
  "Turla": "satellite-serpent espionage avatar, satellite-link arcs, diplomatic network shadows, route paths as abstract snake-like lines, and old-school console ambience",
  "APT29": "cloud-tenant ghost avatar, diplomatic mission corridors, OAuth token fragments, and polished intelligence-service stealth lighting",
  "APT28": "staff-map war-mask avatar, credential phishing lure fragments, destructive influence-operation shards, and hard-edged intrusion campaign boards",
  "Sandworm Team": "power-grid wraith avatar, breaker-panel armor, wiper-damaged disk platters, industrial control diagrams, and harsh blackout lighting",
  "Gamaredon": "phishing-inbox storm avatar, Ukrainian government document stacks without flags, noisy commodity malware panels, and high-volume intrusion trails",
  "FIN6": "payment-terminal jackal-mask avatar, hospitality back-office servers, carding marketplace ledgers, and ransomware-adjacent access-broker pathways",
  "MuddyWater": "muddy telecom mirage avatar, Middle East telecom and government network maps without flags, PowerShell console glow, and credential harvest folders",
  "APT35": "conference-lure persona avatar, academic badge shapes without readable text, journalist inbox fragments, cloud mailbox panels, and social-engineering cues",
  "APT33": "aviation-energy wiper avatar, hangar shadows, energy-sector control boards, destructive wiper shard motifs, and spear-phishing runway-light geometry",
  "Agrius": "data-leak mask avatar, wiper-burned hard-drive platters, Middle East enterprise document stacks, and destructive pressure-operation lighting",
  "OilRig": "oil-rig platform guardian avatar, oil-and-gas control room silhouettes, DNS tunnel streams, web shell panels, and long-running regional espionage ambience",
  "Charming Kitten": "persona-building cat-mask avatar, journalist and researcher inbox lures, fake login panels with no readable text, and close-quarters social-engineering tension",
  "BlackCat": "angular black feline-mask ransomware avatar, ALPHV-linked market portal shapes, Rust-coded blocks, and affiliate negotiation rooms without depicting a real animal",
  "Royal": "crown-mask extortion avatar, angular royal geometry, enterprise boardroom shadows, Conti-successor intrusion paths, and high-pressure negotiation table lighting",
  "BianLian": "martial theater-mask extortion avatar, Go-based malware panels, extortion-only document stacks, and legal-threat dossier folders without cultural caricature",
  "BlackSuit": "tailored black-suit mannequin avatar with blank mask, Royal-overlap campaign board, enterprise extortion folders, and polished negotiation-room atmosphere",
  "Hunters International": "tracking-hound mask avatar without realistic animal gore, global target map with pinless contours, hunter-style tracking grid, and stolen-data archive shelves",
  "Medusa": "fiber-optic serpent-cable avatar, leak-site document walls, healthcare/public-sector dossiers, and cold marble cybercrime lighting",
  "8Base": "eight-node extortion automaton avatar, SMB office server closets, Phobos-family code fragments, and compact double-extortion leak shelf",
  "Rhysida": "library-archive moth-mask avatar, academic and healthcare campus network maps, document stacks, ransomware portal panels, and institutional corridor shadows",
  "BlackByte": "byte-block mosaic golem avatar, vulnerable-driver exploitation motifs, dark EDR-bypass console fragments, and compact ransomware operator lighting",
  "Cactus": "encrypted cactus-spine construct avatar, VPN access door, compressed archive stacks, and harsh desert-green terminal light",
  "TA577": "mass-email conveyor phantom avatar, Qakbot/IcedID loader chain panels, access-broker marketplace shadows, and fast phishing-wave motion",
  "Storm-0501": "cloud-identity storm avatar, cloud control-plane takeover, Entra ID-style identity paths without logos, ransomware affiliate switchboard, and cross-cloud pivot arrows",
};

const ACTOR_POSES = {
  "Qilin": "low-angle three-quarter data-beast crouch, one horned mask plate cutting across the foreground, server racks behind at a diagonal",
  "Akira": "dynamic cyber-rider lean, one armored shoulder thrust forward, dossier pages streaking past like speed lines",
  "Cl0p": "heavy vault-golem stance, one file-vault arm raised like a shield while document streams pour from the other side",
  "Play": "stage-performer pose under a triangular spotlight, one hand-like shape pulling a curtain of access-door panels aside",
  "SafePay": "front-left three-quarter vault guardian, one circular safe-ring arm extended toward the viewer, ledger panels behind",
  "INC Ransom": "industrial automaton in a side-profile inspection pose, one clamp-like hand holding an unreadable incident binder",
  "DragonForce": "wide commander stance over a tilted affiliate table, pressure lines radiating from one extended armored arm",
  "RansomHub": "floating hub construct with spoke-like limbs spread asymmetrically, transfer arrows orbiting around the body",
  "LockBit": "broken-padlock mask in a hunched forward lunge, countdown fragments forming a jagged crown",
  "Black Basta": "paper wraith twisting in profile, ransom-note sheets forming a spiral cloak around one shoulder",
  "Scattered Spider": "trickster leaning into frame with headset close to the viewer, phone shards orbiting like many small eyes",
  "FIN7": "side-profile payment-card phantom gliding left to right, POS terminals receding behind in perspective",
  "TA505": "swarm avatar viewed from slightly above, email-wave cloak spreading like wings across the frame",
  "Evil Corp": "noir ledger phantom seated at an oblique finance desk, one gloved ledger-hand pointing to abstract bank panels",
  "Lazarus Group": "low-angle cold-wallet guardian with both vault-plate arms guarding a circular crypto vault halo",
  "Kimsuky": "paper-mask avatar peering from behind stacked policy folders, envelope shapes fanning outward",
  "APT43": "top-down dossier-table view, nuclear-policy sentinel emerging from research boards and cable strips",
  "Andariel": "split-plated sentinel turning away in three-quarter back view, one side lab-blue and one side ransom-crimson",
  "Volt Typhoon": "floating panda-mask infrastructure phantom above layered utility maps, one tendril touching a grid node",
  "Salt Typhoon": "telecom cable serpent in an S-curve across the frame, head in profile beside a switch-room doorway",
  "Flax Typhoon": "edge-device swarm forming a humanoid outline from many appliances, camera/NVR shells orbiting unevenly",
  "Mustang Panda": "diplomatic infiltrator in a low crouch over folders, one USB-lure talisman held near the foreground",
  "APT41": "dual-faced arcade mask split diagonally, one side lunging forward while the other recedes into cloud panels",
  "APT40": "maritime leviathan-mask rising from blueprint waves, body angled upward from bottom-left to top-right",
  "APT31": "briefcase-headed avatar walking away in profile, router diagrams trailing like a cape",
  "UNC3886": "hypervisor construct viewed from below, kernel rings orbiting around a raised rootkit core",
  "Turla": "satellite-serpent coiled around a diplomatic network globe, head turned in a calm side profile",
  "APT29": "cloud ghost half-emerging from a corridor vanishing point, one token-fragment hand dissolving",
  "APT28": "war-mask avatar leaning over a staff-map table, route arcs crossing the foreground",
  "Sandworm Team": "power-grid wraith with breaker-panel arms spread wide, blackout smoke rising from below",
  "Gamaredon": "phishing storm avatar bursting diagonally out of an inbox tunnel, document scraps spinning around it",
  "FIN6": "payment-terminal jackal-mask avatar crouched near a back-office server rack, carding ledgers behind",
  "MuddyWater": "mirage avatar half-submerged in muddy telecom waves, one PowerShell-glow hand reaching upward",
  "APT35": "conference-lure persona mask in a conversational side lean, badge shapes forming a fan behind",
  "APT33": "aviation-energy wiper avatar standing in runway perspective, disk shards as swept-back wings",
  "Agrius": "data-leak mask hovering over scorched disk platters, document stacks tilted like unstable pillars",
  "OilRig": "oil-platform guardian in a broad low-angle stance, pipeline shoulders sweeping horizontally",
  "Charming Kitten": "cat-mask persona avatar peeking from behind fake login panels, one paw-like hand near the viewer",
  "BlackCat": "angular feline-mask avatar in a sleek side crouch, Rust-code blocks trailing like a segmented tail",
  "Royal": "crown-mask avatar seated at an oblique boardroom table, one crown-spike hand over negotiation folders",
  "BianLian": "theater-mask avatar mid-turn, document fans and Go-code armor forming a diagonal silhouette",
  "BlackSuit": "blank mannequin avatar adjusting a black collar in profile, campaign boards reflected behind",
  "Hunters International": "tracking-mask avatar kneeling over a global map, one tracking-grid hand extended forward",
  "Medusa": "fiber-optic serpent avatar coiled around leak-site panels, cable tendrils framing the title area",
  "8Base": "compact eight-node automaton in a square-on mechanical stance, node halo arranged asymmetrically",
  "Rhysida": "archive moth-mask avatar perched sideways on stacked folders, campus map panels as folded wings",
  "BlackByte": "byte-block golem breaking apart from the shoulders, mosaic tiles flying toward the viewer",
  "Cactus": "cactus-spine construct in a rigid desert sentinel pose, encrypted thorns radiating from its torso",
  "TA577": "email-conveyor phantom surfing a diagonal message wave, loader-chain panels trailing behind",
  "Storm-0501": "cloud-identity storm avatar twisting upward, cross-cloud arrows spiraling around a central identity core",
};

const GEO_STATE_VISUALS = {
  "China": {
    state: "PRC-linked / China-nexus",
    atmosphere: "disciplined state-intelligence operations room, layered coastal and telecom network maps, edge-device access paths, cool jade-cyan signal traces, and a subtle panda-mask geometry or ink-brush circuit contour as a non-official origin symbol",
    avoid: "no flags, no stars, no official seals, no national emblem, no readable Chinese text",
  },
  "Russia": {
    state: "Russia-nexus",
    atmosphere: "cold war-room lighting, hard-edged military or criminal operations boards, satellite route arcs, aurora-like signal bands, snowfield grid textures, and deep red graphite shadows",
    avoid: "no flags, no coat of arms, no official seals, no readable Cyrillic text",
  },
  "North Korea": {
    state: "DPRK-linked / North Korea-nexus",
    atmosphere: "austere intelligence office, isolated network nodes, cryptocurrency vault geometry, bunker-like negative space, controlled document collection, and stark crimson-black contrast",
    avoid: "no flags, no official seals, no leader imagery, no readable Korean text",
  },
  "Iran": {
    state: "Iran-nexus",
    atmosphere: "regional telecom and energy-sector maps, academic or journalist lure desks, web-shell panels, tiled circuit geometry without religious symbolism, and warm desert-amber command-center lighting",
    avoid: "no flags, no official seals, no religious symbols, no readable Persian text",
  },
};

function geoStateTreatment(a) {
  const origin = a.assessed_origin;
  const sponsorship = String(a.sponsorship || "Unknown");
  const geo = origin ? GEO_STATE_VISUALS[origin] : null;
  const targetRegions = j(a.target_regions).slice(0, 4).join(", ");
  if (geo) {
    return [
      `Geo/state-backing: ${geo.state}; sponsorship assessment: ${sponsorship}.`,
      `Visual treatment: ${geo.atmosphere}.`,
      `Target-region context: ${targetRegions || "global"}.`,
      `Geo constraints: ${geo.avoid}; do not caricature ethnicity, nationality, or culture.`,
    ].join("\n");
  }
  if (sponsorship !== "Independent" && sponsorship !== "Unknown") {
    return [
      `Geo/state-backing: state-linked or state-tolerated, exact origin not confidently assigned.`,
      `Visual treatment: formal intelligence-dossier atmosphere, clean government-grade network maps, restrained lighting, and ambiguous regional routing overlays.`,
      `Target-region context: ${targetRegions || "global"}.`,
      `Geo constraints: no flags, no official seals, no national emblems, no readable language-specific text, and no cultural caricature.`,
    ].join("\n");
  }
  return [
    `Geo/state-backing: no confident state backing; treat as independent or unknown-origin activity.`,
    `Visual treatment: transnational cybercrime or deniable operator atmosphere, global routing overlays, anonymous infrastructure, and marketplace or affiliate-network cues where relevant.`,
    `Target-region context: ${targetRegions || "global"}.`,
    `Geo constraints: avoid national symbols, flags, official seals, and cultural stereotypes.`,
  ].join("\n");
}

function actorVisualSignature(a, motivation) {
  const specific = ACTOR_VISUALS[a.primary_name];
  const sectors = j(a.target_sectors).slice(0, 4).join(", ");
  const regions = j(a.target_regions).slice(0, 3).join(", ");
  const tech = j(a.target_tech_stack).slice(0, 4).join(", ");
  const summary = String(a.body_md || "")
    .replace(/\s+/g, " ")
    .replace(/## /g, "")
    .slice(0, 420);
  return [
    specific ? `Actor-specific signature cues: ${specific}.` : `Actor-specific signature cues: ${motif(motivation)}.`,
    `Distinct pose/camera/gesture: ${ACTOR_POSES[a.primary_name] || "use an asymmetrical pose, non-front-facing angle, and one memorable gesture tied to the actor-specific cues"}.`,
    geoStateTreatment(a),
    `Victimology cues: ${sectors || "mixed sectors"} across ${regions || "global regions"}.`,
    `Technology cues: ${tech || "identity, cloud, endpoint, and edge infrastructure"}.`,
    `Profile evidence to inspire the scene, not to render as text: ${summary}`,
  ].join("\n");
}

function compositionForActor(a) {
  const type = String(a.actor_type || "").toLowerCase();
  const name = a.primary_name;
  if (name.includes("Typhoon")) return "fictional infrastructure avatar or symbolic creature behind layered network maps; diagonal cable paths create depth; title sits on a precise lower-third band";
  if (type.includes("nation")) return "formal fictional intelligence avatar, such as a masked sentinel, data spirit, animal-mask construct, or armored dossier figure; low-angle or three-quarter framing with dossier shelves and sparse negative space";
  if (type.includes("organized")) return "comic-style cybercrime avatar at an oblique angle, such as a ledger phantom, payment-card mask, marketplace construct, or access-broker mascot, surrounded by practical tooling";
  if (type.includes("ransomware")) return "fictional extortion avatar with one distinctive prop or backdrop motif from the actor profile, such as a vault guardian, padlock mask, document wraith, cable serpent, or data-beast; avoid generic hoodie-only composition";
  return "enigmatic fictional avatar with actor-specific profile props and a clean lower-third title";
}

function promptForActor(a) {
  const motivation = j(a.motivation);
  const spelled = spellForImageText(a.primary_name);
  return `Use case: stylized-concept.
Asset type: square 1:1 threat actor portrait for OptraSight TAP card.
Primary request: Create a fictional editorial cyber-threat-actor portrait for "${a.primary_name}".

Subject:
- Fictional adversary avatar only; do not depict a real person or celebrity.
- The main character does not need to be human. It may be a masked comic-style figure, symbolic animal-mask avatar, armored construct, sentient device, vault guardian, data spirit, abstract mascot, or cybernetic creature if that better fits the actor profile.
- Portrait-card composition, but do not make every image a centered front-facing bust. Vary pose, gesture, camera angle, and body language; use asymmetry when possible. No gore.
- Archetype cues: ${a.actor_type}; ${a.sponsorship}; motivation: ${motivation.join(", ") || "unknown"}.
- Do not make this a generic hooded hacker portrait. Prefer a memorable fictional avatar over a default human operator, and make the visual identity unique to this actor profile.

Required text:
- Render the exact threat actor name as a clear title inside the image: "${a.primary_name}".
- The title must be spelled exactly as: ${spelled}.
- Use one title only, placed in a clean lower-third title band.
- Use uppercase, high-contrast, condensed sans-serif lettering.
- Keep the title horizontal, readable, and separated from the face and background motifs.
- Do not add any other words, aliases, captions, numbers, symbols, watermarks, or UI labels.

Visual language:
- Bold graphic novel cyber poster, painterly digital illustration, crisp ink outlines, high contrast, dramatic cyan rim light, textured print grain, premium threat-intel dossier aesthetic.
- Background uses abstract cyber motifs connected to the actor profile.
- Unique actor palette: ${actorPalette(a)}.
- Threat intensity accent palette: ${palette(a.threat_level)}.
- Keep the avatar readable at small card size, with strong silhouette and clean edges.
- Composition/framing: ${compositionForActor(a)}.
- Pose/gesture/camera must follow the actor-specific pose direction below; this is required so each TAP portrait has a different main figure posture.
- Geo/state-backed cues must shape atmosphere, infrastructure, map overlays, and lighting only; never use flags, seals, official insignia, or caricature.
- Add one unmistakable identity key from the actor-specific cues so this portrait cannot be confused with another TAP portrait.

Profile-specific customization:
${actorVisualSignature(a, motivation)}

Strict constraints:
- The only readable text in the image must be exactly "${a.primary_name}" in the lower-third title band.
- No misspellings, repeated letters, extra punctuation, logos, flags, watermarks, UI chrome, screenshots, or real organization marks.
- No photorealistic likeness of a known individual.
- No weapons, blood, or explicit violence.
- No extra captions, aliases, symbols, or random typography.`;
}

function spellForImageText(value) {
  const map = {
    "0": "zero", "1": "one", "2": "two", "3": "three", "4": "four",
    "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine",
    "-": "hyphen", "_": "underscore", ".": "dot", "$": "dollar sign",
    "&": "ampersand", "/": "slash",
  };
  return String(value).split("").map((ch) => {
    if (ch === " ") return "space";
    return map[ch] || ch.toUpperCase();
  }).join(" ");
}

function findGeneratedPath(stdout, baseName) {
  const expected = join(PORTRAITS_DIR, `${baseName}.png`);
  if (existsSync(expected)) return expected;
  const generated = join(PORTRAITS_DIR, "generated_assets", `${baseName}.png`);
  if (existsSync(generated)) return generated;
  const m = String(stdout).match(/(\/[^\s'"]+\.png)/);
  if (m && existsSync(m[1])) return m[1];
  return null;
}

function portraitFilePath(row) {
  const urlPath = String(row?.portrait_url || "").split("?")[0];
  const fileName = urlPath.startsWith("/portraits/") ? urlPath.slice("/portraits/".length) : `${row.id}.png`;
  return join(PORTRAITS_DIR, fileName);
}

function hasPosterStylePortrait(row) {
  if (!row?.portrait_url) return false;
  const filePath = portraitFilePath(row);
  if (!existsSync(filePath)) return false;
  if (!replacePlaceholders) return true;
  return require("node:fs").statSync(filePath).size >= PLACEHOLDER_MAX_BYTES;
}

function runImageGen(prompt, baseName) {
  try {
    execFileSync("asi-generate-image", ["--help"], { stdio: "ignore", timeout: 10_000 });
  } catch (e) {
    if (e.code === "ENOENT") {
      throw new Error("asi-generate-image is not installed or not on PATH. Exported prompts are still available via --dry-run.");
    }
  }
  const payload = JSON.stringify({
    prompt,
    filename: baseName,
    aspect_ratio: "1:1",
    model: "gpt_image_2",
  });
  const stdout = execFileSync("asi-generate-image", [payload], {
    cwd: PORTRAITS_DIR,
    timeout: 300_000,
    maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env },
    encoding: "utf8",
  });
  const path = findGeneratedPath(stdout, baseName);
  if (!path) throw new Error(`asi-generate-image completed but no PNG was found for ${baseName}`);
  return path;
}

function canonicalRows() {
  const tenant = db.prepare("SELECT id FROM tenants WHERE slug = ?").get(tenantSlug);
  if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`);
  return db.prepare(`
    SELECT *
      FROM threat_actors
     WHERE tenant_id = ?
     ORDER BY profile_id
  `).all(tenant.id).slice(0, limit);
}

function rowsForActorName(name) {
  if (allTenants) {
    return db.prepare("SELECT id, tenant_id FROM threat_actors WHERE lower(primary_name) = lower(?)").all(name);
  }
  const tenant = db.prepare("SELECT id FROM tenants WHERE slug = ?").get(tenantSlug);
  return db.prepare("SELECT id, tenant_id FROM threat_actors WHERE tenant_id = ? AND lower(primary_name) = lower(?)").all(tenant.id, name);
}

mkdirSync(PORTRAITS_DIR, { recursive: true });
mkdirSync(resolve(process.cwd(), "output"), { recursive: true });

const rows = canonicalRows();
const promptLines = [];
let generated = 0;
let skipped = 0;

for (const row of rows) {
  const prompt = promptForActor(row);
  const targets = rowsForActorName(row.primary_name);
  const missing = targets.filter((t) => {
    const current = db.prepare("SELECT id, portrait_url FROM threat_actors WHERE id = ?").get(t.id);
    return force || !hasPosterStylePortrait(current);
  });
  promptLines.push(JSON.stringify({ profileId: row.profile_id, name: row.primary_name, actorId: row.id, prompt }));
  if (!missing.length) {
    skipped += targets.length;
    continue;
  }
  if (dryRun) continue;

  const sourcePath = runImageGen(prompt, row.id);
  const ts = new Date().toISOString();
  for (const target of missing) {
    const canonical = join(PORTRAITS_DIR, `${target.id}.png`);
    if (sourcePath !== canonical) copyFileSync(sourcePath, canonical);
    db.prepare(`
      UPDATE threat_actors
         SET portrait_url = ?, portrait_generated_at = ?, portrait_status = 'ready'
       WHERE id = ? AND tenant_id = ?
    `).run(`/portraits/${target.id}.png?v=${Date.now()}`, ts, target.id, target.tenant_id);
    generated += 1;
  }
}

writeFileSync(PROMPT_EXPORT, promptLines.join("\n") + "\n");

if (dryRun) {
  console.log(`Dry run: exported ${promptLines.length} portrait prompts to ${PROMPT_EXPORT}`);
  console.log("Run with --generate to call asi-generate-image. Add --all-tenants to copy each canonical actor portrait to matching rows in every tenant. Add --replace-placeholders to backfill deterministic SVG rasters without overwriting poster-style portraits.");
} else {
  console.log(`Generated/assigned ${generated} portrait(s); skipped ${skipped}. Prompt export: ${PROMPT_EXPORT}`);
}
