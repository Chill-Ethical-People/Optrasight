# Threat Actor Portrait Prompt

Use this prompt template with any image provider that supports square editorial illustration output. It matches the OptraSight TAP portrait style without relying on provider-specific parameters.

There are two supported variants. The expected public OptraSight TAP style is the **labeled portrait** variant: a dark, high-detail cyber-threat poster with a clean lower-third title band, exact actor title, subtle distressed border, and a small CEP mark watermark in the lower-right of the title band.

- **Clean card portrait:** no text inside the image. Use this when the UI renders the actor name separately.
- **Labeled portrait:** the actor name is intentionally rendered inside the image. Use this for the public BatchOne portrait pack, exports, reports, or image-only galleries.

Image models can still misspell text. For labeled portraits, keep the text short, spell the actor name explicitly, and reject/regenerate any result where the name is not exact.

The accepted BatchOne style is not an initials badge or generic avatar. It is a square intelligence-dossier poster: actor-specific scene, distinct masked or symbolic subject, dark lower title plaque, condensed bold title lettering, cyan/red edge accents, gritty print texture, and restrained MSSP/security-operations tone.

## Clean Card Portrait

```text
Create a square 1:1 stylized editorial cyber-threat-actor portrait for "{PRIMARY_NAME}".

Subject:
- Fictional adversary avatar only; do not depict a real person or celebrity.
- The main character does not need to be human. It may be a masked comic-style figure, symbolic animal-mask avatar, armored construct, sentient device, vault guardian, data spirit, abstract mascot, or cybernetic creature if that better fits the actor profile.
- Poster-card composition, three-quarter or low-angle view when a face or mask exists, varied pose and silhouette, no gore.
- Archetype cues: {ACTOR_TYPE}; {SPONSORSHIP}; motivation: {MOTIVATION}.

Visual language:
- Bold graphic novel cyber poster, painterly digital illustration, crisp ink outlines, high contrast, dramatic cyan rim light, textured print grain.
- Background uses abstract cyber motifs connected to the actor profile: {MOTIF}.
- Threat-level palette: {PALETTE}.
- Keep the avatar readable at small card size, with strong silhouette and clean edges.
- Use a restrained mature security-operations tone; avoid toy, mascot, emoji, or social-media avatar styling.

Strict constraints:
- No readable text, letters, numbers, logos, flags, watermarks, UI chrome, screenshots, or real organization marks.
- No photorealistic likeness of a known individual.
- No weapons, blood, or explicit violence.
- Do not include the actor name in the image.
```

## Labeled Portrait

```text
Create a square 1:1 cyber threat actor dossier poster for "{PRIMARY_NAME}", matching the established OptraSight BatchOne TAP portrait style.

Subject:
- Fictional adversary avatar only; do not depict a real person or celebrity.
- The main character does not need to be human. It may be a masked comic-style figure, symbolic animal-mask avatar, armored construct, sentient device, vault guardian, data spirit, abstract mascot, or cybernetic creature if that better fits the actor profile.
- Poster-card composition, three-quarter or low-angle view when a face or mask exists, varied pose and silhouette, no gore.
- The subject must be visually unique to this actor. Do not reuse another actor's posture, mask, color identity, or background concept.
- Archetype cues: {ACTOR_TYPE}; {SPONSORSHIP}; motivation: {MOTIVATION}.

Required text:
- Render the exact threat actor name as a clear title inside the image: "{PRIMARY_NAME}".
- The title must be spelled exactly as: {PRIMARY_NAME_SPELLED_OUT}.
- Use one title only, placed in a clean dark lower-third title band occupying roughly 18-24% of the image height.
- Use high-contrast condensed bold block poster lettering with subtle bevel/shadow treatment.
- Keep the title horizontal, centered, readable, uncropped, and separated from the face and background motifs.
- Keep comfortable left and right margins around the title. Do not let the subject, border, or watermark overlap the actor name.
- Do not add aliases, captions, numbers, UI labels, extra symbols, or any other readable words.

Visual language:
- High-detail illustrated cyberpunk intelligence poster, gritty printed poster texture, crisp ink outlines, high contrast, dramatic cyan rim light, premium threat-intel dossier aesthetic.
- Background uses abstract cyber motifs connected to the actor profile: {MOTIF}.
- Threat-level palette: {PALETTE}.
- Keep the avatar readable at small card size, with strong silhouette and clean edges.
- Add a thin distressed poster border and subtle cyan-to-red or cyan-to-amber edge line treatment.
- Keep the overall tone mature, restrained, and operational; avoid cute mascot, toy, consumer app, trading-card, or generic profile-picture styling.

Watermark:
- Add one small subtle CEP chain-link mark watermark in the lower-right corner of the title band.
- Keep it low opacity and small enough that it does not interfere with the actor name.
- Do not add any other watermark, logo, seal, brand, or mark.

Profile-specific customization:
- Do not make a generic hooded hacker portrait.
- Prefer a memorable fictional avatar over a default human operator. The main subject can be non-human, mythic, symbolic, animal-masked, or object-based, as long as it remains editorial and cyber-threat themed.
- Read the profile first and include 2-4 distinctive visual cues from the actor's known tradecraft, infrastructure, victimology, tooling, campaigns, or aliases.
- Use profile facts as visual inspiration only; do not render them as extra text.
- Vary avatar species/type, silhouette, mask, armor, props, background architecture, color palette, symbolic cues, and lighting per actor while keeping the OptraSight editorial style consistent.
- Vary the pose, gesture, and camera angle per actor. Avoid making every portrait a centered front-facing bust. Use distinct layouts such as crouched, leaning, reaching, turning away, profile view, low-angle sentinel, top-down dossier view, floating construct, coiled symbolic creature, object-headed figure, or multi-panel split avatar.
- Include sector and technology hints where relevant, for example telecom switch rooms for telecom espionage, hypervisor racks for ESXi-focused ransomware, help-desk/SaaS login cues for social-engineering actors, or file-transfer vault corridors for managed-transfer exploitation.
- Add one clear "identity key" that makes this actor visually distinct from the other portraits, such as a vault ring, telecom cable trench, hypervisor rack, help-desk headset, cold-wallet vault, satellite arc, power-grid breaker panel, controlled document wall, panda-mask armor, fiber-optic serpent, file-transfer golem, payment-card phantom, or power-grid wraith.

Geo / state-backing treatment:
- If the profile has an assessed origin or state sponsor, use it to shape atmosphere, infrastructure, map overlays, and lighting.
- If appropriate, use non-official symbolic motifs for origin or primary target geography, such as a panda-mask geometry for China-nexus actors, aurora/snowfield signal arcs for Russia-nexus actors, isolated cold-wallet bunker geometry for DPRK-linked actors, or desert-amber telecom/energy infrastructure for Iran-nexus actors.
- Do not render flags, official seals, national emblems, leader imagery, readable language-specific text, or cultural caricatures.
- Treat origin as analytic context, not as identity or ethnicity.
- For independent or unknown-origin ransomware and eCrime, use transnational infrastructure, affiliate-marketplace, access-broker, or global routing cues instead of country cues.

Strict constraints:
- The only readable text in the image must be exactly "{PRIMARY_NAME}" in the lower-third title band.
- The only allowed mark is the small CEP watermark in the lower-right title band.
- No misspellings, repeated letters, extra punctuation, extra logos, flags, UI chrome, screenshots, or real organization marks.
- No photorealistic likeness of a known individual.
- No weapons, blood, or explicit violence.
```

For `{PRIMARY_NAME_SPELLED_OUT}`, write the exact characters separated by spaces. Examples:

| Actor name | `{PRIMARY_NAME_SPELLED_OUT}` |
| --- | --- |
| Qilin | Q I L I N |
| Cl0p | C L zero P |
| APT41 | A P T four one |
| Scattered Spider | S C A T T E R E D space S P I D E R |
| Storm-0501 | S T O R M hyphen zero five zero one |

Palette mapping:

| Threat level | Palette |
| --- | --- |
| CRITICAL / SEVERE | Obsidian black, crimson warning accents, cold cyan rim light, bone-white dossier glow |
| HIGH | Obsidian black, steel blue, glacier cyan, sharp red signal accents, pale document light |
| MODERATE | Charcoal black, steel blue, cyan telemetry light, muted amber threat highlights |
| LOW | Graphite black, teal-cyan signal light, desaturated steel, restrained red accents |

Title plaque mapping:

| Actor tone | Title treatment |
| --- | --- |
| Ransomware / extortion | Dark graphite lower band, warm beige or orange-red condensed title, subtle black bevel shadow |
| Espionage / state-linked | Dark navy lower band, cool off-white title with cyan edge shadow |
| Criminal marketplace / access broker | Blackened slate lower band, amber or muted red title accents |
| Unknown / emerging actor | Charcoal lower band, off-white title with cyan/indigo edge light |

Motif mapping:

| Motivation | Motif |
| --- | --- |
| Espionage | Subtle geopolitical map contours, document fragments, quiet surveillance geometry |
| Financial gain / extortion | Broken currency glyphs, vault-like geometry, cloud exfiltration trails |
| Disruption / destructive | Fragmented infrastructure shards, broken circuitry, blackout textures |
| Ideological / hacktivist | Torn-poster texture, protest-banner fragments, raw urban signal noise |
| Unknown / mixed | Fragmented circuit-board patterns and glitch artifacts dissolving into haze |

Actor-specific examples:

| Actor | Distinctive portrait cues |
| --- | --- |
| Qilin | Mythic angular mask or armored data-beast silhouette, rust-orange ESXi server racks, split Windows/Linux terminal panes, fractured affiliate network map |
| Akira | Retro armored cyber-rider or neon panel-mask avatar, dual Windows/Linux consoles, dark ESXi hypervisor blocks, fast-moving leak-site dossier wall |
| Cl0p | File-transfer vault golem, managed-transfer corridors, cascading document exfiltration streams, mass-exploitation targeting grid |
| Scattered Spider | Social-engineering trickster avatar with headset-mask, SIM-swap phone shards, SaaS login maze, call-center lighting |
| Volt Typhoon | Panda-mask infrastructure phantom, water/energy/transport/communications grid schematics, hidden living-off-the-land foothold shadows |
| Salt Typhoon | Telecom cable serpent or deep-sea switchroom avatar, submarine fiber-optic cable lines, lawful-intercept archive shapes with no readable text |
| Lazarus Group | Cold-wallet vault guardian, cryptocurrency exchange vaults, supply-chain package silhouettes, destructive disk-wipe shards |
| Sandworm Team | Power-grid wraith, breaker panels, industrial control diagrams, wiper-damaged disk platters, blackout lighting |

Pose / gesture examples:

| Avatar type | Pose direction |
| --- | --- |
| Vault guardian | Low-angle three-quarter stance, one vault-ring arm raised like a shield |
| Telecom serpent | Coiled S-curve across the frame, head in profile, cable body wrapping the title area |
| Social-engineering trickster | Leaning into frame with one hand/headset close to the viewer, phone shards orbiting |
| Dossier sentinel | Top-down file-table composition with the avatar emerging from stacked folders |
| Infrastructure phantom | Floating above map layers, one arm or tendril touching a grid node |
| Payment-card phantom | Side-profile glide pose with card-track lines trailing behind |

Geo / state-backing examples:

| Origin / backing | Portrait atmosphere cues | Avoid |
| --- | --- | --- |
| China-nexus / PRC-linked | Disciplined state-intelligence operations room, layered coastal and telecom network maps, edge-device access paths, panda-mask geometry or ink-brush circuit contours, cool jade-cyan signal traces | Flags, stars, official seals, national emblems, readable Chinese text |
| Russia-nexus | Cold war-room lighting, hard-edged military or criminal operations boards, satellite route arcs, aurora/snowfield signal geometry, deep red graphite shadows | Flags, coat of arms, official seals, readable Cyrillic text |
| DPRK-linked / North Korea-nexus | Austere intelligence office, isolated network nodes, cryptocurrency vault geometry, controlled document collection, bunker-like geometry, stark crimson-black contrast | Flags, official seals, leader imagery, readable Korean text |
| Iran-nexus | Regional telecom and energy-sector maps, academic or journalist lure desks, web-shell panels, desert-amber infrastructure lighting, tiled circuit geometry without religious symbolism | Flags, official seals, religious symbols, readable Persian text |
| Independent / unknown origin | Transnational cybercrime infrastructure, affiliate-marketplace boards, global routing overlays, anonymous hosting and access-broker cues | National symbols, flags, stereotypes |

Provider notes:

- Prefer a square output such as `1024x1024` or `2048x2048`.
- For clean card portraits, if the provider supports negative prompts, reuse the strict constraints as the negative prompt.
- For labeled portraits, if the provider supports negative prompts, use: `misspelled text, extra text, duplicate title, random letters, unreadable typography, cropped title, oversized text, subject overlapping title, logo except small CEP mark, flags, UI text, captions, symbols`.
- For labeled portraits, validate the final image manually or with OCR. Regenerate when the title is not exactly `{PRIMARY_NAME}`.
- If the image provider cannot reliably render exact text, generate a clean backdrop without title text, then apply the local plate treatment from `data/public/portraits/curated-source/IMAGEGEN_PROMPTS.md`: dark title band, exact actor name in condensed bold type, thin cyan/red edge line, subtle inner border, and CEP mark watermark.
