# Curated Portrait Generation Prompts

These prompts document the BatchOne TAP portraits that were regenerated because
the full-platform portrait source set did not include visually correct named poster
assets for them.

Generation rule: every portrait must be a unique actor-specific poster. Avoid
renaming an unrelated actor portrait. The final asset must include a dark lower
title band, condensed bold actor wording, bevel/shadow treatment, subtle cyan/red
edge lines, and a small CEP watermark baked into the lower-right corner. Text must
be centered inside the title band with comfortable margins.

## Shared Constraints

- Square 1:1 cyber threat actor dossier portrait.
- Mature MSSP/security-operations tone, not comic or toy-like.
- No brand logos except the small CEP watermark in the lower-right title band.
- Leave the bottom title band clean enough for readable actor text.
- Palette should stay in charcoal/black/cyan/indigo with sparse red, amber, or actor-specific accents.
- Subject should be fictional and masked/armored; no real person identity.

## Actor Prompts

### nightspire

Create a square cyber threat actor dossier portrait backdrop for a fictional actor named Nightspire. Scene: dark intelligence-operations environment with night skyline, signal towers, packet trails, subtle map-grid overlays, OSINT dossier fragments, and low blue/cyan/red telemetry glow. Subject: mysterious armored hooded analyst silhouette, sleek angular mask, quiet nocturnal presence. Style: high-detail illustrated cyberpunk intelligence poster, mature MSSP/security-operations style. Composition: centered chest-up subject, generous margin, cinematic poster framing. Mood: restrained, ominous, blue/cyan edge lighting with small red alert accents.

### titan

Create a square cyber threat actor dossier portrait backdrop for a fictional actor named Titan. Scene: fortress-like data center, towering server racks, shield geometry, cracked encrypted vault doors, subtle global network overlay, and OSINT document fragments. Subject: massive angular armored figure with monolithic helmet and broad silhouette. Style: high-detail illustrated cyberpunk intelligence poster, mature MSSP/security-operations style. Composition: centered chest-up subject with strong silhouette. Mood: restrained power, cyan and indigo rim lighting with small red risk accents.

### apt73

Create a square cyber threat actor dossier portrait backdrop for a fictional actor named APT73. Scene: advanced persistent threat command environment, orbital network lines, stealth access paths, diplomatic dossier fragments, exploit-chain diagrams, and subdued geopolitical map overlays. Subject: precise masked operator in layered dark tactical coat with asymmetric angular helmet and thin cyan visor. Style: high-detail illustrated cyberpunk intelligence poster, mature MSSP/security-operations style. Composition: centered bust portrait with clean silhouette. Mood: quiet stealth, cool cyan/indigo edge light, sparse red telemetry points.

### pear

Create a square cyber threat actor dossier portrait backdrop for a fictional actor named Pear. Scene: dark intrusion lab with encrypted file shards, data-leak dossiers, payment ledgers, and subtle pear-like abstract geometry in the background. Subject: lean masked operator with smooth reflective hood and segmented armor. Style: high-detail illustrated cyberpunk intelligence poster, mature MSSP/security-operations style. Composition: centered chest-up subject, poster framing, bottom area dark. Mood: cold blue/cyan glow with small amber and red incident-response accents.

Final replacement prompt used for `pear.png`: Create a square cyber threat actor dossier poster for a fictional actor named Pear, matching the established BatchOne TAP portrait style. Scene: dark cyber-intelligence operations wall with OSINT dossiers, encrypted archive shards, leak-site ledgers, payment traces, network maps, and subtle pear-shaped abstract geometry integrated into the background, not cute or cartoonish. Subject: a unique masked operator with a sleek reflective segmented helmet and cloak, chest-up, different posture and silhouette from other actors; confident but restrained, no generic initials badge. Style: high-detail illustrated cyberpunk intelligence poster, gritty printed poster texture, mature MSSP/security-operations visual language, similar to ransomware actor cards with a framed image area and bottom title plaque. Composition: centered poster composition, square 1:1. Reserve a clean bottom title band occupying about 18 percent of the image height. The subject must not overlap the title text. Add a thin distressed poster border. Lighting/mood: cold teal/cyan operations glow with small amber and red incident-response accents, strong contrast, crisp detail. Text (verbatim): "Pear". Typography constraints: put the word "Pear" only once in the bottom title band; use condensed bold block poster lettering, warm off-white/beige fill, subtle dark shadow, horizontally centered, fully inside the plaque with comfortable side margins; do not make the text oversized; do not crop, warp, duplicate, or misalign the word. Watermark: add a small subtle CEP chain-link mark in the lower-right corner of the title band, low opacity, not interfering with the actor name.

### termite

Create a square cyber threat actor dossier portrait backdrop for a fictional actor named Termite. Scene: underground infrastructure compromise environment, cutaway server-room foundations, tunneling network paths, data exfiltration conduits, and structural damage represented as abstract digital erosion. Subject: compact masked operator with layered chitin-like black armor and hood; no insect creature. Style: high-detail illustrated cyberpunk intelligence poster, mature MSSP/security-operations style. Composition: centered bust portrait with strong silhouette. Mood: subterranean, cyan rim light, amber warning glow, tiny red compromise indicators.

### gunra

Create a square cyber threat actor dossier portrait backdrop for a fictional actor named Gunra. Scene: encrypted extortion infrastructure with hardened server stacks, command panels, leaked-data dossier cards, global routing arcs, and fragmented shield geometry. Subject: rugged masked operator with heavy angular helmet and dark armor. Style: high-detail illustrated cyberpunk intelligence poster, mature MSSP/security-operations style. Composition: centered bust portrait, broad shoulders, cinematic poster framing. Mood: tense, cyan/indigo rim light, red alert glints, restrained security-ops atmosphere.

### 0day Syndicate

Final prompt used for `0day_Syndicate.png`: Create a square cyber threat actor dossier poster for a fictional actor named 0day Syndicate, matching the established BatchOne TAP portrait style. Scene: dark zero-day exploit operations room with vulnerability disclosure timelines, exploit chain diagrams, bug bounty fragments, CISA-style advisory cards, redacted CVE paperwork, and glowing packet traces. No real company logos. Subject: a distinct masked syndicate figure, angular mirrored helmet, layered tactical cyber coat, one hand holding a fractured glass exploit shard, surrounded by subtle code-fragment halos. Different silhouette and color identity from Pear, Titan, Nightspire, and ransomware actors. Style: high-detail illustrated cyberpunk intelligence poster, gritty printed poster texture, mature MSSP/security-operations visual language, framed image area and bottom title plaque. Composition: centered poster composition, square 1:1. Reserve a clean bottom title band occupying about 18 percent of image height. Subject and background must not overlap title text. Add a thin distressed poster border. Lighting/mood: deep midnight blue and graphite, sharp cyan edge light, controlled violet highlights, small red exploit-warning accents. Text (verbatim): "0day Syndicate". Typography constraints: put "0day Syndicate" only once in the bottom title band; use condensed bold block poster lettering, off-white fill with subtle cyan/violet edge shadow, horizontally centered, fully inside the plaque with comfortable side margins; do not crop, warp, duplicate, or misspell the text. Watermark: add a small subtle CEP chain-link mark in the lower-right corner of the title band, low opacity, not interfering with the actor name.

## Local Plate Treatment

After generation, render the final image locally at `1024x1024`:

- Crop/resize backdrop to cover the square canvas.
- Add a dark title band across the lower portrait area, starting around 72% of canvas height.
- Add a thin cyan-to-red edge line and a subtle rectangular inner border.
- Render the exact actor name in large condensed bold type with shadow and bevel.
- Use actor-specific text tones: warm beige for `nightspire`, `titan`, `pear`; amber for `termite`; muted red for `apt73`, `gunra`.
- Add the CEP mark watermark in the lower-right corner.
