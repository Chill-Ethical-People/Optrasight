# Public TAP Portraits

This directory contains threat actor portrait assets prepared for the BatchOne public release.

- `curated-source/` is the authoritative actor-name-keyed pack for public BatchOne setup. The setup script links TAP rows to these files by primary name or alias before considering any UUID/profile-id asset.
- `root-style/` contains watermarked WebP exports of generated TAP portrait art and is restored into `data/portraits/` by `npm run setup` as fallback art only. Do not use the root-style manifest as an actor identity map.
- Runtime/generated portrait uploads remain in `data/portraits/` and are git-ignored.
- Public release copies include a small CEP mark watermark baked into the image.
- These watermarked copies may be used with the public BatchOne demo dataset, documentation, screenshots, and release materials.
- Keep the watermark intact when redistributing the portraits outside the running product.
- `root-style/manifest.json` and `curated-source/manifest.json` record generated file lists and source rules.
- `curated-source/IMAGEGEN_PROMPTS.md` records the actor-specific prompts and local title-plate treatment for regenerated portraits.
