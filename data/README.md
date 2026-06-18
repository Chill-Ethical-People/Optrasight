# OptraSight Data Layout

The runtime database and client artifacts live under `data/`, but only the
sanitized public exports are intended for GitHub.

| Path | Git status | Contents |
|---|---|---|
| `../data.db` | ignored | Primary local runtime SQLite database used by the app today. May contain tenant/client data. |
| `data.db` | ignored | Optional runtime SQLite database when running with a mounted `data/` directory. May contain tenant/client data. |
| `public/optrasight-threat-intel-public.db` | tracked | Sanitized public OSINT source catalog and threat-intel findings. |
| `public/optrasight-threat-actors-public.db` | tracked | Sanitized public threat actor profiles and appendices. |
| `portraits/` | ignored | Generated or uploaded TAP portraits. |
| `public/portraits/` | tracked when present | Watermarked curated TAP portraits prepared for public release. |
| `.optrasight-kek` | ignored | Local encryption key material. Never commit. |

## Refresh Public Exports

Run:

```bash
npm run db:export-public
```

The exporter reads `data.db` by default, or `data/data.db` if the root DB does
not exist. You can also pass an explicit source:

```bash
node scripts/export-public-dbs.cjs data/data.db
```

To restore the public demo dataset into a local runtime workspace on a fresh
clone:

```bash
npm run db:restore-public
```

That command creates the git-ignored root `data.db`, imports the sanitized
public OSINT/TAP exports, and copies watermarked portraits from
`data/public/portraits/` into `data/portraits/` so Actor Observatory cards render
locally. It refuses to overwrite an existing runtime DB unless called with
`npm run db:restore-public -- --force`.

## Public Export Privacy Rules

The public threat-intel export removes tenant ids, draft emails, analyst tags,
triage status, full source article bodies, provider errors, retry state, and
client relevance fields.

The public threat-actor export removes tenant ids, tenant relevance tagging,
detection-rule links, author identity, client-specific relevance ratings, and
portrait file paths.

The private workspace export is for local backup and inspection only. It is
ignored by Git and should not be uploaded to GitHub.
