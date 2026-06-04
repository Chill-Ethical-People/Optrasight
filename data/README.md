# OptraSight Data Layout

The runtime database and client artifacts live under `data/`, but only the
sanitized public exports are intended for GitHub.

| Path | Git status | Contents |
|---|---|---|
| `../data.db` | ignored | Primary local runtime SQLite database used by the app today. May contain tenant/client data. |
| `data.db` | ignored | Optional runtime SQLite database when running with a mounted `data/` directory. May contain tenant/client data. |
| `public/optrasight-threat-intel-public.db` | tracked | Sanitized public OSINT source catalog and threat-intel findings. |
| `public/optrasight-threat-actors-public.db` | tracked | Sanitized public threat actor profiles and appendices. |
| `private/optrasight-client-workspace-private.db` | ignored | Reconstructed local client workspace export. Contains tenant/client data. |
| `portraits/` | ignored | Generated or uploaded TAP portraits. |
| `dnstwist_screenshots/` | ignored | Runtime malicious-site scanner screenshots. |
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

## Public Export Privacy Rules

The public threat-intel export removes tenant ids, draft emails, analyst tags,
triage status, full source article bodies, provider errors, retry state, and
client relevance fields.

The public threat-actor export removes tenant ids, tenant relevance tagging,
detection-rule links, author identity, client-specific relevance ratings, and
portrait file paths.

The private workspace export is for local backup and inspection only. It is
ignored by Git and should not be uploaded to GitHub.
