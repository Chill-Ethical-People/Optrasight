# Public Data Exports

This directory contains GitHub-shareable SQLite exports generated from the
private OptraSight runtime database.

Generate or refresh them with:

```bash
npm run db:export-public
```

Outputs:

- `optrasight-threat-intel-public.db` - public OSINT source catalog and
  sanitized threat-intel findings. Tenant ids, draft emails, analyst tags,
  triage status, source article bodies, provider errors, and client relevance
  fields are removed.
- `optrasight-threat-actors-public.db` - public threat actor profiles and
  public TTP/tool/campaign/IOC/reference appendices. Tenant relevance tags,
  detection-rule links, author identity, client-specific relevance ratings,
  and portrait file paths are removed.

The exporter also creates `data/private/optrasight-client-workspace-private.db`
for local backup/inspection. That private DB is intentionally ignored by Git.
