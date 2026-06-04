# Seeded data bundled with this export

This directory is mounted at `<repo>/data/` on first boot. The application
will use the SQLite database here instead of seeding an empty one.

| File | Contents |
|---|---|
| `data.db` | 301 threat-actor profiles · 18 589 parsed OSINT findings · 71 OSINT sources · 7 detection rules · 2 exercises · last 200 audit-log entries · 5 tenants · 4 users · 6 portraits seeded to actor IDs |
| `portraits/*.png` | Persisted AI-generated and user-uploaded threat-actor portraits |
| `portraits/.gitkeep` | Keep dir under version control |

## What was redacted before export

- **`ai_providers.api_key_enc`** wiped on every row. Open `/#/ai-setup`, paste your own DeepSeek / OpenAI / Anthropic key into each row, click **Test**. The provider settings (kind, label, model, baseUrl, enabled, default) are preserved.
- **`audit_log`** trimmed to the most recent 200 entries.
- **User session tokens** are kept in memory only; restarting the server already invalidated them. Log in again with the legacy seeded admin (see top-level `README.md` → "Login").

## Schema migrations

Migrations run automatically on every boot via `seedIfEmpty()` and the
column-add migration pass in `server/storage.ts`. Nothing to invoke by hand.

## Clean slate

To start fresh, delete `data/data.db` before the first server start. An
empty database will be seeded with the default tenant and admin user.
