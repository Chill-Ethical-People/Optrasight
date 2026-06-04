# OptraSight

OptraSight, also known as 全向預警台, is an evidence-led blue-team platform for OSINT triage, threat actor profiling, and threat-hunting query generation.

This `main` branch is the **Batch 1 release line**: a single-tenant threat-intel workstation focused on Intel Inbox, Threat Actor Profiles, AI Setup, and Job Control. The full multi-module platform is preserved on `backup/full-platform-before-batch1`.

## What It Does

| Area | Capability |
| --- | --- |
| OSINT monitoring | Source inventory, finding ingestion, ATT&CK scoping, AI triage, deep-dive analysis, email drafts, and STIX preview. |
| Threat-hunting queries | AI-generated Splunk/KQL/Sigma-style hunting queries from selected OSINT findings. |
| Threat Actor Profiles | TAP dossiers with identity, TTPs, Diamond Model, IOCs, campaigns, references, detection coverage, confidence drivers, portraits, DOCX/STIX export, and async AI re-analysis. |
| AI Setup | Per-tenant AI provider configuration, task assignment, provider tests, Gemini compatibility routing, and provider-aware job visibility. |
| Job Control | Background AI/OSINT job visibility and cancellation controls for Batch 1 workflows. |

## Design Principles

- **Truthful capability states:** unavailable actions are disabled and explain why.
- **No silent mock fallback in production:** strict mode surfaces real provider/configuration errors.
- **Traceability first:** OSINT, TAP, ATT&CK techniques, and generated hunt queries remain linked.
- **Single tenant in Batch 1:** backend tenant scoping remains intact, but tenant switching and global views are hidden from this release line.
- **In-memory UI state:** the browser app avoids localStorage, sessionStorage, indexedDB, and cookies for application state.
- **Operational density:** UI favors restrained enterprise controls over marketing-style layouts.

## Contributors

See [CONTRIBUTORS.md](./CONTRIBUTORS.md) for maintainer and AI-assisted
contribution credits, including OpenAI Codex and Anthropic Claude.

## Current UX Notes

Recent platform updates include:

- Batch 1 release gating narrows `main` to OSINT, TAP, threat-hunting queries, AI Setup, and Job Control.
- Route-aware and idle-aware cache warming so initial load is faster while preserving warm TAP/OSINT navigation.
- Gemini compatibility routing for saved `gemini-3.5-flash` rows to Gemini 2.5 where supported.
- TAP re-analysis as async `threat_actor_enrichment` jobs visible in Job Control and the background jobs tray.
- Failed provider jobs preserve `provider_label` for easier Job Control triage.
- Coverage Radar actions are capability-aware: zero-rule techniques show `No detections yet`; observed techniques keep `Open intel` enabled.
- `#/osint?tech=<TTP>` shows an ATT&CK scope banner with count, remove action, and detection-draft pivot.
- Investigation detail now uses a standalone modal cockpit rather than a cramped side sheet.

## Tech Stack

| Layer | Stack |
| --- | --- |
| Frontend | React 18, Vite, TypeScript, Tailwind CSS, Radix/shadcn UI, Wouter hash routing, TanStack Query |
| Backend | Express 5, TypeScript, better-sqlite3, Drizzle ORM, Zod |
| AI | Live provider dispatcher for DeepSeek, OpenAI, Anthropic, and Google Gemini |
| Storage | SQLite database under `data/` with tenant-scoped records |
| Exports | DOCX, PPTX, STIX preview/export, Markdown/HTML-style report flows |

## Repository Layout

```text
client/
  src/
    App.tsx                 Route wiring and providers
    components/             App shell, command palette, job tray, shared controls
    components/ui/          Radix/shadcn UI primitives
    lib/                    auth, query client, warm cache, jobs, formatting
    pages/                  Product routes

server/
  index.ts                  Express boot, strict-mode banner, Vite/static serving
  routes.ts                 HTTP API surface
  storage.ts                SQLite persistence and business logic
  aiClient.ts               Task-level AI orchestration
  aiLive.ts                 Provider-specific live AI calls
  osintFetcher.ts           OSINT source ingestion
  osintChat.ts              AI triage/deep-dive jobs
  backgroundJobs.ts         OSINT scheduler and startup job maintenance
  tapDocx.ts                TAP DOCX export
  tapPortrait.ts            TAP portrait generation/upload handling
  pptxExercise.ts           Exercise PPTX export
  queryGrammars/            SIEM/rule language guidance used by AI generation

shared/
  schema.ts                 Drizzle schema, DTOs, and Zod validation

data/
  data.db                   Runtime SQLite database (git-ignored)
  public/                   Sanitized GitHub-shareable CTI/TAP SQLite exports
  private/                  Local-only client workspace export (git-ignored)
  portraits/                Generated or uploaded TAP portraits (git-ignored)

spec/
  openapi.yaml              API contract snapshot
  integrations.json         Connector catalogue
```

## Quick Start

### Prerequisites

- Node.js 18+ or 20+
- npm 9+
- SQLite-compatible local filesystem
- Optional native tools for richer scans: `dnstwist`, `opensquat`, `whois`

### Install

```bash
npm install
```

### Run Development Server

```bash
npm run dev
```

The app serves Express and Vite together. By default it listens on:

```text
http://localhost:5000
```

### Build Production Bundle

```bash
npm run build
```

### Run Production Bundle

```bash
NODE_ENV=production npm start
```

or:

```bash
NODE_ENV=production node dist/index.cjs
```

## Demo Accounts

Seeded accounts may exist in local demo data. Rotate them immediately before using the platform with real data.

| Role | Email | Password |
| --- | --- | --- |
| Admin | `admin@brandguard.local` | `admin1234` |
| Analyst | `analyst@acmebank.com` | `demo1234` |

Additional tenant-specific demo accounts may exist depending on the bundled `data/data.db`.

## Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `NODE_ENV` | `development` | Switches dev/prod behavior. Production serves `dist/`. |
| `PORT` | `5000` | HTTP listen port. |
| `OPTRASIGHT_STRICT` | `1` in production, `0` otherwise | Blocks mock fallbacks and surfaces real missing-provider/upstream errors. |
| `BRANDGUARD_AI_LIVE` | `1` | Historical live-AI kill switch retained for compatibility. |
| `HOSTING_MODE` | unset | Enables selected multi-hosting behaviors when configured. |
| `PORT_REUSE` | platform-dependent | Allows server reusePort behavior when explicitly enabled. |

AI provider keys are configured inside the platform at `/#/ai-setup`. They are stored per tenant rather than read from environment variables.

## Strict Production Mode

When `NODE_ENV=production`, OptraSight is strict by default:

- AI routes do not silently return synthetic content when no live provider is configured.
- OSINT/mock-mode paths return explicit errors when strict mode blocks fallback.
- Provider failures surface diagnostic details instead of pretending success.
- Job Control and the background tray retain job kind, target labels, target URLs, provider labels, timestamps, and structured error details where available.

Common strict-mode outcomes:

| HTTP | Meaning |
| --- | --- |
| `409` | Mock fallback was blocked because strict mode requires a real provider or real upstream path. |
| `502` | A live provider/upstream was reached but failed, timed out, returned invalid JSON, or violated schema. |
| `4xx` | Validation, auth, tenant mismatch, missing entity, or unsupported action. |
| `5xx` | Unexpected server failure; inspect server logs. |

## Scripts

```bash
npm run dev        # development server
npm run build      # production client/server build
npm start          # run built server
npm run check      # TypeScript check
npm run db:push    # apply Drizzle schema updates
```

Useful diagnostics:

```bash
node scripts/diag-ai-live.cjs
node scripts/diag-chat-live.cjs
```

## Important Routes

| Route | Purpose |
| --- | --- |
| `/#/` | Overview |
| `/#/osint` | Intel Inbox / OSINT monitoring |
| `/#/osint?tech=T1190` | ATT&CK-scoped OSINT view |
| `/#/sources-analytics` | Source quality and health analytics |
| `/#/threat-actors` | Threat Actor Profiles |
| `/#/coverage-radar` | ATT&CK coverage readiness |
| `/#/detection-rules` | Detection rule workspace |
| `/#/investigations` | Investigation case cockpit |
| `/#/operations-audit` | Job control and operational audit |
| `/#/ai-setup` | AI providers and assignments |
| `/#/settings` | Client settings, profile, assets, contacts, and watchlists |

## Selected API Surface

Authentication:

```text
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

Tenant and settings:

```text
GET  /api/v1/tenants
GET  /api/v1/tenant/scope
PUT  /api/v1/tenant/scope
GET  /api/v1/client-profile
PUT  /api/v1/client-profile
GET  /api/v1/client-profile/contacts
POST /api/v1/client-profile/contacts
```

AI and jobs:

```text
GET  /api/v1/ai/providers
POST /api/v1/ai/providers
POST /api/v1/ai/providers/:id/test
GET  /api/v1/ai-jobs/active
GET  /api/v1/ai-jobs/history
```

OSINT:

```text
GET  /api/v1/osint/findings
GET  /api/v1/osint/findings/:id
POST /api/v1/osint/findings/ai-analyze
POST /api/v1/osint/findings/email-draft
GET  /api/v1/osint/sources
```

Threat actors:

```text
GET    /api/v1/threat-actors
POST   /api/v1/threat-actors
GET    /api/v1/threat-actors/:id/full
PATCH  /api/v1/threat-actors/:id
POST   /api/v1/threat-actors/:id/enrich
GET    /api/v1/threat-actors/:id/tenants
POST   /api/v1/threat-actors/:id/tenants
POST   /api/v1/threat-actors/:id/portrait
POST   /api/v1/threat-actors/:id/portrait/upload
DELETE /api/v1/threat-actors/:id/portrait
```

Detections, investigations, reports, exercises:

```text
GET   /api/v1/detection-rules
POST  /api/v1/detection-rules/generate
POST  /api/v1/detection-rules/:id/deploy
GET   /api/v1/investigations
POST  /api/v1/investigations
GET   /api/v1/investigations/:id/full
PATCH /api/v1/investigations/:id
POST  /api/v1/investigations/:id/notes
GET   /api/v1/reports
POST  /api/v1/reports/generate
GET   /api/v1/exercises
POST  /api/v1/exercises
```

See `spec/openapi.yaml` for the broader contract.

## Data and Seed Content

Runtime data lives under `data/`. The local workspace may contain seeded tenants, findings, TAPs, portraits, rules, reports, exercises, and job history.

Public/shareable intelligence exports are generated with:

```bash
npm run db:export-public
```

That command writes:

- `data/public/optrasight-threat-intel-public.db`
- `data/public/optrasight-threat-actors-public.db`
- `data/private/optrasight-client-workspace-private.db` (git-ignored)

Before publishing or sharing a build:

- Remove or rotate seeded account credentials.
- Clear real AI provider keys.
- Check `data.db` and `data/data.db` for sensitive tenant data.
- Commit only the sanitized `data/public/*.db` exports unless intentionally shipping a private demo snapshot.
- Review `data/README.md` for restore notes.

## Security Notes

- Authentication uses bearer session tokens.
- Admins can pivot tenants; analysts remain tenant-scoped.
- Strict mode prevents accidental demo/mock answers in production.
- Unsupported connectors must remain visibly disabled until real implementation exists.
- Browser storage should not be used for app state.
- Secrets should not be committed. AI keys belong in tenant provider configuration, not `.env`.

See `SECURITY.md` for more detail.

## Development Guidance

- Prefer existing app patterns: React Query, `apiRequest`, Radix/shadcn UI, Wouter hash routes.
- Keep tenant-scoped cache keys consistent.
- Use async jobs for long AI/provider work.
- When adding unavailable functions, disable actions visibly and explain the requirement.
- Keep enterprise tool surfaces dense but readable.
- Avoid nested cards inside cards.
- For local visual validation, test at desktop, tablet, and narrow mobile widths.

## Known Local Constraints

- This version-1 snapshot is intended to be committed without runtime databases, uploaded portraits, generated screenshots, logs, or local secrets.
- Some sandboxed environments block `tsx` IPC during build. Re-run with proper local permissions if `npm run build` fails with `listen EPERM` for a `tsx-*.pipe`.
- Browser automation may require installed Playwright browser binaries, not just the package.

## Further Reading

- `ARCHITECTURE.md` - system architecture and data flow
- `DEPLOYMENT.md` - deployment notes
- `SECURITY.md` - security and secret-handling notes
- `CONTRIBUTING.md` - contribution workflow
- `CHANGELOG.md` - historical implementation notes
- `data/README.md` - seeded data handling
- `CONTRIBUTORS.md` - maintainer and AI-assisted contribution credits

## License

MIT. See [package.json](./package.json) for the repository license metadata.
