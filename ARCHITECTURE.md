# Architecture

This document is the navigation map for the OptraSight codebase. Read this before refactoring.

## High-level shape

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Browser (React)                            │
│                                                                     │
│   Hash-router (wouter)  →  Pages  →  React Query  ──┐               │
│                                                     │               │
└──────────────────────────────────────────────────── │ ──────────────┘
                                                      │ /api/v1/*
┌──────────────────────────────────────────────────── ▼ ──────────────┐
│                       Express (Node 18+)                            │
│                                                                     │
│   index.ts (boot + error funnel + production-mode banner)           │
│        │                                                            │
│        ▼                                                            │
│   routes.ts (thin) ─────►  storage.ts (business rules + Drizzle)    │
│        │                       │                                    │
│        │                       ▼                                    │
│        │                  SQLite (better-sqlite3 + WAL)             │
│        │                                                            │
│        ▼                                                            │
│   aiClient.ts ─► aiLive.ts ─► DeepSeek / OpenAI / Anthropic / Gemini│
│   osintFetcher.ts ─► 100+ real feeds                                │
│   tapPortrait.ts ─► gpt-image-2 (asi-generate-image CLI)            │
│   backgroundJobs.ts ─► per-tenant scheduler                         │
└─────────────────────────────────────────────────────────────────────┘
```

## Module map

### `server/`

| File | Lines | Role |
|---|---:|---|
| `index.ts` | 150 | Boot. Express setup. Error funnel (`LiveAiError` → 502, `MockFallbackBlockedError` → 409). Production banner. |
| `routes.ts` | 2.3k | Every HTTP endpoint. Thin — delegates to storage. Tenant resolution via `X-Tenant-Id` + auth Bearer token. |
| `storage.ts` | 6.7k | **Single source of truth for persistence + business rules.** Wraps Drizzle. Owns schema migrations, seed, audit, every CRUD path. *This is the natural first refactor target — split by domain (tenant, osint, tap, rules, exercises, audit, integrations).* |
| `aiClient.ts` | 2.7k | Live-first dispatcher. `dispatchAi({task, provider, input})` returns typed output or throws `LiveAiError`. Mock fallbacks only execute when no provider is configured AND strict mode is off. |
| `aiLive.ts` | 1.2k | Per-provider HTTP plumbing (DeepSeek, OpenAI, Anthropic, Gemini). JSON-mode + schema validation. |
| `productionMode.ts` | 74 | Single auditable gate: `isStrictProduction()`, `MockFallbackBlockedError`, boot banner. |
| `osintFetcher.ts` | 1.5k | RSS / Atom / HTML extraction. Per-source content-hash, IOC parsing, CVE extraction. |
| `osintChat.ts` | 700 | Async job pattern for chat/triage and chat/deep-dive (32k tokens, 540s timeout). |
| `osintSeed.ts` | 800 | Canonical catalogue of 100+ OSINT sources. |
| `osintClustering.ts` | 200 | Backfills `cluster_id` for findings on startup (best-effort, swallows errors). |
| `tapPortrait.ts` | 183 | Calls `asi-generate-image` CLI via child_process. 300s timeout. Stores PNG at `data/portraits/<aid>.png`. |
| `tapDocx.ts` | 462 | DOCX export of a TAP dossier via `docx` package. |
| `pptxExercise.ts` | 343 | PPTX export of an exercise via `pptxgenjs`. |
| `exercises.ts` | 600 | Exercise generation + grading + magic-link tokens. |
| `exerciseTemplates.ts` | 400 | Inject-style templates for the exercise generator. |
| `iocPublisherBlocklist.ts` | 50 | Filter out URL hostnames that publish IOCs (would taint findings). |
| `keywordExpansion.ts` | 80 | Synonym expansion for OSINT search. |
| `mockAdapters.ts` | 200 | Deterministic seed-time mocks. Only fires on first-boot empty DB or when `OPTRASIGHT_STRICT=0`. |
| `sourceFetch.ts` | 176 | Generic HTTP fetch with retry + user-agent. |
| `backgroundJobs.ts` | 250 | Per-tenant OSINT scheduler. Reads `tenant_osint_settings`, defaults OFF. |
| `queryGrammars/` | — | Markdown specs the AI is told to follow when emitting Sigma / SPL / ESQL / YARA-L / KQL / Cortex XQL / Snort / YARA. |
| `static.ts` | 20 | Production static-file middleware. |
| `vite.ts` | 58 | Dev-only Vite middleware. |

### `client/src/`

| File | Lines | Role |
|---|---:|---|
| `App.tsx` | 80 | Router. `<Router hook={useHashLocation}>` wraps `<Switch>`. |
| `main.tsx` | 20 | React mount + theme provider. |
| `pages/` | — | One route per file. Largest are `ThreatActors.tsx` (2.9k), `OsintMonitoring.tsx` (2.5k), `Exercises.tsx` (1.7k), `DetectionRules.tsx` (1.4k), `SourcesAnalytics.tsx` (1.2k). *Natural refactor targets — extract per-section components into `client/src/components/<page>/`.* |
| `components/` | — | Shared UI (`AppShell`, `Logo`, `PageHeader`, `ScopeBar`, `SeverityBadge`, `KanbanCol`, `OsintTriagePanel`, `OsintChatbot`, `OsintAutomationCard`, `AiJobsTray`, `os-primitives`). |
| `components/ui/` | — | shadcn/ui base components. Auto-generated, don't hand-edit. |
| `lib/queryClient.ts` | 120 | `apiRequest` helper + React Query setup. `__PORT_5000__` replaced at deploy time. |
| `lib/auth.tsx` | 100 | `AuthProvider` + `useAuth()`. Stores token in React state (no localStorage). |
| `lib/uiState.tsx` | 60 | Cross-page UI state (selected tenant, last filter, etc). |
| `lib/aiJobs.tsx` | 150 | Tracks async AI jobs site-wide so the `AiJobsTray` shows them everywhere. |

### `shared/schema.ts`

Drizzle SQLite schema. Every table has:
1. A `sqliteTable(...)` definition.
2. An insert Zod schema via `createInsertSchema(...).omit({...})`.
3. An insert type `z.infer<typeof insertSchema>`.
4. A select type `typeof table.$inferSelect`.

SQLite has no array column type — lists are stored as JSON text and parsed in `storage.ts`.

## Data flow

### Synchronous request

```
Browser → React Query → apiRequest(/api/v1/X) → routes.ts → storage.<method>() → SQLite → JSON
```

### Async AI job (chat/triage, chat/deep-dive, exercise/generate)

```
1. Browser POSTs /api/v1/osint/analyze/:fid
2. routes.ts creates a row in ai_jobs (status=running) and returns { jobId } immediately
3. A detached promise calls dispatchAi() with the 540s timeout
4. On success → storage updates the finding row + ai_jobs.status='done'
   On LiveAiError → ai_jobs.status='error' + error column
5. Browser polls /api/v1/jobs/:jid every 2s (via AiJobsProvider context)
6. AiJobsTray (bottom-right of every page) shows progress + final result
```

### Tenant scoping

Every authenticated request resolves a `tenantId` from either:
1. The `X-Tenant-Id` header (set by the AppShell's tenant switcher).
2. The `tid` query param (legacy / direct links).
3. The user's `tenantId` field (fallback for non-MSSP users).

MSSP admins (`role='admin'`) can pivot to any tenant via `X-Tenant-Id`. Non-admin users are pinned to their assigned tenant.

## Error contract

| Class | HTTP | Where thrown |
|---|---:|---|
| `LiveAiError` | 502 | `aiClient.ts`, `aiLive.ts` — provider HTTP / JSON / schema failures |
| `MockFallbackBlockedError` | 409 | `productionMode.ts` — refused mock fallback in strict mode |
| `ZodError` | 400 | Any route that validates with `.parse(req.body)` |
| Generic `Error` | 500 | Last-resort; server logs the stack |

The funnel lives in `server/index.ts`. Every new error class must be registered there.

## Hash routing pitfalls

* `<Router hook={useHashLocation}>` wraps `<Switch>`. **Never pass `hook` to `<Switch>`.**
* Routes are hash paths: `/#/threat-actors`, `/#/detection-rules`, `/#/exercises`, `/#/sources-analytics`.
* `<Link href="/x">` works — wouter prepends `#` automatically.
* `href="#section"` anchor links are intercepted as route changes → 404. Use `onClick` + `scrollIntoView`.

## Tailwind purge gotcha

Dynamic class names (e.g. `os-${severity}-bg`) must be safelisted in `tailwind.config.ts` → `safelist`. The OptraSight palette (Indigo brand, Cyan signal) is already wired.

## Known god-files (next refactor targets)

| File | Why it's a target |
|---|---|
| `server/storage.ts` (6.7k) | Single class with 100+ methods. Suggested split: `storage/tenant.ts`, `storage/osint.ts`, `storage/tap.ts`, `storage/rules.ts`, `storage/exercises.ts`, `storage/audit.ts`, `storage/index.ts` (re-exports). |
| `server/routes.ts` (2.3k) | Mount per-domain routers: `routes/auth.ts`, `routes/osint.ts`, `routes/tap.ts`, `routes/rules.ts`, `routes/exercises.ts`. |
| `client/src/pages/ThreatActors.tsx` (2.9k) | Extract `<TapCard>`, `<TapKanban>`, `<TapDetailSheet>`, `<TapEditDialog>`, `<PortraitActionMenu>` into `components/tap/`. |
| `client/src/pages/OsintMonitoring.tsx` (2.5k) | Extract `<OsintFiltersBar>`, `<OsintFindingsTable>`, `<OsintFindingRow>`, `<OsintDeepDivePanel>`, `<OsintHeatmap>` into `components/osint/`. |
| `client/src/pages/Exercises.tsx` (1.7k) | Extract `<ExerciseCard>`, `<ExerciseGenerateDialog>`, `<ExerciseRunSheet>` into `components/exercises/`. |

These are not blockers — the build is green and the runtime is stable. They are paydown for the next developer.

## Build pipeline

1. `npm run build` runs `tsx script/build.ts`.
2. The build script:
   * Bundles the client with Vite → `dist/public/`.
   * Bundles the server with esbuild → `dist/index.cjs`.
   * Copies `client/public/*` → `dist/public/`.
   * Copies `server/data/*` (dictionary JSON) into the server bundle as imports.
3. Production start: `NODE_ENV=production node dist/index.cjs`. The server serves both the API and the static client from port 5000.

## Database

* `data.db` (next to the running binary). WAL mode (`-shm` and `-wal` siblings).
* Schema is enforced at boot by `ensureSchema()` in `storage.ts`. New columns are added via `ALTER TABLE ADD COLUMN` migrations inside that function — idempotent and safe to call on every start.
* No external migration tool runs in production. `npm run db:push` (`drizzle-kit push`) is for local schema work only.
* Sensitive columns are never logged; the express middleware truncates response bodies in the request log.

## Performance notes

* `better-sqlite3` is synchronous. Long-running queries (the `osint_findings` heatmap, the TAP backfill) are wrapped in `setTimeout(...)` so they never block boot.
* React Query caches are invalidated by key, not by URL. Mutations must call `queryClient.invalidateQueries({ queryKey: ["/api/v1/X"] })` — see `client/src/pages/ThreatActors.tsx` `PortraitActionMenu` for the canonical pattern.
* The OSINT background scheduler runs at-most every minute and skips work when no tenant has it enabled.
