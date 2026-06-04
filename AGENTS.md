# AGENTS.md — Handover brief for Codex Local CLI

> **Read this file first when you (Codex) are picking up the OptraSight codebase.** It is the fastest path from cold-start to productive work.

---

## What is OptraSight?

A multi-tenant MSSP console combining:

* **OSINT monitoring** — 100+ canonical feeds, dedup, AI triage.
* **Threat Actor Profiles (TAP)** — auto-generated dossiers with AI portraits.
* **Detection Rules** — Sigma / SPL / ESQL / YARA-L / KQL / Cortex XQL / Snort / YARA.
* **Tabletop exercises** — AI-generated, magic-link portal, PPTX export.
* **Young-domain monitoring** — newly registered TLD watchlist.

Stack: **Express 5 + better-sqlite3 + Drizzle ORM** server · **React 18 + Vite + Tailwind + shadcn/ui** client. One Node process, one port, one SQLite database.

Current head: **Wave 2.1** — manual portrait upload (complete, verified, deployed).

---

## Required reading order

1. [README.md](./README.md) — what the product is + quick start.
2. [ARCHITECTURE.md](./ARCHITECTURE.md) — module map + data flow + the god-files to refactor next.
3. [CONTRIBUTING.md](./CONTRIBUTING.md) — code conventions + PR checklist + common pitfalls.
4. [SECURITY.md](./SECURITY.md) — what to rotate before any production deploy.
5. [DEPLOYMENT.md](./DEPLOYMENT.md) — Docker + Cloudflare Tunnel + nginx recipes.
6. [CHANGELOG.md](./CHANGELOG.md) — wave-by-wave history.

---

## Locked product constraints (DO NOT VIOLATE)

These have been re-confirmed across every wave. Treat them as load-bearing.

* **English-only AI output.** The Chinese strap line `全向預警台` is brand, not content. AI-generated text (triage, deep-dive, exercise injects, TAP dossiers) is English.
* **DeepSeek live + productional, no mock fallback.** When `OPTRASIGHT_STRICT=1` (default in production), every AI / OSINT path that lacks a real provider must surface a real error (HTTP 409 or 502), never synthesise data.
* **chat/triage + chat/deep-dive + exercise/generate** all use `maxTokens: 32000` and `timeoutSeconds: 540`. They are async-job pattern — never block the request.
* **chat/converse stays synchronous.** Don't accidentally move it to the job pattern.
* **NEVER use `nohup ... &`.** In the Computer sandbox, always start the server with `pplx-tool start_server` and `api_credentials=["pplx-tool:start_server"]`. The server must boot with `api_credentials=["llm-api:image"]` so child `asi-generate-image` calls inherit credentials.
* **NEVER add `relative` to Radix `<SheetContent>`** — it breaks the portal. Wrap children in `<div className="relative min-h-full">` instead.
* **Palette is locked:** `#4F46E5` (brand) / `#22D3EE` (signal) / `#EEF0FE` (brand-soft).
* **No `localStorage`, `sessionStorage`, `indexedDB`, or cookies.** They are blocked in the deploy sandbox and crash the page. Use React state + server storage.

---

## Repo layout (cheat sheet)

```
client/             Vite + React 18 client
  src/pages/        one file per route
  src/components/   shared UI (AppShell, Logo, PageHeader, AiJobsTray, …)
  public/           SVG logo + favicon + PWA icons + OG image + manifest
server/             Express 5 + Drizzle ORM
  index.ts          boot + error funnel
  routes.ts         every HTTP endpoint (THIN — delegates to storage)
  storage.ts        ALL business logic (god-file, 6.7k lines, refactor target)
  aiClient.ts       live-first AI dispatcher
  aiLive.ts         per-provider HTTP plumbing
  productionMode.ts strict-mode gate (NEW in Wave 2.1)
  tapPortrait.ts    AI portrait generation
  osintFetcher.ts   real-feed ingestion
  osintChat.ts      async chat/triage + chat/deep-dive jobs
  backgroundJobs.ts per-tenant OSINT scheduler
  queryGrammars/    Markdown specs for Sigma/SPL/ESQL/etc
shared/schema.ts    Drizzle tables + Zod insert schemas + select types
data/               SQLite + portraits (git-ignored)
```

---

## Default credentials (rotate immediately)

| Field | Value |
|---|---|
| Login | `admin@brandguard.local` |
| Password | `admin1234` |
| Tenant slug | `acme` (Acme Bank, demo) |

**These are seeded on first boot only when the DB is empty.** Documented loudly in [SECURITY.md](./SECURITY.md).

## Bundled seed data (this tarball)

`data/data.db` ships **pre-populated** with the user's live workspace state at export time:

- 301 threat-actor profiles (Play, Conti, Salt Typhoon, Royal, Qilin, Hive, SilentRansomGroup, Anubis, … — TAP-001 through TAP-301)
- 18 589 parsed OSINT findings across 7-day backlog
- 71 OSINT sources configured
- 7 detection rules, 2 tabletop exercises, 200 most recent audit-log entries
- 5 tenants, 4 users (default admin + analysts)
- 18 generated/uploaded threat-actor portrait PNGs in `data/portraits/`

**API keys are NOT bundled** — `ai_providers.api_key_enc` was wiped on every row. After first boot, log in and open `/#/ai-setup` to paste your own DeepSeek / OpenAI / Anthropic / Gemini key into each row.

To start with an empty database instead: delete `data/data.db` before the first `npm run dev` or `node dist/index.cjs`.

---

## Build & run

```bash
npm install
npm run dev                      # http://localhost:5000 (HMR)
# or production:
npm run build
NODE_ENV=production node dist/index.cjs
```

On boot you should see:

```
[express] serving on port 5000
[optrasight] STRICT production mode — mock fallbacks DISABLED (NODE_ENV=production).
```

If you see `permissive mode` in production, set `OPTRASIGHT_STRICT=1`.

---

## Where to make changes

| Task | Touch these files |
|---|---|
| New route | `shared/schema.ts` → `server/storage.ts` → `server/routes.ts` → `client/src/pages/<Page>.tsx` → `client/src/App.tsx` |
| New AI task | `server/aiLive.ts` (provider call) → `server/aiClient.ts` (dispatch case) → route → client `useMutation` |
| New TAP card action | `client/src/pages/ThreatActors.tsx` (or extract into `components/tap/`) |
| New OSINT source | `server/osintSeed.ts` |
| New query grammar | `server/queryGrammars/<name>.md` + AI prompt in `server/aiClient.ts` |
| Schema change | `shared/schema.ts` (add columns) → `ensureSchema()` in `storage.ts` (idempotent ALTER TABLE) |

---

## Known god-files (next refactor targets)

These do not block shipping but are the right thing to split soon:

| File | Lines | Suggested split |
|---|---:|---|
| `server/storage.ts` | 6 700 | `storage/{tenant,osint,tap,rules,exercises,audit,integrations}.ts` + `storage/index.ts` |
| `server/routes.ts` | 2 300 | `routes/{auth,osint,tap,rules,exercises}.ts` + mount in `index.ts` |
| `client/src/pages/ThreatActors.tsx` | 2 900 | Extract `TapCard`, `TapKanban`, `TapDetailSheet`, `TapEditDialog`, `PortraitActionMenu` into `components/tap/` |
| `client/src/pages/OsintMonitoring.tsx` | 2 500 | Extract `OsintFiltersBar`, `OsintFindingsTable`, `OsintFindingRow`, `OsintDeepDivePanel`, `OsintHeatmap` into `components/osint/` |
| `client/src/pages/Exercises.tsx` | 1 700 | Extract `ExerciseCard`, `ExerciseGenerateDialog`, `ExerciseRunSheet` into `components/exercises/` |

**Do not refactor everything at once.** Split one file per branch. Run the build after each move. Verify all routes / pages still work in the browser before merging.

---

## Common pitfalls (every one of these has bitten before)

1. **TS errors on build.** 115 pre-existing errors are expected; `npm run build` still succeeds. Don't let the count grow.
2. **`<Router hook={useHashLocation}>` wraps `<Switch>`** — never put `hook` on `<Switch>`. Silent 404s.
3. **`apiRequest`, not `fetch()`.** Raw `fetch` bypasses `__PORT_5000__` substitution and 404s after deploy.
4. **`drizzle better-sqlite3` is synchronous.** Always `.get()` / `.all()` / `.run()`. Never destructure the builder.
5. **SQLite has no array type.** Lists are JSON text columns. Parse in `storage.ts`.
6. **Dynamic Tailwind classes** (`os-${sev}-bg`) must be safelisted in `tailwind.config.ts`.
7. **`<SelectItem>` requires a `value` prop** — undefined value throws at render.
8. **Portrait upload uses JSON + base64, not multipart.** Reason: matches the existing exercise PPTX upload pattern, no multer dependency.
9. **Cache-bust query string `?v=<ts>`** is mandatory for `/portraits/*` because the path is served with `Cache-Control: immutable`.
10. **AI jobs may time out at 540 s.** Don't increase further — the deploy proxy caps at 600 s.

---

## Verification recipe (always run before saying "done")

```bash
# 1. Build
cd /path/to/repo && npm run build

# 2. Start production
NODE_ENV=production OPTRASIGHT_STRICT=1 node dist/index.cjs

# 3. Smoke test the affected page in a browser

# 4. Tail the log
tail -f /tmp/optrasight.log

# 5. Verify audit row for any state change
sqlite3 data.db "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 5;"
```

---

## Glossary

| Term | Meaning |
|---|---|
| **TAP** | Threat Actor Profile — the dossier object for a named actor (e.g. Mustang Panda, Storm-0558). |
| **Wave** | Numbered slice of work that ships together (replaces semver). Current = Wave 2.1. |
| **Strict mode** | `OPTRASIGHT_STRICT=1` — no mock fallbacks; real errors surface as 409 / 502. |
| **Sigil** | The geometric SVG placeholder shown before an AI portrait loads. |
| **Magic-link token** | Public-portal URL token for exercise participants. Short-lived, single-use logical session. |
| **MSSP admin** | Cross-tenant role; can pivot tenant via `X-Tenant-Id` header. |
| **AppShell** | The shared chrome (sidebar + topbar + AI jobs tray) wrapping every protected route. |
| **ScopeBar** | The horizontal scope filter shown on Overview / Findings / OSINT pages. |
| **Async-job pattern** | Long AI tasks return `{ jobId }` immediately, run detached, write to `ai_jobs`. UI polls. |
| **Live AI** | An AI provider that is configured AND has a usable key AND `BRANDGUARD_AI_LIVE=1`. |
| **dispatchAi()** | The ONE place that talks to LLMs. Throws `LiveAiError` when live fails. |

---

## When in doubt

* Search the codebase before writing new code. The pattern usually already exists.
* Prefer extending `storage.ts` over adding logic in a route.
* Prefer extracting a component over inlining JSX > 200 lines.
* Read the matching `queryGrammars/<name>.md` before changing a detection-rule prompt.
* If you find a TODO marked `XXX` or `// HACK`, fix it in the same PR if it's < 10 lines.

Welcome, and ship cleanly.
