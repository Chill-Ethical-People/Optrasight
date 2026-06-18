# Contributing

These conventions keep OptraSight changes reviewable, reproducible, and safe
to publish.

## Setup

```bash
npm install
cp .env.example .env
npm run dev
```

## Branch / commit style

* Branches: `wave/<n>-<short-slug>` (e.g. `wave/2-1-portrait-upload`).
* Commits: imperative, ≤ 72 chars subject line. Body explains *why* if non-obvious.
* No PR template — instead, every wave gets a one-line entry in [CHANGELOG.md](./CHANGELOG.md).

## Code conventions

### Server

* **All business logic lives in `server/storage.ts`.** Routes are thin: parse → validate → delegate → return.
* New tables go in `shared/schema.ts` first. Then add a CRUD block in `storage.ts`. Then expose via routes.
* Every CRUD write that an analyst can perform must call `storage.appendAudit(tid, actor, action, target, payload)`.
* `dispatchAi()` is the only place that talks to an LLM. Do not call providers directly from routes.
* Async AI jobs go through the `ai_jobs` table + `AiJobsProvider` polling — see [ARCHITECTURE.md](./ARCHITECTURE.md) for the pattern.
* Mock fallbacks must be gated by `isStrictProduction()` from `server/productionMode.ts`. Never silently return synthetic data when strict mode is on.

### Client

* Pages live under `client/src/pages/<RouteName>.tsx`. One file per route.
* Shared components live under `client/src/components/`. shadcn/ui base components in `components/ui/` are auto-generated — don't hand-edit.
* `apiRequest` from `@/lib/queryClient` is the only allowed HTTP helper. Never use raw `fetch()` — it bypasses the `__PORT_5000__` rewrite and 404s after deploy.
* Mutations must invalidate React Query keys: `queryClient.invalidateQueries({ queryKey: ["/api/v1/X"] })`.
* All interactive elements need a `data-testid="<action>-<target>"` attribute (e.g. `button-upload-portrait`, `input-actor-name`).
* `<Switch>` lives inside `<Router hook={useHashLocation}>`. Never put `hook` on `<Switch>`.
* **No `localStorage`, `sessionStorage`, `indexedDB`, or cookies.** They are blocked in the sandbox iframe and crash the page. Use React state + server storage instead.

### Styling

* Tailwind v3. `bg-brand-DEFAULT`, `text-brand-foreground`, `border-signal-DEFAULT`, etc. Never inline `style={{ color: '#4F46E5' }}`.
* Dark mode = `.dark` class on `<html>`. Every visual property must have both light and dark variants when using raw utilities (the design tokens auto-adapt; raw utilities don't).
* Dynamic class names must be in `tailwind.config.ts` → `safelist`.

### TypeScript

* Strict is disabled — 115 pre-existing errors are expected and don't block the build. Do not regress further. New code must be properly typed.
* Drizzle's `better-sqlite3` driver is synchronous. Terminate every query with `.get()` (one row), `.all()` (many), or `.run()` (mutation). Don't destructure the query builder.

## Adding a new page

1. Create `client/src/pages/<Name>.tsx`. Use `PageHeader` + `AppShell` (already wraps every protected route).
2. Register the route in `client/src/App.tsx` *inside* the `<Switch>`.
3. Add a sidebar entry in `client/src/components/AppShell.tsx` (`NAV_ITEMS` array).
4. Use hash routes: `/<name>` (NOT `#<name>` or `/#/<name>`).

## Adding a new API endpoint

1. Schema first: add / extend a Drizzle table in `shared/schema.ts`. Re-export the insert / select types.
2. Storage method: add `storage.<verb><Entity>(...)` in `server/storage.ts`. All persistence rules belong here.
3. Route: register in `server/routes.ts` *inside* `registerRoutes()`. Validate the body with the Zod insert schema. Delegate to storage. Return the storage result.
4. Audit: `storage.appendAudit(...)` for every state change.
5. Client: define a React Query `useQuery` / `useMutation` against the new endpoint. Invalidate the correct keys on mutate.

## Adding a new AI task

1. Define the task name (kebab-case, e.g. `"threat_landscape_summary"`).
2. Add a `<task>Live(...)` function in `server/aiLive.ts` — provider-specific HTTP call returning typed JSON or throwing `LiveAiError`.
3. Add a `case "<task>":` block in `dispatchAi()` in `server/aiClient.ts`.
4. Mock fallback (optional) — only used when no provider is configured. Add a `<task>Mock(...)` function. **Gate any call to it** through `isStrictProduction()`.
5. Wire from a route: `dispatchAi({ task: "<task>", provider, input })`. Wrap in `try/catch` and surface `LiveAiError` as 502.

## PR checklist

Before opening a PR (or marking a wave done):

- [ ] `npm run build` succeeds.
- [ ] Manual smoke test: log in, navigate to the affected page, run the new action.
- [ ] Audit row appears for every state change (`/#/settings` → Audit log).
- [ ] React Query keys are invalidated on mutate.
- [ ] No new `localStorage` / `sessionStorage` usage.
- [ ] No new `console.log` left in production paths.
- [ ] No raw `fetch()` calls in the client.
- [ ] [CHANGELOG.md](./CHANGELOG.md) updated with a one-liner.
- [ ] Screenshots attached to the PR / wave note for any UI change.

## Wave numbering

OptraSight ships in numbered waves rather than semver. Wave N is "the next coherent slice of value" — could be a new page, a redesign, a backend rewrite, or a single feature. The current head is **Wave 2.1** (see CHANGELOG).
