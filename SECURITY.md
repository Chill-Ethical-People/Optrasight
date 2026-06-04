# Security

## What to rotate immediately after first boot

| Item | Where | How to rotate |
|---|---|---|
| **Default admin account** `admin@brandguard.local / admin1234` (legacy domain — kept as primary key on existing installs) | Seeded into `users` table by `seedIfEmpty()` in `server/storage.ts` (line ~1140). | Log in once, create a new admin user with a strong password, then delete the seeded account at `/#/settings`. |
| **Bearer sessions** | `auth_sessions.token_hash` (opaque token issued by `/api/v1/auth/login`). | Logout revokes the current session. Rotating all sessions means deleting rows from `auth_sessions`. |
| **AI provider keys** | `ai_providers.api_key_enc` per tenant. | `/#/ai-setup` → edit each row. Stored encrypted at rest with the per-instance key in `data/.optrasight-kek`. |
| **Magic-link exercise tokens** | `exercise_runs.token` — public-portal access. | Tokens expire when the exercise is closed; re-issue by generating a fresh run. |

## Threat model

OptraSight is an MSSP **back-office** tool. It is assumed to run behind:

* A reverse proxy that terminates TLS (Cloudflare Tunnel, nginx, Caddy).
* An authentication boundary (the dashboard's own login is a baseline; a corporate SSO/SAML layer in front is recommended for production deployments).
* A private network — port 5000 must **never** be exposed directly to the public internet.

The internal authn model is intentionally simple but production-hardened enough for a private back-office deployment:

1. **Passwords are hashed on login** — legacy plaintext seeded rows are transparently rehashed to `scrypt:v1` after the first successful login. New password-management UI should write the same format.
2. **Add SSO / OIDC** — wire `passport-openidconnect` into the existing Passport middleware in `routes.ts`.
3. **Rate limiting is built in for sensitive public edges** — `/api/v1/auth/login` and `/api/v1/exercise-portal/*` use in-memory throttles. Put Cloudflare/nginx limits in front for distributed production traffic.

## What is encrypted, what is not

| Class of data | Storage | Encrypted? |
|---|---|---|
| User passwords | `users.password` | `scrypt:v1` hashes after first successful legacy login. |
| Session tokens | `auth_sessions.token_hash` | SHA-256 hash of an opaque random bearer token; raw token is only returned once. |
| AI provider keys | `ai_providers.api_key_enc` | AES-256-GCM with per-instance key at `data/.optrasight-kek`; keep disk-level encryption enabled. |
| Magic-link exercise tokens | `exercise_runs.token` | Random UUID v4. Short-lived. |
| Finding content (OSINT) | `osint_findings.*` | Public-source data — not sensitive. |
| Portrait images | `data/portraits/*` | Filesystem only. Validated by magic-byte sniff on upload (`POST /api/v1/threat-actors/:aid/portrait/upload`). |

## Upload validation

`POST /api/v1/threat-actors/:aid/portrait/upload` accepts only:

* PNG / JPEG / WebP / GIF (extension regex AND magic-byte sniff).
* Maximum 5 MB.

Other file uploads (exercise PPTX in `routes.ts` line ~1788) use the same JSON+base64 pattern. Add new uploads through this pattern only — there is no multer / multipart endpoint by design (a 50 MB body limit applies globally in `server/index.ts`).

## CORS

The Express server does not set CORS headers by default — the client is served from the same origin. If you split the deployment (separate API host), add `cors` middleware in `server/index.ts` with an explicit allowlist.

## Logging

* Every `/api/*` request is logged with method, path, status, duration, and a redacted response preview.
* Errors are logged via `console.error("Internal Server Error:", err)`.
* API keys, tokens, passwords, large result bodies, report content, uploaded file content, and AI outputs are redacted/truncated in the request log middleware.

## Reporting vulnerabilities

Please report suspected vulnerabilities privately to the project maintainer.
Do not include exploit details, client data, credentials, or sensitive logs in
public issues.
