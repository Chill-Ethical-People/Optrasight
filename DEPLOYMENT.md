# Deployment

OptraSight is a single-process Node.js app. The server binds to one port and serves both the JSON API (`/api/*`) and the static client bundle.

## Recommended target

* **Docker container** behind **Cloudflare Tunnel** (or any TLS-terminating reverse proxy).
* SQLite is the only datastore — mount a volume on `/app/data` so `data.db` (and `data.db-wal`, `data.db-shm`, `data/portraits/`) survive restarts.
* The default port is 5000. Override with `PORT`.

## Dockerfile

A starter `Dockerfile` ships at the repo root. Build:

```bash
docker build -t optrasight .
docker run --rm -d \
  --name optrasight \
  -p 5000:5000 \
  -e NODE_ENV=production \
  -e OPTRASIGHT_STRICT=1 \
  -v $(pwd)/data:/app/data \
  optrasight
```

## docker-compose (recommended for self-host)

```yaml
services:
  optrasight:
    build: .
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      NODE_ENV: production
      OPTRASIGHT_STRICT: "1"
      OPTRASIGHT_AI_LIVE: "1"
    volumes:
      - ./data:/app/data
```

## Cloudflare Tunnel

```bash
cloudflared tunnel create optrasight
cloudflared tunnel route dns optrasight optrasight.example.com
cloudflared tunnel run --url http://localhost:5000 optrasight
```

Configure access policy (Cloudflare Access) in front of the tunnel — never expose port 5000 directly.

## nginx (alternative)

```nginx
server {
  listen 443 ssl http2;
  server_name optrasight.example.com;
  ssl_certificate     /etc/letsencrypt/live/optrasight.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/optrasight.example.com/privkey.pem;

  client_max_body_size 50M;     # matches the server's 50mb body limit

  location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 600s;    # AI jobs run up to 540s
  }
}
```

## Health checks

The simplest probe is `GET /api/v1/health` (returns `{ ok: true }`).

For Kubernetes / orchestrators:

```yaml
livenessProbe:
  httpGet: { path: /api/v1/health, port: 5000 }
  periodSeconds: 30
readinessProbe:
  httpGet: { path: /api/v1/health, port: 5000 }
  periodSeconds: 10
```

## Backup

Back up `data/` as a unit:

```bash
sqlite3 data.db ".backup '/backups/data-$(date +%F).db'"
tar czf /backups/portraits-$(date +%F).tar.gz data/portraits/
```

The `.backup` PRAGMA is safe to run while the server is live (WAL handles concurrent reads).

## Upgrading

1. Stop the container.
2. Pull / replace the image.
3. Start the container — `ensureSchema()` runs `ALTER TABLE ADD COLUMN` migrations idempotently on every boot. No manual migration step.
4. Tail the logs (`docker logs -f optrasight`) and confirm the production banner:
   ```
   [optrasight] STRICT production mode — mock fallbacks DISABLED (NODE_ENV=production).
   ```

## First boot

On a fresh `data/` volume the server seeds:

* One internal BatchOne workspace scope (`BatchOne Workspace`, slug `batchone-workspace`). This is an implementation boundary for local data, not a client tenant-switching feature.
* Local seed accounts `admin@cep.com` and `reviewer@cep.com`. **Rotate immediately** — see [SECURITY.md](./SECURITY.md).
* The curated BatchOne OSINT sources.
* Per-tenant AI provider rows (all in `disabled` state until you supply a key at `/#/ai-setup`).

After first boot:

1. Log in.
2. Change the temporary seed password, enroll MFA, then create named accounts and rotate or remove the seed accounts.
3. Configure AI providers at `/#/ai-setup`. DeepSeek is recommended (live + productional, no fallback).
4. Review OSINT sources on the Intel Inbox sources tab.
5. Use Platform Users for admin/reviewer account management.

## Logs

* `stdout` carries the express request log + `console.warn` / `console.error`.
* No log file is written by default — pipe `docker logs` to your log aggregator (Loki, Splunk, ELK).

## Resource sizing

* **CPU**: 1 vCPU is sufficient for ≤ 10 active tenants. AI jobs are bursty but bounded (one in-flight per finding).
* **RAM**: 1 GB baseline. Spikes to ~2 GB during PPTX export or large OSINT ingests.
* **Disk**: 10 GB starting (SQLite + portraits). Grows ~50 MB / month / active tenant.
