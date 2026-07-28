# Deployment

OptraSight is a single-process Node.js app. The server binds to one port and serves both the JSON API (`/api/*`) and the static client bundle.

## Recommended target

- **Docker container** behind **Cloudflare Tunnel** (or any TLS-terminating reverse proxy).
- SQLite is the only datastore. Containers set `OPTRASIGHT_DB_PATH=/app/data/data.db`; mount `/app/data` so the workspace DB, secret DB, portraits, and client assets survive restarts.
- The default port is 5000. Override with `PORT`.

## Platform installers

The repository includes guarded service installers for the three supported host families. Each installer validates Node.js 20/22, builds and checks staged code before stopping the current service, backs up runtime data outside the installation directory, performs a health check, and restores the previous installation when that check fails.

Linux with systemd:

```bash
sudo ./scripts/install-optrasight-linux.sh \
  --source "$PWD" \
  --install /opt/optrasight \
  --backup /var/backups/optrasight \
  --port 5000
```

The Linux service runs as an unprivileged `optrasight` account with systemd filesystem and privilege restrictions. Put the application behind a TLS reverse proxy; do not expose the Node port directly to the internet.

macOS as a per-user LaunchAgent:

```bash
./scripts/install-optrasight-macos.sh \
  --source "$PWD" \
  --port 5000
```

The macOS default locations are `~/Library/Application Support/OptraSight` and `~/Library/Application Support/OptraSight Backups`. Run the installer as the account that should own the LaunchAgent.

## Windows background service installation

OptraSight includes a guarded Windows installer that runs the backend at startup
through Task Scheduler (as `SYSTEM`), restarts it after failures, checks health every
five minutes, and opens the selected port only to the Windows Domain/Private profiles
and `LocalSubnet` by default.

Open **PowerShell as Administrator** in the newly downloaded or cloned release, then run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install-optrasight-windows.ps1
```

The script prompts for the latest source/release directory and the destination where
the application code should be installed (default `D:\OptraSight`). For a
non-interactive install:

```powershell
.\scripts\install-optrasight-windows.ps1 `
  -SourcePath "D:\Downloads\optrasight-beta" `
  -InstallPath "D:\OptraSight" `
  -BackupRoot "D:\OptraSight-backups" `
  -Port 5050 `
  -AllowedRemoteAddress "LocalSubnet"
```

The installer requires Node.js 20 LTS or 22 LTS. It stages and builds the replacement
before touching the current installation. If an installation exists, it stops the
backend, backs up and SHA-256 verifies `data.db`, SQLite WAL/SHM files, `.env`, `data/`
(including the secret store, portraits, and uploaded client assets), and existing logs.
It restores that runtime data, starts and health-checks the new installation, and only
removes the superseded application code after the health check succeeds. Backups are
stored outside the installation directory and are never included in that cleanup.

To create a standalone verified backup later:

```powershell
.\scripts\backup-optrasight-windows.ps1 `
  -InstallPath "D:\OptraSight" `
  -BackupRoot "D:\OptraSight-backups"
```

Operational commands:

```powershell
Start-ScheduledTask -TaskName "OptraSight Backend"
Stop-ScheduledTask -TaskName "OptraSight Backend"
Get-ScheduledTaskInfo -TaskName "OptraSight Backend"
Invoke-WebRequest http://127.0.0.1:5050/api/v1/health
Get-Content D:\OptraSight\logs\optrasight-error.log -Tail 100
Get-Content D:\OptraSight\logs\optrasight-service.log -Tail 100
Get-Content D:\OptraSight\logs\optrasight-health.log -Tail 100
```

The primary task is a Windows startup background service wrapper rather than an SCM
service, so it does not depend on NSSM or another unsigned third-party executable.
The launcher rotates stdout/stderr at 50 MB, preserves one prior file, and records each
process restart. The separate health task records failed probes and restarts the backend.

## Local LLM TLS

Local Ollama connectivity is opt-in. Add the following to the service `.env`, then restart
OptraSight:

```dotenv
OPTRASIGHT_ALLOW_LOCAL_AI=1
OPTRASIGHT_LOCAL_AI_CA_CERT=/absolute/path/to/local-ai-ca.pem
```

On Windows, use an absolute Windows path such as
`D:\OptraSight\certificates\local-ai-ca.pem`. Grant the OptraSight service identity read
access to that file. The CA bundle may contain one or more PEM certificates and must be no
larger than 1 MB. Configure the Ollama base URL with a hostname or IP address present in the
server certificate's subject alternative names.

The local-network exception is limited to the Ollama connector and recognizes loopback,
RFC1918 IPv4, IPv6 ULA, and reserved local hostnames. Link-local metadata addresses remain
blocked. Omitting `OPTRASIGHT_LOCAL_AI_CA_CERT` uses the operating system trust store. Do
not set `NODE_TLS_REJECT_UNAUTHORIZED=0` and do not add curl `--insecure`; both would turn a
local certificate problem into a platform-wide interception risk.

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
      OPTRASIGHT_DB_PATH: /app/data/data.db
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

Back up the configured workspace database and `data/` as a unit. For the Docker and service-installer layout:

```bash
sqlite3 data/data.db ".backup '/backups/data-$(date +%F).db'"
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

- One internal BatchOne workspace scope (`BatchOne Workspace`, slug `batchone-workspace`). This is an implementation boundary for local data, not a client tenant-switching feature.
- Local seed accounts `admin@cep.com` and `reviewer@cep.com`. **Rotate immediately** — see [SECURITY.md](./SECURITY.md).
- The curated BatchOne OSINT sources.
- Per-tenant AI provider rows (all in `disabled` state until you supply a key at `/#/ai-setup`).

After first boot:

1. Log in.
2. Change the temporary seed password, enroll MFA, then create named accounts and rotate or remove the seed accounts.
3. Configure AI providers at `/#/ai-setup`. DeepSeek is recommended (live + productional, no fallback).
4. Review OSINT sources on the Intel Inbox sources tab.
5. Use Platform Users for admin/reviewer account management.

## Logs

- `stdout` carries the express request log + `console.warn` / `console.error`.
- No log file is written by default — pipe `docker logs` to your log aggregator (Loki, Splunk, ELK).
- The Windows installer redirects stdout to `logs/optrasight-output.log`, stderr to
  `logs/optrasight-error.log`, lifecycle events to `logs/optrasight-service.log`, and
  failed watchdog probes to `logs/optrasight-health.log`.

## Resource sizing

- **CPU**: 1 vCPU is sufficient for ≤ 10 active tenants. AI jobs are bursty but bounded (one in-flight per finding).
- **RAM**: 1 GB baseline. Spikes to ~2 GB during PPTX export or large OSINT ingests.
- **Disk**: 10 GB starting (SQLite + portraits). Grows ~50 MB / month / active tenant.
