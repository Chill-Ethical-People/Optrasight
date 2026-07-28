#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
INSTALL_DIR="/opt/optrasight"
BACKUP_DIR="/var/backups/optrasight"
PORT="5000"
SERVICE_USER="optrasight"

while (($#)); do
  case "$1" in
    --source) SOURCE_DIR="$2"; shift 2 ;;
    --install) INSTALL_DIR="$2"; shift 2 ;;
    --backup) BACKUP_DIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --user) SERVICE_USER="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ "$(uname -s)" == "Linux" ]] || { echo "This installer supports Linux only." >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo "Run with sudo or as root." >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT >= 1 && PORT <= 65535)) || { echo "Port must be 1-65535." >&2; exit 2; }

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
[[ -f "$SOURCE_DIR/package.json" && -d "$SOURCE_DIR/server" ]] || { echo "Source is not an OptraSight release." >&2; exit 1; }
[[ "$INSTALL_DIR" == /* && "$BACKUP_DIR" == /* ]] || { echo "Install and backup paths must be absolute." >&2; exit 2; }
[[ "$INSTALL_DIR" != "/" && "$INSTALL_DIR" != "/opt" && "$BACKUP_DIR" != "$INSTALL_DIR"/* ]] || { echo "Unsafe install or backup path." >&2; exit 2; }

NODE_BIN="$(command -v node || true)"
NPM_BIN="$(command -v npm || true)"
[[ -n "$NODE_BIN" && -n "$NPM_BIN" ]] || { echo "Node.js and npm are required." >&2; exit 1; }
NODE_MAJOR="$($NODE_BIN -p 'process.versions.node.split(".")[0]')"
[[ "$NODE_MAJOR" == "20" || "$NODE_MAJOR" == "22" ]] || { echo "Node.js 20 or 22 is required." >&2; exit 1; }
command -v rsync >/dev/null || { echo "rsync is required." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required." >&2; exit 1; }

id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
PARENT="$(dirname "$INSTALL_DIR")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE="$PARENT/.optrasight-stage-$STAMP-$$"
PREVIOUS="$PARENT/.optrasight-previous-$STAMP"
BACKUP="$BACKUP_DIR/$STAMP"
mkdir -p "$PARENT" "$BACKUP" "$STAGE"

cleanup() {
  if [[ -d "$STAGE" && "$STAGE" == "$PARENT"/.optrasight-stage-* ]]; then rm -rf -- "$STAGE"; fi
}
trap cleanup EXIT

rsync -a --delete \
  --exclude '.git/' --exclude 'node_modules/' --exclude 'dist/' \
  --exclude '.env' --exclude 'data/' --exclude 'data.db*' --exclude 'logs/' \
  "$SOURCE_DIR/" "$STAGE/"
(
  cd "$STAGE"
  "$NPM_BIN" ci
  "$NPM_BIN" run check
  "$NPM_BIN" run build
  "$NPM_BIN" prune --omit=dev
)

systemctl stop optrasight.service 2>/dev/null || true
if [[ -d "$INSTALL_DIR" ]]; then
  runtime=()
  for item in .env data data.db data.db-wal data.db-shm logs; do [[ -e "$INSTALL_DIR/$item" ]] && runtime+=("$item"); done
  if ((${#runtime[@]})); then
    tar -C "$INSTALL_DIR" -czf "$BACKUP/runtime.tar.gz" "${runtime[@]}"
    sha256sum "$BACKUP/runtime.tar.gz" > "$BACKUP/SHA256SUMS"
  fi
  mv "$INSTALL_DIR" "$PREVIOUS"
fi
mv "$STAGE" "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/logs"
if [[ -f "$BACKUP/runtime.tar.gz" ]]; then tar -C "$INSTALL_DIR" -xzf "$BACKUP/runtime.tar.gz"; fi
if [[ -f "$INSTALL_DIR/data.db" && ! -f "$INSTALL_DIR/data/data.db" ]]; then mv "$INSTALL_DIR/data.db" "$INSTALL_DIR/data/data.db"; fi
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
  KEK="$(openssl rand -base64 32)"
  printf 'NODE_ENV=production\nPORT=%s\nOPTRASIGHT_STRICT=1\nOPTRASIGHT_AI_LIVE=1\nOPTRASIGHT_DB_PATH=%s\nOPTRASIGHT_KEY_ENCRYPTION_KEY=%s\n' \
    "$PORT" "$INSTALL_DIR/data/data.db" "$KEK" > "$INSTALL_DIR/.env"
fi
chmod 600 "$INSTALL_DIR/.env"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

cat > /etc/systemd/system/optrasight.service <<EOF
[Unit]
Description=OptraSight threat intelligence platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$NODE_BIN $INSTALL_DIR/dist/index.cjs
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/data $INSTALL_DIR/logs
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now optrasight.service

healthy=0
for _ in {1..30}; do
  if curl --fail --silent --max-time 3 "http://127.0.0.1:$PORT/api/v1/health" >/dev/null; then healthy=1; break; fi
  sleep 1
done
if [[ "$healthy" != "1" ]]; then
  systemctl stop optrasight.service || true
  if [[ -d "$PREVIOUS" ]]; then
    mv "$INSTALL_DIR" "$PARENT/.optrasight-failed-$STAMP"
    mv "$PREVIOUS" "$INSTALL_DIR"
    systemctl start optrasight.service || true
  fi
  echo "Health check failed; the previous installation was restored." >&2
  exit 1
fi

echo "OptraSight is running at http://127.0.0.1:$PORT"
echo "Verified backup: $BACKUP"
