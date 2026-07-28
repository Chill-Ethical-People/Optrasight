#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
INSTALL_DIR="$HOME/Library/Application Support/OptraSight"
BACKUP_DIR="$HOME/Library/Application Support/OptraSight Backups"
PORT="5000"
LABEL="com.optrasight.backend"

while (($#)); do
  case "$1" in
    --source) SOURCE_DIR="$2"; shift 2 ;;
    --install) INSTALL_DIR="$2"; shift 2 ;;
    --backup) BACKUP_DIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || { echo "This installer supports macOS only." >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT >= 1 && PORT <= 65535)) || { echo "Port must be 1-65535." >&2; exit 2; }
SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
[[ -f "$SOURCE_DIR/package.json" && -d "$SOURCE_DIR/server" ]] || { echo "Source is not an OptraSight release." >&2; exit 1; }
[[ "$INSTALL_DIR" == /* && "$BACKUP_DIR" == /* && "$INSTALL_DIR" != "/" ]] || { echo "Dedicated absolute paths are required." >&2; exit 2; }
[[ "$BACKUP_DIR" != "$INSTALL_DIR"/* ]] || { echo "Backup path must be outside the installation." >&2; exit 2; }

NODE_BIN="$(command -v node || true)"
NPM_BIN="$(command -v npm || true)"
[[ -n "$NODE_BIN" && -n "$NPM_BIN" ]] || { echo "Node.js and npm are required." >&2; exit 1; }
NODE_MAJOR="$($NODE_BIN -p 'process.versions.node.split(".")[0]')"
[[ "$NODE_MAJOR" == "20" || "$NODE_MAJOR" == "22" ]] || { echo "Node.js 20 or 22 is required." >&2; exit 1; }
command -v rsync >/dev/null || { echo "rsync is required." >&2; exit 1; }

PARENT="$(dirname "$INSTALL_DIR")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE="$PARENT/.optrasight-stage-$STAMP-$$"
PREVIOUS="$PARENT/.optrasight-previous-$STAMP"
BACKUP="$BACKUP_DIR/$STAMP"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$UID"
mkdir -p "$PARENT" "$BACKUP" "$STAGE" "$(dirname "$PLIST")"
cleanup() { if [[ -d "$STAGE" && "$STAGE" == "$PARENT"/.optrasight-stage-* ]]; then rm -rf -- "$STAGE"; fi; }
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

launchctl bootout "$DOMAIN" "$PLIST" 2>/dev/null || true
if [[ -d "$INSTALL_DIR" ]]; then
  runtime=()
  for item in .env data data.db data.db-wal data.db-shm logs; do [[ -e "$INSTALL_DIR/$item" ]] && runtime+=("$item"); done
  if ((${#runtime[@]})); then
    tar -C "$INSTALL_DIR" -czf "$BACKUP/runtime.tar.gz" "${runtime[@]}"
    shasum -a 256 "$BACKUP/runtime.tar.gz" > "$BACKUP/SHA256SUMS"
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

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$NODE_BIN</string><string>$INSTALL_DIR/dist/index.cjs</string></array>
  <key>WorkingDirectory</key><string>$INSTALL_DIR</string>
  <key>EnvironmentVariables</key><dict><key>DOTENV_CONFIG_PATH</key><string>$INSTALL_DIR/.env</string></dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$INSTALL_DIR/logs/optrasight-output.log</string>
  <key>StandardErrorPath</key><string>$INSTALL_DIR/logs/optrasight-error.log</string>
</dict></plist>
EOF
plutil -lint "$PLIST" >/dev/null
launchctl bootstrap "$DOMAIN" "$PLIST"

healthy=0
for _ in {1..30}; do
  if curl --fail --silent --max-time 3 "http://127.0.0.1:$PORT/api/v1/health" >/dev/null; then healthy=1; break; fi
  sleep 1
done
if [[ "$healthy" != "1" ]]; then
  launchctl bootout "$DOMAIN" "$PLIST" 2>/dev/null || true
  if [[ -d "$PREVIOUS" ]]; then
    mv "$INSTALL_DIR" "$PARENT/.optrasight-failed-$STAMP"
    mv "$PREVIOUS" "$INSTALL_DIR"
    launchctl bootstrap "$DOMAIN" "$PLIST" || true
  fi
  echo "Health check failed; the previous installation was restored." >&2
  exit 1
fi

echo "OptraSight is running at http://127.0.0.1:$PORT"
echo "Verified backup: $BACKUP"
