# =====================================================================
# OptraSight — production container
# Build:  docker build -t optrasight .
# Run:    docker run --rm -d --name optrasight -p 5000:5000 \
#           -e NODE_ENV=production -e OPTRASIGHT_STRICT=1 \
#           -v $(pwd)/data:/app/data optrasight
# =====================================================================

# ---------- Stage 1: build ----------
FROM node:20-alpine AS builder
WORKDIR /app

# native deps (better-sqlite3 needs python + build-base on alpine)
RUN apk add --no-cache python3 make g++

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

# ---------- Stage 2: runtime ----------
FROM node:20-alpine
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=5000
# Strict mode on by default — refuse mock fallbacks. Override at run time.
ENV OPTRASIGHT_STRICT=1

# Bring only what the runtime needs.
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# Persist SQLite + portrait uploads outside the container.
VOLUME ["/app/data"]

EXPOSE 5000

# Simple health probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:5000/api/v1/health || exit 1

CMD ["node", "dist/index.cjs"]
