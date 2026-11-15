# Proof Gatekeeper agent — Docker image (Fly.io).
# Build:  docker build -t proof-gatekeeper .
# Run:    docker run -p 8080:8080 --env-file .env proof-gatekeeper
FROM node:24-slim

WORKDIR /app

# Install production dependencies first (better layer caching).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# App code + circuit artifacts (wasm/zkey/vkey are ~2 MB total).
COPY server.mjs ./
COPY src ./src
COPY circuits ./circuits

# Runtime state lives in ./data (seen-set + idempotency + log). On Fly.io
# mount a volume at /app/data so state survives restarts/deploys (fly.toml).
RUN mkdir -p /app/data

# Run as a non-root user.
USER node

ENV NODE_ENV=production
ENV PORT=8080
ENV HOST=0.0.0.0

EXPOSE 8080

CMD ["node", "server.mjs"]
