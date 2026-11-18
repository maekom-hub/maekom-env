# Stage 1: Build Vite + React + Tailwind web dashboard
FROM node:22-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci || npm install
COPY web/ ./
RUN npm run build

# Stage 2: Build static Go binary with embedded web/dist
FROM golang:1.26-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /app/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/maekom-server ./cmd/server

# Stage 3: Minimal non-root runtime image
FROM alpine:3.20
LABEL org.opencontainers.image.source="https://github.com/maekom-hub/maekom-env"
LABEL org.opencontainers.image.description="Ultra-lightweight encrypted .env secret manager"

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 1000 maekom \
    && adduser -D -u 1000 -G maekom maekom \
    && mkdir -p /data \
    && chown -R maekom:maekom /data

COPY --from=go-builder /out/maekom-server /usr/local/bin/maekom-server

ENV MAEKOM_ADDR=:8080 \
    MAEKOM_DB_PATH=/data/maekom.db \
    SESSION_TIMEOUT=30m

VOLUME ["/data"]
EXPOSE 8080

USER maekom:maekom
ENTRYPOINT ["/usr/local/bin/maekom-server"]
