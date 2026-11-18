# maekom-env

Ultra-lightweight, zero-CGO encrypted `.env` secret manager built with Go, SQLite (WAL), and an embedded React + Tailwind CSS dashboard.

초경량 순수 Go(CGO-free) 및 SQLite(WAL) 기반 암호화 `.env` 시크릿 매니저입니다. 웹 대시보드(SPA)가 단일 Go 바이너리에 내장되어 있으며, `mkv` CLI를 통해 디스크에 `.env` 파일을 남기지 않고 안전하게 시크릿을 주입할 수 있습니다.

---

## Features / 주요 기능

- **AES-256-GCM Encryption**: Every secret value is encrypted with a unique 12-byte random nonce (`crypto/rand`). `MASTER_KEY` lives in memory only and is never stored in SQLite.
- **Pure-Go SQLite (WAL)**: Uses `modernc.org/sqlite` with `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;` and automatic schema migrations.
- **Hardened Web Dashboard**:
  - IP-based login rate limiting (5 consecutive failures -> 15m `HTTP 429` block) & `audit_logs` tracking
  - `HttpOnly; Secure; SameSite=Strict` session cookies with sliding 30m idle timeout (`SESSION_TIMEOUT`)
  - Optional TOTP 2FA (`TOTP_SECRET`)
  - CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`
  - Auto-masking reveal (10s) & auto-clearing clipboard (30s)
- **`mkv` CLI**:
  - `mkv login --url <url> --token <mkv_...>` (`~/.maekom/config.json` with `0600`)
  - `mkv run [-e <env>] -- <cmd...>` (in-memory env injection, zero `.env` written to disk, `SIGINT`/`SIGTERM` forwarding)
  - `mkv pull [-e <env>] [-o .env]` & `mkv push [-e <env>] [.env]`
- **Webhooks & Expiry Alerts**:
  - Async `secret.updated` notifications for Discord, Slack, Email (SMTP), and Custom (`X-Maekom-Signature` HMAC-SHA256)
  - Hourly background scheduler for D-7 and D-1 expiration alerts (never includes plaintext secret values)

---

## Quick Start (Docker Compose)

```bash
export MASTER_KEY=$(openssl rand -hex 32)
export ADMIN_PASSWORD="change-this-strong-password"
docker compose up -d
```

Open `https://your-domain` (or `http://localhost:8080` behind TLS reverse proxy).

---

## Environment Variables / 환경변수

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `MASTER_KEY` | Yes | - | 32-byte raw string or 64-char hex key for AES-256-GCM |
| `ADMIN_PASSWORD` | Yes | - | Web dashboard admin password |
| `TOTP_SECRET` | No | `""` | Base32 secret to enable 6-digit 2FA TOTP on admin login |
| `SESSION_TIMEOUT` | No | `30m` | Sliding idle session expiration (e.g. `30m`, `1h`) |
| `MAEKOM_DB_PATH` | No | `maekom.db` | SQLite database file path (`/data/maekom.db` in Docker) |
| `MAEKOM_ADDR` | No | `:8080` | HTTP listen address |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | No | `587` | SMTP settings for email webhook alerts |

---

## Local Build / 로컬 빌드

```bash
cd web && npm install && npm run build
cd ..
CGO_ENABLED=0 go build -o bin/maekom-server ./cmd/server
CGO_ENABLED=0 go build -o bin/mkv ./cmd/cli
```
