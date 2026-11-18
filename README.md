# maekom-env

초경량 순수 Go(CGO-free) 및 SQLite(WAL) 기반 암호화 `.env` 시크릿 매니저입니다.  
웹 대시보드(React + Tailwind CSS)가 단일 Go 바이너리에 내장(`//go:embed`)되어 있으며, `mkv` CLI를 통해 디스크에 `.env` 파일을 남기지 않고 메모리로 시크릿을 안전하게 주입할 수 있습니다.

> Lightweight, zero-CGO encrypted `.env` secret manager powered by Go, SQLite (WAL), and an embedded React + Tailwind CSS dashboard.

---

## 1. 서버 배포 (`docker-compose.yml`)

### 데이터 디렉터리 권한 설정
컨테이너는 보안을 위해 `root`가 아닌 비특권 사용자(`maekom:1000`)로 실행됩니다. 호스트의 `./data` 볼륨 소유권을 반드시 `1000:1000`으로 설정하세요.

```bash
mkdir -p ./data
sudo chown -R 1000:1000 ./data
```

### `docker-compose.yml` 예시

```yaml
services:
  maekom-env:
    image: ghcr.io/maekom-hub/maekom-env:latest
    container_name: maekom-env
    restart: unless-stopped
    ports:
      # 리버스 프록시(Nginx / Caddy / Cloudflare Tunnel) 뒤에서 사용할 경우 localhost 바인딩 권장
      - "127.0.0.1:52201:8080"
    volumes:
      - ./data:/data
    environment:
      # [필수] AES-256-GCM 마스터 키 (32바이트 raw string 또는 64자리 hex, DB에 저장되지 않음)
      MASTER_KEY: "${MASTER_KEY:?MASTER_KEY is required}"
      # [필수] 웹 대시보드 관리자 로그인 비밀번호
      ADMIN_PASSWORD: "${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
      # [선택] SQLite DB 경로 (컨테이너 기본값: /data/maekom.db)
      MAEKOM_DB_PATH: "/data/maekom.db"
      # [선택] 비활성 세션 자동 만료 시간 (기본값: 30m)
      SESSION_TIMEOUT: "30m"
      # [선택] 이메일 웹훅 사용 시 SMTP 설정
      SMTP_HOST: ""
      SMTP_PORT: "587"
      SMTP_USER: ""
      SMTP_PASS: ""
      SMTP_FROM: ""
```

```bash
export MASTER_KEY=$(openssl rand -hex 32)
export ADMIN_PASSWORD="your-strong-admin-password"
docker compose up -d
```

### 최초 로그인 및 Google OTP(2FA) 등록/재설정
1. **최초 로그인 (2FA Setup)**: `ADMIN_PASSWORD`로 첫 로그인하면 2FA 등록 전용 임시 토큰과 **QR 코드(`otpauth://`) 및 수동 입력 키**가 표시됩니다. Google Authenticator(또는 호환 OTP 앱)로 스캔한 뒤 6자리 코드를 입력해 검증해야 정식 관리자 세션이 발급됩니다.
2. **이후 로그인 (2FA Verify)**: 비밀번호 입력 후 6자리 Google OTP 코드를 추가로 검증해야 로그인됩니다. (5회 연속 실패 시 해당 IP가 15분간 `HTTP 429` 차단되며, 모든 시도 이력은 `Audit Logs`에 기록됩니다.)
3. **OTP 변경/재설정**: 로그인 후 대시보드 상단 **보안 / OTP 설정 (`Security / OTP`)** 탭에서 현재 비밀번호(또는 현재 유효한 OTP 코드)를 재검증한 뒤 새 QR 코드를 발급받을 수 있습니다. 새 6자리 코드를 확정하기 전까지는 기존 OTP가 유지됩니다.

> **참고**: 세션 쿠키는 `HttpOnly; Secure; SameSite=Strict`로 발급되므로 운영 환경에서는 반드시 HTTPS(TLS 리버스 프록시)를 통해 접속하세요.

---

## 2. `mkv` CLI 설치 및 인증

### 바이너리 다운로드 (GitHub Releases)

**Linux (`amd64` / `arm64`)**:
```bash
# amd64
curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-linux-amd64
# arm64 (AWS Graviton, Raspberry Pi 등)
# curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-linux-arm64

chmod +x mkv
sudo mv mkv /usr/local/bin/mkv
mkv version
```

**macOS (`darwin-arm64` Apple Silicon)**:
```bash
curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-darwin-arm64
chmod +x mkv
sudo mv mkv /usr/local/bin/mkv
mkv version
```

### 서비스 토큰 인증 (`mkv login`)
웹 대시보드의 **Service Tokens** 탭에서 프로젝트용 토큰(`mkv_...`)을 발급받은 뒤 로그인합니다. 접속 정보는 `~/.maekom/config.json`에 `0600` 권한으로 저장됩니다.

```bash
mkv login --url https://env.example.com --token "mkv_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

---

## 3. 실전 사용법 (메모리 주입 & `.env` 대체)

`mkv_...` 서비스 토큰 자체가 발급 시점에 특정 **프로젝트**에 자동 귀속되므로, CLI 실행 시 `-p`(프로젝트) 옵션을 지정할 필요 없이 **환경 플래그(`-e dev`, `-e prod`)만 지정**하면 됩니다. (토큰이 특정 환경까지 고정된 경우 `-e`도 생략 가능)

### 디스크에 `.env` 파일을 만들지 않고 실행 (`mkv run`)
`mkv run`은 서버에서 복호화된 시크릿을 받아 자식 프로세스의 메모리(`os.Environ()`)에만 병합한 뒤 실행하며, `SIGINT`/`SIGTERM` 시그널도 자식 프로세스로 그대로 전달합니다.

```bash
# Python (uv) 애플리케이션 실행
mkv run -e dev -- uv run python main.py

# 특정 환경변수가 정상 주입되었는지 확인
mkv run -e dev -- printenv BLOG_ID
```

### Python 코드 연동 예시
별도의 `python-dotenv` 없이 표준 라이브러리 `os.getenv`만 사용하면 됩니다.

```python
import os

blog_id = os.getenv("BLOG_ID")
api_key = os.getenv("OPENAI_API_KEY")

if not blog_id:
    raise RuntimeError("BLOG_ID is not set")
```

### Crontab 등록 예시
```cron
# 매일 오전 9시 10분, 디스크 .env 없이 prod 환경변수를 주입해 배치 실행
10 9 * * * /usr/local/bin/mkv run -e prod -- /home/ubuntu/app/.venv/bin/python /home/ubuntu/app/main.py >> /var/log/my-job.log 2>&1
```

### Systemd 서비스 등록 예시 (`/etc/systemd/system/myapp.service`)
```ini
[Unit]
Description=My App with maekom-env
After=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/app
ExecStart=/usr/local/bin/mkv run -e prod -- /home/ubuntu/app/.venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 부득이하게 `.env` 파일이 필요한 경우 (`mkv pull` / `mkv push`)
레거시 도구나 Docker `--env-file` 등 로컬 파일이 반드시 필요한 경우에만 `pull`을 사용하세요.

```bash
# dev 환경 시크릿을 .env 파일(0600 권한)로 내려받기
mkv pull -e dev -o .env

# 로컬 .env 파일을 서버로 일괄 업로드 (write 권한 토큰 필요)
mkv push -e dev .env
```
