# maekom-env

> **Zero-Disk `.env` Secret Manager** — AES-256-GCM encrypted central vault in pure Go + SQLite (WAL), embedded React dashboard with Google OTP (2FA), and `mkv` CLI for in-memory secret injection.

<p align="center">
  <a href="#korean-guide"><strong>🇰🇷 한국어 가이드</strong></a>
  &nbsp;|&nbsp;
  <a href="#english-guide"><strong>🇺🇸 English Guide</strong></a>
</p>

---

<a id="korean-guide"></a>

## 🇰🇷 한국어 가이드

### 프로젝트 개요 & 보안 아키텍처

`maekom-env`는 서버나 개발 환경 디스크에 평문 `.env` 파일을 남기지 않고, 중앙 관리 서버에서 시크릿을 **AES-256-GCM**으로 암호화 보관한 뒤 애플리케이션 실행 시점(`mkv run`)에 **자식 프로세스 메모리에만 환경변수를 주입**하는 초경량 오픈소스 시크릿 매니저입니다.

- **Zero-Disk Secret Injection (`mkv run`)**: 서버에서 복호화한 시크릿을 디스크에 저장하지 않고 `os.Environ()`에 병합하여 자식 프로세스 메모리로만 전달합니다. 프로세스 종료 시 시크릿도 함께 소멸합니다.
- **Zero-CGO Pure Go + SQLite WAL**: 외부 DB 서버 없이 단일 컨테이너·단일 바이너리로 동작하며(`modernc.org/sqlite`), `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`으로 동시성 잠금을 방지합니다.
- **AES-256-GCM & 메모리 전용 마스터 키**: 모든 시크릿과 관리자 TOTP 시크릿은 `MASTER_KEY`로 암호화(12바이트 고유 Nonce)되며, `MASTER_KEY`는 DB에 절대 저장되지 않습니다.
- **강화된 관리자 보안**: `ADMIN_PASSWORD` + **Google OTP(TOTP 2FA)** 의무 등록/검증, 5회 로그인 실패 시 15분 IP 차단(`HTTP 429`), `HttpOnly; Secure; SameSite=Strict` 세션 쿠키(30분 비활성 만료), 감사 로그(`Audit Logs`), CSP/보안 헤더를 기본 적용합니다.
- **프로젝트 격리 Service Token (`mkv_...`)**: 토큰은 SHA-256 해시만 DB에 저장되며, 프로젝트·환경(`local`/`dev`/`staging`/`prod`)·스코프(`read`/`write`)·허용 IP로 세밀하게 격리됩니다.
- **KO / EN 웹 대시보드 & 알림**: 한국어/영어 전환 UI, 10초 자동 마스킹/30초 클립보드 자동 비우기, Discord/Slack/Email/Custom(HMAC-SHA256) 웹훅 및 D-7/D-1 만료 알림 스케줄러를 내장합니다.

---

### Part 1. 관리 서버 초기 세팅 가이드 (Docker / Synology NAS 기준)

#### Step 1. 영구 데이터 디렉토리 생성 및 권한 설정
컨테이너는 보안을 위해 `root`가 아닌 비특권 사용자(`maekom`, UID/GID `1000`)로 실행됩니다. SQLite 데이터베이스가 저장될 호스트의 `./data` 디렉토리 소유권을 반드시 `1000:1000`으로 설정하세요.

```bash
mkdir -p ./data
sudo chown -R 1000:1000 ./data
```

#### Step 2. 암호화용 `MASTER_KEY` 발급
AES-256-GCM 암호화에 사용할 64자리 hex(32바이트) 마스터 키를 생성합니다.

```bash
openssl rand -hex 32
```

> [!WARNING]
> **`MASTER_KEY`는 데이터베이스에 저장되지 않습니다.**  
> 이 키를 분실하면 저장된 모든 시크릿과 2FA TOTP 설정을 복호화할 수 없으므로, 반드시 별도의 안전한 비밀번호 관리자나 오프라인 백업에 보관하세요.

#### Step 3. `docker-compose.yml` 작성 및 실행
아래 `docker-compose.yml` 파일을 작성합니다. 호스트 포트를 `127.0.0.1:52201:8080`으로 바인딩하여 외부 네트워크에서 컨테이너 포트로 직접 접근하는 것을 차단하고, 리버스 프록시 또는 Cloudflare Tunnel을 통해서만 접속하도록 구성합니다.

```yaml
services:
  maekom-env:
    image: ghcr.io/maekom-hub/maekom-env:latest
    container_name: maekom-env
    restart: unless-stopped
    ports:
      # 외부 직접 노출을 막고 로컬 리버스 프록시 / Cloudflare Tunnel 전용으로 바인딩
      - "127.0.0.1:52201:8080"
    volumes:
      - ./data:/data
    environment:
      # [필수] Step 2에서 생성한 64자리 hex (또는 32바이트 문자열)
      MASTER_KEY: "여기에_openssl_rand_hex_32_결과_입력"
      # [필수] 웹 대시보드 관리자 비밀번호
      ADMIN_PASSWORD: "여기에_강력한_관리자_비밀번호_입력"
      # [필수] 컨테이너 내부 SQLite DB 경로
      MAEKOM_DB_PATH: "/data/maekom.db"
      # [선택] 세션 비활성 자동 만료 시간 (기본값: 30m)
      SESSION_TIMEOUT: "30m"
      # [선택] 이메일 웹훅 사용 시 SMTP 설정
      SMTP_HOST: ""
      SMTP_PORT: "587"
      SMTP_USER: ""
      SMTP_PASS: ""
      SMTP_FROM: ""
```

컨테이너를 백그라운드로 실행하고 헬스체크 엔드포인트를 확인합니다.

```bash
docker compose up -d
curl -I http://127.0.0.1:52201/healthz
```

정상 기동 시 `HTTP/1.1 200 OK` 응답이 반환됩니다.

#### Step 4. 외부 HTTPS 연결 (Cloudflare Tunnel / 리버스 프록시)
세션 쿠키는 `HttpOnly; Secure; SameSite=Strict` 플래그로 발급되므로, 운영 환경에서는 반드시 HTTPS를 통해 접속해야 합니다.

- **Cloudflare Tunnel (`cloudflared`)**: Public Hostname(`env.your-domain.com`)의 Service URL을 `http://localhost:52201` (또는 Synology NAS 내부 IP `http://127.0.0.1:52201`)로 지정하세요.
- **Nginx / Caddy / Synology 역방향 프록시**: HTTPS(`443`) 종단 후 `http://127.0.0.1:52201`로 프록시하고 `X-Forwarded-For` 헤더를 전달하세요.

#### Step 5. 최초 웹 로그인 및 Google OTP(2FA) 등록
1. 브라우저에서 `https://env.your-domain.com`에 접속해 설정한 `ADMIN_PASSWORD`로 로그인합니다. (우측 상단 `KO | EN` 버튼으로 언어를 전환할 수 있습니다.)
2. **최초 로그인 시 2FA 등록 화면**이 자동으로 표시됩니다. (이 단계에서는 정식 세션이 발급되지 않으며, 2FA 등록 전용 임시 토큰만 발급됩니다.)
3. Google Authenticator 또는 호환 OTP 앱으로 화면의 **QR 코드**를 스캔하거나 **수동 시크릿 키**를 입력합니다.
4. 앱에 표시된 6자리 OTP 코드를 입력해 검증을 완료하면 DB에 암호화 저장(`enabled=true`)되고 정식 관리자 세션이 발급됩니다.
5. 추후 기기 변경 등으로 OTP를 교체해야 할 때는 대시보드 상단 **보안 / OTP 설정 (`Security / OTP`)** 탭에서 현재 비밀번호(또는 현재 유효한 OTP 코드)를 재검증한 뒤 새 QR 코드를 발급받을 수 있습니다.

#### Step 6. 프로젝트 / 환경 / 시크릿 / 서비스 토큰 발급 순서
1. **프로젝트 생성**: 좌측 사이드바에서 프로젝트(예: `my-python-bot`)를 생성합니다.
2. **환경 생성**: 프로젝트 아래에 `local`, `dev`, `staging`, `prod` 등 필요한 환경을 추가합니다.
3. **시크릿 등록**: `Secrets` 탭에서 `KEY`(`.env` 표준 규칙 `^[A-Za-z_][A-Za-z0-9_]*$`)와 `Value`(입력 중 평문 표시, 한글·특수문자·멀티라인 지원)를 입력하고 필요시 만료일을 지정합니다. 기존 `.env` 파일이 있다면 **`.env 가져오기`** 모달로 한 번에 붙여넣을 수 있습니다.
4. **서비스 토큰 발급**: `Service Tokens` 탭에서 CLI/서버용 토큰을 생성합니다.
   - **Scope**: 실행 전용 서버는 `read`, 배포/업로드가 필요하면 `write`를 선택합니다.
   - **원문 토큰(`mkv_...`)은 생성 직후 단 1회만 화면에 표시**되므로 즉시 복사해 두세요.

---

### Part 2. 클라이언트 바이너리(`mkv` CLI) 설치 및 초기 설정

#### OS/아키텍처별 바이너리 다운로드 및 설치

**Linux (`x86_64` / `amd64`)**:
```bash
curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-linux-amd64
chmod +x mkv
sudo mv mkv /usr/local/bin/mkv
mkv version
```

**Linux (`ARM64` / Graviton / Raspberry Pi)**:
```bash
curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-linux-arm64
chmod +x mkv
sudo mv mkv /usr/local/bin/mkv
mkv version
```

**macOS (`Apple Silicon` / `arm64`)**:
```bash
curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-darwin-arm64
chmod +x mkv
sudo mv mkv /usr/local/bin/mkv
mkv version
```

#### 서버 인증 (`mkv login`)
발급받은 서비스 토큰(`mkv_...`)으로 서버에 1회 로그인합니다.

```bash
mkv login --url https://your-domain.com --token "mkv_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

- 접속 정보는 `~/.maekom/config.json`에 `0600`(소유자 전용 읽기/쓰기) 권한으로 저장됩니다.
- **핵심 포인트**: 발급된 서비스 토큰 자체가 특정 프로젝트에 자동 귀속되므로, 이후 `mkv run`, `mkv pull`, `mkv push` 명령어 실행 시 프로젝트 ID(`-p`)를 별도로 입력할 필요가 없습니다.

---

### Part 3. 실전 사용법 (메모리 주입 & `.env` 대체)

#### 기본 실행 (`mkv run`)
`--` 구분자 뒤에 실행할 명령어를 적으면, 지정한 환경(`-e`)의 시크릿을 서버에서 가져와 자식 프로세스의 메모리에만 주입한 뒤 실행합니다.

```bash
mkv run -e dev -- [실행할 명령어]
```

**동작 확인용 테스트 명령어**:
```bash
# 특정 키 값이 정상적으로 메모리에 주입되는지 확인
mkv run -e dev -- printenv YOUR_KEY

# 주입된 전체 환경변수 키 목록만 확인 (값 노출 없이 키만 출력)
mkv run -e dev -- env | cut -d= -f1
```

#### Python / `uv` 프로젝트 연동 예시
애플리케이션 코드에서는 `python-dotenv` 같은 파일 로더 없이 표준 라이브러리 `os.getenv`만 사용합니다.

```python
import os

api_key = os.getenv("YOUR_KEY")
if not api_key:
    raise RuntimeError("YOUR_KEY environment variable is missing")

print("Loaded secret in memory securely.")
```

실행은 다음과 같이 `mkv run`으로 감싸서 실행합니다.

```bash
mkv run -e dev -- uv run python main.py
```

시크릿은 프로세스가 살아있는 동안에만 해당 프로세스의 메모리 환경변수에 존재하며, 프로세스가 종료되면 즉시 소멸하고 디스크에는 아무 흔적도 남지 않습니다.

#### 운영 자동화 등록 예시 (Crontab & Systemd)

**Crontab 예시**:  
Cron 환경에서는 `PATH`가 제한적이므로 `/usr/local/bin/mkv` 전체 경로를 지정하세요.

```cron
# 매일 오전 9시 10분, prod 환경 시크릿을 메모리에 주입해 배치 스크립트 실행
10 9 * * * /usr/local/bin/mkv run -e prod -- /home/ubuntu/app/.venv/bin/python /home/ubuntu/app/main.py >> /var/log/my-batch.log 2>&1
```

**Systemd 서비스 예시 (`/etc/systemd/system/my-app.service`)**:

```ini
[Unit]
Description=My Application (maekom-env)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/my-app
ExecStart=/usr/local/bin/mkv run -e prod -- /home/ubuntu/my-app/.venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### 다중 프로젝트 운영 팁
한 서버에서 여러 프로젝트를 동시에 운영할 때는 `MAEKOM_CONFIG` 환경변수로 프로젝트별 설정 파일을 분리할 수 있습니다.

```bash
# 프로젝트 A는 기본 ~/.maekom/config.json 사용, 프로젝트 B는 별도 파일에 로그인
MAEKOM_CONFIG=~/.maekom/project-b.json mkv login --url https://your-domain.com --token "mkv_project_b_token"

# 실행 시에도 MAEKOM_CONFIG만 지정하면 프로젝트 B 시크릿 주입
MAEKOM_CONFIG=~/.maekom/project-b.json mkv run -e prod -- uv run python worker.py
```

#### 레거시 호환용 `.env` 파일 추출 (`mkv pull`)
Docker `--env-file` 등 부득이하게 로컬 `.env` 파일이 꼭 필요한 경우에만 `mkv pull`을 사용하세요.

```bash
mkv pull -e dev -o .env
```

> [!CAUTION]
> `mkv pull`로 생성된 `.env` 파일은 평문 시크릿을 포함하므로, 실수로 Git에 커밋되지 않도록 반드시 `.gitignore`에 `.env`를 등록하고 사용 후 삭제하는 것을 권장합니다.

---

<a id="english-guide"></a>

## 🇺🇸 English Guide

[⬆️ 한국어로 돌아가기](#korean-guide)

### Overview & Security Architecture

`maekom-env` is an ultra-lightweight, open-source secret manager that eliminates plaintext `.env` files on disk. Secrets are stored centrally with **AES-256-GCM** encryption and injected strictly into the **child process memory** at runtime via `mkv run`.

- **Zero-Disk Secret Injection (`mkv run`)**: Decrypted secrets are merged into `os.Environ()` in memory and passed directly to the child process. When the process exits, the secrets vanish with it.
- **Zero-CGO Pure Go + SQLite WAL**: Runs as a single static binary/container (`modernc.org/sqlite`) with `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;` to prevent lock contention under concurrent access.
- **AES-256-GCM & Memory-Only Master Key**: Every secret and the admin TOTP secret are encrypted with `MASTER_KEY` (using a unique 12-byte random nonce per encryption). `MASTER_KEY` is never persisted to SQLite.
- **Hardened Admin Authentication**: `ADMIN_PASSWORD` + mandatory **Google OTP (TOTP 2FA)** enrollment/verification, IP-based brute-force protection (5 failures → 15-minute `HTTP 429` block), `HttpOnly; Secure; SameSite=Strict` session cookies (30-minute idle expiration), Audit Logs, and strict CSP/security headers.
- **Project-Scoped Service Tokens (`mkv_...`)**: Only SHA-256 token hashes are stored in SQLite, isolated by project, environment (`local`/`dev`/`staging`/`prod`), scope (`read`/`write`), and optional IP/CIDR allowlists.
- **KO / EN Web Dashboard & Notifications**: Bilingual UI, 10s auto-masking reveal & 30s clipboard auto-clear, Discord/Slack/Email/Custom (HMAC-SHA256) webhooks, and an hourly D-7/D-1 expiration alert scheduler.

---

### Part 1. Management Server Setup (Docker / Synology NAS)

#### Step 1. Create Persistent Data Directory & Set Ownership
For security, the container runs as a non-root user (`maekom`, UID/GID `1000`). Ensure the host `./data` directory is owned by `1000:1000`.

```bash
mkdir -p ./data
sudo chown -R 1000:1000 ./data
```

#### Step 2. Generate the `MASTER_KEY`
Generate a 64-character hex (32-byte) key for AES-256-GCM encryption:

```bash
openssl rand -hex 32
```

> [!WARNING]
> **`MASTER_KEY` is never stored in the database.**  
> If you lose this key, all encrypted secrets and TOTP settings become unrecoverable. Store a backup in a secure password manager or offline vault.

#### Step 3. Create `docker-compose.yml` & Start the Server
Bind the host port to `127.0.0.1:52201:8080` so the container is never exposed directly to the public internet and is only reachable via a reverse proxy or Cloudflare Tunnel.

```yaml
services:
  maekom-env:
    image: ghcr.io/maekom-hub/maekom-env:latest
    container_name: maekom-env
    restart: unless-stopped
    ports:
      # Bind to localhost only; expose externally via reverse proxy or Cloudflare Tunnel
      - "127.0.0.1:52201:8080"
    volumes:
      - ./data:/data
    environment:
      # [Required] 64-char hex (or 32-byte raw) key generated in Step 2
      MASTER_KEY: "your_64_char_hex_master_key_here"
      # [Required] Admin password for Web Dashboard login
      ADMIN_PASSWORD: "your_strong_admin_password"
      # [Required] SQLite database path inside the container
      MAEKOM_DB_PATH: "/data/maekom.db"
      # [Optional] Idle session expiration timeout (default: 30m)
      SESSION_TIMEOUT: "30m"
      # [Optional] SMTP settings for email webhooks
      SMTP_HOST: ""
      SMTP_PORT: "587"
      SMTP_USER: ""
      SMTP_PASS: ""
      SMTP_FROM: ""
```

Start the container and verify the health endpoint:

```bash
docker compose up -d
curl -I http://127.0.0.1:52201/healthz
```

You should see `HTTP/1.1 200 OK`.

#### Step 4. Expose Over HTTPS (Cloudflare Tunnel / Reverse Proxy)
Because session cookies use `HttpOnly; Secure; SameSite=Strict`, always access the dashboard over HTTPS in production.

- **Cloudflare Tunnel (`cloudflared`)**: Point your Public Hostname (`env.your-domain.com`) to `http://localhost:52201` (or `http://127.0.0.1:52201`).
- **Nginx / Caddy / Synology Reverse Proxy**: Terminate TLS on port `443`, proxy to `http://127.0.0.1:52201`, and forward `X-Forwarded-For`.

#### Step 5. First Web Login & Google OTP (2FA) Enrollment
1. Open `https://env.your-domain.com` and sign in with `ADMIN_PASSWORD`. (Use the `KO | EN` toggle in the top-right corner to switch languages.)
2. On your **very first login**, the server issues a short-lived 2FA setup token (no full session yet) and displays a **QR code** and manual Base32 secret.
3. Scan the QR code with Google Authenticator (or any standard TOTP app) and enter the 6-digit code to finalize setup. The encrypted TOTP secret is saved (`enabled=true`) and your admin session begins.
4. To rotate your OTP later, open the **Security / OTP** tab in the dashboard, re-verify with your current password (or valid OTP code), and confirm the new 6-digit code.

#### Step 6. Project, Environment, Secret & Service Token Workflow
1. **Create a Project**: Add a project (e.g., `my-python-bot`) from the left sidebar.
2. **Create Environments**: Add environments such as `local`, `dev`, `staging`, and `prod`.
3. **Add Secrets**: In the **Secrets** tab, add `KEY` (`^[A-Za-z_][A-Za-z0-9_]*$`) and `Value` (visible while typing, supports UTF-8/Korean & multiline), or bulk-import an existing `.env` file via **Import .env**.
4. **Issue a Service Token**: In **Service Tokens**, create a token (`read` for runtime servers, `write` for CI/push). Copy the `mkv_...` token immediately—it is displayed **only once**.

---

### Part 2. Installing & Authenticating the `mkv` CLI

#### Download & Install by OS/Architecture

**Linux (`x86_64` / `amd64`)**:
```bash
curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-linux-amd64
chmod +x mkv
sudo mv mkv /usr/local/bin/mkv
mkv version
```

**Linux (`ARM64` / Graviton / Raspberry Pi)**:
```bash
curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-linux-arm64
chmod +x mkv
sudo mv mkv /usr/local/bin/mkv
mkv version
```

**macOS (`Apple Silicon` / `arm64`)**:
```bash
curl -fsSL -o mkv https://github.com/maekom-hub/maekom-env/releases/latest/download/mkv-darwin-arm64
chmod +x mkv
sudo mv mkv /usr/local/bin/mkv
mkv version
```

#### Authenticate (`mkv login`)
Log in once with your `mkv_...` service token:

```bash
mkv login --url https://your-domain.com --token "mkv_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

- Credentials are saved to `~/.maekom/config.json` with `0600` permissions.
- **Key Concept**: Each service token is already bound to its project on the server, so you do **not** need a `-p` (project) flag on subsequent commands.

---

### Part 3. Production Usage & Automation

#### Running Commands with In-Memory Injection (`mkv run`)
Pass your command after `--` to inject secrets for the target environment (`-e`) into memory:

```bash
mkv run -e dev -- [command...]
```

**Quick verification commands**:
```bash
# Verify a specific secret is injected into the child process
mkv run -e dev -- printenv YOUR_KEY

# List injected variable names without printing secret values
mkv run -e dev -- env | cut -d= -f1
```

#### Python / `uv` Integration Example
Your application only needs Python's standard `os.getenv`—no `python-dotenv` or `.env` files required:

```python
import os

api_key = os.getenv("YOUR_KEY")
if not api_key:
    raise RuntimeError("YOUR_KEY environment variable is missing")

print("Loaded secret in memory securely.")
```

Run it with `mkv`:

```bash
mkv run -e dev -- uv run python main.py
```

Secrets exist solely in the child process memory during execution and are gone as soon as the process exits.

#### Automation Examples (Crontab & Systemd)

**Crontab**:  
Use the absolute path `/usr/local/bin/mkv` inside cron jobs:

```cron
10 9 * * * /usr/local/bin/mkv run -e prod -- /home/ubuntu/app/.venv/bin/python /home/ubuntu/app/main.py >> /var/log/my-batch.log 2>&1
```

**Systemd Service (`/etc/systemd/system/my-app.service`)**:

```ini
[Unit]
Description=My Application (maekom-env)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/my-app
ExecStart=/usr/local/bin/mkv run -e prod -- /home/ubuntu/my-app/.venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### Multi-Project Tip
When running multiple projects on the same host, use `MAEKOM_CONFIG` to isolate credentials per project:

```bash
MAEKOM_CONFIG=~/.maekom/project-b.json mkv login --url https://your-domain.com --token "mkv_project_b_token"
MAEKOM_CONFIG=~/.maekom/project-b.json mkv run -e prod -- uv run python worker.py
```

#### Legacy `.env` Export (`mkv pull`)
If a legacy tool strictly requires a `.env` file on disk:

```bash
mkv pull -e dev -o .env
```

> [!CAUTION]
> `.env` files created by `mkv pull` contain plaintext secrets. Ensure `.env` is listed in `.gitignore` and remove the file when no longer needed.
