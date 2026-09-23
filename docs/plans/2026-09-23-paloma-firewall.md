# Paloma Firewall Dashboard (`paloma-fw`) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build, version-control in GitHub, and deploy via Coolify an ultra-lightweight (~15MB RAM) security dashboard on `https://fw.potencial.tec.br` storing ban/unban events and metrics in OCI MySQL HeatWave (`10.0.0.159:3306`), integrating with Fail2ban for real-time tracking, 1-click unban actions, and automated database migrations.

**Architecture:** A standalone Go microservice embedded with a high-craft responsive web UI (`embed.FS`), connecting directly to MySQL HeatWave with connection pooling and embedded SQL migrations. The service interacts with Fail2ban via the mounted socket (`/var/run/fail2ban/fail2ban.sock`) and an internal webhook, while Coolify deploys the app container under Traefik with automatic Let's Encrypt SSL termination on `fw.potencial.tec.br`.

**Tech Stack:**
- **Backend:** Go 1.25, `net/http`, `go-sql-driver/mysql`, crypto/subtle, strict `net.ParseIP` validation
- **Database:** Oracle Cloud Infrastructure MySQL HeatWave (`10.0.0.159:3306`, DB: `paloma_security`), SQL migrations runner
- **Frontend / UX:** HTML5 + OKLCH custom tokens (no AI slop, WCAG AAA contrast, semantic dark palette), Vanilla JS/SSE for live updates, toast feedback, confirmation dialogs
- **Infrastructure:** Coolify v4 PaaS on Paloma (`137.131.142.90`), Traefik v3.7 SSL proxy, Fail2ban 1.1.0 on Oracle Linux 9
- **VCS & CI/CD:** GitHub Repository `AlexandreDeCarli/paloma-fw`

---

## Task 1: Initialize Git Repository and Directory Layout

**Files:**
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/.gitignore`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/go.mod`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/README.md`

**Step 1: Write project scaffolding and go.mod**
Initialize Go module `github.com/AlexandreDeCarli/paloma-fw` and dependencies (`github.com/go-sql-driver/mysql`).

**Step 2: Verify Go dependencies**
Run `go mod tidy` and verify `go.sum` is created without errors.

**Step 3: Initialize Git repository and commit**
Run `git init`, `git add .`, and commit initial repository layout.

---

## Task 2: Database Schema & Automated Migrations Engine

**Files:**
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/migrations/000001_init_schema.up.sql`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/internal/db/migrator.go`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/internal/db/migrator_test.go`

**Step 1: Write SQL migration file**
Define tables:
- `schema_migrations` (version, name, applied_at)
- `security_events` (id, event_type, ip, jail, failures, duration_seconds, country, city, banned_at, unbanned_at, unbanned_by, created_at)
- `active_bans` (id, ip, jail, failures, banned_at, expires_at, status, unbanned_at, unbanned_by, notes)
- `audit_logs` (id, username, action, ip, details, created_at)

**Step 2: Write Go migration runner using embedded SQL files**
Implement `ApplyMigrations(db *sql.DB)` reading migrations using `//go:embed migrations/*.sql`.

**Step 3: Write test and run against mock/test connection**
Verify migrator sorts migrations, checks existing versions, and applies pending migrations idempotently.

---

## Task 3: Fail2ban Socket Integration & IPC Client

**Files:**
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/internal/fail2ban/client.go`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/internal/fail2ban/client_test.go`

**Step 1: Implement Fail2ban client**
Execute `fail2ban-client` CLI commands directly or via `/var/run/fail2ban/fail2ban.sock`:
- `GetStatus(jail string)` -> parsed list of currently banned IPs, failed counts.
- `UnbanIP(jail, ip string)` -> validates IP strictly with `net.ParseIP(ip)` before issuing unban.
- `BanIP(jail, ip string)` -> strict IP validation.

**Step 2: Write unit tests**
Test IP validation logic (valid IPv4, IPv6, rejecting shell injection attempts like `1.2.3.4; rm -rf /`).

---

## Task 4: API Endpoints & Security Layer

**Files:**
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/internal/api/handlers.go`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/internal/api/middleware.go`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/internal/api/handlers_test.go`

**Step 1: Implement authentication & middleware**
- Session/Cookie auth for web dashboard using constant-time comparison (`crypto/subtle.ConstantTimeCompare`).
- Internal secret bearer token for Fail2ban webhook notifications (`X-Internal-Secret`).
- Security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).
- Rate limiter on login attempts.

**Step 2: Implement REST & Webhook handlers**
- `POST /api/auth/login` and `POST /api/auth/logout`.
- `GET /api/bans` (active bans from DB + Fail2ban live status).
- `POST /api/bans/unban` (unban IP, update DB, record audit log).
- `GET /api/events` (paginated audit trail with search and filters).
- `GET /api/metrics` (24h statistics, top offending subnets, failure rate).
- `POST /api/internal/event` (webhook called by Fail2ban action on ban/unban).

**Step 3: Run API unit tests**
Verify authentication checks, unauthorized rejection, and webhook payload handling.

---

## Task 5: Impeccable Frontend Craft & UI Dashboard

**Files:**
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/web/index.html`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/web/styles.css`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/web/app.js`

**Step 1: Craft the UI structure and styling**
- Strict adherence to `/impeccable` guidelines:
  - Deep slate dark theme with OKLCH tokens, high contrast (≥4.5:1).
  - No AI cliches (no side-stripe borders, no cheesy gradients, no glassmorphism default, no hero-metric cards).
  - Clean operational header: "Paloma Shield // Firewall & Intrusion Defense", system status badge ("Protegido", "Live").
  - Metrics row: Active Bans, Bans nas últimas 24h, Total de Bloqueios, Taxa de 401.
  - Interactive table of Active Bans: IP, País/Geo, Jail, Erros, Data/Hora, Expira em, Ações ("Desbanir").
  - Modal de confirmação seguro para desbanir com feedback visual e toast animado.
  - Histórico de Auditoria & Eventos com busca por IP, filtro de status e paginação.
  - Auto-refresh seletivo (5s, 15s, 30s ou Manual).

**Step 2: Implement JavaScript interaction logic**
- Fetch API, error state rendering, empty state handling, copy IP with click, toast notifications, keyboard accessibility (`Esc` closes modals).

---

## Task 6: Multi-Stage Dockerfile & Coolify Orchestration

**Files:**
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/Dockerfile`
- Create: `/Users/alexandre/Documents/ProjetosAntigravity/paloma-fw/docker-compose.yml`

**Step 1: Write Dockerfile**
- Stage 1: `golang:1.25-alpine` build binary with `-ldflags="-s -w"`.
- Stage 2: `alpine:latest` with `fail2ban` and `ca-certificates` packages.
- Final image size ~25MB.
- Non-root user or root with socket permissions.

**Step 2: Configure docker-compose.yml**
- Service `paloma-fw` connected to external network `coolify`.
- Volume mount `/var/run/fail2ban/fail2ban.sock:/var/run/fail2ban/fail2ban.sock`.
- Environment variables:
  - `DB_HOST=10.0.0.159`
  - `DB_PORT=3306`
  - `DB_USER=principalUser`
  - `DB_PASSWORD=rl0ipasT-xAHUzLv-bRa`
  - `DB_NAME=paloma_security`
  - `PORT=3340`
  - `ADMIN_PASSWORD=...`
  - `INTERNAL_SECRET=...`
- Traefik labels for `fw.potencial.tec.br` with Let's Encrypt SSL.

---

## Task 7: GitHub Repository Creation & Push

**Commands:**
- `gh repo create AlexandreDeCarli/paloma-fw --public --source=. --remote=origin --push`
- Verify repo is visible on GitHub.

---

## Task 8: Coolify Application Setup & Deployment on Paloma

**Steps:**
1. Connect repository `AlexandreDeCarli/paloma-fw` in Coolify via API or Coolify UI.
2. Deploy application container with volume mount for `/var/run/fail2ban/fail2ban.sock`.
3. Verify Traefik routes `https://fw.potencial.tec.br` with automatic SSL certificate.
4. Verify database migrations run automatically on container startup in MySQL HeatWave `10.0.0.159:3306`.

---

## Task 9: Fail2ban Host Action Webhook Integration

**Files:**
- Modify on Paloma: `/etc/fail2ban/action.d/iptables-docker-multi.conf` (or create `/etc/fail2ban/action.d/paloma-fw.conf`)
- Modify on Paloma: `/etc/fail2ban/jail.d/traefik-401.local`

**Steps:**
1. Update `actionban` to send webhook notification to `http://127.0.0.1:3340/api/internal/event` (or container network) with IP, jail, failures.
2. Update `actionunban` to send unban notification.
3. Reload Fail2ban: `sudo fail2ban-client reload`.

---

## Task 10: End-to-End Verification & Audit

**Verification Steps:**
1. Access `https://fw.potencial.tec.br` in browser / curl, verify SSL, security headers, and login.
2. Simulate a ban using a safe test IP (`198.51.100.88`).
3. Verify event is instantly recorded in MySQL HeatWave (`paloma_security.security_events` and `active_bans`).
4. Verify event appears on the Web UI table in real-time.
5. Click "Desbanir" on the Web UI, verify it unbans in Fail2ban, cleans `iptables`, and updates MySQL.
6. Verify memory usage is ~15MB RAM.
