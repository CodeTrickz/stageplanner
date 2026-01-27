## Docker (production)

### 1) Create `.env`

Docker Compose reads a `.env` file automatically. Copy `env.example` to `.env` and edit it:

- **DOMAIN**: your public domain (e.g. `example.com`)
- **SUBDOMAIN**: Traefik dashboard subdomain (default `traefik`)
- **ACME_EMAIL**: Let's Encrypt email
- **TRAEFIK_AUTH**: basic auth hash for Traefik/metrics/tracing dashboards
- **JWT_SECRET**: long random secret
- **APP_URL**: public URL of your app (e.g. `https://example.com`)
- **CORS_ORIGIN**: must match where you open the UI (e.g. `https://example.com`)
- **SMTP_HOST/SMTP_USER/SMTP_PASS**: SMTP settings for real email sending (optional)
- **MAIL_FROM**: From address (optional, defaults to `SMTP_USER`)
- **CACHE_TTL_SECONDS**: backend cache TTL (seconds)
- **NOTIFICATIONS_SOON_DAYS**: days before deadline to notify (0 disables "soon")
- **NOTIFICATIONS_JOB_INTERVAL_MS**: job interval for deadline scan (ms)
- **VITE_IDLE_LOGOUT_MINUTES**: frontend idle logout (0 = never, default 30)

### 2) Start

```bash
docker compose up --build -d
```

### 3) Open

- Web UI: `https://<DOMAIN>`
- Traefik dashboard: `https://<SUBDOMAIN>.<DOMAIN>`
- Prometheus: `https://metrics.<DOMAIN>` (if enabled)
- Jaeger UI: `https://tracing.<DOMAIN>`

### Notes

- Traefik terminates TLS and issues certificates via Let's Encrypt.
- The backend is **not exposed** to the host (only reachable via Traefik).
- SQLite data is stored in `backend/data` (bind mount).









