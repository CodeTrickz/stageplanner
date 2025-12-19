## Docker (production-ish) run

### 1) Create `.env`

Docker Compose reads a `.env` file automatically. Copy `env.example` to `.env` and edit it:

- **JWT_SECRET**: must be a long random secret
- **APP_URL**: public URL of your app (used in verification emails)
- **CORS_ORIGIN**: must match where you open the UI
- **WEB_PORT**: optional host port (default 8080)

### 2) Start

```bash
docker compose up --build -d
```

### 3) Open

- Web UI: `http://localhost:8080` (or your `WEB_PORT`)

### Notes for serious deployment

- Put this behind HTTPS (e.g. Caddy/Traefik/Nginx Proxy Manager) and set `APP_URL` + `CORS_ORIGIN` to your real domain.
- The backend is **not exposed** to the host (only reachable via the web container).
- SQLite data is persisted in the `backend-data` volume.




