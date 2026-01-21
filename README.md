# Stage Planner

A modern planning application with backend and frontend, built with React, TypeScript, Express, and SQLite.

## Overview

Stage Planner is a full‑stack application for day planning, file management, and notes with workspace scoping and realtime updates:

- **Frontend**: React + TypeScript (Vite) with Material UI
- **Backend**: Express + TypeScript with SQLite database
- **Storage**: SQLite for server-side data (planning/notes/files), no local storage for core data
- **Realtime**: Server-Sent Events (SSE) per workspace

## Quick Start

### Requirements

- Node.js 20+
- npm or yarn
- Docker (optional, for production deployment)

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd stageplanner
   ```

2. **Start backend**
   ```bash
   cd backend
   npm install
   npm run dev
   ```
   Backend runs at `http://localhost:3001`.

3. **Start frontend** (new terminal)
   ```bash
   cd stage-planner
   npm install
   npm run dev
   ```
   Frontend opens at `http://localhost:5173`.

### Docker Deployment

See [README.docker.md](./README.docker.md) for instructions to run the app with Docker Compose (Traefik + Prometheus + Jaeger).

## Project Structure

```
.
├── backend/            # Express backend (TypeScript)
│   ├── src/            # Source code
│   ├── data/           # SQLite databases (gitignored)
│   └── prisma/         # Database schema (if used)
├── stage-planner/      # React frontend (TypeScript)
│   ├── src/            # Source code
│   │   ├── api/        # API client
│   │   ├── auth/       # Authentication
│   │   ├── components/ # React components
│   │   ├── pages/      # Page components
│   │   └── utils/      # Utility functions
│   └── public/         # Static assets
├── .github/            # GitHub workflows and templates
└── docker-compose.yml  # Docker Compose configuration
```

## Configuration

### Backend

Copy `backend/env.example` to `backend/env.local` and edit:

- `JWT_SECRET`: long random string for JWT tokens
- `APP_URL`: public URL of the app (for verification emails)
- `CORS_ORIGIN`: CORS origin (must match frontend URL)
- `SMTP_HOST/SMTP_USER/SMTP_PASS`: SMTP config for real emails
- `MAIL_FROM`: sender address for emails (optional, defaults to `SMTP_USER`)

#### Admin user

The app auto-creates a default admin on startup in development mode (or if `SEED_ADMIN=true`).

**Default credentials:**
- **Email**: `admin@app.be`
- **Username**: `admin`
- **Password**: `admin`

Override via `backend/env.local`:
- `SEED_ADMIN=true` - enable admin seeding (default on in development)
- `ADMIN_EMAIL=admin@app.be`
- `ADMIN_USERNAME=admin`
- `ADMIN_PASSWORD=admin`

**Important for production:**
- Change admin credentials via `.env`
- Or set `SEED_ADMIN=false` and create an admin user manually via the API

### Frontend

The frontend uses Vite environment variables. For local dev you can create `stage-planner/.env.local`.
Important:
- `VITE_IDLE_LOGOUT_MINUTES` (0 = never, default 30)

## Development

### Backend scripts

- `npm run dev` - start development server with hot reload
- `npm run build` - production build
- `npm start` - start production server

### Frontend scripts

- `npm run dev` - start development server
- `npm run build` - production build
- `npm run lint` - run ESLint
- `npm run preview` - preview production build

## Features

- ✅ Dashboard with planning overviews
- ✅ Day planning with time slots
- ✅ Week overview (7 days)
- ✅ Task overview with filters
- ✅ Bulk actions in planning (multi-select, status/priority/tags)
- ✅ File management (upload/download via backend, stored in SQLite)
- ✅ Notes with attachments
- ✅ Export (.txt, .zip)
- ✅ Stage report export (PDF/CSV) with totals and weekly breakdown
- ✅ User authentication and verification
- ✅ Responsive design (mobile-first)
- ✅ Admin functionality
- ✅ Internship day tracking (workdays vs home project)
- ✅ Workspace-scoped collaboration + realtime updates

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](./LICENSE) for license information.

## Security

See [SECURITY.md](./SECURITY.md) for security reporting details.

## Documentation

- [Docker Deployment](./README.docker.md)
- [Traefik Setup](./README.traefik.md)
- [Changelog](./CHANGELOG.md)
- [Frontend README](./stage-planner/README.md)

## Tech Stack

### Frontend
- React 18
- TypeScript
- Vite
- Material UI (MUI)
- Realtime updates via SSE
- React Router

### Backend
- Express
- TypeScript
- SQLite (better-sqlite3, including file blobs)
- JWT authentication
- Nodemailer

## Support

For questions or issues, open a [GitHub issue](../../issues).
