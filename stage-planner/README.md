# Stage Planner (React)

Frontend for Stage Planner with workspace‑scoped data and realtime updates, with multiple tabs:

- **Dashboard**: overview of today/week/tasks + internship progress.
- **Planning**: day planning with time slots (create/edit/delete items + bulk updates).
- **Week**: week view (7 days).
- **Tasks**: task overview with filters.
- **Files**: upload + download (stored on the server in SQLite).
- **Notes / mail**: text + attachments (pick from Files), save, export as **.txt** or **.zip**.
- **Team**: workspaces and member management.
- **Settings**: user settings (planning, internship period, holidays, theme).
- **Admin**: management and logs (admin only).

## Start (Windows)

Go to `stage-planner` and run:

```bash
npm install
npm run dev
```

Vite opens at `http://localhost:5173`.

## Backend (login + planning API)

A simple backend is in `backend/` (Express + SQLite):

```bash
cd "..\\backend"
npm install
npm run dev
```

- Backend runs at `http://localhost:3001`
- Config is in `backend/env.local` (no `.env` needed)
- Frontend has a **Login** page at `/login`
- **Account activation**: on registration a verify link is “emailed”.
  - In dev without SMTP: check `backend/data/mails.log` (or backend console output).

## Frontend configuration

Optional `stage-planner/.env.local`:
- `VITE_IDLE_LOGOUT_MINUTES` (0 = never, default 30)

## Storage

Planning, notes, and files are stored server‑side (SQLite) and synchronized per workspace.
Local storage is only used for UI settings and auth state.

## Tech

- React + TypeScript (Vite)
- UI: MUI (Material UI)
- Storage: server-side API + in-memory state
- Realtime: Server-Sent Events (SSE)
- Export: JSZip
