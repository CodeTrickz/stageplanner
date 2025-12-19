# Stage Planner (React)

Kleine stage-app met 3 tabbladen:

- **Planning**: dagplanning met tijdsindeling (items opslaan, bewerken, verwijderen).
- **Bestanden**: uploaden + downloaden (opslag in **IndexedDB** in je browser).
- **Notities / mail**: tekst + bijlages (kies bijlages uit Bestanden), opslaan, export als **.txt** of **.zip**.

## Starten (Windows)

Ga naar de map `stage-planner` en run:

```bash
npm install
npm run dev
```

Dan opent Vite meestal op `http://localhost:5173`.

## Backend (login + planning API)

Er staat ook een simpele backend in `backend/` (Express + SQLite):

```bash
cd "..\\backend"
npm install
npm run dev
```

- Backend draait op `http://localhost:3001`
- Config staat in `backend/env.local` (geen `.env` nodig)
- Frontend heeft een **Login** pagina op `/login`
- **Account activatie**: bij registreren wordt een verify-link “gemaild”.
  - In dev zonder SMTP: check `backend/data/mails.log` voor de link (of console output van backend).

## Opslag

Alles wordt lokaal opgeslagen in je browser via **IndexedDB** (Dexie).  
Wil je “resetten”: verwijder site data in je browser (of gebruik een andere browser/profiel).

## Tech

- React + TypeScript (Vite)
- UI: MUI (Material UI)
- Storage: Dexie (IndexedDB)
- Export: JSZip

