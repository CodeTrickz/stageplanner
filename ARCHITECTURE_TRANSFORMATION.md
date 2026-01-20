## Architectuur Transformatie: Lokaal -> Cloud Workgroups

Dit document inventariseert waar data nu lokaal wordt opgeslagen en beschrijft
een migratieplan naar een cloud-gebaseerde, multi-tenant architectuur met
`workgroup_id` filtering en centrale opslag voor taken, notities en bestanden.

### 1) Inventaris: Lokale opslag (huidige code)

**Frontend: IndexedDB (Dexie)**
- `stage-planner/src/db/db.ts`
  - `AppDB` (Dexie) bevat tabellen voor planning, notes, files, fileMeta, noteLinks, errors, ocr, etc.
  - Taken, notities en bestanden worden lokaal opgeslagen in IndexedDB.
- `stage-planner/src/pages/*`
  - `PlanningPage.tsx`, `TasksOverviewPage.tsx`, `WeekPage.tsx`,
    `DashboardPage.tsx`, `NotesPage.tsx`, `FilesPage.tsx`,
    `GlobalSearchDialog.tsx` lezen/schrijven via `db.*` (Dexie).
  - Voorbeelden van lokale reads/writes:
    - `db.planning.add/update/delete` in `PlanningPage.tsx`, `WeekPage.tsx`, `TasksOverviewPage.tsx`.
    - `db.notes.add/update/delete` in `NotesPage.tsx`.
    - `db.files.add/update/delete` en `db.fileMeta.*` in `FilesPage.tsx`.

**Frontend: localStorage**
- `stage-planner/src/auth/auth.tsx`
  - Auth state (token/user) wordt in `localStorage` bewaard via `LS_KEY`.
- `stage-planner/src/app/settings.tsx`
  - UI/instellingen worden in `localStorage` bewaard.
- `stage-planner/src/hooks/useWorkspace.tsx`
  - Geselecteerde workspace-id wordt in `localStorage` bewaard.
- `stage-planner/src/app/errorLog.ts`
  - Logging-config uit `localStorage`.

**Backend: lokale JSON opslag (fallback)**
- `backend/src/db.ts`
  - `readJson()` / `writeJson()` gebruikt `fs.readFileSync` / `fs.writeFileSync`.
  - Dit is een lokale JSON datastore fallback voor o.a. planning, notes, files.

**Backend: lokale logbestanden**
- `backend/src/server.ts`
  - `ERROR_LOG_PATH` gebruikt `fs.readFileSync` / `fs.writeFileSync`.
- `backend/scripts/debug-verify.js`
  - Leest lokaal logbestand.

### 1b) Inventaris: Opslag van workgroup selectie & auth

- `stage-planner/src/hooks/useWorkspace.tsx`
  - Geselecteerde workspace wordt opgeslagen in `localStorage`.
- `stage-planner/src/auth/auth.tsx`
  - Auth state (token/user) in `localStorage`.
- `stage-planner/src/app/settings.tsx`
  - UI/instellingen in `localStorage`.
- `stage-planner/src/app/errorLog.ts`
  - Logging config in `localStorage`.

Deze opslag moet worden uitgefaseerd voor **core data** (taken/notities/bestanden).
Auth/session en UI settings kunnen worden gemigreerd naar server-side sessions of
memory-only state, afhankelijk van productkeuze.

### 2) Doelarchitectuur (vereisten)

**Multi-tenancy**
- Elke tabel/collectie bevat **`workgroup_id`**.
- Geen enkele query mag data ophalen zonder `workgroup_id` filter.
- Autorisatie controleert `workgroup_id` membership voor elke request.

**Centrale opslag**
- Taken/Notities: Centrale database (PostgreSQL/Supabase of Firebase).
- Bestanden: Object Storage (Supabase Storage of S3) met objecten gekoppeld aan
  `workgroup_id`.
- Geen IndexedDB/localStorage voor taken, notities, bestanden.

**Realtime delen**
- Leden van dezelfde workgroup zien elkaars wijzigingen live.
- Implementatie via WebSocket/SSE of realtime database (Supabase Realtime/Firebase).

**Authenticatie**
- User-sessie bevat `workgroup_id` (claim in token of server-side session).
- Alle API-calls filteren op `workgroup_id` uit sessie of expliciete scope.

**Datamodellen (minimaal)**
- `workgroups` (id, name, owner_id, created_at)
- `workgroup_members` (workgroup_id, user_id, role, status, created_at)
- `planning_items` (id, workgroup_id, user_id, date, start, end, title, notes, tags_json, priority, status, created_at, updated_at)
- `notes` (id, workgroup_id, user_id, subject, body, created_at, updated_at)
- `files` (id, workgroup_id, user_id, storage_key, name, type, size, group_key, version, created_at, updated_at)

### 2b) Verplichte query-scope

**Back-end**
- Elke `SELECT`, `UPDATE`, `DELETE` moet `WHERE workgroup_id = ?` bevatten.
- Geen fallback naar user-scoped data.

**Front-end**
- Iedere fetch krijgt `workgroup_id` mee (of wordt server-side afgeleid).
- UI toont enkel data van de actieve workgroup.

### 3) Migratieplan (stapsgewijs)

**Stap 0: Keuze stack**
- Database: Postgres + Prisma (of Supabase).
- Object storage: S3/Supabase Storage.
- Realtime: Supabase Realtime of eigen WebSocket server.

**Stap 1: Schema en data-layer**
- Voeg `workgroup_id` toe aan alle relevante tabellen:
  - `planning_items`, `notes`, `files`, `file_meta`, `note_links`, `feedback`, etc.
- Maak unieke indexen gebaseerd op `workgroup_id` (bv. `workgroup_id, date`).
- Voeg membership tabel: `workgroup_members` met rollen/status.

**Stap 2: API-contract (strict scoping)**
- Verplicht `workgroup_id` in elke read/write route.
- Valideer membership bij elke call.
- Pas endpoints aan zodat ze NOOIT zonder `workgroup_id` data teruggeven.
- Logica: `workgroup_id` uit token; optioneel header/param alleen voor admins.

**Stap 2a: API endpoints (concreet)**
- `GET /planning?workgroup_id=...` -> alle items van workgroup (geen user filter)
- `POST /planning` -> insert/update, altijd met `workgroup_id`
- `GET /notes?workgroup_id=...`
- `POST /notes`
- `GET /files?workgroup_id=...`
- `POST /files` (metadata + storage key)
- `GET /files/:id` -> check `workgroup_id` membership

**Stap 3: Frontend data-flow zonder IndexedDB**
- Verwijder Dexie gebruik voor:
  - `planning`, `notes`, `files`, `fileMeta`, `noteLinks`.
- Vervang door API calls + in-memory state (React Query/SWR).
- Caching: alleen in-memory, geen persistent storage.

**Stap 3a: Vervang `db.*` calls (concreet)**
- `PlanningPage.tsx`:
  - vervang `db.planning` reads/writes door API calls naar `/planning`.
- `TasksOverviewPage.tsx`, `WeekPage.tsx`, `DashboardPage.tsx`:
  - queries naar `/planning?workgroup_id=...` + realtime subscription.
- `NotesPage.tsx`:
  - `db.notes` -> `/notes`.
- `FilesPage.tsx`:
  - `db.files` en `db.fileMeta` -> `/files` + storage.
- `GlobalSearchDialog.tsx`:
  - API search endpoints of client-side filtering op server data.

**Stap 4: Realtime updates**
- Subscriptions op `workgroup_id` voor:
  - planning, notes, files.
- Update UI state bij realtime events.

**Stap 5: Bestanden naar object storage**
- Uploads: backend pre-signed URL of direct to storage met `workgroup_id` prefix.
- DB houdt enkel metadata + storage key.
- Download/preview via signed URL of proxy endpoint met auth check.

**Bestandspaden**
- Prefix: `workgroups/{workgroup_id}/files/{file_id}/{filename}`
- Database `files.storage_key` verwijst naar dit pad.

**Stap 6: Auth context met workgroup_id**
- Token/session bevat actieve `workgroup_id`.
- Verplaats huidige `localStorage` selectie naar server-side state of
  session-scoped API (`/session/workgroup`).

### 3b) Real-time opties

- **Supabase**: Realtime subscriptions op tabellen met RLS op `workgroup_id`.
- **Firebase**: collection per workgroup (`workgroups/{id}/planning`).
- **Eigen backend**: WebSocket + server broadcasts bij create/update/delete.

### 4) Werkpunten om direct te implementeren

1. **Verwijder Dexie voor core data** (planning/notes/files).
2. **API altijd scoped** op `workgroup_id` en geen owner-only filters.
3. **Bestandssynchronisatie** via object storage, niet via IndexedDB.
4. **Realtime** via websocket/SSE of Supabase.

### 4b) Concrete refactor checklist (per file)

- `stage-planner/src/db/db.ts`
  - Verwijderen of beperken tot niet-core data (bijv. error log).
- `stage-planner/src/pages/PlanningPage.tsx`
  - Alle `db.planning.*` vervangen door API calls.
- `stage-planner/src/pages/NotesPage.tsx`
  - `db.notes.*`, `db.noteLinks.*` vervangen door API calls.
- `stage-planner/src/pages/FilesPage.tsx`
  - `db.files.*` en `db.fileMeta.*` vervangen door API calls.
- `stage-planner/src/components/FilePreviewDialog.tsx`
  - Alleen remote fetch via storage (geen lokale blob in IndexedDB).
- `backend/src/db.ts`
  - JSON fallback verwijderen; alleen DB layer.

### 4c) Data migratie (script)

- Script om lokale JSON/IndexedDB data te migreren naar server:
  - Extract -> transform -> load per workgroup.
  - Verifieer counts per `workgroup_id` en per entiteit.

### 5) Overgangsstrategie

Om downtime te vermijden:
- Introduceer cloud persistence naast bestaande storage.
- Migreer data per user/workgroup naar de database.
- Verwijder lokale opslag pas na succesvolle migratie en verificatie.

### 6) Hard requirements samenvatting (must)

- Geen `localStorage`/`IndexedDB`/JSON voor taken/notities/bestanden.
- Iedere query scoped met `workgroup_id`.
- Bestanden uitsluitend via object storage.
- Realtime updates per workgroup.

