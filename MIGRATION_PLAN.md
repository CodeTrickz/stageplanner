# Migratieplan: Individueel → Groepsgebaseerd Systeem

## Huidige Situatie Analyse

### Bestaande Database Structuur:
1. **`groups` tabel**: Bestaat al met `id`, `name`, `join_code`, `created_at`
2. **`group_memberships` tabel**: Bestaat al met `group_id`, `user_id`, `role` (enum: 'admin' | 'member'), `created_at`
3. **`planning_items`**: Heeft zowel `user_id` (eigenaar) als `group_id` (workspace)
4. **`notes`**: Heeft zowel `user_id` (eigenaar) als `group_id` (workspace)
5. **`users`**: Heeft `group_id` (hun persoonlijke groep)

### Huidige Logica:
- Elke gebruiker heeft een persoonlijke groep (personal workspace)
- Planning items en notes zijn gekoppeld aan zowel user als group
- Sharing gebeurt via de `shares` tabel (user-to-user sharing)

## Voorgestelde Wijzigingen

### 1. DATABASE SCHEMA UPDATES

#### A. Workspace/Group Model (hergebruik bestaande `groups` tabel)
**Huidige structuur is voldoende**, maar we voegen toe:
- Optioneel: `description` veld voor workspace beschrijving
- Optioneel: `owner_id` veld om de eigenaar (STUDENT) te identificeren

**Migratie SQL:**
```sql
-- Optionele velden toevoegen
ALTER TABLE groups ADD COLUMN description TEXT;
ALTER TABLE groups ADD COLUMN owner_id TEXT;
CREATE INDEX IF NOT EXISTS idx_groups_owner ON groups(owner_id);
```

#### B. WorkspaceMember Model (uitbreiden `group_memberships`)
**Wijziging**: Role enum uitbreiden van `'admin' | 'member'` naar `'STUDENT' | 'MENTOR' | 'BEGELEIDER'`

**Migratie SQL:**
```sql
-- Bestaande data migreren: 'admin' → 'STUDENT', 'member' → 'MENTOR' (tijdelijk)
-- Nieuwe constraint: role moet een van de drie waarden zijn
-- Let op: SQLite ondersteunt geen ALTER COLUMN voor enum, dus we moeten data migreren
```

**Nieuwe TypeScript types:**
```typescript
export type WorkspaceRole = 'STUDENT' | 'MENTOR' | 'BEGELEIDER'

export type DbWorkspaceMember = {
  id: string
  workspaceId: string  // was: groupId
  userId: string
  role: WorkspaceRole   // was: 'admin' | 'member'
  createdAt: number
  invitedBy?: string | null
  invitedAt?: number | null
  status: 'active' | 'pending' | 'inactive'  // NIEUW: voor uitnodigingen
}
```

#### C. Planning & Notes Koppeling
**Huidige situatie**: Planning items hebben al `group_id` ✅
**Wijziging**: 
- `group_id` wordt `workspace_id` (hernoemen voor duidelijkheid)
- `user_id` blijft voor ownership tracking
- Data filtering gebeurt op basis van workspace membership

**Migratie SQL:**
```sql
-- Hernoemen voor duidelijkheid (optioneel, of gewoon logica aanpassen)
-- ALTER TABLE planning_items RENAME COLUMN group_id TO workspace_id;
-- ALTER TABLE notes RENAME COLUMN group_id TO workspace_id;
```

#### D. Nieuwe Tabel: Workspace Invitations
Voor uitnodigingen via email:
```sql
CREATE TABLE IF NOT EXISTS workspace_invitations (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('STUDENT', 'MENTOR', 'BEGELEIDER')),
  invited_by TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  accepted_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(workspace_id) REFERENCES groups(id) ON DELETE CASCADE,
  FOREIGN KEY(invited_by) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON workspace_invitations(email, expires_at);
CREATE INDEX IF NOT EXISTS idx_invitations_workspace ON workspace_invitations(workspace_id);
```

### 2. LOGICA & SERVER ACTIONS

#### A. Data Fetching Updates
**Huidige logica**: 
- Planning: `db.listPlanning(userId, date)` - toont items van gebruiker
- Notes: `db.listNotesOwned(userId)` - toont notes van gebruiker

**Nieuwe logica**:
- Planning: Filter op basis van workspace membership
- Notes: Filter op basis van workspace membership
- Gebruikers zien alleen data van workspaces waar ze lid van zijn

**Nieuwe functies nodig:**
```typescript
// In db.ts
listWorkspacesForUser(userId: string): Array<DbWorkspace & { role: WorkspaceRole }>
getWorkspaceMembers(workspaceId: string): Array<DbUser & { role: WorkspaceRole, joinedAt: number }>
listPlanningForWorkspace(workspaceId: string, date?: string): DbPlanningItem[]
listNotesForWorkspace(workspaceId: string): DbNote[]
```

#### B. Invite User to Workspace
**Nieuwe endpoint**: `POST /workspaces/:id/invite`
- Alleen STUDENT (eigenaar) kan uitnodigen
- Valideer email
- Genereer invite token
- Stuur email met invite link
- Maak entry in `workspace_invitations` tabel

**Flow:**
1. STUDENT nodigt MENTOR/BEGELEIDER uit via email
2. Email bevat link met token
3. Gebruiker klikt link → account maken (als nieuw) of accepteer invite
4. Bij acceptatie: maak `workspace_member` entry

### 3. RECHTEN (RBAC)

#### Role Permissions Matrix:
| Actie | STUDENT | MENTOR | BEGELEIDER |
|-------|---------|--------|------------|
| Planning item aanmaken | ✅ | ❌ | ❌ |
| Planning item bewerken | ✅ (eigen) | ✅ (reacties) | ✅ (reacties) |
| Planning item verwijderen | ✅ (eigen) | ❌ | ❌ |
| Notes aanmaken | ✅ | ❌ | ❌ |
| Notes bewerken | ✅ (eigen) | ✅ (reacties) | ✅ (reacties) |
| Notes verwijderen | ✅ (eigen) | ❌ | ❌ |
| Leden uitnodigen | ✅ | ❌ | ❌ |
| Workspace beheren | ✅ | ❌ | ❌ |

**Implementatie:**
- Nieuwe helper functie: `checkWorkspacePermission(userId, workspaceId, action)`
- Middleware: `requireWorkspaceRole(workspaceId, allowedRoles)`

### 4. UI AANPASSINGEN

#### A. Nieuwe "Team/Leden" Pagina
**Route**: `/workspace/:id/team` of `/team`
**Functionaliteit**:
- Lijst van alle workspace members
- Toon role, naam, email, join date
- Voor STUDENT: invite button
- Status indicators (active/pending)

#### B. Workspace Selector in Sidebar
**Functionaliteit**:
- Dropdown/selector om tussen workspaces te wisselen
- Toon huidige workspace naam
- Badge met aantal members
- "Mijn Workspace" als default

#### C. Planning/Notes Views
**Wijziging**:
- Filter automatisch op basis van geselecteerde workspace
- Toon ownership indicator (eigen item vs. workspace item)
- Reacties/comments voor MENTOR/BEGELEIDER

## Implementatie Volgorde

### Fase 1: Database Migratie (Backend)
1. ✅ Workspace invitations tabel toevoegen
2. ✅ Group memberships role enum uitbreiden
3. ✅ Migratie script voor bestaande data
4. ✅ Nieuwe database functies

### Fase 2: Backend API Updates
1. ✅ Workspace endpoints (list, get, create)
2. ✅ Workspace members endpoints
3. ✅ Invite endpoint
4. ✅ RBAC middleware
5. ✅ Planning/Notes filtering op workspace

### Fase 3: Frontend Updates
1. ✅ Workspace selector component
2. ✅ Team/Leden pagina
3. ✅ Invite functionaliteit
4. ✅ Planning/Notes views aanpassen
5. ✅ Permission-based UI hiding

## Belangrijke Overwegingen

### Backward Compatibility
- Bestaande users hebben al een personal group → dit wordt hun default workspace
- Bestaande planning/notes blijven werken (hebben al group_id)
- Migratie moet data-preserving zijn

### Data Migratie Strategie
1. Bestaande `group_memberships` met role='admin' → 'STUDENT'
2. Bestaande `group_memberships` met role='member' → 'MENTOR' (of vraag gebruiker)
3. Personal groups worden automatisch workspace met owner

### Security
- Invite tokens moeten secure zijn (crypto.randomBytes)
- Email verificatie voor nieuwe users
- RBAC checks op alle endpoints

## Vragen voor Bevestiging

1. **Workspace naming**: Gebruiken we "Workspace" of "StageGroep" in de UI?
2. **Default workspace**: Moet elke user automatisch een personal workspace hebben?
3. **Multiple workspaces**: Kan een user lid zijn van meerdere workspaces?
4. **Role assignment**: Wie bepaalt of iemand MENTOR of BEGELEIDER is? (STUDENT kiest dit bij uitnodiging?)
5. **Reacties systeem**: Moeten MENTOR/BEGELEIDER een apart comments/reacties systeem hebben, of kunnen ze gewoon notes bewerken?

## Volgende Stap

Na goedkeuring van dit plan, start ik met:
1. Database schema updates
2. TypeScript type definitions
3. Database functies
4. Backend API endpoints
5. Frontend components

