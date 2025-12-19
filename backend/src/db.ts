import Database from 'better-sqlite3'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'

export type DbUser = {
  id: string
  username: string
  firstName: string
  lastName: string
  email: string
  passwordHash: string
  isAdmin: 0 | 1
  emailVerified: 0 | 1
  groupId: string | null
  emailVerificationTokenHash: string | null
  emailVerificationExpiresAt: number | null
  createdAt: number
  updatedAt: number
}

export type DbGroup = {
  id: string
  name: string
  joinCode: string
  createdAt: number
}

export type DbGroupMembership = {
  groupId: string
  userId: string
  role: 'admin' | 'member'
  createdAt: number
}

export type DbNote = {
  id: string
  userId: string
  groupId: string
  subject: string
  body: string
  createdAt: number
  updatedAt: number
}

export type DbShare = {
  id: string
  resourceType: 'planning' | 'note'
  resourceId: string
  ownerId: string
  granteeId: string
  permission: 'read' | 'write'
  createdAt: number
}

export type DbAudit = {
  id: string
  actorUserId: string
  action: string
  resourceType: string
  resourceId: string
  metaJson: string
  createdAt: number
}

export type DbAuditWithActor = DbAudit & {
  actorEmail: string | null
  actorUsername: string | null
}

export type DbPlanningItem = {
  id: string
  userId: string
  groupId: string
  date: string
  start: string
  end: string
  title: string
  notes: string | null
  tagsJson: string
  priority: 'low' | 'medium' | 'high'
  status: 'todo' | 'in_progress' | 'done'
  createdAt: number
  updatedAt: number
}

type JsonState = {
  groups: DbGroup[]
  users: DbUser[]
  planning: DbPlanningItem[]
  notes: DbNote[]
  shares: DbShare[]
  audit: DbAudit[]
}

function now() {
  return Date.now()
}

function uuid() {
  return crypto.randomUUID()
}

function generateJoinCode() {
  // short, user-friendly uppercase code
  return crypto.randomBytes(4).toString('hex').toUpperCase()
}

function ensureDir(p: string) {
  fs.mkdirSync(p, { recursive: true })
}

function dbPath() {
  return process.env.DB_PATH || path.resolve(process.cwd(), 'data', 'dev.sqlite')
}

function jsonPath() {
  return process.env.JSON_PATH || path.resolve(process.cwd(), 'data', 'dev.json')
}

function driver() {
  return (process.env.DB_DRIVER || 'sqlite').toLowerCase()
}

function readJson(): JsonState {
  const p = jsonPath()
  ensureDir(path.dirname(p))
  if (!fs.existsSync(p)) {
    const init: JsonState = { groups: [], users: [], planning: [], notes: [], shares: [], audit: [] }
    fs.writeFileSync(p, JSON.stringify(init, null, 2), 'utf-8')
    return init
  }
  const parsed = JSON.parse(fs.readFileSync(p, 'utf-8')) as Partial<JsonState>
  return {
    groups: parsed.groups ?? [],
    users: parsed.users ?? [],
    planning: parsed.planning ?? [],
    notes: parsed.notes ?? [],
    shares: parsed.shares ?? [],
    audit: parsed.audit ?? [],
  } as JsonState
}

function writeJson(s: JsonState) {
  const p = jsonPath()
  ensureDir(path.dirname(p))
  fs.writeFileSync(p, JSON.stringify(s, null, 2), 'utf-8')
}

function openSqlite() {
  const p = dbPath()
  ensureDir(path.dirname(p))
  const db = new Database(p)
  db.pragma('journal_mode = WAL')
  db.exec(`
    CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      join_code TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT,
      first_name TEXT,
      last_name TEXT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      email_verified INTEGER NOT NULL DEFAULT 0,
      group_id TEXT,
      email_verification_token_hash TEXT,
      email_verification_expires_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS planning_items (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      group_id TEXT,
      date TEXT NOT NULL,
      start TEXT NOT NULL,
      end TEXT NOT NULL,
      title TEXT NOT NULL,
      notes TEXT,
      tags_json TEXT NOT NULL DEFAULT '[]',
      priority TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_planning_user_date ON planning_items(user_id, date);

    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      group_id TEXT,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id, updated_at);

    CREATE TABLE IF NOT EXISTS shares (
      id TEXT PRIMARY KEY,
      resource_type TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      grantee_id TEXT NOT NULL,
      permission TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(grantee_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_unique ON shares(resource_type, resource_id, grantee_id);
    CREATE INDEX IF NOT EXISTS idx_shares_grantee ON shares(grantee_id, created_at);

    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      actor_user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      meta_json TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
  `)

  // Lightweight migrations for older dev DBs
  const cols = db
    .prepare(`PRAGMA table_info(users)`)
    .all()
    .map((r: any) => String(r.name))
  function addCol(name: string, ddl: string) {
    if (cols.includes(name)) return
    db.exec(`ALTER TABLE users ADD COLUMN ${ddl};`)
  }
  addCol('username', 'username TEXT')
  addCol('first_name', 'first_name TEXT')
  addCol('last_name', 'last_name TEXT')
  addCol('email_verified', 'email_verified INTEGER NOT NULL DEFAULT 0')
  addCol('is_admin', 'is_admin INTEGER NOT NULL DEFAULT 0')
  addCol('group_id', 'group_id TEXT')
  addCol('email_verification_token_hash', 'email_verification_token_hash TEXT')
  addCol('email_verification_expires_at', 'email_verification_expires_at INTEGER')
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique ON users(username);`)

  // Ensure join_code exists for groups (migrations)
  const gCols = db
    .prepare(`PRAGMA table_info(groups)`)
    .all()
    .map((r: any) => String(r.name))
  if (!gCols.includes('join_code')) {
    db.exec(`ALTER TABLE groups ADD COLUMN join_code TEXT;`)
  }
  // create index only after column is guaranteed to exist
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_join_code_unique ON groups(join_code);`)

  const allGroups = db.prepare(`SELECT id, join_code as joinCode FROM groups`).all() as Array<{ id: string; joinCode: string | null }>
  for (const g of allGroups) {
    if (g.joinCode) continue
    // ensure uniqueness
    for (let i = 0; i < 10; i++) {
      const code = generateJoinCode()
      const exists = db.prepare(`SELECT id FROM groups WHERE join_code=?`).get(code) as any
      if (exists) continue
      db.prepare(`UPDATE groups SET join_code=? WHERE id=?`).run(code, g.id)
      break
    }
  }

  // Ensure group_memberships table exists for older DBs
  db.exec(`
    CREATE TABLE IF NOT EXISTS group_memberships (
      group_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (group_id, user_id),
      FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_group_memberships_user ON group_memberships(user_id, created_at);
  `)

  // Ensure group_id for existing users (personal groups)
  const existingUsers = db
    .prepare(`SELECT id, email, username, group_id as groupId FROM users`)
    .all() as Array<{ id: string; email: string; username: string | null; groupId: string | null }>
  for (const u of existingUsers) {
    if (u.groupId) continue
    const gid = uuid()
    const name = u.username || u.email
    db.prepare(`INSERT INTO groups (id, name, join_code, created_at) VALUES (?, ?, ?, ?)`).run(gid, name, generateJoinCode(), now())
    db.prepare(`UPDATE users SET group_id=? WHERE id=?`).run(gid, u.id)
  }

  // Backfill membership for users' personal groups
  const usersNow = db
    .prepare(`SELECT id, is_admin as isAdmin, group_id as groupId FROM users WHERE group_id IS NOT NULL`)
    .all() as Array<{ id: string; isAdmin: number; groupId: string }>
  for (const u of usersNow) {
    const exists = db
      .prepare(`SELECT 1 FROM group_memberships WHERE group_id=? AND user_id=?`)
      .get(u.groupId, u.id) as any
    if (exists) continue
    const role = u.isAdmin ? 'admin' : 'admin' // personal group owner is admin
    db.prepare(`INSERT INTO group_memberships (group_id, user_id, role, created_at) VALUES (?, ?, ?, ?)`).run(
      u.groupId,
      u.id,
      role,
      now(),
    )
  }

  // Add group_id to planning_items if missing (older DBs) and backfill
  const planningCols = db
    .prepare(`PRAGMA table_info(planning_items)`)
    .all()
    .map((r: any) => String(r.name))
  const hadPlanningGroupId = planningCols.includes('group_id')
  if (!hadPlanningGroupId) {
    db.exec(`ALTER TABLE planning_items ADD COLUMN group_id TEXT;`)
  }
  const hadPlanningTags = planningCols.includes('tags_json')
  if (!hadPlanningTags) {
    db.exec(`ALTER TABLE planning_items ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]';`)
  }
  db.exec(`CREATE INDEX IF NOT EXISTS idx_planning_group_date ON planning_items(group_id, date);`)
  db.exec(`
    UPDATE planning_items
    SET group_id = (SELECT group_id FROM users WHERE users.id = planning_items.user_id)
    WHERE group_id IS NULL;
  `)

  // Add group_id to notes if missing (older DBs) and backfill
  const noteCols = db
    .prepare(`PRAGMA table_info(notes)`)
    .all()
    .map((r: any) => String(r.name))
  const hadNotesGroupId = noteCols.includes('group_id')
  if (!hadNotesGroupId) {
    db.exec(`ALTER TABLE notes ADD COLUMN group_id TEXT;`)
  }
  db.exec(`CREATE INDEX IF NOT EXISTS idx_notes_group ON notes(group_id, updated_at);`)
  db.exec(`
    UPDATE notes
    SET group_id = (SELECT group_id FROM users WHERE users.id = notes.user_id)
    WHERE group_id IS NULL;
  `)

  return db
}

const sqliteDb = driver() === 'sqlite' ? openSqlite() : null

export const db = {
  createGroup: (name: string): DbGroup => {
    const g: DbGroup = { id: uuid(), name, joinCode: generateJoinCode(), createdAt: now() }
    if (sqliteDb) {
      sqliteDb
        .prepare(`INSERT INTO groups (id, name, join_code, created_at) VALUES (?, ?, ?, ?)`)
        .run(g.id, g.name, g.joinCode, g.createdAt)
      return g
    }
    const s = readJson()
    s.groups.push(g)
    writeJson(s)
    return g
  },

  listGroups: (): DbGroup[] => {
    if (sqliteDb) {
      return sqliteDb
        .prepare(`SELECT id, name, join_code as joinCode, created_at as createdAt FROM groups ORDER BY created_at DESC`)
        .all() as DbGroup[]
    }
    const s = readJson()
    return s.groups.slice().sort((a, b) => b.createdAt - a.createdAt)
  },

  getGroupById: (id: string): DbGroup | null => {
    if (sqliteDb) {
      const row = sqliteDb.prepare(`SELECT id, name, join_code as joinCode, created_at as createdAt FROM groups WHERE id=?`).get(id) as
        | DbGroup
        | undefined
      return row ?? null
    }
    const s = readJson()
    return s.groups.find((g) => g.id === id) ?? null
  },

  getGroupByJoinCode: (code: string): DbGroup | null => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(`SELECT id, name, join_code as joinCode, created_at as createdAt FROM groups WHERE join_code=?`)
        .get(code) as DbGroup | undefined
      return row ?? null
    }
    const s = readJson()
    return s.groups.find((g) => g.joinCode === code) ?? null
  },

  addMembership: (input: DbGroupMembership): DbGroupMembership => {
    if (sqliteDb) {
      sqliteDb
        .prepare(
          `INSERT OR IGNORE INTO group_memberships (group_id, user_id, role, created_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(input.groupId, input.userId, input.role, input.createdAt)
      return input
    }
    // json fallback: not implemented
    return input
  },

  listGroupsForUser: (userId: string): Array<DbGroup & { role: 'admin' | 'member' }> => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             g.id,
             g.name,
             g.join_code as joinCode,
             g.created_at as createdAt,
             m.role as role
           FROM group_memberships m
           JOIN groups g ON g.id = m.group_id
           WHERE m.user_id = ?
           ORDER BY g.created_at DESC`,
        )
        .all(userId) as Array<DbGroup & { role: 'admin' | 'member' }>
      return rows
    }
    const s = readJson()
    // fallback: only personal group
    const u = s.users.find((x) => x.id === userId)
    if (!u?.groupId) return []
    const g = s.groups.find((gg) => gg.id === u.groupId)
    return g ? [{ ...g, role: 'admin' }] : []
  },

  isMemberOfGroup: (userId: string, groupId: string): boolean => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(`SELECT 1 FROM group_memberships WHERE user_id=? AND group_id=?`)
        .get(userId, groupId) as any
      return !!row
    }
    const s = readJson()
    const u = s.users.find((x) => x.id === userId)
    return !!(u && u.groupId === groupId)
  },

  getMembershipRole: (userId: string, groupId: string): 'admin' | 'member' | null => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(`SELECT role FROM group_memberships WHERE user_id=? AND group_id=?`)
        .get(userId, groupId) as { role?: string } | undefined
      const role = row?.role
      return role === 'admin' || role === 'member' ? role : null
    }
    const s = readJson()
    const u = s.users.find((x) => x.id === userId)
    if (u?.groupId === groupId) return 'admin'
    return null
  },

  listGroupMembers: (
    groupId: string,
  ): Array<{
    userId: string
    email: string
    username: string
    firstName: string
    lastName: string
    role: 'admin' | 'member'
    createdAt: number
  }> => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             m.user_id as userId,
             u.email as email,
             u.username as username,
             u.first_name as firstName,
             u.last_name as lastName,
             m.role as role,
             m.created_at as createdAt
           FROM group_memberships m
           JOIN users u ON u.id = m.user_id
           WHERE m.group_id = ?
           ORDER BY m.role DESC, u.username ASC, u.email ASC`,
        )
        .all(groupId) as any[]
      return rows
    }
    const s = readJson()
    const gUsers = s.users.filter((u) => u.groupId === groupId)
    return gUsers.map((u) => ({
      userId: u.id,
      email: u.email,
      username: u.username,
      firstName: u.firstName,
      lastName: u.lastName,
      role: 'admin',
      createdAt: u.createdAt,
    }))
  },

  removeMembership: (groupId: string, userId: string): boolean => {
    if (sqliteDb) {
      const info = sqliteDb.prepare(`DELETE FROM group_memberships WHERE group_id=? AND user_id=?`).run(groupId, userId)
      return info.changes > 0
    }
    return false
  },

  countGroupAdmins: (groupId: string): number => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(`SELECT COUNT(1) as c FROM group_memberships WHERE group_id=? AND role='admin'`)
        .get(groupId) as { c: number } | undefined
      return Number(row?.c ?? 0)
    }
    return 1
  },

  deleteGroup: (groupId: string): boolean => {
    if (sqliteDb) {
      // delete shares that point to resources in this group
      sqliteDb
        .prepare(
          `DELETE FROM shares
           WHERE resource_type='planning' AND resource_id IN (SELECT id FROM planning_items WHERE group_id=?)`,
        )
        .run(groupId)
      sqliteDb
        .prepare(`DELETE FROM shares WHERE resource_type='note' AND resource_id IN (SELECT id FROM notes WHERE group_id=?)`)
        .run(groupId)

      sqliteDb.prepare(`DELETE FROM planning_items WHERE group_id=?`).run(groupId)
      sqliteDb.prepare(`DELETE FROM notes WHERE group_id=?`).run(groupId)
      // memberships has FK cascade via groups table; ensure group delete last
      const info = sqliteDb.prepare(`DELETE FROM groups WHERE id=?`).run(groupId)
      return info.changes > 0
    }
    return false
  },

  createUser: (input: {
    email: string
    username: string
    firstName: string
    lastName: string
    passwordHash: string
    groupId?: string | null
    emailVerificationTokenHash?: string | null
    emailVerificationExpiresAt?: number | null
    isAdmin?: boolean
    emailVerified?: boolean
  }): DbUser => {
    const t = now()
    const user: DbUser = {
      id: uuid(),
      email: input.email,
      username: input.username,
      firstName: input.firstName,
      lastName: input.lastName,
      passwordHash: input.passwordHash,
      isAdmin: input.isAdmin ? 1 : 0,
      emailVerified: input.emailVerified ? 1 : 0,
      groupId: input.groupId ?? null,
      emailVerificationTokenHash: input.emailVerificationTokenHash ?? null,
      emailVerificationExpiresAt: input.emailVerificationExpiresAt ?? null,
      createdAt: t,
      updatedAt: t,
    }
    if (sqliteDb) {
      if (!user.groupId) {
        const gid = uuid()
        const code = generateJoinCode()
        sqliteDb
          .prepare(`INSERT INTO groups (id, name, join_code, created_at) VALUES (?, ?, ?, ?)`)
          .run(gid, user.username || user.email, code, t)
        user.groupId = gid
      }
      sqliteDb
        .prepare(
          `INSERT INTO users
             (id, username, first_name, last_name, email, password_hash, is_admin, email_verified, group_id, email_verification_token_hash, email_verification_expires_at, created_at, updated_at)
           VALUES
             (@id, @username, @firstName, @lastName, @email, @passwordHash, @isAdmin, @emailVerified, @groupId, @emailVerificationTokenHash, @emailVerificationExpiresAt, @createdAt, @updatedAt)`,
        )
        .run({
          id: user.id,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          passwordHash: user.passwordHash,
          isAdmin: user.isAdmin,
          emailVerified: user.emailVerified,
          groupId: user.groupId,
          emailVerificationTokenHash: user.emailVerificationTokenHash,
          emailVerificationExpiresAt: user.emailVerificationExpiresAt,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        })
      // Ensure membership
      sqliteDb
        .prepare(
          `INSERT OR IGNORE INTO group_memberships (group_id, user_id, role, created_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(user.groupId, user.id, 'admin', t)
      return user
    }
    const s = readJson()
    if (s.users.some((u) => u.email === user.email)) throw new Error('email_in_use')
    if (s.users.some((u) => u.username === user.username)) throw new Error('username_in_use')
    if (!user.groupId) {
      const g: DbGroup = { id: uuid(), name: user.username || user.email, joinCode: generateJoinCode(), createdAt: t }
      s.groups.push(g)
      user.groupId = g.id
    }
    s.users.push(user)
    writeJson(s)
    return user
  },

  findUserByEmail: (email: string): DbUser | null => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(
          `SELECT
             id,
             username,
             first_name as firstName,
             last_name as lastName,
             email,
             password_hash as passwordHash,
             is_admin as isAdmin,
             email_verified as emailVerified,
             group_id as groupId,
             email_verification_token_hash as emailVerificationTokenHash,
             email_verification_expires_at as emailVerificationExpiresAt,
             created_at as createdAt,
             updated_at as updatedAt
           FROM users WHERE email = ?`,
        )
        .get(email) as DbUser | undefined
      return row ?? null
    }
    const s = readJson()
    return s.users.find((u) => u.email === email) ?? null
  },

  findUserByUsername: (username: string): DbUser | null => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(
          `SELECT
             id,
             username,
             first_name as firstName,
             last_name as lastName,
             email,
             password_hash as passwordHash,
             is_admin as isAdmin,
             email_verified as emailVerified,
             group_id as groupId,
             email_verification_token_hash as emailVerificationTokenHash,
             email_verification_expires_at as emailVerificationExpiresAt,
             created_at as createdAt,
             updated_at as updatedAt
           FROM users WHERE username = ?`,
        )
        .get(username) as DbUser | undefined
      return row ?? null
    }
    const s = readJson()
    return s.users.find((u) => u.username === username) ?? null
  },

  findUserById: (id: string): DbUser | null => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(
          `SELECT
             id,
             username,
             first_name as firstName,
             last_name as lastName,
             email,
             password_hash as passwordHash,
             is_admin as isAdmin,
             email_verified as emailVerified,
             group_id as groupId,
             email_verification_token_hash as emailVerificationTokenHash,
             email_verification_expires_at as emailVerificationExpiresAt,
             created_at as createdAt,
             updated_at as updatedAt
           FROM users WHERE id = ?`,
        )
        .get(id) as DbUser | undefined
      return row ?? null
    }
    const s = readJson()
    return s.users.find((u) => u.id === id) ?? null
  },

  listUsers: (): Array<Omit<DbUser, 'passwordHash'>> => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             id,
             username,
             first_name as firstName,
             last_name as lastName,
             email,
             is_admin as isAdmin,
             email_verified as emailVerified,
             group_id as groupId,
             email_verification_token_hash as emailVerificationTokenHash,
             email_verification_expires_at as emailVerificationExpiresAt,
             created_at as createdAt,
             updated_at as updatedAt
           FROM users
           ORDER BY created_at DESC`,
        )
        .all() as Array<Omit<DbUser, 'passwordHash'>>
      return rows
    }
    const s = readJson()
    return s.users
      .slice()
      .sort((a, b) => b.createdAt - a.createdAt)
      .map(({ passwordHash, ...rest }) => rest)
  },

  updateUser: (
    id: string,
    patch: Partial<Pick<DbUser, 'email' | 'username' | 'firstName' | 'lastName' | 'emailVerified' | 'isAdmin' | 'groupId'>>,
  ): Omit<DbUser, 'passwordHash'> | null => {
    const t = now()
    if (sqliteDb) {
      const current = sqliteDb
        .prepare(
          `SELECT
             id,
             username,
             first_name as firstName,
             last_name as lastName,
             email,
             is_admin as isAdmin,
             email_verified as emailVerified,
             group_id as groupId,
             email_verification_token_hash as emailVerificationTokenHash,
             email_verification_expires_at as emailVerificationExpiresAt,
             created_at as createdAt,
             updated_at as updatedAt
           FROM users WHERE id = ?`,
        )
        .get(id) as any
      if (!current) return null

      const next = {
        email: patch.email ?? current.email,
        username: patch.username ?? current.username,
        firstName: patch.firstName ?? current.firstName,
        lastName: patch.lastName ?? current.lastName,
        isAdmin: patch.isAdmin ?? current.isAdmin,
        emailVerified: patch.emailVerified ?? current.emailVerified,
        groupId: patch.groupId ?? current.groupId,
      }

      sqliteDb
        .prepare(
          `UPDATE users
           SET email=@email, username=@username, first_name=@firstName, last_name=@lastName,
               is_admin=@isAdmin, email_verified=@emailVerified, group_id=@groupId, updated_at=@updatedAt
           WHERE id=@id`,
        )
        .run({ ...next, updatedAt: t, id })

      return { ...current, ...next, updatedAt: t }
    }

    const s = readJson()
    const idx = s.users.findIndex((u) => u.id === id)
    if (idx < 0) return null
    const u = s.users[idx]
    const updated: DbUser = {
      ...u,
      email: patch.email ?? u.email,
      username: patch.username ?? u.username,
      firstName: patch.firstName ?? u.firstName,
      lastName: patch.lastName ?? u.lastName,
      isAdmin: patch.isAdmin ?? u.isAdmin,
      emailVerified: patch.emailVerified ?? u.emailVerified,
      groupId: patch.groupId ?? u.groupId,
      updatedAt: t,
    }
    s.users[idx] = updated
    writeJson(s)
    const { passwordHash, ...rest } = updated
    return rest
  },

  setUserPassword: (id: string, passwordHash: string): boolean => {
    const t = now()
    if (sqliteDb) {
      const info = sqliteDb
        .prepare(`UPDATE users SET password_hash=?, updated_at=? WHERE id=?`)
        .run(passwordHash, t, id)
      return info.changes > 0
    }
    const s = readJson()
    const idx = s.users.findIndex((u) => u.id === id)
    if (idx < 0) return false
    s.users[idx] = { ...s.users[idx], passwordHash, updatedAt: t }
    writeJson(s)
    return true
  },

  deleteUser: (id: string): boolean => {
    if (sqliteDb) {
      const info = sqliteDb.prepare(`DELETE FROM users WHERE id=?`).run(id)
      return info.changes > 0
    }
    const s = readJson()
    const before = s.users.length
    s.users = s.users.filter((u) => u.id !== id)
    const changed = s.users.length !== before
    if (changed) writeJson(s)
    return changed
  },

  verifyEmailByTokenHash: (tokenHash: string): DbUser | null => {
    const t = now()
    if (sqliteDb) {
      const user = sqliteDb
        .prepare(
          `SELECT
             id,
             username,
             first_name as firstName,
             last_name as lastName,
             email,
             password_hash as passwordHash,
             is_admin as isAdmin,
             email_verified as emailVerified,
             group_id as groupId,
             email_verification_token_hash as emailVerificationTokenHash,
             email_verification_expires_at as emailVerificationExpiresAt,
             created_at as createdAt,
             updated_at as updatedAt
           FROM users WHERE email_verification_token_hash = ?`,
        )
        .get(tokenHash) as DbUser | undefined
      if (!user) return null
      // If already verified, treat as success (idempotent link).
      if (!user.emailVerified) {
        if (!user.emailVerificationExpiresAt || user.emailVerificationExpiresAt < t) return null
      }
      sqliteDb
        .prepare(
          `UPDATE users
           SET email_verified=1, email_verification_expires_at=NULL, updated_at=?
           WHERE id=?`,
        )
        .run(t, user.id)
      return {
        ...user,
        emailVerified: 1,
        emailVerificationExpiresAt: null,
        updatedAt: t,
      }
    }

    const s = readJson()
    const idx = s.users.findIndex((u) => u.emailVerificationTokenHash === tokenHash)
    if (idx < 0) return null
    const u = s.users[idx]
    if (!u.emailVerified) {
      if (!u.emailVerificationExpiresAt || u.emailVerificationExpiresAt < t) return null
    }
    const updated: DbUser = {
      ...u,
      emailVerified: 1,
      emailVerificationExpiresAt: null,
      updatedAt: t,
    }
    s.users[idx] = updated
    writeJson(s)
    return updated
  },

  setEmailVerificationForUser: (email: string, tokenHash: string, expiresAt: number): boolean => {
    const t = now()
    if (sqliteDb) {
      const info = sqliteDb
        .prepare(
          `UPDATE users
           SET email_verification_token_hash=?, email_verification_expires_at=?, updated_at=?
           WHERE email=? AND email_verified=0`,
        )
        .run(tokenHash, expiresAt, t, email)
      return info.changes > 0
    }
    const s = readJson()
    const idx = s.users.findIndex((u) => u.email === email && u.emailVerified === 0)
    if (idx < 0) return false
    s.users[idx] = {
      ...s.users[idx],
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpiresAt: expiresAt,
      updatedAt: t,
    }
    writeJson(s)
    return true
  },

  listPlanning: (userId: string, date?: string): DbPlanningItem[] => {
    if (sqliteDb) {
      const rows = date
        ? (sqliteDb
            .prepare(
              `SELECT
                 id,
                 user_id as userId,
                 group_id as groupId,
                 date, start, end, title, notes, tags_json as tagsJson,
                 priority, status,
                 created_at as createdAt,
                 updated_at as updatedAt
               FROM planning_items
               WHERE user_id = ? AND date = ?
               ORDER BY date ASC, start ASC`,
            )
            .all(userId, date) as DbPlanningItem[])
        : (sqliteDb
            .prepare(
              `SELECT
                 id,
                 user_id as userId,
                 group_id as groupId,
                 date, start, end, title, notes, tags_json as tagsJson,
                 priority, status,
                 created_at as createdAt,
                 updated_at as updatedAt
               FROM planning_items
               WHERE user_id = ?
               ORDER BY date ASC, start ASC`,
            )
            .all(userId) as DbPlanningItem[])
      return rows
    }
    const s = readJson()
    return s.planning
      .filter((p) => p.userId === userId && (!date || p.date === date))
      .sort((a, b) => (a.date + a.start).localeCompare(b.date + b.start))
  },

  listPlanningForGroup: (groupId: string, date?: string): DbPlanningItem[] => {
    if (sqliteDb) {
      const rows = date
        ? (sqliteDb
            .prepare(
              `SELECT
                 id,
                 user_id as userId,
                 group_id as groupId,
                 date, start, end, title, notes, tags_json as tagsJson,
                 priority, status,
                 created_at as createdAt,
                 updated_at as updatedAt
               FROM planning_items
               WHERE group_id = ? AND date = ?
               ORDER BY date ASC, start ASC`,
            )
            .all(groupId, date) as DbPlanningItem[])
        : (sqliteDb
            .prepare(
              `SELECT
                 id,
                 user_id as userId,
                 group_id as groupId,
                 date, start, end, title, notes, tags_json as tagsJson,
                 priority, status,
                 created_at as createdAt,
                 updated_at as updatedAt
               FROM planning_items
               WHERE group_id = ?
               ORDER BY date ASC, start ASC`,
            )
            .all(groupId) as DbPlanningItem[])
      return rows
    }
    const s = readJson()
    return s.planning
      .filter((p) => p.groupId === groupId && (!date || p.date === date))
      .sort((a, b) => (a.date + a.start).localeCompare(b.date + b.start))
  },

  listPlanningForGroupWithOwner: (
    groupId: string,
    date?: string,
  ): Array<DbPlanningItem & { ownerEmail: string | null; ownerUsername: string | null }> => {
    if (sqliteDb) {
      const rows = date
        ? (sqliteDb
            .prepare(
              `SELECT
                 p.id,
                 p.user_id as userId,
                 p.group_id as groupId,
                 p.date, p.start, p.end, p.title, p.notes, p.tags_json as tagsJson,
                 p.priority, p.status,
                 p.created_at as createdAt,
                 p.updated_at as updatedAt,
                 u.email as ownerEmail,
                 u.username as ownerUsername
               FROM planning_items p
               LEFT JOIN users u ON u.id = p.user_id
               WHERE p.group_id = ? AND p.date = ?
               ORDER BY p.date ASC, p.start ASC`,
            )
            .all(groupId, date) as any[])
        : (sqliteDb
            .prepare(
              `SELECT
                 p.id,
                 p.user_id as userId,
                 p.group_id as groupId,
                 p.date, p.start, p.end, p.title, p.notes, p.tags_json as tagsJson,
                 p.priority, p.status,
                 p.created_at as createdAt,
                 p.updated_at as updatedAt,
                 u.email as ownerEmail,
                 u.username as ownerUsername
               FROM planning_items p
               LEFT JOIN users u ON u.id = p.user_id
               WHERE p.group_id = ?
               ORDER BY p.date ASC, p.start ASC`,
            )
            .all(groupId) as any[])
      return rows
    }
    const s = readJson()
    const byId = new Map(s.users.map((u) => [u.id, u] as const))
    return s.planning
      .filter((p) => p.groupId === groupId && (!date || p.date === date))
      .sort((a, b) => (a.date + a.start).localeCompare(b.date + b.start))
      .map((p) => {
        const u = byId.get(p.userId)
        return { ...p, ownerEmail: u?.email ?? null, ownerUsername: u?.username ?? null }
      })
  },

  listPlanningForGroupRangeWithOwner: (
    groupId: string,
    from: string,
    to: string,
  ): Array<DbPlanningItem & { ownerEmail: string | null; ownerUsername: string | null }> => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             p.id,
             p.user_id as userId,
             p.group_id as groupId,
             p.date, p.start, p.end, p.title, p.notes, p.tags_json as tagsJson,
             p.priority, p.status,
             p.created_at as createdAt,
             p.updated_at as updatedAt,
             u.email as ownerEmail,
             u.username as ownerUsername
           FROM planning_items p
           LEFT JOIN users u ON u.id = p.user_id
           WHERE p.group_id = ? AND p.date >= ? AND p.date <= ?
           ORDER BY p.date ASC, p.start ASC`,
        )
        .all(groupId, from, to) as any[]
      return rows
    }
    const s = readJson()
    const byId = new Map(s.users.map((u) => [u.id, u] as const))
    return s.planning
      .filter((p) => p.groupId === groupId && p.date >= from && p.date <= to)
      .sort((a, b) => (a.date + a.start).localeCompare(b.date + b.start))
      .map((p) => {
        const u = byId.get(p.userId)
        return { ...p, ownerEmail: u?.email ?? null, ownerUsername: u?.username ?? null }
      })
  },

  upsertPlanning: (
    userId: string,
    input: Omit<DbPlanningItem, 'id' | 'userId' | 'createdAt' | 'updatedAt'> & { id?: string },
  ): DbPlanningItem => {
    const t = now()
    const id = input.id ?? uuid()
    if (sqliteDb) {
      const existing = sqliteDb
        .prepare(`SELECT created_at as createdAt FROM planning_items WHERE id = ? AND user_id = ?`)
        .get(id, userId) as { createdAt: number } | undefined

      if (existing) {
        sqliteDb
          .prepare(
            `UPDATE planning_items
             SET group_id=@groupId,date=@date,start=@start,end=@end,title=@title,notes=@notes,tags_json=@tagsJson,priority=@priority,status=@status,updated_at=@updatedAt
             WHERE id=@id AND user_id=@userId`,
          )
          .run({
            id,
            userId,
            groupId: input.groupId,
            date: input.date,
            start: input.start,
            end: input.end,
            title: input.title,
            notes: input.notes ?? null,
            tagsJson: input.tagsJson ?? '[]',
            priority: input.priority,
            status: input.status,
            updatedAt: t,
          })
        const item = sqliteDb
          .prepare(
            `SELECT
               id,
               user_id as userId,
               group_id as groupId,
              date, start, end, title, notes, tags_json as tagsJson,
               priority, status,
               created_at as createdAt,
               updated_at as updatedAt
             FROM planning_items WHERE id = ? AND user_id = ?`,
          )
          .get(id, userId) as DbPlanningItem
        return item
      }

      const createdAt = t
      sqliteDb
        .prepare(
          `INSERT INTO planning_items
           (id,user_id,group_id,date,start,end,title,notes,tags_json,priority,status,created_at,updated_at)
           VALUES
           (@id,@userId,@groupId,@date,@start,@end,@title,@notes,@tagsJson,@priority,@status,@createdAt,@updatedAt)`,
        )
        .run({
          id,
          userId,
          groupId: input.groupId,
          date: input.date,
          start: input.start,
          end: input.end,
          title: input.title,
          notes: input.notes ?? null,
          tagsJson: input.tagsJson ?? '[]',
          priority: input.priority,
          status: input.status,
          createdAt,
          updatedAt: t,
        })
      return {
        id,
        userId,
        groupId: input.groupId,
        date: input.date,
        start: input.start,
        end: input.end,
        title: input.title,
        notes: input.notes ?? null,
        tagsJson: input.tagsJson ?? '[]',
        priority: input.priority,
        status: input.status,
        createdAt,
        updatedAt: t,
      }
    }

    const s = readJson()
    const idx = s.planning.findIndex((p) => p.id === id && p.userId === userId)
    if (idx >= 0) {
      const prev = s.planning[idx]
      const next: DbPlanningItem = {
        ...prev,
        date: input.date,
        start: input.start,
        end: input.end,
        title: input.title,
        notes: input.notes ?? null,
        tagsJson: input.tagsJson ?? prev.tagsJson ?? '[]',
        priority: input.priority,
        status: input.status,
        updatedAt: t,
      }
      s.planning[idx] = next
      writeJson(s)
      return next
    }
    const item: DbPlanningItem = {
      id,
      userId,
      groupId: input.groupId,
      date: input.date,
      start: input.start,
      end: input.end,
      title: input.title,
      notes: input.notes ?? null,
      tagsJson: input.tagsJson ?? '[]',
      priority: input.priority,
      status: input.status,
      createdAt: t,
      updatedAt: t,
    }
    s.planning.push(item)
    writeJson(s)
    return item
  },

  deletePlanning: (userId: string, id: string): boolean => {
    if (sqliteDb) {
      const info = sqliteDb.prepare(`DELETE FROM planning_items WHERE id = ? AND user_id = ?`).run(id, userId)
      return info.changes > 0
    }
    const s = readJson()
    const before = s.planning.length
    s.planning = s.planning.filter((p) => !(p.userId === userId && p.id === id))
    const changed = s.planning.length !== before
    if (changed) writeJson(s)
    return changed
  },

  setEmailVerificationForEmail: (
    email: string,
    tokenHash: string,
    expiresAt: number,
  ): boolean => {
    const t = now()
    if (sqliteDb) {
      const info = sqliteDb
        .prepare(
          `UPDATE users
           SET email_verified=0, email_verification_token_hash=?, email_verification_expires_at=?, updated_at=?
           WHERE email=?`,
        )
        .run(tokenHash, expiresAt, t, email)
      return info.changes > 0
    }
    const s = readJson()
    const idx = s.users.findIndex((u) => u.email === email)
    if (idx < 0) return false
    const u = s.users[idx]
    s.users[idx] = {
      ...u,
      emailVerified: 0,
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpiresAt: expiresAt,
      updatedAt: t,
    }
    writeJson(s)
    return true
  },

  addAudit: (input: Omit<DbAudit, 'id' | 'createdAt'> & { createdAt?: number }) => {
    const entry: DbAudit = {
      id: uuid(),
      actorUserId: input.actorUserId,
      action: input.action,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      metaJson: input.metaJson,
      createdAt: input.createdAt ?? now(),
    }
    if (sqliteDb) {
      sqliteDb
        .prepare(
          `INSERT INTO audit_log (id, actor_user_id, action, resource_type, resource_id, meta_json, created_at)
           VALUES (@id, @actorUserId, @action, @resourceType, @resourceId, @metaJson, @createdAt)`,
        )
        .run(entry)
      return entry
    }
    const s = readJson()
    s.audit.push(entry)
    writeJson(s)
    return entry
  },

  listAudit: (limit = 200): DbAudit[] => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             id,
             actor_user_id as actorUserId,
             action,
             resource_type as resourceType,
             resource_id as resourceId,
             meta_json as metaJson,
             created_at as createdAt
           FROM audit_log
           ORDER BY created_at DESC
           LIMIT ?`,
        )
        .all(limit) as DbAudit[]
      return rows
    }
    const s = readJson()
    return s.audit.slice().sort((a, b) => b.createdAt - a.createdAt).slice(0, limit)
  },

  listAuditWithActor: (limit = 200): DbAuditWithActor[] => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             a.id,
             a.actor_user_id as actorUserId,
             a.action,
             a.resource_type as resourceType,
             a.resource_id as resourceId,
             a.meta_json as metaJson,
             a.created_at as createdAt,
             u.email as actorEmail,
             u.username as actorUsername
           FROM audit_log a
           LEFT JOIN users u ON u.id = a.actor_user_id
           ORDER BY a.created_at DESC
           LIMIT ?`,
        )
        .all(limit) as DbAuditWithActor[]
      return rows
    }
    const s = readJson()
    const byId = new Map(s.users.map((u) => [u.id, u] as const))
    return s.audit
      .slice()
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, limit)
      .map((a) => {
        const u = byId.get(a.actorUserId)
        return { ...a, actorEmail: u?.email ?? null, actorUsername: u?.username ?? null }
      })
  },

  countAudit: (): number => {
    if (sqliteDb) {
      const row = sqliteDb.prepare(`SELECT COUNT(1) as c FROM audit_log`).get() as { c: number } | undefined
      return Number(row?.c ?? 0)
    }
    const s = readJson()
    return s.audit.length
  },

  listAuditWithActorPaged: (limit = 200, offset = 0): DbAuditWithActor[] => {
    const safeLimit = Math.min(500, Math.max(1, Math.floor(limit)))
    const safeOffset = Math.max(0, Math.floor(offset))
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             a.id,
             a.actor_user_id as actorUserId,
             a.action,
             a.resource_type as resourceType,
             a.resource_id as resourceId,
             a.meta_json as metaJson,
             a.created_at as createdAt,
             u.email as actorEmail,
             u.username as actorUsername
           FROM audit_log a
           LEFT JOIN users u ON u.id = a.actor_user_id
           ORDER BY a.created_at DESC
           LIMIT ? OFFSET ?`,
        )
        .all(safeLimit, safeOffset) as DbAuditWithActor[]
      return rows
    }
    const s = readJson()
    const byId = new Map(s.users.map((u) => [u.id, u] as const))
    return s.audit
      .slice()
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(safeOffset, safeOffset + safeLimit)
      .map((a) => {
        const u = byId.get(a.actorUserId)
        return { ...a, actorEmail: u?.email ?? null, actorUsername: u?.username ?? null }
      })
  },

  upsertNote: (
    userId: string,
    input: { id?: string; subject: string; body: string; groupId: string },
  ): DbNote => {
    const t = now()
    const id = input.id ?? uuid()
    if (sqliteDb) {
      const existing = sqliteDb
        .prepare(`SELECT created_at as createdAt FROM notes WHERE id=? AND user_id=?`)
        .get(id, userId) as { createdAt: number } | undefined
      if (existing) {
        sqliteDb
          .prepare(
            `UPDATE notes SET group_id=@groupId, subject=@subject, body=@body, updated_at=@updatedAt
             WHERE id=@id AND user_id=@userId`,
          )
          .run({ id, userId, groupId: input.groupId, subject: input.subject, body: input.body, updatedAt: t })
        const row = sqliteDb
          .prepare(
            `SELECT id, user_id as userId, group_id as groupId, subject, body, created_at as createdAt, updated_at as updatedAt
             FROM notes WHERE id=? AND user_id=?`,
          )
          .get(id, userId) as DbNote
        return row
      }
      sqliteDb
        .prepare(
          `INSERT INTO notes (id,user_id,group_id,subject,body,created_at,updated_at)
           VALUES (@id,@userId,@groupId,@subject,@body,@createdAt,@updatedAt)`,
        )
        .run({ id, userId, groupId: input.groupId, subject: input.subject, body: input.body, createdAt: t, updatedAt: t })
      return { id, userId, groupId: input.groupId, subject: input.subject, body: input.body, createdAt: t, updatedAt: t }
    }
    const s = readJson()
    const idx = s.notes.findIndex((n) => n.id === id && n.userId === userId)
    if (idx >= 0) {
      s.notes[idx] = { ...s.notes[idx], groupId: input.groupId, subject: input.subject, body: input.body, updatedAt: t }
      writeJson(s)
      return s.notes[idx]
    }
    const note: DbNote = { id, userId, groupId: input.groupId, subject: input.subject, body: input.body, createdAt: t, updatedAt: t }
    s.notes.push(note)
    writeJson(s)
    return note
  },

  getNoteById: (id: string): DbNote | null => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(
          `SELECT id, user_id as userId, group_id as groupId, subject, body, created_at as createdAt, updated_at as updatedAt
           FROM notes WHERE id=?`,
        )
        .get(id) as DbNote | undefined
      return row ?? null
    }
    const s = readJson()
    return s.notes.find((n) => n.id === id) ?? null
  },

  listNotesOwned: (userId: string): DbNote[] => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT id, user_id as userId, group_id as groupId, subject, body, created_at as createdAt, updated_at as updatedAt
           FROM notes WHERE user_id=? ORDER BY updated_at DESC`,
        )
        .all(userId) as DbNote[]
      return rows
    }
    const s = readJson()
    return s.notes.filter((n) => n.userId === userId).sort((a, b) => b.updatedAt - a.updatedAt)
  },

  listNotesSharedForUser: (userId: string): DbNote[] => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             n.id,
             n.user_id as userId,
             n.group_id as groupId,
             n.subject,
             n.body,
             n.created_at as createdAt,
             n.updated_at as updatedAt
           FROM shares s
           JOIN notes n ON n.id = s.resource_id
           WHERE s.grantee_id = ? AND s.resource_type = 'note'
           ORDER BY s.created_at DESC`,
        )
        .all(userId) as DbNote[]
      return rows
    }
    const s = readJson()
    const incoming = s.shares.filter((sh) => sh.granteeId === userId && sh.resourceType === 'note')
    const ids = new Set(incoming.map((sh) => sh.resourceId))
    return s.notes.filter((n) => ids.has(n.id))
  },

  deleteNote: (userId: string, id: string): boolean => {
    if (sqliteDb) {
      const info = sqliteDb.prepare(`DELETE FROM notes WHERE id=? AND user_id=?`).run(id, userId)
      return info.changes > 0
    }
    const s = readJson()
    const before = s.notes.length
    s.notes = s.notes.filter((n) => !(n.userId === userId && n.id === id))
    const changed = s.notes.length !== before
    if (changed) writeJson(s)
    return changed
  },

  getPlanningById: (id: string): DbPlanningItem | null => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(
          `SELECT
             id,
             user_id as userId,
             group_id as groupId,
             date, start, end, title, notes, tags_json as tagsJson,
             priority, status,
             created_at as createdAt,
             updated_at as updatedAt
           FROM planning_items WHERE id=?`,
        )
        .get(id) as DbPlanningItem | undefined
      return row ?? null
    }
    const s = readJson()
    return s.planning.find((p) => p.id === id) ?? null
  },

  listPlanningSharedForUser: (userId: string): Array<DbPlanningItem & { permission: 'read' | 'write'; ownerId: string }> => {
    if (sqliteDb) {
      const rows = sqliteDb
        .prepare(
          `SELECT
             p.id,
             p.user_id as userId,
             p.group_id as groupId,
             p.date, p.start, p.end, p.title, p.notes, p.tags_json as tagsJson,
             p.priority, p.status,
             p.created_at as createdAt,
             p.updated_at as updatedAt,
             s.permission as permission,
             s.owner_id as ownerId
           FROM shares s
           JOIN planning_items p ON p.id = s.resource_id
           WHERE s.grantee_id = ? AND s.resource_type = 'planning'
           ORDER BY p.date ASC, p.start ASC`,
        )
        .all(userId) as Array<DbPlanningItem & { permission: 'read' | 'write'; ownerId: string }>
      return rows
    }
    const s = readJson()
    const incoming = s.shares.filter((sh) => sh.granteeId === userId && sh.resourceType === 'planning')
    const byId = new Map(s.planning.map((p) => [p.id, p] as const))
    return incoming
      .map((sh) => {
        const p = byId.get(sh.resourceId)
        if (!p) return null
        return { ...p, permission: sh.permission, ownerId: sh.ownerId }
      })
      .filter(Boolean) as any
  },

  createShare: (input: Omit<DbShare, 'id' | 'createdAt'> & { createdAt?: number }): DbShare => {
    const entry: DbShare = { id: uuid(), ...input, createdAt: input.createdAt ?? now() }
    if (sqliteDb) {
      sqliteDb
        .prepare(
          `INSERT INTO shares (id, resource_type, resource_id, owner_id, grantee_id, permission, created_at)
           VALUES (@id, @resourceType, @resourceId, @ownerId, @granteeId, @permission, @createdAt)`,
        )
        .run(entry)
      return entry
    }
    const s = readJson()
    s.shares.push(entry)
    writeJson(s)
    return entry
  },

  listSharesForUser: (userId: string) => {
    if (sqliteDb) {
      const incoming = sqliteDb
        .prepare(
          `SELECT
             id,
             resource_type as resourceType,
             resource_id as resourceId,
             owner_id as ownerId,
             grantee_id as granteeId,
             permission,
             created_at as createdAt
           FROM shares WHERE grantee_id=? ORDER BY created_at DESC`,
        )
        .all(userId) as DbShare[]
      const outgoing = sqliteDb
        .prepare(
          `SELECT
             id,
             resource_type as resourceType,
             resource_id as resourceId,
             owner_id as ownerId,
             grantee_id as granteeId,
             permission,
             created_at as createdAt
           FROM shares WHERE owner_id=? ORDER BY created_at DESC`,
        )
        .all(userId) as DbShare[]
      return { incoming, outgoing }
    }
    const s = readJson()
    return {
      incoming: s.shares.filter((sh) => sh.granteeId === userId).sort((a, b) => b.createdAt - a.createdAt),
      outgoing: s.shares.filter((sh) => sh.ownerId === userId).sort((a, b) => b.createdAt - a.createdAt),
    }
  },

  findSharePermission: (resourceType: DbShare['resourceType'], resourceId: string, userId: string): DbShare | null => {
    if (sqliteDb) {
      const row = sqliteDb
        .prepare(
          `SELECT
             id,
             resource_type as resourceType,
             resource_id as resourceId,
             owner_id as ownerId,
             grantee_id as granteeId,
             permission,
             created_at as createdAt
           FROM shares WHERE resource_type=? AND resource_id=? AND grantee_id=?`,
        )
        .get(resourceType, resourceId, userId) as DbShare | undefined
      return row ?? null
    }
    const s = readJson()
    return s.shares.find((sh) => sh.resourceType === resourceType && sh.resourceId === resourceId && sh.granteeId === userId) ?? null
  },
}


